package gateway

import (
	schedulerv1 "agentenv/services/api/proto"
	"context"
	"fmt"
	"google.golang.org/grpc"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLaunchObservationUnknownNeverSchedules(t *testing.T) {
	s := newTestServer(t, stubSchedulerClient{}, time.Second, 1024)
	r := httptest.NewRequest(http.MethodGet, "/launch-observations/550e8400-e29b-41d4-a716-446655440000", nil)
	r.Header.Set(headerAPIKey, testAPIKey)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown attempt: got %d, want404", w.Code)
	}
}

func TestLaunchObservationPinsNodeBeforeDispatchCompletes(t *testing.T) {
	const id = "550e8400-e29b-41d4-a716-446655440000"
	entered, release := make(chan struct{}), make(chan struct{})
	var calls, schedules atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == http.MethodPost {
			if calls.Load() == 1 && r.Header.Get(headerLaunchAttempt) != id {
				t.Error("attempt missing")
			}
			if calls.Load() == 1 {
				close(entered)
				<-release
			}
			w.WriteHeader(500)
			return
		}
		if r.URL.Path != "/launch-observations/"+id || r.Header.Get(headerAPIKey) != testAPIKey {
			t.Errorf("wrong exact request: %s", r.URL.Path)
		}
		fmt.Fprintf(w, `{"attempt_id":%q,"phase":"fetching_snapshot","elapsed_ms":12,"done":false}`, id)
	}))
	defer upstream.Close()
	s := newTestServer(t, stubSchedulerClient{scheduleFunc: func(context.Context, *schedulerv1.ScheduleRequest, ...grpc.CallOption) (*schedulerv1.ScheduleResponse, error) {
		schedules.Add(1)
		return &schedulerv1.ScheduleResponse{Node: &schedulerv1.Node{NodeId: "captured-node", Endpoint: upstream.URL}}, nil
	}}, time.Second, 1024)
	request := func(method, path, attempt, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		r.Header.Set(headerAPIKey, key)
		if attempt != "" {
			r.Header.Set(headerLaunchAttempt, attempt)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	finished := make(chan struct{})
	go func() { defer close(finished); request("POST", "/sandboxes", id, testAPIKey) }()
	<-entered
	if w := request("GET", "/launch-observations/"+id, "", testAPIKey); w.Code != 200 || !strings.Contains(w.Body.String(), id) {
		t.Fatalf("inflight observation: %d %s", w.Code, w.Body.String())
	}
	if w := request("POST", "/sandboxes", id, testAPIKey); w.Code != 500 {
		t.Fatalf("duplicate=%d", w.Code)
	}
	before := calls.Load()
	for _, path := range []string{"/launch-observations/" + id, "/launch-observations/not-an-id"} {
		if w := request("GET", path, "", ""); w.Code != 401 {
			t.Fatalf("unauth=%d", w.Code)
		}
	}
	if calls.Load() != before || schedules.Load() != 2 {
		t.Fatal("denial scheduled or contacted runtime")
	}
	close(release)
	<-finished
	// The original failed dispatch remains inspectable and cannot be reassigned.
	if w := request("GET", "/launch-observations/"+id, "", testAPIKey); w.Code != 404 {
		t.Fatalf("post-failure observation=%d", w.Code)
	}
}

func TestLaunchObservationTimeoutRetainsBoundedRoute(t *testing.T) {
	const id = "550e8400-e29b-41d4-a716-446655440000"
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			<-release
			return
		}
		fmt.Fprintf(w, `{"attempt_id":%q,"phase":"loading_snapshot","elapsed_ms":50,"done":false}`, id)
	}))
	defer upstream.Close()
	s := newTestServer(t, stubSchedulerClient{scheduleFunc: func(context.Context, *schedulerv1.ScheduleRequest, ...grpc.CallOption) (*schedulerv1.ScheduleResponse, error) {
		return &schedulerv1.ScheduleResponse{Node: &schedulerv1.Node{NodeId: "exact", Endpoint: upstream.URL}}, nil
	}}, 20*time.Millisecond, 1024)
	r := httptest.NewRequest("POST", "/sandboxes", strings.NewReader(`{}`))
	r.Header.Set(headerAPIKey, testAPIKey)
	r.Header.Set(headerLaunchAttempt, id)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	close(release)
	if w.Code != 504 {
		t.Fatalf("timeout=%d", w.Code)
	}
	if _, ok := s.launchObservations.lookup(id, time.Now()); !ok {
		t.Fatal("timeout discarded route")
	}
	if _, ok := s.launchObservations.lookup(id, time.Now().Add(launchObservationTTL)); ok {
		t.Fatal("route did not expire")
	}
	var routes launchObservationRoutes
	now := time.Now()
	for i := 0; i < launchObservationCapacity; i++ {
		if code := routes.reserve(fmt.Sprint(i), now); code != 0 {
			t.Fatal(code)
		}
	}
	if routes.reserve("full", now) != 503 {
		t.Fatal("capacity not bounded")
	}
	if routes.reserve("after-expiry", now.Add(launchObservationTTL)) != 0 || len(routes.entries) != 1 {
		t.Fatal("expired routes retained")
	}
}

func TestLaunchObservationRejectsMalformedAndProxyAuthBypass(t *testing.T) {
	s := newTestServer(t, stubSchedulerClient{}, time.Second, 1024)
	for _, tc := range []struct {
		path, key string
		want      int
	}{{"/launch-observations/nope", testAPIKey, 400}, {"/launch-observations/550e8400-e29b-41d4-a716-446655440000", "", 401}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.Header.Set(headerAPIKey, tc.key)
		r.Header.Set(headerSandboxID, "foreign")
		r.Header.Set(headerTargetPort, "80")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s got%d", tc.path, w.Code)
		}
	}
}

func TestLaunchObservationUnavailableDoesNotChangeDispatch(t *testing.T) {
	for _, mode := range []string{"malformed", "capacity"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get(headerLaunchAttempt) != "" {
					t.Error("unavailable observation forwarded")
				}
				w.WriteHeader(418)
			}))
			defer upstream.Close()
			s := newTestServer(t, stubSchedulerClient{scheduleFunc: func(context.Context, *schedulerv1.ScheduleRequest, ...grpc.CallOption) (*schedulerv1.ScheduleResponse, error) {
				return &schedulerv1.ScheduleResponse{Node: &schedulerv1.Node{NodeId: "node", Endpoint: upstream.URL}}, nil
			}}, time.Second, 1024)
			id := "not-a-uuid"
			if mode == "capacity" {
				id = "550e8400-e29b-41d4-a716-446655440000"
				for i := 0; i < launchObservationCapacity; i++ {
					s.launchObservations.reserve(fmt.Sprint(i), time.Now())
				}
			}
			r := httptest.NewRequest("POST", "/sandboxes", strings.NewReader(`{}`))
			r.Header.Set(headerAPIKey, testAPIKey)
			r.Header.Set(headerLaunchAttempt, id)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 418 || calls.Load() != 1 {
				t.Fatalf("lifecycle changed: status%d calls%d", w.Code, calls.Load())
			}
		})
	}
}

func TestLaunchObservationDuplicateBeforeBindStaysSuppressed(t *testing.T) {
	var routes launchObservationRoutes
	now := time.Now()
	routes.reserve("attempt", now)
	routes.reserve("attempt", now)
	routes.bind("attempt", &schedulerv1.Node{NodeId: "late", Endpoint: "http://late"}, now)
	if _, ok := routes.lookup("attempt", now); ok {
		t.Fatal("late bind resurrected duplicate")
	}
}

func TestLaunchObservationRetainedWakeUsesExactLookup(t *testing.T) {
	const id = "550e8400-e29b-41d4-a716-446655440000"
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/sandboxes/retained/connect" || r.Header.Get(headerLaunchAttempt) != id {
			t.Error("wrong retained dispatch")
		}
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	s := newTestServer(t, stubSchedulerClient{lookupNodeFunc: func(_ context.Context, r *schedulerv1.LookupNodeRequest, _ ...grpc.CallOption) (*schedulerv1.LookupNodeResponse, error) {
		if r.SandboxId != "retained" {
			t.Fatal(r.SandboxId)
		}
		return &schedulerv1.LookupNodeResponse{Node: &schedulerv1.Node{NodeId: "exact", Endpoint: upstream.URL}}, nil
	}}, time.Second, 1024)
	r := httptest.NewRequest("POST", "/sandboxes/retained/connect", nil)
	r.Header.Set(headerAPIKey, testAPIKey)
	r.Header.Set(headerLaunchAttempt, id)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	route, ok := s.launchObservations.lookup(id, time.Now())
	if w.Code != 204 || calls.Load() != 1 || !ok || route.endpoint != upstream.URL {
		t.Fatal("retained wake lost exact route")
	}
}

func TestLaunchObservationRejectsReplacedNodeResponse(t *testing.T) {
	const id = "550e8400-e29b-41d4-a716-446655440000"
	for _, body := range []string{`{"attempt_id":"different","phase":"booting_guest"}`, `{"attempt_id":"550e8400-e29b-41d4-a716-446655440000","phase":"raw guest secret"}`} {
		t.Run(body, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer upstream.Close()
			s := newTestServer(t, stubSchedulerClient{}, time.Second, 1024)
			reservedAt := time.Now()
			s.launchObservations.reserve(id, reservedAt)
			s.launchObservations.bind(id, &schedulerv1.Node{NodeId: "exact", Endpoint: upstream.URL}, reservedAt)
			r := httptest.NewRequest("GET", "/launch-observations/"+id, nil)
			r.Header.Set(headerAPIKey, testAPIKey)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 502 || strings.Contains(w.Body.String(), "secret") {
				t.Fatal("foreign or invalid observation exposed")
			}
		})
	}
}

func TestLaunchObservationExpiredDispatchCannotRebindReplacement(t *testing.T) {
	var routes launchObservationRoutes
	now := time.Now()
	routes.reserve("attempt", now)
	next := now.Add(launchObservationTTL)
	routes.reserve("attempt", next)
	routes.bind("attempt", &schedulerv1.Node{NodeId: "old", Endpoint: "http://old"}, now)
	if _, ok := routes.lookup("attempt", next); ok {
		t.Fatal("expired dispatch rebound new observation")
	}
	routes.bind("attempt", &schedulerv1.Node{NodeId: "new", Endpoint: "http://new"}, next)
	if entry, ok := routes.lookup("attempt", next); !ok || entry.nodeID != "new" {
		t.Fatal("replacement lost exact binding")
	}
}

func TestLaunchObservationDiscardsResponseAfterRouteInvalidation(t *testing.T) {
	const id = "550e8400-e29b-41d4-a716-446655440000"
	for _, change := range []string{"duplicate", "expired", "replacement"} {
		t.Run(change, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-release
				fmt.Fprintf(w, `{"attempt_id":%q,"phase":"loading_snapshot","elapsed_ms":12,"done":false}`, id)
			}))
			defer upstream.Close()
			s := newTestServer(t, stubSchedulerClient{}, time.Second, 1024)
			now := time.Now()
			s.launchObservations.reserve(id, now)
			s.launchObservations.bind(id, &schedulerv1.Node{NodeId: "old", Endpoint: upstream.URL}, now)
			r := httptest.NewRequest("GET", "/launch-observations/"+id, nil)
			r.Header.Set(headerAPIKey, testAPIKey)
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); s.Handler().ServeHTTP(w, r) }()
			<-entered
			switch change {
			case "duplicate":
				s.launchObservations.reserve(id, time.Now())
			case "expired":
				s.launchObservations.lookup(id, now.Add(launchObservationTTL))
			case "replacement":
				next := now.Add(launchObservationTTL)
				s.launchObservations.reserve(id, next)
				s.launchObservations.bind(id, &schedulerv1.Node{NodeId: "replacement", Endpoint: upstream.URL}, next)
			}
			close(release)
			<-done
			if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "loading_snapshot") {
				t.Fatalf("stale response after %s: %d %s", change, w.Code, w.Body.String())
			}
		})
	}
}

func TestLocalHealthStaysLocalWithoutObservationQuery(t *testing.T) {
	var calls atomic.Int32
	s := newTestServer(t, stubSchedulerClient{
		scheduleFunc: func(context.Context, *schedulerv1.ScheduleRequest, ...grpc.CallOption) (*schedulerv1.ScheduleResponse, error) {
			calls.Add(1)
			return nil, fmt.Errorf("unexpected scheduling")
		},
		lookupNodeFunc: func(context.Context, *schedulerv1.LookupNodeRequest, ...grpc.CallOption) (*schedulerv1.LookupNodeResponse, error) {
			calls.Add(1)
			return nil, fmt.Errorf("unexpected lookup")
		},
	}, time.Second, 1024)
	for _, key := range []string{"", testAPIKey} {
		r := httptest.NewRequest("GET", "/health", nil)
		r.Header.Set(headerAPIKey, key)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusNoContent || w.Body.Len() != 0 || calls.Load() != 0 {
			t.Fatalf("health changed: status%d body%q downstream%d", w.Code, w.Body.String(), calls.Load())
		}
	}
}

func TestLaunchObservationHealthQueryRequiresAuthAndPinsNode(t *testing.T) {
	const id = "550e8400-e29b-41d4-a716-446655440000"
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/launch-observations/"+id || r.URL.RawQuery != "" || r.Header.Get(headerAPIKey) != testAPIKey {
			t.Errorf("unexpected node request %s %s", r.Method, r.URL.String())
		}
		fmt.Fprintf(w, `{"attempt_id":%q,"phase":"loading_snapshot","elapsed_ms":5,"done":false}`, id)
	}))
	defer upstream.Close()
	s := newTestServer(t, stubSchedulerClient{}, time.Second, 1024)
	now := time.Now()
	s.launchObservations.reserve(id, now)
	s.launchObservations.bind(id, &schedulerv1.Node{NodeId: "exact", Endpoint: upstream.URL}, now)
	for _, tc := range []struct {
		query, key string
		want       int
	}{
		{"launch_observation=" + id, "", 401},
		{"launch_observation=" + id, "wrong", 401},
		{"launch_observation=invalid", testAPIKey, 400},
		{"launch_observation=", testAPIKey, 400},
		{"launch_observation=" + id + "&launch_observation=" + id, testAPIKey, 400},
		{"launch_observation=550e8400-e29b-41d4-a716-446655440001", testAPIKey, 404},
		{"launch_observation=" + id, testAPIKey, 200},
	} {
		r := httptest.NewRequest("GET", "/health?"+tc.query, nil)
		r.Header.Set(headerAPIKey, tc.key)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s: got%d want%d", tc.query, w.Code, tc.want)
		}
		if tc.want != 200 && calls.Load() != 0 {
			t.Fatal("denial reached node")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("node calls=%d", calls.Load())
	}
}
