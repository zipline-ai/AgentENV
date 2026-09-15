package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	schedulerv1 "agentenv/services/api/proto"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func TestOperationPollUsesOnlyDurablePinAndStripsProof(t *testing.T) {
	for _, scenario := range []string{"success", "missing pin", "callback outage", "foreign operation", "missing proof", "proxy auth bypass", "node redirect", "absent config"} {
		t.Run(scenario, func(t *testing.T) {
			var schedules, lookups, assignments, callbacks, nodeCalls, foreignCalls atomic.Int32
			pin := operationPinFixture()
			pin.OperationKey = "44444444-4444-4444-8444-444444444444"
			foreign := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { foreignCalls.Add(1) }))
			defer foreign.Close()
			node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nodeCalls.Add(1)
				if r.Method != "GET" || r.URL.RequestURI() != "/sandbox-operations/"+pin.OperationKey || r.Header.Get(headerAPIKey) != "fleet-key" || r.Header.Get(headerOperationHash) != pin.RequestSHA256 || r.Header.Get(headerOperationTenant) != pin.TenantID || r.Header.Get(headerOperationNodeIncarnation) != pin.Allocation.NodeIncarnation || r.Header.Get(headerOperationRuntime) != pin.Allocation.RuntimeID || r.Header.Get(headerOperationRuntimeIncarnation) != pin.Allocation.RuntimeIncarnation {
					t.Error("wrong exact poll target or captured fence")
				}
				if r.Header.Get(headerOperationPinProof) != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("guest received unrelated credential")
				}
				if scenario == "node redirect" {
					http.Redirect(w, r, foreign.URL, http.StatusTemporaryRedirect)
					return
				}
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(`{"state":"pending"}`))
			}))
			defer node.Close()
			pin.Allocation.NodeEndpoint = node.URL
			app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callbacks.Add(1)
				if r.Header.Get("Authorization") != "Bearer saved-proof" {
					t.Error("wrong callback proof")
				}
				if scenario == "missing pin" {
					http.NotFound(w, r)
					return
				}
				if scenario == "callback outage" {
					http.Error(w, "database failure", 500)
					return
				}
				answer := pin
				if scenario == "foreign operation" {
					answer.OperationKey = "55555555-5555-4555-8555-555555555555"
				}
				_ = json.NewEncoder(w).Encode(answer)
			}))
			defer app.Close()
			scheduler := stubSchedulerClient{
				scheduleFunc: func(context.Context, *schedulerv1.ScheduleRequest, ...grpc.CallOption) (*schedulerv1.ScheduleResponse, error) {
					schedules.Add(1)
					return nil, fmt.Errorf("unexpected schedule")
				},
				lookupNodeFunc: func(context.Context, *schedulerv1.LookupNodeRequest, ...grpc.CallOption) (*schedulerv1.LookupNodeResponse, error) {
					lookups.Add(1)
					return nil, fmt.Errorf("unexpected lookup")
				},
				recordAssignmentFunc: func(context.Context, *schedulerv1.RecordAssignmentRequest, ...grpc.CallOption) (*schedulerv1.RecordAssignmentResponse, error) {
					assignments.Add(1)
					return nil, fmt.Errorf("unexpected assignment")
				},
			}
			endpoint := app.URL
			if scenario == "absent config" {
				endpoint = ""
			}
			server, err := NewServer(zap.NewNop(), scheduler, ServerOptions{APIKey: "fleet-key", OperationPinLookupURL: endpoint, RequestTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("GET", "http://gateway.test/sandbox-operations/"+pin.OperationKey, nil)
			r.Header.Set(headerAPIKey, "fleet-key")
			r.Header.Set(headerOperationPinProof, "saved-proof")
			r.Header.Set(headerOperationHash, pin.RequestSHA256)
			r.Header.Set("Cookie", "unrelated-session")
			r.Header.Set("Authorization", "Bearer unrelated-token")
			wantStatus, wantCallbacks, wantNodes := http.StatusNotFound, int32(1), int32(0)
			switch scenario {
			case "foreign operation", "callback outage":
				wantStatus = http.StatusServiceUnavailable
			case "success":
				wantStatus, wantNodes = http.StatusAccepted, 1
			case "node redirect":
				wantStatus, wantNodes = http.StatusBadGateway, 1
			case "missing proof":
				r.Header.Del(headerOperationPinProof)
				wantCallbacks = 0
			case "proxy auth bypass":
				r.Header.Del(headerAPIKey)
				r.Header.Set(headerSandboxID, "foreign-runtime")
				r.Header.Set(headerTargetPort, "49983")
				wantStatus, wantCallbacks = http.StatusUnauthorized, 0
			case "absent config":
				wantCallbacks = 0
			}
			w := httptest.NewRecorder()
			server.Handler().ServeHTTP(w, r)
			if w.Code != wantStatus || callbacks.Load() != wantCallbacks || nodeCalls.Load() != wantNodes || schedules.Load() != 0 || lookups.Load() != 0 || assignments.Load() != 0 || foreignCalls.Load() != 0 {
				t.Fatalf("status=%d callback=%d node=%d schedule=%d lookup=%d assignments=%d foreign=%d", w.Code, callbacks.Load(), nodeCalls.Load(), schedules.Load(), lookups.Load(), assignments.Load(), foreignCalls.Load())
			}
			if scenario == "success" && w.Body.String() != `{"state":"pending"}` {
				t.Fatalf("body=%s", w.Body.String())
			}
			if strings.Contains(w.Body.String(), "saved-proof") || strings.Contains(w.Body.String(), "unrelated") {
				t.Fatal("credential leaked")
			}
		})
	}
}

func TestOperationPinConfigurationFailsClosed(t *testing.T) {
	for _, endpoint := range []string{"not-a-url", "file:///tmp/pins", "https://user:secret@app.test/lookup", "https://app.test/lookup?proof=secret", "https://app.test/lookup#fragment"} {
		_, err := NewServer(zap.NewNop(), stubSchedulerClient{}, ServerOptions{APIKey: "fleet-key", OperationPinLookupURL: endpoint})
		if err == nil {
			t.Fatalf("accepted callback endpoint %q", endpoint)
		}
	}
}
