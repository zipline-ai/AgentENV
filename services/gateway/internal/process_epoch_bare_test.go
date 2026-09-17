package gateway

import (
	schedulerv1 "agentenv/services/api/proto"
	"context"
	"fmt"
	"google.golang.org/grpc"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReviewC2GuestEpochPathsNeverResolveOrSchedule(t *testing.T) {
	for _, path := range []string{
		"/process-epochs/seal",
		"/process-epoch-operations/operation-a",
		"/process-epochs/unsupported",
		"/process-epoch-operations",
		"/proxy/process-epochs/seal",
		"/proxy/process-epoch-operations/operation-a",
		"/proxy/proxy/process-epochs/seal",
		"/process%2depochs/seal",
		"/process%252depoch-operations/operation-a",
		"/proxy%2fprocess-epochs%2fseal",
		"/sandboxes/runtime-a/process-epochs/seal",
		"/sandboxes/runtime-a/process-epoch-operations/operation-a",
	} {
		for _, route := range []string{"plain", "host", "headers"} {
			t.Run(route+path, func(t *testing.T) {
				var calls []string
				scheduler := stubSchedulerClient{
					scheduleFunc: func(_ context.Context, r *schedulerv1.ScheduleRequest, _ ...grpc.CallOption) (*schedulerv1.ScheduleResponse, error) {
						calls = append(calls, fmt.Sprintf("Schedule(%v)", r))
						return nil, fmt.Errorf("unexpected schedule")
					},
					lookupNodeFunc: func(_ context.Context, r *schedulerv1.LookupNodeRequest, _ ...grpc.CallOption) (*schedulerv1.LookupNodeResponse, error) {
						calls = append(calls, fmt.Sprintf("LookupNode(%v)", r))
						return nil, fmt.Errorf("unexpected lookup")
					},
					recordAssignmentFunc: func(_ context.Context, r *schedulerv1.RecordAssignmentRequest, _ ...grpc.CallOption) (*schedulerv1.RecordAssignmentResponse, error) {
						calls = append(calls, fmt.Sprintf("RecordAssignment(%v)", r))
						return nil, fmt.Errorf("unexpected assignment")
					},
				}
				server := newTestServer(t, scheduler, time.Second, 1024, withSandboxProxyDomains("sandbox-proxy.example.invalid"))
				req := httptest.NewRequest(http.MethodPost, "http://gateway.test"+path, nil)
				if route == "host" {
					req.Host = "49983-runtime-a.sandbox-proxy.example.invalid"
				}
				if route == "headers" {
					req.Header.Set(headerSandboxID, "runtime-a")
					req.Header.Set(headerTargetPort, "49983")
				}
				w := httptest.NewRecorder()
				authenticatedTestHandler(server).ServeHTTP(w, req)
				if w.Code != http.StatusServiceUnavailable {
					t.Errorf("status=%d, body=%q", w.Code, w.Body.String())
				}
				if w.Body.String() != "managed process epochs unavailable\n" {
					t.Errorf("unexpected fixed denial: %q", w.Body.String())
				}
				if len(calls) != 0 {
					t.Fatalf("reserved process route performed downstream work: %v", calls)
				}
			})
		}
	}
}

// Refusal prevents the entire downstream chain, including guest forwarding.
func TestBareProcessEpochRefusalNeverEntersDownstream(t *testing.T) {
	for _, path := range []string{"/process-epochs/seal", "/process-epoch-operations/operation-a"} {
		for _, route := range []string{"plain", "host", "headers", "proxy"} {
			t.Run(route+path, func(t *testing.T) {
				calls := 0
				handler := refuseDormantProcessEpoch(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(200) }))
				uri := path
				if route == "proxy" {
					uri = "/proxy" + path
				}
				req := httptest.NewRequest(http.MethodPost, uri, nil)
				if route == "host" {
					req.Host = "49983-runtime-a.sandbox-proxy.example.invalid"
				}
				if route == "headers" {
					req.Header.Set(headerSandboxID, "runtime-a")
					req.Header.Set(headerTargetPort, "49983")
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				if calls != 0 || w.Code != 503 || w.Body.String() != "managed process epochs unavailable\n" {
					t.Fatalf("calls=%d status=%d body=%q", calls, w.Code, w.Body.String())
				}
			})
		}
	}
}
