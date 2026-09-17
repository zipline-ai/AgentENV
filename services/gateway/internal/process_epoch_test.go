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

func TestDormantProcessEpochRoutesNeverResolveOrSchedule(t *testing.T) {
	for _, path := range []string{
		"/sandboxes/runtime-a/process-epochs/seal",
		"/sandboxes/runtime-a/process-epochs/bind",
		"/sandboxes/runtime-a/process-epoch-operations/operation-a",
		"/proxy/sandboxes/runtime-a/process-epochs/seal",
		"/sandboxes/runtime-a/process%2depochs/seal",
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
				if len(calls) != 0 {
					t.Fatalf("reserved process route performed downstream work: %v", calls)
				}
			})
		}
	}
}
