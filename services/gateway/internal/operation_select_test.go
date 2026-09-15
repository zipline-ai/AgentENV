package gateway

import (
	"context"
	"encoding/json"
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

// In-memory requests have complete bodies. The separate real-HTTP slow-body
// test proves that production's recorder actually forwards this deadline.
type operationDeadlineRecorder struct{ *httptest.ResponseRecorder }

func (operationDeadlineRecorder) SetReadDeadline(time.Time) error { return nil }

func TestOperationSelectionProvesNodeWithoutStartingRuntime(t *testing.T) {
	for _, scenario := range []string{"selected", "foreign identity", "unsupported", "redirect", "advertised endpoint", "unconfigured", "unauthenticated"} {
		t.Run(scenario, func(t *testing.T) {
			var schedules, capabilities, launches, foreignCalls atomic.Int32
			foreign := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { foreignCalls.Add(1) }))
			defer foreign.Close()
			node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.RequestURI() != "/sandbox-operations/capabilities" {
					launches.Add(1)
					http.Error(w, "unexpected runtime call", 500)
					return
				}
				capabilities.Add(1)
				if r.Header.Get(headerAPIKey) != "fleet-key" {
					t.Error("missing node authentication")
				}
				if scenario == "redirect" {
					http.Redirect(w, r, foreign.URL, http.StatusTemporaryRedirect)
					return
				}
				if scenario == "unsupported" {
					http.NotFound(w, r)
					return
				}
				capability := map[string]any{"version": 1, "protocol": asyncRestoreProtocol, "node_id": "node-A", "node_incarnation": "boot-A"}
				if scenario == "foreign identity" {
					capability["node_id"] = "node-B"
				}
				if scenario == "advertised endpoint" {
					capability["node_endpoint"] = foreign.URL
				}
				_ = json.NewEncoder(w).Encode(capability)
			}))
			defer node.Close()
			scheduler := stubSchedulerClient{scheduleFunc: func(_ context.Context, r *schedulerv1.ScheduleRequest, _ ...grpc.CallOption) (*schedulerv1.ScheduleResponse, error) {
				schedules.Add(1)
				if r.GetHint().GetNewSandbox() == nil {
					t.Error("missing snapshot hint")
				}
				return &schedulerv1.ScheduleResponse{Node: &schedulerv1.Node{NodeId: "node-A", Endpoint: node.URL}}, nil
			}}
			callback := "https://app.test/api/runtime-operation-pins/lookup"
			if scenario == "unconfigured" {
				callback = ""
			}
			server, err := NewServer(zap.NewNop(), scheduler, ServerOptions{APIKey: "fleet-key", OperationPinLookupURL: callback})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "http://gateway.test/sandbox-operations/select", strings.NewReader(`{"templateID":"saved-snapshot"}`))
			if scenario != "unauthenticated" {
				r.Header.Set(headerAPIKey, "fleet-key")
			}
			w := httptest.NewRecorder()
			server.Handler().ServeHTTP(operationDeadlineRecorder{w}, r)
			wantedCalls, wantedStatus := int32(1), http.StatusNotImplemented
			switch scenario {
			case "selected":
				wantedStatus = http.StatusOK
			case "unconfigured":
				wantedCalls, wantedStatus = 0, http.StatusNotFound
			case "unauthenticated":
				wantedCalls, wantedStatus = 0, http.StatusUnauthorized
			}
			if w.Code != wantedStatus || schedules.Load() != wantedCalls || capabilities.Load() != wantedCalls || launches.Load() != 0 || foreignCalls.Load() != 0 {
				t.Fatalf("status=%d schedules=%d capabilities=%d launches=%d foreign=%d", w.Code, schedules.Load(), capabilities.Load(), launches.Load(), foreignCalls.Load())
			}
			if scenario == "selected" {
				var selected selectedOperationNode
				if json.Unmarshal(w.Body.Bytes(), &selected) != nil || selected.NodeEndpoint != node.URL || selected.NodeID != "node-A" || selected.NodeIncarnation != "boot-A" || selected.Protocol != asyncRestoreProtocol {
					t.Fatalf("descriptor=%s", w.Body.String())
				}
			}
		})
	}
}
