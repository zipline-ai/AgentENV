package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

func TestOperationDispatchUsesOnlyCommittedPin(t *testing.T) {
	for _, scenario := range []string{"accepted", "changed body", "changed allocation", "terminal pin", "missing proof", "guest headers", "redirect", "lost response"} {
		t.Run(scenario, func(t *testing.T) {
			var schedules, nodes, foreignCalls atomic.Int32
			pin := operationPinFixture()
			pin.OperationKey = "44444444-4444-4444-8444-444444444444"
			pin.State = "pending"
			var wire string
			foreign := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { foreignCalls.Add(1) }))
			defer foreign.Close()
			node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nodes.Add(1)
				body, _ := io.ReadAll(r.Body)
				if r.Method != "POST" || r.URL.RequestURI() != "/sandboxes" || string(body) != wire || r.Header.Get(headerAPIKey) != "fleet-key" || r.Header.Get("Idempotency-Key") != pin.OperationKey || r.Header.Get("X-Agentenv-Async-Restore") != asyncRestoreProtocol || r.Header.Get(headerOperationHash) != pin.RequestSHA256 || r.Header.Get("X-Agentenv-Operation-Body-Sha256") != pin.ProviderBodySHA256 || r.Header.Get(headerOperationTenant) != pin.TenantID || r.Header.Get(headerOperationRuntime) != pin.Allocation.RuntimeID || r.Header.Get(headerOperationRuntimeIncarnation) != pin.Allocation.RuntimeIncarnation || r.Header.Get(headerOperationNodeIncarnation) != pin.Allocation.NodeIncarnation {
					t.Error("dispatch changed captured target, body, or fences")
				}
				if r.Header.Get(headerOperationPinProof) != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("unrelated credential forwarded")
				}
				if scenario == "redirect" {
					http.Redirect(w, r, foreign.URL, 307)
					return
				}
				if scenario == "lost response" {
					conn, _, _ := w.(http.Hijacker).Hijack()
					_ = conn.Close()
					return
				}
				w.WriteHeader(202)
				_, _ = w.Write([]byte(`{"state":"unknown"}`))
			}))
			defer node.Close()
			pin.Allocation.NodeEndpoint = node.URL
			body, _ := json.Marshal(map[string]any{"snapshotId": "snapshot-A", "async_restore": pin.Allocation})
			wire = string(body)
			digest := sha256.Sum256(body)
			pin.ProviderBodySHA256 = hex.EncodeToString(digest[:])
			if scenario == "changed allocation" {
				pin.Allocation.RuntimeID = "55555555-5555-4555-8555-555555555555"
			}
			if scenario == "terminal pin" {
				pin.State = "terminal"
			}
			app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer saved-proof" {
					t.Error("wrong proof")
				}
				_ = json.NewEncoder(w).Encode(pin)
			}))
			defer app.Close()
			scheduler := stubSchedulerClient{
				scheduleFunc: func(context.Context, *schedulerv1.ScheduleRequest, ...grpc.CallOption) (*schedulerv1.ScheduleResponse, error) {
					schedules.Add(1)
					return nil, fmt.Errorf("unexpected scheduling")
				},
				lookupNodeFunc: func(context.Context, *schedulerv1.LookupNodeRequest, ...grpc.CallOption) (*schedulerv1.LookupNodeResponse, error) {
					schedules.Add(1)
					return nil, fmt.Errorf("unexpected lookup")
				},
				recordAssignmentFunc: func(context.Context, *schedulerv1.RecordAssignmentRequest, ...grpc.CallOption) (*schedulerv1.RecordAssignmentResponse, error) {
					schedules.Add(1)
					return nil, fmt.Errorf("unexpected assignment")
				},
			}
			server, err := NewServer(zap.NewNop(), scheduler, ServerOptions{APIKey: "fleet-key", OperationPinLookupURL: app.URL, RequestTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			gateway := httptest.NewServer(server.Handler())
			defer gateway.Close()
			sent := wire
			if scenario == "changed body" {
				sent += " "
			}
			r, _ := http.NewRequest("POST", gateway.URL+"/sandboxes", strings.NewReader(sent))
			r.Header.Set(headerAPIKey, "fleet-key")
			r.Header.Set(headerOperationPinProof, "saved-proof")
			r.Header.Set(headerOperationHash, pin.RequestSHA256)
			r.Header.Set("X-Agentenv-Async-Restore", asyncRestoreProtocol)
			r.Header.Set("Idempotency-Key", pin.OperationKey)
			r.Header.Set("Cookie", "unrelated")
			r.Header.Set("Authorization", "Bearer unrelated")
			want, wantNodes := 409, int32(0)
			switch scenario {
			case "accepted":
				want, wantNodes = 202, 1
			case "missing proof":
				r.Header.Del(headerOperationPinProof)
				want = 404
			case "guest headers":
				r.Header.Del(headerAPIKey)
				r.Header.Set(headerSandboxID, "foreign-runtime")
				r.Header.Set(headerTargetPort, "49983")
				want = 401
			case "redirect", "lost response":
				want, wantNodes = 502, 1
			}
			response, err := gateway.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			responseBody, _ := io.ReadAll(response.Body)
			if response.StatusCode != want || nodes.Load() != wantNodes || schedules.Load() != 0 || foreignCalls.Load() != 0 {
				t.Fatalf("status=%d nodes=%d scheduler=%d foreign=%d body=%s", response.StatusCode, nodes.Load(), schedules.Load(), foreignCalls.Load(), responseBody)
			}
		})
	}
}
