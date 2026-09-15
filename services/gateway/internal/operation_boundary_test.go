package gateway

import (
	"bufio"
	"context"
	"fmt"
	"net"
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

func TestOperationSelectionBoundsSlowBodyThroughMetricsWrapper(t *testing.T) {
	var calls atomic.Int32
	scheduler := stubSchedulerClient{scheduleFunc: func(context.Context, *schedulerv1.ScheduleRequest, ...grpc.CallOption) (*schedulerv1.ScheduleResponse, error) {
		calls.Add(1)
		return nil, fmt.Errorf("unexpected schedule")
	}}
	server, err := NewServer(zap.NewNop(), scheduler, ServerOptions{APIKey: "fleet-key", OperationPinLookupURL: "https://app.test/lookup", RequestTimeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewServer(server.Handler())
	defer listener.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(listener.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, err = fmt.Fprint(conn, "POST /sandbox-operations/select HTTP/1.1\r\nHost: gateway.test\r\nX-API-Key: fleet-key\r\nContent-Length: 100\r\n\r\n{")
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("selection did not enforce its body deadline: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || calls.Load() != 0 {
		t.Fatalf("status=%d scheduler calls=%d", response.StatusCode, calls.Load())
	}
}

func TestOrdinaryProxyNeverForwardsOperationPinProof(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get(headerOperationPinProof) != "" {
			t.Error("operation pin proof leaked through ordinary proxy")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	scheduler := stubSchedulerClient{lookupNodeFunc: func(_ context.Context, r *schedulerv1.LookupNodeRequest, _ ...grpc.CallOption) (*schedulerv1.LookupNodeResponse, error) {
		if r.SandboxId != "exact-runtime" {
			t.Error("wrong runtime target")
		}
		return &schedulerv1.LookupNodeResponse{Node: &schedulerv1.Node{NodeId: "node-A", Endpoint: upstream.URL}}, nil
	}}
	server, err := NewServer(zap.NewNop(), scheduler, ServerOptions{APIKey: "fleet-key", RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://gateway.test/sandboxes/exact-runtime", nil)
	r.Header.Set(headerAPIKey, "fleet-key")
	r.Header.Set(headerOperationPinProof, "private-app-proof")
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || calls.Load() != 1 {
		t.Fatalf("status=%d calls=%d", w.Code, calls.Load())
	}
}
