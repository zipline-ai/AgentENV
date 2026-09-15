package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func operationPinFixture() operationPin {
	p := operationPin{TenantID: "ten-A", LaunchID: "11111111-1111-4111-8111-111111111111", OperationKey: "restore-A", RequestSHA256: strings.Repeat("a", 64), ProviderBodySHA256: strings.Repeat("b", 64), Generation: 4, State: "pending"}
	p.Allocation = restoreAllocation{Version: 1, Protocol: asyncRestoreProtocol, NodeID: "node-A", NodeIncarnation: "node-boot-A", NodeEndpoint: "https://node-a.test", RuntimeID: "22222222-2222-4222-8222-222222222222", RuntimeIncarnation: "33333333-3333-4333-8333-333333333333", VCPUs: 4}
	p.Allocation.NodeRoute.Kind = "native_host"
	p.Allocation.NodeRoute.ProviderID = "agentenv"
	p.Allocation.NodeRoute.HostID = "node-A"
	return p
}

func TestOperationPinReadsExactProofAndSavedCoordinates(t *testing.T) {
	for _, state := range []string{"pending", "running", "terminal"} {
		t.Run(state, func(t *testing.T) {
			pin := operationPinFixture()
			pin.State = state
			var calls atomic.Int32
			app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "GET" || r.URL.RequestURI() != "/api/runtime-operation-pins/lookup" || r.Header.Get("Authorization") != "Bearer exact-proof" || r.Header.Get(headerAPIKey) != "" {
					t.Errorf("unexpected callback request method/path/headers")
				}
				_ = json.NewEncoder(w).Encode(pin)
			}))
			defer app.Close()
			client, err := newOperationPinClient(app.URL + "/api/runtime-operation-pins/lookup")
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.lookup(t.Context(), "exact-proof", pin.OperationKey, pin.RequestSHA256)
			if err != nil || got != pin || calls.Load() != 1 {
				t.Fatalf("pin=%+v err=%v calls=%d", got, err, calls.Load())
			}
		})
	}
}

func TestOperationPinDeniesChangedBindingsAndMalformedResponses(t *testing.T) {
	for _, name := range []string{"foreign operation", "foreign hash", "foreign host", "wrong protocol", "equal incarnations", "credentials in endpoint", "unknown field", "oversized", "second JSON", "missing", "server error"} {
		t.Run(name, func(t *testing.T) {
			want := operationPinFixture()
			pin := want
			switch name {
			case "foreign operation":
				pin.OperationKey = "restore-B"
			case "foreign hash":
				pin.RequestSHA256 = strings.Repeat("c", 64)
			case "foreign host":
				pin.Allocation.NodeRoute.HostID = "node-B"
			case "wrong protocol":
				pin.Allocation.Protocol = "sync"
			case "equal incarnations":
				pin.Allocation.RuntimeIncarnation = pin.Allocation.RuntimeID
			case "credentials in endpoint":
				pin.Allocation.NodeEndpoint = "https://user:secret@node-a.test"
			}
			app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if name == "missing" {
					http.NotFound(w, r)
					return
				}
				if name == "server error" {
					http.Error(w, "sensitive upstream failure", 500)
					return
				}
				wire, _ := json.Marshal(pin)
				if name == "unknown field" {
					wire = append([]byte(`{"extra":true,`), wire[1:]...)
				}
				if name == "oversized" {
					wire = []byte(strings.Repeat(" ", maxOperationPinBytes+1))
				}
				if name == "second JSON" {
					wire = append(wire, []byte(`{}`)...)
				}
				_, _ = w.Write(wire)
			}))
			defer app.Close()
			client, err := newOperationPinClient(app.URL)
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.lookup(t.Context(), "exact-proof", want.OperationKey, want.RequestSHA256)
			wantError := errOperationPinUnavailable
			if name == "missing" {
				wantError = errOperationPinNotFound
			}
			if !errors.Is(err, wantError) || got != (operationPin{}) {
				t.Fatalf("accepted %s: %+v %v", name, got, err)
			}
		})
	}
}

func TestOperationPinNeverFollowsRedirectOrReadsForInvalidProof(t *testing.T) {
	var foreignCalls, appCalls atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { foreignCalls.Add(1) }))
	defer foreign.Close()
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appCalls.Add(1)
		http.Redirect(w, r, foreign.URL, http.StatusTemporaryRedirect)
	}))
	defer app.Close()
	client, err := newOperationPinClient(app.URL)
	if err != nil {
		t.Fatal(err)
	}
	pin := operationPinFixture()
	for _, proof := range []string{"", "contains space", strings.Repeat("x", 4097)} {
		_, err = client.lookup(t.Context(), proof, pin.OperationKey, pin.RequestSHA256)
		if !errors.Is(err, errOperationPinNotFound) {
			t.Fatal(err)
		}
	}
	if appCalls.Load() != 0 {
		t.Fatalf("invalid proofs made %d calls", appCalls.Load())
	}
	_, err = client.lookup(t.Context(), "exact-proof", pin.OperationKey, pin.RequestSHA256)
	if !errors.Is(err, errOperationPinUnavailable) || appCalls.Load() != 1 || foreignCalls.Load() != 0 {
		t.Fatalf("redirect: err=%v app=%d foreign=%d", err, appCalls.Load(), foreignCalls.Load())
	}
}

func TestOperationPinCancellationDoesNotReturnLateRoute(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_ = json.NewEncoder(w).Encode(operationPinFixture())
	}))
	defer app.Close()
	client, err := newOperationPinClient(app.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	pin := operationPinFixture()
	go func() {
		_, err := client.lookup(ctx, "exact-proof", pin.OperationKey, pin.RequestSHA256)
		result <- err
	}()
	<-entered
	cancel()
	err = <-result
	close(release)
	if !errors.Is(err, errOperationPinUnavailable) {
		t.Fatalf("late lookup: %v", err)
	}
}
