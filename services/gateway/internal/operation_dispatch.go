package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

const headerAsyncRestore = "X-Agentenv-Async-Restore"
const headerOperationBodyHash = "X-Agentenv-Operation-Body-Sha256"

func isOperationDispatch(r *http.Request) bool {
	// Even an invalid opt-in must not fall through to legacy scheduling.
	_, present := r.Header[http.CanonicalHeaderKey(headerAsyncRestore)]
	return r.URL.Path == "/sandboxes" && present
}

func (s *Server) handleOperationDispatch(w http.ResponseWriter, r *http.Request) {
	key := oneOperationHeader(r, "Idempotency-Key")
	if s.operationPins == nil || r.Method != http.MethodPost || oneOperationHeader(r, headerAsyncRestore) != asyncRestoreProtocol || !validOperationUUID(key) || r.URL.RawQuery != "" || r.URL.RawPath != "" || hasProxyRoutingHeaders(r.Header) {
		http.Error(w, "operation unavailable", http.StatusNotFound)
		return
	}
	host, err := parseHostRoute(r.Host, s.sandboxProxyDomains)
	if err != nil || host != nil {
		http.Error(w, "operation unavailable", http.StatusNotFound)
		return
	}
	bound := s.requestTimeout
	if bound <= 0 || bound > 10*time.Second {
		bound = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), bound)
	defer cancel()
	pin, err := s.operationPins.lookup(ctx, oneOperationHeader(r, headerOperationPinProof), key, oneOperationHeader(r, headerOperationHash))
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, errOperationPinNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, "operation unavailable", status)
		return
	}
	if pin.State == "terminal" {
		http.Error(w, "operation unavailable", http.StatusConflict)
		return
	}
	deadline, _ := ctx.Deadline()
	if http.NewResponseController(w).SetReadDeadline(deadline) != nil {
		http.Error(w, "operation deadline unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "invalid operation body", http.StatusBadRequest)
		return
	}
	digest := sha256.Sum256(body)
	var request struct {
		Allocation restoreAllocation `json:"async_restore"`
	}
	if hex.EncodeToString(digest[:]) != pin.ProviderBodySHA256 || json.Unmarshal(body, &request) != nil || request.Allocation != pin.Allocation {
		http.Error(w, "operation unavailable", http.StatusConflict)
		return
	}
	// This is the already-claimed dispatch. A callback failure, transport timeout,
	// or missing receipt never authorizes scheduling or a second target.
	target, err := joinUpstream(pin.Allocation.NodeEndpoint, "/sandboxes", "", "")
	if err != nil {
		http.Error(w, "operation unavailable", http.StatusBadGateway)
		return
	}
	upstream, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "operation unavailable", http.StatusBadGateway)
		return
	}
	upstream.Header.Set(headerAPIKey, string(s.apiKey))
	upstream.Header.Set("Content-Type", "application/json")
	upstream.Header.Set("Idempotency-Key", pin.OperationKey)
	upstream.Header.Set(headerAsyncRestore, asyncRestoreProtocol)
	upstream.Header.Set(headerOperationHash, pin.RequestSHA256)
	upstream.Header.Set(headerOperationBodyHash, pin.ProviderBodySHA256)
	upstream.Header.Set(headerOperationTenant, pin.TenantID)
	upstream.Header.Set(headerOperationNodeIncarnation, pin.Allocation.NodeIncarnation)
	upstream.Header.Set(headerOperationRuntime, pin.Allocation.RuntimeID)
	upstream.Header.Set(headerOperationRuntimeIncarnation, pin.Allocation.RuntimeIncarnation)
	client := &http.Client{Transport: s.httpClient.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(upstream)
	if err != nil {
		http.Error(w, "operation unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		status := http.StatusBadGateway
		if response.StatusCode == http.StatusConflict {
			status = http.StatusConflict
		}
		http.Error(w, "operation unavailable", status)
		return
	}
	result, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(result) > 64*1024 {
		http.Error(w, "operation unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write(result)
}
