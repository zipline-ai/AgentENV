package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	headerOperationPinProof           = "X-Agentenv-Operation-Pin-Proof"
	headerOperationHash               = "X-Agentenv-Operation-Request-Sha256"
	headerOperationTenant             = "X-Agentenv-Operation-Tenant"
	headerOperationNodeIncarnation    = "X-Agentenv-Operation-Node-Incarnation"
	headerOperationRuntime            = "X-Agentenv-Operation-Runtime"
	headerOperationRuntimeIncarnation = "X-Agentenv-Operation-Runtime-Incarnation"
)

func isOperationRequest(r *http.Request) bool {
	return isOperationDispatch(r) || r.URL.Path == "/sandbox-operations" || strings.HasPrefix(r.URL.Path, "/sandbox-operations/")
}

func oneOperationHeader(r *http.Request, name string) string {
	values := r.Header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

func (s *Server) handleOperationPoll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if isOperationDispatch(r) {
		s.handleOperationDispatch(w, r)
		return
	}
	if r.URL.Path == "/sandbox-operations/select" && r.Method == http.MethodPost {
		s.handleOperationSelection(w, r)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/sandbox-operations/")
	if s.operationPins == nil || r.Method != http.MethodGet || !validOperationUUID(key) || r.URL.RawQuery != "" || r.URL.RawPath != "" || hasProxyRoutingHeaders(r.Header) {
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
	// Polling is never a Schedule/LookupNode/RecordAssignment operation. Only
	// the route committed with the original dispatch may receive this request.
	target, err := joinUpstream(pin.Allocation.NodeEndpoint, r.URL.Path, "", "")
	if err != nil {
		http.Error(w, "operation unavailable", http.StatusBadGateway)
		return
	}
	upstream, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "operation unavailable", http.StatusBadGateway)
		return
	}
	// Build a fresh header map: the app's pin-read bearer and arbitrary guest
	// headers never leave the gateway. The node receives only captured fences.
	upstream.Header.Set(headerAPIKey, string(s.apiKey))
	upstream.Header.Set(headerOperationHash, pin.RequestSHA256)
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
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		status := http.StatusBadGateway
		if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusConflict {
			status = response.StatusCode
		}
		http.Error(w, "operation unavailable", status)
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 {
		http.Error(w, "operation unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(body)
}
