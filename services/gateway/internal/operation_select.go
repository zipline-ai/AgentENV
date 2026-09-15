package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	schedulerv1 "agentenv/services/api/proto"
)

type operationNodeCapability struct {
	Version         int    `json:"version"`
	Protocol        string `json:"protocol"`
	NodeID          string `json:"node_id"`
	NodeIncarnation string `json:"node_incarnation"`
}

type selectedOperationNode struct {
	operationNodeCapability
	NodeEndpoint string `json:"node_endpoint"`
}

func (s *Server) handleOperationSelection(w http.ResponseWriter, r *http.Request) {
	if s.operationPins == nil || r.URL.RawQuery != "" || r.URL.RawPath != "" || hasProxyRoutingHeaders(r.Header) {
		http.Error(w, "async restore unavailable", http.StatusNotFound)
		return
	}
	host, err := parseHostRoute(r.Host, s.sandboxProxyDomains)
	if err != nil || host != nil {
		http.Error(w, "async restore unavailable", http.StatusNotFound)
		return
	}
	bound := s.requestTimeout
	if bound <= 0 || bound > 5*time.Second {
		bound = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), bound)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := http.NewResponseController(w).SetReadDeadline(deadline); err != nil {
		http.Error(w, "selection deadline unavailable", http.StatusServiceUnavailable)
		return
	}
	// This request selects a descriptor only. It is not a create request and
	// cannot reserve a runtime, write an assignment, or start snapshot work.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxHintBodyBytes))
	if err != nil || !json.Valid(body) {
		http.Error(w, "invalid restore selection", http.StatusBadRequest)
		return
	}
	selected, err := s.scheduler.Schedule(ctx, &schedulerv1.ScheduleRequest{Hint: &schedulerv1.ScheduleRequestHint{Kind: &schedulerv1.ScheduleRequestHint_NewSandbox{NewSandbox: parseNewSandboxHint(body)}}})
	if err != nil {
		s.writeSchedulerError(w, err)
		return
	}
	node := selected.GetNode()
	if node == nil || node.GetNodeId() == "" || !validOperationEndpoint(node.GetEndpoint()) {
		http.Error(w, "async restore unavailable", http.StatusServiceUnavailable)
		return
	}
	target, err := joinUpstream(node.GetEndpoint(), "/sandbox-operations/capabilities", "", "")
	if err != nil {
		http.Error(w, "async restore unavailable", http.StatusServiceUnavailable)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "async restore unavailable", http.StatusServiceUnavailable)
		return
	}
	req.Header.Set(headerAPIKey, string(s.apiKey))
	client := &http.Client{Transport: s.httpClient.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		http.Error(w, "async restore unavailable", http.StatusServiceUnavailable)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		http.Error(w, "async restore unavailable", http.StatusNotImplemented)
		return
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(wire) > 4096 {
		http.Error(w, "async restore unavailable", http.StatusBadGateway)
		return
	}
	var capability operationNodeCapability
	d := json.NewDecoder(bytes.NewReader(wire))
	d.DisallowUnknownFields()
	if d.Decode(&capability) != nil || d.Decode(new(any)) != io.EOF || capability.Version != 1 || capability.Protocol != asyncRestoreProtocol || capability.NodeID != node.GetNodeId() || capability.NodeIncarnation == "" {
		http.Error(w, "async restore unavailable", http.StatusNotImplemented)
		return
	}
	// Transport endpoint is the scheduler-selected address, never an address
	// advertised by a guest or supplied by the original caller.
	s.writeJSON(w, http.StatusOK, selectedOperationNode{operationNodeCapability: capability, NodeEndpoint: node.GetEndpoint()})
}
