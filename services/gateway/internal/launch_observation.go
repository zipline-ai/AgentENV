package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	schedulerv1 "agentenv/services/api/proto"
	"github.com/google/uuid"
)

const headerLaunchAttempt = "X-Agentenv-Launch-Attempt"
const launchObservationTTL = 10 * time.Minute
const launchObservationCapacity = 4096

type launchObservationRoute struct {
	nodeID, endpoint string
	expires          time.Time
	suppressed       bool
}
type launchObservationRoutes struct {
	sync.Mutex
	entries map[string]launchObservationRoute
}

func validLaunchAttempt(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed.String() == id && parsed != uuid.Nil
}
func isLaunchObservationPath(path string) bool {
	return path == "/launch-observations" || strings.HasPrefix(path, "/launch-observations/")
}
func isObservedLaunchRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	path := strings.TrimRight(r.URL.Path, "/")
	if path == "/sandboxes" || path == "/sandboxes-cold" {
		return true
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 3 && parts[0] == "sandboxes" && parts[1] != "" && (parts[2] == "connect" || parts[2] == "resume")
}
func (m *launchObservationRoutes) reserve(id string, now time.Time) int {
	m.Lock()
	defer m.Unlock()
	if m.entries == nil {
		m.entries = make(map[string]launchObservationRoute)
	}
	for key, value := range m.entries {
		if !now.Before(value.expires) {
			delete(m.entries, key)
		}
	}
	if entry, exists := m.entries[id]; exists {
		entry.suppressed = true
		m.entries[id] = entry
		return http.StatusConflict
	}
	if len(m.entries) >= launchObservationCapacity {
		return http.StatusServiceUnavailable
	}
	m.entries[id] = launchObservationRoute{expires: now.Add(launchObservationTTL)}
	return 0
}
func (m *launchObservationRoutes) bind(id string, node *schedulerv1.Node, reservedAt time.Time) {
	m.Lock()
	defer m.Unlock()
	entry, ok := m.entries[id]
	if !ok || entry.suppressed || !entry.expires.Equal(reservedAt.Add(launchObservationTTL)) {
		return
	}
	entry.nodeID = node.GetNodeId()
	entry.endpoint = node.GetEndpoint()
	m.entries[id] = entry
}
func (m *launchObservationRoutes) lookup(id string, now time.Time) (launchObservationRoute, bool) {
	m.Lock()
	defer m.Unlock()
	entry, ok := m.entries[id]
	if !ok || !now.Before(entry.expires) {
		delete(m.entries, id)
		return launchObservationRoute{}, false
	}
	return entry, !entry.suppressed && entry.endpoint != ""
}

// This map describes a dispatch; it never grants placement or resume authority.
// Pin the selected endpoint and opaque attempt, not a mutable sandbox lookup.
// A restarted node has no matching attempt, so it cannot substitute a new launch.
func (s *Server) handleLaunchObservation(w http.ResponseWriter, r *http.Request) {
	setGatewayRouteSource(w, routeSourceGateway)
	id := strings.TrimPrefix(r.URL.Path, "/launch-observations/")
	if !validLaunchAttempt(id) {
		http.Error(w, "invalid launch attempt", http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	entry, ok := s.launchObservations.lookup(id, time.Now())
	if !ok {
		http.NotFound(w, r)
		return
	}
	target, err := joinUpstream(entry.endpoint, r.URL.Path, "", "")
	if err != nil {
		http.Error(w, "observation unavailable", http.StatusBadGateway)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "observation unavailable", http.StatusBadGateway)
		return
	}
	req.Header.Set(headerAPIKey, string(s.apiKey))
	// Do not follow redirects to a different runtime, even if its host is reused.
	client := *s.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "observation unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		http.NotFound(w, r)
		return
	}
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "observation unavailable", http.StatusBadGateway)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(body) > 4096 {
		http.Error(w, "observation unavailable", http.StatusBadGateway)
		return
	}
	var sample struct {
		AttemptID string  `json:"attempt_id"`
		SandboxID *string `json:"sandbox_id,omitempty"`
		Phase     string  `json:"phase"`
		ElapsedMS uint64  `json:"elapsed_ms"`
		Done      bool    `json:"done"`
	}
	decodeErr := json.Unmarshal(body, &sample)
	if decodeErr == nil && sample.AttemptID == id && sample.Phase == "unknown" {
		http.NotFound(w, r)
		return
	}
	if decodeErr != nil || sample.AttemptID != id || (sample.Phase != "fetching_snapshot" && sample.Phase != "loading_snapshot" && sample.Phase != "booting_guest") {
		http.Error(w, "observation unavailable", http.StatusBadGateway)
		return
	}
	s.writeJSON(w, http.StatusOK, sample)
}
