package gateway

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

const asyncRestoreProtocol = "agentenv-async-restore-v1"
const maxOperationPinBytes = 16 << 10

var errOperationPinUnavailable = errors.New("operation pin unavailable")
var errOperationPinNotFound = errors.New("operation pin not found")

// This view comes only from the configured app's authenticated pin reader. It
// is routing evidence, not permission to allocate a replacement runtime.
type operationPin struct {
	TenantID           string            `json:"tenant_id"`
	LaunchID           string            `json:"launch_id"`
	OperationKey       string            `json:"operation_key"`
	RequestSHA256      string            `json:"request_sha256"`
	ProviderBodySHA256 string            `json:"provider_body_sha256"`
	Generation         int64             `json:"generation"`
	State              string            `json:"state"`
	Allocation         restoreAllocation `json:"allocation"`
}

type restoreAllocation struct {
	Version            int    `json:"version"`
	Protocol           string `json:"protocol"`
	NodeID             string `json:"node_id"`
	NodeIncarnation    string `json:"node_incarnation"`
	NodeEndpoint       string `json:"node_endpoint"`
	RuntimeID          string `json:"runtime_id"`
	RuntimeIncarnation string `json:"runtime_incarnation"`
	VCPUs              int64  `json:"vcpus"`
	NodeRoute          struct {
		Kind            string `json:"kind"`
		ProviderID      string `json:"provider_id,omitempty"`
		HostID          string `json:"host_id,omitempty"`
		GatewayEndpoint string `json:"gateway_endpoint,omitempty"`
	} `json:"node_route"`
}

type operationPinClient struct {
	endpoint string
	client   *http.Client
}

// The callback endpoint is operator configuration. No request header, saved
// guest value or redirect can change where the operation read proof is sent.
func newOperationPinClient(endpoint string) (*operationPinClient, error) {
	if !validOperationEndpoint(endpoint) {
		return nil, errOperationPinUnavailable
	}
	return &operationPinClient{endpoint: endpoint, client: &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func validOperationEndpoint(raw string) bool {
	if strings.IndexFunc(raw, unicode.IsSpace) >= 0 || strings.ContainsAny(raw, "\\?#%") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil && u.Opaque == "" && u.String() == raw
}

func validOperationUUID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}

func validOperationHash(raw string) bool {
	digest, err := hex.DecodeString(raw)
	return err == nil && len(digest) == 32 && hex.EncodeToString(digest) == raw
}

func (p operationPin) valid() bool {
	a := p.Allocation
	return p.TenantID != "" && len(p.TenantID) <= 256 && p.OperationKey != "" && len(p.OperationKey) <= 256 && validOperationUUID(p.LaunchID) &&
		validOperationHash(p.RequestSHA256) && validOperationHash(p.ProviderBodySHA256) && p.Generation > 0 &&
		(p.State == "pending" || p.State == "running" || p.State == "terminal") &&
		a.Version == 1 && a.Protocol == asyncRestoreProtocol && a.NodeID != "" && a.NodeIncarnation != "" && a.VCPUs > 0 &&
		validOperationUUID(a.RuntimeID) && validOperationUUID(a.RuntimeIncarnation) && a.RuntimeID != a.RuntimeIncarnation &&
		validOperationEndpoint(a.NodeEndpoint) && a.NodeRoute.Kind == "native_host" && a.NodeRoute.ProviderID == "agentenv" && a.NodeRoute.HostID == a.NodeID && a.NodeRoute.GatewayEndpoint == ""
}

func (c *operationPinClient) lookup(ctx context.Context, proof, operationKey, requestHash string) (operationPin, error) {
	var zero operationPin
	if proof == "" || len(proof) > 4096 || strings.IndexFunc(proof, unicode.IsSpace) >= 0 || !validOperationHash(requestHash) || operationKey == "" || len(operationKey) > 256 {
		return zero, errOperationPinNotFound
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return zero, errOperationPinUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+proof)
	resp, err := c.client.Do(req)
	if err != nil {
		// Do not propagate errors containing the URL, headers or remote body.
		return zero, errOperationPinUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return zero, errOperationPinNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return zero, errOperationPinUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOperationPinBytes+1))
	if err != nil || len(body) > maxOperationPinBytes {
		return zero, errOperationPinUnavailable
	}
	var pin operationPin
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&pin) != nil || d.Decode(new(any)) != io.EOF || !pin.valid() || pin.OperationKey != operationKey || pin.RequestSHA256 != requestHash {
		return zero, errOperationPinUnavailable
	}
	return pin, nil
}
