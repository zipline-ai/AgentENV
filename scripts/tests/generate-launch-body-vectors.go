// Run from repository root: go run scripts/tests/generate-launch-body-vectors.go
// Standalone Go encoding/json reference for the agreed B + E wire rule.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"time"
)

type volume struct {
	VolumeID      string `json:"volumeId"`
	VolumeKind    string `json:"volumeKind"`
	DriveID       string `json:"driveId,omitempty"`
	Grant         []byte `json:"grant"`
	Signature     []byte `json:"signature"`
	WrappedDEK    []byte `json:"wrappedDek"`
	KMSKey        string `json:"kmsKey"`
	KMSKeyVersion string `json:"kmsKeyVersion"`
	KMSAAD        string `json:"kmsAad"`
	Cipher        string `json:"cipher"`
	SectorSize    int    `json:"sectorSize"`
}
type create struct {
	TemplateID string `json:"templateID"`
	Timeout    int64  `json:"timeout"`
	AutoPause  bool   `json:"autoPause"`
	AutoResume struct {
		Enabled bool `json:"enabled"`
	} `json:"autoResume"`
	EnvVars  map[string]string `json:"envVars"`
	Metadata map[string]string `json:"metadata"`
}
type vector struct{ Name, Body, Envelope, Wire, SHA256 string }

func main() {
	writeGrantVector()
	e, err := json.Marshal(volume{"vol_a", "sandbox_rootfs", "", []byte(`{"v":6}`), []byte{1, 2, 3}, []byte{4, 5, 6}, "projects/p/locations/l/keyRings/r/cryptoKeys/k", "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", "vol:tenant:vol_a", "aes-xts-plain64", 4096})
	if err != nil {
		panic(err)
	}
	// Illustrative public data only. These are serialization vectors, not valid grants.
	c := create{TemplateID: "template-immutable-id", Timeout: 300, AutoPause: true, EnvVars: map[string]string{"PUBLIC": "<hello> \"world\" ☃"}, Metadata: map[string]string{"volumeEncryption": "nested ordinary data"}}
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	bodies := []struct{ name, body string }{{"create", string(b)}, {"restore", `{"templateID":"snapshot-id","metadata":{"zippy.stable_sandbox_id":"stable","zippy.generation":"2"},"async_restore":{"node_id":"node","node_incarnation":"boot","runtime_id":"new-runtime"}}`}, {"whitespace", `{ "templateID" : "template-id", "metadata":{"volumeEncryption":"not a root envelope"} }`}}
	var out []vector
	for _, v := range bodies {
		hash := sha256.Sum256([]byte(v.body))
		out = append(out, vector{v.name, v.body, string(e), v.body[:len(v.body)-1] + `,"volumeEncryption":` + string(e) + `}`, hex.EncodeToString(hash[:])})
	}
	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile("src/volume/testdata/launch_body_vectors.json", append(encoded, '\n'), 0644); err != nil {
		panic(err)
	}
}

type grantOrigin struct {
	Kind          string `json:"kind"` // snapshot | template
	SnapshotID    string `json:"snapshot_id,omitempty"`
	SnapshotAlias string `json:"snapshot_alias,omitempty"`
	RecordDigest  string `json:"record_digest,omitempty"`
	TemplateID    string `json:"template_id,omitempty"`
}

type grantPayload struct {
	V                   int         `json:"v"`
	GrantID             string      `json:"grant_id"`
	TenantID            string      `json:"tenant_id"`
	OwnerUserID         string      `json:"owner_user_id"`
	SandboxFamily       string      `json:"sandbox_family"`
	LaunchKind          string      `json:"launch_kind"` // create | restore | creds_attach
	CreationID          string      `json:"creation_id,omitempty"`
	RestoreLaunchID     string      `json:"restore_launch_id,omitempty"`
	ReservedSessionID   string      `json:"reserved_session_id,omitempty"`
	Mode                string      `json:"mode"` // required | legacy
	VolumeID            string      `json:"volume_id"`
	VolumeKind          string      `json:"volume_kind"`
	DriveID             string      `json:"drive_id"`
	LiveSandboxID       string      `json:"live_sandbox_id,omitempty"`
	Generation          int64       `json:"generation,omitempty"`
	Origin              grantOrigin `json:"origin"`
	TemplateLineageRoot string      `json:"template_lineage_root"`
	RequestSHA256       string      `json:"request_sha256"`
	DestinationNodeID   string      `json:"destination_node_id"`
	KMSKey              string      `json:"kms_key"`
	KMSKeyVersion       string      `json:"kms_key_version"`
	KMSAAD              string      `json:"kms_aad"`
	WrappedDEKSHA256    string      `json:"wrapped_dek_sha256"`
	IssuedAt            time.Time   `json:"issued_at"`
	ExpiresAt           time.Time   `json:"expires_at"`
}

func writeGrantVector() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	wrapped := []byte("wrapped")
	sum := sha256.Sum256(wrapped)
	p := grantPayload{V: 6, GrantID: "grant-exact", TenantID: "tenant-exact", OwnerUserID: "owner<&>\u2028\u2029", SandboxFamily: "legacy", LaunchKind: "create", CreationID: "creation-exact", Mode: "required", VolumeID: "vol-exact", VolumeKind: "sandbox_rootfs", Origin: grantOrigin{Kind: "template", TemplateID: "template-exact"}, TemplateLineageRoot: "root-exact", RequestSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", DestinationNodeID: "node-exact", KMSKey: "key-exact", KMSKeyVersion: "version-exact", KMSAAD: "vol:tenant-exact:vol-exact:sandbox_rootfs", WrappedDEKSHA256: hex.EncodeToString(sum[:]), IssuedAt: time.Date(2026, 9, 16, 12, 0, 0, 123456789, time.UTC), ExpiresAt: time.Date(2026, 9, 16, 12, 15, 0, 123456789, time.UTC)}
	payload, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		panic(err)
	}
	result := map[string]string{"payload": base64.StdEncoding.EncodeToString(payload), "signature": base64.StdEncoding.EncodeToString(sig), "public_sec1": base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), key.X, key.Y)), "payload_sha256": hex.EncodeToString(digest[:])}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile("src/volume/testdata/grant_go_vector.json", append(raw, '\n'), 0644); err != nil {
		panic(err)
	}
}
