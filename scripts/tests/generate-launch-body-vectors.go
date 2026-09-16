// Run from repository root: go run scripts/tests/generate-launch-body-vectors.go
// Standalone Go encoding/json reference for the agreed B + E wire rule.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
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
