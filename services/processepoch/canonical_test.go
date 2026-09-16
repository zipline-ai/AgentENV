package processepoch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const fixtureDir = "../../testdata/process-epoch-vectors/v1"

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func readFixture(t *testing.T, name string, v any) {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(fixtureDir, name))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, v); e != nil {
		t.Fatal(e)
	}
}
func TestCanonicalVectorsAndEd25519MatchRust(t *testing.T) {
	var manifest struct {
		Positive []string
		Seed     string `json:"test_only_ed25519_seed_hex"`
	}
	readFixture(t, "manifest.json", &manifest)
	for _, name := range manifest.Positive {
		t.Run(name, func(t *testing.T) {
			var v map[string]string
			readFixture(t, name, &v)
			body := unhex(t, v["canonical_hex"])
			if _, e := DecodeCanonical(v["kind"], body); e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256(body)
			if hex.EncodeToString(sum[:]) != v["sha256"] {
				t.Fatal("body hash")
			}
			envelope := unhex(t, v["envelope_hex"])
			input, e := SignatureInput(envelope)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(input, unhex(t, v["signature_input_hex"])) {
				t.Fatal("signature bytes")
			}
			key, sig := unhex(t, v["public_key_hex"]), unhex(t, v["signature_hex"])
			if e = VerifySignature(envelope, key, sig); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(ed25519.Sign(ed25519.NewKeyFromSeed(unhex(t, manifest.Seed)), input), sig) {
				t.Fatal("signature mismatch")
			}
			var original SignedEnvelope
			if e = json.Unmarshal(envelope, &original); e != nil {
				t.Fatal(e)
			}
			if e = VerifyRecord(v["kind"], original.Domain, body, envelope, key, sig); e != nil {
				t.Fatal(e)
			}
			if VerifyRecord(v["kind"], "wrong-domain", body, envelope, key, sig) == nil {
				t.Fatal("wrong domain accepted")
			}
			var changed SignedEnvelope
			if e = json.Unmarshal(envelope, &changed); e != nil {
				t.Fatal(e)
			}
			if changed.Domain == "agentenv-process-epoch/lookup/v1" {
				changed.Domain = "agentenv-process-epoch/seal/v1"
			} else {
				changed.Domain = "agentenv-process-epoch/lookup/v1"
			}
			b, _ := marshal(changed)
			if VerifySignature(b, key, sig) == nil {
				t.Fatal("wrong domain accepted")
			}
			if e = json.Unmarshal(envelope, &changed); e != nil {
				t.Fatal(e)
			}
			changed.EnrollmentRevision++
			b, _ = marshal(changed)
			if VerifySignature(b, key, sig) == nil {
				t.Fatal("wrong enrollment accepted")
			}
			sig[0] ^= 1
			if VerifySignature(envelope, key, sig) == nil {
				t.Fatal("changed signature accepted")
			}
		})
	}
}
func TestNegativeVectorsAreNeverRepaired(t *testing.T) {
	var all []map[string]string
	readFixture(t, "negative.json", &all)
	for _, v := range all {
		t.Run(v["name"], func(t *testing.T) {
			if _, e := DecodeCanonical(v["kind"], unhex(t, v["canonical_hex"])); e == nil {
				t.Fatal("accepted invalid bytes")
			}
		})
	}
}
func TestVendoredSchemaIsExact(t *testing.T) {
	b, e := os.ReadFile(filepath.Join(fixtureDir, "schema.json"))
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(schemaBytes, b) {
		t.Fatal("schema copy drift")
	}
}
func TestSignedInitialOwnerAndAdoptionCannotChange(t *testing.T) {
	var v map[string]string
	readFixture(t, "InitialBindRequest.json", &v)
	body, envelope, key, sig := unhex(t, v["canonical_hex"]), unhex(t, v["envelope_hex"]), unhex(t, v["public_key_hex"]), unhex(t, v["signature_hex"])
	for _, field := range []string{"owner", "adoption"} {
		t.Run(field, func(t *testing.T) {
			var record InitialBindRequest
			if err := json.Unmarshal(body, &record); err != nil {
				t.Fatal(err)
			}
			if field == "owner" {
				record.InitialAuthority.OwnerUserId = "another-owner"
			} else {
				record.AdoptionSha256 = string(bytes.Repeat([]byte{'a'}, 64))
			}
			changed, err := marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = DecodeCanonical("InitialBindRequest", changed); err != nil {
				t.Fatal("control must retain valid shape", err)
			}
			if VerifyRecord("InitialBindRequest", "agentenv-process-epoch/bind/v1", changed, envelope, key, sig) == nil {
				t.Fatal("changed authority accepted")
			}
		})
	}
}

func TestAddendumRecordsAreCanonical(t *testing.T) {
	var manifest struct{ Positive []string }
	readFixture(t, "addendum-manifest.json", &manifest)
	for _, name := range manifest.Positive {
		var v map[string]string
		readFixture(t, name, &v)
		if _, err := DecodeCanonical(v["kind"], unhex(t, v["canonical_hex"])); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestAddendumVectorsAndEd25519MatchRust(t *testing.T) {
	var manifest struct {
		Positive []string
		Seed     string `json:"test_only_ed25519_seed_hex"`
	}
	readFixture(t, "addendum-manifest.json", &manifest)
	for _, name := range manifest.Positive {
		t.Run(name, func(t *testing.T) {
			var v map[string]string
			readFixture(t, name, &v)
			body := unhex(t, v["canonical_hex"])
			if _, e := DecodeCanonical(v["kind"], body); e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256(body)
			if hex.EncodeToString(sum[:]) != v["sha256"] {
				t.Fatal("body hash")
			}
			envelope := unhex(t, v["envelope_hex"])
			input, e := SignatureInput(envelope)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(input, unhex(t, v["signature_input_hex"])) {
				t.Fatal("signature bytes")
			}
			key, sig := unhex(t, v["public_key_hex"]), unhex(t, v["signature_hex"])
			if e = VerifySignature(envelope, key, sig); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(ed25519.Sign(ed25519.NewKeyFromSeed(unhex(t, manifest.Seed)), input), sig) {
				t.Fatal("signature mismatch")
			}
			var original SignedEnvelope
			if e = json.Unmarshal(envelope, &original); e != nil {
				t.Fatal(e)
			}
			if e = VerifyRecord(v["kind"], original.Domain, body, envelope, key, sig); e != nil {
				t.Fatal(e)
			}
			if VerifyRecord(v["kind"], "wrong-domain", body, envelope, key, sig) == nil {
				t.Fatal("wrong domain accepted")
			}
			var changed SignedEnvelope
			if e = json.Unmarshal(envelope, &changed); e != nil {
				t.Fatal(e)
			}
			if changed.Domain == "agentenv-process-epoch/lookup/v1" {
				changed.Domain = "agentenv-process-epoch/seal/v1"
			} else {
				changed.Domain = "agentenv-process-epoch/lookup/v1"
			}
			b, _ := marshal(changed)
			if VerifySignature(b, key, sig) == nil {
				t.Fatal("wrong domain accepted")
			}
			if e = json.Unmarshal(envelope, &changed); e != nil {
				t.Fatal(e)
			}
			changed.EnrollmentRevision++
			b, _ = marshal(changed)
			if VerifySignature(b, key, sig) == nil {
				t.Fatal("wrong enrollment accepted")
			}
			sig[0] ^= 1
			if VerifySignature(envelope, key, sig) == nil {
				t.Fatal("changed signature accepted")
			}
		})
	}
}
func TestAddendumNegativeVectorsAreNeverRepaired(t *testing.T) {
	var all []map[string]string
	readFixture(t, "negative-addendum.json", &all)
	for _, v := range all {
		t.Run(v["name"], func(t *testing.T) {
			if _, e := DecodeCanonical(v["kind"], unhex(t, v["canonical_hex"])); e == nil {
				t.Fatal("accepted invalid bytes")
			}
		})
	}
}

func TestAddendumLookupPreservesFirstSignedReceipt(t *testing.T) {
	var manifest struct{ Containers []string }
	readFixture(t, "addendum-manifest.json", &manifest)
	octets := func(v []uint16) []byte {
		b := make([]byte, len(v))
		for i, n := range v {
			if n > 255 {
				t.Fatal("octet")
			}
			b[i] = byte(n)
		}
		return b
	}
	for _, name := range manifest.Containers {
		var v map[string]string
		readFixture(t, name, &v)
		var response ReceiptResponse
		if err := json.Unmarshal(unhex(t, v["canonical_hex"]), &response); err != nil {
			t.Fatal(err)
		}
		var result LookupResponse
		if err := json.Unmarshal(octets(response.Node.Body), &result); err != nil {
			t.Fatal(err)
		}
		key := unhex(t, v["public_key_hex"])
		if err := VerifyRecord("LookupResponse", "agentenv-process-epoch/node-response/v1", octets(response.Node.Body), octets(response.Node.Envelope), key, octets(response.Node.Signature)); err != nil {
			t.Fatal(err)
		}
		if response.Receipt == nil {
			if result.ReceiptId != nil || result.ReceiptSha256 != nil {
				t.Fatal("missing receipt")
			}
			continue
		}
		receipt := response.Receipt
		kind := map[string]string{"seal": "SealReceipt", "bind": "BindReceipt", "release": "ReleaseReceipt"}[*result.ReceiptKind]
		if err := VerifyRecord(kind, "agentenv-process-epoch/node-response/v1", octets(receipt.Body), octets(receipt.Envelope), key, octets(receipt.Signature)); err != nil {
			t.Fatal(err)
		}
		b, _ := marshal(receipt)
		sum := sha256.Sum256(b)
		if *result.ReceiptSha256 != hex.EncodeToString(sum[:]) {
			t.Fatal("receipt digest")
		}
		var original map[string]any
		if err := json.Unmarshal(octets(receipt.Body), &original); err != nil {
			t.Fatal(err)
		}
		if *result.ReceiptId != original["receipt_id"] || result.RequestSha256 != original["request_sha256"] {
			t.Fatal("receipt identity")
		}
		switch result.State {
		case "bound":
			if original["state"] != "bound_closed" {
				t.Fatal("bound state")
			}
		case "bind_pending":
			if original["state"] != "incomplete" {
				t.Fatal("pending bind")
			}
		case "released":
			if original["outcome"] != "released" {
				t.Fatal("released state")
			}
		case "release_pending":
			if original["outcome"] != "accepted" && original["outcome"] != "incomplete" {
				t.Fatal("pending release")
			}
		case "completed_seal":
			if original["state"] != "sealed" {
				t.Fatal("seal state")
			}
		default:
			t.Fatal("unexpected receipt state")
		}
		var first, fresh SignedEnvelope
		json.Unmarshal(octets(receipt.Envelope), &first)
		json.Unmarshal(octets(response.Node.Envelope), &fresh)
		if first.Nonce == fresh.Nonce || first.RequestSha256 != fresh.RequestSha256 {
			t.Fatal("historical versus fresh envelope")
		}
		receipt.Signature[0] ^= 1
		b, _ = marshal(receipt)
		sum = sha256.Sum256(b)
		if *result.ReceiptSha256 == hex.EncodeToString(sum[:]) {
			t.Fatal("changed historical signature accepted")
		}
	}
}
