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

func TestAddendumTwoRecordsAreCanonical(t *testing.T) {
	var manifest struct{ Positive []string }
	readFixture(t, "addendum-2-manifest.json", &manifest)
	for _, name := range manifest.Positive {
		var v map[string]string
		readFixture(t, name, &v)
		if _, err := DecodeCanonical(v["kind"], unhex(t, v["canonical_hex"])); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestAddendumTwoVectorsAndEd25519MatchRust(t *testing.T) {
	var manifest struct {
		Positive []string
		Seed     string `json:"test_only_ed25519_seed_hex"`
	}
	readFixture(t, "addendum-2-manifest.json", &manifest)
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
func TestAddendumTwoNegativeVectorsAreNeverRepaired(t *testing.T) {
	var all []map[string]string
	readFixture(t, "negative-addendum-2.json", &all)
	for _, v := range all {
		t.Run(v["name"], func(t *testing.T) {
			if _, e := DecodeCanonical(v["kind"], unhex(t, v["canonical_hex"])); e == nil {
				t.Fatal("accepted invalid bytes")
			}
		})
	}
}

// These are wire-verifier controls, not proof that a host stopped a VM.
func TestAddendumTwoEvidenceNeedsNodeTrustAndExactRetirement(t *testing.T) {
	var authority map[string]string
	readFixture(t, "Addendum2Retirement.json", &authority)
	var a RetirementAuthority
	if err := json.Unmarshal(unhex(t, authority["canonical_hex"]), &a); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Addendum2HostCessation.json", "Addendum2WrongIncarnation.json", "Addendum2GuestImpostor.json"} {
		var v map[string]string
		readFixture(t, name, &v)
		body := unhex(t, v["canonical_hex"])
		err := VerifyRecord("HostCessationEvidence", "agentenv-process-epoch/node-response/v1", body, unhex(t, v["envelope_hex"]), unhex(t, v["public_key_hex"]), unhex(t, v["signature_hex"]))
		var evidence HostCessationEvidence
		if e := json.Unmarshal(body, &evidence); e != nil {
			t.Fatal(e)
		}
		accepted := err == nil && evidence.RuntimeId == a.RuntimeId && evidence.RuntimeIncarnation == a.RuntimeIncarnation && evidence.RetirementOperationId == a.OperationId && evidence.RetirementRequestSha256 == authority["sha256"] && evidence.NoSecondCopy
		if accepted != (name == "Addendum2HostCessation.json") {
			t.Fatalf("%s acceptance=%v", name, accepted)
		}
	}
	var manifest struct{ Positive []string }
	readFixture(t, "addendum-2-manifest.json", &manifest)
	for _, name := range manifest.Positive {
		var v map[string]string
		readFixture(t, name, &v)
		var e SignedEnvelope
		if err := json.Unmarshal(unhex(t, v["envelope_hex"]), &e); err != nil {
			t.Fatal(err)
		}
		if e.RequestSha256 != v["sha256"] || e.BodySha256 != v["sha256"] {
			t.Fatalf("%s: self digest not envelope-only", name)
		}
	}
}

func TestAddendumThreeRecordsAreCanonical(t *testing.T) {
	var manifest struct{ Positive []string }
	readFixture(t, "addendum-3-manifest.json", &manifest)
	for _, name := range manifest.Positive {
		var v map[string]string
		readFixture(t, name, &v)
		if _, err := DecodeCanonical(v["kind"], unhex(t, v["canonical_hex"])); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestAddendumThreeVectorsAndEd25519MatchRust(t *testing.T) {
	var manifest struct {
		Positive []string
		Seed     string `json:"test_only_ed25519_seed_hex"`
	}
	readFixture(t, "addendum-3-manifest.json", &manifest)
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
func TestAddendumThreeNegativeVectorsAreNeverRepaired(t *testing.T) {
	var all []map[string]string
	readFixture(t, "negative-addendum-3.json", &all)
	for _, v := range all {
		t.Run(v["name"], func(t *testing.T) {
			if _, e := DecodeCanonical(v["kind"], unhex(t, v["canonical_hex"])); e == nil {
				t.Fatal("accepted invalid bytes")
			}
		})
	}
}

// Fixture verifier only: these comparisons do not authorize a lifecycle transition.
func TestAddendumThreeResponseMapping(t *testing.T) {
	var manifest struct {
		Contexts []struct {
			Name, Source string
			Binding      EpochBinding
			RequestHash  string `json:"request_sha256"`
			Nonce        string
			ReceiptKind  string `json:"receipt_kind"`
			State        string
			Accepted     bool
		}
	}
	readFixture(t, "addendum-3-manifest.json", &manifest)
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
	hash := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	for _, ctx := range manifest.Contexts {
		t.Run(ctx.Name, func(t *testing.T) {
			var v, source map[string]string
			readFixture(t, ctx.Name, &v)
			readFixture(t, ctx.Source, &source)
			raw := unhex(t, v["canonical_hex"])
			_, err := DecodeCanonical("ReceiptResponse", raw)
			var response ReceiptResponse
			if e := json.Unmarshal(raw, &response); e != nil {
				t.Fatal(e)
			}
			var result LookupResponse
			if e := json.Unmarshal(octets(response.Node.Body), &result); e != nil {
				t.Fatal(e)
			}
			var fresh SignedEnvelope
			json.Unmarshal(octets(response.Node.Envelope), &fresh)
			key := unhex(t, source["public_key_hex"])
			accepted := err == nil && response.Guest == nil && VerifyRecord("LookupResponse", "agentenv-process-epoch/node-response/v1", octets(response.Node.Body), octets(response.Node.Envelope), key, octets(response.Node.Signature)) == nil
			b, _ := marshal(result.Binding)
			expected, _ := marshal(ctx.Binding)
			accepted = accepted && bytes.Equal(b, expected) && result.RequestSha256 == ctx.RequestHash && result.State == ctx.State && fresh.Nonce == ctx.Nonce && fresh.RequestSha256 == ctx.RequestHash && result.ReceiptKind != nil && *result.ReceiptKind == ctx.ReceiptKind
			if response.Receipt == nil {
				accepted = false
			} else {
				r := response.Receipt
				rb := octets(r.Body)
				re := octets(r.Envelope)
				kind := map[string]string{"dispatch_result": "DispatchResult", "host_cessation": "HostCessationEvidence"}[ctx.ReceiptKind]
				accepted = accepted && VerifyRecord(kind, "agentenv-process-epoch/node-response/v1", rb, re, key, octets(r.Signature)) == nil
				canonicalRecord, _ := marshal(r)
				var historical SignedEnvelope
				json.Unmarshal(re, &historical)
				var original map[string]any
				json.Unmarshal(rb, &original)
				id, request := original["operation_id"], original["dispatch_request_sha256"]
				if ctx.ReceiptKind == "host_cessation" {
					id, request = original["retirement_operation_id"], original["retirement_request_sha256"]
				}
				accepted = accepted && result.ReceiptId != nil && *result.ReceiptId == id && id == ctx.Binding.OperationId && request == ctx.RequestHash && result.ReceiptSha256 != nil && *result.ReceiptSha256 == hash(canonicalRecord) && historical.RequestSha256 == hash(rb) && historical.BodySha256 == hash(rb) && fresh.Nonce != historical.Nonce
				accepted = accepted && bytes.Equal(rb, unhex(t, source["canonical_hex"])) && bytes.Equal(re, unhex(t, source["envelope_hex"])) && bytes.Equal(octets(r.Signature), unhex(t, source["signature_hex"]))
				for _, field := range []string{"runtime_id", "runtime_incarnation"} {
					var saved map[string]any
					json.Unmarshal(expected, &saved)
					accepted = accepted && original[field] == saved[field]
				}
				if kind == "DispatchResult" {
					var saved map[string]any
					json.Unmarshal(expected, &saved)
					for _, field := range []string{"node_id", "node_incarnation", "guest_boot_id", "process_endpoint", "guest_build_sha256", "enrollment_revision"} {
						accepted = accepted && original[field] == saved[field]
					}
				}
				accepted = accepted && fresh.RuntimeId == historical.RuntimeId && fresh.RuntimeIncarnation == historical.RuntimeIncarnation
				accepted = accepted && fresh.NodeId == historical.NodeId && fresh.NodeIncarnation == historical.NodeIncarnation && fresh.EnrollmentRevision == historical.EnrollmentRevision && fresh.Audience == historical.Audience
			}
			if accepted != ctx.Accepted {
				t.Fatalf("accepted=%v want=%v", accepted, ctx.Accepted)
			}
		})
	}
}
