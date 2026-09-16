// Package processepoch defines dormant canonical transport records. A parsed record
// or valid signature is not authority or proof of host cessation.
package processepoch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

var errInvalid = errors.New("invalid process epoch record")

func checkScalar(kind string, value any) error {
	if kind == "octets" {
		values, ok := value.([]uint16)
		if !ok || len(values) == 0 || len(values) > 65536 {
			return errInvalid
		}
		for _, n := range values {
			if n > 255 {
				return errInvalid
			}
		}
		return nil
	}
	if kind == "uint" || kind == "positive" {
		n, ok := value.(uint64)
		if !ok || kind == "positive" && n == 0 {
			return errInvalid
		}
		return nil
	}
	if kind == "true" {
		if value != true {
			return errInvalid
		}
		return nil
	}
	s, ok := value.(string)
	if !ok || len(s) == 0 || len(s) > 2048 {
		return errInvalid
	}
	for _, b := range []byte(s) {
		if b < 32 || b > 126 {
			return errInvalid
		}
	}
	switch kind {
	case "text":
		return nil
	case "hash":
		if len(s) != 64 {
			return errInvalid
		}
		for _, b := range []byte(s) {
			if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
				return errInvalid
			}
		}
		return nil
	case "uuid":
		if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || strings.ToLower(s) != s {
			return errInvalid
		}
		raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
		if err != nil || len(raw) != 16 || bytes.Equal(raw, make([]byte, 16)) {
			return errInvalid
		}
		return nil
	default:
		for _, v := range enumValues[kind] {
			if v == s {
				return nil
			}
		}
		return errInvalid
	}
}
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}
func DecodeCanonical(kind string, data []byte) ([]byte, error) {
	if len(data) > 65536 {
		return nil, errInvalid
	}
	canonical, err := decode(kind, data)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: noncanonical bytes", errInvalid)
	}
	return canonical, nil
}
func SignatureInput(envelope []byte) ([]byte, error) {
	if _, err := DecodeCanonical("SignedEnvelope", envelope); err != nil {
		return nil, err
	}
	var e SignedEnvelope
	if err := json.Unmarshal(envelope, &e); err != nil {
		return nil, err
	}
	return append(append([]byte(e.Domain), 0), envelope...), nil
}
func VerifySignature(envelope, key, signature []byte) error {
	input, err := SignatureInput(envelope)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, input, signature) {
		return errInvalid
	}
	return nil
}
func lookupPath(v any, path string) any {
	for _, k := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}
func validateRelations(kind string, record any) error {
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err = dec.Decode(&v); err != nil {
		return err
	}
	for _, r := range schemaRules.Rules[kind] {
		if w, ok := r["when"].([]any); ok && !reflect.DeepEqual(lookupPath(v, w[0].(string)), w[1]) {
			continue
		}
		if p, ok := r["when_present"].(string); ok && lookupPath(v, p) == nil {
			continue
		}
		for key, rule := range r {
			valid := false
			switch key {
			case "when", "when_present":
				valid = true
			case "present":
				valid = lookupPath(v, rule.(string)) != nil
			case "absent":
				valid = lookupPath(v, rule.(string)) == nil
			case "equal", "paired", "value", "one_of":
				a := rule.([]any)
				left := lookupPath(v, a[0].(string))
				switch key {
				case "equal":
					valid = left != nil && reflect.DeepEqual(left, lookupPath(v, a[1].(string)))
				case "paired":
					valid = (left != nil) == (lookupPath(v, a[1].(string)) != nil)
				case "value":
					valid = reflect.DeepEqual(left, a[1])
				case "one_of":
					for _, x := range a[1].([]any) {
						if reflect.DeepEqual(left, x) {
							valid = true
						}
					}
				}
			}
			if !valid {
				return fmt.Errorf("%w: %s %s", errInvalid, kind, key)
			}
		}
	}
	return nil
}

//go:embed schema.json
var schemaBytes []byte
var schemaRules struct {
	Rules map[string][]map[string]any `json:"rules"`
}

func init() {
	if err := json.Unmarshal(schemaBytes, &schemaRules); err != nil {
		panic(err)
	}
}

// VerifyRecord proves cryptographic integrity only. The caller must independently
// authenticate the signer, audience, enrollment, saved authority, nonce and expiry.
func VerifyRecord(kind, domain string, body, envelope, key, signature []byte) error {
	if _, err := DecodeCanonical(kind, body); err != nil {
		return err
	}
	if err := VerifySignature(envelope, key, signature); err != nil {
		return err
	}
	var e SignedEnvelope
	if err := json.Unmarshal(envelope, &e); err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	if e.Domain != domain || e.BodySha256 != hex.EncodeToString(sum[:]) {
		return errInvalid
	}
	return nil
}
