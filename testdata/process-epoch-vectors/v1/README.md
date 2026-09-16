# Process epoch wire v1

Contract: zippy `42ae960e`, process-epoch contract r3. Vector-content freeze commit: `eb1c0e4d1df0cf4d01218efcb6774b36bb5c3242`.
The original body/signature fixtures remain unchanged. The receipt addendum is
specified in [ADDENDUM.md](ADDENDUM.md), with its own `addendum-manifest.json`.
Addendum content freeze: `e976f0df95fcda5bcaa634305c48e1b04cb37c5c`.
This README publication adds no changes to those fixture bytes.
Vendor this directory verbatim. The Go reference package is `services/processepoch`;
the Rust reference module is `src/process_epoch/wire`. Both consume these exact
fixtures. `schema.json` defines field order, vocabulary and structural relationships.
Run `python3 scripts/generate-process-epoch-wire.py` to reproduce the typed records
and Go schema copy. Do not regenerate or edit an original frozen v1 fixture in place. The authorized
addendum extends schema/types and adds fixtures; run both manifests.

Each positive JSON file contains the exact body bytes as lowercase hexadecimal,
SHA-256, canonical envelope bytes, signature-input bytes, public key and Ed25519
signature. `manifest.json` lists the original fixtures; `addendum-manifest.json` lists the new
receipt/container fixtures and their negative corpus.
The published private seed is TEST ONLY. It is not an enrollment or controller key.

Encoding is UTF-8 JSON with declaration order, no whitespace, omitted optional
fields, and no unknown or duplicate keys. Explicit null is rejected. Integers are
unsigned 64-bit decimal, never floating point; positive fields exclude zero. UUIDs
are nonnil lowercase canonical strings. Hashes are lowercase SHA-256. Wire strings
are nonempty printable ASCII (32–126), at most 2048 bytes. This restriction applies
to opaque coordinates, not terminal payload: payload bytes travel separately and
are bound by length and SHA-256. Strings use ordinary JSON quote/backslash escaping;
HTML characters are not escaped. The total canonical record limit is 64 KiB.

The signature input is the exact envelope `domain` bytes, one NUL byte, then the
canonical envelope bytes. Ed25519 signs that entire input directly (not Ed25519ph).
The envelope's `body_sha256` hashes the separate canonical body. `request_sha256`
is the original saved operation digest; for responses it need not equal the response
body digest. There is no self-hashed envelope field. Descriptor hashes refer to the
canonical descriptor body. The audience is an opaque configured recipient identity;
its exact value, node coordinates and enrollment must match the independent trusted
saved enrollment. The fixture audience is a test value, not a production naming rule.
Nonce is 32 bytes encoded as lowercase hex; expiry is integer UTC milliseconds.

An envelope authenticates bytes only after its key is independently trusted. These
records do not authorize reconciliation, bind, release, dispatch or host cessation.
Callers must prove saved claims, current trust/revocation, exact recipient/allocation,
nonce, expiry and immutable operation identity. A signed changed owner/adoption is
still denied against saved authority. Byte validation cannot supply that authority.
The initial/transition tagged records reject mixed arms. Restore binds predecessor
seal to the captured LR/result and exact destination. Bind is `bound_closed` only.
A guest report cannot encode a successful seal. `EvidenceReference` is untrusted
reported data; its `host_scope_stopped` vocabulary does not construct host evidence.
The original bundle has no successful host cessation fixture. The addendum adds a
syntax-only completed-seal fixture; it is not host evidence or a success stub. No
live host-stop constructor is supplied by these wire records.

Tests run both serializers over the same positive and negative bytes, reproduce all
signatures, and reject changed domain, enrollment and signature. These are wire and
cryptographic tests, not root-tampering, process/PTY, accounting or rollout evidence.
No managed capability or consumer is enabled by freezing these records.

Commands (from fork root):

- `cargo test --locked --lib process_epoch::wire`
- `cd services && go test ./processepoch`
