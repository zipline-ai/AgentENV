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
addenda extend schema/types and add fixtures; run all five manifests.

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

The dispatch/retirement addendum is [ADDENDUM-2.md](ADDENDUM-2.md). Its
`addendum-2-manifest.json` lists positive, malformed and contextual negative vectors.
Its generator is `scripts/generate-process-epoch-addendum-2.py`. All earlier fixture
bytes are unchanged. The consolidated item-4 ruling changes only the new dispatch
result reference to its envelope digest; historical bind/release references retain
their original rule.

Addendum-2 content freeze: `cfc0f89e4f3667790c2a6fd69ba4dd9eb113249e`. This publication only records
the content commit; it does not alter the vectors.

The authenticated response mapping is [ADDENDUM-3.md](ADDENDUM-3.md).
`addendum-3-manifest.json` freezes 14 positive lookup/container vectors, four
malformed records and 12 contextual negatives. Dispatch create/restore include
running, failed and unknown results; the retirement arm references the original
whole-domain authority. The receipt reference hashes the complete SignedRecord;
SavedDispatchProof retains the addendum-2 envelope digest. Earlier vectors are
unchanged. These are wire tests, not provider execution or field-8 evidence.

Addendum-3 content freeze: `963b0de634833b22805d18235d749d82f879dd73`.
This publication records the content commit without changing any vector bytes.

The captured allocation binding is [ADDENDUM-4.md](ADDENDUM-4.md).
`addendum-4-manifest.json` adds the separately tagged DispatchResultV2 and its
`dispatch_result_v2` response arm. V1 remains unchanged and cannot supply retirement
allocation authority. Eighteen positives, five malformed records and three validly
signed contextual-negative records cover the captured-allocation requirement.
