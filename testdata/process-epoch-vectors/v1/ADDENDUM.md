# v1 receipt and saved-result addendum

Contract: r3 `42ae960e`, fields 3/7. This freezes transport bytes, not implemented
provider success or a lifecycle authorization proof. Original positive fixtures and
`negative.json` remain byte-identical. `schema.json` adds records/optional fields;
the original manifest remains unchanged. Use `addendum-manifest.json` as well.
The schema digest has changed; a production build/enrollment manifest must pin the
reviewed complete schema. This publication is not permission to rotate that policy.

## Exact response container (bind, release and recovery)

Canonical field order: `node`, optional `guest`, optional `receipt`.
The schema calls this `ReceiptResponse`; it is the additive form of the runtime's
`AuthenticatedResponse`. Each member is a `SignedRecord`, field order `body`,
`envelope`, `signature`. These are JSON integer arrays of octets, **not base64**.
Go's generated `[]uint16` representation is range-checked to 0–255 to preserve this
encoding; it is not a permission to send values larger than an octet.

- `node.body` is canonical `LookupResponse`, with a fresh current lookup/request
  nonce in its `node-response/v1` signed envelope. This wrapper describes the exact
  saved operation; it is never a new dispatch capability.
- `receipt.body` is canonical `SealReceipt`, `BindReceipt` or `ReleaseReceipt`,
  selected by `node.body.receipt_kind`. Its original node-response envelope and
  signature remain unchanged, including the original nonce and expiry.
- `receipt_sha256` hashes the **complete canonical SignedRecord** (body, historical
  envelope, signature), not just the receipt body. `receipt_id` must equal the ID
  inside that body. Body `request_sha256` and both envelopes' request hashes identify
  the exact saved original request. Check the complete tenant/runtime/epoch binding.
- `guest`, when present, remains the separate guest-signed `GuestReceipt` already
  defined by commit 2. It never substitutes for `receipt`, bound-closed evidence or
  host cessation. Its complete SignedRecord digest is bound by the evidence reference.

Every returned signature requires independently pinned signer/key/enrollment/build,
correct audience/domain and current authorized lookup proof. Verify the fresh wrapper
and original receipt separately. Historical receipt expiry is not fresh grant authority
and does not justify rewriting its signature. Exact replay returns original bytes;
changed operation scope/request/receipt bytes conflict. Canonical/signature validation
alone does not prove those store predicates or authenticate a reference's backing fact.

All seal/bind receipt reference hashes use this complete SignedRecord convention,
including `seal_receipt_sha256` and `bind_receipt_sha256` in subsequent requests.
Request hashes still hash canonical request **body** bytes. The response wrapper has
its own body digest. This distinction avoids a nonce-changing recovery digest.

## BindReceipt

Field order is in schema.json: binding, request_sha256, receipt_id, kind, state,
optional expected_session_id, optional seal_receipt_id, optional seal_receipt_sha256,
optional adoption_sha256, node_ledger_revision, guest_journal_revision, evidence.
The addendum supplies initial, transition/restore and incomplete examples.

Initial receipts omit expected A and seal references and carry adoption_sha256.
Transition receipts require exact A and both original seal receipt ID/hash; restore
still requires the request's LR/predecessor/destination bridge. B/C is exactly
`binding.reserved_session_id`, never a newly allocated ID. The node signature covers
all fields. A bound_closed receipt leaves admission closed and never itself publishes
B/C in the app or authorizes release. Installation must consume real provider evidence
with the saved creation/transition/adoption/result; the vectors do not supply it.

## ReleaseReceipt

Canonical order: request, request_sha256, receipt_id, outcome, node_ledger_revision,
obligations_retained. `request` is the complete original ReleaseRequest: exact bind
receipt references, installed session, installation/grant/publication revisions,
release_revision, expected_provider_revision and lease_not_after_unix_ms. The nested
request preserves the policy-derived absolute deadline on replay; no new duration is
invented. Check request_sha256 against that exact canonical request body.

Outcomes are `accepted`, `incomplete`, `released`. Accepted/incomplete acknowledge
only retained work, never open admission or authorize app endpoint disclosure.
`obligations_retained` is always true: release is not compute-stop, settlement, or
proof that unknown effects disappeared. It is not an enumeration or completion of
monetary obligations. The actual accounting/cleanup rows remain lifecycle authority.
The first terminal released receipt is immutable. Nonterminal observations are also
immutable records with their own receipt IDs; they cannot overwrite a terminal receipt.
A fresh lookup wrapper may describe a later state without changing a historical record.

## Lookup → saved app result

Every row includes exact `binding`, original `request_sha256`, `state`, and positive
`node_ledger_revision`. Optional receipt references are always the tuple receipt_id,
receipt_sha256, receipt_kind; the referenced SignedRecord is required in the container.
No lookup outcome creates a grant, debit, session or replacement runtime.

| state | Additional fields/container | App meaning |
| --- | --- | --- |
| claimed | No receipt tuple | Exact operation persisted; not proof of forwarding or effects. |
| closing | affected_operations_sha256; no receipt tuple | Admission closed and inventory frozen; not a completed seal. |
| completed_seal | frozen inventory hash; seal receipt tuple and original SignedRecord | Candidate exact seal evidence. Consume only separately authenticated, independently conclusive whole-domain host evidence. |
| bind_pending | Optional bind receipt tuple/record, state incomplete only | Bind unresolved; no installable publication. Missing receipt is not successful bind. |
| bound | Bind receipt tuple/record, state bound_closed only | Candidate first bound-closed record; app installation still needs all current saved-authority predicates. |
| release_pending | Optional release receipt tuple/record, outcome accepted/incomplete only | Keep release obligation; no endpoint disclosure or resend. |
| released | Release receipt tuple/record, outcome released only | Candidate saved release completion; current grant/enrollment/publication and deadline still govern access. |
| unknown | No receipt tuple | Retain saved obligations and previously recorded history; no inference, resend or publication. |

The old commit-2 states remain parseable: execution_claimed maps to claimed for
presentation, effect_unknown/incomplete to unknown. This does not upgrade old evidence
or fill missing fields. Commit 2 itself still emits its original response and has no
bind/release implementation. Consumers must validate receipt kind, body state, request,
full binding and record digest together; parsing a known state string is insufficient.

## Answers to codex-9 and explicit pending fields

1. First BindReceipt bytes are `receipt.body`, with its original `receipt.envelope`
   and `receipt.signature`; the fresh nonce-bound LookupResponse is `node`. This is
   the same container on bind completion and recovery. No guest cast is allowed.
2. The digest covers the complete first SignedRecord, as above. A different historical
   signature/envelope cannot be swapped under an unchanged reference.
3. Release completion uses ReleaseReceipt with the complete original release request,
   deadline/revisions/outcome and retained-obligation flag. Nonterminal results never
   authorize access. Neutral recovery cannot sign a new release/grant.
4. **PENDING: canonical provider creation/restore result record** and the bytes named
   by SavedDispatchProof.exact_result_sha256. Contract r3 does not define that record.
   Do not hash to_jsonb(creation receipt), cast DB P1 evidence to enrollment proof, or
   use these synthetic vector hashes as a positive provider-result journey. This needs
   the lifecycle/provider owners' separate agreed result mapping before initial/LR-C
   success composition. The frozen request field remains an opaque reference meanwhile.
5. **PENDING: backing whole-domain retirement authority record/resolver**, independent
   host allocation/no-second-copy evidence, and actual receipt participants. The
   completed-seal fixture is syntax/signature-only, not fabricated test-provider success.
6. **PENDING: lifecycle persistence/resolution of accepted/incomplete release observations**;
   their wire bytes are fixed here, not permission to discard existing obligations or
   retry. Real guest/host and PG proofs, build/image identities and rollout remain pending.
