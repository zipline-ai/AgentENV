# Captured host allocation binding (addendum-4)

The coordinator chose captured dispatch-completion authority, not allocation lookup
at retirement time. This adds DispatchResultV2 and its authenticated response arm.
Earlier DispatchResult records, wrappers, protocol tags and fixture bytes stay fixed.

## Record and response version

DispatchResultV2 has the same ordered fields as DispatchResult with two differences:
protocol is the dedicated tag `agentenv-process-epoch-dispatch-result-v2`, and the
required nonempty `host_allocation_id` follows `runtime_incarnation`. The shared
v1 envelope and node-response/v1 signature domain remain unchanged. Only this new
record accepts the new protocol tag; other v1 record validators are not broadened.
An old result cannot be upgraded by inserting a field or interpreting runtime_id.

LookupResponse keeps state `dispatch_completed` and adds the distinct receipt_kind
`dispatch_result_v2`, selecting DispatchResultV2 in ReceiptResponse.receipt. The
existing `dispatch_result` arm continues selecting the original DispatchResult.
Unknown versions/kinds fail closed. The fresh node LookupResponse still binds the
original committed operation/request, saved binding, nonce, current enrolled trust,
audience and expiry. receipt_sha256 still hashes the complete first SignedRecord.
The result's envelope request_sha256/body_sha256 both hash its canonical body;
SavedDispatchProof.exact_result_sha256 keeps that envelope digest. No digest rule
changes, and recovery never mutates a first result to add an allocation.

## Capture before retirement

The node supplies its own host allocation identity for the exact runtime incarnation
at dispatch completion. It is an opaque nonempty identity, not a runtime UUID alias,
guest report or caller-provided label. A create and a restore both require this value
before the positive capture path can support retirement. The provider's immutable
operation and host allocation records must prove the value; these fixtures do not
implement that source. The same identity must appear in later HostCessationEvidence.

Lifecycle captures the authenticated V2 result through the existing exact saved
response transaction and persists host_allocation_id before a retirement claim can
sign RetirementAuthority. Claim requires the saved nonempty value. A V1 result,
missing capture or failed/unknown outcome cannot be repaired by a retirement-time
node query, a runtime-ID conversion or a new dispatch. Obligations remain pending.
Failed/unknown V2 outcomes still retain obligations and authorize no replacement.
The three outcome fixtures are syntax cases, not successful adoption evidence.

The resolver compares HostCessationEvidence.host_allocation_id to that persisted
value, in addition to the committed retirement operation ID/digest and exact runtime,
incarnation, enrollment, node trust and whole-domain authority checks from r4. A
valid node signature with a different allocation is refused. Runtime scope, closed
admission, frozen inventory and independently conclusive no-second-copy cessation
remain mandatory. This adds no retirement-time authority delegation to the node,
no settlement from a parse, and no automatic destroy/replace path.

## Fixtures and tests

`addendum-4-manifest.json` lists six V2 results (create/restore × running/failed/unknown),
each with a canonical LookupResponse and ReceiptResponse. Five malformed records
cover absent/empty allocation, wrong protocol, injecting the field into V1 and a
bind-state substitution. The contextual negative is independently node-signed host
evidence with the correct operation/runtime/incarnation but a different allocation,
plus its authenticated lookup/container. Both Go and Rust exercise matching create
and restore cases, reject those mismatches and reject V1 as a capture source.
The allocation comparison sensitivity check fails when that equality is removed.

Run `python3 scripts/generate-process-epoch-addendum-4.py`. All earlier fixture bytes
remain unchanged. Reference serializers/schema are additive; no service producer,
lifecycle consumer, managed capability or real host cessation primitive is enabled.
These wire tests are not field-8 process/PTY/host execution evidence. The lifecycle
implementation and real host allocation proof remain the respective owners' work.
