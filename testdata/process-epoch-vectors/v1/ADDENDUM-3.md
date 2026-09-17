# Authenticated dispatch and retirement response mapping (addendum-3)

Contract r4 c654e745 and addendum-2 e59d5424. This is an additive wire freeze.
It adds no live producer, lifecycle authority, managed capability or cessation proof.
Earlier frozen fixture bytes, record fields and digest rules remain unchanged.

## ReceiptResponse and saved-result mapping

Use the addendum-1 container in its fixed order: node, optional guest, optional
receipt. The node member is a fresh node-signed LookupResponse. The receipt member
is the first immutable node-signed record, retaining its original envelope, nonce,
expiry and signature. A missing record cannot satisfy a present reference tuple.
The two new arms forbid a guest member; guest output cannot supply either result.

| Lookup state | receipt_kind | receipt.body | receipt_id |
| --- | --- | --- | --- |
| dispatch_completed | dispatch_result | DispatchResult | DispatchResult.operation_id |
| retired | host_cessation | HostCessationEvidence | HostCessationEvidence.retirement_operation_id |

Every arm carries the full exact saved EpochBinding, positive node_ledger_revision,
request_sha256 and complete receipt reference tuple. receipt_sha256 is SHA-256 of
**the complete canonical SignedRecord**: body, historical envelope and signature.
The wrapper request_sha256 (in body and envelope) identifies the original committed
dispatch/retirement request. It equals DispatchResult.dispatch_request_sha256 or
HostCessationEvidence.retirement_request_sha256, respectively. binding.operation_id
and receipt_id equal the original dispatch/retirement operation ID. The wrapper's
revision describes the current saved lookup observation and cannot precede the
historical record revision. Recovery never changes the historical record bytes.

The standalone result's own envelope request_sha256 remains SHA-256 of its canonical
body, as frozen in addendum-2. SavedDispatchProof.exact_result_sha256 uses that digest;
it does NOT use LookupResponse.receipt_sha256. exact_result_id remains operation_id.
Thus the fresh wrapper identifies the original request, its reference authenticates
the entire historical record, and the lifecycle result reference uses the unchanged
addendum-2 body/envelope digest. None are interchangeable.

The receiving lifecycle verifies the fresh node signature against current independently
pinned node trust, audience, domain, key/trust revision, descriptor, exact saved node/
runtime/incarnation/enrollment, nonce and expiry. The nonce belongs to this authenticated
completion request or lookup. The request hash stays the original operation hash, never
the lookup transport body hash. It separately verifies the historical record with its
approved node key and original scope. Historical expiry is not a fresh grant: the fresh
wrapper supplies current lookup authentication, without re-signing the first record.
Exact replays keep the same record reference; changed scope/hash/record bytes conflict.
Old nodes lacking these arms remain unavailable for positive result capture.

## Dispatch completion

For create and restore, all node/runtime/incarnation/boot/endpoint/build/enrollment
fields in DispatchResult must equal the saved result binding being consumed. Tenant,
owner/creation authority, reserved session, template/body and saved route still come
from the independently proven committed dispatch; a signed wrapper cannot invent them.
The frozen outcome values running, failed and unknown all have a dispatch_completed
wrapper when an immutable DispatchResult exists. This state means a saved result record
is available, not successful execution. With no saved record, retain the existing
claimed/unknown states and no receipt tuple. Failed/unknown records retain obligations
and authorize neither a replacement dispatch nor adoption. Running is enrollment/result
identity only; P1 remains the first committed DB observation after exact confirmation.

## Host evidence and the affected seal

The retired arm delivers retained evidence for the exact committed RetirementAuthority
pair (operation_id, envelope digest). Its runtime/incarnation and envelope enrollment
must match that authority and the separately saved affected seal. If the authority has
an affected_seal_receipt tuple, resolve that exact tuple from the committed authority;
the lookup does not select, reassign or invent a seal. The optional tuple's absence does
not authorize broader scope. The lifecycle's installProcessEpochReceiptTx still proves
its issued whole-domain authority, closed admission, frozen inventory and independently
conclusive host cessation with no executing second copy under contract r4. A node
signature over guest data is not this evidence. A retired incarnation never becomes B.
Missing/unknown host evidence uses unknown without a receipt tuple and retains obligations.
No settlement, release or replacement follows merely from parsing a retired wrapper.

## Reproduction and limitations

Run scripts/generate-process-epoch-addendum-3.py. addendum-3-manifest.json contains
canonical/signature positives, malformed vocabulary/reference negatives, and contextual
response negatives with independently saved expected bindings/nonces. Go and Rust verify
these same bytes, historical record preservation and signature/digest relationships.
The outer fixture signature is serializer test scaffolding; the transport signatures
are the node and receipt members. Published test keys and fixture cessation methods
are not real host evidence, authenticated provisioning or field-8 execution tests.
No service response producer, bind/release consumer or pool assignment is enabled.
