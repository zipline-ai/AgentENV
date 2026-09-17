# Dispatch and retirement records (addendum-2)

This freeze implements the coordinator's consolidated items 4/5 ruling. It adds
wire records, not authority issuers, host cessation, or lifecycle consumers.
Canonical field order and types are in schema.json. All three new record bodies
exclude their own digest. Both SignedEnvelope.request_sha256 and body_sha256 are
SHA-256 of the complete canonical body. Existing v1 records retain their original
bytes and digest semantics. References to other records remain explicit body fields.

## DispatchResult

The node signs a completion of one create or restore operation using the existing
node-response/v1 domain. ReceiptResponse.receipt carries that original SignedRecord;
ReceiptResponse.node authenticates the lookup response as before. The body field
dispatch_request_sha256 identifies the originating dispatch request's envelope
digest. It is different from the result's own digest.

SavedDispatchProof.exact_result_id is operation_id. exact_result_sha256 is the
result's envelope request_sha256 (canonical result body digest), **not** a hash of
the SignedRecord container. This supersedes the earlier item-4 container-hash
proposal. It does not change existing BindReceipt or ReleaseReceipt reference rules.

The lifecycle must capture the saved authenticated response of its exact committed
dispatch. A database creation receipt or a newly serialized row is not a substitute.
A running result supplies enrollment/incarnation identity for adoption, not billing
start. P1 remains the first committed database observation after exact running
confirmation. Failed/unknown results retain obligations and authorize no replacement.
Old nodes without this protocol supply no result; initial/LR-C capture stays closed.

## RetirementAuthority

The ProcessEpochAuthorityIssuer signs the committed retire_whole_domain dispatch.
Its domain and audience are agentenv-process-epoch/retire/v1. Exact node/enrollment
recipient coordinates must still match the signed envelope and saved authority.
operation_id equals SealRequest.retirement_authority_id; the matching hash is this
authority's envelope digest. One signed operation ID maps to one immutable hash.
The scope is always the entire runtime incarnation; there is no process-only arm.

The optional affected_seal_receipt tuple contains operation_id and envelope_sha256.
It references the affected seal operation and its receipt's authenticated envelope
digest. Absence does not widen the captured authority. Every timestamp in these new
records is an integer UTC millisecond value; observation times are informational.
The issuer/consumer must enforce expiry, exact scope and saved dispatch matching.
Canonical parsing alone does not validate current authority or time.

## HostCessationEvidence

retirement_operation_id and retirement_request_sha256 refer to the consumed
RetirementAuthority. The node signs this record with node-response/v1 only after
independently conclusive cessation of the exact host allocation, closed admission,
frozen inventory and exclusion of an executing second copy. Enrollment revision is
in the signed envelope and must match the authority and sealed incarnation.

The host claims retirement once in its serialized durable ledger before effect.
It must terminate the exact VM/jailer allocation and independently confirm host
cessation and absence of a second copy. A guest report, pause acknowledgement,
empty process list, resumed old memory or node signature over guest data cannot
produce this evidence. Unknown outcomes retain obligations. There is no automatic
destroy/replace to make a process-only request succeed.

The lifecycle resolver accepts scope_retired only against its own committed
RetirementAuthority and the current trusted node signature, exact incarnation,
enrollment and request hash. A retired incarnation cannot become B. Fresh B/C needs
its own authorized transition. No ledger debit or billing settlement follows from
parsing these bytes.

## Evidence and remaining implementation

Nine positive vectors and seven malformed records exercise the new canonical
records. Two additional negatives exercise a validly signed foreign incarnation
and a guest-key impostor against the trusted node key. Both Go and Rust run them.
Test keys are public fixtures; the same fixture key's use across roles is not a
production trust policy. Production issuer/node/guest roots stay separate.

The cessation_method fixture explicitly says fixture-only-not-execution-evidence.
The actual host primitive, method value and independent no-second-copy proof remain
commit-3 work. These syntax/signature fixtures are not field-8 root/process/PTY/VM
proofs. Existing receipt mirroring, lifecycle resolution and rollout dependencies
remain. No managed capability, bind/release consumer or input path is enabled.

Reproduce: python3 scripts/generate-process-epoch-addendum-2.py.
