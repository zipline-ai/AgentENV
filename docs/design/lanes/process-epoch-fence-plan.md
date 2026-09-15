# T-536: process epoch fence implementation plan r1

Owners: codex-8 (provider) and codex-9 (lifecycle). Plan only; no provider composition or consumer activation is authorized by this document. Review against the app contract at `683610dd4f5c7a4300ba77fffba6a16c51535da6`, `docs/design/lanes/process-epoch-contract.md`. This plan proposes concrete resolutions for pending items 1, 2, 4 and 5. It does not declare that contract's pending list empty.

## Source inventory

Fork baseline: `5fdfcdb`, including async-restore PR #2. Restore operation receipts are separate from execution receipts and grant no process authority. Implementation PR will be rebased on fork main after that prerequisite lands. The tools image currently builds upstream envd tag `2026.17`; the inspected resolved commit is `9c3b7c5dbd181ba819084276b8228f70936e911e`. Pin that full commit and apply a reviewed patch, rather than editing generated clients alone.

| File / anchor | Planned change |
| --- | --- |
| `tools-image/Dockerfile:43–73` | Pin full source commit, apply guest patch, embed source/patch/protocol identity and test the compiled binary. |
| New `tools-image/envd-patches/` and guest patch manifest | Versioned source patch and executable guest tests; patch application must fail on source drift. |
| Upstream `packages/envd/spec/process/process.proto` and generated specs; fork `thirdparty/envd/proto/process.proto` | Add typed epoch authority, exact operation selectors, seal/bind/lookup messages, output coordinates; regenerate Go/Rust clients using existing build tooling. |
| Upstream `internal/services/process/service.go:20,58` | Shared execution gate and exact operation registry; managed requests cannot resolve by PID/tag. |
| Upstream `process/start.go:21,58,62`; `handler/handler.go:423` | Cover ordinary and initialization starts, persist operation claim before spawn, execution admission at actual spawn. |
| Upstream `process/input.go:16,45,63,102`; `handler/handler.go:368,390,410` | Check each input frame and close operation at execution; prevent queued A input from executing after seal. |
| Upstream `process/signal.go`, `update.go`; `handler/handler.go:348,360` | Fence signal and resize, including late work already accepted by the HTTP handler. |
| Upstream `process/connect.go`, `handler/multiplex.go`, `start.go` output forwarding | Bind output to the original process operation/epoch; invalidate stream subscribers at seal. |
| Upstream `internal/api/auth.go:31`; init/config plumbing | Managed mode requires an authenticated controller identity even if legacy access-token setup is absent. An ordinary envd token alone cannot authorize managed mutation. |
| New fork `src/process_epoch.rs`, `src/api/impls/process_epoch.rs`; `src/api/server.rs` | Node-side authenticated descriptor/control/lookup surface, exact-runtime checks and durable receipt mirror. |
| `src/local_store.rs`; new process-epoch tests | Reuse Sync durability and atomic batches in a separate namespace. Do not reuse restore receipts as execution evidence. |
| `src/api/proxy.rs:139,299,712`; `src/sandbox/envd.rs`; `src/orchestrator/service.rs` exact guest access | Saved endpoint only, no automatic resume, managed bypass denial, guest incarnation reconciliation. |
| `services/gateway/internal/`, protocol client generation, fork CI | Exact saved route forwarding, no scheduling fallback, real guest/process/PTY/tmux test job. |

## Proposed protocol and descriptor (pending field 1)

Protocol identifier: `agentenv-process-epoch-v1`. A descriptor contains `protocol`, `node_id`, `node_incarnation`, `runtime_id`, `runtime_incarnation`, `guest_boot_id`, `process_endpoint`, `guest_build_sha256`, `capabilities_sha256`, and `managed=true`. UUID coordinates use canonical lower-case strings; hashes are lower-case SHA-256 hex. Node identity/incarnation come from authenticated node state; runtime identity/incarnation come from the exact retained allocation, never request metadata. The guest supplies a fresh startup boot UUID; snapshot restoration must reconcile it with the node before any epoch opens.

The build digest covers the pinned upstream commit, ordered patch digests, generated protocol descriptor and compiled guest binary digest in a reproducible manifest. A build-time manifest and actual guest handshake must agree. Caller-supplied build strings are not evidence. Unsupported protocol, absent authentication, changed endpoint/incarnation or unreconciled restored state denies managed access. No capability probe enables a consumer.

Proposed authentication: a dedicated controller-signed authority envelope with key ID, audience and expiry, verified by the node and guest against configured public keys. Use Ed25519 and golden canonical-byte vectors shared across Go/Rust. Do not reuse ordinary sandbox access tokens or accept identity from unsigned headers. Trust-root provisioning, key rotation and the lifecycle issuer remain explicit joint dependencies; no guessed production keys or configuration defaults. Keep trust material outside writable user credential volumes.

## Seal request, receipt and outcomes (pending field 2)

The proposed immutable binding is: `protocol`, `tenant_id`, `sandbox_family`, `sandbox_id`, `transition_id`, `launch_id`, `expected_session_id`, `reserved_session_id`, all descriptor coordinates, and `operation_id`. Canonical request bytes are a fixed-order UTF-8 JSON object with no maps, unknown fields, alternate UUID spellings or duplicate keys. Store the exact original bytes and SHA-256; golden vectors define encoding across implementations. The outer signed envelope carries that digest; no circular hash field occurs inside its own input. A changed byte sequence under the same operation ID conflicts.

`SealProcessEpoch` closes admission for expected A under the same gate used at final execution. Persist closing intent before acknowledging it; queued operations must reacquire/check admission, not wait through the seal and execute in B. Track all admitted work until it finishes or is conclusively canceled. No SQL lock or provider network call is part of this guest exclusion.

Receipt fields: immutable binding, `request_sha256`, `receipt_id`, `state` (`sealed` or `incomplete`), `execution_outcome` (`drained`, `scope_retired`, `unknown`), and `affected_operations_sha256`. The digest covers a sorted exact process-operation inventory, not PIDs. A successful receipt requires no unresolved admitted work or effects in that inventory. Persist the first completed receipt before returning it. An incomplete observation is not a successful receipt and cannot authorize bind. Later lookup may observe a subsequently proven terminal receipt; it cannot rewrite one already committed.

A successful stdin write, tcdrain, empty socket buffer or closed stream does not establish that a program consumed PTY input. V1 will conservatively return `incomplete/unknown` for any affected live scope with unproved queued input or continuing effects. It will not kill processes to obtain success. `scope_retired` requires separate explicit captured retirement authority plus real proof that the exact affected process scope has ended; siblings and history are preserved. Processes that escape the provable scope keep the result unknown. This deliberately leaves retained interactive-process handover unavailable until codex-9 and the reviewer approve an implementable retirement/drain policy.

## Lookup, storage and restart (pending field 4)

Proposed node endpoints: POST `/sandboxes/{runtime_id}/process-epochs/seal`, POST `/sandboxes/{runtime_id}/process-epochs/bind`, and GET `/sandboxes/{runtime_id}/process-epoch-operations/{operation_id}`. Guest controls use typed ProcessEpoch RPCs with the identical authority binding. The node checks the saved runtime/incarnation and forwards only to the saved endpoint. Neither node nor gateway may schedule, resume, resolve a newer runtime or redispatch a mutation to answer lookup.

The guest records accepted operation identity/hash and the execution claim in an fsynced journal before the effect. Node mirrors receipt evidence in a separate Sync LocalKvStore namespace keyed by authenticated controller/tenant/runtime-incarnation/operation ID. A node acceptance record alone is not a successful guest execution receipt. Lost replies recover the first exact committed receipt. Missing records return fixed 404; storage or reconciliation uncertainty returns unavailable/unknown. Neither permits another spawn or epoch bind.

Keep operation identity tombstones indefinitely in v1; no TTL makes an ID reusable. Do not implement evidence GC in this cut. After node/guest restart or snapshot rollback, deny managed work until the saved external ledger and guest journal reconcile their exact identities. A completed node mirror cannot reopen an older guest epoch. A crash between effect and receipt remains unknown unless exact guest evidence proves completion; recovery never repeats the effect. First-bind creation likewise needs external saved creation authority, not a fabricated A or a reset local journal.

## Execution and bind fencing (pending field 5)

Each process has a unique `process_operation_id`; each mutation has its own `operation_id`, immutable digest and epoch binding. Streaming input assigns an operation identity/digest to each data frame; a stream-level admission check is insufficient. Registry lookup is exact, never PID/tag search. Seal and final spawn/write/signal/resize/close share exclusion. Long writes must support cancellation and bounded drain; failure to prove cancellation leaves the epoch closed and incomplete. The seal transport deadline cannot turn incomplete work into success or reopen A.

`BindProcessEpoch` performs an atomic expected-A/transition/seal-receipt comparison before publishing reserved B. No queued A operation is carried into B. Exact replay returns the original receipt; changed scope or seal conflicts. Initial bind is a separate operation requiring saved creation authority and an unused exact guest incarnation. The request/receipt fields for first bind and the lifecycle publication transaction are pending joint contract items 3 and 7; implement no success stub while those are unresolved.

Managed guests deny the old PID/tag process mutation paths even through direct envd access. Audit initializer/bootstrap process starts as separate authority: managed boot cannot silently use an unrestricted legacy initialization path. Ordinary unmanaged guests keep their current protocol. Output chunks retain epoch, process operation and terminal incarnation; seal cancels the old subscribers. App-buffered output invalidation is codex-9's participant and remains required before consumers activate.

## Implementation and tests

One fork implementation PR with reviewable commits: (1) pinned source/build manifest and typed protocol with invalid-descriptor tests; (2) durable guest operation registry plus seal/bind exclusion and real process tests; (3) authenticated exact node/gateway forwarding, restart reconciliation and hard CI job. If the guest patch cannot be reviewed as one PR, split after the dormant protocol/registry commit; neither partial cut advertises a usable capability. App registration/composition is a later jointly reviewed PR after the contract pending list is empty.

Write red tests before enforcement. These named proofs from the versioned contract are commitments, not existing passing tests:

- `TestProcessEpochSealOrdersEveryMutation`: real child processes and PTYs; barriers before admission and immediately before the actual effect; both orders for spawn, stdin, signal, resize, close, and queued stream frames. Assert exact operation IDs and zero denied effects.
- `TestProcessEpochUnknownPTYDrainRefusesBind`: unread PTY bytes and blocked writes keep B unavailable; exact tmux sibling remains alive and history unchanged. No sleep-based ordering or tcdrain inference.
- `TestProcessEpochExactOperationReplay`: same operation returns first receipt; changed bytes/scope/epoch/incarnation denied; kill server after claim and after effect, reopen journal, lose replies, and prove no duplicate spawn or PID fallback.
- `TestProcessEpochRestoredGuestAndProxyBypassDeny`: wrong build, unsupported guest, stale snapshot ledger, direct envd, proxy host/path and gateway fallback all deny; zero resume/scheduler calls.
- `TestProcessEpochOutputDoesNotCrossSeal`: hold an output subscriber across seal, then release; no A chunk reaches B, prior displayed history retained. Codex-9 supplies the app half.

CI must execute the patched guest binary with real process/PTY/tmux fixtures, not only mocked Rust clients. Run guest Go tests with race detection, Rust build/tests/clippy, gateway tests/race, protocol generation drift checks and image build. Fork Actions' pending admin opt-in blocks PR READY, not this plan. Local logs are interim evidence. Build/import/select and live operations remain coordinator-owned.

## Contract and release blockers

Before provider composition, publish final DTO/golden vectors, descriptor authentication/trust provisioning and exact first-receipt lookup semantics into the jointly owned versioned app contract. Obtain codex-9 confirmation of saved authority, first bind, install/replay/neutral recovery and explicit process retirement policy. Do not remove pending rows merely because this plan proposes fields.

Release additionally requires codex-9's real-PG `TestFundedEpochRequiresExactSealBindReceipt`, `TestFundedEpochReceiptReproofDuringProviderBarrier`, and `TestFundedEpochNeutralReceiptRecovery`, combined provider barriers, tested guest/node/gateway image digests, compatible rollout approval and exact-head CI. No billable session is invented from a provider receipt, and no current session is inferred from runtime generation. #125/#127 boot bounds/markers and #134 retained-runtime cancellation/accounting contracts remain unchanged.
