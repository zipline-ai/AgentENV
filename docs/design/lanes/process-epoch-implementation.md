# T-536 provider implementation

Approved provider plan: branch `nikhil/process-epoch-fence-plan`, through
`0b25607adfb5adc1c58dfb2d55cac89023c4dfda`. The coordinator authorized the conservative
host-ledger/routing/forwarding/refusal implementation after the root-threat review.
The exact joint lifecycle contract r3 at `42ae960e` is confirmed. Nothing here composes
bind/release, enables consumers, or advertises a managed capability.

This first commit contains the isolated durable operation ledger, typed records,
receipt classification refusal and pinned guest build inputs. It is based directly
on fork main, independent of the open async-restore PR. The ledger APIs are storage
primitives, not authorization: future authenticated routing must supply exact host
allocation and saved lifecycle authority. No production caller is installed.

A claim is persisted once before forwarding and has no evidence class. A claim alone does not prove forwarding. Its operation ID has one immutable
request hash; retries cannot dispatch again. Reopening requires existing host
storage and the same allocation. Neither host-dispatch records nor guest reports
prove cessation; no successful stop/bind receipt constructor is provided. Admission
records are not charges or proof that CPU was funded.

Remaining commits: authenticated exact host allocation/route participants, executable
once-only forwarding and refusal tests; pinned guest cooperative protocol patch and
real root-tampering/process/PTY/tmux fixtures; crash/effect boundaries and host
receipt evidence. Per-process authority may not stop siblings; it stays incomplete.
No automatic stop/replace is permitted to manufacture success. Host cessation needs
separately captured authority and independently observed exact scope termination.

Local commands and exit codes will be recorded in the PR as they finish. Fork CI
still requires the admin Actions opt-in. Real patched guest and full provider tests
remain required; first-commit ledger tests do not claim those release proofs.

Provider confirmed consolidated app contract r3 `42ae960e`; field 8 remains pending.

## Commit 1b: reconciliation and directory publication

Every reopen durably increments `recovery_revision` and sets admission to
`unreconciled`. The saved positive `enrollment_revision` and exact allocation must
match; callers cannot replace them on reopen. New claims require confirmed directory
publication and reconciled Open state for the same epoch. Exact saved claim replay
still returns false, and retained evidence stays readable. Reconciliation CASes the
saved allocation, recovery revision and epoch; it cannot advance enrollment, change
an existing epoch, bind/release work or reopen a closed enrollment. Those transitions
still require the later authenticated lifecycle/provider participants.

The future authenticated participant must independently prove the saved enrollment;
reading this ledger's snapshot is not authority. A stale/corrupt/missing anchor cannot
be reset through these primitives. Closing admission persists independently of the
recovery state so restart cannot erase it. Close is not cessation or settlement proof.

Initialization first records a pending directory-confirmation obligation, then fsyncs
the parent directory, then durably marks confirmation before enabling initial claims.
Failure returns an error and leaves the obligation pending. Reopen never equates an
existing directory with confirmation; an explicit successful retry is required and
still does not reconcile/open admission. Missing recovery storage remains unavailable.

Tests include the reviewer reopen scenario, stale recovery/enrollment and changed-epoch
denials with whole-ledger equality, an observed before-commit reconciliation barrier,
concurrent reconciliation and queued claim, closure across restart, injected parent
sync failure before/after the actual fsync, a blocked confirmation barrier and retry.
These are storage/ordering proofs, not a simulated power cut or a real malicious-root
process/PTY proof; field 8 remains pending.

## Canonical wire prerequisite

The v1 bundle lives in `testdata/process-epoch-vectors/v1`. It freezes descriptor,
seal request/receipt, tagged initial/transition bind (including restore bridge), bind
receipt, lookup, stream open/frame, guest receipt, node response and release records.
The signed envelope has independent domain, recipient/enrollment, saved request hash,
body hash, nonce, trust revision and expiry. The README defines exact signing bytes.
Go and Rust use the same 14 signed fixtures and 16 negative byte fixtures. Both also
reject changed owner/adoption against the unchanged signed envelope. The generated
records come from the committed schema; regeneration is deterministic.

This is a wire prerequisite only. Authenticated saved-authority routing, once-only
forwarding, host cessation, root/process/PTY tests and lifecycle composition are
still pending. Receipt references are untrusted data, not host-stop proof objects.
The accepted commit-1 ledger and its eleven tests are unchanged. No capability,
consumer, route or image behavior is activated.

## Commit 2 historical checkpoints

The reserved epoch namespace now refuses before generic gateway authentication/
routing and before node proxy classification. The red gateway test recorded
Schedule/LookupNode calls; the red node test entered auto-resume on a paused fixture.
Both focused regressions pass after the refusal guards.

At the first checkpoint the candidate pin verifier compiled only in tests. It proves signatures
and exact captured coordinates against test host pins, including correctly re-signed
foreign bodies and stale envelope authority. It does not implement authenticated
provisioning or a production authority factory. Do not use it as that proof.

`begin_close` atomically records a new operation, closes admission and saves its
sorted exact inventory/digest. A sixteen-way close race has one winner. Replay after
restart preserves the original inventory and never grants forwarding again. These
records acknowledge closing intent only; they provide no drain or cessation evidence.

Still required for commit 2: authenticated provisioning/response chain, durable
original request and once-only exact transport, saved-operation recovery, refusal/
transport barriers and the final validation run. No managed capability, lifecycle
bind/release or terminal/input consumer is enabled by this checkpoint.

### Original close request persistence

The close transaction now saves the original canonical request, signed envelope,
signature and captured descriptor with its frozen inventory. Structural binding and
hash checks reject mismatched epochs/allocations before writing. Signature authority
still belongs to the authenticated participant; the ledger does not authenticate a
caller. Replays require identical saved bytes. An older hash-only claim cannot be
upgraded into a recorded request. Restart lookup returns historical bytes and leaves
admission unreconciled; it never grants another dispatch.

Red: `cargo test --locked --lib process_epoch::tests::original_close -- --nocapture`
exit 101, both regressions failed. Green: `cargo test --locked --lib process_epoch::
-- --nocapture` exit 0, 20 passed. Logs: `/tmp/lanes/aenv3-c2-original-{red,green}.log`.
Commit 2 remains incomplete until authenticated provisioning, once-only dispatch,
response mirroring and exact recovery are connected and tested.

### Exact channel primitive (dormant)

The channel pins its peer certificate and host client identity, accepts only an
HTTPS origin, and fixes the seal and exact-operation lookup paths. It disables
redirects, proxies and transport retries. The request and response byte caps are
256 KiB and 64 KiB; the complete request/response budget cannot exceed 30 seconds.
Certificate inputs must come from authenticated enrollment. This primitive does
not implement that enrollment or independently authorize an operation. It is not
wired into a route, consumer or managed capability.

Real mutual-TLS tests prove certificate denial on both sides with zero HTTP requests,
unsafe endpoint/budget refusal, and a full POST followed by a lost response on a
reused connection. Recovery reads the same operation on a new connection, with
exactly one POST recorded. A separate redirect regression failed with the default
client (it followed 307) and passes with redirects disabled. Fixture setup first
needed explicit Rustls crypto-provider/backend selection; those setup errors are
not counted as the behavioral reproduction.

Behavioral red log: `/tmp/lanes/aenv3-c2-transport-red-configured.log` (exit 101,
redirect assertion; two controls passed). Focused green log:
`/tmp/lanes/aenv3-c2-transport-green.log` (exit 0, 25 process-epoch tests passed).
This is still not the complete commit-2 dispatch participant: authenticated
provisioning, claim-to-forward composition and response mirroring remain required.

Local checkpoint validation uses `CARGO_BUILD_JOBS=1` and
`CARGO_TARGET_DIR=/workspace/lanes/agentenv-fast-boot-f1/target`:

- `cargo test --locked --lib`: exit 0, 794 passed, four existing ignored tests unchanged.
- `cargo build --locked --lib --bin server`: exit 0.
- `cargo clippy --locked --lib --bin server --tests -- -D warnings`: exit 0.
- `git diff --check`: exit 0.

Logs use `/tmp/lanes/aenv3-c2-original-transport-{lib-final,build,clippy}.log`.
Fork Actions remains disabled pending the admin opt-in; this is local evidence.

## Commit 2: authenticated participant

`HostTrust::verify` authenticates canonical host enrollment and build manifest
records with separate operator and release roots. It checks the exact allocation,
enrollment and recovery revisions, existing funded session, controller key and trust
revision, expiry, independently approved manifest hash, protocol schema, build and
host-mapped tools artifact. `VerifiedEnrollment` has no public unchecked constructor.
The frozen v1 vectors are unchanged.

`Participant::new` checks the host signing key and both certificate fingerprints
against that enrollment before constructing the exact mutual-TLS channel. The seal
participant verifies controller authority, then atomically closes admission, freezes
inventory and saves the original signed request before one POST. The claim rechecks
the captured recovery revision under the ledger lock, so reconciliation cannot admit
a queued old participant. Caller cancellation
does not cancel the claimed continuation. Lost responses retain the claim; recovery
uses an authorized GET for the exact saved operation, never another POST. Generic
routes remain refused and no consumer or managed capability is enabled.

Provider initialization is stamped in the parent enrollment in the same synchronous
batch as its immutable binding and revision. Missing binding, revision or first
mirrored report refuses recovery instead of resetting authority or replacing evidence.
A reopened closed ledger needs a new signed reconciliation attestation for its exact
recovery revision. This restores closed lookup only, never opens the old epoch.

Mirroring stores the first canonical guest-signed response and advances the durable
revision atomically. Every disclosure revalidates stored bytes and current caller
proof. Historical guest signature expiry does not prevent recovery with fresh lookup
authority. `AuthenticatedResponse` returns the node-signed LookupResponse and the
original guest SignedRecord; the node evidence digest binds that complete backing
record. A guest completion claim remains `guest_reported` and an incomplete outcome.
No node signature or mirror turns it into cessation, settlement or funding evidence.

### Provisioning handoff and release dependencies

The operator enrollment signer must independently establish the exact host runtime,
incarnation, boot/endpoint, enrolled keys and mapped artifact before signing. Comparing
a caller's descriptor to another caller-supplied value is not sufficient. The release
signer identifies the initial approved artifact, not continuing guest honesty. This
cut supplies the verifier and callable participant; the production workload-identity,
host-inventory and per-boot certificate provisioning adapter remains uninstalled.

Trust roots, approved manifest policy, node signing keys, client identity and ledger
must be provisioned outside tenant-accessible storage. Separate operator, release
and controller roots sign distinct domains. Enrollment signing uses
`agentenv-process-epoch/host-enrollment/v1`; manifest signing uses
`agentenv-process-epoch/release-manifest/v1`, each followed by NUL and canonical bytes.
The operator controls key creation and distribution. Rotation/revocation must first
close old admission and preserve its ledger; this cut refuses an in-place anchor or
trust replacement. It does not supply an automatic key-rotation or re-enrollment path.
Existing participants require explicit host revocation and expiry; replacing a config
object alone is not live revocation. No secrets or signer endpoint are exposed by RPC.

Real TLS fixtures exercise the production participant factory and exact signed POST.
They do not count as patched-guest, malicious-root, process/PTY or host cessation
proofs. Those fixtures, independently conclusive whole-domain cessation, lifecycle
bind/release composition, production provisioning and field-8 image/build evidence
remain release dependencies. No success receipt constructor is added here.

### Commit 2 regression evidence

Red logs under `/tmp/lanes/aenv3-c2-` include `enrollment-red` (unavailable verifier),
`participant-red` (unavailable participant), `anchor-red` (missing anchor and revision),
`evidence-red` (missing backing signature, corrupt mirror and historical expiry),
`lookup-expiry-red` (expiry at the admission barrier), and `loss-red` (lost child records
incorrectly healed), and `reconciliation-race-red` (old participant forwarded after
reconciliation advanced). Each command exited 101 before its fix. Tests retain whole-ledger
comparisons and exact request/count assertions. The final local commands and exit
codes are recorded in the PR; Actions still requires the administrator opt-in.

Final library validation: `CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/workspace/lanes/agentenv-fast-boot-f1/target cargo test --locked --lib`
exited 0: 813 passed, four existing ignored tests unchanged, including all 45
process-epoch tests. The final race regression failed first with one POST instead of
zero, then passed in this full run. Log: `/tmp/lanes/aenv3-c2-final-lib-r2.log`.

On the same final code, `cargo build --locked --lib --bin server` and
`cargo clippy --locked --lib --bin server --tests -- -D warnings` both exited 0.
Logs: `/tmp/lanes/aenv3-c2-final-{build,clippy}-r2.log`, adjacent `.exit` files.
`cargo fmt --all -- --check` and `git diff --check` also exited 0. Fork Actions
remains disabled pending administrator opt-in; these results are local evidence.
