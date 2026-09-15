# T-536 implementation checkpoint

Approved provider plan: branch `nikhil/process-epoch-fence-plan`, through
`0b25607adfb5adc1c58dfb2d55cac89023c4dfda`. The coordinator authorized the conservative
host-ledger/routing/forwarding/refusal implementation after the root-threat review.
The joint lifecycle contract is still being consolidated. Nothing here composes
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
