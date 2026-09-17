# T-631/T-632: preserve guests before shutdown telemetry

Review only, fork main `8cda52c`. No production changes; preserve
`TimeoutStopSec=30`, unit/package settings and HTTP drain.
Evidence: zippy `node-rollout-proof.md` at `3f252273`, `/tmp/lanes/t629/`.

**Failure timeline (September 17 UTC).** SIGTERM at 16:19:49.094664; admission
closed and HTTP drained by 49.094739. Cleanup entered **reporter**, not guest
preservation. Unregister attempt 1 expired at 16:19:59.096857, then 200 ms backoff;
attempt 2 expired at 16:20:09.299131, then 400 ms backoff; attempt 3 was still
pending when systemd sent SIGKILL at 16:20:19. Guest cleanup never started.
Stop returned at +41.608 s with five Firecracker processes left. Direct-SIGTERM
control: reporter +31.206 s (three calls, 200/400/600 ms backoffs), guest cleanup
502 ms, exit +31.883 s. Restart lost the running guest's record.

**Ordering and budget.** In `src/bin/server.rs`, start owned guest preservation
and reporter shutdown concurrently at the first signal, after closing admission.
Retain the accepted-operation join before pause/persist; never abort lifecycle
work. Keep guest → warm pool → ublk → P2P dependency ordering and join cleanup on
HTTP errors too. In `src/observability/reporter.rs`, use one absolute **2-second
budget from the signal**, including stopping heartbeat/event senders and at most
one unregister attempt: no retries/backoff. Cancel and join reporter-only tasks
and abandon an unfinished RPC at expiry; do not detach them or report successful
unregister. Two seconds fits within HTTP drain; guest cleanup gets the full window. Log
monotonic phases, remaining operations and unregister outcome. A missed unregister leaves stale
scheduler observations/bindings; observed status expires after its configured
report TTL (default 30 s), not instantly. This is not scheduler exclusion and
does not guarantee removal of assignments. No scheduler changes in this cut.

**Separate persistence bug.** `src/orchestrator/persistence/file_backed.rs:278`
deletes Resuming records/artifacts on startup, independently of reporter order.
The smallest safe fix retains their exact bytes and includes their artifact IDs
in orphan-GC retention, with an explicit unresolved-recovery diagnostic. Do not
relabel them Paused, publish a route or replay resume: the prior VM might have
started. Graceful shutdown still joins the accepted resume through preservation
or rollback. Automatic crash recovery still requires exact-runtime reconciliation; retention
is not recovery or a bound on hung storage.

**RED → GREEN.** Extend `tests/http_shutdown.rs` with the real shutdown
coordinator, real reporter/fake scheduler that first accepts heartbeat, real
Orchestrator and disk persister: `reporter_stall_cannot_delay_guest_persistence`
(held-forever unregister + running mock guest, subprocess SIGTERM, guest cleanup
observed before reporter expiry, exit <10 s and intact reloadable record);
`resuming_across_signal_preserves_record` (observed backend barrier, HTTP expiry,
then release; no early exit, lifecycle join before cleanup); and
`crash_resuming_record_and_artifacts_survive_repeated_load` (byte equality,
no backend launch/route/GC deletion). Keep healthy-reporter/repeated-signal/HTTP-error/cleanup-held controls and prove
reporter joins. Run proxy/orchestrator/persistence tests, fmt and clippy.

**Next disposable proof.** Repeat the isolated real running/paused guests,
held proxy, reporter-held and lifecycle barriers, exact hashes/counters/volumes,
upgrade/rollback, and unchanged 30-second systemd stop. Include interrupted
Resuming retention without claiming automatic recovery. Add T-633's old ublk
socket-delay beyond 30 seconds, checking actual daemon exit/readiness and guest
fidelity; review the external fault mechanism first because the resident stop
helper kills/unlinks after ~10 seconds. Do not bypass the helper or shrink cleanup budgets. Archive and delete resources.
Rollout remains blocked on real cleanup/recovery proof, including unresolved
Resuming recovery; telemetry changes alone cannot guarantee whole-node timing.
