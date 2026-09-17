# T-631/T-632: preserve guests before shutdown telemetry

Implementation approved at `b2cdfe5c` with socket-fault addendum `1f4770f3`; based on fork main `8cda52c`. No production changes; preserve
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
Resuming retention without claiming automatic recovery. Archive and delete
resources. Rollout remains blocked on real cleanup/recovery proof, including
unresolved Resuming recovery; telemetry changes alone cannot guarantee timing.

**T-633 fault mechanism (part of this PR's test harness).** After real guests
are paused/persisted and the actual daemon has exited, keep the service stopped.
A pipe-controlled subprocess owns the configured Unix socket as an injected old
socket; it accepts and closes probes without speaking the daemon protocol. Run
the real `UblkDaemonClient::new` with the unchanged 30-second startup deadline
and actual daemon binary from a standalone diagnostic harness, outside systemd.
Hold the socket until the timeout is observed; then command the holder to close,
join its PID, and retry startup. No sleeps establish the barrier. Continuous
acceptance avoids accidentally testing a full listen backlog instead.

Expected: while held, startup times out without spawning a replacement, unlinking
the owned socket or advertising readiness; after release, the real daemon starts,
GetFeatures succeeds, and the same paused guests restore with file/memory/volume
fidelity. Premature spawn/unlink/readiness, a hang beyond the deadline, or failed
restore is FAIL. Record holder PID/socket inode, spawn/exit events and elapsed
time. This is an injected socket-ownership test, **not** evidence of an actual
old daemon completing cleanup or a <30-second unit restart. Keep the real-daemon
exit and unchanged-systemd tests separate. No stop-helper change is needed: the
standalone harness is never an ExecStopPost participant and cannot bypass it in
a service restart. Do not add a production helper bypass or timeout override.


## Implementation and validation

The server closes admission synchronously, then `shutdown_with_reporter` joins
reporting alongside the unchanged orchestrator → pool → ublk → P2P chain.
`shutdown_until` cancels and joins only reporter senders; unregister is one
best-effort call under the absolute signal + 2s deadline. Timeout is logged as
unknown. This is **not a placement fence**: `report_ttl` defaults to 30s before
observed status becomes UNHEALTHY, assignments remain, and discovery scheduling
is not excluded by this reporting budget.

The new ordering tests live in `src/orchestrator/shutdown_ordering_tests.rs`
because the mock backend is library-test-only. They call the same production
coordinator as the unchanged `tests/http_shutdown.rs` controls. The reporter
uses real gRPC wire traffic against an isolated fake scheduler; an empty real
observer orchestrator supplies telemetry, while the guest orchestrator has a
mock backend and a synchronous disk persister. This proves scheduling and
record retention, not KVM/ublk timing.

Recorded REDs: `reporter_stall_cannot_delay_guest_persistence` timed out before
persistence with the original sequential scheduling (exit 101);
`crash_resuming_record_and_artifacts_survive_repeated_load` found the record
missing with the original loader (exit 101). The accepted-resume test is an
already-correct ownership control, not a newly fixed RED. All three named tests
must stay green; do not claim three newly reproduced defects.

The T-633 standalone harness is
`storage/ublk-daemon/examples/socket_wait_probe.rs`. On the next authorized,
isolated disposable node, after guests are preserved and the service and real
daemon are stopped, run it with the real daemon binary/configs:

```sh
cargo run -p uvm-ublk-daemon --example socket_wait_probe --   --disposable-node-service-stopped   --binary /path/to/uvm-ublk-daemon --socket /path/to/daemon.sock   --global-config /path/to/global.json   --resize-global-config /path/to/resize.json --app-config /path/to/aenv.toml
```

It reports holder PID/inode, the unchanged 30s socket wait, then joins the holder
and retries the real daemon with GetFeatures followed by shutdown. The harness
has not been run on a privileged node in this cut. Its success would still need
separate guest restore/fidelity and actual daemon-exit evidence. T-629 remains
a rollout prerequisite; no whole-node <30s guarantee, automatic Resuming
recovery, unit/package changes, or production rollout is claimed.

Local validation: `cargo test --lib` passed 780 tests with four pre-existing
privileged tests ignored; `cargo test --test http_shutdown` passed all nine;
`cargo fmt --all --check` and workspace/all-target/all-feature clippy with
`-D warnings` exited 0. No privileged test or disposable-node proof was run.
The real held-heartbeat test also proves that the shutdown budget covers an
in-flight telemetry RPC, not only a reporter timer.
