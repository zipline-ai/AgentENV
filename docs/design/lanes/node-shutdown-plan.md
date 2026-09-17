# T-620: bound HTTP shutdown without truncating guest cleanup

Plan for codex-7; no implementation or rollout yet. AgentENV fork base:
`39bfa34` (origin/main); the inspected process-epoch branch has the same server
shutdown sequence. Unit/package/log-pipeline changes remain separate.

**Cause and files.** `src/bin/server.rs:169–209` starts cleanup on SIGTERM
concurrently with HTTP drain, then awaits Axum before joining cleanup. Axum
0.8.8 `serve/mod.rs:269–287` stops accepting but waits for all connection tasks
without a deadline. `src/api/proxy.rs:1088` forwards `Incoming` response bodies
without shutdown cancellation; its WebSocket bridge at 1096 also waits on both
streams. Header timeouts do not bound either response lifetime.

**Proposed fix.** Use one named **5-second HTTP drain budget**, starting at the
first SIGTERM/Ctrl-C, not at server start. Stop admission immediately; allow
finite responses to finish during that grace. At expiry cancel remaining proxy
bodies/upgrades and close/reap tracked HTTP connection work. Keep routing/auth
unchanged. Extract the production shutdown coordinator into a testable helper
beside `src/bin/server.rs`, with proxy cancellation in `src/api/proxy.rs`.
Prefer owned connection cancellation over merely dropping `axum::serve`:
Axum spawns connection tasks, so dropping its outer future is not cancellation.
Do not cancel guest lifecycle tasks when cancelling HTTP transport.

**Cleanup contract and limit.** Keep reporter → orchestrator → warm pool →
ublk → overlay/P2P cleanup running concurrently with HTTP drain, and await it
before returning from main; no `process::exit`, cleanup timeout or abort.
Record errors, never label failed cleanup complete. Five seconds removes the
HTTP wait well before `TimeoutStopSec=30`; it does **not** prove a 30-second
whole-node bound. Reporter unregister alone can use 3×10 seconds plus backoff
(`reporter.rs:219`); orchestrator retries/transitions are unbounded in aggregate
(`service.rs:2360`, 60-second transition wait); ublk's five-second shutdown RPC
acknowledges initiation, not daemon exit. Preserve these semantics/budgets.
If real-guest cleanup misses 30 seconds or daemon completion is unproved, report
a release blocker rather than shortening cleanup or claiming this cut solves it.

**RED → GREEN evidence.** Subprocess test using the production coordinator and
real SIGTERM: upstream sends headers/one frame, then holds its body pending;
with cleanup complete, require exit within the drain budget plus test tolerance
and no surviving HTTP/upgraded tasks. It must fail on today's unbounded wait.
Positive: release a finite response before the deadline and compare every byte.
Barrier tests hold cleanup past HTTP expiry: process must not exit or cancel it;
then release it and prove cleanup order/exactly-once under repeated signals.
Retain existing pause/retry/persist shutdown tests. A disposable KVM/ublk node
must prove running and already-paused guests retain restorable state, warm VMs
and daemon finish before exit, and total time is below 30 seconds; no production
experiment. Run focused tests, existing proxy/orchestrator tests, fmt/clippy and
fork CI. Log structured phases: signal, admission_closed, http_drained or
http_drain_expired, cleanup phase start/end/error, exit; include elapsed_ms and
remaining connection counts. These are code logs, not logging configuration.
