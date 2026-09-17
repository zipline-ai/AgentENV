# T-620: bound HTTP shutdown without truncating guest cleanup

Approved implementation scope; no production rollout in this PR. AgentENV fork base:
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
The coordinator deferred the disposable KVM/ublk proof until a node is available.
This cut does NOT prove the 30-second whole-node bound or daemon completion.
Do not shorten guest cleanup or claim this cut solves that separate risk.

**RED → GREEN evidence.** Subprocess test using the production coordinator and
real SIGTERM: upstream sends headers/one frame, then holds its body pending;
with cleanup complete, require exit within the drain budget plus test tolerance
and no surviving HTTP/upgraded tasks. It must fail on today's unbounded wait.
Positive: release a finite response before the deadline and compare every byte.
Barrier tests hold cleanup past HTTP expiry: process must not exit or cancel it;
then release it and prove cleanup order/exactly-once under repeated signals.
Retain existing pause/retry/persist shutdown tests. The deferred disposable KVM/ublk test must prove running and already-paused guests retain restorable state, warm VMs
and daemon finish before exit, and total time is below 30 seconds; no production
experiment. Run focused tests, existing proxy/orchestrator tests, fmt/clippy and
fork CI. Log structured phases: signal, admission_closed, http_drained or
http_drain_expired, cleanup phase start/end/error, exit; include elapsed_ms and
remaining connection counts. These are code logs, not logging configuration.


## Implementation evidence

The pending-body subprocess regression failed against the original unbounded
Axum drain: `sigterm_cancels_a_pending_response_body_after_the_drain_budget`
returned exit 101 because cleanup completed but the body was never dropped.
The production coordinator now owns connection tasks and Hyper HTTP/2 executor
work. Proxy upgrade callbacks acquire tracking before Axum detaches them; expiry
cancels and joins both WebSocket directions. The five-second deadline cancels
transport only. Orchestrator admission closes synchronously before reporter
cleanup starts; existing cancellation-safe lifecycle tasks remain independent.
The existing cleanup sequence is awaited and all phase failures are retained.

The subprocess suite runs from `make test-unit`. It covers finite response bytes,
HTTP/1 and HTTP/2 pending bodies, HTTP/2 pending handlers, held cleanup, repeated
SIGTERM, keep-alive admission, accepted lifecycle work and cleanup failure.
Separate library tests cover bidirectional upgraded transport teardown and the
orchestrator admission/guest-preservation boundary. These are deterministic
transport and mocked lifecycle proofs, not a real KVM/ublk preservation claim.
