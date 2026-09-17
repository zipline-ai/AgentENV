//! Exercises the production HTTP shutdown coordinator with real TCP and SIGTERM.
//! The cleanup callback is a barrier-controlled stand-in, not real-guest proof.

#![cfg(unix)]

use std::{
    collections::VecDeque,
    io::{BufRead, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    time::Duration,
};

use agentenv::api::shutdown::{serve_with_shutdown, ShutdownState, HTTP_DRAIN_BUDGET};
use axum::{
    body::Body,
    response::Response,
    routing::{get, post},
    Router,
};
use bytes::Bytes;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
};

const PREFIX: &str = "HTTP_SHUTDOWN:";
const WAIT: Duration = Duration::from_secs(10);

fn marker(value: &str) {
    println!("{PREFIX}{value}");
    std::io::stdout().flush().unwrap();
}

struct BodyGuard;

impl Drop for BodyGuard {
    fn drop(&mut self) {
        marker("BODY_DROPPED");
    }
}

struct EventGuard(&'static str);

impl Drop for EventGuard {
    fn drop(&mut self) {
        marker(self.0);
    }
}

struct CleanupGuard(bool);

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if !self.0 {
            marker("CLEANUP_CANCELLED");
        }
    }
}

/// This test is also the subprocess entry point. Normal suite runs do nothing.
#[tokio::test]
async fn shutdown_child() {
    let Ok(mode) = std::env::var("AGENTENV_HTTP_SHUTDOWN_CHILD") else {
        return;
    };
    tracing_subscriber::fmt()
        .json()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stdout)
        .try_init()
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    let (body_tx, body_rx) = oneshot::channel();
    let (cleanup_tx, cleanup_rx) = oneshot::channel();
    let (lifecycle_tx, lifecycle_rx) = oneshot::channel();
    let (lifecycle_done_tx, lifecycle_done_rx) = oneshot::channel();

    // A plain thread avoids Tokio stdin's uncancellable blocking read keeping
    // the runtime alive after the coordinator has returned.
    std::thread::spawn(move || {
        let mut body_tx = Some(body_tx);
        let mut cleanup_tx = Some(cleanup_tx);
        let mut lifecycle_tx = Some(lifecycle_tx);
        for line in std::io::stdin().lock().lines() {
            match line.unwrap().as_str() {
                "release-body" => {
                    let _ = body_tx.take().unwrap().send(());
                }
                "release-cleanup" => {
                    let _ = cleanup_tx.take().unwrap().send(());
                }
                "release-lifecycle" => {
                    let _ = lifecycle_tx.take().unwrap().send(());
                }
                "probe" => marker("PROBE"),
                other => panic!("unexpected command: {other}"),
            }
        }
    });

    let body_rx = Arc::new(Mutex::new(Some(body_rx)));
    let app = Router::new().route(
        "/stream",
        get(move || {
            let receiver = body_rx.lock().unwrap().take().unwrap();
            async move {
                // The guard belongs to the body itself, including while its
                // next frame is pending. Dropping a handler is insufficient.
                let stream = futures::stream::unfold(
                    (0, receiver, BodyGuard),
                    |(step, receiver, guard)| async move {
                        match step {
                            0 => Some((
                                Ok::<_, std::io::Error>(Bytes::from_static(b"first-frame\n")),
                                (1, receiver, guard),
                            )),
                            1 => {
                                receiver.await.unwrap();
                                Some((
                                    Ok(Bytes::from_static(b"last-frame\n")),
                                    (2, oneshot::channel().1, guard),
                                ))
                            }
                            _ => None,
                        }
                    },
                );
                Response::new(Body::from_stream(stream))
            }
        }),
    );
    let lifecycle = Arc::new(Mutex::new(Some((lifecycle_rx, lifecycle_done_tx))));
    let app = app
        .route("/ready", get(|| async { "ready" }))
        .route(
            "/mutation",
            post(|| async {
                marker("MUTATION_EFFECT");
                "mutated"
            }),
        )
        .route(
            "/lifecycle",
            post(move || {
                let (release, done) = lifecycle.lock().unwrap().take().unwrap();
                async move {
                    let _handler_guard = EventGuard("HANDLER_DROPPED");
                    let (result_tx, result_rx) = oneshot::channel();
                    // Mirrors Orchestrator::run_cancellation_safe: HTTP owns the
                    // receiver, while accepted lifecycle work runs independently.
                    tokio::spawn(async move {
                        let mut guard = CleanupGuard(false);
                        marker("LIFECYCLE_STARTED");
                        release.await.unwrap();
                        marker("LIFECYCLE_FINISHED");
                        guard.0 = true;
                        let _ = done.send(());
                        let _ = result_tx.send(());
                    });
                    result_rx.await.unwrap();
                    "completed"
                }
            }),
        );
    let hold_cleanup = mode == "cleanup" || mode == "admission";
    let await_lifecycle = mode == "lifecycle";
    let fail_cleanup = mode == "cleanup-error";
    let cleanup = async move {
        let mut guard = CleanupGuard(false);
        marker("CLEANUP_STARTED");
        if hold_cleanup {
            cleanup_rx.await.unwrap();
        }
        if await_lifecycle {
            lifecycle_done_rx.await.unwrap();
        }
        // Observable ordering within a single cleanup invocation, including
        // when its caller has already exhausted the HTTP drain budget.
        marker("CLEANUP_PHASE_ONE");
        if fail_cleanup {
            marker("CLEANUP_PHASE_ONE_ERROR");
        }
        marker("CLEANUP_PHASE_TWO");
        guard.0 = true;
        if fail_cleanup {
            marker("CLEANUP_FAILED");
            return Err(std::io::Error::other("injected first stage failure"));
        }
        marker("CLEANUP_FINISHED");
        Ok(())
    };
    let signal = async move {
        terminate.recv().await.unwrap();
        marker("SIGNAL_RECEIVED");
    };
    let budget = if mode == "finite" || mode == "admission" {
        HTTP_DRAIN_BUDGET
    } else {
        Duration::from_millis(100)
    };
    marker(&format!("READY {address}"));
    let result = serve_with_shutdown(
        listener,
        app,
        ShutdownState::default(),
        signal,
        cleanup,
        budget,
    )
    .await;
    if fail_cleanup {
        assert_eq!(
            result.unwrap_err().to_string(),
            "injected first stage failure"
        );
        marker("ERROR_RETURNED");
    } else {
        result.unwrap();
    }
    marker("RETURNED");
}

struct Harness {
    child: Child,
    input: ChildStdin,
    messages: mpsc::Receiver<String>,
    unmatched: VecDeque<String>,
    observed: Vec<String>,
    address: String,
    mode: String,
}

impl Harness {
    fn start(mode: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "shutdown_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("AGENTENV_HTTP_SHUTDOWN_CHILD", mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (tx, messages) = mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(output).lines() {
                let line = line.unwrap();
                let message = line
                    .split_once(PREFIX)
                    .map_or_else(|| line.clone(), |(_, message)| message.to_owned());
                // Preserve production tracing as well as explicit barriers.
                if tx.send(message).is_err() {
                    break;
                }
            }
        });
        let mut harness = Self {
            child,
            input,
            messages,
            unmatched: VecDeque::new(),
            observed: Vec::new(),
            address: String::new(),
            mode: mode.to_owned(),
        };
        let ready = harness.wait_for("READY ", WAIT);
        harness.address = ready.strip_prefix("READY ").unwrap().to_owned();
        harness
    }

    fn wait_for(&mut self, expected: &str, timeout: Duration) -> String {
        if let Some(index) = self
            .unmatched
            .iter()
            .position(|line| line.starts_with(expected))
        {
            return self.unmatched.remove(index).unwrap();
        }
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let message = self
                .messages
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .unwrap_or_else(|error| {
                    panic!(
                        "waiting for {expected}: {error}; observed {:?}",
                        self.observed
                    )
                });
            self.observed.push(message.clone());
            if message.starts_with(expected) {
                return message;
            }
            self.unmatched.push_back(message);
        }
    }

    fn command(&mut self, command: &str) {
        writeln!(self.input, "{command}").unwrap();
        self.input.flush().unwrap();
    }

    fn terminate(&self) {
        // The child installed its SIGTERM handler before publishing READY.
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) },
            0
        );
    }

    async fn response(&self) -> reqwest::Response {
        tokio::time::timeout(
            WAIT,
            reqwest::get(format!("http://{}/stream", self.address)),
        )
        .await
        .unwrap()
        .unwrap()
    }

    fn finish(&mut self) {
        self.wait_for("RETURNED", WAIT);
        assert!(self.child.wait().unwrap().success());
        self.observed.extend(self.messages.try_iter());
        assert!(!self.observed.iter().any(|line| line == "CLEANUP_CANCELLED"));
        for event in [
            "SIGNAL_RECEIVED",
            "CLEANUP_STARTED",
            "CLEANUP_PHASE_ONE",
            "CLEANUP_PHASE_TWO",
            "CLEANUP_FINISHED",
            "RETURNED",
        ] {
            assert_eq!(
                self.observed
                    .iter()
                    .filter(|line| line.as_str() == event)
                    .count(),
                1,
                "{event}: {:?}",
                self.observed
            );
        }
        let position = |event| self.observed.iter().position(|line| line == event).unwrap();
        assert!(position("CLEANUP_PHASE_ONE") < position("CLEANUP_PHASE_TWO"));
        assert!(position("CLEANUP_FINISHED") < position("RETURNED"));
        if self.mode == "lifecycle" {
            assert!(position("HANDLER_DROPPED") < position("LIFECYCLE_FINISHED"));
            assert!(position("LIFECYCLE_FINISHED") < position("CLEANUP_FINISHED"));
            assert_eq!(
                self.observed
                    .iter()
                    .filter(|line| line.as_str() == "LIFECYCLE_STARTED")
                    .count(),
                1
            );
            assert_eq!(
                self.observed
                    .iter()
                    .filter(|line| line.as_str() == "LIFECYCLE_FINISHED")
                    .count(),
                1
            );
        } else if self.mode != "admission" {
            assert_eq!(
                self.observed
                    .iter()
                    .filter(|line| line.as_str() == "BODY_DROPPED")
                    .count(),
                1
            );
            assert!(position("BODY_DROPPED") < position("RETURNED"));
        }
        assert!(!self.observed.iter().any(|line| line == "MUTATION_EFFECT"));
        self.assert_shutdown_trace(false);
    }

    fn assert_shutdown_trace(&self, cleanup_failed: bool) {
        const PHASES: &[&str] = &[
            "signal",
            "admission_closed",
            "http_drain_expired",
            "http_drained",
            "http_cancelled",
            "cleanup_start",
            "cleanup_finished",
            "cleanup_failed",
            "exit",
        ];
        let phases: Vec<serde_json::Value> = self
            .observed
            .iter()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter_map(|event| {
                let fields = event.get("fields")?;
                PHASES
                    .contains(&fields.get("phase")?.as_str()?)
                    .then(|| fields.clone())
            })
            .collect();
        let phase = |name: &str| {
            let matching: Vec<_> = phases
                .iter()
                .filter(|fields| fields["phase"] == name)
                .collect();
            assert_eq!(
                matching.len(),
                1,
                "expected one {name} event; trace: {phases:?}"
            );
            matching[0]
        };
        let absent = |name: &str| {
            assert!(
                !phases.iter().any(|fields| fields["phase"] == name),
                "unexpected {name}; trace: {phases:?}"
            );
        };
        let mut previous_elapsed = 0;
        for fields in &phases {
            let elapsed = fields["elapsed_ms"]
                .as_u64()
                .expect("overall phase must include elapsed_ms");
            assert!(
                elapsed >= previous_elapsed,
                "overall phase elapsed time moved backwards: {phases:?}"
            );
            previous_elapsed = elapsed;
        }
        assert_eq!(phase("signal")["elapsed_ms"], 0);
        phase("admission_closed");
        phase("cleanup_start");
        let cleanup_outcome = if cleanup_failed {
            "cleanup_failed"
        } else {
            "cleanup_finished"
        };
        phase(cleanup_outcome);
        absent(if cleanup_failed {
            "cleanup_finished"
        } else {
            "cleanup_failed"
        });
        let expired = matches!(self.mode.as_str(), "pending" | "cleanup" | "lifecycle");
        let transport_outcome = if expired {
            let expiry = phase("http_drain_expired");
            assert_eq!(expiry["interrupted_request_outcome"], "unknown");
            assert!(
                expiry["elapsed_ms"].as_u64().unwrap() >= 100,
                "drain ended before its configured budget"
            );
            assert!(
                expiry["remaining_connections"].as_u64().unwrap()
                    + expiry["remaining_tasks"].as_u64().unwrap()
                    > 0
            );
            absent("http_drained");
            "http_cancelled"
        } else {
            absent("http_drain_expired");
            absent("http_cancelled");
            "http_drained"
        };
        for completed in [transport_outcome, "exit"] {
            let fields = phase(completed);
            assert_eq!(fields["remaining_connections"], 0, "{fields}");
            assert_eq!(fields["remaining_tasks"], 0, "{fields}");
        }
        let position = |name: &str| {
            phases
                .iter()
                .position(|fields| fields["phase"] == name)
                .unwrap()
        };
        assert!(position("signal") < position("admission_closed"));
        assert!(position("admission_closed") < position("cleanup_start"));
        assert!(position("cleanup_start") < position(cleanup_outcome));
        assert!(position(cleanup_outcome) < position("exit"));
        assert!(position(transport_outcome) < position("exit"));
        if expired {
            assert!(position("http_drain_expired") < position("http_cancelled"));
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn sigterm_cancels_a_pending_response_body_after_the_drain_budget() {
    let mut child = Harness::start("pending");
    let mut response = child.response().await;
    assert_eq!(response.chunk().await.unwrap().unwrap(), "first-frame\n");
    child.terminate();
    child.wait_for("SIGNAL_RECEIVED", WAIT);
    // Today's unbounded axum drain fails here even though cleanup finishes.
    child.wait_for("BODY_DROPPED", Duration::from_secs(2));
    child.finish();
    // Keep the client open until after coordinator completion so client-side
    // cancellation cannot make the regression pass accidentally.
    let result = tokio::time::timeout(WAIT, response.chunk()).await.unwrap();
    assert!(matches!(result, Ok(None) | Err(_)));
}

#[tokio::test]
async fn finite_response_finishes_without_losing_bytes_during_grace() {
    let mut child = Harness::start("finite");
    let mut response = child.response().await;
    let first = response.chunk().await.unwrap().unwrap();
    child.terminate();
    child.wait_for("SIGNAL_RECEIVED", WAIT);
    child.command("release-body");
    let rest = tokio::time::timeout(WAIT, response.bytes())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        [first.as_ref(), rest.as_ref()].concat(),
        b"first-frame\nlast-frame\n"
    );
    child.finish();
}

#[tokio::test]
async fn cleanup_outlives_http_expiry_and_repeated_sigterm_without_cancellation() {
    let mut child = Harness::start("cleanup");
    let mut response = child.response().await;
    assert_eq!(response.chunk().await.unwrap().unwrap(), "first-frame\n");
    child.terminate();
    child.wait_for("CLEANUP_STARTED", WAIT);
    child.wait_for("BODY_DROPPED", Duration::from_secs(2));
    assert!(child.child.try_wait().unwrap().is_none());
    child.terminate();
    child.command("probe");
    child.wait_for("PROBE", WAIT);
    child.terminate();
    child.command("probe");
    child.wait_for("PROBE", WAIT);
    assert!(!child
        .observed
        .iter()
        .any(|line| line == "RETURNED" || line == "CLEANUP_FINISHED"));
    child.command("release-cleanup");
    child.finish();
    drop(response);
}

#[tokio::test]
async fn keep_alive_connection_cannot_start_a_mutation_while_cleanup_is_held() {
    let mut child = Harness::start("admission");
    let socket = tokio::net::TcpStream::connect(&child.address)
        .await
        .unwrap();
    let mut socket = tokio::io::BufReader::new(socket);
    socket
        .write_all(b"GET /ready HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut line = String::new();
    socket.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("HTTP/1.1 200"), "{line}");
    loop {
        line.clear();
        socket.read_line(&mut line).await.unwrap();
        if line == "\r\n" {
            break;
        }
    }
    let mut body = [0; 5];
    socket.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"ready");
    child.terminate();
    child.wait_for("CLEANUP_STARTED", WAIT);
    // Reuse the already accepted connection. A closed transport and a 503
    // both reject admission; the mutation handler must never run.
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        socket
            .write_all(b"POST /mutation HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
            .await?;
        let mut status = String::new();
        socket.read_line(&mut status).await?;
        Ok::<_, std::io::Error>(status)
    })
    .await
    .expect("admission must close before the five-second drain deadline");
    if let Ok(status) = result {
        assert!(
            status.is_empty() || status.starts_with("HTTP/1.1 503"),
            "{status}"
        );
    }
    assert!(child.child.try_wait().unwrap().is_none());
    child.command("release-cleanup");
    child.finish();
}

#[tokio::test]
async fn accepted_lifecycle_work_survives_handler_cancellation_and_finishes_once() {
    let mut child = Harness::start("lifecycle");
    let mut socket = tokio::net::TcpStream::connect(&child.address)
        .await
        .unwrap();
    socket
        .write_all(b"POST /lifecycle HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    child.wait_for("LIFECYCLE_STARTED", WAIT);
    child.terminate();
    child.wait_for("CLEANUP_STARTED", WAIT);
    child.wait_for("HANDLER_DROPPED", Duration::from_secs(2));
    assert!(child.child.try_wait().unwrap().is_none());
    child.command("probe");
    child.wait_for("PROBE", WAIT);
    assert!(!child
        .observed
        .iter()
        .any(|line| line == "LIFECYCLE_FINISHED"
            || line == "CLEANUP_CANCELLED"
            || line == "RETURNED"));
    child.command("release-lifecycle");
    child.finish();
    drop(socket);
}

async fn http2_client(
    address: &str,
) -> (
    hyper::client::conn::http2::SendRequest<Body>,
    tokio::task::JoinHandle<Result<(), hyper::Error>>,
) {
    let socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let (sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(socket),
    )
    .await
    .unwrap();
    (sender, tokio::spawn(connection))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http2_pending_response_body_is_cancelled_and_reaped() {
    use http_body_util::BodyExt;

    let mut child = Harness::start("pending");
    let (mut sender, connection) = http2_client(&child.address).await;
    let request = hyper::Request::builder()
        .uri(format!("http://{}/stream", child.address))
        .body(Body::empty())
        .unwrap();
    let mut response = sender.send_request(request).await.unwrap();
    let frame = response.body_mut().frame().await.unwrap().unwrap();
    assert_eq!(frame.into_data().unwrap(), "first-frame\n");
    child.terminate();
    child.wait_for("BODY_DROPPED", Duration::from_secs(2));
    child.finish();
    let frame = tokio::time::timeout(WAIT, response.body_mut().frame())
        .await
        .unwrap();
    assert!(matches!(frame, None | Some(Err(_))));
    drop(response);
    drop(sender);
    let _ = tokio::time::timeout(WAIT, connection)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http2_pending_handler_is_reaped_without_cancelling_accepted_lifecycle_work() {
    let mut child = Harness::start("lifecycle");
    let (mut sender, connection) = http2_client(&child.address).await;
    let request = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://{}/lifecycle", child.address))
        .body(Body::empty())
        .unwrap();
    let response = tokio::spawn(async move { sender.send_request(request).await });
    child.wait_for("LIFECYCLE_STARTED", WAIT);
    child.terminate();
    child.wait_for("CLEANUP_STARTED", WAIT);
    child.wait_for("HANDLER_DROPPED", Duration::from_secs(2));
    assert!(child.child.try_wait().unwrap().is_none());
    child.command("release-lifecycle");
    child.finish();
    assert!(tokio::time::timeout(WAIT, response)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    let _ = tokio::time::timeout(WAIT, connection)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn cleanup_failure_is_returned_after_remaining_cleanup_phases_run() {
    let mut child = Harness::start("cleanup-error");
    child.terminate();
    child.wait_for("RETURNED", WAIT);
    assert!(child.child.wait().unwrap().success());
    child.observed.extend(child.messages.try_iter());
    let position = |event| {
        child
            .observed
            .iter()
            .position(|line| line == event)
            .unwrap()
    };
    assert!(position("CLEANUP_PHASE_ONE_ERROR") < position("CLEANUP_PHASE_TWO"));
    assert!(position("CLEANUP_PHASE_TWO") < position("CLEANUP_FAILED"));
    assert!(position("CLEANUP_FAILED") < position("ERROR_RETURNED"));
    child.assert_shutdown_trace(true);
    assert!(!child
        .observed
        .iter()
        .any(|line| line == "CLEANUP_FINISHED" || line == "CLEANUP_CANCELLED"));
}
