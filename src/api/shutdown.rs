//! A transport-only drain deadline. Guest preservation is never cancelled here.
use std::{
    future::Future,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    extract::State,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Router,
};
use hyper_util::{rt::TokioIo, server::conn::auto::Builder, service::TowerToHyperService};
use tokio::{net::TcpListener, task::JoinSet, time::Instant};
use tokio_util::{
    sync::CancellationToken,
    task::{task_tracker::TaskTrackerToken, TaskTracker},
};
use tracing::{info, warn};

pub const HTTP_DRAIN_BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct ShutdownState {
    accepting: Arc<AtomicBool>,
    force: CancellationToken,
    tasks: TaskTracker,
}

impl Default for ShutdownState {
    fn default() -> Self {
        Self {
            accepting: Arc::new(AtomicBool::new(true)),
            force: CancellationToken::new(),
            tasks: TaskTracker::new(),
        }
    }
}

impl ShutdownState {
    // Acquire before on_upgrade detaches the callback, including pending/failed upgrades.
    pub(crate) fn upgrade_guard(&self) -> TaskTrackerToken {
        self.tasks.token()
    }

    pub(crate) async fn until_cancelled(&self, future: impl Future<Output = ()>) {
        tokio::select! { biased;
            _ = self.force.cancelled() => {},
            () = future => {},
        }
    }
}

// Hyper's HTTP/2 executor can spawn stream/upgrade tasks outside the connection
// future. Own their lifetime too, without touching detached guest lifecycle work.
#[derive(Clone)]
struct HttpExecutor(ShutdownState);
impl<F> hyper::rt::Executor<F> for HttpExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        let state = self.0.clone();
        self.0.tasks.spawn(async move {
            state
                .until_cancelled(async move {
                    let _ = future.await;
                })
                .await;
        });
    }
}

async fn reject_new_requests(
    State(state): State<ShutdownState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if !state.accepting.load(Ordering::Acquire) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    next.run(request).await
}

pub async fn serve_with_shutdown(
    listener: TcpListener,
    app: Router,
    state: ShutdownState,
    signal: impl Future<Output = ()>,
    cleanup: impl Future<Output = io::Result<()>> + Send,
    drain_budget: Duration,
) -> io::Result<()> {
    let app = app.layer(middleware::from_fn_with_state(
        state.clone(),
        reject_new_requests,
    ));
    let mut connections = JoinSet::new();
    let graceful = CancellationToken::new();
    tokio::pin!(signal);
    loop {
        tokio::select! { biased;
            () = &mut signal => break,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result { warn!(%error, "HTTP connection task failed"); }
            },
            accepted = listener.accept() => {
                let (socket, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        warn!(%error, "HTTP accept failed");
                        tokio::select! { biased;
                            () = &mut signal => break,
                            () = tokio::time::sleep(Duration::from_secs(1)) => {},
                        }
                        continue;
                    }
                };
                // Preserve the low-latency Connect-RPC framing of the old listener.
                if let Err(error) = socket.set_nodelay(true) { warn!(%error, "failed to set TCP_NODELAY"); }
                let service = TowerToHyperService::new(app.clone());
                let executor = HttpExecutor(state.clone());
                let graceful = graceful.clone();
                connections.spawn(async move {
                    let mut builder = Builder::new(executor);
                    builder.http2().enable_connect_protocol();
                    let connection = builder.serve_connection_with_upgrades(TokioIo::new(socket), service);
                    tokio::pin!(connection);
                    let result = tokio::select! { biased;
                        () = graceful.cancelled() => {
                            connection.as_mut().graceful_shutdown();
                            connection.await
                        },
                        result = &mut connection => result,
                    };
                    if let Err(error) = result { tracing::debug!(%error, "HTTP connection closed"); }
                });
            },
        }
    }
    let started = Instant::now();
    info!(phase = "signal", elapsed_ms = 0, "HTTP shutdown starting");
    state.accepting.store(false, Ordering::Release);
    drop(listener);
    graceful.cancel();
    state.tasks.close();
    info!(
        phase = "admission_closed",
        elapsed_ms = started.elapsed().as_millis() as u64,
        remaining_connections = connections.len(),
        remaining_tasks = state.tasks.len(),
        "HTTP admission closed"
    );
    let drain = async {
        let outcome = tokio::time::timeout_at(started + drain_budget, async {
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    warn!(%error, "HTTP connection task failed during drain");
                }
            }
            state.tasks.wait().await;
        })
        .await;
        if outcome.is_err() {
            warn!(
                phase = "http_drain_expired",
                elapsed_ms = started.elapsed().as_millis() as u64,
                remaining_connections = connections.len(),
                remaining_tasks = state.tasks.len(),
                "HTTP drain budget expired; cancelling transports"
            );
            // A truncated process stream is an unknown transport outcome. It
            // neither replays input nor proves that its guest has stopped.
            state.force.cancel();
            connections.abort_all();
            while connections.join_next().await.is_some() {}
            state.tasks.wait().await;
            info!(
                phase = "http_cancelled",
                elapsed_ms = started.elapsed().as_millis() as u64,
                remaining_connections = connections.len(),
                remaining_tasks = state.tasks.len(),
                "HTTP transport tasks joined"
            );
        } else {
            info!(
                phase = "http_drained",
                elapsed_ms = started.elapsed().as_millis() as u64,
                remaining_connections = connections.len(),
                remaining_tasks = state.tasks.len(),
                "HTTP drain finished"
            );
        }
    };
    let preserve = async {
        info!(
            phase = "cleanup_start",
            elapsed_ms = started.elapsed().as_millis() as u64,
            "starting existing cleanup sequence"
        );
        let result = cleanup.await;
        match &result {
            Ok(()) => info!(
                phase = "cleanup_finished",
                elapsed_ms = started.elapsed().as_millis() as u64,
                "cleanup sequence completed"
            ),
            Err(error) => {
                warn!(phase = "cleanup_failed", elapsed_ms = started.elapsed().as_millis() as u64, %error, "cleanup sequence failed")
            }
        }
        result
    };
    let ((), result) = tokio::join!(drain, preserve);
    info!(
        phase = "exit",
        elapsed_ms = started.elapsed().as_millis() as u64,
        remaining_connections = connections.len(),
        remaining_tasks = state.tasks.len(),
        "HTTP work joined and cleanup awaited"
    );
    result
}

pub async fn cleanup_phase<T, E: std::fmt::Display>(
    phase: &'static str,
    action: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let started = Instant::now();
    info!(phase, event = "start", "shutdown cleanup phase");
    let result = action.await;
    match &result {
        Ok(_) => info!(
            phase,
            event = "end",
            elapsed_ms = started.elapsed().as_millis() as u64,
            "shutdown cleanup phase"
        ),
        Err(error) => {
            warn!(phase, event = "error", elapsed_ms = started.elapsed().as_millis() as u64, %error, "shutdown cleanup phase")
        }
    }
    result
}

#[cfg(test)]
mod websocket_shutdown_tests {
    use super::{serve_with_shutdown, ShutdownState};
    use axum::{extract::WebSocketUpgrade, routing::get, Router};
    use futures::{SinkExt, StreamExt};
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };
    use tokio::{net::TcpListener, sync::oneshot};
    use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};

    struct ActiveGuard(Arc<AtomicUsize>);

    impl ActiveGuard {
        fn new(active: &Arc<AtomicUsize>) -> Self {
            active.fetch_add(1, Ordering::SeqCst);
            Self(Arc::clone(active))
        }
    }

    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    // zippy:guarded — both upgraded directions must be gone before return.
    #[tokio::test]
    async fn upgraded_websocket_drops_both_pending_directions_before_shutdown_returns() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (socket, _) = upstream_listener.accept().await.unwrap();
            accept_async(socket).await.unwrap()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = ShutdownState::default();
        let handler_state = state.clone();
        let callbacks = Arc::new(AtomicUsize::new(0));
        let directions = Arc::new(AtomicUsize::new(0));
        let handler_callbacks = callbacks.clone();
        let handler_directions = directions.clone();
        let (bridge_started_tx, bridge_started_rx) = oneshot::channel();
        let bridge_started_tx = Arc::new(Mutex::new(Some(bridge_started_tx)));
        let app = Router::new().route(
            "/ws",
            get(move |upgrade: WebSocketUpgrade| {
                let state = handler_state.clone();
                let callbacks = handler_callbacks.clone();
                let directions = handler_directions.clone();
                let bridge_started_tx = bridge_started_tx.clone();
                async move {
                    let (upstream, _) = connect_async(format!("ws://{upstream_address}"))
                        .await
                        .unwrap();
                    // Register synchronously, before Axum detaches the upgrade
                    // callback. The guard also covers a pending/failed upgrade.
                    let upgrade_guard = state.upgrade_guard();
                    upgrade.on_upgrade(move |client| async move {
                        let _upgrade_guard = upgrade_guard;
                        let _callback_guard = ActiveGuard::new(&callbacks);
                        let (mut client_tx, mut client_rx) = client.split();
                        let (mut upstream_tx, mut upstream_rx) = upstream.split();
                        let client_guard = ActiveGuard::new(&directions);
                        let upstream_guard = ActiveGuard::new(&directions);
                        bridge_started_tx
                            .lock()
                            .unwrap()
                            .take()
                            .unwrap()
                            .send(())
                            .unwrap();
                        state
                            .until_cancelled(async move {
                                let to_upstream = async move {
                                    let _guard = client_guard;
                                    while let Some(message) = client_rx.next().await {
                                        let message = message.unwrap();
                                        let axum::extract::ws::Message::Text(text) = message else {
                                            panic!("unexpected client websocket message");
                                        };
                                        upstream_tx
                                            .send(Message::Text(text.to_string().into()))
                                            .await
                                            .unwrap();
                                    }
                                };
                                let to_client = async move {
                                    let _guard = upstream_guard;
                                    while let Some(message) = upstream_rx.next().await {
                                        let Message::Text(text) = message.unwrap() else {
                                            panic!("unexpected upstream websocket message");
                                        };
                                        client_tx
                                            .send(axum::extract::ws::Message::Text(
                                                text.to_string().into(),
                                            ))
                                            .await
                                            .unwrap();
                                    }
                                };
                                tokio::join!(to_upstream, to_client);
                            })
                            .await;
                    })
                }
            }),
        );
        let (signal_tx, signal_rx) = oneshot::channel();
        let server = tokio::spawn(serve_with_shutdown(
            listener,
            app,
            state.clone(),
            async move {
                signal_rx.await.unwrap();
            },
            async { Ok(()) },
            Duration::from_millis(50),
        ));
        let (mut client, _) = connect_async(format!("ws://{address}/ws")).await.unwrap();
        let mut upstream = upstream.await.unwrap();
        bridge_started_rx.await.unwrap();

        // Confirm this is a real, working bridge in both directions before
        // leaving both forwarding futures blocked on their next message.
        client
            .send(Message::Text("client-to-upstream".into()))
            .await
            .unwrap();
        assert_eq!(
            upstream.next().await.unwrap().unwrap(),
            Message::Text("client-to-upstream".into())
        );
        upstream
            .send(Message::Text("upstream-to-client".into()))
            .await
            .unwrap();
        assert_eq!(
            client.next().await.unwrap().unwrap(),
            Message::Text("upstream-to-client".into())
        );
        assert_eq!(callbacks.load(Ordering::SeqCst), 1);
        assert_eq!(directions.load(Ordering::SeqCst), 2);

        signal_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("upgraded sockets must obey the HTTP drain budget")
            .unwrap()
            .unwrap();
        assert_eq!(
            callbacks.load(Ordering::SeqCst),
            0,
            "detached upgrade callback survived shutdown"
        );
        assert_eq!(
            directions.load(Ordering::SeqCst),
            0,
            "forwarding direction survived shutdown"
        );
        assert_eq!(state.tasks.len(), 0);

        // Keep both peers open until the coordinator returns. Their sockets
        // must close because the tracked bridge was dropped, not because the
        // test disconnected a client or the runtime was destroyed.
        let client_end = tokio::time::timeout(Duration::from_secs(1), client.next())
            .await
            .unwrap();
        let upstream_end = tokio::time::timeout(Duration::from_secs(1), upstream.next())
            .await
            .unwrap();
        assert!(matches!(
            client_end,
            None | Some(Err(_)) | Some(Ok(Message::Close(_)))
        ));
        assert!(matches!(
            upstream_end,
            None | Some(Err(_)) | Some(Ok(Message::Close(_)))
        ));
    }
}
