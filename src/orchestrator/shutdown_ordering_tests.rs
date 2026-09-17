use super::*;
use crate::api::shutdown::{serve_with_shutdown, ShutdownState};
use crate::observability::reporter::shutdown_fixture::scheduler_fixture;
use crate::observability::shutdown::{shutdown_with_reporter, REPORTER_SHUTDOWN_BUDGET};
use crate::orchestrator::persistence::FileBackedSandboxPersister;
use anyhow::{Context, Result};
use axum::{routing::get, Router};
use std::io::{BufRead, Write};

// The mock backend is intentional: this proves ordering and durable records,
// not the KVM/ublk wall-clock bound required before rollout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reporter_shutdown_child() -> Result<()> {
    let Ok(root) = std::env::var("AENV_REPORTER_SHUTDOWN_CHILD") else {
        return Ok(());
    };
    setup();
    let mut fixture = scheduler_fixture(true).await;
    let orchestrator = make_orchestrator_without_background_with_factory_and_persister(
        InMemoryMetadataStore::new(),
        MockBackendFactory::new(),
        FileBackedSandboxPersister::new_for_test(PathBuf::from(&root)),
    );
    let guest = orchestrator
        .create_sandbox(create_request(Some(60), &[]))
        .await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let signal_at = Arc::new(OnceLock::new());
    let clock = signal_at.clone();
    let for_signal = orchestrator.clone();
    let for_cleanup = orchestrator.clone();
    let reporter = fixture.reporter.take();
    println!("ORDERING_READY {}", guest.id);
    std::io::stdout().flush()?;
    serve_with_shutdown(
        listener,
        Router::new().route("/", get(|| async { "ok" })),
        ShutdownState::default(),
        async move {
            signal.recv().await;
            clock.set(tokio::time::Instant::now()).unwrap();
            for_signal.close_admission();
        },
        async move {
            shutdown_with_reporter(
                reporter,
                *signal_at.get().unwrap() + REPORTER_SHUTDOWN_BUDGET,
                async move {
                    for_cleanup
                        .shutdown()
                        .await
                        .map_err(std::io::Error::other)?;
                    println!("ORDERING_PERSISTED");
                    std::io::stdout().flush().unwrap();
                    Ok(())
                },
            )
            .await
        },
        Duration::from_millis(20),
    )
    .await?;
    assert_eq!(fixture.unregisters.load(Ordering::SeqCst), 1);
    assert_eq!(orchestrator.lifecycle_tasks.len(), 0);
    assert_eq!(
        orchestrator
            .persister
            .load_all(&MockBackendFactory::new())
            .await?
            .len(),
        1
    );
    fixture.observer.shutdown().await?;
    println!("ORDERING_DONE");
    Ok(())
}

// zippy:guarded — real SIGTERM cannot put persistence behind telemetry RPC retries.
#[test]
fn reporter_stall_cannot_delay_guest_persistence() -> Result<()> {
    use std::process::{Command, Stdio};
    let root = TempDir::new()?;
    let mut child = Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg("orchestrator::service::tests::shutdown_ordering_tests::reporter_shutdown_child")
        .arg("--nocapture")
        .env("AENV_REPORTER_SHUTDOWN_CHILD", root.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let (tx, rx) = std::sync::mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            let _ = tx.send(line.unwrap());
        }
    });
    let wait_marker = |prefix: &str, budget: Duration| -> Result<String> {
        let deadline = std::time::Instant::now() + budget;
        loop {
            let line = rx
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .with_context(|| format!("waiting for {prefix}"))?;
            if line.starts_with(prefix) {
                return Ok(line);
            }
        }
    };
    let result = (|| -> Result<()> {
        wait_marker("ORDERING_READY", Duration::from_secs(20))?;
        let started = std::time::Instant::now();
        assert!(Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success());
        wait_marker("ORDERING_PERSISTED", Duration::from_secs(2))?;
        wait_marker("ORDERING_DONE", Duration::from_secs(8))?;
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(child.wait()?.success());
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    reader.join().unwrap();
    result
}

// zippy:guarded — reporter completion never cancels the owned cleanup future.
#[tokio::test]
async fn healthy_reporter_is_joined_while_cleanup_remains_held() -> Result<()> {
    let mut fixture = scheduler_fixture(true).await;
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mut cleanup = tokio::spawn(shutdown_with_reporter(
        fixture.reporter.take(),
        tokio::time::Instant::now() + REPORTER_SHUTDOWN_BUDGET,
        async {
            release_rx.await.unwrap();
            Err(std::io::Error::other("held cleanup error"))
        },
    ));
    tokio::time::timeout(
        Duration::from_secs(5),
        fixture.unregister_entered.notified(),
    )
    .await?;
    fixture.release_unregister.notify_one();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut cleanup)
            .await
            .is_err()
    );
    release_tx.send(()).unwrap();
    assert!(cleanup
        .await?
        .unwrap_err()
        .to_string()
        .contains("held cleanup error"));
    assert_eq!(fixture.unregisters.load(Ordering::SeqCst), 1);
    fixture.observer.shutdown().await?;
    Ok(())
}

// zippy:guarded — HTTP expiry must not cancel or replay an accepted resume.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resuming_across_signal_preserves_record() -> Result<()> {
    let root = TempDir::new()?;
    let behavior = Arc::new(MockBehavior::new());
    let orchestrator = make_orchestrator_without_background_with_factory_and_persister(
        InMemoryMetadataStore::new(),
        MockBackendFactory::with_behavior(behavior.clone()),
        FileBackedSandboxPersister::new_for_test(root.path().to_path_buf()),
    );
    let guest = orchestrator
        .create_sandbox(create_request(Some(60), &[]))
        .await?;
    orchestrator.pause_sandbox(guest.id).await?;
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_tx = Arc::new(StdMutex::new(Some(entered_tx)));
    let gate = Arc::new((StdMutex::new(false), std::sync::Condvar::new()));
    let held = gate.clone();
    behavior.set_on_operation(
        MockOperation::StartNowait,
        Arc::new(move || {
            entered_tx.lock().unwrap().take().unwrap().send(()).unwrap();
            let mut released = held.0.lock().unwrap();
            while !*released {
                released = held.1.wait(released).unwrap();
            }
        }),
    );
    let for_handler = orchestrator.clone();
    let app = Router::new().route(
        "/resume",
        axum::routing::post(move || {
            let orchestrator = for_handler.clone();
            async move {
                format!(
                    "{:?}",
                    orchestrator
                        .resume_sandbox(guest.id, NewTimeout::UseExisting)
                        .await
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (signal_tx, signal_rx) = tokio::sync::oneshot::channel();
    let for_signal = orchestrator.clone();
    let for_cleanup = orchestrator.clone();
    let server = tokio::spawn(serve_with_shutdown(
        listener,
        app,
        ShutdownState::default(),
        async move {
            signal_rx.await.unwrap();
            for_signal.close_admission();
        },
        async move { for_cleanup.shutdown().await.map_err(std::io::Error::other) },
        Duration::from_millis(20),
    ));
    let client = tokio::spawn(async move {
        reqwest::Client::new()
            .post(format!("http://{address}/resume"))
            .send()
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), entered_rx).await??;
    signal_tx.send(()).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), client).await;
    let returned = server.is_finished();
    let still_resuming = orchestrator.store.get(&guest.id).await?.unwrap().state;
    let owned = orchestrator.lifecycle_tasks.len();
    // Release even if an assertion will fail, so the blocking mock cannot hang the runtime.
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    assert!(
        response??.is_err(),
        "expired response is unknown, not resume success"
    );
    assert!(
        !returned,
        "cleanup returned with accepted resume still held"
    );
    assert_eq!(still_resuming, SandboxState::Resuming);
    assert_eq!(owned, 1);
    assert_eq!(orchestrator.lifecycle_tasks.len(), 0);
    let loaded = orchestrator
        .persister
        .load_all(&MockBackendFactory::new())
        .await?;
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].id, guest.id);
    assert_eq!(loaded[0].state, SandboxState::Paused);
    assert_proxy_paused(&orchestrator, &guest.id).await?;
    Ok(())
}
