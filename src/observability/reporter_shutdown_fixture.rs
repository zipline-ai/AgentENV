//! Real gRPC reporter fixture. The empty observer never launches a VM.
use super::*;
use crate::orchestrator::{FileBackedSandboxPersister, InMemoryMetadataStore, Orchestrator};
use crate::sandbox::FirecrackerSandboxFactory;
use crate::virtualization::VirtualizationMode;
use axum::{body::Body, response::Response, routing::post, Router};
use std::sync::atomic::AtomicUsize;
use tokio::sync::Notify;

pub(crate) struct SchedulerFixture {
    pub reporter: Option<ObservabilityReporter>,
    pub unregisters: Arc<AtomicUsize>,
    pub unregister_entered: Arc<Notify>,
    pub release_unregister: Arc<Notify>,
    pub observer: Arc<Orchestrator>,
    hold_heartbeat: Arc<AtomicBool>,
    heartbeat_entered: Arc<Notify>,
    server: JoinHandle<()>,
    _temp: tempfile::TempDir,
}

impl Drop for SchedulerFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn grpc_ok() -> Response {
    use hyper::body::Frame;
    let mut trailers = axum::http::HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().unwrap());
    let frames: Vec<Result<_, std::convert::Infallible>> = vec![
        Ok(Frame::data(bytes::Bytes::from_static(&[0, 0, 0, 0, 0]))),
        Ok(Frame::trailers(trailers)),
    ];
    Response::builder()
        .header("content-type", "application/grpc")
        .body(Body::new(http_body_util::StreamBody::new(
            futures::stream::iter(frames),
        )))
        .unwrap()
}

pub(crate) async fn scheduler_fixture(hold_unregister: bool) -> SchedulerFixture {
    let unregisters = Arc::new(AtomicUsize::new(0));
    let unregister_entered = Arc::new(Notify::new());
    let release_unregister = Arc::new(Notify::new());
    let count = unregisters.clone();
    let entered = unregister_entered.clone();
    let release = release_unregister.clone();
    let hold_heartbeat = Arc::new(AtomicBool::new(false));
    let heartbeat_entered = Arc::new(Notify::new());
    let hb_hold = hold_heartbeat.clone();
    let hb_entered = heartbeat_entered.clone();
    let app = Router::new()
        .route(
            "/scheduler.v1.Scheduler/Heartbeat",
            post(move || {
                let (hold, entered) = (hb_hold.clone(), hb_entered.clone());
                async move {
                    if hold.load(Ordering::SeqCst) {
                        entered.notify_one();
                        std::future::pending::<()>().await;
                    }
                    grpc_ok()
                }
            }),
        )
        .route(
            "/scheduler.v1.Scheduler/UnregisterNode",
            post(move || {
                let (count, entered, release) = (count.clone(), entered.clone(), release.clone());
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    entered.notify_one();
                    if hold_unregister {
                        release.notified().await;
                    }
                    grpc_ok()
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let temp = tempfile::TempDir::new().unwrap();
    let observer = Orchestrator::new(
        InMemoryMetadataStore::new(),
        FirecrackerSandboxFactory::new(),
        FileBackedSandboxPersister::new(temp.path().to_path_buf(), VirtualizationMode::Kvm),
    )
    .await
    .unwrap();
    let service = Arc::new(
        ObservabilityService::new(
            crate::identity::NodeIdentity {
                id: "shutdown-test".into(),
                cluster_id: uuid::Uuid::nil(),
                service_instance_id: "shutdown-test-process".into(),
                commit: "test".into(),
                version: "test".into(),
            },
            observer.clone(),
            None,
            Arc::new(std::sync::RwLock::new(None)),
        )
        .await,
    );
    let mut reporter = ObservabilityReporter::new(
        service,
        &ObservabilitySchedulerReportConfig {
            enabled: true,
            interval_secs: 1,
        },
        &ClusterConfig {
            scheduler_endpoint: Some(endpoint),
        },
        None,
    )
    .unwrap()
    .unwrap();
    reporter.start();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !reporter.ever_heartbeat_succeeded.load(Ordering::Relaxed) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("real heartbeat response must be consumed before shutdown");
    SchedulerFixture {
        reporter: Some(reporter),
        unregisters,
        unregister_entered,
        release_unregister,
        observer,
        hold_heartbeat,
        heartbeat_entered,
        server,
        _temp: temp,
    }
}

// zippy:guarded — an expired absolute signal budget cannot start a new RPC.
#[tokio::test]
async fn spent_reporter_budget_joins_senders_without_unregister() {
    let mut fixture = scheduler_fixture(true).await;
    let reporter = fixture.reporter.as_mut().unwrap();
    reporter
        .shutdown_until(tokio::time::Instant::now())
        .await
        .unwrap();
    assert!(reporter.heartbeat_join.is_none());
    assert!(reporter.event_join.is_none());
    assert!(reporter.shutdown_tx.is_none());
    assert_eq!(fixture.unregisters.load(Ordering::SeqCst), 0);
    fixture.observer.shutdown().await.unwrap();
}

// zippy:guarded — the budget includes cancellation of in-flight telemetry tasks.
#[tokio::test]
async fn reporter_budget_joins_both_cancelled_senders() {
    struct Joined(Arc<AtomicUsize>);
    impl Drop for Joined {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let mut fixture = scheduler_fixture(true).await;
    let reporter = fixture.reporter.as_mut().unwrap();
    // Replace the already-proven live senders with parked in-flight task bodies.
    // Their drop counters prove shutdown joins cancellation instead of detaching.
    for task in [reporter.heartbeat_join.take(), reporter.event_join.take()]
        .into_iter()
        .flatten()
    {
        task.abort();
        let _ = task.await;
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    for slot in [&mut reporter.heartbeat_join, &mut reporter.event_join] {
        let guard = Joined(dropped.clone());
        let task_entered = entered.clone();
        *slot = Some(tokio::spawn(async move {
            let _guard = guard;
            task_entered.notify_one();
            std::future::pending::<()>().await;
        }));
        entered.notified().await;
    }
    let started = tokio::time::Instant::now();
    reporter
        .shutdown_until(started + Duration::from_millis(100))
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.unregisters.load(Ordering::SeqCst), 1);
    fixture.observer.shutdown().await.unwrap();
}

// zippy:guarded — cancellation covers a real heartbeat RPC, not only its timer.
#[tokio::test]
async fn in_flight_heartbeat_is_joined_before_single_unregister() {
    let mut fixture = scheduler_fixture(false).await;
    fixture.hold_heartbeat.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(5), fixture.heartbeat_entered.notified())
        .await
        .unwrap();
    let reporter = fixture.reporter.as_mut().unwrap();
    tokio::time::timeout(Duration::from_secs(3), reporter.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(reporter.heartbeat_join.is_none());
    assert!(reporter.event_join.is_none());
    assert_eq!(fixture.unregisters.load(Ordering::SeqCst), 1);
    fixture.observer.shutdown().await.unwrap();
}
