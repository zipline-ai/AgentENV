use super::*;
use crate::{
    api::server,
    api_key::ApiKey,
    cfg::AppConfig,
    image::ImageResolver,
    orchestrator::{FileBackedSandboxPersister, InMemoryMetadataStore, Orchestrator},
    sandbox::{FirecrackerSandboxFactory, FirecrackerSnapshotManifest},
    snapshot::{
        mock::{MockSnapshotRepository, MockSnapshotRuntimeResolver},
        repository::{RepositoryResult, SnapshotListFilter, SnapshotRepository},
        SnapshotManager, SnapshotPublishMetadata, SnapshotRecord, TemplateBuildErrorReason,
    },
    template::TemplateBuilder,
};
use async_trait::async_trait;
use http_body_util::BodyExt;
use std::sync::Mutex;
use tokio::sync::Notify;
use tower::ServiceExt;

#[derive(Default)]
struct RecordingRepository {
    calls: Mutex<Vec<String>>,
    entered: Notify,
    release: Notify,
}
impl RecordingRepository {
    fn record(&self, method: &str, id: &str) {
        self.calls.lock().unwrap().push(format!("{method}:{id}"));
    }
}
#[async_trait]
impl SnapshotRepository for RecordingRepository {
    async fn get(&self, id: &str) -> RepositoryResult<Option<SnapshotRecord>> {
        self.record("get", id);
        self.entered.notify_one();
        self.release.notified().await;
        MockSnapshotRepository.get(id).await
    }
    async fn create(&self, r: SnapshotRecord) -> RepositoryResult<SnapshotRecord> {
        self.record("create", "");
        MockSnapshotRepository.create(r).await
    }
    async fn publish(
        &self,
        m: SnapshotPublishMetadata,
        f: FirecrackerSnapshotManifest,
    ) -> RepositoryResult<SnapshotRecord> {
        self.record("publish", "");
        MockSnapshotRepository.publish(m, f).await
    }
    async fn list(&self, f: SnapshotListFilter) -> RepositoryResult<Vec<SnapshotRecord>> {
        self.record("list", "");
        MockSnapshotRepository.list(f).await
    }
    async fn delete(&self, id: &str) -> RepositoryResult<()> {
        self.record("delete", id);
        MockSnapshotRepository.delete(id).await
    }
    async fn resolve_alias(&self, id: &str) -> RepositoryResult<Option<SnapshotId>> {
        self.record("alias", id);
        MockSnapshotRepository.resolve_alias(id).await
    }
    async fn try_start_build(&self, id: &SnapshotId) -> RepositoryResult<SnapshotRecord> {
        self.record("build", &id.to_string());
        MockSnapshotRepository.try_start_build(id).await
    }
    async fn mark_build_error(
        &self,
        id: &SnapshotId,
        r: TemplateBuildErrorReason,
    ) -> RepositoryResult<()> {
        self.record("error", &id.to_string());
        MockSnapshotRepository.mark_build_error(id, r).await
    }
}

fn key() -> String {
    format!("e2b_{}", "a".repeat(40))
}
async fn fixture() -> (Arc<ApiImpl>, Arc<RecordingRepository>, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    let orchestrator = Orchestrator::new(
        InMemoryMetadataStore::new(),
        FirecrackerSandboxFactory::new(),
        FileBackedSandboxPersister::new_for_test(root.path().join("runtimes")),
    )
    .await
    .unwrap();
    let repository = Arc::new(RecordingRepository::default());
    let manager = SnapshotManager::from_parts(
        repository.clone(),
        Arc::new(MockSnapshotRuntimeResolver),
        None,
    );
    let api = ApiImpl::new(
        orchestrator,
        Arc::new(manager),
        Arc::new(TemplateBuilder::new()),
        Arc::new(ImageResolver::new(&AppConfig::default())),
        None,
        vec![],
        ApiKey::new(key()).unwrap(),
    );
    let identity = NodeIdentity {
        id: "node-A".into(),
        service_instance_id: "boot-A".into(),
        cluster_id: Uuid::nil(),
        commit: "test".into(),
        version: "test".into(),
    };
    let api = api
        .with_async_restore(identity, root.path().join("receipts"))
        .await
        .unwrap();
    (Arc::new(api), repository, root)
}
fn allocation() -> Allocation {
    Allocation {
        version: 1,
        protocol: PROTOCOL.into(),
        node_id: "node-A".into(),
        node_incarnation: "boot-A".into(),
        node_endpoint: "https://node-a.test".into(),
        node_route: NodeRoute {
            kind: "native_host".into(),
            provider_id: "agentenv".into(),
            host_id: "node-A".into(),
        },
        runtime_id: Uuid::new_v4(),
        runtime_incarnation: Uuid::new_v4(),
        vcpus: 4,
    }
}
fn request(a: &Allocation, op: &str, snapshot: &str) -> Request {
    let bytes = serde_json::to_vec(
        &serde_json::json!({"templateID":snapshot,"timeout":60,"async_restore":a}),
    )
    .unwrap();
    Request::builder()
        .method("POST")
        .uri("/sandboxes")
        .header("x-api-key", key())
        .header("content-type", "application/json")
        .header(OPT_IN, PROTOCOL)
        .header(TENANT, "tenant-A")
        .header("idempotency-key", op)
        .header(REQUEST_HASH, "a".repeat(64))
        .header(BODY_HASH, format!("{:x}", Sha256::digest(&bytes)))
        .header(NODE_INCARNATION, &a.node_incarnation)
        .header(RUNTIME, a.runtime_id.to_string())
        .header(RUNTIME_INCARNATION, a.runtime_incarnation.to_string())
        .body(Body::from(bytes))
        .unwrap()
}
fn poll(a: &Allocation, op: &str, tenant: &str) -> Request {
    Request::builder()
        .uri(format!("/sandbox-operations/{op}"))
        .header("x-api-key", key())
        .header(TENANT, tenant)
        .header(REQUEST_HASH, "a".repeat(64))
        .header(NODE_INCARNATION, &a.node_incarnation)
        .header(RUNTIME, a.runtime_id.to_string())
        .header(RUNTIME_INCARNATION, a.runtime_incarnation.to_string())
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn accepted_receipt_precedes_snapshot_work_completion_and_replay_does_not_fetch_again() {
    let (api, repository, _root) = fixture().await;
    let app = server::new(api.clone());
    let a = allocation();
    let op = Uuid::new_v4().to_string();
    let snapshot = Uuid::new_v4().to_string();
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        app.clone().oneshot(request(&a, &op, &snapshot)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    repository.entered.notified().await;
    let wire: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(wire["allocation"]["runtime_id"], a.runtime_id.to_string());
    assert_eq!(wire["completed"], false);
    assert_eq!(wire["state"], "unknown");
    let receipt = api
        .async_restore
        .as_ref()
        .unwrap()
        .receipts
        .lookup(AUTHORITY, &op)
        .await
        .unwrap()
        .unwrap();
    assert!(receipt.dispatched);
    assert!(!receipt.completed);
    let repeated = app
        .clone()
        .oneshot(request(&a, &op, &snapshot))
        .await
        .unwrap();
    assert_eq!(repeated.status(), StatusCode::ACCEPTED);
    let looked_up = app
        .clone()
        .oneshot(poll(&a, &op, "tenant-A"))
        .await
        .unwrap();
    assert_eq!(looked_up.status(), StatusCode::OK);
    let foreign = app.oneshot(poll(&a, &op, "tenant-B")).await.unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        *repository.calls.lock().unwrap(),
        vec![format!("get:{snapshot}")]
    );
    assert!(api.orchestrator.list_sandboxes().await.unwrap().is_empty());
    repository.release.notify_one();
}

#[tokio::test]
async fn wrong_identity_or_guest_auth_cannot_create_a_receipt_or_fetch_snapshot() {
    for field in [
        "node",
        "incarnation",
        "body hash",
        "runtime header",
        "no api key",
        "guest headers",
        "alias",
    ] {
        let (api, repository, _root) = fixture().await;
        let mut a = allocation();
        let op = Uuid::new_v4().to_string();
        if field == "node" {
            a.node_id = "other-node".into();
        }
        if field == "incarnation" {
            a.node_incarnation = "other-boot".into();
        }
        let snapshot = if field == "alias" {
            "mutable-alias".into()
        } else {
            Uuid::new_v4().to_string()
        };
        let mut r = request(&a, &op, &snapshot);
        if field == "body hash" {
            r.headers_mut()
                .insert(BODY_HASH, "b".repeat(64).parse().unwrap());
        }
        if field == "runtime header" {
            r.headers_mut()
                .insert(RUNTIME, Uuid::new_v4().to_string().parse().unwrap());
        }
        if field == "no api key" || field == "guest headers" {
            r.headers_mut().remove("x-api-key");
        }
        if field == "guest headers" {
            r.headers_mut().insert(
                "x-agentenv-sandbox-id",
                a.runtime_id.to_string().parse().unwrap(),
            );
            r.headers_mut()
                .insert("x-agentenv-target-port", "49983".parse().unwrap());
        }
        let response = server::new(api.clone()).oneshot(r).await.unwrap();
        assert!(!response.status().is_success(), "{field}");
        assert!(
            api.async_restore
                .as_ref()
                .unwrap()
                .receipts
                .lookup(AUTHORITY, &op)
                .await
                .unwrap()
                .is_none(),
            "{field}"
        );
        assert!(repository.calls.lock().unwrap().is_empty(), "{field}");
        assert!(
            api.orchestrator.list_sandboxes().await.unwrap().is_empty(),
            "{field}"
        );
    }
}

#[tokio::test]
async fn only_exact_current_running_metadata_is_reported_running() {
    for state in [
        SandboxState::Creating,
        SandboxState::Resuming,
        SandboxState::Paused,
        SandboxState::Running,
    ] {
        for exact in [false, true] {
            let (api, repository, _root) = fixture().await;
            let a = allocation();
            let op = Uuid::new_v4().to_string();
            let binding = OperationBinding {
                authority: AUTHORITY.into(),
                tenant_id: "tenant-A".into(),
                operation_key: op,
                request_sha256: "a".repeat(64),
                provider_body_sha256: "b".repeat(64),
                saved_route: serde_json::to_string(&a).unwrap(),
            };
            let receipts = &api.async_restore.as_ref().unwrap().receipts;
            let receipt = receipts
                .reserve_exact(binding, a.runtime_id, a.runtime_incarnation)
                .await
                .unwrap();
            assert!(receipts.claim(receipt.clone()).await.unwrap());
            let receipt = receipts.complete(receipt).await.unwrap();
            let id = SandboxId::from_uuid(a.runtime_id);
            api.orchestrator
                .set_metadata_state_for_test(id, state)
                .await
                .unwrap();
            api.orchestrator
                .set_operation_incarnation_for_test(
                    id,
                    Some(if exact {
                        a.runtime_incarnation
                    } else {
                        Uuid::new_v4()
                    }),
                )
                .await
                .unwrap();
            let view = api.operation_view(receipt).await.unwrap();
            assert_eq!(
                view.state,
                if exact && state == SandboxState::Running {
                    "running"
                } else {
                    "unknown"
                }
            );
            assert!(repository.calls.lock().unwrap().is_empty());
        }
    }
}
