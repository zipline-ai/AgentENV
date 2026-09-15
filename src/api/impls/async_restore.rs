//! Opt-in restore acceptance. The ordinary generated create route stays synchronous.

use std::{path::PathBuf, sync::Arc, time::Duration};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::ApiImpl;
use crate::{
    identity::NodeIdentity,
    observability::prometheus::SandboxStageTimer,
    orchestrator::SandboxState,
    sandbox_operation::{OperationBinding, OperationReceipt, OperationReceipts},
    snapshot::SnapshotId,
    types::SandboxId,
};

const PROTOCOL: &str = "agentenv-async-restore-v1";
const OPT_IN: &str = "x-agentenv-async-restore";
const TENANT: &str = "x-agentenv-operation-tenant";
const REQUEST_HASH: &str = "x-agentenv-operation-request-sha256";
const BODY_HASH: &str = "x-agentenv-operation-body-sha256";
const NODE_INCARNATION: &str = "x-agentenv-operation-node-incarnation";
const RUNTIME: &str = "x-agentenv-operation-runtime";
const RUNTIME_INCARNATION: &str = "x-agentenv-operation-runtime-incarnation";
// A valid fleet API key is the server's control-plane principal. Tenant is
// additional binding data, never a caller-selected authentication principal.
const AUTHORITY: &str = "authenticated-controller";

pub(super) struct AsyncRestoreState {
    identity: NodeIdentity,
    receipts: OperationReceipts,
}

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeRoute {
    kind: String,
    provider_id: String,
    host_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Allocation {
    version: u8,
    protocol: String,
    node_id: String,
    node_incarnation: String,
    node_endpoint: String,
    node_route: NodeRoute,
    runtime_id: Uuid,
    runtime_incarnation: Uuid,
    vcpus: i64,
}

#[derive(Serialize)]
struct OperationView {
    version: u8,
    operation_key: String,
    request_sha256: String,
    provider_body_sha256: String,
    allocation: Allocation,
    dispatched: bool,
    completed: bool,
    // Only an exact current internal metadata observation produces "running".
    // Missing/transitional/paused state and old process receipts stay unknown.
    state: &'static str,
}

fn single_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() || value.is_empty() || value.len() > 256 {
        return None;
    }
    Some(value.to_owned())
}

fn failure(status: StatusCode) -> Response<Body> {
    (status, "restore operation unavailable").into_response()
}

fn allocation_headers_match(headers: &HeaderMap, allocation: &Allocation) -> bool {
    single_header(headers, NODE_INCARNATION).as_deref() == Some(&allocation.node_incarnation)
        && single_header(headers, RUNTIME).as_deref() == Some(&allocation.runtime_id.to_string())
        && single_header(headers, RUNTIME_INCARNATION).as_deref()
            == Some(&allocation.runtime_incarnation.to_string())
}

impl ApiImpl {
    /// Called once before serving. A failed durable-store open fails startup;
    /// receipt support is never advertised on an in-memory fallback.
    pub async fn with_async_restore(
        mut self,
        identity: NodeIdentity,
        path: PathBuf,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            self.async_restore.is_none(),
            "async restore already configured"
        );
        anyhow::ensure!(
            !identity.id.is_empty() && !identity.service_instance_id.is_empty(),
            "node identity required"
        );
        self.async_restore = Some(Arc::new(AsyncRestoreState {
            identity,
            receipts: OperationReceipts::open(path).await?,
        }));
        Ok(self)
    }

    async fn operation_view(&self, receipt: OperationReceipt) -> anyhow::Result<OperationView> {
        let state = self
            .async_restore
            .as_ref()
            .context("async restore unavailable")?;
        let allocation: Allocation = serde_json::from_str(&receipt.binding.saved_route)?;
        anyhow::ensure!(
            receipt.runtime_id == allocation.runtime_id
                && receipt.incarnation == allocation.runtime_incarnation,
            "receipt allocation mismatch"
        );
        let current = self
            .orchestrator
            .get_sandbox(&SandboxId::from_uuid(receipt.runtime_id))
            .await?;
        let running = receipt.completed
            && state.identity.id == allocation.node_id
            && state.identity.service_instance_id == allocation.node_incarnation
            && current.is_some_and(|metadata| {
                metadata.state == SandboxState::Running
                    && metadata.id.into_inner() == receipt.runtime_id
                    && metadata.operation_incarnation == Some(receipt.incarnation)
            });
        Ok(OperationView {
            version: 1,
            operation_key: receipt.binding.operation_key,
            request_sha256: receipt.binding.request_sha256,
            provider_body_sha256: receipt.binding.provider_body_sha256,
            allocation,
            dispatched: receipt.dispatched,
            completed: receipt.completed,
            state: if running { "running" } else { "unknown" },
        })
    }
}

use anyhow::Context;

pub(crate) async fn dispatch<I>(
    State(api): State<I>,
    request: Request,
    next: Next,
) -> Response<Body>
where
    I: AsRef<ApiImpl> + Clone + Send + Sync + 'static,
{
    let path = request.uri().path();
    let operation_path = path == "/sandbox-operations" || path.starts_with("/sandbox-operations/");
    let opt_in = request.headers().contains_key(OPT_IN);
    if !operation_path && !opt_in {
        return next.run(request).await;
    }
    let implementation = api.as_ref();
    // Reprove here even if proxy classification made outer auth take a different
    // path. No guest-scoped ingress token can authorize receipt access/creation.
    if !implementation.has_valid_api_key(request.headers()) {
        return failure(StatusCode::UNAUTHORIZED);
    }
    let Some(state) = implementation.async_restore.as_ref() else {
        return failure(StatusCode::NOT_IMPLEMENTED);
    };
    if request.uri().query().is_some() {
        return failure(StatusCode::BAD_REQUEST);
    }
    if request.method() == Method::GET && path == "/sandbox-operations/capabilities" {
        return Json(serde_json::json!({"version":1,"protocol":PROTOCOL,"node_id":state.identity.id,"node_incarnation":state.identity.service_instance_id})).into_response();
    }
    if request.method() == Method::GET && operation_path {
        let Some(key) = path.strip_prefix("/sandbox-operations/") else {
            return failure(StatusCode::NOT_FOUND);
        };
        if Uuid::parse_str(key).is_err() {
            return failure(StatusCode::NOT_FOUND);
        }
        let receipt = match state.receipts.lookup(AUTHORITY, key).await {
            Ok(Some(receipt)) => receipt,
            Ok(None) => return failure(StatusCode::NOT_FOUND),
            Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE),
        };
        let allocation: Allocation = match serde_json::from_str(&receipt.binding.saved_route) {
            Ok(a) => a,
            Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE),
        };
        if single_header(request.headers(), TENANT).as_deref() != Some(&receipt.binding.tenant_id)
            || single_header(request.headers(), REQUEST_HASH).as_deref()
                != Some(&receipt.binding.request_sha256)
            || !allocation_headers_match(request.headers(), &allocation)
        {
            return failure(StatusCode::NOT_FOUND);
        }
        return match implementation.operation_view(receipt).await {
            Ok(view) => Json(view).into_response(),
            Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE),
        };
    }
    if request.method() != Method::POST
        || path != "/sandboxes"
        || single_header(request.headers(), OPT_IN).as_deref() != Some(PROTOCOL)
    {
        return failure(StatusCode::BAD_REQUEST);
    }
    let headers = request.headers().clone();
    let (Some(tenant_id), Some(operation_key), Some(request_sha256), Some(provider_body_sha256)) = (
        single_header(&headers, TENANT),
        single_header(&headers, "idempotency-key"),
        single_header(&headers, REQUEST_HASH),
        single_header(&headers, BODY_HASH),
    ) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    if Uuid::parse_str(&operation_key).is_err() {
        return failure(StatusCode::BAD_REQUEST);
    }
    let bytes = match tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(request.into_body(), 1 << 20),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        _ => return failure(StatusCode::BAD_REQUEST),
    };
    if format!("{:x}", Sha256::digest(&bytes)) != provider_body_sha256 {
        return failure(StatusCode::CONFLICT);
    }
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return failure(StatusCode::BAD_REQUEST),
    };
    let allocation: Allocation =
        match serde_json::from_value(value.get("async_restore").cloned().unwrap_or_default()) {
            Ok(a) => a,
            Err(_) => return failure(StatusCode::BAD_REQUEST),
        };
    if allocation.version != 1
        || allocation.protocol != PROTOCOL
        || allocation.node_id != state.identity.id
        || allocation.node_incarnation != state.identity.service_instance_id
        || allocation.node_route.kind != "native_host"
        || allocation.node_route.provider_id != "agentenv"
        || allocation.node_route.host_id != allocation.node_id
        || allocation.runtime_id.is_nil()
        || allocation.runtime_incarnation.is_nil()
        || allocation.runtime_id == allocation.runtime_incarnation
        || allocation.vcpus <= 0
        || !allocation_headers_match(&headers, &allocation)
    {
        return failure(StatusCode::CONFLICT);
    }
    let body: agentenv_http_server::models::NewSandbox = match serde_json::from_value(value) {
        Ok(body) => body,
        Err(_) => return failure(StatusCode::BAD_REQUEST),
    };
    // This transport restores a captured immutable snapshot, never a mutable
    // template alias that could resolve differently after a lost response.
    if SnapshotId::try_from(body.template_id.as_str()).is_err() {
        return failure(StatusCode::BAD_REQUEST);
    }
    let binding = OperationBinding {
        authority: AUTHORITY.into(),
        tenant_id,
        operation_key,
        request_sha256,
        provider_body_sha256,
        saved_route: match serde_json::to_string(&allocation) {
            Ok(route) => route,
            Err(_) => return failure(StatusCode::BAD_REQUEST),
        },
    };
    let worker_api = implementation.clone();
    let expected_vcpus = allocation.vcpus;
    let accepted = state
        .receipts
        .submit_exact(
            binding,
            allocation.runtime_id,
            allocation.runtime_incarnation,
            move |captured| async move {
                let timer = SandboxStageTimer::new("create_async_restore");
                let request = worker_api
                    .prepare_new_sandbox(&body, &timer)
                    .await
                    .map_err(|_| anyhow::anyhow!("restore preparation unresolved"))?;
                let crate::orchestrator::SandboxLaunchSource::Snapshot(snapshot) = &request.source
                else {
                    anyhow::bail!("immutable snapshot required")
                };
                anyhow::ensure!(
                    i64::from(snapshot.resources().cpu_count) == expected_vcpus,
                    "snapshot allocation mismatch"
                );
                let metadata = worker_api
                    .orchestrator
                    .create_sandbox_allocated(
                        request,
                        SandboxId::from_uuid(captured.runtime_id),
                        captured.incarnation,
                    )
                    .await?;
                anyhow::ensure!(
                    metadata.id.into_inner() == captured.runtime_id
                        && metadata.operation_incarnation == Some(captured.incarnation)
                        && metadata.state == SandboxState::Running,
                    "restore result unresolved"
                );
                Ok(())
            },
        )
        .await;
    match accepted {
        Ok(receipt) => match implementation.operation_view(receipt).await {
            Ok(view) => (StatusCode::ACCEPTED, Json(view)).into_response(),
            Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE),
        },
        Err(_) => failure(StatusCode::CONFLICT),
    }
}
