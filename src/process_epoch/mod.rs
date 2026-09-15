//! Dormant host-side process operation records. No route or capability uses this module.
//! Guest-root reports are observations, never evidence of cessation or funding.
#[cfg(test)]
mod authentication;
pub mod transport;
pub mod wire;
use crate::local_store::{LocalKvStore, LocalStoreDurability};
use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;

pub const PROTOCOL: &str = "agentenv-process-epoch-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allocation {
    pub controller: String,
    pub tenant_id: String,
    pub sandbox_id: String,
    pub runtime_id: Uuid,
    pub runtime_incarnation: Uuid,
    pub enrollment_revision: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub allocation: Allocation,
    pub epoch_id: Uuid,
    pub operation_id: Uuid,
    pub request_sha256: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    HostDispatchRecorded,
    GuestReported,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub operation: Operation,
    // A pre-I/O claim carries no observation class. It cannot prove forwarding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_class: Option<EvidenceClass>,
}
impl Receipt {
    /// Neither once-only forwarding nor root-controlled guest data proves host cessation.
    /// There is intentionally no host-stop receipt constructor in this dormant cut.
    pub fn proves_cessation(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Admission {
    Unreconciled,
    Open,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub allocation: Allocation,
    pub recovery_revision: u64,
    pub admission: Admission,
    pub directory_confirmed: bool,
    pub epoch_id: Option<Uuid>,
    // A restart cannot erase an already committed close.
    pub closed: bool,
}

/// Persisted bytes are historical evidence, not fresh forwarding authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalCloseRequest {
    pub body: Vec<u8>,
    pub envelope: Vec<u8>,
    pub signature: Vec<u8>,
    pub descriptor: Vec<u8>,
}

impl OriginalCloseRequest {
    // Structural consistency only. The authenticated participant checks signatures
    // against independently enrolled keys before this storage primitive is called.
    fn validate(&self, operation: &Operation) -> anyhow::Result<()> {
        use sha2::{Digest, Sha256};
        wire::decode_canonical("SealRequest", &self.body)?;
        wire::decode_canonical("SignedEnvelope", &self.envelope)?;
        wire::decode_canonical("Descriptor", &self.descriptor)?;
        let request: wire::SealRequest = serde_json::from_slice(&self.body)?;
        let envelope: wire::SignedEnvelope = serde_json::from_slice(&self.envelope)?;
        let descriptor: wire::Descriptor = serde_json::from_slice(&self.descriptor)?;
        let b = &request.binding;
        let hash = format!("{:x}", Sha256::digest(&self.body));
        let descriptor_hash = format!("{:x}", Sha256::digest(&self.descriptor));
        anyhow::ensure!(
            self.signature.len() == 64
                && envelope.domain == "agentenv-process-epoch/seal/v1"
                && envelope.signer == operation.allocation.controller
                && envelope.body_sha256 == hash
                && envelope.request_sha256 == hash
                && operation.request_sha256 == hash
                && b.operation_id == operation.operation_id.to_string()
                && request.expected_session_id == operation.epoch_id.to_string()
                && b.tenant_id == operation.allocation.tenant_id
                && b.sandbox_id == operation.allocation.sandbox_id
                && b.runtime_id == operation.allocation.runtime_id.to_string()
                && b.runtime_incarnation == operation.allocation.runtime_incarnation.to_string()
                && b.enrollment_revision == operation.allocation.enrollment_revision
                && b.descriptor_sha256 == descriptor_hash
                && envelope.descriptor_sha256 == descriptor_hash
                && envelope.runtime_id == b.runtime_id
                && envelope.runtime_incarnation == b.runtime_incarnation
                && envelope.enrollment_revision == b.enrollment_revision
                && envelope.node_id == b.node_id
                && envelope.node_incarnation == b.node_incarnation
                && descriptor.node_id == b.node_id
                && descriptor.node_incarnation == b.node_incarnation
                && descriptor.runtime_id == b.runtime_id
                && descriptor.runtime_incarnation == b.runtime_incarnation
                && descriptor.enrollment_revision == b.enrollment_revision
                && descriptor.guest_boot_id == b.guest_boot_id
                && descriptor.process_endpoint == b.process_endpoint
                && descriptor.guest_build_sha256 == b.guest_build_sha256
                && descriptor.capabilities_sha256 == b.capabilities_sha256,
            "original process request conflict"
        );
        Ok(())
    }
}

// Internal closing intent. Neither the inventory nor its hash proves cessation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosingIntent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original: Option<OriginalCloseRequest>,
    operation: Operation,
    inventory: Vec<Operation>,
    inventory_sha256: String,
}

#[derive(Clone)]
pub struct HostLedger {
    db: LocalKvStore,
    serial: Arc<Mutex<()>>,
    allocation: Allocation,
    path: PathBuf,
}
impl HostLedger {
    /// Only an independently authorized NEW host allocation may initialize.
    /// Existing paths are never reset, including failed initialization attempts.
    pub async fn initialize(path: PathBuf, allocation: Allocation) -> anyhow::Result<Self> {
        Self::initialize_with_confirmation(path, allocation, sync_parent).await
    }
    async fn initialize_with_confirmation<F>(
        path: PathBuf,
        allocation: Allocation,
        confirm: F,
    ) -> anyhow::Result<Self>
    where
        F: FnOnce(&std::path::Path) -> anyhow::Result<()> + Send + 'static,
    {
        validate_allocation(&allocation)?;
        std::fs::create_dir(&path).context("create new process ledger")?;
        let db = LocalKvStore::open(&path, LocalStoreDurability::Sync).await?;
        let state = Enrollment {
            allocation: allocation.clone(),
            recovery_revision: 0,
            admission: Admission::Unreconciled,
            directory_confirmed: false,
            epoch_id: None,
            closed: false,
        };
        db.put(b"enrollment".to_vec(), serde_json::to_vec(&state)?)
            .await?;
        let ledger = Self {
            db,
            serial: Arc::new(Mutex::new(())),
            allocation,
            path,
        };
        // Record the obligation before attempting parent fsync. Failure leaves it pending.
        ledger.confirm_directory_with(confirm).await?;
        let mut state = ledger.enrollment().await?;
        state.admission = Admission::Open;
        ledger
            .db
            .put(b"enrollment".to_vec(), serde_json::to_vec(&state)?)
            .await?;
        Ok(ledger)
    }
    pub async fn reopen(path: PathBuf, allocation: Allocation) -> anyhow::Result<Self> {
        validate_allocation(&allocation)?;
        if !path.join("CURRENT").is_file() {
            bail!("process ledger unavailable");
        }
        let db = LocalKvStore::open(&path, LocalStoreDurability::Sync).await?;
        let ledger = Self {
            db,
            serial: Arc::new(Mutex::new(())),
            allocation,
            path,
        };
        let mut state = ledger.enrollment().await?;
        state.recovery_revision = state
            .recovery_revision
            .checked_add(1)
            .context("recovery revision exhausted")?;
        state.admission = Admission::Unreconciled;
        ledger
            .db
            .put(b"enrollment".to_vec(), serde_json::to_vec(&state)?)
            .await?;
        Ok(ledger)
    }
    /// This snapshot grants no reconciliation authority. The future authenticated
    /// participant must independently prove the exact saved host enrollment/epoch.
    pub async fn enrollment(&self) -> anyhow::Result<Enrollment> {
        let raw = self
            .db
            .get(b"enrollment".to_vec())
            .await?
            .context("process enrollment missing")?;
        let state: Enrollment = serde_json::from_slice(&raw)?;
        if state.allocation != self.allocation {
            bail!("process allocation conflict");
        }
        Ok(state)
    }
    pub async fn confirm_directory(&self) -> anyhow::Result<()> {
        self.confirm_directory_with(sync_parent).await
    }
    async fn confirm_directory_with<F>(&self, confirm: F) -> anyhow::Result<()>
    where
        F: FnOnce(&std::path::Path) -> anyhow::Result<()> + Send + 'static,
    {
        let this = self.clone();
        tokio::spawn(async move {
            let _guard = this.serial.lock().await;
            let mut state = this.enrollment().await?;
            if state.directory_confirmed {
                return Ok(());
            }
            let path = this.path.clone();
            tokio::task::spawn_blocking(move || confirm(&path))
                .await
                .context("join parent confirmation")??;
            state.directory_confirmed = true;
            this.db
                .put(b"enrollment".to_vec(), serde_json::to_vec(&state)?)
                .await?;
            Ok(())
        })
        .await
        .context("join directory confirmation")?
    }
    /// CAS against the exact saved enrollment and recovery revision. This storage
    /// primitive neither authenticates an HTTP caller nor advances an enrollment,
    /// changes a funded epoch, binds/releases work, or proves host cessation.
    pub async fn reconcile(
        &self,
        expected: Allocation,
        recovery_revision: u64,
        epoch_id: Uuid,
    ) -> anyhow::Result<()> {
        self.reconcile_before_commit(
            expected,
            recovery_revision,
            epoch_id,
            std::future::ready(()),
        )
        .await
    }
    async fn reconcile_before_commit<F>(
        &self,
        expected: Allocation,
        recovery_revision: u64,
        epoch_id: Uuid,
        before_commit: F,
    ) -> anyhow::Result<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let this = self.clone();
        tokio::spawn(async move {
            let _guard = this.serial.lock().await;
            let mut state = this.enrollment().await?;
            if state.allocation != expected
                || state.recovery_revision != recovery_revision
                || state.admission != Admission::Unreconciled
                || state.closed
                || !state.directory_confirmed
                || epoch_id.is_nil()
                || state.epoch_id.is_some_and(|saved| saved != epoch_id)
            {
                bail!("process enrollment reconciliation refused");
            }
            before_commit.await;
            state.epoch_id = Some(epoch_id);
            state.admission = Admission::Open;
            this.db
                .put(b"enrollment".to_vec(), serde_json::to_vec(&state)?)
                .await?;
            Ok(())
        })
        .await
        .context("join enrollment reconciliation")?
    }
    /// Close admission only. This is not seal/drain or permission to settle a bill.
    pub async fn close(&self, expected: Allocation, recovery_revision: u64) -> anyhow::Result<()> {
        let this = self.clone();
        tokio::spawn(async move {
            let _guard = this.serial.lock().await;
            let mut state = this.enrollment().await?;
            if state.allocation != expected || state.recovery_revision != recovery_revision {
                bail!("process enrollment close refused");
            }
            state.closed = true;
            state.admission = Admission::Closed;
            this.db
                .put(b"enrollment".to_vec(), serde_json::to_vec(&state)?)
                .await?;
            Ok(())
        })
        .await
        .context("join enrollment close")?
    }
    pub async fn claim(&self, operation: Operation) -> anyhow::Result<bool> {
        self.validate(&operation)?;
        let this = self.clone();
        tokio::spawn(async move {
            let _guard = this.serial.lock().await;
            let key = operation_key(operation.operation_id);
            if let Some(raw) = this.db.get(key.clone()).await? {
                let saved: Receipt = serde_json::from_slice(&raw)?;
                if saved.operation != operation {
                    bail!("process operation conflict");
                }
                return Ok(false);
            }
            let mut state = this.enrollment().await?;
            if state.admission != Admission::Open
                || state.closed
                || !state.directory_confirmed
                || state
                    .epoch_id
                    .is_some_and(|saved| saved != operation.epoch_id)
            {
                bail!("process enrollment unavailable");
            }
            state.epoch_id = Some(operation.epoch_id);
            let receipt = Receipt {
                operation,
                evidence_class: None,
            };
            this.db
                .write_batch([
                    crate::local_store::LocalKvBatchOp::put(key, serde_json::to_vec(&receipt)?),
                    crate::local_store::LocalKvBatchOp::put(
                        b"enrollment".to_vec(),
                        serde_json::to_vec(&state)?,
                    ),
                ])
                .await?;
            Ok(true)
        })
        .await
        .context("join process operation claim")?
    }
    /// Claim a cooperative close and close admission in the same durable batch.
    /// This acknowledges only intent. No guest I/O or cessation evidence occurs here.
    pub async fn begin_close_recorded(
        &self,
        operation: Operation,
        original: OriginalCloseRequest,
    ) -> anyhow::Result<bool> {
        original.validate(&operation)?;
        self.begin_close_inner(operation, Some(original)).await
    }
    /// Historical lookup only. The caller still needs authenticated lookup authority;
    /// returning these bytes never grants permission to retry delivery.
    pub async fn original_close_request(
        &self,
        operation: &Operation,
    ) -> anyhow::Result<OriginalCloseRequest> {
        self.validate(operation)?;
        let _guard = self.serial.lock().await;
        self.lookup(operation)
            .await?
            .context("process claim missing")?;
        let raw = self
            .db
            .get(b"closing_intent".to_vec())
            .await?
            .context("original close request unavailable")?;
        let intent: ClosingIntent = serde_json::from_slice(&raw)?;
        anyhow::ensure!(&intent.operation == operation, "process close conflict");
        let original = intent
            .original
            .context("original close request unavailable")?;
        original.validate(operation)?;
        Ok(original)
    }
    pub async fn begin_close(&self, operation: Operation) -> anyhow::Result<bool> {
        self.begin_close_inner(operation, None).await
    }
    async fn begin_close_inner(
        &self,
        operation: Operation,
        original: Option<OriginalCloseRequest>,
    ) -> anyhow::Result<bool> {
        self.validate(&operation)?;
        let this = self.clone();
        tokio::spawn(async move {
            let _guard = this.serial.lock().await;
            let key = operation_key(operation.operation_id);
            if let Some(raw) = this.db.get(key.clone()).await? {
                let saved: Receipt = serde_json::from_slice(&raw)?;
                if saved.operation != operation {
                    bail!("process operation conflict");
                }
                if let Some(expected) = &original {
                    let raw = this
                        .db
                        .get(b"closing_intent".to_vec())
                        .await?
                        .context("original close request unavailable")?;
                    let intent: ClosingIntent = serde_json::from_slice(&raw)?;
                    anyhow::ensure!(
                        intent.operation == operation && intent.original.as_ref() == Some(expected),
                        "process close conflict"
                    );
                }
                return Ok(false);
            }
            let mut state = this.enrollment().await?;
            if state.admission != Admission::Open
                || state.closed
                || !state.directory_confirmed
                || state
                    .epoch_id
                    .is_some_and(|saved| saved != operation.epoch_id)
            {
                bail!("process enrollment unavailable");
            }
            let mut inventory = Vec::new();
            for (key, raw) in this.db.entries().await? {
                if key.starts_with(b"operation/") {
                    let saved: Receipt = serde_json::from_slice(&raw)?;
                    this.validate(&saved.operation)?;
                    if saved.operation.epoch_id == operation.epoch_id {
                        inventory.push(saved.operation);
                    }
                }
            }
            inventory.push(operation.clone());
            inventory.sort_by_key(|item| item.operation_id);
            use sha2::{Digest, Sha256};
            let inventory_sha256 = format!("{:x}", Sha256::digest(serde_json::to_vec(&inventory)?));
            let intent = ClosingIntent {
                original,
                operation: operation.clone(),
                inventory,
                inventory_sha256,
            };
            state.epoch_id = Some(operation.epoch_id);
            state.admission = Admission::Closed;
            state.closed = true;
            let receipt = Receipt {
                operation,
                evidence_class: None,
            };
            this.db
                .write_batch([
                    crate::local_store::LocalKvBatchOp::put(key, serde_json::to_vec(&receipt)?),
                    crate::local_store::LocalKvBatchOp::put(
                        b"enrollment".to_vec(),
                        serde_json::to_vec(&state)?,
                    ),
                    crate::local_store::LocalKvBatchOp::put(
                        b"closing_intent".to_vec(),
                        serde_json::to_vec(&intent)?,
                    ),
                ])
                .await?;
            Ok(true)
        })
        .await
        .context("join process close claim")?
    }
    pub async fn lookup(&self, operation: &Operation) -> anyhow::Result<Option<Receipt>> {
        self.validate(operation)?;
        match self.db.get(operation_key(operation.operation_id)).await? {
            None => Ok(None),
            Some(raw) => {
                let saved: Receipt = serde_json::from_slice(&raw)?;
                if &saved.operation != operation {
                    bail!("process operation conflict");
                }
                Ok(Some(saved))
            }
        }
    }
    fn validate(&self, operation: &Operation) -> anyhow::Result<()> {
        if operation.allocation != self.allocation
            || operation.epoch_id.is_nil()
            || operation.operation_id.is_nil()
            || operation.request_sha256.len() != 64
            || !operation
                .request_sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            bail!("invalid process operation");
        }
        Ok(())
    }
}
fn sync_parent(path: &std::path::Path) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .context("ledger parent required")?;
    std::fs::File::open(parent)
        .context("open process ledger parent")?
        .sync_all()
        .context("sync process ledger parent")
}
fn operation_key(id: Uuid) -> Vec<u8> {
    format!("operation/{id}").into_bytes()
}
fn validate_allocation(a: &Allocation) -> anyhow::Result<()> {
    if [&a.controller, &a.tenant_id, &a.sandbox_id]
        .iter()
        .any(|s| s.is_empty() || s.len() > 256)
        || a.enrollment_revision == 0
        || a.runtime_id.is_nil()
        || a.runtime_incarnation.is_nil()
        || a.runtime_id == a.runtime_incarnation
    {
        bail!("invalid process allocation");
    }
    Ok(())
}
#[cfg(test)]
mod tests;
