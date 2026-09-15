//! Dormant host-side process operation records. No route or capability uses this module.
//! Guest-root reports are observations, never evidence of cessation or funding.
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

#[derive(Clone)]
pub struct HostLedger {
    db: LocalKvStore,
    serial: Arc<Mutex<()>>,
    allocation: Allocation,
}
impl HostLedger {
    /// Bootstrap a NEW isolated host ledger. This is not a recovery operation.
    /// The future authenticated allocation participant must authorize this call;
    /// accepting raw serialized Allocation values on a route is forbidden.
    pub async fn initialize(path: PathBuf, allocation: Allocation) -> anyhow::Result<Self> {
        validate_allocation(&allocation)?;
        std::fs::create_dir(&path).context("create new process ledger")?;
        let db = LocalKvStore::open(&path, LocalStoreDurability::Sync).await?;
        db.put(b"allocation".to_vec(), serde_json::to_vec(&allocation)?)
            .await?;
        Ok(Self {
            db,
            serial: Arc::new(Mutex::new(())),
            allocation,
        })
    }
    pub async fn reopen(path: PathBuf, allocation: Allocation) -> anyhow::Result<Self> {
        validate_allocation(&allocation)?;
        if !path.join("CURRENT").is_file() {
            bail!("process ledger unavailable");
        }
        let db = LocalKvStore::open(path, LocalStoreDurability::Sync).await?;
        let saved = db
            .get(b"allocation".to_vec())
            .await?
            .context("process allocation missing")?;
        let saved: Allocation = serde_json::from_slice(&saved)?;
        if saved != allocation {
            bail!("process allocation conflict");
        }
        Ok(Self {
            db,
            serial: Arc::new(Mutex::new(())),
            allocation,
        })
    }
    pub async fn claim(&self, operation: Operation) -> anyhow::Result<bool> {
        self.validate(&operation)?;
        let this = self.clone();
        // Hold serialization through the fsync even if the HTTP future is dropped.
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
            let receipt = Receipt {
                operation,
                evidence_class: None,
            };
            this.db.put(key, serde_json::to_vec(&receipt)?).await?;
            Ok(true)
        })
        .await
        .context("join process operation claim")?
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
fn operation_key(id: Uuid) -> Vec<u8> {
    format!("operation/{id}").into_bytes()
}
fn validate_allocation(a: &Allocation) -> anyhow::Result<()> {
    if [&a.controller, &a.tenant_id, &a.sandbox_id]
        .iter()
        .any(|s| s.is_empty() || s.len() > 256)
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
