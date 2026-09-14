//! Durable dispatch receipts. A lost response never makes a dispatched key reusable.

use std::{path::PathBuf, sync::Arc};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::local_store::{LocalKvStore, LocalStoreDurability};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationBinding {
    pub authority: String,
    pub operation_key: String,
    pub request_sha256: String,
    pub saved_route: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationReceipt {
    pub binding: OperationBinding,
    pub runtime_id: Uuid,
    pub incarnation: Uuid,
    pub dispatched: bool,
    pub completed: bool,
}

#[derive(Clone)]
pub struct OperationReceipts {
    db: LocalKvStore,
    serial: Arc<Mutex<()>>,
}

impl OperationReceipts {
    pub async fn open(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        Ok(Self {
            db: LocalKvStore::open(path, LocalStoreDurability::Sync).await?,
            serial: Arc::new(Mutex::new(())),
        })
    }

    /// Authority must come from authentication, never an unverified request field.
    /// The route is frozen before this call; this store never chooses another node.
    pub async fn reserve(&self, binding: OperationBinding) -> anyhow::Result<OperationReceipt> {
        let this = self.clone();
        // Retain serialization until the fsync completes even if the HTTP caller
        // drops its future. A cancelled write must not race the next reservation.
        tokio::spawn(async move {
            let _guard = this.serial.lock().await;
            let key = receipt_key(&binding.authority, &binding.operation_key)?;
            if let Some(bytes) = this.db.get(key.clone()).await? {
                let receipt: OperationReceipt = serde_json::from_slice(&bytes)?;
                if receipt.binding != binding {
                    bail!("operation binding conflict");
                }
                return Ok(receipt);
            }
            if binding.saved_route.is_empty()
                || binding.request_sha256.len() != 64
                || !binding
                    .request_sha256
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit())
            {
                bail!("invalid operation binding");
            }
            let receipt = OperationReceipt {
                binding,
                runtime_id: Uuid::new_v4(),
                incarnation: Uuid::new_v4(),
                dispatched: false,
                completed: false,
            };
            this.db.put(key, serde_json::to_vec(&receipt)?).await?;
            Ok(receipt)
        })
        .await
        .context("join operation reservation")?
    }

    /// True authorizes only the first worker to dispatch the captured allocation.
    /// After restart a dispatched receipt requires exact-runtime reconciliation;
    /// absence from a local roster cannot authorize running this operation again.
    pub async fn claim(&self, expected: OperationReceipt) -> anyhow::Result<bool> {
        let this = self.clone();
        tokio::spawn(async move {
            let _guard = this.serial.lock().await;
            let key = receipt_key(&expected.binding.authority, &expected.binding.operation_key)?;
            let bytes = this
                .db
                .get(key.clone())
                .await?
                .context("operation receipt missing")?;
            let mut saved: OperationReceipt = serde_json::from_slice(&bytes)?;
            if saved.binding != expected.binding
                || saved.runtime_id != expected.runtime_id
                || saved.incarnation != expected.incarnation
            {
                bail!("operation allocation conflict");
            }
            if saved.dispatched {
                return Ok(false);
            }
            saved.dispatched = true;
            this.db.put(key, serde_json::to_vec(&saved)?).await?;
            Ok(true)
        })
        .await
        .context("join operation claim")?
    }

    /// Save successful creation evidence before publishing the final response.
    /// The caller must have confirmed this exact allocation with the runtime.
    /// This historical result does not prove the runtime is still running.
    pub async fn complete(&self, expected: OperationReceipt) -> anyhow::Result<OperationReceipt> {
        let this = self.clone();
        tokio::spawn(async move {
            let _guard = this.serial.lock().await;
            let key = receipt_key(&expected.binding.authority, &expected.binding.operation_key)?;
            let bytes = this
                .db
                .get(key.clone())
                .await?
                .context("operation receipt missing")?;
            let mut saved: OperationReceipt = serde_json::from_slice(&bytes)?;
            if saved.binding != expected.binding
                || saved.runtime_id != expected.runtime_id
                || saved.incarnation != expected.incarnation
                || !saved.dispatched
            {
                bail!("operation completion conflict");
            }
            if !saved.completed {
                saved.completed = true;
                this.db.put(key, serde_json::to_vec(&saved)?).await?;
            }
            Ok(saved)
        })
        .await
        .context("join operation completion")?
    }

    pub async fn lookup(
        &self,
        authority: &str,
        operation_key: &str,
    ) -> anyhow::Result<Option<OperationReceipt>> {
        let _guard = self.serial.lock().await;
        let key = receipt_key(authority, operation_key)?;
        self.db
            .get(key)
            .await?
            .map(|bytes| serde_json::from_slice(&bytes).context("decode operation receipt"))
            .transpose()
    }
}

fn receipt_key(authority: &str, operation_key: &str) -> anyhow::Result<Vec<u8>> {
    if authority.is_empty()
        || authority.len() > 256
        || operation_key.is_empty()
        || operation_key.len() > 256
    {
        bail!("invalid operation identity");
    }
    // Length framing prevents different authority/key pairs sharing a namespace.
    let mut hash = Sha256::new();
    hash.update((authority.len() as u64).to_be_bytes());
    hash.update(authority.as_bytes());
    hash.update(operation_key.as_bytes());
    Ok(hash.finalize().to_vec())
}

#[cfg(test)]
mod tests;
