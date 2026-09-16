//! Dormant authenticated participant. No managed route or input consumer installs it.
//! Guest reports remain unknown for cessation, even after durable host mirroring.
use super::{
    authentication::{ProvisioningPins, Verifier},
    enrollment::{digest, HostEnrollment, SignedRecord, VerifiedEnrollment},
    wire, Admission, HostLedger, Operation, OriginalCloseRequest,
};
use anyhow::{ensure, Context, Result};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[async_trait::async_trait]
pub(super) trait Channel: Send + Sync {
    async fn seal(&self, request: Vec<u8>) -> Result<Vec<u8>>;
    async fn lookup(&self, operation: uuid::Uuid, authority: Vec<u8>) -> Result<Vec<u8>>;
}
#[async_trait::async_trait]
impl Channel for super::transport::ExactChannel {
    async fn seal(&self, request: Vec<u8>) -> Result<Vec<u8>> {
        self.seal(request).await
    }
    async fn lookup(&self, operation: uuid::Uuid, authority: Vec<u8>) -> Result<Vec<u8>> {
        self.lookup_signed(operation, authority).await
    }
}
/// The node signature binds the canonical guest record's digest. Consumers verify
/// both signatures; guest evidence remains historical and never proves cessation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedResponse {
    pub node: SignedRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest: Option<SignedRecord>,
}
#[derive(Clone)]
pub struct Participant {
    inner: Arc<Inner>,
}
struct Inner {
    anchor: Vec<u8>,
    ledger: HostLedger,
    saved: HostEnrollment,
    verifier: Verifier,
    controller_key: [u8; 32],
    key: Ed25519KeyPair,
    channel: Arc<dyn Channel>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}
impl Participant {
    /// Inputs are host-only provisioning material. This does not install a route,
    /// issue a grant, bind/release an epoch, or advertise a managed capability.
    pub async fn new(
        ledger: HostLedger,
        enrollment: VerifiedEnrollment,
        node_key_pkcs8: &[u8],
        guest_certificate: &[u8],
        host_identity: &[u8],
        budget: Duration,
    ) -> Result<Self> {
        ensure!(
            certificate_digest(guest_certificate)? == enrollment.saved.guest_certificate_sha256
                && certificate_digest(host_identity)? == enrollment.saved.host_certificate_sha256,
            "channel certificates differ from host enrollment"
        );
        let key = Ed25519KeyPair::from_pkcs8(node_key_pkcs8)
            .map_err(|_| anyhow::anyhow!("invalid host signing key"))?;
        let channel = super::transport::ExactChannel::new(
            &enrollment.saved.descriptor.process_endpoint,
            guest_certificate,
            host_identity,
            budget,
        )?;
        Self::with_channel(ledger, enrollment, key, Arc::new(channel), Arc::new(now)).await
    }
    async fn with_channel(
        ledger: HostLedger,
        enrollment: VerifiedEnrollment,
        key: Ed25519KeyPair,
        channel: Arc<dyn Channel>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<Self> {
        let saved = enrollment.saved;
        ensure!(
            key.public_key().as_ref() == saved.node_public_key
                && saved.valid_until_unix_ms > clock(),
            "host key/enrollment unavailable"
        );
        let verifier = Verifier::new(ProvisioningPins {
            allocation: saved.allocation.clone(),
            sandbox_family: saved.sandbox_family.clone(),
            descriptor: saved.descriptor.clone(),
            funded_session_id: saved.funded_session_id,
            controller_key: enrollment.controller_key,
            controller_key_id: saved.controller_key_id.clone(),
            trust_revision: saved.trust_revision,
            audience: saved.audience.clone(),
        })?;
        let anchor = host_anchor(&saved, &enrollment.controller_key)?;
        {
            let _guard = ledger.serial.lock().await;
            let mut state = ledger.enrollment().await?;
            ensure!(
                state.allocation == saved.allocation
                    && state.recovery_revision == saved.recovery_revision
                    && state.epoch_id == Some(saved.funded_session_id)
                    && state.directory_confirmed,
                "enrollment does not match saved host epoch"
            );
            // A signed current provisioning/reconciliation attestation may restore
            // closed lookup availability. It may NEVER reopen an unreconciled A.
            if state.admission == Admission::Unreconciled {
                ensure!(state.closed, "open epoch needs explicit reconciliation");
            }
            ensure!(
                ledger.db.get(b"provider_revoked".to_vec()).await?.is_none(),
                "provider authority revoked"
            );
            if let Some(prior) = ledger.db.get(b"provider_binding".to_vec()).await? {
                ensure!(
                    state.provider_initialized,
                    "provider initialization unavailable"
                );
                ensure!(prior == anchor, "host provisioning anchor changed");
                ledger.provider_revision().await?;
            } else {
                ensure!(
                    !state.provider_initialized
                        && ledger
                            .db
                            .get(b"provider_revision".to_vec())
                            .await?
                            .is_none()
                        && state.admission == Admission::Open
                        && !state.closed
                        && state.recovery_revision == 0,
                    "missing provider anchor during recovery"
                );
                state.provider_initialized = true;
                ledger
                    .db
                    .write_batch([
                        crate::local_store::LocalKvBatchOp::put(
                            b"enrollment".to_vec(),
                            serde_json::to_vec(&state)?,
                        ),
                        crate::local_store::LocalKvBatchOp::put(
                            b"provider_binding".to_vec(),
                            anchor.clone(),
                        ),
                        crate::local_store::LocalKvBatchOp::put(
                            b"provider_revision".to_vec(),
                            serde_json::to_vec(&1_u64)?,
                        ),
                    ])
                    .await?;
            }
            ensure!(
                ledger.db.get(b"provider_revoked".to_vec()).await?.is_none(),
                "provider authority revoked"
            );
            if state.admission == Admission::Unreconciled {
                state.admission = Admission::Closed;
                let revision = ledger
                    .provider_revision()
                    .await?
                    .checked_add(1)
                    .context("provider revision exhausted")?;
                ledger
                    .db
                    .write_batch([
                        crate::local_store::LocalKvBatchOp::put(
                            b"enrollment".to_vec(),
                            serde_json::to_vec(&state)?,
                        ),
                        crate::local_store::LocalKvBatchOp::put(
                            b"provider_revision".to_vec(),
                            serde_json::to_vec(&revision)?,
                        ),
                    ])
                    .await?;
            }
        }
        Ok(Self {
            inner: Arc::new(Inner {
                anchor,
                ledger,
                saved,
                verifier,
                controller_key: enrollment.controller_key,
                key,
                channel,
                clock,
            }),
        })
    }
    pub async fn seal(&self, request: SignedRecord) -> Result<AuthenticatedResponse> {
        // Dropping the caller must not cancel a claimed operation between network
        // acceptance and durable mirroring. Unknown outcomes retain their claim.
        let this = self.clone();
        tokio::spawn(async move { this.seal_inner(request).await })
            .await
            .context("join captured process dispatch")?
    }
    async fn seal_inner(&self, request: SignedRecord) -> Result<AuthenticatedResponse> {
        self.current().await?;
        let i = &self.inner;
        let verified = i.verifier.seal(
            &request.body,
            &request.envelope,
            &request.signature,
            (i.clock)(),
        )?;
        ensure!(
            verified.endpoint() == i.saved.descriptor.process_endpoint
                && verified.body() == request.body,
            "route mismatch"
        );
        let op = verified.operation().clone();
        let e: wire::SignedEnvelope = serde_json::from_slice(&request.envelope)?;
        let original = OriginalCloseRequest {
            body: request.body.clone(),
            envelope: request.envelope.clone(),
            signature: request.signature.clone(),
            descriptor: serde_json::to_vec(&i.saved.descriptor)?,
        };
        let deadline = e.expires_at_unix_ms.min(i.saved.valid_until_unix_ms);
        let clock = i.clock.clone();
        let fresh = i
            .ledger
            .begin_close_authorized(
                op.clone(),
                original,
                i.anchor.clone(),
                i.saved.recovery_revision,
                move || {
                    ensure!(clock() < deadline, "process authority expired before claim");
                    Ok(())
                },
            )
            .await?;
        if fresh {
            // No orphan adoption, runtime lookup, or retry. A lost/partial send
            // stays unknown even if the guest later claims it did nothing.
            if let Ok(bytes) = i.channel.seal(serde_json::to_vec(&request)?).await {
                self.mirror(&op, &bytes).await?;
            }
        }
        self.reply(&op, &e).await
    }
    pub async fn lookup(&self, authority: SignedRecord) -> Result<AuthenticatedResponse> {
        let this = self.clone();
        tokio::spawn(async move { this.lookup_inner(authority).await })
            .await
            .context("join captured process lookup")?
    }
    async fn lookup_inner(&self, authority: SignedRecord) -> Result<AuthenticatedResponse> {
        self.current().await?;
        let i = &self.inner;
        wire::verify_record(
            "LookupRequest",
            "agentenv-process-epoch/lookup/v1",
            &authority.body,
            &authority.envelope,
            &i.controller_key,
            &authority.signature,
        )?;
        let e: wire::SignedEnvelope = serde_json::from_slice(&authority.envelope)?;
        let r: wire::LookupRequest = serde_json::from_slice(&authority.body)?;
        self.envelope(
            &e,
            &i.saved.allocation.controller,
            &i.saved.controller_key_id,
            &i.saved.audience,
            &digest(&authority.body),
            true,
        )?;
        ensure!(e.nonce == r.nonce, "lookup nonce mismatch");
        let op = Operation {
            allocation: i.saved.allocation.clone(),
            epoch_id: i.saved.funded_session_id,
            operation_id: r.binding.operation_id.parse()?,
            request_sha256: r.saved_request_sha256.clone(),
        };
        let original = i
            .ledger
            .original_close_request(&op)
            .await
            .context("process operation unavailable")?;
        let saved: wire::SealRequest = serde_json::from_slice(&original.body)?;
        ensure!(r.binding == saved.binding, "lookup scope conflict");
        let read_admitted = {
            let _guard = i.ledger.serial.lock().await;
            self.current().await?;
            ensure!(
                (i.clock)() < e.expires_at_unix_ms,
                "lookup expired before admission"
            );
            let missing = i.ledger.db.get(mirror_key(&op)).await?.is_none();
            if missing {
                let receipt = i.ledger.lookup(&op).await?.context("claim missing")?;
                ensure!(receipt.evidence_class.is_none(), "guest report missing");
            }
            missing
        };
        if read_admitted {
            // Read-only recovery presents the caller's exact signed lookup proof.
            // It cannot mint a user grant or send the original POST again.
            if let Ok(bytes) = i
                .channel
                .lookup(op.operation_id, serde_json::to_vec(&authority)?)
                .await
            {
                self.mirror(&op, &bytes).await?;
            }
        }
        self.reply(&op, &e).await
    }
    /// Operator-side revocation only; no public HTTP handler exposes this primitive.
    /// Closing admission is not host cessation or permission to settle accounting.
    pub async fn revoke(&self) -> Result<()> {
        let ledger = self.inner.ledger.clone();
        tokio::spawn(async move {
            let _guard = ledger.serial.lock().await;
            let mut state = ledger.enrollment().await?;
            state.closed = true;
            state.admission = Admission::Closed;
            ledger
                .db
                .write_batch([
                    crate::local_store::LocalKvBatchOp::put(
                        b"provider_revoked".to_vec(),
                        b"revoked".to_vec(),
                    ),
                    crate::local_store::LocalKvBatchOp::put(
                        b"enrollment".to_vec(),
                        serde_json::to_vec(&state)?,
                    ),
                ])
                .await
        })
        .await
        .context("join provider revocation")?
    }
    async fn current(&self) -> Result<()> {
        let i = &self.inner;
        ensure!(
            i.ledger
                .db
                .get(b"provider_binding".to_vec())
                .await?
                .as_ref()
                == Some(&i.anchor),
            "provider anchor unavailable"
        );
        i.ledger.provider_revision().await?;
        let state = i.ledger.enrollment().await?;
        ensure!(
            (i.clock)() < i.saved.valid_until_unix_ms
                && state.allocation == i.saved.allocation
                && state.recovery_revision == i.saved.recovery_revision
                && state.epoch_id == Some(i.saved.funded_session_id)
                && state.directory_confirmed
                && state.provider_initialized
                && state.admission != Admission::Unreconciled
                && i.ledger
                    .db
                    .get(b"provider_revoked".to_vec())
                    .await?
                    .is_none(),
            "current process authority unavailable"
        );
        Ok(())
    }
    fn envelope(
        &self,
        e: &wire::SignedEnvelope,
        signer: &str,
        key_id: &str,
        audience: &str,
        request_hash: &str,
        current: bool,
    ) -> Result<()> {
        let i = &self.inner;
        let d = &i.saved.descriptor;
        ensure!(
            e.signer == signer
                && e.key_id == key_id
                && e.audience == audience
                && e.trust_revision == i.saved.trust_revision
                && (!current || e.expires_at_unix_ms > (i.clock)())
                && e.node_id == d.node_id
                && e.node_incarnation == d.node_incarnation
                && e.runtime_id == d.runtime_id
                && e.runtime_incarnation == d.runtime_incarnation
                && e.enrollment_revision == d.enrollment_revision
                && e.descriptor_sha256 == digest(&serde_json::to_vec(d)?)
                && e.request_sha256 == request_hash,
            "response/lookup authority mismatch"
        );
        Ok(())
    }
    fn validate_guest(
        &self,
        op: &Operation,
        signed: &SignedRecord,
        saved: &wire::SealRequest,
    ) -> Result<()> {
        let i = &self.inner;
        wire::verify_record(
            "GuestReceipt",
            "agentenv-process-epoch/guest-receipt/v1",
            &signed.body,
            &signed.envelope,
            &i.saved.guest_public_key,
            &signed.signature,
        )?;
        let e: wire::SignedEnvelope = serde_json::from_slice(&signed.envelope)?;
        self.envelope(
            &e,
            &i.saved.descriptor.guest_boot_id,
            &i.saved.guest_key_id,
            &i.saved.audience,
            &op.request_sha256,
            false,
        )?;
        let guest: wire::GuestReceipt = serde_json::from_slice(&signed.body)?;
        ensure!(
            guest.binding == saved.binding
                && guest.request_sha256 == op.request_sha256
                && guest.evidence_class == "guest_reported",
            "guest receipt scope/class conflict"
        );
        Ok(())
    }
    async fn mirror(&self, op: &Operation, bytes: &[u8]) -> Result<()> {
        ensure!(bytes.len() <= 65536, "guest response too large");
        let signed: SignedRecord = serde_json::from_slice(bytes)?;
        let i = &self.inner;
        let original = i.ledger.original_close_request(op).await?;
        let saved: wire::SealRequest = serde_json::from_slice(&original.body)?;
        self.validate_guest(op, &signed, &saved)?;
        let _guard = i.ledger.serial.lock().await;
        ensure!(
            i.ledger
                .db
                .get(b"provider_binding".to_vec())
                .await?
                .as_ref()
                == Some(&i.anchor),
            "provider anchor unavailable"
        );
        let mut receipt = i.ledger.lookup(op).await?.context("claim missing")?;
        let key = mirror_key(op);
        let canonical = serde_json::to_vec(&signed)?;
        if let Some(prior) = i.ledger.db.get(key.clone()).await? {
            ensure!(prior == canonical, "first guest report conflict");
            return Ok(());
        }
        ensure!(receipt.evidence_class.is_none(), "guest report missing");
        // Even a correctly signed reported_complete is only guest_reported.
        receipt.evidence_class = Some(super::EvidenceClass::GuestReported);
        let revision = i
            .ledger
            .provider_revision()
            .await?
            .checked_add(1)
            .context("provider revision exhausted")?;
        i.ledger
            .db
            .write_batch([
                crate::local_store::LocalKvBatchOp::put(key, canonical),
                crate::local_store::LocalKvBatchOp::put(
                    b"provider_revision".to_vec(),
                    serde_json::to_vec(&revision)?,
                ),
                crate::local_store::LocalKvBatchOp::put(
                    super::operation_key(op.operation_id),
                    serde_json::to_vec(&receipt)?,
                ),
            ])
            .await?;
        Ok(())
    }
    async fn reply(
        &self,
        op: &Operation,
        authority: &wire::SignedEnvelope,
    ) -> Result<AuthenticatedResponse> {
        let i = &self.inner;
        let _guard = i.ledger.serial.lock().await;
        self.current().await?;
        ensure!(
            (i.clock)() < authority.expires_at_unix_ms,
            "request expired before response"
        );
        let raw = i
            .ledger
            .db
            .get(b"closing_intent".to_vec())
            .await?
            .context("closing intent missing")?;
        let intent: super::ClosingIntent = serde_json::from_slice(&raw)?;
        ensure!(&intent.operation == op, "operation conflict");
        let original = intent.original.context("original request missing")?;
        original.validate(op)?;
        wire::verify_record(
            "SealRequest",
            "agentenv-process-epoch/seal/v1",
            &original.body,
            &original.envelope,
            &i.controller_key,
            &original.signature,
        )?;
        let saved: wire::SealRequest = serde_json::from_slice(&original.body)?;
        let receipt = i.ledger.lookup(op).await?.context("claim missing")?;
        let mirror = i.ledger.db.get(mirror_key(op)).await?;
        let guest = if let Some(bytes) = &mirror {
            ensure!(bytes.len() <= 65536, "stored guest report too large");
            let guest: SignedRecord = serde_json::from_slice(bytes)?;
            ensure!(
                serde_json::to_vec(&guest)? == *bytes
                    && receipt.evidence_class == Some(super::EvidenceClass::GuestReported),
                "stored guest report conflict"
            );
            self.validate_guest(op, &guest, &saved)?;
            Some(guest)
        } else {
            ensure!(receipt.evidence_class.is_none(), "guest report missing");
            None
        };
        let evidence = mirror.as_ref().map(|bytes| wire::EvidenceReference {
            evidence_class: "guest_reported".into(),
            evidence_id: op.operation_id.to_string(),
            evidence_sha256: digest(bytes),
        });
        let body = wire::LookupResponse {
            binding: saved.binding,
            request_sha256: op.request_sha256.clone(),
            state: if mirror.is_some() {
                "incomplete"
            } else {
                "effect_unknown"
            }
            .into(),
            node_ledger_revision: i.ledger.provider_revision().await?,
            receipt_id: None,
            receipt_sha256: None,
            receipt_kind: None,
            affected_operations_sha256: None,
            evidence,
        };
        let body = serde_json::to_vec(&body)?;
        wire::decode_canonical("LookupResponse", &body)?;
        let mut e = authority.clone();
        e.domain = "agentenv-process-epoch/node-response/v1".into();
        e.signer = i.saved.descriptor.node_id.clone();
        e.key_id = i.saved.node_key_id.clone();
        e.audience = i.saved.allocation.controller.clone();
        e.request_sha256 = op.request_sha256.clone();
        e.body_sha256 = digest(&body);
        e.expires_at_unix_ms = e.expires_at_unix_ms.min(i.saved.valid_until_unix_ms);
        let envelope = serde_json::to_vec(&e)?;
        let signature = i
            .key
            .sign(&wire::signature_input(&envelope)?)
            .as_ref()
            .to_vec();
        Ok(AuthenticatedResponse {
            node: SignedRecord {
                body,
                envelope,
                signature,
            },
            guest,
        })
    }
}
fn mirror_key(op: &Operation) -> Vec<u8> {
    format!("guest_report/{}", op.operation_id).into_bytes()
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(u64::MAX)
}
fn certificate_digest(pem: &[u8]) -> Result<String> {
    use base64::Engine;
    let pem = std::str::from_utf8(pem)?;
    let start = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    ensure!(
        pem.matches(start).count() == 1 && pem.matches(end).count() == 1,
        "one enrolled certificate required"
    );
    let encoded = pem
        .split_once(start)
        .context("certificate missing")?
        .1
        .split_once(end)
        .context("certificate incomplete")?
        .0;
    let encoded: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    Ok(digest(
        &base64::engine::general_purpose::STANDARD.decode(encoded)?,
    ))
}
#[cfg(test)]
mod tests;

fn host_anchor(saved: &HostEnrollment, controller_key: &[u8; 32]) -> Result<Vec<u8>> {
    let mut anchor = saved.clone();
    anchor.recovery_revision = 0;
    anchor.valid_until_unix_ms = 0;
    Ok(serde_json::to_vec(&(anchor, controller_key))?)
}
