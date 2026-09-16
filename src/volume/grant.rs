//! Dormant signature/consume boundary. A consumed grant is retained evidence,
//! not a VerifiedLaunch or permission for KMS/mount; app pins remain unavailable.
use super::wire::{decode_base64, validate_unique_json, UntrustedVolumeEncryption};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantOrigin {
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub snapshot_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub snapshot_alias: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub record_digest: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub template_id: String,
}

// Field order/omissions match LaunchGrantPayload v6 in the Go app. Strings retain
// signed timestamp bytes; parsed clocks are only used for validity checks.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantPayload {
    pub v: u32,
    pub grant_id: String,
    pub tenant_id: String,
    pub owner_user_id: String,
    pub sandbox_family: String,
    pub launch_kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub creation_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub restore_launch_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reserved_session_id: String,
    pub mode: String,
    pub volume_id: String,
    pub volume_kind: String,
    pub drive_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub live_sandbox_id: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub generation: i64,
    pub origin: GrantOrigin,
    pub template_lineage_root: String,
    pub request_sha256: String,
    pub destination_node_id: String,
    pub kms_key: String,
    pub kms_key_version: String,
    pub kms_aad: String,
    pub wrapped_dek_sha256: String,
    pub issued_at: String,
    pub expires_at: String,
}
fn is_zero(v: &i64) -> bool {
    *v == 0
}

/// Only a future authenticated app participant may construct this. There is no
/// public constructor, Deserialize or production producer. It is NOT caller input.
pub struct AuthenticatedGrantBinding {
    expected: GrantPayload,
    node_id: String,
    incarnation: String,
}

pub struct TrustedGrantKeys {
    keys: Vec<Vec<u8>>,
}
impl TrustedGrantKeys {
    /// Provisioned allowlisted signing versions only, never request-provided keys.
    pub fn from_sec1(keys: Vec<Vec<u8>>) -> Result<Self, GrantDenied> {
        if keys.is_empty() || keys.len() > 16 || keys.iter().any(|k| k.len() != 65 || k[0] != 4) {
            return Err(GrantDenied);
        }
        Ok(Self { keys })
    }
}
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("volume launch grant unavailable or denied")]
pub struct GrantDenied;

/// Private fields prevent constructing verification evidence from an HTTP body.
pub struct VerifiedGrant {
    payload: GrantPayload,
    payload_hash: String,
    node_id: String,
    incarnation: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumeRequest {
    pub grant_id: String,
    pub payload_sha256: String,
    pub node_id: String,
    pub incarnation: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumeReply {
    pub state: String,
    pub tenant_id: String,
    pub volume_id: String,
}
#[async_trait]
pub trait GrantConsumer: Send + Sync {
    /// Adapter must authenticate the configured node and await the app's committed
    /// deadline-qualified single-use CAS. No retry of ambiguous consumption.
    async fn consume(&self, request: ConsumeRequest) -> Result<ConsumeReply, GrantDenied>;
}
pub struct ConsumedGrantEvidence {
    grant: VerifiedGrant,
}
impl ConsumedGrantEvidence {
    pub fn grant_id(&self) -> &str {
        &self.grant.payload.grant_id
    }
}

pub fn verify_grant(
    wire: &UntrustedVolumeEncryption,
    binding: &AuthenticatedGrantBinding,
    keys: &TrustedGrantKeys,
    now: DateTime<Utc>,
) -> Result<VerifiedGrant, GrantDenied> {
    let raw = decode_base64(&wire.grant).map_err(|_| GrantDenied)?;
    let sig = decode_base64(&wire.signature).map_err(|_| GrantDenied)?;
    if raw.len() > 64 * 1024 || sig.len() > 80 {
        return Err(GrantDenied);
    }
    if !keys.keys.iter().any(|key| {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
            .verify(&raw, &sig)
            .is_ok()
    }) {
        return Err(GrantDenied);
    }
    validate_unique_json(&raw).map_err(|_| GrantDenied)?;
    let payload: GrantPayload = serde_json::from_slice(&raw).map_err(|_| GrantDenied)?;
    // Match Go encoding/json's HTML and line-separator escaping without ever
    // replacing the original bytes used for signature or payload hash checks.
    let canonical = serde_json::to_string(&payload)
        .map_err(|_| GrantDenied)?
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    if canonical.as_bytes() != raw
        || payload != binding.expected
        || payload.destination_node_id != binding.node_id
        || binding.incarnation.trim().is_empty()
    {
        return Err(GrantDenied);
    }
    validate_payload(&payload, now)?;
    let wrapped = decode_base64(&wire.wrapped_dek).map_err(|_| GrantDenied)?;
    if wire.volume_id != payload.volume_id
        || wire.volume_kind != payload.volume_kind
        || wire.drive_id.as_deref().unwrap_or("") != payload.drive_id
        || wire.kms_key != payload.kms_key
        || wire.kms_key_version != payload.kms_key_version
        || wire.kms_aad != payload.kms_aad
        || wire.cipher != "aes-xts-plain64"
        || wire.sector_size != 4096
        || hex::encode(Sha256::digest(wrapped)) != payload.wrapped_dek_sha256
    {
        return Err(GrantDenied);
    }
    Ok(VerifiedGrant {
        payload,
        payload_hash: hex::encode(Sha256::digest(raw)),
        node_id: binding.node_id.clone(),
        incarnation: binding.incarnation.clone(),
    })
}
fn validate_payload(p: &GrantPayload, now: DateTime<Utc>) -> Result<(), GrantDenied> {
    let issued = DateTime::parse_from_rfc3339(&p.issued_at).map_err(|_| GrantDenied)?;
    let expires = DateTime::parse_from_rfc3339(&p.expires_at).map_err(|_| GrantDenied)?;
    if p.v != 6
        || p.sandbox_family != "legacy"
        || p.mode != "required"
        || issued > now
        || expires <= now
        || expires <= issued
        || expires.signed_duration_since(issued) > chrono::Duration::minutes(15)
    {
        return Err(GrantDenied);
    }
    for field in [
        &p.grant_id,
        &p.tenant_id,
        &p.owner_user_id,
        &p.volume_id,
        &p.template_lineage_root,
        &p.destination_node_id,
        &p.kms_key,
        &p.kms_key_version,
    ] {
        if field.trim().is_empty() || field.len() > 2048 || field.chars().any(char::is_control) {
            return Err(GrantDenied);
        }
    }
    if !sha256_hex(&p.request_sha256)
        || !sha256_hex(&p.wrapped_dek_sha256)
        || p.kms_aad != format!("vol:{}:{}:{}", p.tenant_id, p.volume_id, p.volume_kind)
    {
        return Err(GrantDenied);
    }
    match p.volume_kind.as_str() {
        "sandbox_rootfs" if p.drive_id.is_empty() => (),
        // Attached writable drives remain unavailable until their own binding exists.
        _ => return Err(GrantDenied),
    }
    match p.launch_kind.as_str() {
        "create"
            if !p.creation_id.is_empty()
                && p.restore_launch_id.is_empty()
                && p.reserved_session_id.is_empty()
                && p.live_sandbox_id.is_empty()
                && p.generation == 0
                && p.origin.kind == "template"
                && !p.origin.template_id.is_empty()
                && p.origin.snapshot_id.is_empty()
                && p.origin.snapshot_alias.is_empty()
                && p.origin.record_digest.is_empty() =>
        {
            ()
        }
        "restore"
            if p.creation_id.is_empty()
                && !p.restore_launch_id.is_empty()
                && !p.reserved_session_id.is_empty()
                && !p.live_sandbox_id.is_empty()
                && p.generation > 0
                && p.origin.kind == "snapshot"
                && !p.origin.snapshot_id.is_empty()
                && sha256_hex(&p.origin.record_digest)
                && p.origin.template_id.is_empty() =>
        {
            ()
        }
        _ => return Err(GrantDenied),
    }
    Ok(())
}
fn sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub async fn consume_verified_grant(
    grant: VerifiedGrant,
    consumer: &dyn GrantConsumer,
    now: DateTime<Utc>,
) -> Result<ConsumedGrantEvidence, GrantDenied> {
    validate_payload(&grant.payload, now)?;
    let reply = consumer
        .consume(ConsumeRequest {
            grant_id: grant.payload.grant_id.clone(),
            payload_sha256: grant.payload_hash.clone(),
            node_id: grant.node_id.clone(),
            incarnation: grant.incarnation.clone(),
        })
        .await?;
    if reply.state != "consumed"
        || reply.tenant_id != grant.payload.tenant_id
        || reply.volume_id != grant.payload.volume_id
    {
        return Err(GrantDenied);
    }
    // No retry here, including ambiguous errors. Recovery uses the saved exact
    // operation through a separate authority path; this evidence cannot mount.
    Ok(ConsumedGrantEvidence { grant })
}
#[cfg(test)]
mod tests;
