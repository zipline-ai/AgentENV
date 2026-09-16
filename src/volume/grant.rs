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
    _wire: &UntrustedVolumeEncryption,
    _binding: &AuthenticatedGrantBinding,
    _keys: &TrustedGrantKeys,
    _now: DateTime<Utc>,
) -> Result<VerifiedGrant, GrantDenied> {
    Err(GrantDenied)
}
pub async fn consume_verified_grant(
    _grant: VerifiedGrant,
    _consumer: &dyn GrantConsumer,
    _now: DateTime<Utc>,
) -> Result<ConsumedGrantEvidence, GrantDenied> {
    Err(GrantDenied)
}

#[cfg(test)]
mod tests;
