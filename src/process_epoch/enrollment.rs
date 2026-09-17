//! Dormant enrollment verifier. Operator attestation must describe an independently
//! verified host runtime/artifact mapping, not a guest handshake. The production
//! workload-identity/provisioning adapter and rollout remain uninstalled.
use super::{wire, Allocation};
use anyhow::ensure;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRecord {
    pub body: Vec<u8>,
    pub envelope: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub envd_commit: String,
    pub ordered_patch_sha256: Vec<String>,
    pub protocol_sha256: String,
    pub binary_sha256: String,
    pub tools_image_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEnrollment {
    pub allocation: Allocation,
    pub sandbox_family: String,
    pub descriptor: wire::Descriptor,
    pub funded_session_id: uuid::Uuid,
    pub recovery_revision: u64,
    pub trust_revision: u64,
    pub valid_until_unix_ms: u64,
    pub manifest_sha256: String,
    pub mapped_tools_sha256: String,
    pub controller_key_id: String,
    pub node_key_id: String,
    pub node_public_key: Vec<u8>,
    pub guest_key_id: String,
    pub guest_public_key: Vec<u8>,
    pub guest_certificate_sha256: String,
    pub host_certificate_sha256: String,
    pub audience: String,
}
/// These roots/policy arrive through host-only operator configuration, never RPC
/// parameters or tenant volumes. Distinct roles prevent guest/controller keys from
/// certifying their own provisioning. No signing/registration endpoint is installed.
pub struct HostTrust {
    pub provider_root: [u8; 32],
    pub release_root: [u8; 32],
    pub controller_root: [u8; 32],
    pub controller_key_id: String,
    pub trust_revision: u64,
    pub approved_manifest_sha256: String,
}
pub struct EnrollmentDocuments {
    pub enrollment: Vec<u8>,
    pub enrollment_signature: Vec<u8>,
    pub manifest: Vec<u8>,
    pub manifest_signature: Vec<u8>,
}
pub struct VerifiedEnrollment {
    pub(super) saved: HostEnrollment,
    pub(super) controller_key: [u8; 32],
}
impl HostTrust {
    pub fn verify(
        &self,
        documents: &EnrollmentDocuments,
        allocation: &Allocation,
        recovery_revision: u64,
        now: u64,
    ) -> anyhow::Result<VerifiedEnrollment> {
        ensure!(
            self.provider_root != self.release_root
                && self.provider_root != self.controller_root
                && self.release_root != self.controller_root
                && self.trust_revision > 0,
            "invalid host trust roles"
        );
        verify_domain(
            "agentenv-process-epoch/host-enrollment/v1",
            &documents.enrollment,
            &documents.enrollment_signature,
            &self.provider_root,
        )?;
        verify_domain(
            "agentenv-process-epoch/release-manifest/v1",
            &documents.manifest,
            &documents.manifest_signature,
            &self.release_root,
        )?;
        let saved: HostEnrollment = canonical(&documents.enrollment)?;
        let manifest: ReleaseManifest = canonical(&documents.manifest)?;
        super::validate_allocation(&saved.allocation)?;
        let d = &saved.descriptor;
        wire::decode_canonical("Descriptor", &serde_json::to_vec(d)?)?;
        ensure!(
            matches!(saved.sandbox_family.as_str(), "legacy" | "native")
                && &saved.allocation == allocation
                && saved.recovery_revision == recovery_revision
                && saved.trust_revision == self.trust_revision
                && saved.valid_until_unix_ms > now
                && saved.controller_key_id == self.controller_key_id
                && !saved.funded_session_id.is_nil()
                && !saved.node_key_id.is_empty()
                && !saved.guest_key_id.is_empty()
                && !saved.audience.is_empty()
                && saved.node_public_key.len() == 32
                && saved.guest_public_key.len() == 32
                && saved.node_public_key != saved.guest_public_key
                && saved.node_public_key != self.controller_root
                && saved.guest_public_key != self.controller_root
                && saved.node_public_key != self.provider_root
                && saved.guest_public_key != self.provider_root
                && saved.node_public_key != self.release_root
                && saved.guest_public_key != self.release_root
                && is_hash(&saved.guest_certificate_sha256)
                && is_hash(&saved.host_certificate_sha256)
                && d.runtime_id == allocation.runtime_id.to_string()
                && d.runtime_incarnation == allocation.runtime_incarnation.to_string()
                && d.enrollment_revision == allocation.enrollment_revision,
            "host enrollment does not match current authority"
        );
        let manifest_hash = digest(&documents.manifest);
        ensure!(
            manifest_hash == self.approved_manifest_sha256
                && manifest_hash == saved.manifest_sha256
                && saved.mapped_tools_sha256 == manifest.tools_image_sha256
                && d.guest_build_sha256 == manifest.binary_sha256
                && manifest.protocol_sha256
                    == digest(include_bytes!(
                        "../../testdata/process-epoch-vectors/v1/schema.json"
                    ))
                && manifest.envd_commit.len() == 40
                && is_lower_hex(&manifest.envd_commit)
                && manifest.ordered_patch_sha256.len() <= 128
                && manifest
                    .ordered_patch_sha256
                    .iter()
                    .all(|hash| is_hash(hash))
                && is_hash(&manifest.binary_sha256)
                && is_hash(&manifest.tools_image_sha256),
            "unapproved host build mapping"
        );
        Ok(VerifiedEnrollment {
            saved,
            controller_key: self.controller_root,
        })
    }
}
pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(super) fn canonical<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> anyhow::Result<T> {
    ensure!(bytes.len() <= 65536, "enrollment document too large");
    let record: T = serde_json::from_slice(bytes)?;
    ensure!(
        serde_json::to_vec(&record)? == bytes,
        "noncanonical enrollment document"
    );
    Ok(record)
}
pub(super) fn verify_domain(
    domain: &str,
    bytes: &[u8],
    signature: &[u8],
    key: &[u8],
) -> anyhow::Result<()> {
    let mut message = domain.as_bytes().to_vec();
    message.push(0);
    message.extend_from_slice(bytes);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(&message, signature)
        .map_err(|_| anyhow::anyhow!("invalid provisioning signature"))
}
#[cfg(test)]
pub(crate) mod tests;

fn is_hash(value: &str) -> bool {
    value.len() == 64 && is_lower_hex(value)
}
fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
