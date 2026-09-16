//! Strict parsing of the frozen B + E transport shape. Parsing is not authority.
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UntrustedVolumeEncryption {
    pub volume_id: String,
    pub volume_kind: String,
    #[serde(default)]
    pub drive_id: Option<String>,
    pub grant: String,
    pub signature: String,
    pub wrapped_dek: String,
    pub kms_key: String,
    pub kms_key_version: String,
    pub kms_aad: String,
    pub cipher: String,
    pub sector_size: u32,
}

/// Contains potentially sensitive original request bytes; intentionally no Debug
/// or Serialize. Neither this nor its envelope is a VerifiedLaunch capability.
pub struct ParsedLaunchBody {
    body: Vec<u8>,
    envelope: Option<UntrustedVolumeEncryption>,
}
impl ParsedLaunchBody {
    pub fn provider_body(&self) -> &[u8] {
        &self.body
    }
    pub fn envelope(&self) -> Option<&UntrustedVolumeEncryption> {
        self.envelope.as_ref()
    }
    pub fn body_sha256(&self) -> String {
        hex::encode(Sha256::digest(&self.body))
    }
}
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid encrypted launch request encoding")]
pub struct InvalidLaunchBody;

/// A missing envelope says nothing about the required encryption policy.
pub fn parse_launch_body(_wire: &[u8]) -> Result<ParsedLaunchBody, InvalidLaunchBody> {
    Err(InvalidLaunchBody)
}
#[cfg(test)]
mod tests;
