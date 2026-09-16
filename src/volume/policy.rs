//! Independent policy is required even when the launch omits volumeEncryption.
//! This is a policy check, not a verified launch or permission to perform effects.
use async_trait::async_trait;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchKind {
    Create,
    Restore,
    Reopen,
}

/// Observed coordinates; dispatch identity must be resolved by an authenticated
/// control-plane adapter. Merely copying these fields grants no authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyObservation {
    pub dispatch_id: String,
    pub node_id: String,
    pub incarnation: String,
    pub kind: LaunchKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyPolicy {
    NoKey,
    Active,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetainedHistory {
    Legacy,
    Encrypted,
    Unknown,
}

/// Facts from a current authenticated, row-locked lookup, never from NewSandbox.
/// No production adapter exists until the app-side contract is frozen and gated.
#[derive(Clone, Debug)]
pub struct PolicyFacts {
    pub observation: PolicyObservation,
    pub tenant_id: String,
    pub owner_id: String,
    pub admission_allowed: bool,
    pub key_policy: KeyPolicy,
    pub retained_history: RetainedHistory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadPresence {
    Absent,
    Present,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionRequirement {
    Legacy,
    Required,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("volume launch policy unavailable or denied")]
pub struct PolicyDenied;

#[async_trait]
pub trait LaunchPolicy: Send + Sync {
    async fn lookup(&self, observed: &PolicyObservation) -> Result<PolicyFacts, PolicyDenied>;
}

/// Does not consume a grant, unwrap keys or authorize any launch effect.
/// None is missing configuration, never an instruction to use legacy mode.
pub async fn authorize_launch_policy(
    policy: Option<&dyn LaunchPolicy>,
    observed: &PolicyObservation,
    payload: PayloadPresence,
) -> Result<EncryptionRequirement, PolicyDenied> {
    if observed.dispatch_id.trim().is_empty()
        || observed.node_id.trim().is_empty()
        || observed.incarnation.trim().is_empty()
        || payload == PayloadPresence::Invalid
    {
        return Err(PolicyDenied);
    }
    let facts = policy.ok_or(PolicyDenied)?.lookup(observed).await?;
    if facts.observation != *observed
        || facts.tenant_id.trim().is_empty()
        || facts.owner_id.trim().is_empty()
        || !facts.admission_allowed
        || facts.key_policy == KeyPolicy::Unavailable
        || facts.retained_history == RetainedHistory::Unknown
    {
        return Err(PolicyDenied);
    }
    let required = facts.key_policy == KeyPolicy::Active
        || facts.retained_history == RetainedHistory::Encrypted;
    match payload {
        PayloadPresence::Absent if !required => Ok(EncryptionRequirement::Legacy),
        PayloadPresence::Present => Ok(EncryptionRequirement::Required),
        _ => Err(PolicyDenied),
    }
}

#[cfg(test)]
mod tests;
