use super::*;
use std::sync::Mutex;

struct RecordingPolicy {
    expected: PolicyObservation,
    result: Result<PolicyFacts, PolicyDenied>,
    calls: Mutex<Vec<PolicyObservation>>,
}
#[async_trait]
impl LaunchPolicy for RecordingPolicy {
    async fn lookup(&self, observed: &PolicyObservation) -> Result<PolicyFacts, PolicyDenied> {
        assert_eq!(observed, &self.expected);
        self.calls.lock().unwrap().push(observed.clone());
        self.result.as_ref().cloned().map_err(|_| PolicyDenied)
    }
}
fn observation(kind: LaunchKind) -> PolicyObservation {
    PolicyObservation {
        dispatch_id: "dispatch-exact".into(),
        node_id: "node-exact".into(),
        incarnation: "boot-exact".into(),
        kind,
    }
}
fn recording(
    observed: &PolicyObservation,
    key: KeyPolicy,
    history: RetainedHistory,
) -> RecordingPolicy {
    RecordingPolicy {
        expected: observed.clone(),
        result: Ok(PolicyFacts {
            observation: observed.clone(),
            tenant_id: "tenant-exact".into(),
            owner_id: "owner-exact".into(),
            admission_allowed: true,
            key_policy: key,
            retained_history: history,
        }),
        calls: Mutex::new(Vec::new()),
    }
}
// The boundary has no KMS/device/boot participant and returns no launch capability.
// The counter also proves a caller gated on this result cannot continue on denial.
async fn deny(
    policy: Option<&dyn LaunchPolicy>,
    observed: &PolicyObservation,
    payload: PayloadPresence,
) {
    let mut downstream = 0;
    let result = authorize_launch_policy(policy, observed, payload).await;
    if result.is_ok() {
        downstream += 1;
    }
    assert_eq!(result, Err(PolicyDenied));
    assert_eq!(downstream, 0);
}

#[tokio::test]
async fn stripped_encrypted_create_denied() {
    let o = observation(LaunchKind::Create);
    let p = recording(&o, KeyPolicy::Active, RetainedHistory::Legacy);
    deny(Some(&p), &o, PayloadPresence::Absent).await;
    assert_eq!(*p.calls.lock().unwrap(), vec![o]);
}
#[tokio::test]
async fn retained_restore_and_reopen_deny_stripped_payload() {
    for kind in [LaunchKind::Restore, LaunchKind::Reopen] {
        let o = observation(kind);
        let p = recording(&o, KeyPolicy::NoKey, RetainedHistory::Encrypted);
        deny(Some(&p), &o, PayloadPresence::Absent).await;
        assert_eq!(*p.calls.lock().unwrap(), vec![o]);
    }
}
#[tokio::test]
async fn configuration_loss_never_selects_legacy() {
    for kind in [LaunchKind::Create, LaunchKind::Restore, LaunchKind::Reopen] {
        for payload in [
            PayloadPresence::Absent,
            PayloadPresence::Present,
            PayloadPresence::Invalid,
        ] {
            deny(None, &observation(kind.clone()), payload).await;
        }
    }
}
#[tokio::test]
async fn unknown_policy_and_history_deny() {
    let o = observation(LaunchKind::Create);
    for (key, history) in [
        (KeyPolicy::Unavailable, RetainedHistory::Legacy),
        (KeyPolicy::Active, RetainedHistory::Unknown),
        (KeyPolicy::NoKey, RetainedHistory::Unknown),
    ] {
        let p = recording(&o, key, history);
        for payload in [PayloadPresence::Absent, PayloadPresence::Present] {
            deny(Some(&p), &o, payload).await;
        }
    }
}
#[tokio::test]
async fn unknown_dispatch_or_inactive_authority_denied() {
    let o = observation(LaunchKind::Create);
    let mut p = recording(&o, KeyPolicy::NoKey, RetainedHistory::Legacy);
    p.result = Err(PolicyDenied);
    deny(Some(&p), &o, PayloadPresence::Absent).await;
    p.result = recording(&o, KeyPolicy::NoKey, RetainedHistory::Legacy).result;
    p.result.as_mut().unwrap().admission_allowed = false;
    deny(Some(&p), &o, PayloadPresence::Absent).await;
}
#[tokio::test]
async fn policy_response_must_match_exact_observation() {
    let o = observation(LaunchKind::Restore);
    for field in 0..6 {
        let mut p = recording(&o, KeyPolicy::NoKey, RetainedHistory::Legacy);
        let f = p.result.as_mut().unwrap();
        match field {
            0 => f.observation.dispatch_id = "other".into(),
            1 => f.observation.node_id = "other".into(),
            2 => f.observation.incarnation = "other".into(),
            3 => f.observation.kind = LaunchKind::Create,
            4 => f.tenant_id.clear(),
            _ => f.owner_id.clear(),
        }
        deny(Some(&p), &o, PayloadPresence::Absent).await;
    }
}
#[tokio::test]
async fn incomplete_observation_denied_before_lookup() {
    for field in 0..3 {
        let mut o = observation(LaunchKind::Create);
        match field {
            0 => o.dispatch_id.clear(),
            1 => o.node_id.clear(),
            _ => o.incarnation.clear(),
        }
        let p = recording(&o, KeyPolicy::NoKey, RetainedHistory::Legacy);
        deny(Some(&p), &o, PayloadPresence::Absent).await;
        assert!(p.calls.lock().unwrap().is_empty());
    }
}
#[tokio::test]
async fn invalid_payload_cannot_choose_plaintext() {
    let o = observation(LaunchKind::Create);
    let p = recording(&o, KeyPolicy::NoKey, RetainedHistory::Legacy);
    deny(Some(&p), &o, PayloadPresence::Invalid).await;
    assert!(p.calls.lock().unwrap().is_empty());
}
#[tokio::test]
async fn proven_legacy_is_the_only_omission_control() {
    for kind in [LaunchKind::Create, LaunchKind::Restore, LaunchKind::Reopen] {
        let o = observation(kind);
        let p = recording(&o, KeyPolicy::NoKey, RetainedHistory::Legacy);
        assert_eq!(
            authorize_launch_policy(Some(&p), &o, PayloadPresence::Absent).await,
            Ok(EncryptionRequirement::Legacy)
        );
        assert_eq!(*p.calls.lock().unwrap(), vec![o]);
    }
}
#[tokio::test]
async fn present_payload_never_downgrades_to_legacy() {
    let o = observation(LaunchKind::Create);
    for (key, history) in [
        (KeyPolicy::NoKey, RetainedHistory::Legacy),
        (KeyPolicy::Active, RetainedHistory::Legacy),
        (KeyPolicy::NoKey, RetainedHistory::Encrypted),
    ] {
        let p = recording(&o, key, history);
        assert_eq!(
            authorize_launch_policy(Some(&p), &o, PayloadPresence::Present).await,
            Ok(EncryptionRequirement::Required)
        );
    }
}
