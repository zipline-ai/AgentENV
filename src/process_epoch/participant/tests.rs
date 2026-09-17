use super::*;
use crate::process_epoch::{
    enrollment::{self},
    wire, Operation,
};
use ring::signature::Ed25519KeyPair;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
fn key(n: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[n; 32]).unwrap()
}
fn signed(
    kind: &str,
    body: Vec<u8>,
    mut e: wire::SignedEnvelope,
    pair: &Ed25519KeyPair,
) -> SignedRecord {
    wire::decode_canonical(kind, &body).unwrap();
    e.body_sha256 = enrollment::digest(&body);
    let envelope = serde_json::to_vec(&e).unwrap();
    let signature = pair
        .sign(&wire::signature_input(&envelope).unwrap())
        .as_ref()
        .to_vec();
    SignedRecord {
        body,
        envelope,
        signature,
    }
}
struct Recorder {
    sent: std::sync::Mutex<Vec<Vec<u8>>>,
    read: std::sync::Mutex<Vec<(uuid::Uuid, Vec<u8>)>>,
    blocked: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    posts: AtomicUsize,
    gets: AtomicUsize,
    response: std::sync::Mutex<Option<Vec<u8>>>,
}
#[async_trait::async_trait]
impl Channel for Recorder {
    async fn seal(&self, body: Vec<u8>) -> Result<Vec<u8>> {
        self.sent.lock().unwrap().push(body);
        self.entered.notify_one();
        self.posts.fetch_add(1, Ordering::SeqCst);
        if self.blocked.load(Ordering::SeqCst) {
            self.release.notified().await;
        }
        self.response
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("lost response"))
    }
    async fn lookup(&self, op: uuid::Uuid, body: Vec<u8>) -> Result<Vec<u8>> {
        self.read.lock().unwrap().push((op, body));
        self.gets.fetch_add(1, Ordering::SeqCst);
        self.response
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("unknown"))
    }
}
async fn fixture() -> (
    tempfile::TempDir,
    HostLedger,
    Participant,
    SignedRecord,
    Arc<Recorder>,
) {
    let (trust, docs, saved) = enrollment::tests::fixture();
    let verified = trust.verify(&docs, &saved.allocation, 0, 1).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ledger = HostLedger::initialize(dir.path().join("ledger"), saved.allocation.clone())
        .await
        .unwrap();
    ledger
        .claim(Operation {
            allocation: saved.allocation.clone(),
            epoch_id: saved.funded_session_id,
            operation_id: uuid::Uuid::new_v4(),
            request_sha256: "a".repeat(64),
        })
        .await
        .unwrap();
    let request = request_for(&saved, 500);
    let channel = Arc::new(Recorder {
        sent: std::sync::Mutex::new(Vec::new()),
        read: std::sync::Mutex::new(Vec::new()),
        blocked: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        posts: AtomicUsize::new(0),
        gets: AtomicUsize::new(0),
        response: std::sync::Mutex::new(None),
    });
    let participant = Participant::with_channel(
        ledger.clone(),
        verified,
        key(4),
        channel.clone(),
        Arc::new(|| 10),
    )
    .await
    .unwrap();
    (dir, ledger, participant, request, channel)
}
#[tokio::test]
async fn lost_dispatch_is_claimed_once_and_replay_never_posts_again() {
    let (_dir, ledger, p, request, channel) = fixture().await;
    let response = p.seal(request.clone()).await.unwrap();
    assert_eq!(
        channel.sent.lock().unwrap().as_slice(),
        &[serde_json::to_vec(&request).unwrap()]
    );
    let body: wire::LookupResponse = serde_json::from_slice(&response.node.body).unwrap();
    assert_eq!(body.state, "effect_unknown");
    assert!(body.evidence.is_none());
    assert_eq!(channel.posts.load(Ordering::SeqCst), 1);
    let rows = ledger.db.entries().await.unwrap();
    let repeated = p.seal(request).await.unwrap();
    assert_eq!(response, repeated);
    assert_eq!(rows, ledger.db.entries().await.unwrap());
    assert_eq!(channel.posts.load(Ordering::SeqCst), 1);
    assert_eq!(channel.gets.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn correctly_signed_foreign_request_has_zero_ledger_and_channel_effects() {
    let (_dir, ledger, p, request, channel) = fixture().await;
    let before = ledger.db.entries().await.unwrap();
    let mut body: wire::SealRequest = serde_json::from_slice(&request.body).unwrap();
    body.binding.tenant_id = "foreign".into();
    let mut e: wire::SignedEnvelope = serde_json::from_slice(&request.envelope).unwrap();
    let body = serde_json::to_vec(&body).unwrap();
    e.request_sha256 = enrollment::digest(&body);
    assert!(p
        .seal(signed("SealRequest", body, e, &key(3)))
        .await
        .is_err());
    assert_eq!(before, ledger.db.entries().await.unwrap());
    assert_eq!(channel.posts.load(Ordering::SeqCst), 0);
    assert_eq!(channel.gets.load(Ordering::SeqCst), 0);
}

fn guest_report(request: &SignedRecord) -> Vec<u8> {
    let original: wire::SealRequest = serde_json::from_slice(&request.body).unwrap();
    let mut e: wire::SignedEnvelope = serde_json::from_slice(&request.envelope).unwrap();
    let guest = wire::GuestReceipt {
        binding: original.binding.clone(),
        request_sha256: e.request_sha256.clone(),
        receipt_id: uuid::Uuid::new_v4().to_string(),
        evidence_class: "guest_reported".into(),
        outcome: "reported_complete".into(),
        guest_journal_revision: 8,
    };
    e.domain = "agentenv-process-epoch/guest-receipt/v1".into();
    e.signer = original.binding.guest_boot_id;
    e.key_id = "guest-key".into();
    serde_json::to_vec(&signed(
        "GuestReceipt",
        serde_json::to_vec(&guest).unwrap(),
        e,
        &key(5),
    ))
    .unwrap()
}
fn lookup_authority(request: &SignedRecord) -> SignedRecord {
    let original: wire::SealRequest = serde_json::from_slice(&request.body).unwrap();
    let mut e: wire::SignedEnvelope = serde_json::from_slice(&request.envelope).unwrap();
    let lookup = wire::LookupRequest {
        binding: original.binding,
        saved_request_sha256: e.request_sha256.clone(),
        nonce: "b".repeat(64),
    };
    e.domain = "agentenv-process-epoch/lookup/v1".into();
    e.nonce = lookup.nonce.clone();
    let body = serde_json::to_vec(&lookup).unwrap();
    e.request_sha256 = enrollment::digest(&body);
    signed("LookupRequest", body, e, &key(3))
}
#[tokio::test]
async fn guest_completion_is_mirrored_signed_and_never_promoted() {
    use ring::signature::KeyPair;
    let (_dir, ledger, p, request, channel) = fixture().await;
    let guest = guest_report(&request);
    *channel.response.lock().unwrap() = Some(guest.clone());
    let response = p.seal(request.clone()).await.unwrap();
    wire::verify_record(
        "LookupResponse",
        "agentenv-process-epoch/node-response/v1",
        &response.node.body,
        &response.node.envelope,
        key(4).public_key().as_ref(),
        &response.node.signature,
    )
    .unwrap();
    let body: wire::LookupResponse = serde_json::from_slice(&response.node.body).unwrap();
    assert_eq!(body.state, "incomplete");
    assert_eq!(body.evidence.unwrap().evidence_class, "guest_reported");
    let op = p
        .inner
        .verifier
        .seal(&request.body, &request.envelope, &request.signature, 10)
        .unwrap()
        .operation()
        .clone();
    let receipt = ledger.lookup(&op).await.unwrap().unwrap();
    assert_eq!(
        receipt.evidence_class,
        Some(crate::process_epoch::EvidenceClass::GuestReported)
    );
    assert!(!receipt.proves_cessation());
    let before = ledger.db.entries().await.unwrap();
    let authority = lookup_authority(&request);
    let lookup = p.lookup(authority).await.unwrap();
    let e: wire::SignedEnvelope = serde_json::from_slice(&lookup.node.envelope).unwrap();
    assert_eq!(e.nonce, "b".repeat(64));
    assert_eq!(before, ledger.db.entries().await.unwrap());
    assert_eq!(channel.posts.load(Ordering::SeqCst), 1);
    assert_eq!(channel.gets.load(Ordering::SeqCst), 0);
    assert!(
        p.mirror(&op, &guest_report(&request)).await.is_err(),
        "changed first receipt must conflict"
    );
    assert_eq!(before, ledger.db.entries().await.unwrap());
}
#[tokio::test]
async fn recovery_get_uses_original_operation_and_signed_lookup_without_posting_again() {
    let (_dir, ledger, p, request, channel) = fixture().await;
    p.seal(request.clone()).await.unwrap();
    *channel.response.lock().unwrap() = Some(guest_report(&request));
    let authority = lookup_authority(&request);
    let body: wire::LookupRequest = serde_json::from_slice(&authority.body).unwrap();
    let response = p.lookup(authority.clone()).await.unwrap();
    let response: wire::LookupResponse = serde_json::from_slice(&response.node.body).unwrap();
    assert_eq!(response.evidence.unwrap().evidence_class, "guest_reported");
    assert_eq!(channel.posts.load(Ordering::SeqCst), 1);
    assert_eq!(
        channel.read.lock().unwrap().as_slice(),
        &[(
            body.binding.operation_id.parse().unwrap(),
            serde_json::to_vec(&authority).unwrap()
        )]
    );
    let before = ledger.db.entries().await.unwrap();
    let mut wrong = body;
    wrong.binding.sandbox_family = "native".into();
    let mut e: wire::SignedEnvelope = serde_json::from_slice(&authority.envelope).unwrap();
    let body = serde_json::to_vec(&wrong).unwrap();
    e.request_sha256 = enrollment::digest(&body);
    assert!(p
        .lookup(signed("LookupRequest", body, e, &key(3)))
        .await
        .is_err());
    assert_eq!(before, ledger.db.entries().await.unwrap());
    assert_eq!(channel.gets.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn caller_cancellation_after_claim_does_not_cancel_mirroring() {
    let (_dir, ledger, p, request, channel) = fixture().await;
    *channel.response.lock().unwrap() = Some(guest_report(&request));
    channel.blocked.store(true, Ordering::SeqCst);
    let task = {
        let p = p.clone();
        let r = request.clone();
        tokio::spawn(async move { p.seal(r).await })
    };
    channel.entered.notified().await;
    assert!(ledger.enrollment().await.unwrap().closed);
    task.abort();
    let _ = task.await;
    channel.release.notify_one();
    let op = p
        .inner
        .verifier
        .seal(&request.body, &request.envelope, &request.signature, 10)
        .unwrap()
        .operation()
        .clone();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if ledger
                .lookup(&op)
                .await
                .unwrap()
                .unwrap()
                .evidence_class
                .is_some()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(channel.posts.load(Ordering::SeqCst), 1);
    p.seal(request).await.unwrap();
    assert_eq!(channel.posts.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn revoke_first_denies_and_claim_first_retains_obligations_without_disclosure() {
    let (_dir, ledger, p, request, channel) = fixture().await;
    p.revoke().await.unwrap();
    let before = ledger.db.entries().await.unwrap();
    assert!(p.seal(request).await.is_err());
    assert_eq!(before, ledger.db.entries().await.unwrap());
    assert_eq!(channel.posts.load(Ordering::SeqCst), 0);
    let (_dir, ledger, p, request, channel) = fixture().await;
    *channel.response.lock().unwrap() = Some(guest_report(&request));
    channel.blocked.store(true, Ordering::SeqCst);
    let task = {
        let p = p.clone();
        let r = request.clone();
        tokio::spawn(async move { p.seal(r).await })
    };
    channel.entered.notified().await;
    p.revoke().await.unwrap();
    channel.release.notify_one();
    assert!(task.await.unwrap().is_err());
    let op = p
        .inner
        .verifier
        .seal(&request.body, &request.envelope, &request.signature, 10)
        .unwrap()
        .operation()
        .clone();
    assert!(!ledger
        .lookup(&op)
        .await
        .unwrap()
        .unwrap()
        .proves_cessation());
    assert_eq!(channel.posts.load(Ordering::SeqCst), 1);
    assert!(p.lookup(lookup_authority(&request)).await.is_err());
    assert_eq!(channel.gets.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn missing_host_anchor_denies_before_any_dispatch_or_write() {
    let (_dir, ledger, p, request, channel) = fixture().await;
    ledger
        .db
        .delete(b"provider_binding".to_vec())
        .await
        .unwrap();
    let before = ledger.db.entries().await.unwrap();
    assert!(p.seal(request).await.is_err());
    assert_eq!(before, ledger.db.entries().await.unwrap());
    assert_eq!(channel.posts.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn signed_replies_use_the_durable_claim_and_mirror_revision() {
    let (_dir, ledger, p, request, channel) = fixture().await;
    let response = p.seal(request.clone()).await.unwrap();
    let response: wire::LookupResponse = serde_json::from_slice(&response.node.body).unwrap();
    assert_eq!(response.node_ledger_revision, 2);
    let raw = ledger
        .db
        .get(b"provider_revision".to_vec())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::from_slice::<u64>(&raw).unwrap(), 2);
    *channel.response.lock().unwrap() = Some(guest_report(&request));
    let response = p.lookup(lookup_authority(&request)).await.unwrap();
    let response: wire::LookupResponse = serde_json::from_slice(&response.node.body).unwrap();
    assert_eq!(response.node_ledger_revision, 3);
    let raw = ledger
        .db
        .get(b"provider_revision".to_vec())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::from_slice::<u64>(&raw).unwrap(), 3);
}

#[tokio::test]
async fn node_response_returns_the_immutable_backing_guest_signature() {
    let (_dir, _ledger, p, request, channel) = fixture().await;
    let guest = guest_report(&request);
    *channel.response.lock().unwrap() = Some(guest.clone());
    let response = p.seal(request).await.unwrap();
    let json = serde_json::to_value(&response).unwrap();
    let backing: SignedRecord = serde_json::from_value(
        json.get("guest")
            .cloned()
            .expect("backing guest signature must be available"),
    )
    .unwrap();
    assert_eq!(serde_json::to_vec(&backing).unwrap(), guest);
    let body: wire::LookupResponse = serde_json::from_slice(&response.node.body).unwrap();
    assert_eq!(
        body.evidence.unwrap().evidence_sha256,
        enrollment::digest(&guest)
    );
}
#[tokio::test]
async fn corrupted_mirror_never_gets_a_fresh_node_signature() {
    let (_dir, ledger, p, request, channel) = fixture().await;
    *channel.response.lock().unwrap() = Some(guest_report(&request));
    p.seal(request.clone()).await.unwrap();
    let op = p
        .inner
        .verifier
        .seal(&request.body, &request.envelope, &request.signature, 10)
        .unwrap()
        .operation()
        .clone();
    ledger
        .db
        .put(super::mirror_key(&op), b"corrupt".to_vec())
        .await
        .unwrap();
    let rows = ledger.db.entries().await.unwrap();
    assert!(p.lookup(lookup_authority(&request)).await.is_err());
    assert_eq!(rows, ledger.db.entries().await.unwrap());
    assert_eq!(channel.gets.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn fresh_lookup_recovers_expired_historical_guest_receipt_without_redispatch() {
    let (_dir, ledger, mut p, request, channel) = fixture().await;
    p.seal(request.clone()).await.unwrap();
    *channel.response.lock().unwrap() = Some(guest_report(&request));
    Arc::get_mut(&mut p.inner).unwrap().clock = Arc::new(|| 600);
    let mut authority = lookup_authority(&request);
    let mut e: wire::SignedEnvelope = serde_json::from_slice(&authority.envelope).unwrap();
    e.expires_at_unix_ms = 900;
    authority = signed("LookupRequest", authority.body, e, &key(3));
    let result = p.lookup(authority).await.unwrap();
    let body: wire::LookupResponse = serde_json::from_slice(&result.node.body).unwrap();
    assert_eq!(body.state, "incomplete");
    assert_eq!(body.evidence.unwrap().evidence_class, "guest_reported");
    assert_eq!(channel.posts.load(Ordering::SeqCst), 1);
    assert_eq!(channel.gets.load(Ordering::SeqCst), 1);
    assert!(ledger.enrollment().await.unwrap().closed);
}

#[tokio::test]
async fn lookup_expiring_while_waiting_for_history_makes_zero_guest_calls() {
    use std::sync::atomic::AtomicU64;
    let (_dir, ledger, mut p, request, channel) = fixture().await;
    p.seal(request.clone()).await.unwrap();
    let clock = Arc::new(AtomicU64::new(10));
    let observed = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let c = clock.clone();
    let n = observed.clone();
    Arc::get_mut(&mut p.inner).unwrap().clock = Arc::new(move || {
        let now = c.load(Ordering::SeqCst);
        if calls.fetch_add(1, Ordering::SeqCst) == 1 {
            n.notify_one();
        }
        now
    });
    let guard = ledger.serial.lock().await;
    let task = tokio::spawn(async move { p.lookup(lookup_authority(&request)).await });
    observed.notified().await;
    clock.store(600, Ordering::SeqCst);
    drop(guard);
    assert!(task.await.unwrap().is_err());
    assert_eq!(channel.gets.load(Ordering::SeqCst), 0);
    assert_eq!(channel.posts.load(Ordering::SeqCst), 1);
}

fn request_for(saved: &enrollment::HostEnrollment, deadline: u64) -> SignedRecord {
    let d = &saved.descriptor;
    let binding = wire::EpochBinding {
        protocol: super::super::PROTOCOL.into(),
        tenant_id: saved.allocation.tenant_id.clone(),
        sandbox_family: saved.sandbox_family.clone(),
        sandbox_id: saved.allocation.sandbox_id.clone(),
        transition_id: uuid::Uuid::new_v4().to_string(),
        launch_id: Some(uuid::Uuid::new_v4().to_string()),
        operation_id: uuid::Uuid::new_v4().to_string(),
        reserved_session_id: uuid::Uuid::new_v4().to_string(),
        descriptor_sha256: enrollment::digest(&serde_json::to_vec(d).unwrap()),
        node_id: d.node_id.clone(),
        node_incarnation: d.node_incarnation.clone(),
        runtime_id: d.runtime_id.clone(),
        runtime_incarnation: d.runtime_incarnation.clone(),
        guest_boot_id: d.guest_boot_id.clone(),
        enrollment_revision: d.enrollment_revision,
        process_endpoint: d.process_endpoint.clone(),
        guest_build_sha256: d.guest_build_sha256.clone(),
        capabilities_sha256: d.capabilities_sha256.clone(),
    };
    let request = wire::SealRequest {
        binding: binding.clone(),
        expected_session_id: saved.funded_session_id.to_string(),
        retirement_authority_id: None,
        retirement_authority_sha256: None,
    };
    let body = serde_json::to_vec(&request).unwrap();
    let envelope = wire::SignedEnvelope {
        protocol: super::super::PROTOCOL.into(),
        domain: "agentenv-process-epoch/seal/v1".into(),
        signer: saved.allocation.controller.clone(),
        key_id: saved.controller_key_id.clone(),
        trust_revision: saved.trust_revision,
        audience: saved.audience.clone(),
        node_id: d.node_id.clone(),
        node_incarnation: d.node_incarnation.clone(),
        runtime_id: d.runtime_id.clone(),
        runtime_incarnation: d.runtime_incarnation.clone(),
        enrollment_revision: d.enrollment_revision,
        descriptor_sha256: binding.descriptor_sha256.clone(),
        request_sha256: enrollment::digest(&body),
        nonce: "a".repeat(64),
        expires_at_unix_ms: deadline,
        body_sha256: enrollment::digest(&body),
    };
    signed("SealRequest", body, envelope, &key(3))
}

fn certify(saved: &enrollment::HostEnrollment, docs: &mut enrollment::EnrollmentDocuments) {
    docs.enrollment = serde_json::to_vec(saved).unwrap();
    let mut bytes = b"agentenv-process-epoch/host-enrollment/v1\0".to_vec();
    bytes.extend_from_slice(&docs.enrollment);
    docs.enrollment_signature = key(1).sign(&bytes).as_ref().to_vec();
}
#[tokio::test]
async fn closed_restart_requires_fresh_attestation_and_preserves_original_mirror() {
    let (dir, ledger, p, request, channel) = fixture().await;
    let mut saved = p.inner.saved.clone();
    *channel.response.lock().unwrap() = Some(guest_report(&request));
    let first = p.seal(request.clone()).await.unwrap();
    let initial_rows = ledger.db.entries().await.unwrap();
    let (trust, mut docs, _) = enrollment::tests::fixture();
    certify(&saved, &mut docs);
    let old = trust.verify(&docs, &saved.allocation, 0, 1).unwrap();
    drop(p);
    drop(ledger);
    let ledger = HostLedger::reopen(dir.path().join("ledger"), saved.allocation.clone())
        .await
        .unwrap();
    let rows = ledger.db.entries().await.unwrap();
    assert!(Participant::with_channel(
        ledger.clone(),
        old,
        key(4),
        channel.clone(),
        Arc::new(|| 10)
    )
    .await
    .is_err());
    assert_eq!(rows, ledger.db.entries().await.unwrap());
    saved.recovery_revision = ledger.enrollment().await.unwrap().recovery_revision;
    certify(&saved, &mut docs);
    let verified = trust
        .verify(&docs, &saved.allocation, saved.recovery_revision, 1)
        .unwrap();
    let p = Participant::with_channel(
        ledger.clone(),
        verified,
        key(4),
        channel.clone(),
        Arc::new(|| 10),
    )
    .await
    .unwrap();
    let response = p.lookup(lookup_authority(&request)).await.unwrap();
    assert_eq!(response.guest, first.guest);
    let body: wire::LookupResponse = serde_json::from_slice(&response.node.body).unwrap();
    assert_eq!(body.node_ledger_revision, 4);
    assert!(ledger.enrollment().await.unwrap().closed);
    let keep = |rows: Vec<(Vec<u8>, Vec<u8>)>| {
        rows.into_iter()
            .filter(|(k, _)| k != b"enrollment" && k != b"provider_revision")
            .collect::<Vec<_>>()
    };
    assert_eq!(keep(initial_rows), keep(ledger.db.entries().await.unwrap()));
    assert_eq!(channel.posts.load(Ordering::SeqCst), 1);
    assert_eq!(channel.gets.load(Ordering::SeqCst), 0);
    p.seal(request).await.unwrap();
    assert_eq!(channel.posts.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn production_factory_dispatches_exact_signed_bytes_over_mutual_tls_once() {
    use ring::signature::KeyPair;
    let peer = crate::process_epoch::transport::tests::peer(false).await;
    let (trust, mut docs, mut saved) = enrollment::tests::fixture();
    saved.descriptor.process_endpoint = peer.endpoint.clone();
    saved.guest_certificate_sha256 = super::certificate_digest(peer.cert.as_bytes()).unwrap();
    saved.host_certificate_sha256 = super::certificate_digest(peer.identity.as_bytes()).unwrap();
    saved.valid_until_unix_ms = super::now() + 60000;
    let private = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let node_key = Ed25519KeyPair::from_pkcs8(private.as_ref()).unwrap();
    saved.node_public_key = node_key.public_key().as_ref().to_vec();
    certify(&saved, &mut docs);
    let verified = trust
        .verify(&docs, &saved.allocation, 0, super::now())
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ledger = HostLedger::initialize(dir.path().join("ledger"), saved.allocation.clone())
        .await
        .unwrap();
    ledger
        .claim(Operation {
            allocation: saved.allocation.clone(),
            epoch_id: saved.funded_session_id,
            operation_id: uuid::Uuid::new_v4(),
            request_sha256: "a".repeat(64),
        })
        .await
        .unwrap();
    let p = Participant::new(
        ledger.clone(),
        verified,
        private.as_ref(),
        peer.cert.as_bytes(),
        peer.identity.as_bytes(),
        std::time::Duration::from_secs(2),
    )
    .await
    .unwrap();
    let request = request_for(&saved, super::now() + 30000);
    let response = p.seal(request.clone()).await.unwrap();
    wire::verify_record(
        "LookupResponse",
        "agentenv-process-epoch/node-response/v1",
        &response.node.body,
        &response.node.envelope,
        node_key.public_key().as_ref(),
        &response.node.signature,
    )
    .unwrap();
    let body: wire::LookupResponse = serde_json::from_slice(&response.node.body).unwrap();
    assert_eq!(body.state, "effect_unknown");
    assert!(body.evidence.is_none());
    assert!(response.guest.is_none());
    let rows = ledger.db.entries().await.unwrap();
    p.seal(request.clone()).await.unwrap();
    assert_eq!(rows, ledger.db.entries().await.unwrap());
    let recorded = peer.observed.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].1, "POST /process-epochs/seal HTTP/1.1");
    assert_eq!(recorded[0].2, serde_json::to_vec(&request).unwrap());
}

#[tokio::test]
async fn missing_mirror_is_not_healed_from_a_new_guest_report() {
    let (_dir, ledger, p, request, channel) = fixture().await;
    *channel.response.lock().unwrap() = Some(guest_report(&request));
    p.seal(request.clone()).await.unwrap();
    let op = p
        .inner
        .verifier
        .seal(&request.body, &request.envelope, &request.signature, 10)
        .unwrap()
        .operation()
        .clone();
    ledger.db.delete(super::mirror_key(&op)).await.unwrap();
    let before = ledger.db.entries().await.unwrap();
    let changed = guest_report(&request);
    *channel.response.lock().unwrap() = Some(changed.clone());
    assert!(p.lookup(lookup_authority(&request)).await.is_err());
    assert_eq!(channel.gets.load(Ordering::SeqCst), 0);
    assert_eq!(before, ledger.db.entries().await.unwrap());
    assert!(p.mirror(&op, &changed).await.is_err());
    assert_eq!(before, ledger.db.entries().await.unwrap());
}
#[tokio::test]
async fn lost_provider_anchor_never_becomes_first_initialization_again() {
    for delete_revision in [false, true] {
        let (_dir, ledger, p, _request, channel) = fixture().await;
        let saved = p.inner.saved.clone();
        let (trust, mut docs, _) = enrollment::tests::fixture();
        certify(&saved, &mut docs);
        ledger
            .db
            .delete(b"provider_binding".to_vec())
            .await
            .unwrap();
        if delete_revision {
            ledger
                .db
                .delete(b"provider_revision".to_vec())
                .await
                .unwrap();
        }
        let before = ledger.db.entries().await.unwrap();
        let verified = trust.verify(&docs, &saved.allocation, 0, 1).unwrap();
        assert!(Participant::with_channel(
            ledger.clone(),
            verified,
            key(4),
            channel.clone(),
            Arc::new(|| 10)
        )
        .await
        .is_err());
        assert_eq!(before, ledger.db.entries().await.unwrap());
        assert_eq!(channel.posts.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn reconciliation_between_verification_and_claim_denies_old_enrollment() {
    let (_dir, ledger, mut p, request, channel) = fixture().await;
    let observed = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let n = observed.clone();
    Arc::get_mut(&mut p.inner).unwrap().clock = Arc::new(move || {
        if calls.fetch_add(1, Ordering::SeqCst) == 1 {
            n.notify_one();
        }
        10
    });
    let guard = ledger.serial.lock().await;
    let task = tokio::spawn(async move { p.seal(request).await });
    observed.notified().await;
    // Model a completed reconciliation under the same host exclusion.
    let mut state = ledger.enrollment().await.unwrap();
    state.recovery_revision += 1;
    ledger
        .db
        .put(b"enrollment".to_vec(), serde_json::to_vec(&state).unwrap())
        .await
        .unwrap();
    let before = ledger.db.entries().await.unwrap();
    drop(guard);
    assert!(task.await.unwrap().is_err());
    assert_eq!(channel.posts.load(Ordering::SeqCst), 0);
    assert_eq!(before, ledger.db.entries().await.unwrap());
}
