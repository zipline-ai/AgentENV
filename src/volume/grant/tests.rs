use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use std::sync::Mutex;

fn clock() -> DateTime<Utc> {
    "2026-09-16T12:01:00Z".parse().unwrap()
}
fn fixture() -> (
    UntrustedVolumeEncryption,
    AuthenticatedGrantBinding,
    TrustedGrantKeys,
    EcdsaKeyPair,
) {
    let rng = SystemRandom::new();
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, doc.as_ref(), &rng).unwrap();
    let keys = TrustedGrantKeys::from_sec1(vec![key.public_key().as_ref().to_vec()]).unwrap();
    let p = GrantPayload {
        v: 6,
        grant_id: "grant-exact".into(),
        tenant_id: "tenant-exact".into(),
        owner_user_id: "owner-exact".into(),
        sandbox_family: "legacy".into(),
        launch_kind: "create".into(),
        creation_id: "creation-exact".into(),
        restore_launch_id: String::new(),
        reserved_session_id: String::new(),
        mode: "required".into(),
        volume_id: "vol-exact".into(),
        volume_kind: "sandbox_rootfs".into(),
        drive_id: String::new(),
        live_sandbox_id: String::new(),
        generation: 0,
        origin: GrantOrigin {
            kind: "template".into(),
            snapshot_id: String::new(),
            snapshot_alias: String::new(),
            record_digest: String::new(),
            template_id: "template-exact".into(),
        },
        template_lineage_root: "a".repeat(64),
        request_sha256: "b".repeat(64),
        destination_node_id: "node-exact".into(),
        kms_key: "key-exact".into(),
        kms_key_version: "version-exact".into(),
        kms_aad: "vol:tenant-exact:vol-exact:sandbox_rootfs".into(),
        wrapped_dek_sha256: hex::encode(Sha256::digest(b"wrapped")),
        issued_at: "2026-09-16T12:00:00Z".into(),
        expires_at: "2026-09-16T12:15:00Z".into(),
    };
    let wire = UntrustedVolumeEncryption {
        volume_id: p.volume_id.clone(),
        volume_kind: p.volume_kind.clone(),
        drive_id: None,
        grant: String::new(),
        signature: String::new(),
        wrapped_dek: STANDARD.encode(b"wrapped"),
        kms_key: p.kms_key.clone(),
        kms_key_version: p.kms_key_version.clone(),
        kms_aad: p.kms_aad.clone(),
        cipher: "aes-xts-plain64".into(),
        sector_size: 4096,
    };
    let binding = AuthenticatedGrantBinding {
        expected: p,
        node_id: "node-exact".into(),
        incarnation: "boot-exact".into(),
    };
    let mut wire = wire;
    sign(&mut wire, &binding.expected, &key);
    (wire, binding, keys, key)
}
fn sign(wire: &mut UntrustedVolumeEncryption, p: &GrantPayload, key: &EcdsaKeyPair) {
    let bytes = serde_json::to_vec(p).unwrap();
    wire.signature = STANDARD.encode(key.sign(&SystemRandom::new(), &bytes).unwrap().as_ref());
    wire.grant = STANDARD.encode(bytes);
}
struct RecordingConsumer {
    expected: ConsumeRequest,
    calls: Mutex<Vec<ConsumeRequest>>,
    used: Mutex<bool>,
    reply: ConsumeReply,
    fail: bool,
}
#[async_trait]
impl GrantConsumer for RecordingConsumer {
    async fn consume(&self, r: ConsumeRequest) -> Result<ConsumeReply, GrantDenied> {
        assert_eq!(r, self.expected);
        self.calls.lock().unwrap().push(r);
        let mut used = self.used.lock().unwrap();
        if *used || self.fail {
            return Err(GrantDenied);
        }
        *used = true;
        Ok(self.reply.clone())
    }
}
fn consumer(wire: &UntrustedVolumeEncryption) -> RecordingConsumer {
    RecordingConsumer {
        expected: ConsumeRequest {
            grant_id: "grant-exact".into(),
            payload_sha256: hex::encode(Sha256::digest(STANDARD.decode(&wire.grant).unwrap())),
            node_id: "node-exact".into(),
            incarnation: "boot-exact".into(),
        },
        calls: Mutex::new(vec![]),
        used: Mutex::new(false),
        reply: ConsumeReply {
            state: "consumed".into(),
            tenant_id: "tenant-exact".into(),
            volume_id: "vol-exact".into(),
        },
        fail: false,
    }
}
#[tokio::test]
async fn signed_exact_grant_consumes_once_by_captured_identity() {
    let (w, b, k, _) = fixture();
    let c = consumer(&w);
    let verified = verify_grant(&w, &b, &k, clock()).unwrap();
    let evidence = consume_verified_grant(verified, &c, clock()).await.unwrap();
    assert_eq!(evidence.grant_id(), "grant-exact");
    let replay = verify_grant(&w, &b, &k, clock()).unwrap();
    assert!(consume_verified_grant(replay, &c, clock()).await.is_err());
    assert_eq!(c.calls.lock().unwrap().len(), 2);
}
#[test]
fn signature_context_tamper_and_wrong_key_deny() {
    let (mut w, mut b, k, _) = fixture();
    b.expected.tenant_id = "foreign".into();
    assert!(verify_grant(&w, &b, &k, clock()).is_err());
    b.expected.tenant_id = "tenant-exact".into();
    b.node_id = "wrong-node".into();
    assert!(verify_grant(&w, &b, &k, clock()).is_err());
    b.node_id = "node-exact".into();
    w.wrapped_dek = STANDARD.encode(b"different");
    assert!(verify_grant(&w, &b, &k, clock()).is_err());
    let (mut w, b, k, _) = fixture();
    w.signature = STANDARD.encode([0; 70]);
    assert!(verify_grant(&w, &b, &k, clock()).is_err());
    let (w, b, _, _) = fixture();
    let (_, _, other, _) = fixture();
    assert!(verify_grant(&w, &b, &other, clock()).is_err());
}
#[test]
fn signed_expiry_future_issue_invalid_arms_and_version_deny() {
    for variant in 0..7 {
        let (mut w, mut b, k, key) = fixture();
        match variant {
            0 => b.expected.expires_at = "2026-09-16T12:01:00Z".into(),
            1 => b.expected.issued_at = "2026-09-16T12:02:00Z".into(),
            2 => b.expected.expires_at = "2026-09-16T12:16:00Z".into(),
            3 => b.expected.v = 5,
            4 => b.expected.launch_kind = "creds_attach".into(),
            5 => b.expected.restore_launch_id = "foreign-arm".into(),
            _ => b.expected.sandbox_family = "native".into(),
        }
        sign(&mut w, &b.expected, &key);
        assert!(verify_grant(&w, &b, &k, clock()).is_err());
    }
}
#[tokio::test]
async fn expiry_between_verify_and_consume_calls_nothing() {
    let (w, b, k, _) = fixture();
    let c = consumer(&w);
    let v = verify_grant(&w, &b, &k, clock()).unwrap();
    assert!(
        consume_verified_grant(v, &c, "2026-09-16T12:15:00Z".parse().unwrap())
            .await
            .is_err()
    );
    assert!(c.calls.lock().unwrap().is_empty());
}
#[tokio::test]
async fn consume_ambiguity_and_wrong_reply_never_return_evidence_or_retry() {
    for variant in 0..4 {
        let (w, b, k, _) = fixture();
        let mut c = consumer(&w);
        match variant {
            0 => c.fail = true,
            1 => c.reply.tenant_id = "foreign".into(),
            2 => c.reply.volume_id = "foreign".into(),
            _ => c.reply.state = "issued".into(),
        }
        let v = verify_grant(&w, &b, &k, clock()).unwrap();
        assert!(consume_verified_grant(v, &c, clock()).await.is_err());
        assert_eq!(c.calls.lock().unwrap().len(), 1);
    }
}
#[tokio::test]
async fn concurrent_claims_only_return_one_consumption() {
    let (w, b, k, _) = fixture();
    let c = consumer(&w);
    let (a, z) = tokio::join!(
        consume_verified_grant(verify_grant(&w, &b, &k, clock()).unwrap(), &c, clock()),
        consume_verified_grant(verify_grant(&w, &b, &k, clock()).unwrap(), &c, clock())
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(z.is_ok()), 1);
    assert_eq!(c.calls.lock().unwrap().len(), 2);
}
