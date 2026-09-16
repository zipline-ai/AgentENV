use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
fn key(n: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[n; 32]).unwrap()
}
fn sign(domain: &str, body: &[u8], pair: &Ed25519KeyPair) -> Vec<u8> {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(body);
    pair.sign(&bytes).as_ref().to_vec()
}
pub(crate) fn fixture() -> (HostTrust, EnrollmentDocuments, HostEnrollment) {
    let v: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("testdata/process-epoch-vectors/v1/Descriptor.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut descriptor: wire::Descriptor =
        serde_json::from_slice(&hex::decode(v["canonical_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    let manifest = ReleaseManifest {
        envd_commit: "a".repeat(40),
        ordered_patch_sha256: vec!["b".repeat(64)],
        protocol_sha256: digest(include_bytes!(
            "../../../testdata/process-epoch-vectors/v1/schema.json"
        )),
        binary_sha256: descriptor.guest_build_sha256.clone(),
        tools_image_sha256: "d".repeat(64),
    };
    descriptor.capabilities_sha256 = manifest.protocol_sha256.clone();
    let manifest = serde_json::to_vec(&manifest).unwrap();
    let saved = HostEnrollment {
        allocation: Allocation {
            controller: "controller".into(),
            tenant_id: "tenant".into(),
            sandbox_id: "sandbox".into(),
            runtime_id: descriptor.runtime_id.parse().unwrap(),
            runtime_incarnation: descriptor.runtime_incarnation.parse().unwrap(),
            enrollment_revision: descriptor.enrollment_revision,
        },
        sandbox_family: "legacy".into(),
        descriptor,
        funded_session_id: uuid::Uuid::new_v4(),
        recovery_revision: 0,
        trust_revision: 3,
        valid_until_unix_ms: 1000,
        manifest_sha256: digest(&manifest),
        mapped_tools_sha256: "d".repeat(64),
        controller_key_id: "controller-key".into(),
        node_key_id: "node-key".into(),
        node_public_key: key(4).public_key().as_ref().to_vec(),
        guest_key_id: "guest-key".into(),
        guest_public_key: key(5).public_key().as_ref().to_vec(),
        guest_certificate_sha256: "e".repeat(64),
        host_certificate_sha256: "f".repeat(64),
        audience: "node".into(),
    };
    let enrollment = serde_json::to_vec(&saved).unwrap();
    let trust = HostTrust {
        provider_root: key(1).public_key().as_ref().try_into().unwrap(),
        release_root: key(2).public_key().as_ref().try_into().unwrap(),
        controller_root: key(3).public_key().as_ref().try_into().unwrap(),
        controller_key_id: "controller-key".into(),
        trust_revision: 3,
        approved_manifest_sha256: digest(&manifest),
    };
    let docs = EnrollmentDocuments {
        enrollment_signature: sign(
            "agentenv-process-epoch/host-enrollment/v1",
            &enrollment,
            &key(1),
        ),
        enrollment,
        manifest_signature: sign(
            "agentenv-process-epoch/release-manifest/v1",
            &manifest,
            &key(2),
        ),
        manifest,
    };
    (trust, docs, saved)
}
#[test]
fn authenticated_enrollment_accepts_only_exact_current_host_attestation() {
    let (trust, docs, saved) = fixture();
    let verified = trust.verify(&docs, &saved.allocation, 0, 1).unwrap();
    assert_eq!(verified.saved, saved);
    assert_eq!(verified.controller_key, trust.controller_root);
    for revision in [1, 2] {
        assert!(trust.verify(&docs, &saved.allocation, revision, 1).is_err());
    }
    assert!(trust.verify(&docs, &saved.allocation, 0, 1000).is_err());
    let mut foreign = saved.allocation.clone();
    foreign.tenant_id = "foreign".into();
    assert!(trust.verify(&docs, &foreign, 0, 1).is_err());
}
#[test]
fn correctly_signed_wrong_mapping_build_and_trust_cannot_enroll() {
    let (trust, mut docs, saved) = fixture();
    for field in [
        "mapped_tools_sha256",
        "manifest_sha256",
        "controller_key_id",
        "trust_revision",
        "funded_session_id",
    ] {
        let mut value = serde_json::to_value(&saved).unwrap();
        value[field] = match field {
            "trust_revision" => 2.into(),
            "funded_session_id" => uuid::Uuid::nil().to_string().into(),
            _ => "wrong".into(),
        };
        let changed: HostEnrollment = serde_json::from_value(value).unwrap();
        docs.enrollment = serde_json::to_vec(&changed).unwrap();
        docs.enrollment_signature = sign(
            "agentenv-process-epoch/host-enrollment/v1",
            &docs.enrollment,
            &key(1),
        );
        assert!(
            trust.verify(&docs, &saved.allocation, 0, 1).is_err(),
            "{field}"
        );
    }
    let (_, mut docs, _) = fixture();
    docs.enrollment_signature = sign(
        "agentenv-process-epoch/host-enrollment/v1",
        &docs.enrollment,
        &key(3),
    );
    assert!(trust.verify(&docs, &saved.allocation, 0, 1).is_err());
}
