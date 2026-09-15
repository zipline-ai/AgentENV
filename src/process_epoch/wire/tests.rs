use super::*;
use sha2::{Digest, Sha256};
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn fixture(name: &str) -> Value {
    serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("testdata/process-epoch-vectors/v1")
                .join(name),
        )
        .unwrap(),
    )
    .unwrap()
}
#[test]
fn canonical_vectors_and_ed25519_match_go() {
    let manifest = fixture("manifest.json");
    for name in manifest["positive"].as_array().unwrap() {
        let v = fixture(name.as_str().unwrap());
        let body = unhex(v["canonical_hex"].as_str().unwrap());
        decode_canonical(v["kind"].as_str().unwrap(), &body).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&body)),
            v["sha256"].as_str().unwrap()
        );
        let envelope = unhex(v["envelope_hex"].as_str().unwrap());
        let input = signature_input(&envelope).unwrap();
        assert_eq!(input, unhex(v["signature_input_hex"].as_str().unwrap()));
        let key = unhex(v["public_key_hex"].as_str().unwrap());
        let signature = unhex(v["signature_hex"].as_str().unwrap());
        verify_signature(&envelope, &key, &signature).unwrap();
        let e: SignedEnvelope = serde_json::from_slice(&envelope).unwrap();
        verify_record(
            v["kind"].as_str().unwrap(),
            &e.domain,
            &body,
            &envelope,
            &key,
            &signature,
        )
        .unwrap();
        assert!(verify_record(
            v["kind"].as_str().unwrap(),
            "wrong-domain",
            &body,
            &envelope,
            &key,
            &signature
        )
        .is_err());
        let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&unhex(
            manifest["test_only_ed25519_seed_hex"].as_str().unwrap(),
        ))
        .unwrap();
        assert_eq!(pair.sign(&input).as_ref(), signature);
        let mut changed: SignedEnvelope = serde_json::from_slice(&envelope).unwrap();
        changed.domain = if changed.domain.ends_with("/lookup/v1") {
            "agentenv-process-epoch/seal/v1"
        } else {
            "agentenv-process-epoch/lookup/v1"
        }
        .into();
        assert!(
            verify_signature(&serde_json::to_vec(&changed).unwrap(), &key, &signature).is_err()
        );
        changed = serde_json::from_slice(&envelope).unwrap();
        changed.enrollment_revision += 1;
        assert!(
            verify_signature(&serde_json::to_vec(&changed).unwrap(), &key, &signature).is_err()
        );
        let mut bad_signature = signature.clone();
        bad_signature[0] ^= 1;
        assert!(verify_signature(&envelope, &key, &bad_signature).is_err());
    }
}
#[test]
fn negative_vectors_are_never_repaired() {
    for v in fixture("negative.json").as_array().unwrap() {
        assert!(
            decode_canonical(
                v["kind"].as_str().unwrap(),
                &unhex(v["canonical_hex"].as_str().unwrap())
            )
            .is_err(),
            "{}",
            v["name"]
        );
    }
}
#[test]
fn signed_initial_owner_and_adoption_cannot_change() {
    let v = fixture("InitialBindRequest.json");
    let body = unhex(v["canonical_hex"].as_str().unwrap());
    let envelope = unhex(v["envelope_hex"].as_str().unwrap());
    let key = unhex(v["public_key_hex"].as_str().unwrap());
    let sig = unhex(v["signature_hex"].as_str().unwrap());
    for owner in [true, false] {
        let mut record: InitialBindRequest = serde_json::from_slice(&body).unwrap();
        if owner {
            record.initial_authority.owner_user_id = "another-owner".into();
        } else {
            record.adoption_sha256 = "a".repeat(64);
        }
        let changed = serde_json::to_vec(&record).unwrap();
        decode_canonical("InitialBindRequest", &changed).unwrap();
        assert!(verify_record(
            "InitialBindRequest",
            "agentenv-process-epoch/bind/v1",
            &changed,
            &envelope,
            &key,
            &sig
        )
        .is_err());
    }
}
