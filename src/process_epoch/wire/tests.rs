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

#[test]
fn addendum_records_are_canonical() {
    for name in fixture("addendum-manifest.json")["positive"]
        .as_array()
        .unwrap()
    {
        let v = fixture(name.as_str().unwrap());
        decode_canonical(
            v["kind"].as_str().unwrap(),
            &unhex(v["canonical_hex"].as_str().unwrap()),
        )
        .unwrap();
    }
}

#[test]
fn addendum_vectors_and_ed25519_match_go() {
    let manifest = fixture("addendum-manifest.json");
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
fn addendum_negative_vectors_are_never_repaired() {
    for v in fixture("negative-addendum.json").as_array().unwrap() {
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
fn addendum_lookup_preserves_first_signed_receipt() {
    for name in fixture("addendum-manifest.json")["containers"]
        .as_array()
        .unwrap()
    {
        let v = fixture(name.as_str().unwrap());
        let response: ReceiptResponse =
            serde_json::from_slice(&unhex(v["canonical_hex"].as_str().unwrap())).unwrap();
        let result: LookupResponse = serde_json::from_slice(&response.node.body).unwrap();
        let key = unhex(v["public_key_hex"].as_str().unwrap());
        verify_record(
            "LookupResponse",
            "agentenv-process-epoch/node-response/v1",
            &response.node.body,
            &response.node.envelope,
            &key,
            &response.node.signature,
        )
        .unwrap();
        if let Some(receipt) = response.receipt {
            let kind = match result.receipt_kind.as_deref().unwrap() {
                "seal" => "SealReceipt",
                "bind" => "BindReceipt",
                "release" => "ReleaseReceipt",
                _ => panic!("kind"),
            };
            verify_record(
                kind,
                "agentenv-process-epoch/node-response/v1",
                &receipt.body,
                &receipt.envelope,
                &key,
                &receipt.signature,
            )
            .unwrap();
            assert_eq!(
                result.receipt_sha256.as_deref().unwrap(),
                format!(
                    "{:x}",
                    Sha256::digest(serde_json::to_vec(&receipt).unwrap())
                )
            );
            let original: Value = serde_json::from_slice(&receipt.body).unwrap();
            assert_eq!(
                result.receipt_id.as_deref().unwrap(),
                original["receipt_id"].as_str().unwrap()
            );
            assert_eq!(
                result.request_sha256,
                original["request_sha256"].as_str().unwrap()
            );
            match result.state.as_str() {
                "bound" => assert_eq!(original["state"], "bound_closed"),
                "bind_pending" => assert_eq!(original["state"], "incomplete"),
                "released" => assert_eq!(original["outcome"], "released"),
                "release_pending" => assert!(matches!(
                    original["outcome"].as_str(),
                    Some("accepted" | "incomplete")
                )),
                "completed_seal" => {
                    assert_eq!(original["state"], "sealed");
                    assert_eq!(original["evidence"]["evidence_class"], "host_scope_stopped");
                }
                _ => panic!("unexpected receipt state"),
            }
            let first: SignedEnvelope = serde_json::from_slice(&receipt.envelope).unwrap();
            let fresh: SignedEnvelope = serde_json::from_slice(&response.node.envelope).unwrap();
            assert_ne!(first.nonce, fresh.nonce);
            assert_eq!(first.request_sha256, fresh.request_sha256);
            let mut altered = receipt.clone();
            altered.signature[0] ^= 1;
            assert_ne!(
                result.receipt_sha256.unwrap(),
                format!(
                    "{:x}",
                    Sha256::digest(serde_json::to_vec(&altered).unwrap())
                )
            );
        } else {
            assert!(result.receipt_id.is_none());
            assert!(result.receipt_sha256.is_none());
        }
    }
}

#[test]
fn addendum_two_records_are_canonical() {
    for name in fixture("addendum-2-manifest.json")["positive"]
        .as_array()
        .unwrap()
    {
        let v = fixture(name.as_str().unwrap());
        decode_canonical(
            v["kind"].as_str().unwrap(),
            &unhex(v["canonical_hex"].as_str().unwrap()),
        )
        .unwrap();
    }
}

#[test]
fn addendum_two_vectors_and_ed25519_match_go() {
    let manifest = fixture("addendum-2-manifest.json");
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
fn addendum_two_negative_vectors_are_never_repaired() {
    for v in fixture("negative-addendum-2.json").as_array().unwrap() {
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

// Wire controls do not establish independent host cessation.
#[test]
fn addendum_two_evidence_needs_node_trust_and_exact_retirement() {
    let authority = fixture("Addendum2Retirement.json");
    let a: RetirementAuthority =
        serde_json::from_slice(&unhex(authority["canonical_hex"].as_str().unwrap())).unwrap();
    for name in [
        "Addendum2HostCessation.json",
        "Addendum2WrongIncarnation.json",
        "Addendum2GuestImpostor.json",
    ] {
        let v = fixture(name);
        let body = unhex(v["canonical_hex"].as_str().unwrap());
        let valid = verify_record(
            "HostCessationEvidence",
            "agentenv-process-epoch/node-response/v1",
            &body,
            &unhex(v["envelope_hex"].as_str().unwrap()),
            &unhex(v["public_key_hex"].as_str().unwrap()),
            &unhex(v["signature_hex"].as_str().unwrap()),
        )
        .is_ok();
        let e: HostCessationEvidence = serde_json::from_slice(&body).unwrap();
        let accepted = valid
            && e.runtime_id == a.runtime_id
            && e.runtime_incarnation == a.runtime_incarnation
            && e.retirement_operation_id == a.operation_id
            && e.retirement_request_sha256 == authority["sha256"].as_str().unwrap()
            && e.no_second_copy;
        assert_eq!(accepted, name == "Addendum2HostCessation.json", "{name}");
    }
    for name in fixture("addendum-2-manifest.json")["positive"]
        .as_array()
        .unwrap()
    {
        let v = fixture(name.as_str().unwrap());
        let e: SignedEnvelope =
            serde_json::from_slice(&unhex(v["envelope_hex"].as_str().unwrap())).unwrap();
        assert_eq!(e.request_sha256, v["sha256"].as_str().unwrap());
        assert_eq!(e.body_sha256, e.request_sha256);
    }
}

#[test]
fn addendum_three_records_are_canonical() {
    for name in fixture("addendum-3-manifest.json")["positive"]
        .as_array()
        .unwrap()
    {
        let v = fixture(name.as_str().unwrap());
        decode_canonical(
            v["kind"].as_str().unwrap(),
            &unhex(v["canonical_hex"].as_str().unwrap()),
        )
        .unwrap();
    }
}

#[test]
fn addendum_three_vectors_and_ed25519_match_go() {
    let manifest = fixture("addendum-3-manifest.json");
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
fn addendum_three_negative_vectors_are_never_repaired() {
    for v in fixture("negative-addendum-3.json").as_array().unwrap() {
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

// Wire controls do not establish independent host cessation.

// Fixture comparisons are not live lifecycle authorization or host cessation proof.
#[test]
fn addendum_three_response_mapping() {
    for ctx in fixture("addendum-3-manifest.json")["contexts"]
        .as_array()
        .unwrap()
    {
        let v = fixture(ctx["name"].as_str().unwrap());
        let source = fixture(ctx["source"].as_str().unwrap());
        let raw = unhex(v["canonical_hex"].as_str().unwrap());
        let response: ReceiptResponse = serde_json::from_slice(&raw).unwrap();
        let result: Value = serde_json::from_slice(&response.node.body).unwrap();
        let fresh: Value = serde_json::from_slice(&response.node.envelope).unwrap();
        let key = unhex(source["public_key_hex"].as_str().unwrap());
        let mut accepted = response.guest.is_none()
            && decode_canonical("ReceiptResponse", &raw).is_ok()
            && verify_record(
                "LookupResponse",
                "agentenv-process-epoch/node-response/v1",
                &response.node.body,
                &response.node.envelope,
                &key,
                &response.node.signature,
            )
            .is_ok()
            && result["binding"] == ctx["binding"]
            && result["request_sha256"] == ctx["request_sha256"]
            && result["state"] == ctx["state"]
            && result["receipt_kind"] == ctx["receipt_kind"]
            && fresh["nonce"] == ctx["nonce"]
            && fresh["request_sha256"] == ctx["request_sha256"];
        if let Some(r) = response.receipt {
            let kind = if ctx["receipt_kind"] == "dispatch_result" {
                "DispatchResult"
            } else {
                "HostCessationEvidence"
            };
            let original: Value = serde_json::from_slice(&r.body).unwrap();
            let historical: Value = serde_json::from_slice(&r.envelope).unwrap();
            let (id, request) = if kind == "DispatchResult" {
                ("operation_id", "dispatch_request_sha256")
            } else {
                ("retirement_operation_id", "retirement_request_sha256")
            };
            accepted &= verify_record(
                kind,
                "agentenv-process-epoch/node-response/v1",
                &r.body,
                &r.envelope,
                &key,
                &r.signature,
            )
            .is_ok()
                && result["receipt_id"] == original[id]
                && original[id] == ctx["binding"]["operation_id"]
                && original[request] == ctx["request_sha256"]
                && result["receipt_sha256"]
                    == format!("{:x}", Sha256::digest(serde_json::to_vec(&r).unwrap()))
                && historical["request_sha256"] == format!("{:x}", Sha256::digest(&r.body))
                && historical["body_sha256"] == historical["request_sha256"]
                && historical["nonce"] != fresh["nonce"]
                && r.body == unhex(source["canonical_hex"].as_str().unwrap())
                && r.envelope == unhex(source["envelope_hex"].as_str().unwrap())
                && r.signature == unhex(source["signature_hex"].as_str().unwrap());
            for field in [
                "node_id",
                "node_incarnation",
                "enrollment_revision",
                "audience",
                "runtime_id",
                "runtime_incarnation",
            ] {
                accepted &= fresh[field] == historical[field];
            }
            for field in ["runtime_id", "runtime_incarnation"] {
                accepted &= original[field] == ctx["binding"][field];
            }
            if kind == "DispatchResult" {
                for field in [
                    "node_id",
                    "node_incarnation",
                    "guest_boot_id",
                    "process_endpoint",
                    "guest_build_sha256",
                    "enrollment_revision",
                ] {
                    accepted &= original[field] == ctx["binding"][field];
                }
            }
        } else {
            accepted = false;
        }
        assert_eq!(
            accepted,
            ctx["accepted"].as_bool().unwrap(),
            "{}",
            ctx["name"]
        );
    }
}
