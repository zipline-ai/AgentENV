use super::*;
use serde_json::{json, Value};

fn vectors() -> Vec<Value> {
    serde_json::from_str(include_str!("../testdata/launch_body_vectors.json")).unwrap()
}
fn envelope() -> String {
    vectors()[0]["Envelope"].as_str().unwrap().to_owned()
}
fn append(body: &str, envelope: &str) -> Vec<u8> {
    format!(
        "{},\"volumeEncryption\":{}}}",
        &body[..body.len() - 1],
        envelope
    )
    .into_bytes()
}
fn denied(bytes: &[u8]) {
    assert!(matches!(parse_launch_body(bytes), Err(InvalidLaunchBody)));
}

#[test]
fn go_vectors_preserve_exact_body_and_distinct_hash() {
    for v in vectors() {
        let parsed = parse_launch_body(v["Wire"].as_str().unwrap().as_bytes()).unwrap();
        assert_eq!(
            parsed.provider_body(),
            v["Body"].as_str().unwrap().as_bytes()
        );
        assert_eq!(parsed.body_sha256(), v["SHA256"].as_str().unwrap());
        assert_ne!(
            parsed.body_sha256(),
            hex::encode(Sha256::digest(v["Wire"].as_str().unwrap().as_bytes()))
        );
        let e = parsed.envelope().unwrap();
        assert_eq!(e.volume_id, "vol_a");
        assert_eq!(e.sector_size, 4096);
    }
}
#[test]
fn absent_envelope_preserves_bytes_without_selecting_legacy() {
    for v in vectors() {
        let b = v["Body"].as_str().unwrap().as_bytes();
        let parsed = parse_launch_body(b).unwrap();
        assert_eq!(parsed.provider_body(), b);
        assert!(parsed.envelope().is_none());
    }
}
#[test]
fn duplicate_keys_at_any_depth_are_rejected() {
    for b in [
        r#"{"templateID":"t","templateID":"other"}"#,
        r#"{"templateID":"t","metadata":{"x":"one","\u0078":"two"}}"#,
        r#"{"templateID":"t","metadata":{"items":[{"x":1,"x":2}]}}"#,
    ] {
        denied(&append(b, &envelope()));
        denied(b.as_bytes());
    }
    let e = envelope().replacen('{', "{\"volumeId\":\"other\",", 1);
    denied(&append(r#"{"templateID":"t"}"#, &e));
}
#[test]
fn root_envelope_must_be_unique_terminal_and_exactly_appended() {
    let e = envelope();
    for b in [
        format!(r#"{{"volumeEncryption":{e},"templateID":"t"}}"#),
        format!(r#"{{"templateID":"t","volumeEncryption":{e},"volumeEncryption":{e}}}"#),
        format!(r#"{{"templateID":"t", "volumeEncryption":{e}}}"#),
        format!(r#"{{"templateID":"t","volumeEncryption": {e}}}"#),
        format!(r#"{{"templateID":"t","volumeEncryption":{e} }}"#),
        format!(r#"{{"templateID":"t","\u0076olumeEncryption":{e}}}"#),
    ] {
        denied(b.as_bytes());
    }
}
#[test]
fn invalid_envelope_never_becomes_absence() {
    let original: Value = serde_json::from_str(&envelope()).unwrap();
    for e in [json!(null), json!({}), json!("text"), json!([])] {
        denied(&append(r#"{"templateID":"t"}"#, &e.to_string()));
    }
    for field in [
        "volumeId",
        "volumeKind",
        "grant",
        "signature",
        "wrappedDek",
        "kmsKey",
        "kmsKeyVersion",
        "kmsAad",
        "cipher",
        "sectorSize",
    ] {
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(field);
        denied(&append(r#"{"templateID":"t"}"#, &missing.to_string()));
    }
    for (field, value) in [
        ("rawKey", json!("plaintext")),
        ("mount", json!("/tmp")),
        ("grant", json!("%%%")),
        ("signature", json!("")),
        ("sectorSize", json!(512)),
        ("cipher", json!("plain")),
    ] {
        let mut e = original.clone();
        e[field] = value;
        denied(&append(r#"{"templateID":"t"}"#, &e.to_string()));
    }
}
#[test]
fn unknown_source_empty_body_and_trailing_data_deny() {
    for b in [
        "{}",
        "[]",
        "null",
        r#"{"templateID":""}"#,
        r#"{"templateID":"t","unknown":true}"#,
        r#"{"templateID":"t"} "#,
        r#"{"templateID":"t"}{}"#,
    ] {
        denied(b.as_bytes());
    }
    denied(format!(r#"{{"volumeEncryption":{}}}"#, envelope()).as_bytes());
    let mut wire = append(r#"{"templateID":"t"}"#, &envelope());
    wire.push(b'\n');
    denied(&wire);
}
#[test]
fn body_changes_are_preserved_for_authenticated_hash_comparison() {
    let v = &vectors()[0];
    let original = v["Wire"].as_str().unwrap();
    for changed in [
        original.replacen("template-immutable-id", "different-source", 1),
        original.replacen("300", "301", 1),
        original.replacen("hello", "changed", 1),
    ] {
        let parsed = parse_launch_body(changed.as_bytes()).unwrap();
        assert_ne!(parsed.body_sha256(), v["SHA256"].as_str().unwrap());
    }
}
#[test]
fn oversized_or_deep_wire_is_rejected_without_echoing_secrets() {
    denied(&vec![b' '; 2 * 1024 * 1024 + 1]);
    let nested = format!(
        "{{\"templateID\":\"t\",\"metadata\":{}0{}}}",
        "[".repeat(140),
        "]".repeat(140)
    );
    denied(nested.as_bytes());
    assert_eq!(
        InvalidLaunchBody.to_string(),
        "invalid encrypted launch request encoding"
    );
}
