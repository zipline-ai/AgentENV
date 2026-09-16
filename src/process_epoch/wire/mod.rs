//! Canonical transport records only. Parsing or verifying a signature does not grant
//! authority, authenticate provisioning, or establish cessation. In particular an
//! EvidenceReference is an untrusted reference, not a HostScopeStopped proof.
mod enums;
mod generated;
use anyhow::{bail, ensure};
pub use generated::*;
use serde_json::Value;

pub trait Validate {
    fn validate(&self) -> anyhow::Result<()>;
}
fn check_scalar(kind: &str, value: &Value) -> anyhow::Result<()> {
    if kind == "octets" {
        let bytes = value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("octet array required"))?;
        ensure!(
            !bytes.is_empty()
                && bytes.len() <= 65536
                && bytes.iter().all(|b| b.as_u64().is_some_and(|n| n <= 255)),
            "invalid octet array"
        );
        return Ok(());
    }
    if kind == "uint" || kind == "positive" {
        let n = value
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("unsigned integer required"))?;
        ensure!(kind != "positive" || n > 0, "positive integer required");
        return Ok(());
    }
    if kind == "true" {
        ensure!(value.as_bool() == Some(true), "managed must be true");
        return Ok(());
    }
    let s = value
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("string required"))?;
    ensure!(
        !s.is_empty() && s.len() <= 2048 && s.bytes().all(|b| (32..=126).contains(&b)),
        "noncanonical string"
    );
    match kind {
        "uuid" => {
            let id = uuid::Uuid::parse_str(s)?;
            ensure!(
                !id.is_nil() && id.to_string() == s,
                "canonical nonnil uuid required"
            );
        }
        "hash" => ensure!(
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "lowercase sha256 required"
        ),
        "text" => (),
        _ => ensure!(
            enums::enum_values(kind).is_some_and(|values| values.contains(&s)),
            "unknown vocabulary"
        ),
    }
    Ok(())
}
/// Reject alternate bytes, including duplicate/unknown keys and explicit null.
/// Semantic saved-authority checks belong to the authenticated participant.
pub fn decode_canonical(kind: &str, bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure!(bytes.len() <= 65536, "record too large");
    let canonical = generated::canonical(kind, bytes)?;
    ensure!(canonical == bytes, "noncanonical process epoch bytes");
    Ok(canonical)
}
pub fn signature_input(envelope: &[u8]) -> anyhow::Result<Vec<u8>> {
    decode_canonical("SignedEnvelope", envelope)?;
    let e: SignedEnvelope = serde_json::from_slice(envelope)?;
    let mut input = e.domain.into_bytes();
    input.push(0);
    input.extend_from_slice(envelope);
    Ok(input)
}
pub fn verify_signature(envelope: &[u8], key: &[u8], signature: &[u8]) -> anyhow::Result<()> {
    let input = signature_input(envelope)?;
    if ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(&input, signature)
        .is_err()
    {
        bail!("invalid process epoch signature");
    }
    Ok(())
}
#[cfg(test)]
mod tests;
fn path<'a>(v: &'a Value, p: &str) -> Option<&'a Value> {
    p.split('.').try_fold(v, |v, k| v.get(k))
}
fn validate_relations(kind: &str, value: &Value) -> anyhow::Result<()> {
    static SCHEMA: std::sync::LazyLock<Value> = std::sync::LazyLock::new(|| {
        serde_json::from_str(include_str!(
            "../../../testdata/process-epoch-vectors/v1/schema.json"
        ))
        .expect("checked schema")
    });
    let Some(rules) = SCHEMA["rules"][kind].as_array() else {
        return Ok(());
    };
    for r in rules {
        if let Some(w) = r["when"].as_array() {
            if path(value, w[0].as_str().unwrap()) != Some(&w[1]) {
                continue;
            }
        }
        if let Some(p) = r["when_present"].as_str() {
            if path(value, p).is_none() {
                continue;
            }
        }
        for (key, rule) in r.as_object().unwrap() {
            let valid = match key.as_str() {
                "when" | "when_present" => true,
                "equal" => {
                    let a = path(value, rule[0].as_str().unwrap());
                    a.is_some() && a == path(value, rule[1].as_str().unwrap())
                }
                "paired" => {
                    path(value, rule[0].as_str().unwrap()).is_some()
                        == path(value, rule[1].as_str().unwrap()).is_some()
                }
                "present" => path(value, rule.as_str().unwrap()).is_some(),
                "absent" => path(value, rule.as_str().unwrap()).is_none(),
                "value" => path(value, rule[0].as_str().unwrap()) == Some(&rule[1]),
                "one_of" => path(value, rule[0].as_str().unwrap())
                    .is_some_and(|v| rule[1].as_array().unwrap().contains(v)),
                _ => false,
            };
            ensure!(valid, "invalid {kind} relationship: {key}");
        }
    }
    Ok(())
}
/// Cryptographic record integrity only. The caller must independently authenticate
/// the signer, audience, enrollment, saved authority, nonce and expiry.
pub fn verify_record(
    kind: &str,
    domain: &str,
    body: &[u8],
    envelope: &[u8],
    key: &[u8],
    signature: &[u8],
) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};
    decode_canonical(kind, body)?;
    verify_signature(envelope, key, signature)?;
    let e: SignedEnvelope = serde_json::from_slice(envelope)?;
    ensure!(
        e.domain == domain && e.body_sha256 == format!("{:x}", Sha256::digest(body)),
        "record digest or domain mismatch"
    );
    Ok(())
}
