//! Verification against host-owned pins obtained from authenticated enrollment.
//! The participant remains dormant; production provisioning and routes are not installed.
use super::{wire, Allocation, Operation};
use anyhow::{ensure, Context};
use sha2::{Digest, Sha256};

pub(crate) struct ProvisioningPins {
    pub allocation: Allocation,
    pub sandbox_family: String,
    pub descriptor: wire::Descriptor,
    pub funded_session_id: uuid::Uuid,
    pub controller_key: [u8; 32],
    pub controller_key_id: String,
    pub trust_revision: u64,
    pub audience: String,
}
pub(crate) struct Verifier {
    pins: ProvisioningPins,
}
pub(crate) struct VerifiedSeal {
    operation: Operation,
    endpoint: String,
    body: Vec<u8>,
}
impl VerifiedSeal {
    pub(crate) fn operation(&self) -> &Operation {
        &self.operation
    }
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}
impl Verifier {
    pub(crate) fn new(pins: ProvisioningPins) -> anyhow::Result<Self> {
        super::validate_allocation(&pins.allocation)?;
        let bytes = serde_json::to_vec(&pins.descriptor)?;
        wire::decode_canonical("Descriptor", &bytes)?;
        ensure!(
            pins.descriptor.runtime_id == pins.allocation.runtime_id.to_string()
                && pins.descriptor.runtime_incarnation
                    == pins.allocation.runtime_incarnation.to_string()
                && pins.descriptor.enrollment_revision == pins.allocation.enrollment_revision
                && pins.trust_revision > 0
                && !pins.funded_session_id.is_nil(),
            "invalid provisioning pins"
        );
        Ok(Self { pins })
    }
    pub(crate) fn seal(
        &self,
        body: &[u8],
        envelope: &[u8],
        signature: &[u8],
        now_unix_ms: u64,
    ) -> anyhow::Result<VerifiedSeal> {
        wire::verify_record(
            "SealRequest",
            "agentenv-process-epoch/seal/v1",
            body,
            envelope,
            &self.pins.controller_key,
            signature,
        )?;
        let e: wire::SignedEnvelope = serde_json::from_slice(envelope)?;
        let request: wire::SealRequest = serde_json::from_slice(body)?;
        let b = &request.binding;
        let d = &self.pins.descriptor;
        let descriptor_hash = format!("{:x}", Sha256::digest(serde_json::to_vec(d)?));
        let request_hash = format!("{:x}", Sha256::digest(body));
        ensure!(
            e.signer == self.pins.allocation.controller
                && e.key_id == self.pins.controller_key_id
                && e.trust_revision == self.pins.trust_revision
                && e.audience == self.pins.audience
                && e.expires_at_unix_ms > now_unix_ms
                && e.node_id == d.node_id
                && e.node_incarnation == d.node_incarnation
                && e.runtime_id == d.runtime_id
                && e.runtime_incarnation == d.runtime_incarnation
                && e.enrollment_revision == d.enrollment_revision
                && e.descriptor_sha256 == descriptor_hash
                && e.request_sha256 == request_hash,
            "process authority does not match current host pins"
        );
        ensure!(
            b.tenant_id == self.pins.allocation.tenant_id
                && b.sandbox_id == self.pins.allocation.sandbox_id
                && b.sandbox_family == self.pins.sandbox_family
                && b.descriptor_sha256 == descriptor_hash
                && b.node_id == d.node_id
                && b.node_incarnation == d.node_incarnation
                && b.runtime_id == d.runtime_id
                && b.runtime_incarnation == d.runtime_incarnation
                && b.guest_boot_id == d.guest_boot_id
                && b.enrollment_revision == d.enrollment_revision
                && b.process_endpoint == d.process_endpoint
                && b.guest_build_sha256 == d.guest_build_sha256
                && b.capabilities_sha256 == d.capabilities_sha256
                && request.expected_session_id == self.pins.funded_session_id.to_string()
                && b.reserved_session_id != request.expected_session_id,
            "process request does not match captured allocation"
        );
        Ok(VerifiedSeal {
            operation: Operation {
                allocation: self.pins.allocation.clone(),
                epoch_id: self.pins.funded_session_id,
                operation_id: b.operation_id.parse().context("process operation id")?,
                request_sha256: request_hash,
            },
            endpoint: d.process_endpoint.clone(),
            body: body.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
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
    fn fixture_verifier() -> (Verifier, Vec<u8>, Vec<u8>, Vec<u8>) {
        let v = fixture("SealRequest.json");
        let body = unhex(v["canonical_hex"].as_str().unwrap());
        let envelope = unhex(v["envelope_hex"].as_str().unwrap());
        let e: wire::SignedEnvelope = serde_json::from_slice(&envelope).unwrap();
        let r: wire::SealRequest = serde_json::from_slice(&body).unwrap();
        let d = fixture("Descriptor.json");
        let descriptor =
            serde_json::from_slice(&unhex(d["canonical_hex"].as_str().unwrap())).unwrap();
        let pins = ProvisioningPins {
            allocation: Allocation {
                controller: e.signer.clone(),
                tenant_id: r.binding.tenant_id.clone(),
                sandbox_id: r.binding.sandbox_id.clone(),
                runtime_id: r.binding.runtime_id.parse().unwrap(),
                runtime_incarnation: r.binding.runtime_incarnation.parse().unwrap(),
                enrollment_revision: r.binding.enrollment_revision,
            },
            sandbox_family: r.binding.sandbox_family.clone(),
            descriptor,
            funded_session_id: r.expected_session_id.parse().unwrap(),
            controller_key: unhex(v["public_key_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
            controller_key_id: e.key_id,
            trust_revision: e.trust_revision,
            audience: e.audience,
        };
        (
            Verifier::new(pins).unwrap(),
            body,
            envelope,
            unhex(v["signature_hex"].as_str().unwrap()),
        )
    }
    #[test]
    fn exact_signed_seal_uses_only_the_pinned_endpoint() {
        let (v, body, envelope, sig) = fixture_verifier();
        let verified = v.seal(&body, &envelope, &sig, 1_900_000_000_000).unwrap();
        assert_eq!(verified.endpoint(), v.pins.descriptor.process_endpoint);
        assert_eq!(verified.body(), body);
        assert_eq!(verified.operation().allocation, v.pins.allocation);
        assert_eq!(verified.operation().epoch_id, v.pins.funded_session_id);
    }
    #[test]
    fn signed_foreign_scope_and_stale_authority_never_produce_a_route() {
        let (v, body, envelope, sig) = fixture_verifier();
        assert!(v.seal(&body, &envelope, &sig, 2_000_000_000_000).is_err());
        for field in [
            "tenant", "family", "sandbox", "boot", "runtime", "node", "build", "endpoint",
            "session",
        ] {
            let mut r: wire::SealRequest = serde_json::from_slice(&body).unwrap();
            match field {
                "tenant" => r.binding.tenant_id = "foreign-tenant".into(),
                "family" => r.binding.sandbox_family = "native".into(),
                "sandbox" => r.binding.sandbox_id = "foreign-sandbox".into(),
                "boot" => r.binding.guest_boot_id = uuid::Uuid::now_v7().to_string(),
                "runtime" => r.binding.runtime_id = uuid::Uuid::now_v7().to_string(),
                "node" => r.binding.node_id = "foreign-node".into(),
                "build" => r.binding.guest_build_sha256 = "a".repeat(64),
                "endpoint" => r.binding.process_endpoint = "https://192.0.2.99:9443".into(),
                "session" => r.expected_session_id = uuid::Uuid::now_v7().to_string(),
                _ => unreachable!(),
            }
            let changed = serde_json::to_vec(&r).unwrap();
            let mut e: wire::SignedEnvelope = serde_json::from_slice(&envelope).unwrap();
            e.body_sha256 = format!("{:x}", Sha256::digest(&changed));
            e.request_sha256 = e.body_sha256.clone();
            let eb = serde_json::to_vec(&e).unwrap();
            let key =
                ring::signature::Ed25519KeyPair::from_seed_unchecked(&(0..32).collect::<Vec<u8>>())
                    .unwrap();
            let signature = key.sign(&wire::signature_input(&eb).unwrap());
            assert!(
                v.seal(&changed, &eb, signature.as_ref(), 1_900_000_000_000)
                    .is_err(),
                "{field}"
            );
        }
        let mut e: wire::SignedEnvelope = serde_json::from_slice(&envelope).unwrap();
        for field in ["key", "revision", "audience", "signer", "descriptor"] {
            let saved = e.clone();
            match field {
                "key" => e.key_id = "untrusted".into(),
                "revision" => e.trust_revision += 1,
                "audience" => e.audience = "other-node".into(),
                "signer" => e.signer = "other-controller".into(),
                "descriptor" => e.descriptor_sha256 = "a".repeat(64),
                _ => unreachable!(),
            }
            let eb = serde_json::to_vec(&e).unwrap();
            let key =
                ring::signature::Ed25519KeyPair::from_seed_unchecked(&(0..32).collect::<Vec<u8>>())
                    .unwrap();
            let signed = key.sign(&wire::signature_input(&eb).unwrap());
            assert!(
                v.seal(&body, &eb, signed.as_ref(), 1_900_000_000_000)
                    .is_err(),
                "{field}"
            );
            e = saved;
        }
    }
}
