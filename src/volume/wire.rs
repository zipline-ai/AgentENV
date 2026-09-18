//! Strict parsing of the frozen B + E transport shape. Parsing is not authority.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UntrustedVolumeEncryption {
    pub volume_id: String,
    pub volume_kind: String,
    #[serde(default, deserialize_with = "present_string")]
    pub drive_id: Option<String>,
    pub grant: String,
    pub signature: String,
    pub wrapped_dek: String,
    pub kms_key: String,
    pub kms_key_version: String,
    pub kms_aad: String,
    pub cipher: String,
    pub sector_size: u32,
}

/// Contains potentially sensitive original request bytes; intentionally no Debug
/// or Serialize. Neither this nor its envelope is a VerifiedLaunch capability.
pub struct ParsedLaunchBody {
    body: Vec<u8>,
    envelope: Option<UntrustedVolumeEncryption>,
}
impl ParsedLaunchBody {
    pub fn provider_body(&self) -> &[u8] {
        &self.body
    }
    pub fn envelope(&self) -> Option<&UntrustedVolumeEncryption> {
        self.envelope.as_ref()
    }
    pub fn body_sha256(&self) -> String {
        hex::encode(Sha256::digest(&self.body))
    }
}
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid encrypted launch request encoding")]
pub struct InvalidLaunchBody;

/// A missing envelope says nothing about the required encryption policy.
pub fn parse_launch_body(wire: &[u8]) -> Result<ParsedLaunchBody, InvalidLaunchBody> {
    if wire.len() > 2 * 1024 * 1024 || wire.first() != Some(&b'{') || wire.last() != Some(&b'}') {
        return Err(InvalidLaunchBody);
    }
    validate_unique_json(wire)?;
    let Root(fields) = serde_json::from_slice(wire).map_err(|_| InvalidLaunchBody)?;
    const ALLOWED: &[&str] = &[
        "templateID",
        "timeout",
        "autoPause",
        "autoResume",
        "envVars",
        "metadata",
        "secure",
        "allow_internet_access",
        "network",
        "customExtensionParams",
        "mcp",
        "async_restore",
        "volumeEncryption",
    ];
    if fields
        .iter()
        .any(|(key, _)| !ALLOWED.contains(&key.as_str()))
    {
        return Err(InvalidLaunchBody);
    }
    let template = fields
        .iter()
        .find(|(key, _)| key == "templateID")
        .ok_or(InvalidLaunchBody)?
        .1;
    let template: String = serde_json::from_str(template.get()).map_err(|_| InvalidLaunchBody)?;
    if template.trim().is_empty() {
        return Err(InvalidLaunchBody);
    }
    let Some((_, raw)) = fields.iter().find(|(key, _)| key == "volumeEncryption") else {
        return Ok(ParsedLaunchBody {
            body: wire.to_vec(),
            envelope: None,
        });
    };
    if fields.last().map(|(key, _)| key.as_str()) != Some("volumeEncryption") {
        return Err(InvalidLaunchBody);
    }
    // RawValue borrows this input. Only the exact terminal appended member is removed.
    let start = (raw.get().as_ptr() as usize)
        .checked_sub(wire.as_ptr() as usize)
        .ok_or(InvalidLaunchBody)?;
    let tag = b",\"volumeEncryption\":";
    let prefix_end = start.checked_sub(tag.len()).ok_or(InvalidLaunchBody)?;
    if wire.get(prefix_end..start) != Some(tag.as_slice())
        || start + raw.get().len() + 1 != wire.len()
    {
        return Err(InvalidLaunchBody);
    }
    let envelope: UntrustedVolumeEncryption =
        serde_json::from_str(raw.get()).map_err(|_| InvalidLaunchBody)?;
    envelope.validate()?;
    let mut body = wire[..prefix_end].to_vec();
    body.push(b'}');
    Ok(ParsedLaunchBody {
        body,
        envelope: Some(envelope),
    })
}

impl UntrustedVolumeEncryption {
    fn validate(&self) -> Result<(), InvalidLaunchBody> {
        for value in [
            &self.volume_id,
            &self.volume_kind,
            &self.kms_key,
            &self.kms_key_version,
            &self.kms_aad,
        ] {
            if value.trim().is_empty() || value.len() > 2048 || value.chars().any(char::is_control)
            {
                return Err(InvalidLaunchBody);
            }
        }
        if self
            .drive_id
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 128)
            || self.cipher != "aes-xts-plain64"
            || self.sector_size != 4096
        {
            return Err(InvalidLaunchBody);
        }
        for value in [&self.grant, &self.signature, &self.wrapped_dek] {
            decode_base64(value)?;
        }
        Ok(())
    }
}
fn present_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
pub(crate) fn decode_base64(value: &str) -> Result<Vec<u8>, InvalidLaunchBody> {
    if value.is_empty() || value.len() > 128 * 1024 {
        return Err(InvalidLaunchBody);
    }
    let bytes = STANDARD.decode(value).map_err(|_| InvalidLaunchBody)?;
    if STANDARD.encode(&bytes) != value {
        return Err(InvalidLaunchBody);
    }
    Ok(bytes)
}

// serde_json::Value alone silently overwrites duplicate object fields. Validate
// every nesting level first, including decoded-key aliases and array elements.
pub(crate) fn validate_unique_json(bytes: &[u8]) -> Result<(), InvalidLaunchBody> {
    serde_json::from_slice::<Unique>(bytes)
        .map(|_| ())
        .map_err(|_| InvalidLaunchBody)
}
struct Unique;
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("unique JSON fields")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
                let mut seen = HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    map.next_value::<Unique>()?;
                }
                Ok(Unique)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
                while seq.next_element::<Unique>()?.is_some() {}
                Ok(Unique)
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                Ok(Unique)
            }
        }
        d.deserialize_any(V)
    }
}
struct Root<'a>(Vec<(String, &'a RawValue)>);
impl<'de> Deserialize<'de> for Root<'de> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Root<'de>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("launch object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut fields = Vec::new();
                while let Some(entry) = map.next_entry::<String, &'de RawValue>()? {
                    fields.push(entry);
                }
                Ok(Root(fields))
            }
        }
        d.deserialize_map(V)
    }
}
#[cfg(test)]
mod tests;
