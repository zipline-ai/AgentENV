//! Dormant KMS custody boundary. No production effect authority or launch caller.
use super::key::LockedBytes;
use async_trait::async_trait;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("volume key unavailable or denied")]
pub struct KmsDenied;

// Constructible only by a future in-lock effect-authority participant. Consumed
// grant evidence alone does not satisfy reverify or durable descriptor obligations.
// This is deliberately uninhabited outside tests until the full authenticated
// launch capability is implemented and gated. There is no production success
// adapter; consumed-grant evidence cannot fill this field.
struct UnavailableLaunchAuthority {
    #[cfg(not(test))]
    _missing: std::convert::Infallible,
}
pub struct KmsUnwrapAuthority {
    _launch: UnavailableLaunchAuthority,
    operation: RetainedKmsOperation,
    key: String,
    version: String,
    aad: String,
    wrapped: Vec<u8>,
    wrapped_sha256: String,
}
/// The future descriptor participant supplies this exact durable operation.
/// It is not constructible from network input and is not itself authorization.
pub struct RetainedKmsOperation {
    operation_id: String,
    tenant_id: String,
    volume_id: String,
    node_id: String,
    incarnation: String,
}
impl RetainedKmsOperation {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn volume_id(&self) -> &str {
        &self.volume_id
    }
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
    pub fn incarnation(&self) -> &str {
        &self.incarnation
    }
}
#[async_trait]
pub trait KmsEffectGuard: Send {
    /// Implementations retain the stable effect lock across the entire unwrap.
    /// Recheck the exact durable operation and live incarnation, including fence.
    async fn revalidate(&mut self, operation: &RetainedKmsOperation) -> Result<(), KmsDenied>;
}
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptRequest {
    pub ciphertext: String,
    pub additional_authenticated_data: String,
    pub ciphertext_crc32c: String,
    pub additional_authenticated_data_crc32c: String,
}
#[async_trait]
pub trait KmsTransport: Send + Sync {
    // Implementations must bound the response, redact failures and clear temporary
    // plaintext-bearing transport storage. The destination is already mlocked.
    async fn decrypt(
        &self,
        key: &str,
        request: &DecryptRequest,
        response: &mut LockedBytes,
    ) -> Result<usize, KmsDenied>;
}
pub struct VolumeDek {
    bytes: LockedBytes,
}
impl VolumeDek {
    /// The callback must not retain or persist key bytes. The buffer stays locked
    /// until this owner drops, including during a pipe write to cryptsetup.
    pub fn with_key<T>(&self, use_key: impl FnOnce(&[u8]) -> T) -> T {
        use_key(self.bytes.bytes())
    }
}
pub async fn unwrap_dek(
    authority: KmsUnwrapAuthority,
    transport: &dyn KmsTransport,
    effect: &mut dyn KmsEffectGuard,
) -> Result<VolumeDek, KmsDenied> {
    unwrap_with_allocator(authority, transport, effect, LockedBytes::new).await
}
async fn unwrap_with_allocator(
    authority: KmsUnwrapAuthority,
    transport: &dyn KmsTransport,
    effect: &mut dyn KmsEffectGuard,
    mut allocate: impl FnMut(usize) -> Result<LockedBytes, KmsDenied>,
) -> Result<VolumeDek, KmsDenied> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use sha2::{Digest, Sha256};
    validate_authority(&authority)?;
    if hex::encode(Sha256::digest(&authority.wrapped)) != authority.wrapped_sha256 {
        return Err(KmsDenied);
    }
    let request = DecryptRequest {
        ciphertext: STANDARD.encode(&authority.wrapped),
        additional_authenticated_data: STANDARD.encode(authority.aad.as_bytes()),
        ciphertext_crc32c: crc32c::crc32c(&authority.wrapped).to_string(),
        additional_authenticated_data_crc32c: crc32c::crc32c(authority.aad.as_bytes()).to_string(),
    };
    // Allocate and lock every custody buffer before even requesting the key.
    let mut response = allocate(8192)?;
    let mut key = allocate(64)?;
    effect.revalidate(&authority.operation).await?;
    let n = transport
        .decrypt(&authority.key, &request, &mut response)
        .await?;
    // A key arriving after a fence is discarded while the same guard is held.
    effect.revalidate(&authority.operation).await?;
    if n > response.bytes().len() {
        return Err(KmsDenied);
    }
    // No general JSON decoder: its scratch/error strings may copy rejected
    // secret-bearing input into ordinary heap storage.
    let reply = decode_reply(&response.bytes()[..n])?;
    let crc: u32 = reply.plaintext_crc32c.parse().map_err(|_| KmsDenied)?;
    if (reply.plaintext_crc32c.len() > 1 && reply.plaintext_crc32c.starts_with('0'))
        || !reply.plaintext_crc32c.bytes().all(|b| b.is_ascii_digit())
        || reply.plaintext.len() != 88
    {
        return Err(KmsDenied);
    }
    let decoded = STANDARD
        .decode_slice(reply.plaintext, key.bytes_mut())
        .map_err(|_| KmsDenied)?;
    if decoded != 64 || crc32c::crc32c(key.bytes()) != crc {
        return Err(KmsDenied);
    }
    // KMS decrypt has no version-name response. Version provenance comes from
    // the authenticated original wrap binding and exact ciphertext hash, never
    // from usedPrimary. The transport must use CryptoKey:decrypt, not version.
    Ok(VolumeDek { bytes: key })
}
fn validate_authority(a: &KmsUnwrapAuthority) -> Result<(), KmsDenied> {
    if [
        &a.operation.operation_id,
        &a.operation.tenant_id,
        &a.operation.volume_id,
        &a.operation.node_id,
        &a.operation.incarnation,
    ]
    .iter()
    .any(|v| v.is_empty())
        || a.aad
            != format!(
                "vol:{}:{}:sandbox_rootfs",
                a.operation.tenant_id, a.operation.volume_id
            )
    {
        return Err(KmsDenied);
    }
    let parts: Vec<_> = a.key.split('/').collect();
    if parts.len() != 8
        || parts[0] != "projects"
        || parts[2] != "locations"
        || parts[4] != "keyRings"
        || parts[6] != "cryptoKeys"
        || parts.iter().any(|p| {
            p.is_empty()
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        })
        || a.wrapped.is_empty()
        || a.wrapped.len() > 65536
        || a.aad.is_empty()
        || a.aad.len() > 4096
    {
        return Err(KmsDenied);
    }
    let prefix = format!("{}/cryptoKeyVersions/", a.key);
    let version = a.version.strip_prefix(&prefix).ok_or(KmsDenied)?;
    if version.is_empty()
        || version.starts_with('0')
        || !version.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(KmsDenied);
    }
    Ok(())
}
struct DecryptReply<'a> {
    plaintext: &'a str,
    plaintext_crc32c: &'a str,
}
// This limited JSON grammar borrows only unescaped ASCII strings. Every error
// is static; neither valid nor malformed response bytes are allocated or echoed.
fn decode_reply(bytes: &[u8]) -> Result<DecryptReply<'_>, KmsDenied> {
    struct Cursor<'a> {
        bytes: &'a [u8],
        at: usize,
    }
    impl<'a> Cursor<'a> {
        fn space(&mut self) {
            while self
                .bytes
                .get(self.at)
                .is_some_and(|b| b" \r\n\t".contains(b))
            {
                self.at += 1;
            }
        }
        fn take(&mut self, token: u8) -> Result<(), KmsDenied> {
            self.space();
            if self.bytes.get(self.at) != Some(&token) {
                return Err(KmsDenied);
            }
            self.at += 1;
            Ok(())
        }
        fn string(&mut self) -> Result<&'a str, KmsDenied> {
            self.take(b'"')?;
            let start = self.at;
            while let Some(&b) = self.bytes.get(self.at) {
                if b == b'"' {
                    let value =
                        std::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| KmsDenied)?;
                    self.at += 1;
                    return Ok(value);
                }
                if !(0x20..=0x7e).contains(&b) || b == b'\\' {
                    return Err(KmsDenied);
                }
                self.at += 1;
            }
            Err(KmsDenied)
        }
        fn boolean(&mut self) -> Result<(), KmsDenied> {
            self.space();
            let tail = &self.bytes[self.at..];
            if tail.starts_with(b"true") {
                self.at += 4;
            } else if tail.starts_with(b"false") {
                self.at += 5;
            } else {
                return Err(KmsDenied);
            }
            Ok(())
        }
    }
    let mut c = Cursor { bytes, at: 0 };
    c.take(b'{')?;
    let (mut plaintext, mut crc) = (None, None);
    let mut seen = 0u8;
    loop {
        let field = c.string()?;
        c.take(b':')?;
        let bit = match field {
            "plaintext" => 1,
            "plaintextCrc32c" => 2,
            "usedPrimary" => 4,
            "protectionLevel" => 8,
            _ => return Err(KmsDenied),
        };
        if seen & bit != 0 {
            return Err(KmsDenied);
        }
        seen |= bit;
        match bit {
            1 => plaintext = Some(c.string()?),
            2 => crc = Some(c.string()?),
            4 => c.boolean()?,
            8 => {
                if !matches!(
                    c.string()?,
                    "SOFTWARE" | "HSM" | "EXTERNAL" | "EXTERNAL_VPC"
                ) {
                    return Err(KmsDenied);
                }
            }
            _ => unreachable!(),
        }
        c.space();
        match c.bytes.get(c.at) {
            Some(b',') => c.at += 1,
            Some(b'}') => {
                c.at += 1;
                break;
            }
            _ => return Err(KmsDenied),
        }
    }
    c.space();
    if c.at != bytes.len() {
        return Err(KmsDenied);
    }
    Ok(DecryptReply {
        plaintext: plaintext.ok_or(KmsDenied)?,
        plaintext_crc32c: crc.ok_or(KmsDenied)?,
    })
}
#[cfg(test)]
mod tests;
