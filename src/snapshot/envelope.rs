//! term.so snapshot object wrapper (plan r8 "Snapshot store: format and
//! lineage"), the Rust counterpart of the Go reference implementation in
//! zippy's internal/snapcrypto. Every snapshot object is client-side
//! encrypted before upload: a 53-byte unauthenticated preamble of hints,
//! then DARE 1.0 packages (version 0x10, cipher AES-256_GCM = 0x00) keyed
//! by a stream key unique to the object. Package 0 is the framed identity
//! manifest, the final package is the framed completion trailer, and an
//! empty object is one combined package.
//!
//! The DARE 1.0 package codec is implemented directly because a streaming
//! AEAD API cannot force the package boundaries this format mandates
//! (package 0 alone, trailer package alone, exact sequence). Byte-exact
//! interop with the Go implementation is proven by the pinned vectors in
//! src/snapshot/testdata/wrapper_vectors.json (written by the Go
//! reference): this writer reproduces them exactly, and this reader
//! authenticates them back.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io;

/// Object classes carried in the preamble and the identity manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
    Layer = 1,
    Record = 2,
    Alias = 3,
    Artifact = 4,
}

impl Class {
    fn from_u8(v: u8) -> Result<Class, Error> {
        match v {
            1 => Ok(Class::Layer),
            2 => Ok(Class::Record),
            3 => Ok(Class::Alias),
            4 => Ok(Class::Artifact),
            _ => Err(Error::Preamble(format!("class {v}"))),
        }
    }
}

pub const PREAMBLE_SIZE: usize = 53;
pub const MAX_PAYLOAD_SIZE: usize = 65536;
const MAX_MANIFEST_FRAME: usize = 4096;
const PREAMBLE_MAGIC: &[u8; 3] = b"TE1";
const PREAMBLE_VERSION: u8 = 4;
const DARE_VERSION_10: u8 = 0x10;
const CIPHER_AES_256_GCM: u8 = 0x00;
const HEADER_SIZE: usize = 16;
const TAG_SIZE: usize = 16;
const MASTER_KEY_INFO: &[u8] = b"termso/snap-obj/v1";
const STREAM_KEY_INFO: &[u8] = b"termso/snap-dare/v1";

/// Sentinel error classes; every rejection maps to exactly one, mirroring
/// the Go reference's err_* sentinels.
#[derive(Debug)]
pub enum Error {
    Preamble(String),
    DareVersion(String),
    CipherSuite(String),
    PayloadLength(String),
    PackageOrder(String),
    TagMismatch(String),
    Manifest(String),
    TruncatedStream(String),
    TrailingBytes(String),
    Context(String),
    KeyLength(String),
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, detail) = match self {
            Error::Preamble(d) => ("err_preamble", d),
            Error::DareVersion(d) => ("err_dare_version", d),
            Error::CipherSuite(d) => ("err_cipher_suite", d),
            Error::PayloadLength(d) => ("err_payload_length", d),
            Error::PackageOrder(d) => ("err_package_out_of_order", d),
            Error::TagMismatch(d) => ("err_tag_mismatch", d),
            Error::Manifest(d) => ("err_manifest", d),
            Error::TruncatedStream(d) => ("err_truncated_stream", d),
            Error::TrailingBytes(d) => ("err_trailing_bytes", d),
            Error::Context(d) => ("err_context", d),
            Error::KeyLength(d) => ("err_key_length", d),
            Error::Io(e) => return write!(f, "snapcrypto: io: {e}"),
        };
        write!(f, "snapcrypto: {name}: {detail}")
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

/// Framed package-0 identity, framed trailer, or the combined
/// identity+trailer of an empty object. Field order matches the Go
/// reference's canonical JSON exactly.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Manifest {
    pub class: u8,
    pub tenant: String,
    pub volume: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub plaintext_length: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub snapshot_id: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub alias: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub object_path: String,
    #[serde(skip_serializing_if = "is_false", default)]
    pub trailer: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub total_packages: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub total_plaintext_length: Option<i64>,
}

fn is_false(v: &bool) -> bool {
    !*v
}

/// The 53-byte unauthenticated hint block. It is never authority: a
/// tampered preamble derives the wrong stream key (the first tag fails) or
/// mismatches the authenticated package-0 manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preamble {
    pub class: Class,
    pub volume_fp: [u8; 8],
    pub master_key_fp: [u8; 8],
    pub salt: [u8; 32],
}

impl Preamble {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PREAMBLE_SIZE);
        out.extend_from_slice(PREAMBLE_MAGIC);
        out.push(PREAMBLE_VERSION);
        out.push(self.class as u8);
        out.extend_from_slice(&self.volume_fp);
        out.extend_from_slice(&self.master_key_fp);
        out.extend_from_slice(&self.salt);
        out
    }

    fn decode(b: &[u8]) -> Result<Preamble, Error> {
        if b.len() < PREAMBLE_SIZE {
            return Err(Error::Preamble(format!("short preamble {}", b.len())));
        }
        if &b[..3] != PREAMBLE_MAGIC {
            return Err(Error::Preamble("bad magic".to_string()));
        }
        if b[3] != PREAMBLE_VERSION {
            return Err(Error::Preamble(format!("preamble version {}", b[3])));
        }
        let mut p = Preamble {
            class: Class::from_u8(b[4])?,
            volume_fp: [0; 8],
            master_key_fp: [0; 8],
            salt: [0; 32],
        };
        p.volume_fp.copy_from_slice(&b[5..13]);
        p.master_key_fp.copy_from_slice(&b[13..21]);
        p.salt.copy_from_slice(&b[21..PREAMBLE_SIZE]);
        Ok(p)
    }
}

/// Derives the publisher-held per-volume envelope master key from the
/// volume DEK: HKDF-SHA256(DEK, "termso/snap-obj/v1" ‖ volume_id).
pub fn master_key(dek: &[u8], volume_id: &str) -> Result<[u8; 32], Error> {
    if dek.is_empty() || volume_id.is_empty() {
        return Err(Error::KeyLength(
            "dek and volume id are required".to_string(),
        ));
    }
    let mut info = Vec::with_capacity(MASTER_KEY_INFO.len() + volume_id.len());
    info.extend_from_slice(MASTER_KEY_INFO);
    info.extend_from_slice(volume_id.as_bytes());
    let hk = Hkdf::<Sha256>::new(None, dek);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .map_err(|_| Error::KeyLength("hkdf expand".to_string()))?;
    Ok(out)
}

/// Derives the per-object DARE key from the master key and the object's
/// random salt: HKDF-SHA256(master_key, salt, "termso/snap-dare/v1"). A
/// fresh random salt per write makes stream-key reuse impossible by
/// construction; a retried upload draws a new salt.
pub fn stream_key(master: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let mut out = [0u8; 32];
    hk.expand(STREAM_KEY_INFO, &mut out)
        .expect("hkdf expand 32 bytes");
    out
}

/// The preamble's opaque volume hint: SHA256(tenant_id ‖ volume_id)[0:8].
pub fn volume_fingerprint(tenant_id: &str, volume_id: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(tenant_id.as_bytes());
    h.update(volume_id.as_bytes());
    let sum = h.finalize();
    let mut fp = [0u8; 8];
    fp.copy_from_slice(&sum[..8]);
    fp
}

/// The preamble's opaque key hint: SHA256(master_key)[0:8].
pub fn master_key_fingerprint(master: &[u8; 32]) -> [u8; 8] {
    let sum = Sha256::digest(master);
    let mut fp = [0u8; 8];
    fp.copy_from_slice(&sum[..8]);
    fp
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// sha256 of the empty payload, the trailer digest of every empty object.
pub fn empty_sha256() -> &'static str {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}

/// Seals one DARE 1.0 package onto dst.
pub(crate) fn dare_seal(
    dst: &mut Vec<u8>,
    key: &[u8; 32],
    rand_val: &[u8; 8],
    seq: u32,
    payload: &[u8],
) -> Result<(), Error> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD_SIZE {
        return Err(Error::PayloadLength(format!(
            "package payload {}",
            payload.len()
        )));
    }
    let aead = Aes256Gcm::new_from_slice(key).map_err(|e| Error::KeyLength(e.to_string()))?;
    let start = dst.len();
    dst.resize(start + HEADER_SIZE, 0);
    let mut h = [0u8; HEADER_SIZE];
    h[0] = DARE_VERSION_10;
    h[1] = CIPHER_AES_256_GCM;
    h[2..4].copy_from_slice(&((payload.len() - 1) as u16).to_le_bytes());
    h[4..8].copy_from_slice(&seq.to_le_bytes());
    h[8..16].copy_from_slice(rand_val);
    let ct = aead
        .encrypt(
            aes_gcm::Nonce::from_slice(&h[4..16]),
            Payload {
                msg: payload,
                aad: &h[..4],
            },
        )
        .map_err(|e| Error::TagMismatch(e.to_string()))?;
    dst[start..start + HEADER_SIZE].copy_from_slice(&h);
    dst.extend_from_slice(&ct);
    Ok(())
}

/// Parses and authenticates exactly one DARE 1.0 package at the head of r,
/// verifying the expected sequence number before any plaintext is
/// returned. Ok(None) signals zero bytes before a header; a partial
/// package is err_truncated_stream.
pub(crate) fn dare_open(
    r: &mut dyn io::Read,
    key: &[u8; 32],
    expected_seq: u32,
) -> Result<Option<Vec<u8>>, Error> {
    let aead = Aes256Gcm::new_from_slice(key).map_err(|e| Error::KeyLength(e.to_string()))?;
    let mut h = [0u8; HEADER_SIZE];
    match read_full_or_eof(r, &mut h)? {
        0 => return Ok(None),
        n if n == HEADER_SIZE => {}
        _ => return Err(Error::TruncatedStream("package header".to_string())),
    }
    if h[0] != DARE_VERSION_10 {
        return Err(Error::DareVersion(format!("0x{:02x}", h[0])));
    }
    if h[1] != CIPHER_AES_256_GCM {
        return Err(Error::CipherSuite(format!("0x{:02x}", h[1])));
    }
    let payload_len = u16::from_le_bytes([h[2], h[3]]) as usize + 1;
    let seq = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
    if seq != expected_seq {
        return Err(Error::PackageOrder(format!(
            "package {seq}, expected {expected_seq}"
        )));
    }
    let mut body = vec![0u8; payload_len + TAG_SIZE];
    if read_full_or_eof(r, &mut body)? != body.len() {
        return Err(Error::TruncatedStream("package body".to_string()));
    }
    let payload = aead
        .decrypt(
            aes_gcm::Nonce::from_slice(&h[4..16]),
            Payload {
                msg: &body,
                aad: &h[..4],
            },
        )
        .map_err(|_| Error::TagMismatch(format!("package {seq}")))?;
    Ok(Some(payload))
}

/// Reads until buf is full or EOF; returns the number of bytes read.
fn read_full_or_eof(r: &mut dyn io::Read, buf: &mut [u8]) -> Result<usize, Error> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(m) => n += m,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(n)
}

/// Encodes u16_be length ‖ JSON, rejecting frames over MAX_MANIFEST_FRAME.
fn frame(m: &Manifest) -> Result<Vec<u8>, Error> {
    let body =
        serde_json::to_vec(m).map_err(|e| Error::Manifest(format!("manifest marshal: {e}")))?;
    if body.len() > MAX_MANIFEST_FRAME {
        return Err(Error::Manifest(format!(
            "manifest frame {} > {MAX_MANIFEST_FRAME}",
            body.len()
        )));
    }
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parses exactly one frame; the payload must contain the frame and
/// nothing else.
fn deframe(payload: &[u8]) -> Result<Manifest, Error> {
    if payload.len() < 2 {
        return Err(Error::Manifest("short frame".to_string()));
    }
    let n = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if n > MAX_MANIFEST_FRAME {
        return Err(Error::Manifest(format!("frame {n} > {MAX_MANIFEST_FRAME}")));
    }
    if payload.len() - 2 != n {
        return Err(Error::Manifest(format!(
            "frame length {n}, payload {}",
            payload.len() - 2
        )));
    }
    serde_json::from_slice(&payload[2..])
        .map_err(|e| Error::Manifest(format!("manifest JSON: {e}")))
}

/// Enforces per-class identity fields on a package-0 manifest (or the
/// identity half of a combined empty-object package).
fn validate_identity(m: &Manifest) -> Result<(), Error> {
    let class =
        Class::from_u8(m.class).map_err(|_| Error::Manifest(format!("class {}", m.class)))?;
    if m.tenant.is_empty() || m.volume.is_empty() {
        return Err(Error::Manifest("tenant/volume required".to_string()));
    }
    let has_layer_fields = !m.sha256.is_empty() || m.plaintext_length.is_some();
    match class {
        Class::Layer => {
            if m.sha256.is_empty() || m.plaintext_length.is_none_or(|n| n < 0) {
                return Err(Error::Manifest(
                    "layer identity needs sha256 and plaintext_length".to_string(),
                ));
            }
            if !m.snapshot_id.is_empty() || !m.alias.is_empty() || !m.object_path.is_empty() {
                return Err(Error::Manifest(
                    "layer carries record/alias/artifact fields".to_string(),
                ));
            }
        }
        Class::Record => {
            if m.snapshot_id.is_empty() || !m.alias.is_empty() || !m.object_path.is_empty() {
                return Err(Error::Manifest(
                    "record identity is exactly snapshot_id".to_string(),
                ));
            }
            if !m.trailer && has_layer_fields {
                return Err(Error::Manifest(
                    "record identity carries layer fields".to_string(),
                ));
            }
        }
        Class::Alias => {
            if m.snapshot_id.is_empty() || m.alias.is_empty() || !m.object_path.is_empty() {
                return Err(Error::Manifest(
                    "alias identity is exactly alias + snapshot_id".to_string(),
                ));
            }
            if !m.trailer && has_layer_fields {
                return Err(Error::Manifest(
                    "alias identity carries layer fields".to_string(),
                ));
            }
        }
        Class::Artifact => {
            if m.snapshot_id.is_empty() || m.object_path.is_empty() || !m.alias.is_empty() {
                return Err(Error::Manifest(
                    "artifact identity is exactly snapshot_id + object_path".to_string(),
                ));
            }
            if !m.trailer && has_layer_fields {
                return Err(Error::Manifest(
                    "artifact identity carries layer fields".to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// Enforces the trailer fields and the three-way completion equality
/// (package count, plaintext length, payload digest).
fn validate_trailer(
    m: &Manifest,
    total_packages: i64,
    plaintext_length: i64,
    payload_sha256: &str,
) -> Result<(), Error> {
    if !m.trailer
        || m.total_packages.is_none()
        || m.total_plaintext_length.is_none()
        || m.sha256.is_empty()
    {
        return Err(Error::Manifest(
            "trailer needs trailer/total_packages/total_plaintext_length/sha256".to_string(),
        ));
    }
    if m.total_packages != Some(total_packages) {
        return Err(Error::Manifest(format!(
            "trailer total_packages {:?}, stream {total_packages}",
            m.total_packages
        )));
    }
    if m.total_plaintext_length != Some(plaintext_length) {
        return Err(Error::Manifest(format!(
            "trailer total_plaintext_length {:?}, stream {plaintext_length}",
            m.total_plaintext_length
        )));
    }
    if m.sha256 != payload_sha256 {
        return Err(Error::Manifest(
            "trailer payload digest mismatch".to_string(),
        ));
    }
    Ok(())
}

/// One object to encrypt. Layer objects carry their plaintext digest and
/// length in the identity manifest, so the caller supplies them and the
/// writer proves the streamed payload matches before sealing the trailer.
#[derive(Debug, Clone)]
pub struct WriteConfig {
    pub class: Class,
    pub tenant: String,
    pub volume: String,
    pub master_key: [u8; 32],
    pub snapshot_id: String,
    pub alias: String,
    pub object_path: String,
    pub layer_sha256: String,
    pub plaintext_length: Option<i64>,
}

impl WriteConfig {
    pub fn new(class: Class, tenant: &str, volume: &str, master_key: [u8; 32]) -> WriteConfig {
        WriteConfig {
            class,
            tenant: tenant.to_string(),
            volume: volume.to_string(),
            master_key,
            snapshot_id: String::new(),
            alias: String::new(),
            object_path: String::new(),
            layer_sha256: String::new(),
            plaintext_length: None,
        }
    }

    fn identity(&self) -> Manifest {
        Manifest {
            class: self.class as u8,
            tenant: self.tenant.clone(),
            volume: self.volume.clone(),
            sha256: self.layer_sha256.clone(),
            plaintext_length: self.plaintext_length,
            snapshot_id: self.snapshot_id.clone(),
            alias: self.alias.clone(),
            object_path: self.object_path.clone(),
            trailer: false,
            total_packages: None,
            total_plaintext_length: None,
        }
    }
}

/// What was sealed.
#[derive(Debug, Clone)]
pub struct WriteResult {
    pub preamble: Preamble,
    pub payload_sha256: String,
    pub plaintext_length: i64,
    pub total_packages: i64,
    pub object_size: i64,
}

/// Encrypts src as one object per the wrapper layout with an explicit salt
/// and DARE nonce value (the deterministic form used by vectors); an empty
/// src produces the combined manifest+trailer single-package form. A layer
/// whose streamed bytes do not match the claimed digest/length fails
/// before the trailer is sealed; the partial output in dst is never a
/// valid object. Production callers draw salt and nonce value from the OS
/// RNG per write and never reuse either.
pub fn write_object_with_nonce(
    dst: &mut dyn io::Write,
    src: &mut dyn io::Read,
    cfg: &WriteConfig,
    salt: [u8; 32],
    rand_val: [u8; 8],
) -> Result<WriteResult, Error> {
    let identity = cfg.identity();
    validate_identity(&identity)?;
    let stream_key = stream_key(&cfg.master_key, &salt);
    let pre = Preamble {
        class: cfg.class,
        volume_fp: volume_fingerprint(&cfg.tenant, &cfg.volume),
        master_key_fp: master_key_fingerprint(&cfg.master_key),
        salt,
    };

    let mut first = vec![0u8; MAX_PAYLOAD_SIZE];
    let n_first = read_full_or_eof(src, &mut first)?;
    first.truncate(n_first);

    let mut seq: u32 = 0;
    let mut out = pre.encode();
    let mut res = WriteResult {
        preamble: pre,
        payload_sha256: String::new(),
        plaintext_length: 0,
        total_packages: 0,
        object_size: 0,
    };

    if n_first == 0 {
        // Empty object: one combined identity+trailer package.
        let mut combined = identity.clone();
        combined.trailer = true;
        combined.total_packages = Some(1);
        combined.total_plaintext_length = Some(0);
        combined.sha256 = empty_sha256().to_string();
        if cfg.class == Class::Layer {
            if cfg.plaintext_length != Some(0) || cfg.layer_sha256 != empty_sha256() {
                return Err(Error::Manifest(
                    "empty layer must claim sha256(empty) and length 0".to_string(),
                ));
            }
            combined.plaintext_length = Some(0);
        }
        let framed = frame(&combined)?;
        dare_seal(&mut out, &stream_key, &rand_val, seq, &framed)?;
        res.payload_sha256 = empty_sha256().to_string();
        res.total_packages = 1;
        dst.write_all(&out)?;
        res.object_size = out.len() as i64;
        return Ok(res);
    }

    let identity_frame = frame(&identity)?;
    dare_seal(&mut out, &stream_key, &rand_val, seq, &identity_frame)?;
    seq += 1;

    let mut digest = Sha256::new();
    let mut payload_len: i64 = 0;
    let mut chunk = first;
    let mut buf = vec![0u8; MAX_PAYLOAD_SIZE];
    loop {
        digest.update(&chunk);
        payload_len += chunk.len() as i64;
        dare_seal(&mut out, &stream_key, &rand_val, seq, &chunk)?;
        seq += 1;
        let n = read_full_or_eof(src, &mut buf)?;
        if n == 0 {
            break;
        }
        chunk = buf[..n].to_vec();
    }

    let payload_sha256 = hex::encode(digest.finalize());
    if cfg.class == Class::Layer
        && (cfg.plaintext_length != Some(payload_len) || cfg.layer_sha256 != payload_sha256)
    {
        return Err(Error::Manifest(format!(
            "layer streamed {payload_len} bytes {payload_sha256:?}, manifest claimed {:?} {:?}",
            cfg.plaintext_length, cfg.layer_sha256
        )));
    }
    let trailer = Manifest {
        trailer: true,
        total_packages: Some(i64::from(seq) + 1),
        total_plaintext_length: Some(payload_len),
        sha256: payload_sha256.clone(),
        ..Default::default()
    };
    let trailer_frame = frame(&trailer)?;
    dare_seal(&mut out, &stream_key, &rand_val, seq, &trailer_frame)?;
    res.payload_sha256 = payload_sha256;
    res.plaintext_length = payload_len;
    res.total_packages = i64::from(seq) + 1;
    dst.write_all(&out)?;
    res.object_size = out.len() as i64;
    Ok(res)
}

/// The reader's expected context. Master key, tenant and volume are
/// required; the preamble fingerprints are checked against them as hints
/// (a mismatch guarantees tag failure, so it is rejected at the preamble).
/// Identity fields that are set must match the authenticated manifest
/// exactly; unset fields are not asserted (catalog discovery).
#[derive(Debug, Clone)]
pub struct ExpectConfig {
    pub class: Class,
    pub tenant: String,
    pub volume: String,
    pub master_key: [u8; 32],
    pub snapshot_id: Option<String>,
    pub alias: Option<String>,
    pub object_path: Option<String>,
}

impl ExpectConfig {
    pub fn new(class: Class, tenant: &str, volume: &str, master_key: [u8; 32]) -> ExpectConfig {
        ExpectConfig {
            class,
            tenant: tenant.to_string(),
            volume: volume.to_string(),
            master_key,
            snapshot_id: None,
            alias: None,
            object_path: None,
        }
    }
}

/// The authenticated object.
#[derive(Debug, Clone)]
pub struct ReadResult {
    pub manifest: Manifest,
    pub payload_sha256: String,
    pub plaintext_length: i64,
    pub total_packages: i64,
}

/// Authenticates and decrypts one object from src, writing the verified
/// payload to dst. The payload is emitted per package only after that
/// package's tag verifies, and the trailer's three fields are verified
/// before returning: on any error the caller MUST discard whatever dst
/// received, because a prefix without a trailer is never a valid object.
/// The stream must end exactly on the trailer's package boundary.
pub fn read_object(
    dst: &mut dyn io::Write,
    src: &mut dyn io::Read,
    expect: &ExpectConfig,
) -> Result<ReadResult, Error> {
    let mut pre_bytes = [0u8; PREAMBLE_SIZE];
    if read_full_or_eof(src, &mut pre_bytes)? != PREAMBLE_SIZE {
        return Err(Error::Preamble("short preamble".to_string()));
    }
    let pre = Preamble::decode(&pre_bytes)?;
    if pre.class != expect.class {
        return Err(Error::Context(format!(
            "preamble class {:?}, expected {:?}",
            pre.class, expect.class
        )));
    }
    if expect.tenant.is_empty() || expect.volume.is_empty() {
        return Err(Error::Context(
            "tenant/volume expectation required".to_string(),
        ));
    }
    if pre.volume_fp != volume_fingerprint(&expect.tenant, &expect.volume) {
        return Err(Error::Context("volume fingerprint hint".to_string()));
    }
    if pre.master_key_fp != master_key_fingerprint(&expect.master_key) {
        return Err(Error::Context("master key fingerprint hint".to_string()));
    }
    let stream_key = stream_key(&expect.master_key, &pre.salt);

    let mut seq: u32 = 0;
    let manifest_payload = dare_open(src, &stream_key, seq)?
        .ok_or_else(|| Error::TruncatedStream("no identity package".to_string()))?;
    seq += 1;
    let identity = deframe(&manifest_payload)?;
    validate_identity(&identity)?;
    if identity.class != expect.class as u8 {
        return Err(Error::Context(format!(
            "manifest class {}, expected {}",
            identity.class, expect.class as u8
        )));
    }
    if identity.tenant != expect.tenant || identity.volume != expect.volume {
        return Err(Error::Context("manifest tenant/volume".to_string()));
    }
    if let Some(want) = &expect.snapshot_id {
        if identity.snapshot_id != *want {
            return Err(Error::Context("snapshot_id".to_string()));
        }
    }
    if let Some(want) = &expect.alias {
        if identity.alias != *want {
            return Err(Error::Context("alias".to_string()));
        }
    }
    if let Some(want) = &expect.object_path {
        if identity.object_path != *want {
            return Err(Error::Context("object_path".to_string()));
        }
    }

    let mut res = ReadResult {
        manifest: identity.clone(),
        payload_sha256: String::new(),
        plaintext_length: 0,
        total_packages: 0,
    };

    if identity.trailer {
        // Combined empty form: exactly one package, zero payload bytes.
        validate_trailer(&identity, i64::from(seq), 0, empty_sha256())?;
        if identity.class == Class::Layer as u8 && identity.plaintext_length != Some(0) {
            return Err(Error::Manifest(
                "empty layer claims nonzero length".to_string(),
            ));
        }
        expect_exact_eof(src)?;
        res.payload_sha256 = empty_sha256().to_string();
        res.total_packages = i64::from(seq);
        return Ok(res);
    }

    // One package lookahead: the last package before a clean EOF is the
    // trailer. Bytes trailing a valid trailer cannot parse as a further
    // package: a partial header is err_truncated_stream and a forged whole
    // package fails its tag.
    let mut digest = Sha256::new();
    let mut payload_len: i64 = 0;
    let mut pending = dare_open(src, &stream_key, seq)?
        .ok_or_else(|| Error::TruncatedStream("no trailer package".to_string()))?;
    seq += 1;
    loop {
        let next = match dare_open(src, &stream_key, seq)? {
            None => break,
            Some(p) => p,
        };
        seq += 1;
        dst.write_all(&pending)?;
        digest.update(&pending);
        payload_len += pending.len() as i64;
        pending = next;
    }
    let trailer = deframe(&pending)?;
    let payload_sha256 = hex::encode(digest.finalize());
    validate_trailer(&trailer, i64::from(seq), payload_len, &payload_sha256)?;
    if identity.class == Class::Layer as u8
        && (identity.plaintext_length != Some(payload_len) || identity.sha256 != payload_sha256)
    {
        return Err(Error::Manifest("layer manifest vs payload".to_string()));
    }
    res.payload_sha256 = payload_sha256;
    res.plaintext_length = payload_len;
    res.total_packages = i64::from(seq);
    Ok(res)
}

/// Rejects any trailing byte after the single combined package of an empty
/// object.
fn expect_exact_eof(r: &mut dyn io::Read) -> Result<(), Error> {
    let mut b = [0u8; 1];
    let n = r.read(&mut b)?;
    if n > 0 {
        return Err(Error::TrailingBytes(String::new()));
    }
    Ok(())
}

/// One record-body layer entry; an encrypted layer object's identity
/// manifest and payload must match all three fields.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct LayerExpectation {
    pub digest: String,
    pub enc: bool,
    pub plaintext_length: i64,
}

/// One record-body artifact entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ArtifactExpectation {
    pub path: String,
    pub length: i64,
    pub sha256: String,
}

/// The encrypted record payload: ordered layer list, artifact list, and
/// the template lineage root the plaintext layers must descend from.
/// record_digest = sha256 of this body's canonical JSON — the grant-pinned
/// authentication root kept outside the store.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct RecordBody {
    pub layers: Vec<LayerExpectation>,
    pub artifacts: Vec<ArtifactExpectation>,
    pub template_lineage_root: String,
}

impl RecordBody {
    /// Deterministic compact JSON (struct field order); both the publisher
    /// and the restore verifier digest these exact bytes.
    pub fn canonical_json(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|e| Error::Manifest(format!("record body marshal: {e}")))
    }

    /// The record's grant-pinned plaintext digest.
    pub fn digest(&self) -> Result<String, Error> {
        Ok(sha256_hex(&self.canonical_json()?))
    }

    /// Enforces the restore lineage rules on an authenticated record body:
    /// the record's template lineage root must equal the grant pin — a
    /// matching label is not lineage proof. Plaintext (enc:false) layers
    /// are REFUSED outright: membership in the immutable template lineage
    /// can only be proven against a verified immutable template manifest,
    /// which this layer of the stack does not hold, so enc:false alone
    /// authenticates nothing. When that manifest/proof seam lands, this
    /// check grows to verify each plaintext layer's identity, order and
    /// length against it instead of refusing.
    pub fn verify_against_grant(&self, pinned_template_lineage_root: &str) -> Result<(), Error> {
        if self.template_lineage_root.is_empty()
            || self.template_lineage_root != pinned_template_lineage_root
        {
            return Err(Error::Context("template_lineage_root".to_string()));
        }
        for (i, l) in self.layers.iter().enumerate() {
            if l.digest.is_empty() || l.plaintext_length < 0 {
                return Err(Error::Manifest("malformed layer expectation".to_string()));
            }
            if !l.enc {
                return Err(Error::Context(format!(
                    "plaintext layer {i} has no membership proof against the pinned lineage"
                )));
            }
        }
        Ok(())
    }

    /// Checks a layer object's authenticated identity and payload against
    /// the record's ordered expectations (position matters). Plaintext
    /// lineage layers (enc:false) are not objects and have no object to
    /// verify.
    pub fn verify_layer(
        &self,
        position: usize,
        manifest: &Manifest,
        payload_sha256: &str,
        payload_len: i64,
    ) -> Result<(), Error> {
        let exp = self
            .layers
            .get(position)
            .ok_or_else(|| Error::Context(format!("layer position {position} outside record")))?;
        if !exp.enc {
            return Err(Error::Context(format!(
                "layer {position} is a plaintext lineage layer, not an object"
            )));
        }
        if exp.digest != payload_sha256 || exp.plaintext_length != payload_len {
            return Err(Error::Context(format!(
                "layer {position} expectation mismatch"
            )));
        }
        if manifest.class != Class::Layer as u8
            || manifest.sha256 != exp.digest
            || manifest.plaintext_length != Some(exp.plaintext_length)
        {
            return Err(Error::Manifest(format!(
                "layer {position} manifest mismatch"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    include!("envelope_tests.rs");
}
