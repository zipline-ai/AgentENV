//! term.so snapshot object wrapper (plan r8 "Snapshot store: format and
//! lineage"), the Rust counterpart of the Go reference implementation in
//! zippy's internal/snapcrypto. Every snapshot object is client-side
//! encrypted before upload: a 53-byte unauthenticated preamble of hints,
//! then DARE 1.0 packages (version 0x10, cipher AES-256_GCM = 0x00) keyed
//! by a stream key unique to the object. Package 0 is the framed identity
//! manifest, the final package is the framed completion trailer, and an
//! empty object is one combined package.
//!
//! Byte-exact interop with the Go implementation is proven by the pinned
//! vectors in src/snapshot/testdata/wrapper_vectors.json (written by the Go
//! reference): this writer reproduces them exactly, and this reader
//! authenticates them back.

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

/// The 53-byte unauthenticated hint block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preamble {
    pub class: Class,
    pub volume_fp: [u8; 8],
    pub master_key_fp: [u8; 8],
    pub salt: [u8; 32],
}

/// Derives the publisher-held per-volume envelope master key from the
/// volume DEK: HKDF-SHA256(DEK, "termso/snap-obj/v1" ‖ volume_id).
pub fn master_key(dek: &[u8], volume_id: &str) -> Result<[u8; 32], Error> {
    let _ = (dek, volume_id);
    unimplemented!("stage 2")
}

/// Derives the per-object DARE key from the master key and the object's
/// random salt: HKDF-SHA256(master_key, salt, "termso/snap-dare/v1").
pub fn stream_key(master: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let _ = (master, salt);
    unimplemented!("stage 2")
}

/// The preamble's opaque volume hint: SHA256(tenant_id ‖ volume_id)[0:8].
pub fn volume_fingerprint(tenant_id: &str, volume_id: &str) -> [u8; 8] {
    let _ = (tenant_id, volume_id);
    unimplemented!("stage 2")
}

/// The preamble's opaque key hint: SHA256(master_key)[0:8].
pub fn master_key_fingerprint(master: &[u8; 32]) -> [u8; 8] {
    let _ = master;
    unimplemented!("stage 2")
}

/// Seals one DARE 1.0 package onto dst.
pub(crate) fn dare_seal(
    dst: &mut Vec<u8>,
    key: &[u8; 32],
    rand_val: &[u8; 8],
    seq: u32,
    payload: &[u8],
) -> Result<(), Error> {
    let _ = (dst, key, rand_val, seq, payload);
    unimplemented!("stage 2")
}

/// Parses and authenticates exactly one DARE 1.0 package; Ok(None) is a
/// clean end of stream before a header.
pub(crate) fn dare_open(
    r: &mut dyn io::Read,
    key: &[u8; 32],
    expected_seq: u32,
) -> Result<Option<Vec<u8>>, Error> {
    let _ = (r, key, expected_seq);
    unimplemented!("stage 2")
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
/// src produces the combined manifest+trailer single-package form.
pub fn write_object_with_nonce(
    dst: &mut dyn io::Write,
    src: &mut dyn io::Read,
    cfg: &WriteConfig,
    salt: [u8; 32],
    rand_val: [u8; 8],
) -> Result<WriteResult, Error> {
    let _ = (dst, src, cfg, salt, rand_val);
    unimplemented!("stage 2")
}

/// The reader's expected context. Master key, tenant and volume are
/// required; identity fields that are set must match the authenticated
/// manifest exactly (unset fields are not asserted — catalog discovery).
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
pub fn read_object(
    dst: &mut dyn io::Write,
    src: &mut dyn io::Read,
    expect: &ExpectConfig,
) -> Result<ReadResult, Error> {
    let _ = (dst, src, expect);
    unimplemented!("stage 2")
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
        let _ = self;
        unimplemented!("stage 2")
    }

    /// The record's grant-pinned plaintext digest.
    pub fn digest(&self) -> Result<String, Error> {
        let _ = self;
        unimplemented!("stage 2")
    }

    /// Enforces the restore lineage rules: the record's template lineage
    /// root must equal the grant pin, and every plaintext (enc:false)
    /// layer is refused outright — membership in the immutable template
    /// lineage can only be proven against a verified immutable template
    /// manifest, which does not exist here yet.
    pub fn verify_against_grant(&self, pinned_template_lineage_root: &str) -> Result<(), Error> {
        let _ = (self, pinned_template_lineage_root);
        unimplemented!("stage 2")
    }

    /// Checks a layer object's authenticated identity and payload against
    /// the record's ordered expectations (position matters).
    pub fn verify_layer(
        &self,
        position: usize,
        manifest: &Manifest,
        payload_sha256: &str,
        payload_len: i64,
    ) -> Result<(), Error> {
        let _ = (self, position, manifest, payload_sha256, payload_len);
        unimplemented!("stage 2")
    }
}

/// sha256 of the empty payload, the trailer digest of every empty object.
pub fn empty_sha256() -> &'static str {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let _ = bytes;
    unimplemented!("stage 2")
}

#[cfg(test)]
mod tests {
    include!("envelope_tests.rs");
}
