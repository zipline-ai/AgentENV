// Wrapper test suite: known-answer vectors (sio's DARE 1.0 set and the
// pinned wrapper set written by the Go reference), interop, uniqueness,
// and the adversarial parse matrix. Included from envelope.rs.

use super::*;
use std::io::Read as _;

fn test_master() -> [u8; 32] {
    let raw = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let mut m = [0u8; 32];
    m.copy_from_slice(&raw);
    m
}

fn write_config_for(class: Class, master: [u8; 32]) -> WriteConfig {
    let mut cfg = WriteConfig::new(class, "ten_kat", "vol_kat", master);
    match class {
        Class::Record | Class::Alias | Class::Artifact => cfg.snapshot_id = "snap_kat".to_string(),
        _ => {}
    }
    match class {
        Class::Alias => cfg.alias = "termso-kat-g1".to_string(),
        Class::Artifact => cfg.object_path = "/home/user/.config/app/token".to_string(),
        _ => {}
    }
    cfg
}

fn expect_for(class: Class, master: [u8; 32]) -> ExpectConfig {
    let mut e = ExpectConfig::new(class, "ten_kat", "vol_kat", master);
    match class {
        Class::Record | Class::Alias | Class::Artifact => e.snapshot_id = Some("snap_kat".to_string()),
        _ => {}
    }
    match class {
        Class::Alias => e.alias = Some("termso-kat-g1".to_string()),
        Class::Artifact => e.object_path = Some("/home/user/.config/app/token".to_string()),
        _ => {}
    }
    e
}

fn layer_config(master: [u8; 32], payload: &[u8]) -> WriteConfig {
    let mut cfg = write_config_for(Class::Layer, master);
    cfg.layer_sha256 = sha256_hex(payload);
    cfg.plaintext_length = Some(payload.len() as i64);
    cfg
}

fn write_one(cfg: &WriteConfig, payload: &[u8], salt: [u8; 32], rand_val: [u8; 8]) -> (Vec<u8>, WriteResult) {
    let mut buf = Vec::new();
    let res = write_object_with_nonce(&mut buf, &mut io::Cursor::new(payload), cfg, salt, rand_val)
        .expect("write_object");
    (buf, res)
}

fn read_one(object: &[u8], expect: &ExpectConfig) -> (Vec<u8>, ReadResult) {
    let mut dst = Vec::new();
    let res = read_object(&mut dst, &mut io::Cursor::new(object), expect).expect("read_object");
    (dst, res)
}

fn kat_salt(i: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (j, b) in s.iter_mut().enumerate() {
        *b = i.wrapping_add(j as u8);
    }
    s
}

fn kat_rand_val() -> [u8; 8] {
    [0, 1, 2, 3, 4, 5, 6, 7]
}

/// sio's published DARE 1.0 vectors (github.com/minio/sio v0.4.3
/// dare_test.go goldenTestsV10, even indices are AES_256_GCM): each golden
/// package authenticates to a zero payload, and re-sealing the same inputs
/// reproduces the exact bytes. The invalid vectors are rejected at their
/// named layer.
#[test]
fn dare_known_answer_vectors() {
    let key = test_master();
    let rand_val = kat_rand_val();
    let golden = [
        "100000000000000000010203040506077eda3bd68d5fb40f5579e61ff2c94c5b20",
        "10000200020000000001020304050607426fb9754fa4a3207e3dcf0e15f27660de6235",
        "10000400040000000001020304050607a0f419b01663fe8e4ef68c6a5149b0ad3ba9c53697",
        "10000600060000000001020304050607eac91ebf8257fa7b1ced7e3c6b7344beea4b437a53746b",
        "10000800080000000001020304050607a7cc8d09ab9b585f62b320cbd79ce151b7d8a71a2710fd73bf",
        "10000a000a0000000001020304050607e15d31c60c7da60226b93abeb9c856c4e0055f3dc863b957d73ef6",
        "10000c000c0000000001020304050607a30672aeb9bd814042bf4705b9a1aa08d39e18a110aeba1e5d5fade412",
        "10000e000e0000000001020304050607f560df38a0df89f88abf63ff42baf373e04066e2bf34e3adf308746abf99b4",
        "10001000100000000001020304050607ac8be00b7b8996084d3d2ad1c98c3019d04f896147bb34cc656d46c560caadd4fc",
    ];
    for (i, g) in golden.iter().enumerate() {
        let seq = (i * 2) as u32;
        let ct = hex::decode(g).unwrap();
        let payload = dare_open(&mut io::Cursor::new(&ct), &key, seq)
            .unwrap_or_else(|e| panic!("golden {i}: {e}"))
            .unwrap_or_else(|| panic!("golden {i}: unexpected EOF"));
        assert_eq!(payload.len(), ct.len() - 32, "golden {i} length");
        assert!(payload.iter().all(|b| *b == 0), "golden {i} payload is zeros");
        let mut sealed = Vec::new();
        dare_seal(&mut sealed, &key, &rand_val, seq, &payload).expect("seal");
        assert_eq!(ct, sealed, "golden {i} re-seal is byte-exact");
    }
    let invalid = [
        ("110000000000000000010203040506077eda3bd68d5fb40f5579e61ff2c94c5b20", "version"),
        ("20010100010000000001020304050607cbc0fd42bdb3dc957dfb70ebdba13c56b6d6", "version"),
        ("10020200020000000001020304050607426fb9754fa4a3207e3dcf0e15f27660de6235", "cipher"),
        ("10100300030000000001020304050607bf90f9bac4e1b9a0a107595a2079b93e536fdec3", "cipher"),
        ("10000300040000000001020304050607a0f419b01663fe8e4ef68c6a5149b0ad3ba9c53697", "any"),
        ("100106000500000000010203040506073916788fc83b331e99d827ed23cf712798f90c85a69e", "any"),
        ("10000800090000000001020304050607a7cc8d09ab9b585f62b320cbd79ce151b7d8a71a2710fd73bf", "any"),
        ("10010900070000000001020304050607abbb4f40edecc42ed11f4cb95b159122f1f05cb39dad4ca7cdca", "any"),
        ("10000c000c0000000000020304050607a30672aeb9bd814042bf4705b9a1aa08d39e18a110aeba1e5d5fade412", "any"),
        ("10010d000d00000000010203040506083504246c486df9573588fec833589f550fc0c779b8234075e1d43caca883", "any"),
        ("10000e000e0000000001020304050607e560df38a0df89f88abf63ff42baf373e04066e2bf34e3adf308746abf99b4", "any"),
        ("10001000100000000001020304050607ac8be00b7b8996084d3d2ad1c98c3019d04f896147bb34cc656346c560caadd4fc", "any"),
    ];
    for (i, (g, want)) in invalid.iter().enumerate() {
        let ct = hex::decode(g).unwrap();
        let err = dare_open(&mut io::Cursor::new(&ct), &key, 0).expect_err(&format!("invalid {i} must reject"));
        match *want {
            "version" => assert!(matches!(err, Error::DareVersion(_)), "invalid {i}: {err}"),
            "cipher" => assert!(matches!(err, Error::CipherSuite(_)), "invalid {i}: {err}"),
            _ => {}
        }
    }
}

/// The pinned wrapper vectors, generated once by the Go reference
/// implementation and committed at src/snapshot/testdata/wrapper_vectors.json:
/// the Rust writer reproduces the exact bytes (byte-exact interop with Go
/// in the write direction) and the Rust reader authenticates them back
/// (read direction).
#[test]
fn snapshot_wrapper_known_answer_vectors() {
    #[derive(serde::Deserialize)]
    struct Vector {
        name: String,
        class: u8,
        tenant: String,
        volume: String,
        #[serde(default)]
        snapshot_id: String,
        #[serde(default)]
        alias: String,
        #[serde(default)]
        object_path: String,
        master_key: String,
        salt: String,
        rand_val: String,
        payload: String,
        object: String,
    }
    #[derive(serde::Deserialize)]
    struct File {
        vectors: Vec<Vector>,
    }
    let raw = std::fs::read_to_string("src/snapshot/testdata/wrapper_vectors.json")
        .expect("committed wrapper vectors are required");
    let file: File = serde_json::from_str(&raw).expect("vectors parse");
    assert_eq!(5, file.vectors.len(), "the pinned vector set");
    for v in &file.vectors {
        let master: [u8; 32] = hex::decode(&v.master_key).unwrap().try_into().unwrap();
        let salt: [u8; 32] = hex::decode(&v.salt).unwrap().try_into().unwrap();
        let rand_val: [u8; 8] = hex::decode(&v.rand_val).unwrap().try_into().unwrap();
        let payload = hex::decode(&v.payload).unwrap();
        let want_object = hex::decode(&v.object).unwrap();
        let class = Class::from_u8(v.class).expect("vector class");
        let mut cfg = WriteConfig::new(class, &v.tenant, &v.volume, master);
        cfg.snapshot_id = v.snapshot_id.clone();
        cfg.alias = v.alias.clone();
        cfg.object_path = v.object_path.clone();
        if class == Class::Layer {
            cfg.layer_sha256 = sha256_hex(&payload);
            cfg.plaintext_length = Some(payload.len() as i64);
        }
        let (object, _) = write_one(&cfg, &payload, salt, rand_val);
        assert_eq!(want_object, object, "{}: write is byte-exact with the Go reference", v.name);

        let mut expect = ExpectConfig::new(class, &v.tenant, &v.volume, master);
        if !v.snapshot_id.is_empty() {
            expect.snapshot_id = Some(v.snapshot_id.clone());
        }
        if !v.alias.is_empty() {
            expect.alias = Some(v.alias.clone());
        }
        if !v.object_path.is_empty() {
            expect.object_path = Some(v.object_path.clone());
        }
        let (got, res) = read_one(&want_object, &expect);
        assert_eq!(payload, got, "{}: read-back payload", v.name);
        assert_eq!(sha256_hex(&payload), res.payload_sha256, "{}: trailer digest", v.name);
    }
}

/// Every write draws a fresh salt and derives a distinct stream key; a
/// retried upload of the same plaintext never reuses a stream key, so
/// nonce reuse under one key is impossible by construction.
#[test]
fn dare_stream_key_unique_per_object_write() {
    let master = test_master();
    let cfg = layer_config(master, b"retried upload body");
    let mut salts = std::collections::HashSet::new();
    let mut keys = std::collections::HashSet::new();
    let mut objects = std::collections::HashSet::new();
    for i in 0..64u8 {
        let salt = kat_salt(i);
        let (object, res) = write_one(&cfg, b"retried upload body", salt, kat_rand_val());
        assert!(salts.insert(res.preamble.salt), "salt reused at write {i}");
        assert!(keys.insert(stream_key(&master, &res.preamble.salt)), "stream key reused at write {i}");
        objects.insert(object);
    }
    assert_eq!(64, objects.len(), "every write of the same plaintext differs");
}

/// The empty special form is exactly one package that is both identity
/// manifest and trailer; there is always authenticated identity and
/// completion even with no payload.
#[test]
fn snapshot_empty_object_round_trip() {
    let master = test_master();
    for class in [Class::Artifact, Class::Alias, Class::Record] {
        let cfg = write_config_for(class, master);
        let (object, res) = write_one(&cfg, &[], kat_salt(1), kat_rand_val());
        assert_eq!(1, res.total_packages, "class {class:?}");
        let (payload, got) = read_one(&object, &expect_for(class, master));
        assert!(payload.is_empty(), "class {class:?}");
        assert!(got.manifest.trailer, "class {class:?}");
        assert_eq!(empty_sha256(), got.payload_sha256, "class {class:?}");
        assert_eq!(1, got.total_packages, "class {class:?}");
    }
}

/// An alias object carries its whole content in the authenticated identity
/// manifest — a trailer-only object with zero payload still proves identity
/// and completion.
#[test]
fn snapshot_manifest_only_object_round_trip() {
    let master = test_master();
    let cfg = write_config_for(Class::Alias, master);
    let (object, res) = write_one(&cfg, &[], kat_salt(2), kat_rand_val());
    assert_eq!(1, res.total_packages);
    let (_, got) = read_one(&object, &expect_for(Class::Alias, master));
    assert_eq!("termso-kat-g1", got.manifest.alias);
    assert_eq!("snap_kat", got.manifest.snapshot_id);
    assert_eq!(Some(1), got.manifest.total_packages);
    assert_eq!(Some(0), got.manifest.total_plaintext_length);
}

/// A stream cut on any package boundary (including one that keeps only
/// valid packages) is never booted or published from — without the trailer
/// there is no authenticated completion.
#[test]
fn snapshot_rejects_valid_prefix_truncation_at_package_boundary() {
    let master = test_master();
    let payload = b"layer-bytes-".repeat(20000);
    for class in [Class::Layer, Class::Record] {
        let cfg = if class == Class::Layer {
            layer_config(master, &payload)
        } else {
            write_config_for(class, master)
        };
        let (object, _) = write_one(&cfg, &payload, kat_salt(3), kat_rand_val());
        let bounds = package_boundaries(&object);
        assert!(bounds.len() >= 4, "manifest + payload packages + trailer");
        for cut in &bounds[..bounds.len() - 1] {
            let mut dst = Vec::new();
            let err = read_object(&mut dst, &mut io::Cursor::new(&object[..*cut]), &expect_for(class, master))
                .expect_err(&format!("class {class:?} prefix {cut} must reject"));
            assert!(
                matches!(err, Error::TruncatedStream(_) | Error::Manifest(_) | Error::Preamble(_)),
                "class {class:?} prefix {cut}: {err}"
            );
        }
    }
}

fn package_boundaries(object: &[u8]) -> Vec<usize> {
    let mut bounds = vec![0, PREAMBLE_SIZE];
    let mut off = PREAMBLE_SIZE;
    while off < object.len() {
        assert!(object.len() - off > 16, "header fits");
        let payload_len = object[off + 2] as usize | (object[off + 3] as usize) << 8;
        off += 16 + payload_len + 1 + 16;
        bounds.push(off);
    }
    assert_eq!(object.len(), off);
    bounds
}

/// Swapping two payload packages breaks the exact sequence 0,1,2,… with
/// err_package_out_of_order.
#[test]
fn snapshot_rejects_reordered_chunks() {
    let master = test_master();
    let payload = b"reorder-me--".repeat(20000);
    let cfg = layer_config(master, &payload);
    let (object, _) = write_one(&cfg, &payload, kat_salt(4), kat_rand_val());
    let bounds = package_boundaries(&object);
    let mut reordered = Vec::new();
    reordered.extend_from_slice(&object[..bounds[2]]);
    reordered.extend_from_slice(&object[bounds[3]..bounds[4]]);
    reordered.extend_from_slice(&object[bounds[2]..bounds[3]]);
    reordered.extend_from_slice(&object[bounds[4]..]);
    let mut dst = Vec::new();
    let err = read_object(&mut dst, &mut io::Cursor::new(&reordered), &expect_for(Class::Layer, master))
        .expect_err("reordered must reject");
    assert!(matches!(err, Error::PackageOrder(_)), "{err}");
}

/// The stream must end exactly on the trailer's package boundary.
#[test]
fn snapshot_rejects_trailing_bytes() {
    let master = test_master();
    let cfg = layer_config(master, b"some payload");
    let (object, _) = write_one(&cfg, b"some payload", kat_salt(5), kat_rand_val());
    let mut dst = Vec::new();
    let mut one = object.clone();
    one.push(0);
    let err = read_object(&mut dst, &mut io::Cursor::new(&one), &expect_for(Class::Layer, master))
        .expect_err("one trailing byte must reject");
    assert!(matches!(err, Error::TruncatedStream(_) | Error::TagMismatch(_)), "{err}");

    let mut forged = object.clone();
    forged.extend_from_slice(&object[PREAMBLE_SIZE..PREAMBLE_SIZE + 48]);
    assert!(read_object(&mut dst, &mut io::Cursor::new(&forged), &expect_for(Class::Layer, master)).is_err());

    let empty_cfg = write_config_for(Class::Artifact, master);
    let (empty, _) = write_one(&empty_cfg, &[], kat_salt(6), kat_rand_val());
    let mut empty_plus = empty.clone();
    empty_plus.push(0);
    let err = read_object(&mut dst, &mut io::Cursor::new(&empty_plus), &expect_for(Class::Artifact, master))
        .expect_err("combined form trailing byte must reject");
    assert!(matches!(err, Error::TrailingBytes(_)), "{err}");
}

/// An empty artifact presented as a record or alias is rejected; the empty
/// form never relaxes identity.
#[test]
fn snapshot_empty_artifact_wrong_context_denied() {
    let master = test_master();
    let cfg = write_config_for(Class::Artifact, master);
    let (object, _) = write_one(&cfg, &[], kat_salt(7), kat_rand_val());
    for class in [Class::Record, Class::Alias, Class::Layer] {
        let mut dst = Vec::new();
        let err = read_object(&mut dst, &mut io::Cursor::new(&object), &expect_for(class, master))
            .expect_err(&format!("empty artifact as {class:?} must reject"));
        assert!(matches!(err, Error::Context(_)), "{class:?}: {err}");
    }
    let mut wrong_snap = expect_for(Class::Artifact, master);
    wrong_snap.snapshot_id = Some("snap_other".to_string());
    let mut dst = Vec::new();
    let err = read_object(&mut dst, &mut io::Cursor::new(&object), &wrong_snap)
        .expect_err("wrong snapshot must reject");
    assert!(matches!(err, Error::Context(_)), "{err}");
}

/// An object never authenticates outside its tenant/volume/snapshot
/// context, by manifest identity or by the preamble fingerprint hints.
#[test]
fn snapshot_context_substitution_denied() {
    let master = test_master();
    let payload = b"context-bound bytes";
    let cfg = layer_config(master, payload);
    let (object, _) = write_one(&cfg, payload, kat_salt(8), kat_rand_val());
    let mut dst = Vec::new();

    let mut other_tenant = expect_for(Class::Layer, master);
    other_tenant.tenant = "ten_other".to_string();
    let err = read_object(&mut dst, &mut io::Cursor::new(&object), &other_tenant).expect_err("tenant");
    assert!(matches!(err, Error::Context(_)), "{err}");

    let mut other_volume = expect_for(Class::Layer, master);
    other_volume.volume = "vol_other".to_string();
    let err = read_object(&mut dst, &mut io::Cursor::new(&object), &other_volume).expect_err("volume");
    assert!(matches!(err, Error::Context(_)), "{err}");

    let other_master = stream_key(&master, &[1u8; 32]);
    let mut wrong_key = expect_for(Class::Layer, master);
    wrong_key.master_key = other_master;
    let err = read_object(&mut dst, &mut io::Cursor::new(&object), &wrong_key).expect_err("master key");
    assert!(matches!(err, Error::Context(_)), "{err}");

    let rec_cfg = write_config_for(Class::Record, master);
    let body = br#"{"layers":[],"artifacts":[],"template_lineage_root":"tpl"}"#;
    let (rec_object, _) = write_one(&rec_cfg, body, kat_salt(9), kat_rand_val());
    let err = read_object(&mut dst, &mut io::Cursor::new(&rec_object), &expect_for(Class::Artifact, master))
        .expect_err("record as artifact");
    assert!(matches!(err, Error::Context(_)), "{err}");
}

/// Layer identity is its plaintext digest under its volume; cross-volume
/// reuse fails because the master key differs.
#[test]
fn snapshot_encrypted_layers_are_volume_namespaced() {
    let master_a = test_master();
    let master_b = master_key(&[0x11u8; 64], "vol_b").expect("master key");
    let payload = b"identical plaintext in two volumes";
    let (object_a, _) = write_one(&layer_config(master_a, payload), payload, kat_salt(10), kat_rand_val());
    let mut cfg_b = layer_config(master_b, payload);
    cfg_b.volume = "vol_b".to_string();
    let (object_b, _) = write_one(&cfg_b, payload, kat_salt(10), kat_rand_val());
    assert_ne!(object_a, object_b, "same plaintext differs across volumes");

    let mut dst = Vec::new();
    let mut expect_b = expect_for(Class::Layer, master_b);
    expect_b.volume = "vol_b".to_string();
    let err = read_object(&mut dst, &mut io::Cursor::new(&object_a), &expect_b)
        .expect_err("A's object under B's master key");
    assert!(matches!(err, Error::Context(_)), "{err}");

    // Same volume re-encrypted inherits across snapshots of the volume:
    // layer identity is snapshot-independent (digest under the volume).
    let (_, res_a2) = write_one(&layer_config(master_a, payload), payload, kat_salt(11), kat_rand_val());
    assert_eq!(sha256_hex(payload), res_a2.payload_sha256);
}

/// The preamble is hints; a tampered salt derives the wrong stream key
/// (first tag fails), a tampered fingerprint or class is rejected against
/// the expected context.
#[test]
fn snapshot_rejects_tampered_preamble() {
    let master = test_master();
    let cfg = layer_config(master, b"preamble-tamper payload");
    let (object, _) = write_one(&cfg, b"preamble-tamper payload", kat_salt(12), kat_rand_val());
    let expect = expect_for(Class::Layer, master);
    let mut dst = Vec::new();

    let mut t = object.clone();
    t[30] ^= 0xff;
    let err = read_object(&mut dst, &mut io::Cursor::new(&t), &expect).expect_err("salt tamper");
    assert!(matches!(err, Error::TagMismatch(_)), "{err}");

    let mut t = object.clone();
    t[5] ^= 0x01;
    let err = read_object(&mut dst, &mut io::Cursor::new(&t), &expect).expect_err("volume fp tamper");
    assert!(matches!(err, Error::Context(_)), "{err}");

    let mut t = object.clone();
    t[4] = Class::Record as u8;
    let err = read_object(&mut dst, &mut io::Cursor::new(&t), &expect).expect_err("class tamper");
    assert!(matches!(err, Error::Context(_)), "{err}");

    let mut t = object.clone();
    t[0..3].copy_from_slice(b"XE1");
    let err = read_object(&mut dst, &mut io::Cursor::new(&t), &expect).expect_err("magic tamper");
    assert!(matches!(err, Error::Preamble(_)), "{err}");
}

/// The writer refuses to seal a layer whose claimed identity does not
/// match the streamed payload; a payload bit-flip fails the tag before
/// emission.
#[test]
fn snapshot_layer_manifest_self_check() {
    let master = test_master();
    let payload = b"self-checked layer payload";
    let mut cfg = layer_config(master, payload);
    cfg.layer_sha256 = sha256_hex(b"different");
    let mut buf = Vec::new();
    let err = write_object_with_nonce(
        &mut buf,
        &mut io::Cursor::new(payload),
        &cfg,
        kat_salt(13),
        kat_rand_val(),
    )
    .expect_err("mismatched layer claim must refuse");
    assert!(matches!(err, Error::Manifest(_)), "{err}");

    let mut dst = Vec::new();
    assert!(read_object(&mut dst, &mut io::Cursor::new(&buf), &expect_for(Class::Layer, master)).is_err());

    let (object, _) = write_one(&layer_config(master, payload), payload, kat_salt(14), kat_rand_val());
    let mut t = object.clone();
    t[PREAMBLE_SIZE + 16 + 5] ^= 0x01;
    let err = read_object(&mut dst, &mut io::Cursor::new(&t), &expect_for(Class::Layer, master))
        .expect_err("payload bit-flip");
    assert!(matches!(err, Error::TagMismatch(_)), "{err}");
}

/// The record body digests deterministically, the lineage root must equal
/// the grant pin, plaintext layers are refused without a membership proof,
/// and layer expectations bind position, digest, length and the enc flag.
#[test]
fn snapshot_record_body_lineage_and_grant_pinning() {
    let layer_payload = b"hello term.so";
    let body = RecordBody {
        layers: vec![LayerExpectation {
            digest: sha256_hex(layer_payload),
            enc: true,
            plaintext_length: layer_payload.len() as i64,
        }],
        artifacts: vec![ArtifactExpectation {
            path: "/var/log/boot.log".to_string(),
            length: 3,
            sha256: sha256_hex(b"abc"),
        }],
        template_lineage_root: "tpl_build_7".to_string(),
    };
    let d1 = body.digest().expect("digest");
    let d2 = body.digest().expect("digest");
    assert_eq!(d1, d2, "canonical digest is stable");

    // Positive control: a fully encrypted lineage under the pinned root.
    body.verify_against_grant("tpl_build_7").expect("pinned root");
    assert!(matches!(
        body.verify_against_grant("tpl_build_8").unwrap_err(),
        Error::Context(_)
    ));
    assert!(matches!(
        body.verify_against_grant("").unwrap_err(),
        Error::Context(_)
    ));

    // A plaintext layer is refused even under the matching root label:
    // the label is not membership proof.
    for layer in [
        LayerExpectation { digest: "a".repeat(64), enc: false, plaintext_length: 4096 },
        LayerExpectation { digest: sha256_hex(layer_payload), enc: false, plaintext_length: layer_payload.len() as i64 },
        LayerExpectation { digest: sha256_hex(layer_payload), enc: false, plaintext_length: 8192 },
    ] {
        let mut mixed = body.clone();
        mixed.layers.insert(0, layer);
        assert!(matches!(
            mixed.verify_against_grant("tpl_build_7").unwrap_err(),
            Error::Context(_)
        ));
    }

    let master = test_master();
    let (object, _) = write_one(&layer_config(master, layer_payload), layer_payload, kat_salt(15), kat_rand_val());
    let (payload, read_res) = read_one(&object, &expect_for(Class::Layer, master));
    assert_eq!(layer_payload.to_vec(), payload);
    body.verify_layer(0, &read_res.manifest, &read_res.payload_sha256, read_res.plaintext_length)
        .expect("position 0 matches");
    assert!(matches!(
        body.verify_layer(1, &read_res.manifest, &read_res.payload_sha256, read_res.plaintext_length).unwrap_err(),
        Error::Context(_)
    ));
    assert!(matches!(
        body.verify_layer(0, &read_res.manifest, &sha256_hex(b"x"), read_res.plaintext_length).unwrap_err(),
        Error::Context(_)
    ));
    assert!(matches!(
        body.verify_layer(0, &read_res.manifest, &read_res.payload_sha256, read_res.plaintext_length + 1).unwrap_err(),
        Error::Context(_)
    ));

    // Reordered lineage: the real layer verified at the wrong position.
    let reordered = RecordBody {
        layers: vec![
            LayerExpectation { digest: sha256_hex(b"other"), enc: true, plaintext_length: 5 },
            LayerExpectation { digest: sha256_hex(layer_payload), enc: true, plaintext_length: layer_payload.len() as i64 },
        ],
        artifacts: vec![],
        template_lineage_root: "tpl_build_7".to_string(),
    };
    reordered.verify_against_grant("tpl_build_7").expect("encrypted lineage");
    assert!(matches!(
        reordered.verify_layer(0, &read_res.manifest, &read_res.payload_sha256, read_res.plaintext_length).unwrap_err(),
        Error::Context(_)
    ));
}

/// Payloads crossing the 64 KB package ceiling round-trip with exact
/// package counts and totals.
#[test]
fn snapshot_multi_package_round_trip() {
    let master = test_master();
    for size in [1usize, MAX_PAYLOAD_SIZE - 1, MAX_PAYLOAD_SIZE, MAX_PAYLOAD_SIZE + 1, 3 * MAX_PAYLOAD_SIZE + 17] {
        let payload = vec![0x42u8; size];
        let cfg = layer_config(master, &payload);
        let (object, res) = write_one(&cfg, &payload, kat_salt(16), kat_rand_val());
        let want_packages = 2 + (size + MAX_PAYLOAD_SIZE - 1) / MAX_PAYLOAD_SIZE;
        assert_eq!(want_packages as i64, res.total_packages, "size {size}");
        let (got, read_res) = read_one(&object, &expect_for(Class::Layer, master));
        assert_eq!(payload, got, "size {size}");
        assert_eq!(res.total_packages, read_res.total_packages, "size {size}");
        assert_eq!(res.payload_sha256, read_res.payload_sha256, "size {size}");
    }
}

/// The strict restore context never admits a foreign object; the discovery
/// context (class + tenant + volume, no identity assertion) authenticates
/// and yields the manifest for catalog listing.
#[test]
fn snapshot_rejects_encrypted_record_without_grant_context() {
    let master = test_master();
    let cfg = write_config_for(Class::Record, master);
    let body = br#"{"layers":[],"artifacts":[],"template_lineage_root":"tpl"}"#;
    let (object, _) = write_one(&cfg, body, kat_salt(17), kat_rand_val());
    let mut dst = Vec::new();

    let mut expect = expect_for(Class::Record, master);
    expect.snapshot_id = Some("snap_foreign".to_string());
    let err = read_object(&mut dst, &mut io::Cursor::new(&object), &expect).expect_err("foreign snapshot");
    assert!(matches!(err, Error::Context(_)), "{err}");

    let bare = ExpectConfig::new(Class::Record, "", "vol_kat", master);
    let err = read_object(&mut dst, &mut io::Cursor::new(&object), &bare).expect_err("missing tenant");
    assert!(matches!(err, Error::Context(_)), "{err}");

    let discovery = ExpectConfig::new(Class::Record, "ten_kat", "vol_kat", master);
    let (_, res) = read_one(&object, &discovery);
    assert_eq!("snap_kat", res.manifest.snapshot_id);
}

/// Malformed identities are rejected before any byte is written.
#[test]
fn snapshot_write_config_validation() {
    let master = test_master();
    let mut buf = Vec::new();

    let cfg = WriteConfig::new(Class::Alias, "t", "v", master);
    let err = write_object_with_nonce(&mut buf, &mut io::Cursor::new(b"x"), &cfg, kat_salt(18), kat_rand_val())
        .expect_err("alias without alias");
    assert!(matches!(err, Error::Manifest(_)), "{err}");

    let cfg = WriteConfig::new(Class::Layer, "t", "v", master);
    let err = write_object_with_nonce(&mut buf, &mut io::Cursor::new(b"x"), &cfg, kat_salt(19), kat_rand_val())
        .expect_err("layer without digest/length");
    assert!(matches!(err, Error::Manifest(_)), "{err}");

    assert!(buf.is_empty(), "no bytes leave the writer on denial");

    // Master key derivation needs a DEK and a volume id.
    assert!(matches!(master_key(&[], "vol"), Err(Error::KeyLength(_))));
    assert!(matches!(master_key(&[1u8; 32], ""), Err(Error::KeyLength(_))));
}
