use super::*;
use sha2::{Digest, Sha256};
fn binding() -> VolumeBinding {
    VolumeBinding {
        tenant_id: "tenant".into(),
        volume_id: "volume".into(),
        owner_id: "owner".into(),
        node_id: "node".into(),
        incarnation: "inc".into(),
        operation_id: "op".into(),
        backing_bytes: 4096 * 16,
        fs_uuid: "fe5fc313-3712-49d6-9b6f-8ab2fa157236".into(),
        grant: b"signed-grant-fixture".to_vec(),
        signature: vec![9; 64],
        wrapped_dek: b"wrapped-ciphertext".to_vec(),
        wrapped_sha256: hex::encode(Sha256::digest(b"wrapped-ciphertext")),
    }
}
fn new() -> NewVolumeAuthority {
    NewVolumeAuthority {
        _proof: MissingLaunchProof {},
        binding: binding(),
    }
}
fn reopen() -> ReopenVolumeAuthority {
    ReopenVolumeAuthority {
        _proof: MissingLaunchProof {},
        binding: binding(),
    }
}
#[tokio::test]
async fn descriptor_initialization_and_reopen_preserve_wrapped_binding() {
    let root = tempfile::tempdir().unwrap();
    let s = VolumeStore::initialize(root.path().into(), new())
        .await
        .unwrap();
    let first = s.snapshot().await.unwrap();
    assert!(first.directory_confirmed);
    assert!(first.binding == binding());
    drop(s);
    let s = VolumeStore::reopen(root.path().into(), reopen())
        .await
        .unwrap();
    let after = s.snapshot().await.unwrap();
    assert!(first == after);
    assert!(VolumeStore::initialize(root.path().into(), new())
        .await
        .is_err());
}
#[tokio::test]
async fn descriptor_second_opener_is_excluded_without_replacing_lock() {
    let root = tempfile::tempdir().unwrap();
    let s = VolumeStore::initialize(root.path().into(), new())
        .await
        .unwrap();
    let before = s.snapshot().await.unwrap();
    assert!(VolumeStore::reopen(root.path().into(), reopen())
        .await
        .is_err());
    assert!(s.snapshot().await.unwrap() == before);
    drop(s);
    assert!(VolumeStore::reopen(root.path().into(), reopen())
        .await
        .is_ok());
}
#[tokio::test]
async fn descriptor_missing_store_is_not_initialized_by_reopen() {
    let root = tempfile::tempdir().unwrap();
    assert!(VolumeStore::reopen(root.path().into(), reopen())
        .await
        .is_err());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
struct Fault {
    at: Option<usize>,
    seen: Mutex<Vec<Boundary>>,
}
impl Durability for Fault {
    fn before(&self, b: Boundary) -> Result<(), VolumeUnavailable> {
        let mut seen = self.seen.lock().unwrap();
        let index = seen.len();
        seen.push(b);
        if self.at == Some(index) {
            Err(VolumeUnavailable)
        } else {
            Ok(())
        }
    }
}
#[tokio::test]
async fn descriptor_publication_failures_preserve_pending_identity_or_orphan() {
    let sample_root = tempfile::tempdir().unwrap();
    let expected = publication_boundaries(sample_root.path());
    for at in 0..expected.len() {
        let root = tempfile::tempdir().unwrap();
        let fault = Arc::new(Fault {
            at: Some(at),
            seen: Mutex::new(vec![]),
        });
        assert!(
            VolumeStore::initialize_with(root.path().into(), new(), fault.clone())
                .await
                .is_err()
        );
        assert_eq!(*fault.seen.lock().unwrap(), expected[..=at]);
        assert!(VolumeStore::initialize(root.path().into(), new())
            .await
            .is_err());
        let reopened = VolumeStore::reopen(root.path().into(), reopen()).await;
        if at
            < expected
                .iter()
                .position(|b| *b == Boundary::StoreDirectory)
                .unwrap()
        {
            assert!(reopened.is_err());
            continue;
        }
        let s = reopened.unwrap();
        let before = s.snapshot().await.unwrap();
        assert!(!before.directory_confirmed);
        let again = Arc::new(Fault {
            at: Some(0),
            seen: Mutex::new(vec![]),
        });
        assert!(s.confirm_with(again).await.is_err());
        assert!(s.snapshot().await.unwrap() == before);
        s.confirm_directory().await.unwrap();
        let mut expected = before;
        expected.directory_confirmed = true;
        assert!(s.snapshot().await.unwrap() == expected);
    }
    let root = tempfile::tempdir().unwrap();
    let trace = Arc::new(Fault {
        at: None,
        seen: Mutex::new(vec![]),
    });
    let s = VolumeStore::initialize_with(root.path().into(), new(), trace.clone())
        .await
        .unwrap();
    assert_eq!(*trace.seen.lock().unwrap(), expected);
    assert!(s.snapshot().await.unwrap().directory_confirmed);
}
#[tokio::test]
async fn descriptor_missing_corrupt_or_foreign_recovery_never_repairs() {
    for case in 0..8 {
        let root = tempfile::tempdir().unwrap();
        let s = VolumeStore::initialize(root.path().into(), new())
            .await
            .unwrap();
        let before = s.snapshot().await.unwrap();
        drop(s);
        let dir = root.path().join(volume_name(&binding()));
        match case {
            0 => fs::remove_dir_all(dir.join("descriptor")).unwrap(),
            1 => fs::remove_file(dir.join("descriptor/CURRENT")).unwrap(),
            2 => fs::remove_file(dir.join("backing")).unwrap(),
            3 => fs::remove_file(dir.join("effect.lock")).unwrap(),
            4 => regular(&dir.join("backing"), false)
                .unwrap()
                .set_len(4096)
                .unwrap(),
            5 => {
                let db = LocalKvStore::open_blocking(
                    dir.join("descriptor"),
                    LocalStoreDurability::Sync,
                    false,
                )
                .unwrap();
                db.put_blocking(DESCRIPTOR_KEY, b"{").unwrap();
            }
            6 => {
                let mut options = rocksdb::Options::default();
                options.create_if_missing(false);
                let db = rocksdb::DB::open(&options, dir.join("descriptor")).unwrap();
                db.delete(DESCRIPTOR_KEY).unwrap();
            }
            _ => {
                fs::rename(dir.join("backing"), dir.join("original-backing")).unwrap();
                std::os::unix::fs::symlink("original-backing", dir.join("backing")).unwrap();
            }
        }
        let names = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(VolumeStore::reopen(root.path().into(), reopen())
            .await
            .is_err());
        assert_eq!(
            fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<std::collections::BTreeSet<_>>(),
            names
        );
        assert!(VolumeStore::initialize(root.path().into(), new())
            .await
            .is_err());
        if case == 1 {
            assert!(!dir.join("descriptor/CURRENT").exists());
        }
        if case == 2 {
            assert!(!dir.join("backing").exists());
        }
        if case == 3 {
            assert!(!dir.join("effect.lock").exists());
        }
        assert!(before.directory_confirmed);
    }
    let root = tempfile::tempdir().unwrap();
    let s = VolumeStore::initialize(root.path().into(), new())
        .await
        .unwrap();
    let before = s.snapshot().await.unwrap();
    drop(s);
    let mut foreign = reopen();
    foreign.binding.owner_id = "other-owner".into();
    assert!(VolumeStore::reopen(root.path().into(), foreign)
        .await
        .is_err());
    let s = VolumeStore::reopen(root.path().into(), reopen())
        .await
        .unwrap();
    assert!(s.snapshot().await.unwrap() == before);
}
#[tokio::test]
async fn descriptor_replaced_lock_is_never_accepted_as_new_exclusion() {
    let root = tempfile::tempdir().unwrap();
    let s = VolumeStore::initialize(root.path().into(), new())
        .await
        .unwrap();
    let dir = root.path().join(volume_name(&binding()));
    fs::rename(dir.join("effect.lock"), dir.join("old-lock")).unwrap();
    let replacement = regular(&dir.join("effect.lock"), true).unwrap();
    let id = identity(&replacement).unwrap();
    assert!(s.snapshot().await.is_err());
    assert!(s.confirm_directory().await.is_err());
    assert!(VolumeStore::reopen(root.path().into(), reopen())
        .await
        .is_err());
    assert_eq!(
        identity(&regular(&dir.join("effect.lock"), false).unwrap()).unwrap(),
        id
    );
}
#[tokio::test]
async fn descriptor_cancelled_waiter_retains_lock_until_worker_finishes() {
    struct Paused {
        entered: tokio::sync::Notify,
        release: (Mutex<bool>, std::sync::Condvar),
    }
    impl Durability for Paused {
        fn before(&self, b: Boundary) -> Result<(), VolumeUnavailable> {
            if b == Boundary::StoreDirectory {
                self.entered.notify_one();
                let (lock, cv) = &self.release;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = cv.wait(released).unwrap();
                }
            }
            Ok(())
        }
    }
    let root = tempfile::tempdir().unwrap();
    let fault = Arc::new(Paused {
        entered: tokio::sync::Notify::new(),
        release: (Mutex::new(false), std::sync::Condvar::new()),
    });
    let taskroot = root.path().to_path_buf();
    let taskfault = fault.clone();
    let task =
        tokio::spawn(async move { VolumeStore::initialize_with(taskroot, new(), taskfault).await });
    fault.entered.notified().await;
    task.abort();
    assert!(matches!(task.await,Err(e) if e.is_cancelled()));
    let lock = regular(
        &root
            .path()
            .join(volume_name(&binding()))
            .join("effect.lock"),
        false,
    )
    .unwrap();
    assert!(flock(&lock).is_err());
    assert!(VolumeStore::reopen(root.path().into(), reopen())
        .await
        .is_err());
    *fault.release.0.lock().unwrap() = true;
    fault.release.1.notify_all();
    // Wait for actual exclusion release, not a sleep or a guessed task lifetime.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if flock(&lock).is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(lock);
    let s = VolumeStore::reopen(root.path().into(), reopen())
        .await
        .unwrap();
    assert!(s.snapshot().await.unwrap().directory_confirmed);
}
#[tokio::test]
async fn descriptor_record_is_wrapped_only_and_rejects_extra_plaintext_fields() {
    let root = tempfile::tempdir().unwrap();
    let s = VolumeStore::initialize(root.path().into(), new())
        .await
        .unwrap();
    let state = s.snapshot().await.unwrap();
    let raw = serde_json::to_vec(&state).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let fields = value["binding"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let expected = [
        "tenant_id",
        "volume_id",
        "owner_id",
        "node_id",
        "incarnation",
        "operation_id",
        "backing_bytes",
        "fs_uuid",
        "grant",
        "signature",
        "wrapped_dek",
        "wrapped_sha256",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(fields, expected);
    value["binding"]["raw_key"] = serde_json::json!("plaintext-canary");
    assert!(serde_json::from_value::<WrappedDescriptor>(value).is_err());
}
#[tokio::test]
async fn descriptor_confirmed_retry_rechecks_identity_after_sync() {
    struct ReplaceLock(PathBuf);
    impl Durability for ReplaceLock {
        fn before(&self, b: Boundary) -> Result<(), VolumeUnavailable> {
            if b == Boundary::StoreDirectory {
                fs::rename(self.0.join("effect.lock"), self.0.join("old-lock")).unwrap();
                regular(&self.0.join("effect.lock"), true).unwrap();
            }
            Ok(())
        }
    }
    let root = tempfile::tempdir().unwrap();
    let s = VolumeStore::initialize(root.path().into(), new())
        .await
        .unwrap();
    assert!(s
        .confirm_with(Arc::new(ReplaceLock(
            root.path().join(volume_name(&binding()))
        )))
        .await
        .is_err());
}
#[tokio::test]
async fn descriptor_confirms_root_publication_through_ancestors() {
    let root = tempfile::tempdir().unwrap();
    let trace = Arc::new(Fault {
        at: None,
        seen: Mutex::new(vec![]),
    });
    let _s = VolumeStore::initialize_with(root.path().into(), new(), trace.clone())
        .await
        .unwrap();
    let seen = trace.seen.lock().unwrap();
    let parents = root.path().ancestors().skip(1).count();
    assert_eq!(
        seen.iter()
            .filter(|b| **b == Boundary::RootAncestor)
            .count(),
        parents * 2
    );
    assert!(
        seen.iter()
            .position(|b| *b == Boundary::RootAncestor)
            .unwrap()
            < seen.iter().position(|b| *b == Boundary::LockFile).unwrap()
    );
}

fn publication_boundaries(root: &Path) -> Vec<Boundary> {
    let parents = root.ancestors().skip(1).count();
    let mut result = vec![Boundary::RootDirectory];
    result.extend(std::iter::repeat_n(Boundary::RootAncestor, parents));
    result.extend([
        Boundary::LockFile,
        Boundary::LockDirectory,
        Boundary::BackingFile,
        Boundary::BackingDirectory,
        Boundary::DescriptorWrite,
        Boundary::StoreDirectory,
        Boundary::VolumeDirectory,
        Boundary::RootDirectory,
    ]);
    result.extend(std::iter::repeat_n(Boundary::RootAncestor, parents));
    result.push(Boundary::ConfirmWrite);
    result
}
#[tokio::test]
async fn descriptor_child_holds_same_stable_lock() {
    use std::io::{BufRead, Write};
    let root = tempfile::tempdir().unwrap();
    let s = VolumeStore::initialize(root.path().into(), new())
        .await
        .unwrap();
    let first = s.snapshot().await.unwrap();
    drop(s);
    let path = root
        .path()
        .join(volume_name(&binding()))
        .join("effect.lock");
    let mut child = std::process::Command::new("flock")
        .arg("--exclusive")
        .arg("--nonblock")
        .arg(&path)
        .args(["sh", "-c", "printf 'locked\\n'; read -r release"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "locked\n");
    assert!(VolumeStore::reopen(root.path().into(), reopen())
        .await
        .is_err());
    child.stdin.take().unwrap().write_all(b"release\n").unwrap();
    assert!(child.wait().unwrap().success());
    let s = VolumeStore::reopen(root.path().into(), reopen())
        .await
        .unwrap();
    assert!(s.snapshot().await.unwrap() == first);
}
#[tokio::test]
async fn descriptor_invalid_binding_and_symlink_root_have_zero_publications() {
    for case in 0..6 {
        let root = tempfile::tempdir().unwrap();
        let mut a = new();
        match case {
            0 => a.binding.backing_bytes = 0,
            1 => a.binding.backing_bytes += 1,
            2 => a.binding.fs_uuid = "../unsafe".into(),
            3 => a.binding.wrapped_sha256 = "0".repeat(64),
            4 => a.binding.tenant_id.clear(),
            _ => a.binding.grant.clear(),
        };
        assert!(VolumeStore::initialize(root.path().into(), a)
            .await
            .is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
    let outer = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let alias = outer.path().join("alias");
    std::os::unix::fs::symlink(root.path(), &alias).unwrap();
    assert!(VolumeStore::initialize(alias, new()).await.is_err());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}
