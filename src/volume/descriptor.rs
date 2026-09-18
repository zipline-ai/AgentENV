//! Dormant wrapped-volume storage. Storage confirmation is never launch authority.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("encrypted volume state unavailable; recovery required")]
pub struct VolumeUnavailable;
struct MissingLaunchProof {
    #[cfg(not(test))]
    _missing: std::convert::Infallible,
}
pub struct NewVolumeAuthority {
    _proof: MissingLaunchProof,
    binding: VolumeBinding,
}
pub struct ReopenVolumeAuthority {
    _proof: MissingLaunchProof,
    binding: VolumeBinding,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VolumeBinding {
    tenant_id: String,
    volume_id: String,
    owner_id: String,
    node_id: String,
    incarnation: String,
    operation_id: String,
    backing_bytes: u64,
    fs_uuid: String,
    grant: Vec<u8>,
    signature: Vec<u8>,
    wrapped_dek: Vec<u8>,
    wrapped_sha256: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WrappedDescriptor {
    version: u32,
    binding: VolumeBinding,
    lock_device: u64,
    lock_inode: u64,
    backing_device: u64,
    backing_inode: u64,
    directory_confirmed: bool,
}
use crate::local_store::{LocalKvStore, LocalStoreDurability};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
    sync::{Arc, Mutex},
};
const DESCRIPTOR_KEY: &[u8] = b"wrapped-volume/v1";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    RootDirectory,
    RootAncestor,
    LockFile,
    LockDirectory,
    BackingFile,
    BackingDirectory,
    DescriptorWrite,
    StoreDirectory,
    VolumeDirectory,
    ConfirmWrite,
}
trait Durability: Send + Sync {
    fn before(&self, boundary: Boundary) -> Result<(), VolumeUnavailable>;
}
struct RealDurability;
impl Durability for RealDurability {
    fn before(&self, _: Boundary) -> Result<(), VolumeUnavailable> {
        Ok(())
    }
}
// Field order is deliberate: RocksDB closes before the flock FD is released.
struct Disk {
    db: LocalKvStore,
    db_dir: File,
    backing: File,
    directory: File,
    root: File,
    ancestors: Vec<File>,
    root_path: PathBuf,
    volume_name: String,
    binding: VolumeBinding,
    lock: File,
}
#[derive(Clone)]
pub struct VolumeStore {
    disk: Arc<Mutex<Disk>>,
}
impl VolumeStore {
    pub async fn initialize(
        root: PathBuf,
        authority: NewVolumeAuthority,
    ) -> Result<Self, VolumeUnavailable> {
        Self::initialize_with(root, authority, Arc::new(RealDurability)).await
    }
    async fn initialize_with(
        root: PathBuf,
        authority: NewVolumeAuthority,
        durability: Arc<dyn Durability>,
    ) -> Result<Self, VolumeUnavailable> {
        // The blocking worker owns all exclusion and database work. Dropping or
        // aborting the async waiter never releases its flock while work continues.
        tokio::task::spawn_blocking(move || {
            initialize_sync(root, authority.binding, durability.as_ref())
        })
        .await
        .map_err(|_| VolumeUnavailable)?
    }
    pub async fn reopen(
        root: PathBuf,
        authority: ReopenVolumeAuthority,
    ) -> Result<Self, VolumeUnavailable> {
        tokio::task::spawn_blocking(move || reopen_sync(root, authority.binding))
            .await
            .map_err(|_| VolumeUnavailable)?
    }
    pub async fn snapshot(&self) -> Result<WrappedDescriptor, VolumeUnavailable> {
        let disk = self.disk.clone();
        tokio::task::spawn_blocking(move || disk.lock().map_err(|_| VolumeUnavailable)?.read())
            .await
            .map_err(|_| VolumeUnavailable)?
    }
    pub async fn confirm_directory(&self) -> Result<(), VolumeUnavailable> {
        self.confirm_with(Arc::new(RealDurability)).await
    }
    async fn confirm_with(&self, durability: Arc<dyn Durability>) -> Result<(), VolumeUnavailable> {
        let disk = self.disk.clone();
        tokio::task::spawn_blocking(move || {
            disk.lock()
                .map_err(|_| VolumeUnavailable)?
                .confirm(durability.as_ref())
        })
        .await
        .map_err(|_| VolumeUnavailable)?
    }
}
fn volume_name(b: &VolumeBinding) -> String {
    let mut hash = Sha256::new();
    hash.update((b.tenant_id.len() as u64).to_be_bytes());
    hash.update(b.tenant_id.as_bytes());
    hash.update(b.volume_id.as_bytes());
    hex::encode(hash.finalize())
}
fn validate(b: &VolumeBinding) -> Result<(), VolumeUnavailable> {
    for field in [
        &b.tenant_id,
        &b.volume_id,
        &b.owner_id,
        &b.node_id,
        &b.incarnation,
        &b.operation_id,
    ] {
        if field.is_empty() || field.len() > 1024 || field.chars().any(char::is_control) {
            return Err(VolumeUnavailable);
        }
    }
    if b.backing_bytes == 0
        || !b.backing_bytes.is_multiple_of(4096)
        || b.backing_bytes > 16 * 1024 * 1024 * 1024 * 1024
        || uuid::Uuid::parse_str(&b.fs_uuid)
            .map_err(|_| VolumeUnavailable)?
            .to_string()
            != b.fs_uuid
        || b.grant.is_empty()
        || b.grant.len() > 65536
        || b.signature.is_empty()
        || b.signature.len() > 80
        || b.wrapped_dek.is_empty()
        || b.wrapped_dek.len() > 65536
        || hex::encode(Sha256::digest(&b.wrapped_dek)) != b.wrapped_sha256
    {
        return Err(VolumeUnavailable);
    }
    Ok(())
}
fn anchor(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}
fn open_directory(path: &Path) -> Result<File, VolumeUnavailable> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| VolumeUnavailable)?;
    Ok(f)
}
fn owned_directory(f: &File) -> Result<(), VolumeUnavailable> {
    let m = f.metadata().map_err(|_| VolumeUnavailable)?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
        return Err(VolumeUnavailable);
    }
    Ok(())
}
fn directory(path: &Path) -> Result<File, VolumeUnavailable> {
    let f = open_directory(path)?;
    owned_directory(&f)?;
    Ok(f)
}
fn root_chain(path: &Path) -> Result<(File, Vec<File>), VolumeUnavailable> {
    use std::path::Component;
    if !path.is_absolute() {
        return Err(VolumeUnavailable);
    }
    let mut chain = vec![open_directory(Path::new("/"))?];
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let next =
                    open_directory(&anchor(chain.last().ok_or(VolumeUnavailable)?).join(name))?;
                chain.push(next);
            }
            _ => return Err(VolumeUnavailable),
        }
    }
    let root = chain.pop().ok_or(VolumeUnavailable)?;
    owned_directory(&root)?;
    Ok((root, chain))
}
fn regular(path: &Path, create: bool) -> Result<File, VolumeUnavailable> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| VolumeUnavailable)?;
    let m = f.metadata().map_err(|_| VolumeUnavailable)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
    {
        return Err(VolumeUnavailable);
    }
    Ok(f)
}
fn sync(file: &File, boundary: Boundary, d: &dyn Durability) -> Result<(), VolumeUnavailable> {
    d.before(boundary)?;
    file.sync_all().map_err(|_| VolumeUnavailable)
}
fn flock(file: &File) -> Result<(), VolumeUnavailable> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(VolumeUnavailable);
    }
    Ok(())
}
fn identity(file: &File) -> Result<(u64, u64), VolumeUnavailable> {
    let m = file.metadata().map_err(|_| VolumeUnavailable)?;
    Ok((m.dev(), m.ino()))
}
fn same_path(file: &File, path: &Path) -> Result<(), VolumeUnavailable> {
    let m = fs::symlink_metadata(path).map_err(|_| VolumeUnavailable)?;
    if m.file_type().is_symlink() || (m.dev(), m.ino()) != identity(file)? {
        return Err(VolumeUnavailable);
    }
    Ok(())
}
fn initialize_sync(
    root_path: PathBuf,
    binding: VolumeBinding,
    d: &dyn Durability,
) -> Result<VolumeStore, VolumeUnavailable> {
    validate(&binding)?;
    let (root, ancestors) = root_chain(&root_path)?;
    let name = volume_name(&binding);
    let path = anchor(&root).join(&name);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| VolumeUnavailable)?;
    sync(&root, Boundary::RootDirectory, d)?;
    for ancestor in ancestors.iter().rev() {
        sync(ancestor, Boundary::RootAncestor, d)?;
    }
    let dir = directory(&path)?;
    let lock = regular(&anchor(&dir).join("effect.lock"), true)?;
    flock(&lock)?;
    sync(&lock, Boundary::LockFile, d)?;
    sync(&dir, Boundary::LockDirectory, d)?;
    let backing = regular(&anchor(&dir).join("backing"), true)?;
    backing
        .set_len(binding.backing_bytes)
        .map_err(|_| VolumeUnavailable)?;
    sync(&backing, Boundary::BackingFile, d)?;
    sync(&dir, Boundary::BackingDirectory, d)?;
    let db_path = anchor(&dir).join("descriptor");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&db_path)
        .map_err(|_| VolumeUnavailable)?;
    let db_dir = directory(&db_path)?;
    let db = LocalKvStore::open_blocking(anchor(&db_dir), LocalStoreDurability::Sync, true)
        .map_err(|_| VolumeUnavailable)?;
    let (lock_device, lock_inode) = identity(&lock)?;
    let (backing_device, backing_inode) = identity(&backing)?;
    let state = WrappedDescriptor {
        version: 1,
        binding: binding.clone(),
        lock_device,
        lock_inode,
        backing_device,
        backing_inode,
        directory_confirmed: false,
    };
    let disk = Disk {
        db,
        db_dir,
        backing,
        directory: dir,
        root,
        ancestors,
        root_path,
        volume_name: name,
        binding,
        lock,
    };
    d.before(Boundary::DescriptorWrite)?;
    disk.write(&state)?;
    disk.confirm(d)?;
    Ok(VolumeStore {
        disk: Arc::new(Mutex::new(disk)),
    })
}
fn reopen_sync(
    root_path: PathBuf,
    binding: VolumeBinding,
) -> Result<VolumeStore, VolumeUnavailable> {
    validate(&binding)?;
    let (root, ancestors) = root_chain(&root_path)?;
    let name = volume_name(&binding);
    let dir = directory(&anchor(&root).join(&name))?;
    let lock = regular(&anchor(&dir).join("effect.lock"), false)?;
    flock(&lock)?;
    let backing = regular(&anchor(&dir).join("backing"), false)?;
    let db_dir = directory(&anchor(&dir).join("descriptor"))?;
    // This check supplies a clear fail-closed path; create_if_missing=false is the
    // actual protection against accidental recreation, including a raced deletion.
    let current =
        fs::symlink_metadata(anchor(&db_dir).join("CURRENT")).map_err(|_| VolumeUnavailable)?;
    if !current.is_file() || current.file_type().is_symlink() {
        return Err(VolumeUnavailable);
    }
    let db = LocalKvStore::open_blocking(anchor(&db_dir), LocalStoreDurability::Sync, false)
        .map_err(|_| VolumeUnavailable)?;
    let disk = Disk {
        db,
        db_dir,
        backing,
        directory: dir,
        root,
        ancestors,
        root_path,
        volume_name: name,
        binding,
        lock,
    };
    disk.read()?;
    Ok(VolumeStore {
        disk: Arc::new(Mutex::new(disk)),
    })
}
impl Disk {
    fn check_paths(&self) -> Result<(), VolumeUnavailable> {
        owned_directory(&self.root)?;
        owned_directory(&self.directory)?;
        owned_directory(&self.db_dir)?;
        for file in [&self.lock, &self.backing] {
            let m = file.metadata().map_err(|_| VolumeUnavailable)?;
            if !m.is_file()
                || m.nlink() != 1
                || m.uid() != unsafe { libc::geteuid() }
                || m.mode() & 0o077 != 0
            {
                return Err(VolumeUnavailable);
            }
        }
        same_path(&self.root, &self.root_path)?;
        for (file, path) in self
            .ancestors
            .iter()
            .rev()
            .zip(self.root_path.ancestors().skip(1))
        {
            same_path(file, path)?;
        }
        same_path(&self.directory, &anchor(&self.root).join(&self.volume_name))?;
        same_path(&self.lock, &anchor(&self.directory).join("effect.lock"))?;
        same_path(&self.backing, &anchor(&self.directory).join("backing"))?;
        same_path(&self.db_dir, &anchor(&self.directory).join("descriptor"))?;
        Ok(())
    }
    fn read(&self) -> Result<WrappedDescriptor, VolumeUnavailable> {
        self.check_paths()?;
        let raw = self
            .db
            .get_blocking(DESCRIPTOR_KEY)
            .map_err(|_| VolumeUnavailable)?
            .ok_or(VolumeUnavailable)?;
        if raw.len() > 1024 * 1024 {
            return Err(VolumeUnavailable);
        }
        let s: WrappedDescriptor = serde_json::from_slice(&raw).map_err(|_| VolumeUnavailable)?;
        if s.version != 1
            || s.binding != self.binding
            || (s.lock_device, s.lock_inode) != identity(&self.lock)?
            || (s.backing_device, s.backing_inode) != identity(&self.backing)?
            || self
                .backing
                .metadata()
                .map_err(|_| VolumeUnavailable)?
                .len()
                != self.binding.backing_bytes
        {
            return Err(VolumeUnavailable);
        }
        Ok(s)
    }
    fn write(&self, s: &WrappedDescriptor) -> Result<(), VolumeUnavailable> {
        self.check_paths()?;
        let value = serde_json::to_vec(s).map_err(|_| VolumeUnavailable)?;
        self.db
            .put_blocking(DESCRIPTOR_KEY, &value)
            .map_err(|_| VolumeUnavailable)
    }
    fn confirm(&self, d: &dyn Durability) -> Result<(), VolumeUnavailable> {
        let mut s = self.read()?;
        // Even an existing confirmed record does not justify skipping confirmation
        // of reopened directory handles before this process uses the storage.
        sync(&self.db_dir, Boundary::StoreDirectory, d)?;
        sync(&self.directory, Boundary::VolumeDirectory, d)?;
        sync(&self.root, Boundary::RootDirectory, d)?;
        for ancestor in self.ancestors.iter().rev() {
            sync(ancestor, Boundary::RootAncestor, d)?;
        }
        if self.read()? != s {
            return Err(VolumeUnavailable);
        }
        if !s.directory_confirmed {
            d.before(Boundary::ConfirmWrite)?;
            s.directory_confirmed = true;
            self.write(&s)?;
        }
        if self.read()? != s {
            return Err(VolumeUnavailable);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
