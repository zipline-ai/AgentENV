//! Locked, non-dumpable key storage. No serialization, cloning or debug output.
use super::kms::KmsDenied;

pub struct LockedBytes {
    ptr: std::ptr::NonNull<u8>,
    len: usize,
    #[cfg(test)]
    pub(super) after_wipe: Option<Box<dyn Fn(&[u8]) + Send>>,
}
// The mapping has one owner. Access still requires a Rust borrow of that owner.
unsafe impl Send for LockedBytes {}
impl LockedBytes {
    pub fn new(len: usize) -> Result<Self, KmsDenied> {
        Self::allocate(len, |ptr, len| unsafe { libc::mlock(ptr, len) })
    }
    fn allocate(
        len: usize,
        lock: impl FnOnce(*mut libc::c_void, usize) -> i32,
    ) -> Result<Self, KmsDenied> {
        if len == 0 || len > 128 * 1024 {
            return Err(KmsDenied);
        }
        // Dedicated anonymous pages prevent one secret's munlock from unlocking
        // another allocator object. No secret is written before both checks pass.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(KmsDenied);
        }
        if ptr.is_null() {
            unsafe {
                libc::munmap(ptr, len);
            }
            return Err(KmsDenied);
        }
        if lock(ptr, len) != 0 {
            unsafe {
                libc::munmap(ptr, len);
            }
            return Err(KmsDenied);
        }
        if unsafe { libc::madvise(ptr, len, libc::MADV_DONTDUMP) } != 0 {
            unsafe {
                libc::munlock(ptr, len);
                libc::munmap(ptr, len);
            }
            return Err(KmsDenied);
        }
        Ok(Self {
            ptr: std::ptr::NonNull::new(ptr.cast()).ok_or(KmsDenied)?,
            len,
            #[cfg(test)]
            after_wipe: None,
        })
    }
    fn wipe(&mut self) {
        for byte in self.bytes_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}
impl Drop for LockedBytes {
    fn drop(&mut self) {
        self.wipe();
        #[cfg(test)]
        if let Some(observer) = &self.after_wipe {
            observer(self.bytes());
        }
        unsafe {
            libc::munlock(self.ptr.as_ptr().cast(), self.len);
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}
#[cfg(test)]
mod tests;
