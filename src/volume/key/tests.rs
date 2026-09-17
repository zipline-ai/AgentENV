use super::*;
#[test]
fn key_mapping_is_locked_and_excluded_from_dumps() {
    let mut key = LockedBytes::new(64).unwrap();
    key.bytes_mut().fill(0x5a);
    assert_eq!(key.bytes(), &[0x5a; 64]);
    let address = key.ptr.as_ptr() as usize;
    let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut matched = false;
    for block in maps.split("VmFlags:") {
        let mut in_mapping = false;
        for line in block.lines() {
            if let Some(range) = line.split_whitespace().next() {
                if let Some((start, end)) = range.split_once('-') {
                    if let (Ok(start), Ok(end)) = (
                        usize::from_str_radix(start, 16),
                        usize::from_str_radix(end, 16),
                    ) {
                        in_mapping = start <= address && address < end;
                        if in_mapping {
                            break;
                        }
                    }
                }
            }
        }
        if in_mapping {
            matched = true;
            break;
        }
    }
    assert!(matched);
    // Inspect the exact mapping, including VmFlags, rather than aggregate VmLck.
    let mut active = false;
    let mut flags = None;
    for line in maps.lines() {
        if let Some((start, rest)) = line.split_once('-') {
            if let (Ok(start), Some(end)) = (
                usize::from_str_radix(start, 16),
                rest.split_whitespace().next(),
            ) {
                if let Ok(end) = usize::from_str_radix(end, 16) {
                    active = start <= address && address < end;
                }
            }
        }
        if active && line.starts_with("VmFlags:") {
            flags = Some(line.to_owned());
            break;
        }
    }
    let flags = flags.unwrap();
    assert!(flags.split_whitespace().any(|s| s == "lo"));
    assert!(flags.split_whitespace().any(|s| s == "dd"));
}
#[test]
fn key_mapping_rejects_empty_and_unbounded_allocations() {
    for len in [0, 131073, usize::MAX] {
        assert!(LockedBytes::new(len).is_err());
    }
}
#[test]
fn locking_failure_denies_before_secret_storage() {
    let mut called = false;
    let result = LockedBytes::allocate(64, |ptr, len| {
        called = true;
        assert_eq!(
            unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) },
            &[0; 64]
        );
        -1
    });
    assert!(called);
    assert!(result.is_err());
}
#[test]
fn key_wipe_clears_entire_mapping_before_release() {
    let mut key = LockedBytes::new(8192).unwrap();
    key.bytes_mut().fill(0xa7);
    key.wipe();
    assert!(key.bytes().iter().all(|b| *b == 0));
}
