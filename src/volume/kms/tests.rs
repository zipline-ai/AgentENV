use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
struct Recording {
    calls: Mutex<Vec<(String, serde_json::Value)>>,
    response: Vec<u8>,
    fail: bool,
}
#[async_trait]
impl KmsTransport for Recording {
    async fn decrypt(
        &self,
        key: &str,
        request: &DecryptRequest,
        response: &mut LockedBytes,
    ) -> Result<usize, KmsDenied> {
        self.calls
            .lock()
            .unwrap()
            .push((key.into(), serde_json::to_value(request).unwrap()));
        response.bytes_mut()[..self.response.len()].copy_from_slice(&self.response);
        if self.fail {
            return Err(KmsDenied);
        }
        Ok(self.response.len())
    }
}
fn authority() -> KmsUnwrapAuthority {
    KmsUnwrapAuthority {
        _launch: UnavailableLaunchAuthority {},
        operation: RetainedKmsOperation {
            operation_id: "op".into(),
            tenant_id: "t".into(),
            volume_id: "v".into(),
            node_id: "node".into(),
            incarnation: "inc".into(),
        },
        key: "projects/p/locations/l/keyRings/r/cryptoKeys/k".into(),
        version: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1".into(),
        aad: "vol:t:v:sandbox_rootfs".into(),
        wrapped: b"wrapped".to_vec(),
        wrapped_sha256: hex::encode(Sha256::digest(b"wrapped")),
    }
}
fn response(key: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"plaintext":STANDARD.encode(key),"plaintextCrc32c":crc32c::crc32c(key).to_string(),"usedPrimary":true,"protectionLevel":"SOFTWARE"})).unwrap()
}
fn recording(response: Vec<u8>) -> Recording {
    Recording {
        calls: Mutex::new(vec![]),
        response,
        fail: false,
    }
}
#[tokio::test]
async fn kms_exact_key_ciphertext_aad_and_crc_return_locked_xts_key() {
    let r = recording(response(&[7; 64]));
    let key = unwrap_dek(authority(), &r, &mut LiveGuard).await.unwrap();
    key.with_key(|bytes| assert_eq!(bytes, &[7; 64]));
    let calls = r.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, authority().key);
    assert_eq!(
        calls[0].1,
        serde_json::json!({"ciphertext":STANDARD.encode(b"wrapped"),"additionalAuthenticatedData":STANDARD.encode(authority().aad.as_bytes()),"ciphertextCrc32c":crc32c::crc32c(b"wrapped").to_string(),"additionalAuthenticatedDataCrc32c":crc32c::crc32c(authority().aad.as_bytes()).to_string()})
    );
}
#[tokio::test]
async fn kms_wrong_binding_denies_before_transport() {
    for case in 0..6 {
        let mut a = authority();
        match case {
            0 => a.wrapped_sha256 = "0".repeat(64),
            1 => a.version = a.version.replace("/k/", "/other/"),
            2 => a.key = "https://attacker/".into(),
            3 => a.aad.clear(),
            4 => a.wrapped.clear(),
            _ => a.version.push_str("/../2"),
        };
        let r = recording(response(&[7; 64]));
        assert!(unwrap_dek(a, &r, &mut LiveGuard).await.is_err());
        assert!(r.calls.lock().unwrap().is_empty());
    }
}
#[tokio::test]
async fn kms_bad_plaintext_crc_length_or_json_denies_without_retry() {
    let mut wrong: serde_json::Value = serde_json::from_slice(&response(&[7; 64])).unwrap();
    wrong["plaintextCrc32c"] = "0".into();
    for body in [
        response(&[7; 63]),
        response(&[7; 65]),
        serde_json::to_vec(&wrong).unwrap(),
        b"{\"plaintext\":\"secret\",\"plaintext\":\"x\"}".to_vec(),
        b"{\"error\":\"secret\"}".to_vec(),
    ] {
        let r = recording(body);
        let err = unwrap_dek(authority(), &r, &mut LiveGuard)
            .await
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "volume key unavailable or denied");
        assert_eq!(r.calls.lock().unwrap().len(), 1);
    }
    let mut r = recording(vec![]);
    r.fail = true;
    assert!(unwrap_dek(authority(), &r, &mut LiveGuard).await.is_err());
    assert_eq!(r.calls.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn cancelled_kms_future_wipes_locked_response() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct Hanging {
        entered: tokio::sync::Notify,
        wiped: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl KmsTransport for Hanging {
        async fn decrypt(
            &self,
            _: &str,
            _: &DecryptRequest,
            response: &mut LockedBytes,
        ) -> Result<usize, KmsDenied> {
            response.bytes_mut().fill(0xab);
            let wiped = self.wiped.clone();
            response.after_wipe = Some(Box::new(move |bytes| {
                assert!(bytes.iter().all(|b| *b == 0));
                wiped.fetch_add(1, Ordering::SeqCst);
            }));
            self.entered.notify_one();
            std::future::pending().await
        }
    }
    let wiped = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(Hanging {
        entered: tokio::sync::Notify::new(),
        wiped: wiped.clone(),
    });
    let run = transport.clone();
    let task =
        tokio::spawn(async move { unwrap_dek(authority(), run.as_ref(), &mut LiveGuard).await });
    transport.entered.notified().await;
    task.abort();
    assert!(matches!(task.await, Err(err) if err.is_cancelled()));
    assert_eq!(wiped.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn kms_allocation_and_failure_paths_wipe_every_buffer() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    for case in 0..5 {
        let wiped = Arc::new(AtomicUsize::new(0));
        let mut allocated = 0;
        let count = wiped.clone();
        let mut r = recording(response(&[7; 64]));
        if case == 1 {
            r.response = response(&[7; 63]);
        }
        if case == 2 {
            r.fail = true;
        }
        if case == 3 {
            let mut v: serde_json::Value = serde_json::from_slice(&r.response).unwrap();
            v["plaintextCrc32c"] = "0".into();
            r.response = serde_json::to_vec(&v).unwrap();
        }
        let result = unwrap_with_allocator(authority(), &r, &mut LiveGuard, |len| {
            allocated += 1;
            if case == 4 && allocated == 2 {
                return Err(KmsDenied);
            }
            let mut bytes = LockedBytes::new(len)?;
            let count = count.clone();
            bytes.after_wipe = Some(Box::new(move |data| {
                assert!(data.iter().all(|b| *b == 0));
                count.fetch_add(1, Ordering::SeqCst);
            }));
            Ok(bytes)
        })
        .await;
        if case == 0 {
            assert!(result.is_ok());
            assert_eq!(wiped.load(Ordering::SeqCst), 1);
            drop(result);
        } else {
            assert!(result.is_err());
        }
        assert_eq!(wiped.load(Ordering::SeqCst), if case == 4 { 1 } else { 2 });
        assert_eq!(r.calls.lock().unwrap().len(), usize::from(case != 4));
    }
}
#[test]
fn kms_response_scanner_rejects_ambiguous_encodings_without_owned_strings() {
    for raw in [
        r#"{"plaintext":"\u0041","plaintextCrc32c":"0"}"#,
        r#"{"plain\u0074ext":"AA==","plaintextCrc32c":"0"}"#,
        r#"{"secret-field":"x","plaintextCrc32c":"0"}"#,
        r#"{"plaintext":"x","plaintextCrc32c":"0","usedPrimary":true,"usedPrimary":false}"#,
        r#"{"plaintext":"x","plaintextCrc32c":"0",}"#,
        r#"{"plaintext":"x","plaintextCrc32c":"0"} trailing"#,
        r#"{"plaintext":"x"}"#,
    ] {
        assert!(decode_reply(raw.as_bytes()).is_err());
    }
}

struct LiveGuard;
#[async_trait]
impl KmsEffectGuard for LiveGuard {
    async fn revalidate(&mut self, operation: &RetainedKmsOperation) -> Result<(), KmsDenied> {
        assert_eq!(
            (
                &*operation.operation_id,
                &*operation.tenant_id,
                &*operation.volume_id,
                &*operation.node_id,
                &*operation.incarnation
            ),
            ("op", "t", "v", "node", "inc")
        );
        Ok(())
    }
}
#[tokio::test]
async fn kms_fence_before_or_during_reply_denies_and_wipes() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct Fence {
        calls: usize,
        deny_at: usize,
    }
    #[async_trait]
    impl KmsEffectGuard for Fence {
        async fn revalidate(&mut self, op: &RetainedKmsOperation) -> Result<(), KmsDenied> {
            LiveGuard.revalidate(op).await?;
            self.calls += 1;
            if self.calls == self.deny_at {
                Err(KmsDenied)
            } else {
                Ok(())
            }
        }
    }
    for deny_at in [1, 2] {
        let r = recording(response(&[7; 64]));
        let mut guard = Fence { calls: 0, deny_at };
        let wiped = Arc::new(AtomicUsize::new(0));
        let result = unwrap_with_allocator(authority(), &r, &mut guard, |len| {
            let mut buffer = LockedBytes::new(len)?;
            let wiped = wiped.clone();
            buffer.after_wipe = Some(Box::new(move |bytes| {
                assert!(bytes.iter().all(|b| *b == 0));
                wiped.fetch_add(1, Ordering::SeqCst);
            }));
            Ok(buffer)
        })
        .await;
        assert!(result.is_err());
        assert_eq!(guard.calls, deny_at);
        assert_eq!(r.calls.lock().unwrap().len(), deny_at - 1);
        assert_eq!(wiped.load(Ordering::SeqCst), 2);
    }
}
#[tokio::test]
async fn kms_observed_inflight_fence_discards_late_key() {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    struct Paused {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
        calls: AtomicUsize,
    }
    #[async_trait]
    impl KmsTransport for Paused {
        async fn decrypt(
            &self,
            _: &str,
            _: &DecryptRequest,
            out: &mut LockedBytes,
        ) -> Result<usize, KmsDenied> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            self.release.notified().await;
            let body = response(&[7; 64]);
            out.bytes_mut()[..body.len()].copy_from_slice(&body);
            Ok(body.len())
        }
    }
    struct Guard(Arc<AtomicBool>);
    #[async_trait]
    impl KmsEffectGuard for Guard {
        async fn revalidate(&mut self, op: &RetainedKmsOperation) -> Result<(), KmsDenied> {
            LiveGuard.revalidate(op).await?;
            if self.0.load(Ordering::SeqCst) {
                Err(KmsDenied)
            } else {
                Ok(())
            }
        }
    }
    let remote = Arc::new(Paused {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        calls: AtomicUsize::new(0),
    });
    let fenced = Arc::new(AtomicBool::new(false));
    let wiped = Arc::new(AtomicUsize::new(0));
    let (task_remote, task_fenced, task_wiped) = (remote.clone(), fenced.clone(), wiped.clone());
    let task = tokio::spawn(async move {
        unwrap_with_allocator(
            authority(),
            task_remote.as_ref(),
            &mut Guard(task_fenced),
            |len| {
                let mut bytes = LockedBytes::new(len)?;
                let count = task_wiped.clone();
                bytes.after_wipe = Some(Box::new(move |data| {
                    assert!(data.iter().all(|b| *b == 0));
                    count.fetch_add(1, Ordering::SeqCst);
                }));
                Ok(bytes)
            },
        )
        .await
    });
    remote.entered.notified().await;
    fenced.store(true, Ordering::SeqCst);
    remote.release.notify_one();
    assert!(task.await.unwrap().is_err());
    assert_eq!(remote.calls.load(Ordering::SeqCst), 1);
    assert_eq!(wiped.load(Ordering::SeqCst), 2);
}
