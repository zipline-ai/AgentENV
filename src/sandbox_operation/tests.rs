use super::*;

fn binding() -> OperationBinding {
    OperationBinding {
        authority: "authenticated-controller".into(),
        tenant_id: "tenant-A".into(),
        operation_key: "restore-LR".into(),
        request_sha256: "a".repeat(64),
        provider_body_sha256: "b".repeat(64),
        saved_route: "node-A/incarnation-A".into(),
    }
}

#[tokio::test]
async fn lost_acceptance_reopens_exact_durable_allocation() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = OperationReceipts::open(dir.path()).await?;
    let original = store.reserve(binding()).await?;
    drop(store);
    let restarted = OperationReceipts::open(dir.path()).await?;
    assert_eq!(restarted.reserve(binding()).await?, original);
    assert!(restarted.claim(original.clone()).await?);
    drop(restarted);
    let restarted = OperationReceipts::open(dir.path()).await?;
    let saved = restarted.reserve(binding()).await?;
    assert_eq!(saved.runtime_id, original.runtime_id);
    assert_eq!(saved.incarnation, original.incarnation);
    assert!(saved.dispatched);
    assert!(!restarted.claim(original).await?);
    Ok(())
}

#[tokio::test]
async fn concurrent_identical_requests_allocate_and_dispatch_once() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = OperationReceipts::open(dir.path()).await?;
    let mut jobs = Vec::new();
    for _ in 0..16 {
        let store = store.clone();
        jobs.push(tokio::spawn(async move {
            let receipt = store.reserve(binding()).await?;
            let send = store.claim(receipt.clone()).await?;
            anyhow::Ok((receipt.runtime_id, send))
        }));
    }
    let mut ids = std::collections::HashSet::new();
    let mut sends = 0;
    for job in jobs {
        let (id, send) = job.await??;
        ids.insert(id);
        sends += usize::from(send);
    }
    assert_eq!(ids.len(), 1);
    assert_eq!(sends, 1);
    Ok(())
}

#[tokio::test]
async fn changed_binding_or_allocation_cannot_change_receipt() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = OperationReceipts::open(dir.path()).await?;
    let original = store.reserve(binding()).await?;
    for mutate_route in [true, false] {
        let mut changed = binding();
        if mutate_route {
            changed.saved_route = "node-B".into();
        } else {
            changed.request_sha256 = "b".repeat(64);
        }
        assert!(store.reserve(changed).await.is_err());
    }
    let mut forged = original.clone();
    forged.runtime_id = Uuid::new_v4();
    assert!(store.claim(forged).await.is_err());
    let mut forged = original.clone();
    forged.incarnation = Uuid::new_v4();
    assert!(store.claim(forged).await.is_err());
    assert_eq!(
        store.lookup(&binding().authority, "restore-LR").await?,
        Some(original)
    );
    assert_eq!(
        store.lookup("foreign-controller", "restore-LR").await?,
        None
    );
    assert_eq!(store.lookup(&binding().authority, "missing").await?, None);
    Ok(())
}

#[tokio::test]
async fn lost_final_response_survives_restart_without_second_dispatch() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = OperationReceipts::open(dir.path()).await?;
    let allocation = store.reserve(binding()).await?;
    assert!(store.complete(allocation.clone()).await.is_err());
    assert!(store.claim(allocation.clone()).await?);
    let completed = store.complete(allocation.clone()).await?;
    assert!(completed.completed);
    drop(store);
    let restarted = OperationReceipts::open(dir.path()).await?;
    assert_eq!(
        restarted.lookup(&binding().authority, "restore-LR").await?,
        Some(completed.clone())
    );
    assert_eq!(restarted.complete(allocation.clone()).await?, completed);
    assert!(!restarted.claim(allocation).await?);
    Ok(())
}

#[tokio::test]
async fn requested_allocation_cannot_move_or_be_reused_after_restart() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let runtime = Uuid::new_v4();
    let incarnation = Uuid::new_v4();
    let store = OperationReceipts::open(dir.path()).await?;
    let original = store.reserve_exact(binding(), runtime, incarnation).await?;
    assert_eq!(original.runtime_id, runtime);
    assert_eq!(original.incarnation, incarnation);
    drop(store);
    let restarted = OperationReceipts::open(dir.path()).await?;
    assert_eq!(
        restarted
            .reserve_exact(binding(), runtime, incarnation)
            .await?,
        original
    );
    assert!(restarted
        .reserve_exact(binding(), Uuid::new_v4(), incarnation)
        .await
        .is_err());
    assert!(restarted
        .reserve_exact(binding(), runtime, Uuid::new_v4())
        .await
        .is_err());
    let mut other = binding();
    other.operation_key = "restore-another-operation".into();
    assert!(restarted
        .reserve_exact(other.clone(), runtime, incarnation)
        .await
        .is_err());
    assert_eq!(
        restarted
            .lookup(&other.authority, &other.operation_key)
            .await?,
        None
    );
    assert!(restarted
        .reserve_exact(other.clone(), Uuid::new_v4(), incarnation)
        .await
        .is_err());
    other.authority = "different-controller".into();
    assert!(restarted
        .reserve_exact(other.clone(), runtime, Uuid::new_v4())
        .await
        .is_err());
    assert_eq!(
        restarted
            .lookup(&other.authority, &other.operation_key)
            .await?,
        None
    );
    assert_eq!(
        restarted
            .lookup(&binding().authority, &binding().operation_key)
            .await?,
        Some(original)
    );
    Ok(())
}

#[tokio::test]
async fn worker_acceptance_is_durable_before_completion_and_duplicates_do_not_dispatch(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = OperationReceipts::open(dir.path()).await?;
    let runtime = Uuid::new_v4();
    let incarnation = Uuid::new_v4();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let entered_worker = entered.clone();
    let release_worker = release.clone();
    let worker_calls = calls.clone();
    let saved = store
        .submit_exact(
            binding(),
            runtime,
            incarnation,
            move |captured| async move {
                assert_eq!(captured.runtime_id, runtime);
                assert_eq!(captured.incarnation, incarnation);
                worker_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                entered_worker.notify_one();
                release_worker.notified().await;
                Ok(())
            },
        )
        .await?;
    entered.notified().await;
    assert!(saved.dispatched);
    assert!(!saved.completed);
    let durable = store
        .lookup(&saved.binding.authority, &saved.binding.operation_key)
        .await?
        .unwrap();
    assert!(durable.dispatched);
    assert!(!durable.completed);
    let duplicate_calls = calls.clone();
    let (unexpected_send, unexpected_receive) = tokio::sync::oneshot::channel();
    let repeated = store
        .submit_exact(binding(), runtime, incarnation, move |_| async move {
            duplicate_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = unexpected_send.send(());
            Ok(())
        })
        .await?;
    assert_eq!(repeated.runtime_id, runtime);
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(2), unexpected_receive)
            .await?
            .is_err()
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if store
                .lookup(&saved.binding.authority, &saved.binding.operation_key)
                .await?
                .unwrap()
                .completed
            {
                break anyhow::Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn changed_tenant_or_provider_body_cannot_reuse_a_receipt() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = OperationReceipts::open(dir.path()).await?;
    let original = store.reserve(binding()).await?;
    for changed_tenant in [false, true] {
        let mut other = binding();
        if changed_tenant {
            other.tenant_id = "tenant-B".into();
        } else {
            other.provider_body_sha256 = "c".repeat(64);
        }
        assert!(store
            .reserve_exact(other, original.runtime_id, original.incarnation)
            .await
            .is_err());
        assert_eq!(
            store
                .lookup(&original.binding.authority, &original.binding.operation_key)
                .await?
                .unwrap(),
            original
        );
    }
    Ok(())
}

// Run the receipt worker in a separate OS process so the parent can terminate
// it after the durable claim, without a clean RocksDB shutdown.
#[tokio::test]
async fn receipt_worker_process_fixture() -> anyhow::Result<()> {
    let Some(path) = std::env::var_os("AENV_TEST_RECEIPT_WORKER_DIR") else {
        return Ok(());
    };
    let path = std::path::PathBuf::from(path);
    let store = OperationReceipts::open(path.join("receipts")).await?;
    let captured = store.reserve(binding()).await?;
    tokio::fs::write(path.join("allocation.json"), serde_json::to_vec(&captured)?).await?;
    let marker = path.join("worker-started");
    store
        .submit_exact(
            binding(),
            captured.runtime_id,
            captured.incarnation,
            move |_| async move {
                tokio::fs::write(marker, b"one worker").await?;
                std::future::pending::<()>().await;
                Ok(())
            },
        )
        .await?;
    std::future::pending::<()>().await;
    Ok(())
}

#[tokio::test]
async fn killed_worker_restart_retains_claim_and_never_redispatches() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "sandbox_operation::tests::receipt_worker_process_fixture",
            "--nocapture",
        ])
        .env("AENV_TEST_RECEIPT_WORKER_DIR", dir.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !dir.path().join("worker-started").exists() {
            anyhow::ensure!(child.try_wait()?.is_none(), "worker exited before claim");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        anyhow::Ok(())
    })
    .await??;
    child.kill().await?;
    let _ = child.wait().await?;
    let original: OperationReceipt =
        serde_json::from_slice(&tokio::fs::read(dir.path().join("allocation.json")).await?)?;
    let restarted = OperationReceipts::open(dir.path().join("receipts")).await?;
    let before = restarted
        .lookup(&binding().authority, &binding().operation_key)
        .await?
        .unwrap();
    assert!(before.dispatched);
    assert!(!before.completed);
    assert_eq!(before.runtime_id, original.runtime_id);
    assert_eq!(before.incarnation, original.incarnation);
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worker_calls = calls.clone();
    let (unexpected_send, unexpected_receive) = tokio::sync::oneshot::channel();
    let replay = restarted
        .submit_exact(
            binding(),
            original.runtime_id,
            original.incarnation,
            move |_| async move {
                worker_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = unexpected_send.send(());
                Ok(())
            },
        )
        .await?;
    assert_eq!(replay, before);
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(2), unexpected_receive)
            .await?
            .is_err()
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        restarted
            .lookup(&binding().authority, &binding().operation_key)
            .await?,
        Some(before)
    );
    assert_eq!(
        tokio::fs::read(dir.path().join("worker-started")).await?,
        b"one worker"
    );
    Ok(())
}
