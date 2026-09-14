use super::*;

fn binding() -> OperationBinding {
    OperationBinding {
        authority: "authenticated-controller".into(),
        operation_key: "restore-LR".into(),
        request_sha256: "a".repeat(64),
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
