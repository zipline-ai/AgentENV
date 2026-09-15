use super::*;
fn allocation() -> Allocation {
    Allocation {
        controller: "controller-A".into(),
        tenant_id: "tenant-A".into(),
        sandbox_id: "sandbox-A".into(),
        runtime_id: Uuid::new_v4(),
        runtime_incarnation: Uuid::new_v4(),
    }
}
fn operation(a: Allocation) -> Operation {
    Operation {
        allocation: a,
        epoch_id: Uuid::new_v4(),
        operation_id: Uuid::new_v4(),
        request_sha256: "a".repeat(64),
    }
}
#[tokio::test]
async fn operation_hash_is_not_a_second_identity() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let a = allocation();
    let ledger = HostLedger::initialize(dir.path().join("ledger"), a.clone()).await?;
    let op = operation(a);
    assert!(ledger.claim(op.clone()).await?);
    let before = ledger.lookup(&op).await?;
    let mut changed = op.clone();
    changed.request_sha256 = "b".repeat(64);
    assert!(ledger.claim(changed).await.is_err());
    assert_eq!(before, ledger.lookup(&op).await?);
    assert!(!ledger.claim(op).await?);
    Ok(())
}
#[tokio::test]
async fn concurrent_claim_and_restart_never_grant_second_dispatch() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    let a = allocation();
    let ledger = HostLedger::initialize(path.clone(), a.clone()).await?;
    let op = operation(a.clone());
    let mut jobs = Vec::new();
    for _ in 0..16 {
        let l = ledger.clone();
        let o = op.clone();
        jobs.push(tokio::spawn(async move { l.claim(o).await }));
    }
    let mut sends = 0;
    for job in jobs {
        sends += usize::from(job.await??);
    }
    assert_eq!(sends, 1);
    let first = ledger.lookup(&op).await?;
    drop(ledger);
    let ledger = HostLedger::reopen(path, a).await?;
    assert!(!ledger.claim(op.clone()).await?);
    assert_eq!(first, ledger.lookup(&op).await?);
    Ok(())
}
#[tokio::test]
async fn missing_or_foreign_ledger_never_initializes_on_recovery() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    let a = allocation();
    assert!(HostLedger::reopen(path.clone(), a.clone()).await.is_err());
    assert!(!path.exists());
    let ledger = HostLedger::initialize(path.clone(), a.clone()).await?;
    let op = operation(a.clone());
    assert!(ledger.claim(op.clone()).await?);
    let mut foreign = op.clone();
    foreign.allocation.tenant_id = "tenant-B".into();
    assert!(ledger.claim(foreign.clone()).await.is_err());
    assert!(ledger.lookup(&foreign).await.is_err());
    drop(ledger);
    assert!(HostLedger::reopen(path.clone(), foreign.allocation)
        .await
        .is_err());
    assert!(HostLedger::initialize(path.clone(), a.clone())
        .await
        .is_err());
    let ledger = HostLedger::reopen(path, a).await?;
    assert!(!ledger.claim(op).await?);
    Ok(())
}
#[test]
fn guest_root_cannot_label_a_receipt_as_host_cessation() -> anyhow::Result<()> {
    let op = operation(allocation());
    for class in [
        EvidenceClass::GuestReported,
        EvidenceClass::HostDispatchRecorded,
    ] {
        let receipt = Receipt {
            operation: op.clone(),
            evidence_class: Some(class),
        };
        assert!(!receipt.proves_cessation());
        let mut forged = serde_json::to_value(receipt)?;
        forged["evidence_class"] = serde_json::json!("host_scope_stopped");
        assert!(serde_json::from_value::<Receipt>(forged).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn a_forwarding_claim_is_not_evidence_of_forwarding() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let a = allocation();
    let ledger = HostLedger::initialize(dir.path().join("ledger"), a.clone()).await?;
    let op = operation(a);
    assert!(ledger.claim(op.clone()).await?);
    let raw = serde_json::to_value(ledger.lookup(&op).await?.unwrap())?;
    assert!(
        raw.get("evidence_class").is_none(),
        "claim before I/O must not certify forwarding"
    );
    Ok(())
}
