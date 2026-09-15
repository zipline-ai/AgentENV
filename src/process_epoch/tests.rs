use super::*;
fn allocation() -> Allocation {
    Allocation {
        controller: "controller-A".into(),
        tenant_id: "tenant-A".into(),
        sandbox_id: "sandbox-A".into(),
        runtime_id: Uuid::new_v4(),
        runtime_incarnation: Uuid::new_v4(),
        enrollment_revision: 7,
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

#[tokio::test]
async fn review_reopen_cannot_claim_before_enrollment_reconciliation() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    let a = allocation();
    let ledger = HostLedger::initialize(path.clone(), a.clone()).await?;
    let op = operation(a.clone());
    assert!(ledger.claim(op.clone()).await?);
    drop(ledger);
    let ledger = HostLedger::reopen(path, a).await?;
    assert!(ledger.lookup(&op).await?.is_some());
    assert!(!ledger.claim(op.clone()).await?);
    let mut fresh = op;
    fresh.operation_id = Uuid::new_v4();
    fresh.epoch_id = Uuid::new_v4();
    let result = ledger.claim(fresh).await;
    assert!(
        !matches!(result, Ok(true)),
        "reopened unreconciled enrollment issued a new claim: {result:?}"
    );
    Ok(())
}

#[tokio::test]
async fn failed_parent_confirmation_must_fail_initialization() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let result =
        HostLedger::initialize_with_confirmation(dir.path().join("ledger"), allocation(), |_| {
            anyhow::bail!("injected parent sync failure")
        })
        .await;
    assert!(
        result.is_err(),
        "initialization acknowledged without parent-directory confirmation"
    );
    Ok(())
}

#[tokio::test]
async fn reconciliation_requires_current_revision_and_preserves_closed_epochs() -> anyhow::Result<()>
{
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    let a = allocation();
    let op = operation(a.clone());
    let ledger = HostLedger::initialize(path.clone(), a.clone()).await?;
    assert!(ledger.claim(op.clone()).await?);
    drop(ledger);
    let mut stale = a.clone();
    stale.enrollment_revision -= 1;
    assert!(HostLedger::reopen(path.clone(), stale.clone())
        .await
        .is_err());
    let ledger = HostLedger::reopen(path.clone(), a.clone()).await?;
    let state = ledger.enrollment().await?;
    assert_eq!(state.admission, Admission::Unreconciled);
    assert_eq!(state.recovery_revision, 1);
    let before = ledger.db.entries().await?;
    assert!(ledger
        .reconcile(stale, state.recovery_revision, op.epoch_id)
        .await
        .is_err());
    assert!(ledger.reconcile(a.clone(), 0, op.epoch_id).await.is_err());
    assert!(ledger
        .reconcile(a.clone(), state.recovery_revision, Uuid::new_v4())
        .await
        .is_err());
    assert_eq!(before, ledger.db.entries().await?);
    ledger
        .reconcile(a.clone(), state.recovery_revision, op.epoch_id)
        .await?;
    let mut fresh = op.clone();
    fresh.operation_id = Uuid::new_v4();
    assert!(ledger.claim(fresh.clone()).await?);
    ledger.close(a.clone(), state.recovery_revision).await?;
    let mut another = fresh.clone();
    another.operation_id = Uuid::new_v4();
    assert!(ledger.claim(another.clone()).await.is_err());
    drop(ledger);
    let ledger = HostLedger::reopen(path, a.clone()).await?;
    let state2 = ledger.enrollment().await?;
    assert_eq!(state2.recovery_revision, 2);
    assert_eq!(state2.admission, Admission::Unreconciled);
    assert!(state2.closed);
    assert!(ledger
        .reconcile(a, state2.recovery_revision, op.epoch_id)
        .await
        .is_err());
    assert!(ledger.claim(another).await.is_err());
    assert!(!ledger.claim(fresh).await?);
    Ok(())
}

#[tokio::test]
async fn parent_confirmation_obligation_survives_failure_and_reopen() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    let a = allocation();
    let expected_parent = dir.path().to_path_buf();
    assert!(
        HostLedger::initialize_with_confirmation(path.clone(), a.clone(), move |p| {
            assert_eq!(p.parent(), Some(expected_parent.as_path()));
            assert!(
                p.join("CURRENT").exists(),
                "pending DB must exist before confirmation"
            );
            anyhow::bail!("injected parent sync failure")
        })
        .await
        .is_err()
    );
    assert!(HostLedger::initialize(path.clone(), a.clone())
        .await
        .is_err());
    let ledger = HostLedger::reopen(path.clone(), a.clone()).await?;
    let before = ledger.enrollment().await?;
    assert!(!before.directory_confirmed);
    let op = operation(a.clone());
    assert!(ledger.claim(op.clone()).await.is_err());
    assert!(ledger
        .reconcile(a.clone(), before.recovery_revision, op.epoch_id)
        .await
        .is_err());
    let rows = ledger.db.entries().await?;
    assert!(ledger
        .confirm_directory_with(|_| anyhow::bail!("retry sync failure"))
        .await
        .is_err());
    assert_eq!(rows, ledger.db.entries().await?);
    // Real parent-directory fsync succeeds; it confirms publication, not admission.
    ledger.confirm_directory().await?;
    let confirmed = ledger.enrollment().await?;
    assert!(confirmed.directory_confirmed);
    assert_eq!(confirmed.admission, Admission::Unreconciled);
    assert!(ledger.claim(op.clone()).await.is_err());
    ledger
        .reconcile(a.clone(), confirmed.recovery_revision, op.epoch_id)
        .await?;
    assert!(ledger.claim(op.clone()).await?);
    drop(ledger);
    let ledger = HostLedger::reopen(path, a).await?;
    assert!(ledger.enrollment().await?.directory_confirmed);
    assert!(!ledger.claim(op).await?);
    Ok(())
}

#[tokio::test]
async fn concurrent_reconciliation_has_one_winner_and_claims_follow_its_commit(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    let a = allocation();
    let op = operation(a.clone());
    let ledger = HostLedger::initialize(path.clone(), a.clone()).await?;
    assert!(ledger.claim(op.clone()).await?);
    drop(ledger);
    let ledger = HostLedger::reopen(path, a.clone()).await?;
    let state = ledger.enrollment().await?;
    let mut fresh = op.clone();
    fresh.operation_id = Uuid::new_v4();
    // Claim-first is denied and leaves the whole ledger unchanged.
    let before = ledger.db.entries().await?;
    assert!(ledger.claim(fresh.clone()).await.is_err());
    assert_eq!(before, ledger.db.entries().await?);
    let (entered, entered_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = tokio::sync::oneshot::channel();
    let l = ledger.clone();
    let captured = a.clone();
    let winner = tokio::spawn(async move {
        l.reconcile_before_commit(captured, state.recovery_revision, op.epoch_id, async move {
            entered.send(()).unwrap();
            release_rx.await.unwrap();
        })
        .await
    });
    entered_rx.await?;
    assert_eq!(
        ledger.enrollment().await?.admission,
        Admission::Unreconciled
    );
    let mut claim = Box::pin(ledger.claim(fresh.clone()));
    assert!(futures::poll!(&mut claim).is_pending());
    let mut loser = Box::pin(ledger.reconcile(a.clone(), state.recovery_revision, op.epoch_id));
    assert!(futures::poll!(&mut loser).is_pending());
    release.send(()).unwrap();
    winner.await??;
    assert!(loser.await.is_err());
    assert!(claim.await?);
    assert_eq!(ledger.enrollment().await?.admission, Admission::Open);
    ledger.close(a.clone(), state.recovery_revision).await?;
    assert!(ledger
        .reconcile(a, state.recovery_revision, op.epoch_id)
        .await
        .is_err());
    assert!(!ledger.claim(fresh).await?);
    Ok(())
}

#[tokio::test]
async fn directory_confirmation_blocks_ack_and_cannot_open_admission() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    let a = allocation();
    assert!(
        HostLedger::initialize_with_confirmation(path.clone(), a.clone(), |p| {
            sync_parent(p)?;
            anyhow::bail!("failure after parent fsync before obligation completion")
        })
        .await
        .is_err()
    );
    let ledger = HostLedger::reopen(path, a.clone()).await?;
    let (entered, entered_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let l = ledger.clone();
    let confirmation = tokio::spawn(async move {
        l.confirm_directory_with(move |p| {
            entered.send(()).unwrap();
            release_rx.recv().unwrap();
            sync_parent(p)
        })
        .await
    });
    entered_rx.await?;
    assert!(!confirmation.is_finished());
    assert!(!ledger.enrollment().await?.directory_confirmed);
    let op = operation(a.clone());
    let mut claim = Box::pin(ledger.claim(op.clone()));
    assert!(futures::poll!(&mut claim).is_pending());
    release.send(())?;
    confirmation.await??;
    assert!(claim.await.is_err());
    let state = ledger.enrollment().await?;
    assert!(state.directory_confirmed);
    assert_eq!(state.admission, Admission::Unreconciled);
    ledger
        .reconcile(a, state.recovery_revision, op.epoch_id)
        .await?;
    assert!(ledger.claim(op).await?);
    Ok(())
}

#[tokio::test]
async fn closing_claim_blocks_new_operations_before_any_forward() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let a = allocation();
    let ledger = HostLedger::initialize(dir.path().join("ledger"), a.clone()).await?;
    let prior = operation(a.clone());
    assert!(ledger.claim(prior.clone()).await?);
    let mut close = prior.clone();
    close.operation_id = Uuid::new_v4();
    close.request_sha256 = "b".repeat(64);
    assert!(ledger.begin_close(close.clone()).await?);
    assert_eq!(ledger.enrollment().await?.admission, Admission::Closed);
    assert!(!ledger.begin_close(close.clone()).await?);
    let before = ledger.db.entries().await?;
    let mut late = prior.clone();
    late.operation_id = Uuid::new_v4();
    assert!(ledger.claim(late).await.is_err());
    let mut different_close = close.clone();
    different_close.operation_id = Uuid::new_v4();
    assert!(ledger.begin_close(different_close).await.is_err());
    assert_eq!(before, ledger.db.entries().await?);
    assert_eq!(ledger.lookup(&prior).await?.unwrap().evidence_class, None);
    assert_eq!(ledger.lookup(&close).await?.unwrap().evidence_class, None);
    Ok(())
}

#[tokio::test]
async fn competing_close_claims_freeze_one_inventory_and_restart_never_resends(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    let a = allocation();
    let ledger = HostLedger::initialize(path.clone(), a.clone()).await?;
    let first = operation(a.clone());
    assert!(ledger.claim(first.clone()).await?);
    let mut jobs = Vec::new();
    for _ in 0..16 {
        let l = ledger.clone();
        let mut o = first.clone();
        o.operation_id = Uuid::new_v4();
        jobs.push(tokio::spawn(
            async move { (o.clone(), l.begin_close(o).await) },
        ));
    }
    let mut winner = None;
    for job in jobs {
        let (op, result) = job.await?;
        if result.is_ok_and(|fresh| fresh) {
            assert!(winner.replace(op).is_none());
        }
    }
    let winner = winner.context("one close winner")?;
    let raw = ledger.db.get(b"closing_intent".to_vec()).await?.unwrap();
    let intent: ClosingIntent = serde_json::from_slice(&raw)?;
    assert_eq!(intent.operation, winner);
    assert_eq!(intent.inventory.len(), 2);
    assert!(intent.inventory.contains(&first));
    assert!(intent.inventory.contains(&winner));
    use sha2::{Digest, Sha256};
    assert_eq!(
        intent.inventory_sha256,
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&intent.inventory)?)
        )
    );
    drop(ledger);
    let ledger = HostLedger::reopen(path, a).await?;
    assert!(!ledger.begin_close(winner).await?);
    assert_eq!(ledger.db.get(b"closing_intent".to_vec()).await?, Some(raw));
    assert!(ledger.enrollment().await?.closed);
    Ok(())
}
