//! Bounded, node-local observations. These records never authorize lifecycle work.
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use uuid::Uuid;

const TTL: Duration = Duration::from_secs(600);
const CAPACITY: usize = 4096;
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Unknown,
    FetchingSnapshot,
    LoadingSnapshot,
    BootingGuest,
}
#[derive(Clone, Serialize)]
pub struct Status {
    pub attempt_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
    pub phase: Phase,
    pub elapsed_ms: u64,
    pub done: bool,
}
struct Record {
    valid: std::sync::atomic::AtomicBool,
    sandbox_id: Mutex<Option<String>>,
    started: Instant,
    phase_started: Mutex<Instant>,
    status: Mutex<Option<Status>>,
    done: std::sync::atomic::AtomicBool,
}
struct Lease {
    id: Uuid,
    record: Arc<Record>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.record
            .done
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}
#[derive(Clone)]
pub struct Observation(Arc<Lease>);
#[derive(Default)]
struct Registry(Mutex<HashMap<Uuid, Arc<Record>>>);
impl Registry {
    fn begin(&self, id: Uuid) -> Option<Observation> {
        let mut records = self.0.lock().unwrap_or_else(|e| e.into_inner());
        records.retain(|_, record| record.started.elapsed() < TTL);
        if let Some(existing) = records.get(&id) {
            existing
                .valid
                .store(false, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        if records.len() >= CAPACITY {
            return None;
        }
        let record = Arc::new(Record {
            valid: true.into(),
            sandbox_id: Mutex::new(None),
            started: Instant::now(),
            phase_started: Mutex::new(Instant::now()),
            status: Mutex::new(None),
            done: false.into(),
        });
        records.insert(id, record.clone());
        Some(Observation(Arc::new(Lease { id, record })))
    }
    fn read(&self, id: Uuid) -> Option<Status> {
        let records = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let record = records.get(&id)?;
        if record.started.elapsed() >= TTL
            || !record.valid.load(std::sync::atomic::Ordering::Relaxed)
        {
            return None;
        }
        let guard = record.status.lock().unwrap_or_else(|e| e.into_inner());
        let mut status = guard.clone()?;
        status.sandbox_id = record
            .sandbox_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        status.elapsed_ms = record
            .phase_started
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .elapsed()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        status.done = record.done.load(std::sync::atomic::Ordering::Relaxed);
        Some(status)
    }
}
fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::default)
}
pub fn begin(id: Uuid) -> Option<Observation> {
    registry().begin(id)
}
pub fn read(id: Uuid) -> Option<Status> {
    registry().read(id)
}
tokio::task_local! { static CURRENT: Option<Observation>; }
pub fn current() -> Option<Observation> {
    CURRENT.try_with(Clone::clone).ok().flatten()
}
pub async fn scope<T>(
    observation: Option<Observation>,
    future: impl std::future::Future<Output = T>,
) -> T {
    CURRENT.scope(observation, future).await
}
pub fn phase(phase: Phase) {
    if let Some(observation) = current() {
        let mut status = observation
            .0
            .record
            .status
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if status.as_ref().is_none_or(|status| status.phase != phase) {
            *observation
                .0
                .record
                .phase_started
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Instant::now();
        }
        match status.as_mut() {
            Some(status) => status.phase = phase,
            None => {
                *status = Some(Status {
                    attempt_id: observation.0.id,
                    sandbox_id: None,
                    phase,
                    elapsed_ms: 0,
                    done: false,
                })
            }
        }
    }
}
pub fn bind(sandbox_id: String) {
    if let Some(observation) = current() {
        let mut bound = observation
            .0
            .record
            .sandbox_id
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match bound.as_ref() {
            None => *bound = Some(sandbox_id),
            Some(existing) if existing != &sandbox_id => {
                observation
                    .0
                    .record
                    .valid
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            }
            Some(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn launch_observation_cannot_rebind_to_a_replacement_runtime() {
        let registry = Registry::default();
        let id = Uuid::new_v4();
        scope(registry.begin(id), async {
            phase(Phase::BootingGuest);
            bind("original".into());
            bind("original".into());
            assert!(registry.read(id).is_some());
            bind("replacement".into());
            assert!(registry.read(id).is_none());
        })
        .await;
        assert!(registry.read(id).is_none());
    }
    #[tokio::test]
    async fn launch_observation_capacity_and_duplicate_only_disable_observation() {
        let registry = Registry::default();
        let id = Uuid::new_v4();
        let lease = registry.begin(id).unwrap();
        scope(Some(lease.clone()), async {
            phase(Phase::LoadingSnapshot);
        })
        .await;
        assert!(registry.read(id).is_some());
        assert!(registry.begin(id).is_none());
        assert!(registry.read(id).is_none());
        scope(Some(lease), async {
            phase(Phase::BootingGuest);
        })
        .await;
        assert!(registry.read(id).is_none());
        for _ in 1..CAPACITY {
            assert!(registry.begin(Uuid::new_v4()).is_some());
        }
        let unavailable = registry.begin(Uuid::new_v4());
        assert!(unavailable.is_none());
        assert_eq!(scope(unavailable, async { 42 }).await, 42);
    }
    #[tokio::test]
    async fn launch_observation_follows_detached_work_without_authority() {
        let registry = Registry::default();
        let id = Uuid::new_v4();
        let observation = registry.begin(id).unwrap();
        assert!(registry.read(id).is_none());
        let (release, wait) = tokio::sync::oneshot::channel();
        let (task,) = scope(Some(observation), async {
            phase(Phase::FetchingSnapshot);
            bind("exact-runtime".into());
            let inherited = current();
            (tokio::spawn(scope(inherited, async {
                wait.await.unwrap();
                phase(Phase::LoadingSnapshot);
            })),)
        })
        .await;
        let status = registry.read(id).unwrap();
        assert_eq!(status.sandbox_id.as_deref(), Some("exact-runtime"));
        assert!(!status.done);
        assert_eq!(
            serde_json::to_value(status).unwrap()["phase"],
            "fetching_snapshot"
        );
        release.send(()).unwrap();
        task.await.unwrap();
        assert!(registry.read(id).unwrap().done);
        assert!(registry.read(Uuid::new_v4()).is_none());
    }
    #[tokio::test]
    async fn launch_observation_cancellation_finishes_without_fabricated_phases() {
        let registry = Registry::default();
        let id = Uuid::new_v4();
        let (ready, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(scope(registry.begin(id), async {
            phase(Phase::BootingGuest);
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        }));
        started.await.unwrap();
        assert!(!registry.read(id).unwrap().done);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let value = serde_json::to_value(registry.read(id).unwrap()).unwrap();
        assert_eq!(value["phase"], "booting_guest");
        assert_eq!(value["done"], true);
        assert!(value.get("sandbox_id").is_none());
        assert_eq!(value.as_object().unwrap().len(), 4);
    }
}
