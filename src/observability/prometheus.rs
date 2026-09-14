use std::future::Future;
use std::time::Instant;

use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

pub async fn http_metrics_middleware(request: Request, next: Next) -> Response {
    if request.uri().path() == "/metrics" {
        return next.run(request).await;
    }

    let method = http_method_label(request.method());
    let route = http_route_label(request.uri().path());
    let start = Instant::now();
    let response = next.run(request).await;
    let status = http_status_label(response.status());
    let route_source = response
        .extensions()
        .get::<HttpRouteSource>()
        .copied()
        .unwrap_or(HttpRouteSource::ControlPlane)
        .as_str();
    let elapsed = start.elapsed().as_secs_f64();

    metrics::histogram!(
        "agentenv_http_request_duration_seconds",
        "method" => method,
        "route" => route,
        "route_source" => route_source,
        "status" => status,
    )
    .record(elapsed);

    response
}

#[derive(Clone, Copy)]
pub(crate) enum HttpRouteSource {
    ControlPlane,
    ProxyHost,
    ProxyHeader,
    ProxyPrefix,
}

impl HttpRouteSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::ControlPlane => "control_plane",
            Self::ProxyHost => "proxy_host",
            Self::ProxyHeader => "proxy_header",
            Self::ProxyPrefix => "proxy_prefix",
        }
    }
}

pub struct SandboxStageTimer {
    operation: &'static str,
}

impl SandboxStageTimer {
    pub fn new(operation: &'static str) -> Self {
        Self { operation }
    }

    pub async fn time<F, T, E>(&self, stage: &'static str, future: F) -> Result<T, E>
    where
        F: Future<Output = Result<T, E>>,
    {
        let _inflight = SandboxStageInFlight::new(self.operation, stage);
        let mut metric = MetricGuard::operation_stage(self.operation, stage);
        let result = future.await;
        metric.finish(&result);
        result
    }
}

struct SandboxStageInFlight {
    operation: &'static str,
    stage: &'static str,
}

impl SandboxStageInFlight {
    fn new(operation: &'static str, stage: &'static str) -> Self {
        metrics::gauge!(
            "agentenv_sandbox_stage_inflight",
            "operation" => operation,
            "stage" => stage,
        )
        .increment(1.0);
        Self { operation, stage }
    }
}

impl Drop for SandboxStageInFlight {
    fn drop(&mut self) {
        metrics::gauge!(
            "agentenv_sandbox_stage_inflight",
            "operation" => self.operation,
            "stage" => self.stage,
        )
        .decrement(1.0);
    }
}

pub struct MetricGuard {
    metric: &'static str,
    label: MetricGuardLabel,
    start: Instant,
    status: &'static str,
    recorded: bool,
    node_sample: Option<(crate::observability::launch::Observation, &'static str)>,
}

#[derive(Clone, Copy)]
enum MetricGuardLabel {
    Operation(&'static str),
    OperationArtifact {
        operation: &'static str,
        artifact: &'static str,
    },
    Stage(&'static str),
    OperationStage(&'static str, &'static str),
}

fn node_sample_stage(operation: &str, stage: &str) -> Option<&'static str> {
    match (operation, stage) {
        ("create_warm", "load_snapshot") => Some("fetch_snapshot"),
        ("guest_boot", "load_snapshot") => Some("load_snapshot"),
        ("guest_boot", "vm_start_issued") => Some("vm_start_issued"),
        ("guest_boot", "envd_ready") => Some("envd_ready"),
        ("guest_boot", "memory_download_release") => Some("memory_download_release"),
        ("guest_boot", "rootfs_download_release") => Some("rootfs_download_release"),
        ("guest_boot", "envd_init") => Some("envd_init"),
        _ => None,
    }
}

impl MetricGuard {
    fn operation_stage(operation: &'static str, stage: &'static str) -> Self {
        Self {
            metric: "agentenv_sandbox_stage_duration_seconds",
            label: MetricGuardLabel::OperationStage(operation, stage),
            start: Instant::now(),
            status: "canceled",
            recorded: false,
            node_sample: crate::observability::launch::current()
                .zip(node_sample_stage(operation, stage)),
        }
    }

    pub fn operation(metric: &'static str, operation: &'static str) -> Self {
        // A guard dropped before finish() is treated as cancellation. That
        // includes futures dropped by caller-side timeouts, which is useful
        // signal distinct from an operation returning an error.
        Self {
            metric,
            label: MetricGuardLabel::Operation(operation),
            start: Instant::now(),
            status: "canceled",
            recorded: false,
            node_sample: None,
        }
    }

    /// Operation metric with an additional artifact dimension, used by OSS
    /// upload operations so per-artifact latency and cancellation stay
    /// visible (a dropped guard still records with status "canceled").
    pub fn operation_artifact(
        metric: &'static str,
        operation: &'static str,
        artifact: &'static str,
    ) -> Self {
        Self {
            metric,
            label: MetricGuardLabel::OperationArtifact {
                operation,
                artifact,
            },
            start: Instant::now(),
            status: "canceled",
            recorded: false,
            node_sample: None,
        }
    }

    pub fn stage(metric: &'static str, stage: &'static str) -> Self {
        Self {
            metric,
            label: MetricGuardLabel::Stage(stage),
            start: Instant::now(),
            status: "canceled",
            recorded: false,
            node_sample: None,
        }
    }

    pub fn finish<T, E>(&mut self, result: &Result<T, E>) {
        self.status = result_status(result.is_ok());
        self.record();
    }

    fn record(&mut self) {
        if self.recorded {
            return;
        }
        self.recorded = true;
        let duration = self.start.elapsed();
        let elapsed = duration.as_secs_f64();
        if let Some((observation, stage)) = self.node_sample.as_ref() {
            if let Some(dispatch_attempt) = observation.sample_attempt() {
                let sample = serde_json::json!({
                    "version": 1,
                    "dispatch_attempt": dispatch_attempt,
                    "stage": stage,
                    "outcome": match self.status { "ok" => "success", "error" => "failed", _ => "canceled" },
                    "duration_ms": duration.as_millis().min(u64::MAX as u128) as u64,
                });
                if let Ok(node_sample_json) = serde_json::to_string(&sample) {
                    // Explicit opt-in sample; keep coordinates out of metric labels.
                    tracing::info!(node_sample_json, "node launch phase sample");
                }
            }
        }
        match self.label {
            MetricGuardLabel::OperationStage(operation, stage) => {
                // Numeric timing under the caller's protected trace context.
                // Fixed labels only; no user, image URL or credential dimensions.
                tracing::debug!(
                    operation,
                    stage,
                    status = self.status,
                    elapsed_seconds = elapsed,
                    "sandbox stage timing"
                );
                metrics::histogram!(self.metric, "operation" => operation, "stage" => stage, "status" => self.status).record(elapsed);
            }
            MetricGuardLabel::Operation(operation) => {
                metrics::histogram!(
                    self.metric,
                    "operation" => operation,
                    "status" => self.status,
                )
                .record(elapsed);
            }
            MetricGuardLabel::OperationArtifact {
                operation,
                artifact,
            } => {
                metrics::histogram!(
                    self.metric,
                    "operation" => operation,
                    "artifact" => artifact,
                    "status" => self.status,
                )
                .record(elapsed);
            }
            MetricGuardLabel::Stage(stage) => {
                metrics::histogram!(
                    self.metric,
                    "stage" => stage,
                    "status" => self.status,
                )
                .record(elapsed);
            }
        }
    }
}

impl Drop for MetricGuard {
    fn drop(&mut self) {
        self.record();
    }
}

pub fn result_status(ok: bool) -> &'static str {
    if ok {
        "ok"
    } else {
        "error"
    }
}

pub fn http_method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        _ => "OTHER",
    }
}

pub fn http_status_label(status: StatusCode) -> &'static str {
    match status.as_u16() {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

pub fn http_route_label(path: &str) -> &'static str {
    let path = path.trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    match path {
        "/sandboxes" => "/sandboxes",
        "/sandboxes-cold" => "/sandboxes-cold",
        "/v2/sandboxes" => "/v2/sandboxes",
        "/snapshots" => "/snapshots",
        "/templates" => "/templates",
        "/v3/templates" => "/v3/templates",
        "/nodes" => "/nodes",
        "/health" => "/health",
        _ => dynamic_route_label(path),
    }
}

fn dynamic_route_label(path: &str) -> &'static str {
    let mut parts = path.trim_matches('/').split('/');
    let first = parts.next();
    let second = parts.next();
    let third = parts.next();
    let fourth = parts.next();
    let fifth = parts.next();

    match (first, second, third, fourth, fifth) {
        (Some("sandboxes"), Some(_), None, None, None) => "/sandboxes/{sandbox_id}",
        (Some("sandboxes"), Some(_), Some("snapshots"), None, None) => {
            "/sandboxes/{sandbox_id}/snapshots"
        }
        (Some("sandboxes"), Some(_), Some("network"), None, None) => {
            "/sandboxes/{sandbox_id}/network"
        }
        (Some("sandboxes"), Some(_), Some("pause"), None, None) => "/sandboxes/{sandbox_id}/pause",
        (Some("sandboxes"), Some(_), Some("resume"), None, None) => {
            "/sandboxes/{sandbox_id}/resume"
        }
        (Some("sandboxes"), Some(_), Some("fork"), None, None) => "/sandboxes/{sandbox_id}/fork",
        (Some("nodes"), Some(_), None, None, None) => "/nodes/{node_id}",
        (Some("proxy"), _, _, _, _) => "/proxy/*",
        _ => "unmatched",
    }
}

#[cfg(test)]
mod tests {
    use super::http_route_label;

    #[test]
    fn route_labels_hide_ids() {
        assert_eq!(
            http_route_label("/sandboxes/sb-1/snapshots"),
            "/sandboxes/{sandbox_id}/snapshots"
        );
        assert_eq!(http_route_label("/nodes/node-a"), "/nodes/{node_id}");
        assert_eq!(http_route_label("/templates"), "/templates");
        assert_eq!(http_route_label("/snapshots"), "/snapshots");
        assert_eq!(http_route_label("/v3/templates"), "/v3/templates");
        assert_eq!(http_route_label("/health"), "/health");
        assert_eq!(
            http_route_label("/sandboxes/sb-1/network"),
            "/sandboxes/{sandbox_id}/network"
        );
        assert_eq!(
            http_route_label("/sandboxes/sb-1/pause"),
            "/sandboxes/{sandbox_id}/pause"
        );
        assert_eq!(
            http_route_label("/sandboxes/sb-1/resume"),
            "/sandboxes/{sandbox_id}/resume"
        );
        assert_eq!(
            http_route_label("/sandboxes/sb-1/fork"),
            "/sandboxes/{sandbox_id}/fork"
        );
        assert_eq!(
            http_route_label("/templates/tpl/builds/build/status"),
            "unmatched"
        );
    }
}

#[cfg(test)]
mod stage_tests {
    use super::SandboxStageTimer;
    use metrics::{
        Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
    };
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<(Key, f64)>>>);
    struct RecordHistogram(Key, Capture);
    impl metrics::HistogramFn for RecordHistogram {
        fn record(&self, value: f64) {
            self.1 .0.lock().unwrap().push((self.0.clone(), value));
        }
    }
    impl Recorder for Capture {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn register_counter(&self, _: &Key, _: &Metadata<'_>) -> Counter {
            Counter::noop()
        }
        fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
            Gauge::noop()
        }
        fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
            Histogram::from_arc(Arc::new(RecordHistogram(key.clone(), self.clone())))
        }
    }
    #[test]
    fn stages_record_success_failure_and_dropped_future_once() {
        let capture = Capture::default();
        metrics::with_local_recorder(&capture, || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(async {
                    let timer = SandboxStageTimer::new("guest_boot");
                    assert_eq!(
                        timer.time("envd_ready", async { Ok::<_, ()>(7) }).await,
                        Ok(7)
                    );
                    assert_eq!(
                        timer.time("envd_ready", async { Err::<(), _>(9) }).await,
                        Err(9)
                    );
                    let mut canceled = Box::pin(
                        timer.time("envd_ready", std::future::pending::<Result<(), ()>>()),
                    );
                    assert!(futures::poll!(canceled.as_mut()).is_pending());
                    drop(canceled);
                });
        });
        let rows = capture.0.lock().unwrap();
        assert_eq!(rows.len(), 3);
        for ((key, duration), status) in rows.iter().zip(["ok", "error", "canceled"]) {
            assert_eq!(key.name(), "agentenv_sandbox_stage_duration_seconds");
            let labels: Vec<_> = key
                .labels()
                .map(|label| (label.key(), label.value()))
                .collect();
            assert_eq!(
                labels,
                vec![
                    ("operation", "guest_boot"),
                    ("stage", "envd_ready"),
                    ("status", status)
                ]
            );
            assert!(duration.is_finite() && *duration >= 0.0);
        }
    }
}

#[cfg(test)]
mod node_sample_tests {
    use super::SandboxStageTimer;
    use crate::observability::launch;
    use std::sync::{Arc, Mutex};
    #[derive(Clone, Default)]
    struct Writer(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn node_phase_samples_capture_dispatch_before_runtime_and_record_cancel_once() {
        let writer = Writer::default();
        let sink = writer.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || sink.clone())
            .finish();
        let dispatch = uuid::Uuid::new_v4();
        tracing::subscriber::with_default(subscriber, || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(async {
                    let timer = SandboxStageTimer::new("guest_boot");
                    timer
                        .time("envd_ready", async { Ok::<(), ()>(()) })
                        .await
                        .unwrap();
                    let (pending,) = launch::scope(launch::begin(dispatch), async {
                        SandboxStageTimer::new("create_warm")
                            .time("load_snapshot", async { Ok::<(), ()>(()) })
                            .await
                            .unwrap();
                        timer
                            .time("load_snapshot", async { Ok::<(), ()>(()) })
                            .await
                            .unwrap();
                        timer
                            .time("untrusted-extra-stage", async { Ok::<(), ()>(()) })
                            .await
                            .unwrap();
                        assert!(timer
                            .time("envd_ready", async { Err::<(), ()>(()) })
                            .await
                            .is_err());
                        let mut pending = Box::pin(
                            timer.time("vm_start_issued", std::future::pending::<Result<(), ()>>()),
                        );
                        assert!(futures::poll!(pending.as_mut()).is_pending());
                        (pending,)
                    })
                    .await;
                    assert!(launch::current().is_none());
                    drop(pending);
                });
        });
        let output = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
        let samples: Vec<serde_json::Value> = output
            .lines()
            .filter_map(|line| {
                let row: serde_json::Value = serde_json::from_str(line).unwrap();
                if row["fields"]["message"] != "node launch phase sample" {
                    return None;
                }
                Some(
                    serde_json::from_str(row["fields"]["node_sample_json"].as_str().unwrap())
                        .unwrap(),
                )
            })
            .collect();
        assert_eq!(samples.len(), 4, "{output}");
        for (row, (stage, outcome)) in samples.iter().zip([
            ("fetch_snapshot", "success"),
            ("load_snapshot", "success"),
            ("envd_ready", "failed"),
            ("vm_start_issued", "canceled"),
        ]) {
            assert_eq!(row.as_object().unwrap().len(), 5);
            assert_eq!(row["version"], 1);
            assert_eq!(row["dispatch_attempt"], dispatch.to_string());
            assert_eq!(row["stage"], stage);
            assert_eq!(row["outcome"], outcome);
            assert!(row["duration_ms"].as_u64().is_some());
        }
    }
}
