use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Reserve epoch control before host/header proxy classification. A legacy API key
/// or guest traffic token is never epoch authority, and absent enrollment must not
/// cause scheduling, auto-resume, or guest I/O. Capability remains unavailable.
pub(crate) async fn refuse_dormant(request: Request, next: Next) -> Response {
    if reserved_path(request.uri().path()) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "managed process epochs unavailable",
        )
            .into_response();
    }
    next.run(request).await
}
fn reserved_path(path: &str) -> bool {
    let mut path = path.to_owned();
    for _ in 0..8 {
        let decoded = percent_encoding::percent_decode_str(&path)
            .decode_utf8_lossy()
            .into_owned();
        if decoded == path {
            break;
        }
        path = decoded;
    }
    let mut parts = path.trim_start_matches('/').split('/').peekable();
    while parts.peek() == Some(&"proxy") {
        parts.next();
    }
    // Host/header routing uses the bare guest namespace, without sandboxes/{id}.
    match parts.next() {
        Some("process-epochs" | "process-epoch-operations") => true,
        Some("sandboxes") => {
            parts.next().is_some()
                && matches!(
                    parts.next(),
                    Some("process-epochs" | "process-epoch-operations")
                )
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, middleware, Router};
    use http_body_util::BodyExt;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn bare_epoch_routing_matrix_never_enters_downstream() {
        let calls = Arc::new(AtomicUsize::new(0));
        let recorded = calls.clone();
        let app = Router::new()
            .fallback(move || {
                let recorded = recorded.clone();
                async move {
                    recorded.fetch_add(1, Ordering::SeqCst);
                    "ordinary guest path"
                }
            })
            .layer(middleware::from_fn(refuse_dormant));
        for path in [
            "/process-epochs/seal",
            "/process-epoch-operations/operation-a",
            "/process-epochs/unsupported",
            "/process-epochs",
            "/process-epoch-operations",
            "/process%2depochs/seal",
            "/process%252depoch-operations/operation-a",
            "/process-epochs%2fseal",
        ] {
            for route in [
                "plain",
                "host",
                "headers",
                "proxy",
                "encoded-proxy",
                "nested-proxy",
                "sandbox-path",
            ] {
                let uri = match route {
                    "proxy" => format!("/proxy{path}"),
                    "encoded-proxy" => format!("/proxy%2f{}", path.trim_start_matches('/')),
                    "nested-proxy" => format!("/proxy/proxy{path}"),
                    "sandbox-path" => format!("/sandboxes/runtime-a{path}"),
                    _ => path.to_string(),
                };
                let mut req = Request::builder().method("POST").uri(&uri);
                if route == "host" {
                    req = req.header("host", "49983-runtime-a.sandbox.example.invalid");
                }
                if route == "headers" {
                    req = req
                        .header("x-agentenv-sandbox-id", "runtime-a")
                        .header("x-agentenv-target-port", "49983");
                }
                let response = app
                    .clone()
                    .oneshot(req.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "{route} {uri}"
                );
                assert_eq!(
                    response.into_body().collect().await.unwrap().to_bytes(),
                    "managed process epochs unavailable",
                    "{route} {uri}"
                );
                assert_eq!(calls.load(Ordering::SeqCst), 0, "{route} {uri}");
            }
        }
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
