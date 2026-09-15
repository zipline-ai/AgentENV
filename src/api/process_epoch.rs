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
    parts.next() == Some("sandboxes")
        && parts.next().is_some()
        && matches!(
            parts.next(),
            Some("process-epochs" | "process-epoch-operations")
        )
}
