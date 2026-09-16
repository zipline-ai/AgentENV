use super::*;
use axum::{
    extract::{Request, State},
    routing::post,
    Router,
};
use std::sync::{Arc, Mutex};
struct Recording {
    calls: Mutex<Vec<(String, serde_json::Value)>>,
    status: u16,
    body: String,
}
async fn handle(State(s): State<Arc<Recording>>, req: Request) -> axum::response::Response {
    assert_eq!(req.uri().path(), "/api/internal/launch-grants/consume");
    let auth = req
        .headers()
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let body = axum::body::to_bytes(req.into_body(), 8192).await.unwrap();
    s.calls
        .lock()
        .unwrap()
        .push((auth, serde_json::from_slice(&body).unwrap()));
    axum::response::Response::builder()
        .status(s.status)
        .header("location", "/must-not-follow")
        .body(axum::body::Body::from(s.body.clone()))
        .unwrap()
}
async fn setup(
    status: u16,
    body: &str,
) -> (
    HttpGrantConsumer,
    Arc<Recording>,
    tokio::task::JoinHandle<()>,
) {
    let recording = Arc::new(Recording {
        calls: Mutex::new(vec![]),
        status,
        body: body.into(),
    });
    let app = Router::new()
        .route("/api/internal/launch-grants/consume", post(handle))
        .with_state(recording.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let consumer = HttpGrantConsumer::build(
        base.parse().unwrap(),
        "node".into(),
        "boot".into(),
        "test-token",
    )
    .unwrap();
    (consumer, recording, task)
}
fn request() -> ConsumeRequest {
    ConsumeRequest {
        grant_id: "grant".into(),
        payload_sha256: "a".repeat(64),
        node_id: "node".into(),
        incarnation: "boot".into(),
    }
}
#[tokio::test]
async fn authenticated_consume_sends_exact_identity_once() {
    let (c, r, t) = setup(
        200,
        r#"{"state":"consumed","tenant_id":"tenant","volume_id":"volume"}"#,
    )
    .await;
    let result = c.consume(request()).await.unwrap();
    assert_eq!(result.tenant_id, "tenant");
    let calls = r.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "Bearer test-token");
    assert_eq!(
        calls[0].1,
        serde_json::json!({"grant_id":"grant","payload_sha256":"a".repeat(64),"node_id":"node","incarnation":"boot"})
    );
    t.abort();
}
#[tokio::test]
async fn consume_redirect_server_error_and_malformed_reply_do_not_retry() {
    for (status, body) in [
        (307, ""),
        (500, "provider secret"),
        (404, ""),
        (
            200,
            r#"{"state":"consumed","state":"issued","tenant_id":"t","volume_id":"v"}"#,
        ),
        (200, "null"),
    ] {
        let (c, r, t) = setup(status, body).await;
        assert_eq!(c.consume(request()).await, Err(GrantDenied));
        assert_eq!(r.calls.lock().unwrap().len(), 1);
        t.abort();
    }
    let (c, r, t) = setup(200, &"x".repeat(8193)).await;
    assert_eq!(c.consume(request()).await, Err(GrantDenied));
    assert_eq!(r.calls.lock().unwrap().len(), 1);
    t.abort();
}
#[tokio::test]
async fn consume_wrong_node_or_incarnation_denied_before_network() {
    let (c, r, t) = setup(200, "{}").await;
    let mut q = request();
    q.node_id = "foreign".into();
    assert_eq!(c.consume(q).await, Err(GrantDenied));
    let mut q = request();
    q.incarnation = "old".into();
    assert_eq!(c.consume(q).await, Err(GrantDenied));
    assert!(r.calls.lock().unwrap().is_empty());
    t.abort();
}
#[test]
fn consume_configuration_requires_tls_identity_and_secret_safe_endpoint() {
    for base in [
        "http://app/",
        "https://user:secret@app/",
        "https://app/?key=secret",
        "https://app/#frag",
        "https://app/arbitrary",
    ] {
        assert!(HttpGrantConsumer::new(base, "node".into(), "boot".into(), "token").is_err());
    }
    assert!(HttpGrantConsumer::new("https://app/", "node".into(), "boot".into(), "token").is_ok());
}
