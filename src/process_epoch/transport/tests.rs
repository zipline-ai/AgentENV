use super::*;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{rustls, TlsAcceptor};

type CapturedRequest = (usize, String, Vec<u8>);

struct Peer {
    endpoint: String,
    cert: String,
    identity: String,
    observed: Arc<Mutex<Vec<CapturedRequest>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn peer(redirect: bool) -> Peer {
    let server = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let client = rcgen::generate_simple_self_signed(vec!["host.fixture".into()]).unwrap();
    let cert = server.cert.pem();
    let identity = client.cert.pem() + &client.signing_key.serialize_pem();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(client.cert.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_client_cert_verifier(verifier)
    .with_single_cert(
        vec![server.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(server.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let records = observed.clone();
    let task = tokio::spawn(async move {
        let mut connection = 0;
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            connection += 1;
            let Ok(mut stream) = acceptor.accept(socket).await else {
                continue;
            };
            loop {
                let mut header = Vec::new();
                while let Ok(byte) = stream.read_u8().await {
                    header.push(byte);
                    assert!(header.len() < 16384);
                    if header.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                if !header.ends_with(b"\r\n\r\n") {
                    break;
                }
                let header = String::from_utf8(header).unwrap();
                let first = header.lines().next().unwrap().to_owned();
                let size: usize = header
                    .lines()
                    .find_map(|s| {
                        s.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|s| s.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                assert!(size <= 262144);
                let mut body = vec![0; size];
                stream.read_exact(&mut body).await.unwrap();
                records
                    .lock()
                    .unwrap()
                    .push((connection, first.clone(), body));
                if first.starts_with("POST /process-epochs/seal ") {
                    if !redirect {
                        break;
                    } // Entire POST received; lose the response.
                    stream.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /other-runtime\r\nContent-Length: 0\r\n\r\n").await.unwrap();
                } else {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                        .await
                        .unwrap();
                }
            }
        }
    });
    Peer {
        endpoint,
        cert,
        identity,
        observed,
        task,
    }
}
fn channel(p: &Peer) -> ExactChannel {
    ExactChannel::new(
        &p.endpoint,
        p.cert.as_bytes(),
        p.identity.as_bytes(),
        Duration::from_secs(2),
    )
    .unwrap()
}
#[tokio::test]
async fn enrolled_channel_refuses_redirect_before_a_second_runtime_receives_bytes() {
    let p = peer(true).await;
    let c = channel(&p);
    assert!(c.seal(b"captured-original".to_vec()).await.is_err());
    let rows = p.observed.lock().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "POST /process-epochs/seal HTTP/1.1");
    assert_eq!(rows[0].2, b"captured-original");
}
#[tokio::test]
async fn full_post_lost_response_on_reused_tls_connection_never_replays() {
    let p = peer(false).await;
    let c = channel(&p);
    let operation = uuid::Uuid::new_v4();
    assert_eq!(c.lookup(operation).await.unwrap(), b"{}");
    assert!(c.seal(b"captured-original".to_vec()).await.is_err());
    assert_eq!(c.lookup(operation).await.unwrap(), b"{}");
    let rows = p.observed.lock().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].0, rows[1].0, "must reuse the warmed connection");
    assert_ne!(rows[1].0, rows[2].0);
    assert_eq!(rows[1].1, "POST /process-epochs/seal HTTP/1.1");
    assert_eq!(rows[1].2, b"captured-original");
    assert_eq!(
        rows[0].1, rows[2].1,
        "recovery reads only the exact operation"
    );
}
#[tokio::test]
async fn wrong_peer_certificate_makes_zero_requests() {
    let p = peer(false).await;
    let unrelated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let c = ExactChannel::new(
        &p.endpoint,
        unrelated.cert.pem().as_bytes(),
        p.identity.as_bytes(),
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(c.seal(b"captured-original".to_vec()).await.is_err());
    assert!(p.observed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unenrolled_host_certificate_makes_zero_requests() {
    let p = peer(false).await;
    let other = rcgen::generate_simple_self_signed(vec!["other-host.fixture".into()]).unwrap();
    let identity = other.cert.pem() + &other.signing_key.serialize_pem();
    let c = ExactChannel::new(
        &p.endpoint,
        p.cert.as_bytes(),
        identity.as_bytes(),
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(c.seal(b"captured-original".to_vec()).await.is_err());
    assert!(p.observed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unsafe_endpoint_and_budget_are_rejected_before_connecting() {
    let p = peer(false).await;
    for endpoint in [
        "http://127.0.0.1",
        "https://user:password@127.0.0.1",
        "https://127.0.0.1/other-runtime",
        "https://127.0.0.1?route=other",
        "https://127.0.0.1#other",
    ] {
        assert!(ExactChannel::new(
            endpoint,
            p.cert.as_bytes(),
            p.identity.as_bytes(),
            Duration::from_secs(2)
        )
        .is_err());
    }
    for budget in [Duration::ZERO, Duration::from_secs(31)] {
        assert!(ExactChannel::new(
            &p.endpoint,
            p.cert.as_bytes(),
            p.identity.as_bytes(),
            budget
        )
        .is_err());
    }
    assert!(p.observed.lock().unwrap().is_empty());
}
