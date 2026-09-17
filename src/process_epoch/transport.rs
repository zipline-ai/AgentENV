//! Exact, dormant channel primitive. Certificates and endpoint must come from
//! authenticated host enrollment; constructing a channel does not establish it.
//! A response, including an authenticated guest response, never proves cessation.
use anyhow::{ensure, Context};
use std::time::Duration;

pub struct ExactChannel {
    client: reqwest::Client,
    endpoint: reqwest::Url,
}
impl ExactChannel {
    pub fn new(
        endpoint: &str,
        enrolled_peer_certificate_pem: &[u8],
        host_identity_pem: &[u8],
        budget: Duration,
    ) -> anyhow::Result<Self> {
        let endpoint: reqwest::Url = endpoint.parse()?;
        ensure!(
            endpoint.scheme() == "https"
                && endpoint.host_str().is_some()
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && endpoint.path() == "/",
            "invalid enrolled process endpoint"
        );
        ensure!(
            !budget.is_zero() && budget <= Duration::from_secs(30),
            "invalid channel budget"
        );
        let client = reqwest::Client::builder()
            .tls_backend_rustls()
            // The saved dispatch permits one network attempt, including on a
            // reused connection. Redirects must never select another runtime.
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .tls_certs_only([reqwest::Certificate::from_pem(
                enrolled_peer_certificate_pem,
            )?])
            .identity(reqwest::Identity::from_pem(host_identity_pem)?)
            .https_only(true)
            .http1_only()
            .no_proxy()
            .timeout(budget)
            .build()?;
        Ok(Self { client, endpoint })
    }
    /// The caller must durably consume its dispatch permit BEFORE calling this.
    /// Any error is an unknown result; this method has no application retry loop.
    pub async fn seal(&self, original: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        ensure!(original.len() <= 262144, "process request too large");
        self.collect(
            self.client
                .post(self.endpoint.join("process-epochs/seal")?)
                .header("content-type", "application/json")
                .body(original),
        )
        .await
    }
    pub async fn lookup(&self, operation: uuid::Uuid) -> anyhow::Result<Vec<u8>> {
        ensure!(!operation.is_nil(), "operation required");
        self.collect(
            self.client.get(
                self.endpoint
                    .join(&format!("process-epoch-operations/{operation}"))?,
            ),
        )
        .await
    }
    pub(super) async fn lookup_signed(
        &self,
        operation: uuid::Uuid,
        authority: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        ensure!(
            !operation.is_nil() && authority.len() <= 262144,
            "invalid captured lookup"
        );
        self.collect(
            self.client
                .get(
                    self.endpoint
                        .join(&format!("process-epoch-operations/{operation}"))?,
                )
                .header("content-type", "application/json")
                .body(authority),
        )
        .await
    }
    async fn collect(&self, request: reqwest::RequestBuilder) -> anyhow::Result<Vec<u8>> {
        let mut response = request
            .send()
            .await
            .context("exact process channel outcome unknown")?;
        ensure!(
            response.status().is_success(),
            "exact process channel refused"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 65536,
                "process response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}
#[cfg(test)]
pub(crate) mod tests;
