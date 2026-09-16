//! Bounded, one-attempt adapter for the existing authenticated app consume CAS.
//! No startup wiring; the authenticated launch-binding producer is still absent.
use super::grant::{ConsumeReply, ConsumeRequest, GrantConsumer, GrantDenied};
use async_trait::async_trait;

pub struct HttpGrantConsumer {
    node_id: String,
    incarnation: String,
    token: reqwest::header::HeaderValue,
    endpoint: reqwest::Url,
    client: reqwest::Client,
}
impl HttpGrantConsumer {
    pub fn new(
        base: &str,
        node_id: String,
        incarnation: String,
        token: &str,
    ) -> Result<Self, GrantDenied> {
        let url = reqwest::Url::parse(base).map_err(|_| GrantDenied)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(GrantDenied);
        }
        Self::build(url, node_id, incarnation, token)
    }
    fn build(
        base: reqwest::Url,
        node_id: String,
        incarnation: String,
        token: &str,
    ) -> Result<Self, GrantDenied> {
        if node_id.trim().is_empty() || incarnation.trim().is_empty() || token.is_empty() {
            return Err(GrantDenied);
        }
        let mut token = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| GrantDenied)?;
        token.set_sensitive(true);
        let endpoint = base
            .join("/api/internal/launch-grants/consume")
            .map_err(|_| GrantDenied)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|_| GrantDenied)?;
        Ok(Self {
            node_id,
            incarnation,
            token,
            endpoint,
            client,
        })
    }
}
#[async_trait]
impl GrantConsumer for HttpGrantConsumer {
    async fn consume(&self, request: ConsumeRequest) -> Result<ConsumeReply, GrantDenied> {
        if request.node_id != self.node_id
            || request.incarnation != self.incarnation
            || request.grant_id.trim().is_empty()
            || request.payload_sha256.len() != 64
            || !request
                .payload_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(GrantDenied);
        }
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .header(reqwest::header::AUTHORIZATION, self.token.clone())
            .json(&request)
            .send()
            .await
            .map_err(|_| GrantDenied)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(GrantDenied);
        }
        if response.content_length().is_some_and(|size| size > 8192) {
            return Err(GrantDenied);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| GrantDenied)? {
            if bytes.len() + chunk.len() > 8192 {
                return Err(GrantDenied);
            }
            bytes.extend_from_slice(&chunk);
        }
        super::wire::validate_unique_json(&bytes).map_err(|_| GrantDenied)?;
        serde_json::from_slice(&bytes).map_err(|_| GrantDenied)
    }
}
#[cfg(test)]
mod tests;
