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
    async fn consume(&self, _request: ConsumeRequest) -> Result<ConsumeReply, GrantDenied> {
        Err(GrantDenied)
    }
}
#[cfg(test)]
mod tests;
