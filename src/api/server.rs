use axum::{middleware, routing::get, Router};

use super::{impls::auth, proxy, ApiImpl};
use crate::observability::prometheus;
use agentenv_http_server::apis;
use agentenv_observability::metrics_handler;

pub fn new<I, A, E, C>(api_impl: I) -> Router
where
    I: AsRef<A> + AsRef<ApiImpl> + Clone + Send + Sync + 'static,
    A: apis::admin::Admin<E, Claims = C>
        + apis::default::Default<E>
        + apis::sandboxes::Sandboxes<E, Claims = C>
        + apis::snapshots::Snapshots<E, Claims = C>
        + apis::templates::Templates<E, Claims = C>
        + apis::ApiKeyAuthHeader<Claims = C>
        + apis::ApiAuthBasic<Claims = C>
        + Send
        + Sync
        + 'static,
    E: std::fmt::Debug + Send + Sync + 'static,
    C: Send + Sync + 'static,
{
    // Keep the generated control-plane API as the primary router, then merge in
    // the hand-written `/proxy/*` entrypoints needed for the temporary reverse
    // proxy contract.
    agentenv_http_server::server::new::<I, A, E, C>(api_impl.clone())
        .merge(proxy::router(api_impl.clone()))
        .route("/metrics", get(metrics_handler))
        .route("/launch-observations/{attempt_id}", get(launch_status))
        .layer(middleware::from_fn(observe_launch))
        .layer(middleware::from_fn_with_state(
            api_impl.clone(),
            proxy::sandbox_proxy_classifier::<I>,
        ))
        .layer(middleware::from_fn_with_state(
            api_impl,
            auth::require_auth::<I>,
        ))
        .layer(middleware::from_fn(prometheus::http_metrics_middleware))
}

// Auth wraps this route and middleware, exactly like the generated node API.
async fn launch_status(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Ok(id) = uuid::Uuid::parse_str(&id) else {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    };
    match crate::observability::launch::read(id) {
        Some(status) => axum::Json(status).into_response(),
        None => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}
async fn observe_launch(
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let path = request.uri().path();
    let eligible = request.method() == axum::http::Method::POST
        && (path == "/sandboxes"
            || path == "/sandboxes-cold"
            || (path.starts_with("/sandboxes/")
                && (path.ends_with("/connect") || path.ends_with("/resume"))));
    if !eligible {
        return next.run(request).await;
    }
    let mut headers = request
        .headers()
        .get_all("x-agentenv-launch-attempt")
        .iter();
    let Some(value) = headers.next() else {
        return next.run(request).await;
    };
    let id = value.to_str().ok().and_then(|v| {
        uuid::Uuid::parse_str(v)
            .ok()
            .filter(|id| id.to_string() == v)
    });
    if headers.next().is_some() || id.is_none() {
        return next.run(request).await;
    }
    let Some(observation) = crate::observability::launch::begin(id.unwrap()) else {
        return next.run(request).await;
    };
    crate::observability::launch::scope(Some(observation), next.run(request)).await
}

#[cfg(test)]
mod launch_tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::post,
    };
    use tower::ServiceExt;
    #[tokio::test]
    async fn launch_observer_never_rejects_duplicate_or_malformed_lifecycle_requests() {
        let app = Router::new()
            .route(
                "/sandboxes",
                post(|| async {
                    crate::observability::launch::phase(
                        crate::observability::launch::Phase::FetchingSnapshot,
                    );
                    StatusCode::CREATED
                }),
            )
            .layer(middleware::from_fn(observe_launch));
        let id = uuid::Uuid::new_v4().to_string();
        for value in [&id, &id, "malformed"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/sandboxes")
                        .header("x-agentenv-launch-attempt", value)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
        }
        assert!(crate::observability::launch::read(uuid::Uuid::parse_str(&id).unwrap()).is_none());
    }
}
