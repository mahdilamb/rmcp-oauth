use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::types::ProtectedResourceMetadata;

/// Shared state for the protected resource metadata handler.
pub type ProtectedResourceState = Arc<ProtectedResourceMetadata>;

/// GET /.well-known/oauth-protected-resource
pub async fn protected_resource_handler(
    State(meta): State<ProtectedResourceState>,
) -> Response {
    let mut resp = Json(&*meta).into_response();
    resp.headers_mut().insert(
        "cache-control",
        HeaderValue::from_static("public, max-age=3600"),
    );
    resp
}
