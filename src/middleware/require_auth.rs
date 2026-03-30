use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::types::AccessToken;

/// Middleware that requires an `AccessToken` in request extensions.
///
/// This is a secondary layer applied after `bearer_auth_middleware`. It simply
/// verifies the token is present (it should always be if bearer_auth ran first).
pub async fn require_auth_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    if request.extensions().get::<AccessToken>().is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}
