use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::provider::TokenVerifier;

/// State for the bearer auth middleware.
#[derive(Clone)]
pub struct AuthState {
    pub verifier: Arc<dyn TokenVerifier>,
    pub resource_metadata_url: String,
    pub required_scopes: Option<Vec<String>>,
}

fn www_authenticate_challenge(resource_metadata_url: &str) -> HeaderValue {
    let val = format!("Bearer resource_metadata=\"{resource_metadata_url}\"");
    HeaderValue::from_str(&val).unwrap_or_else(|_| HeaderValue::from_static("Bearer"))
}

fn www_authenticate_error(
    resource_metadata_url: &str,
    error: &str,
    description: &str,
) -> HeaderValue {
    let val = format!(
        "Bearer resource_metadata=\"{resource_metadata_url}\", error=\"{error}\", error_description=\"{description}\""
    );
    HeaderValue::from_str(&val).unwrap_or_else(|_| HeaderValue::from_static("Bearer"))
}

fn www_authenticate_insufficient_scope(
    resource_metadata_url: &str,
    missing_scopes: &str,
) -> HeaderValue {
    let val = format!(
        "Bearer resource_metadata=\"{resource_metadata_url}\", error=\"insufficient_scope\", scope=\"{missing_scopes}\", error_description=\"Insufficient scope\""
    );
    HeaderValue::from_str(&val).unwrap_or_else(|_| HeaderValue::from_static("Bearer"))
}

/// Axum middleware that extracts and verifies Bearer tokens.
///
/// On success, inserts `AccessToken` into request extensions.
/// On failure, returns 401 with proper `WWW-Authenticate` header.
pub async fn bearer_auth_middleware(
    State(state): State<Arc<AuthState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let token_str = match extract_bearer_token(&request) {
        Some(t) => t,
        None => {
            tracing::debug!("no bearer token in request");
            let mut resp = StatusCode::UNAUTHORIZED.into_response();
            resp.headers_mut().insert(
                "www-authenticate",
                www_authenticate_challenge(&state.resource_metadata_url),
            );
            return resp;
        }
    };

    let access_token = match state.verifier.verify_access_token(&token_str).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            tracing::warn!("bearer token not found");
            let mut resp = StatusCode::UNAUTHORIZED.into_response();
            resp.headers_mut().insert(
                "www-authenticate",
                www_authenticate_error(
                    &state.resource_metadata_url,
                    "invalid_token",
                    "token not found",
                ),
            );
            return resp;
        }
        Err(_) => {
            tracing::error!("bearer token verification error");
            let mut resp = StatusCode::INTERNAL_SERVER_ERROR.into_response();
            resp.headers_mut().insert(
                "www-authenticate",
                www_authenticate_error(
                    &state.resource_metadata_url,
                    "invalid_token",
                    "token verification failed",
                ),
            );
            return resp;
        }
    };

    // Check token expiration
    if let Some(expires_at) = access_token.expires_at {
        let now = chrono::Utc::now().timestamp();
        if now >= expires_at {
            tracing::warn!(client_id = %access_token.client_id, "bearer token expired");
            let mut resp = StatusCode::UNAUTHORIZED.into_response();
            resp.headers_mut().insert(
                "www-authenticate",
                www_authenticate_error(
                    &state.resource_metadata_url,
                    "invalid_token",
                    "token expired",
                ),
            );
            return resp;
        }
    }

    // Check required scopes
    if let Some(ref required) = state.required_scopes {
        let missing: Vec<&str> = required
            .iter()
            .filter(|s| !access_token.scopes.contains(s))
            .map(|s| s.as_str())
            .collect();

        if !missing.is_empty() {
            tracing::warn!(
                client_id = %access_token.client_id,
                missing_scopes = %missing.join(" "),
                "insufficient scopes"
            );
            let mut resp = StatusCode::FORBIDDEN.into_response();
            resp.headers_mut().insert(
                "www-authenticate",
                www_authenticate_insufficient_scope(
                    &state.resource_metadata_url,
                    &missing.join(" "),
                ),
            );
            return resp;
        }
    }

    // Store token in extensions for downstream handlers
    tracing::debug!(client_id = %access_token.client_id, "bearer auth succeeded");
    request.extensions_mut().insert(access_token);
    next.run(request).await
}

fn extract_bearer_token(request: &Request<Body>) -> Option<String> {
    let header = request.headers().get("authorization")?;
    let value = header.to_str().ok()?;
    let token = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))?;
    Some(token.trim().to_string())
}
