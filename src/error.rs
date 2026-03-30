use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Standard OAuth 2.0 error response body.
#[derive(Debug, Serialize)]
pub struct OAuthErrorBody {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

fn json_error_response(status: StatusCode, body: &OAuthErrorBody) -> Response {
    let json = serde_json::to_string(body).unwrap_or_default();
    let mut resp = (status, json).into_response();
    let headers = resp.headers_mut();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("pragma", HeaderValue::from_static("no-cache"));
    resp
}

// ── Provider errors ──

/// A catch-all error from the provider implementation.
#[derive(Debug, thiserror::Error)]
#[error("internal provider error: {0}")]
pub struct ProviderError(pub String);

impl IntoResponse for ProviderError {
    fn into_response(self) -> Response {
        json_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &OAuthErrorBody {
                error: "server_error".into(),
                error_description: Some(self.0),
            },
        )
    }
}

// ── Registration errors ──

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("invalid client metadata: {0}")]
    InvalidClientMetadata(String),
    #[error("invalid redirect URI: {0}")]
    InvalidRedirectUri(String),
    #[error("server error: {0}")]
    ServerError(String),
}

impl IntoResponse for RegistrationError {
    fn into_response(self) -> Response {
        let (code, body) = match &self {
            RegistrationError::InvalidClientMetadata(desc) => (
                "invalid_client_metadata",
                desc.clone(),
            ),
            RegistrationError::InvalidRedirectUri(desc) => (
                "invalid_redirect_uri",
                desc.clone(),
            ),
            RegistrationError::ServerError(desc) => ("server_error", desc.clone()),
        };
        json_error_response(
            StatusCode::BAD_REQUEST,
            &OAuthErrorBody {
                error: code.into(),
                error_description: Some(body),
            },
        )
    }
}

// ── Authorization errors ──

#[derive(Debug, thiserror::Error)]
pub enum AuthorizeError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("access denied: {0}")]
    AccessDenied(String),
    #[error("server error: {0}")]
    ServerError(String),
}

impl AuthorizeError {
    /// Produce a JSON error response (for pre-redirect errors).
    pub fn into_json_response(self) -> Response {
        let (code, desc) = match &self {
            AuthorizeError::InvalidRequest(d) => ("invalid_request", d.clone()),
            AuthorizeError::AccessDenied(d) => ("access_denied", d.clone()),
            AuthorizeError::ServerError(d) => ("server_error", d.clone()),
        };
        json_error_response(
            StatusCode::BAD_REQUEST,
            &OAuthErrorBody {
                error: code.into(),
                error_description: Some(desc),
            },
        )
    }

    /// Produce a redirect response with error params (for post-redirect errors).
    pub fn into_redirect_response(self, redirect_uri: &str, state: Option<&str>) -> Response {
        let (code, desc) = match &self {
            AuthorizeError::InvalidRequest(d) => ("invalid_request", d.clone()),
            AuthorizeError::AccessDenied(d) => ("access_denied", d.clone()),
            AuthorizeError::ServerError(d) => ("server_error", d.clone()),
        };
        let mut url = redirect_uri.to_string();
        let sep = if url.contains('?') { '&' } else { '?' };
        url.push(sep);
        url.push_str(&format!(
            "error={}&error_description={}",
            code,
            urlencoding::encode(&desc)
        ));
        if let Some(s) = state {
            url.push_str(&format!("&state={}", urlencoding::encode(s)));
        }
        Response::builder()
            .status(StatusCode::FOUND)
            .header("location", &url)
            .header("cache-control", "no-store")
            .header("pragma", "no-cache")
            .body(axum::body::Body::empty())
            .unwrap()
    }
}

impl IntoResponse for AuthorizeError {
    fn into_response(self) -> Response {
        self.into_json_response()
    }
}

// ── Token errors ──

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("invalid grant: {0}")]
    InvalidGrant(String),
    #[error("invalid client: {0}")]
    InvalidClient(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("unsupported grant type: {0}")]
    UnsupportedGrantType(String),
    #[error("invalid scope: {0}")]
    InvalidScope(String),
    #[error("server error: {0}")]
    ServerError(String),
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        let (status, code, desc) = match &self {
            TokenError::InvalidGrant(d) => {
                (StatusCode::BAD_REQUEST, "invalid_grant", d.clone())
            }
            TokenError::InvalidClient(d) => {
                (StatusCode::UNAUTHORIZED, "invalid_client", d.clone())
            }
            TokenError::InvalidRequest(d) => {
                (StatusCode::BAD_REQUEST, "invalid_request", d.clone())
            }
            TokenError::UnsupportedGrantType(d) => {
                (StatusCode::BAD_REQUEST, "unsupported_grant_type", d.clone())
            }
            TokenError::InvalidScope(d) => {
                (StatusCode::BAD_REQUEST, "invalid_scope", d.clone())
            }
            TokenError::ServerError(d) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "server_error", d.clone())
            }
        };
        json_error_response(
            status,
            &OAuthErrorBody {
                error: code.into(),
                error_description: Some(desc),
            },
        )
    }
}
