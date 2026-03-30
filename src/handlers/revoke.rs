use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Form;

use crate::error::TokenError;
use crate::middleware::client_auth::ClientAuthenticator;
use crate::provider::OAuthAuthorizationServerProvider;

pub struct RevokeState {
    pub provider: Arc<dyn OAuthAuthorizationServerProvider>,
}

/// POST /revoke
pub async fn revoke_handler(
    State(state): State<Arc<RevokeState>>,
    headers: axum::http::HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let authenticator = ClientAuthenticator {
        provider: state.provider.clone(),
    };

    tracing::info!("token revocation request received");

    // Authenticate client
    if let Err(e) = authenticator.authenticate(&headers, &form).await {
        tracing::warn!("revocation request: client authentication failed");
        return e.into_response();
    }

    let token = match form.get("token") {
        Some(t) => t.clone(),
        None => {
            tracing::warn!("revocation request: missing token parameter");
            return TokenError::InvalidRequest("missing token".into()).into_response();
        }
    };

    let token_type_hint = form.get("token_type_hint").map(|s| s.as_str());

    // Per RFC 7009: always return 200, even if token doesn't exist
    let _ = state.provider.revoke_token(&token, token_type_hint).await;
    tracing::info!(token_type_hint = ?token_type_hint, "token revocation completed");

    StatusCode::OK.into_response()
}
