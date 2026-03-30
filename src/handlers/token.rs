use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::Form;

use crate::error::TokenError;
use crate::middleware::client_auth::ClientAuthenticator;
use crate::pkce::verify_pkce_s256;
use crate::provider::OAuthAuthorizationServerProvider;

pub struct TokenState {
    pub provider: Arc<dyn OAuthAuthorizationServerProvider>,
}

/// POST /token
pub async fn token_handler(
    State(state): State<Arc<TokenState>>,
    headers: axum::http::HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let authenticator = ClientAuthenticator {
        provider: state.provider.clone(),
    };

    let grant_type = match form.get("grant_type") {
        Some(gt) => gt.clone(),
        None => {
            tracing::warn!("token request missing grant_type");
            return TokenError::InvalidRequest("missing grant_type".into()).into_response();
        }
    };
    tracing::info!(grant_type = %grant_type, "token request received");

    let result = match grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code(&state.provider, &authenticator, &headers, &form).await
        }
        "refresh_token" => {
            handle_refresh_token(&state.provider, &authenticator, &headers, &form).await
        }
        _ => {
            tracing::warn!(grant_type = %grant_type, "unsupported grant_type");
            Err(TokenError::UnsupportedGrantType(format!(
                "unsupported grant_type: {grant_type}"
            )))
        }
    };

    match result {
        Ok(token) => {
            tracing::info!(grant_type = %grant_type, "token issued successfully");
            let mut resp = axum::Json(&token).into_response();
            resp.headers_mut()
                .insert("cache-control", HeaderValue::from_static("no-store"));
            resp.headers_mut()
                .insert("pragma", HeaderValue::from_static("no-cache"));
            resp
        }
        Err(e) => {
            tracing::warn!(grant_type = %grant_type, error = %e, "token request failed");
            e.into_response()
        }
    }
}

async fn handle_authorization_code(
    provider: &Arc<dyn OAuthAuthorizationServerProvider>,
    authenticator: &ClientAuthenticator,
    headers: &axum::http::HeaderMap,
    form: &HashMap<String, String>,
) -> Result<crate::types::OAuthToken, TokenError> {
    let client = authenticator.authenticate(headers, form).await?;
    tracing::debug!(client_id = %client.client_id, "client authenticated for auth code exchange");

    let code_str = form
        .get("code")
        .ok_or_else(|| TokenError::InvalidRequest("missing code".into()))?;

    let code_verifier = form
        .get("code_verifier")
        .ok_or_else(|| TokenError::InvalidRequest("missing code_verifier".into()))?;

    let auth_code = provider
        .load_authorization_code(&client, code_str)
        .await
        .map_err(|e| TokenError::ServerError(e.0))?
        .ok_or_else(|| TokenError::InvalidGrant("authorization code not found".into()))?;

    // Check expiration
    let now = chrono::Utc::now().timestamp();
    if now >= auth_code.expires_at {
        tracing::warn!(client_id = %client.client_id, "authorization code expired");
        return Err(TokenError::InvalidGrant("authorization code expired".into()));
    }

    // Verify redirect_uri matches
    if let Some(redirect_uri) = form.get("redirect_uri") {
        if *redirect_uri != auth_code.redirect_uri {
            tracing::warn!(client_id = %client.client_id, "redirect_uri mismatch in token exchange");
            return Err(TokenError::InvalidGrant("redirect_uri mismatch".into()));
        }
    } else if auth_code.redirect_uri_provided_explicitly {
        return Err(TokenError::InvalidRequest(
            "redirect_uri required (was provided in authorization request)".into(),
        ));
    }

    // PKCE verification
    if !verify_pkce_s256(code_verifier, &auth_code.code_challenge) {
        tracing::warn!(
            client_id = %client.client_id,
            code_challenge = %auth_code.code_challenge,
            code_verifier = %code_verifier,
            code_challenge_len = auth_code.code_challenge.len(),
            code_verifier_len = code_verifier.len(),
            "PKCE verification failed"
        );
        return Err(TokenError::InvalidGrant("PKCE verification failed".into()));
    }

    // Verify resource if provided
    if let Some(resource) = form.get("resource") {
        if auth_code.resource.as_deref() != Some(resource.as_str()) {
            return Err(TokenError::InvalidGrant("resource mismatch".into()));
        }
    }

    provider
        .exchange_authorization_code(&client, auth_code)
        .await
}

async fn handle_refresh_token(
    provider: &Arc<dyn OAuthAuthorizationServerProvider>,
    authenticator: &ClientAuthenticator,
    headers: &axum::http::HeaderMap,
    form: &HashMap<String, String>,
) -> Result<crate::types::OAuthToken, TokenError> {
    let client = authenticator.authenticate(headers, form).await?;
    tracing::debug!(client_id = %client.client_id, "client authenticated for refresh token exchange");

    let refresh_token_str = form
        .get("refresh_token")
        .ok_or_else(|| TokenError::InvalidRequest("missing refresh_token".into()))?;

    let refresh_token = provider
        .load_refresh_token(&client, refresh_token_str)
        .await
        .map_err(|e| TokenError::ServerError(e.0))?
        .ok_or_else(|| TokenError::InvalidGrant("refresh token not found".into()))?;

    // Check expiration
    if let Some(expires_at) = refresh_token.expires_at {
        let now = chrono::Utc::now().timestamp();
        if now >= expires_at {
            tracing::warn!(client_id = %client.client_id, "refresh token expired");
            return Err(TokenError::InvalidGrant("refresh token expired".into()));
        }
    }

    // Validate requested scopes are a subset of the original grant
    let requested_scopes = form
        .get("scope")
        .map(|s| s.split_whitespace().map(String::from).collect::<Vec<_>>());

    if let Some(ref scopes) = requested_scopes {
        for scope in scopes {
            if !refresh_token.scopes.contains(scope) {
                tracing::warn!(client_id = %client.client_id, scope = %scope, "requested scope not in original grant");
                return Err(TokenError::InvalidScope(format!(
                    "scope '{scope}' not in original grant"
                )));
            }
        }
    }

    provider
        .exchange_refresh_token(&client, refresh_token, requested_scopes)
        .await
}
