use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::config::ClientRegistrationOptions;
use crate::error::RegistrationError;
use crate::provider::OAuthAuthorizationServerProvider;
use crate::types::{OAuthClientInformationFull, OAuthClientMetadata};

pub struct RegisterState {
    pub provider: Arc<dyn OAuthAuthorizationServerProvider>,
    pub options: ClientRegistrationOptions,
}

/// POST /register
pub async fn register_handler(
    State(state): State<Arc<RegisterState>>,
    Json(metadata): Json<OAuthClientMetadata>,
) -> Response {
    tracing::info!(
        client_name = ?metadata.client_name,
        redirect_uri_count = metadata.redirect_uris.len(),
        "client registration request received"
    );
    match do_register(&state, metadata).await {
        Ok(client) => {
            tracing::info!(client_id = %client.client_id, "client registered successfully");
            let mut resp = (StatusCode::CREATED, Json(client)).into_response();
            resp.headers_mut()
                .insert("cache-control", HeaderValue::from_static("no-store"));
            resp.headers_mut()
                .insert("pragma", HeaderValue::from_static("no-cache"));
            resp
        }
        Err(e) => {
            tracing::warn!(error = %e, "client registration failed");
            e.into_response()
        }
    }
}

async fn do_register(
    state: &RegisterState,
    mut metadata: OAuthClientMetadata,
) -> Result<OAuthClientInformationFull, RegistrationError> {
    // Validate redirect_uris
    if metadata.redirect_uris.is_empty() {
        return Err(RegistrationError::InvalidRedirectUri(
            "redirect_uris must not be empty".into(),
        ));
    }

    // Enforce grant_types
    let grant_types = metadata
        .grant_types
        .get_or_insert_with(|| vec!["authorization_code".into()]);
    if !grant_types.contains(&"authorization_code".into()) {
        return Err(RegistrationError::InvalidClientMetadata(
            "grant_types must include 'authorization_code'".into(),
        ));
    }

    // Enforce response_types
    let response_types = metadata
        .response_types
        .get_or_insert_with(|| vec!["code".into()]);
    if !response_types.contains(&"code".into()) {
        return Err(RegistrationError::InvalidClientMetadata(
            "response_types must include 'code'".into(),
        ));
    }

    // Validate scopes against valid_scopes
    if let Some(ref valid_scopes) = state.options.valid_scopes {
        if let Some(ref scope_str) = metadata.scope {
            for scope in scope_str.split_whitespace() {
                if !valid_scopes.contains(&scope.to_string()) {
                    return Err(RegistrationError::InvalidClientMetadata(format!(
                        "scope '{scope}' is not allowed"
                    )));
                }
            }
        } else if let Some(ref defaults) = state.options.default_scopes {
            metadata.scope = Some(defaults.join(" "));
        }
    }

    // Generate credentials
    let client_id = uuid::Uuid::new_v4().to_string();
    let auth_method = metadata
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("client_secret_post");

    let (client_secret, client_secret_expires_at) = if auth_method != "none" {
        let secret = generate_secret();
        let expires_at = state
            .options
            .client_secret_expiry_seconds
            .map(|secs| chrono::Utc::now().timestamp() + secs);
        (Some(secret), expires_at)
    } else {
        (None, None)
    };

    tracing::debug!(client_id = %client_id, auth_method = %auth_method, "generated client credentials");

    let now = chrono::Utc::now().timestamp();

    let client_info = OAuthClientInformationFull {
        client_id,
        client_secret,
        client_id_issued_at: Some(now),
        client_secret_expires_at,
        metadata,
    };

    state.provider.register_client(client_info).await
}

fn generate_secret() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    hex::encode(bytes)
}
