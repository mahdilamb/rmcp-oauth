use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::config::ClientRegistrationOptions;
use crate::error::AuthorizeError;
use crate::provider::OAuthAuthorizationServerProvider;
use crate::types::{AuthorizationParams, OAuthClientInformationFull, OAuthClientMetadata};

#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub resource: Option<String>,
}

pub struct AuthorizeState {
    pub provider: Arc<dyn OAuthAuthorizationServerProvider>,
    pub client_registration_options: ClientRegistrationOptions,
}

/// GET /authorize
pub async fn authorize_handler(
    State(state): State<Arc<AuthorizeState>>,
    Query(params): Query<AuthorizeRequest>,
) -> Response {
    handle_authorize(state, params).await
}

/// POST /authorize — accepts parameters in the form body.
pub async fn authorize_post_handler(
    State(state): State<Arc<AuthorizeState>>,
    axum::Form(params): axum::Form<AuthorizeRequest>,
) -> Response {
    handle_authorize(state, params).await
}

async fn handle_authorize(
    state: Arc<AuthorizeState>,
    params: AuthorizeRequest,
) -> Response {
    tracing::info!(
        client_id = ?params.client_id,
        response_type = ?params.response_type,
        redirect_uri = ?params.redirect_uri,
        scope = ?params.scope,
        "authorize request received"
    );

    // Validate response_type
    let response_type = match &params.response_type {
        Some(rt) if rt == "code" => rt.clone(),
        Some(rt) => {
            tracing::warn!(response_type = %rt, "unsupported response_type");
            return AuthorizeError::InvalidRequest(format!(
                "unsupported response_type: {rt}"
            ))
            .into_json_response();
        }
        None => {
            tracing::warn!("missing response_type");
            return AuthorizeError::InvalidRequest("missing response_type".into())
                .into_json_response();
        }
    };
    let _ = response_type;

    // Validate client_id
    let client_id = match &params.client_id {
        Some(id) => id.clone(),
        None => {
            return AuthorizeError::InvalidRequest("missing client_id".into())
                .into_json_response();
        }
    };

    // Look up client, auto-registering if dynamic registration is enabled
    let client = match state.provider.get_client(&client_id).await {
        Ok(Some(c)) => c,
        Ok(None) if state.client_registration_options.enabled => {
            // Auto-register the unknown client with the provided redirect_uri
            let redirect_uri = match &params.redirect_uri {
                Some(uri) => uri.clone(),
                None => {
                    return AuthorizeError::InvalidRequest(
                        "unknown client_id and no redirect_uri provided for auto-registration"
                            .into(),
                    )
                    .into_json_response();
                }
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let client_info = OAuthClientInformationFull {
                client_id: client_id.clone(),
                client_secret: None,
                client_id_issued_at: Some(now),
                client_secret_expires_at: None,
                metadata: OAuthClientMetadata {
                    redirect_uris: vec![redirect_uri],
                    client_name: None,
                    client_uri: None,
                    logo_uri: None,
                    scope: params.scope.clone(),
                    grant_types: Some(vec!["authorization_code".into()]),
                    response_types: Some(vec!["code".into()]),
                    token_endpoint_auth_method: Some("none".into()),
                    application_type: None,
                    contacts: None,
                    tos_uri: None,
                    policy_uri: None,
                },
            };
            match state.provider.register_client(client_info).await {
                Ok(c) => {
                    tracing::info!(client_id = %client_id, "auto-registered unknown client");
                    c
                }
                Err(e) => {
                    tracing::error!(client_id = %client_id, error = %e, "auto-registration failed");
                    return AuthorizeError::ServerError(e.to_string()).into_json_response();
                }
            }
        }
        Ok(None) => {
            tracing::warn!(client_id = %client_id, "unknown client_id");
            return AuthorizeError::InvalidRequest(format!(
                "unknown client_id: {client_id}"
            ))
            .into_json_response();
        }
        Err(e) => {
            tracing::error!(client_id = %client_id, error = %e.0, "provider error during client lookup");
            return AuthorizeError::ServerError(e.0).into_json_response();
        }
    };
    tracing::debug!(client_id = %client_id, "client found");

    // Validate redirect_uri
    let redirect_uri_provided_explicitly = params.redirect_uri.is_some();
    let redirect_uri = if let Some(ref uri) = params.redirect_uri {
        if !client.metadata.redirect_uris.contains(uri) {
            tracing::warn!(client_id = %client_id, redirect_uri = %uri, "redirect_uri not registered");
            return AuthorizeError::InvalidRequest(format!(
                "redirect_uri not registered: {uri}"
            ))
            .into_json_response();
        }
        uri.clone()
    } else if client.metadata.redirect_uris.len() == 1 {
        client.metadata.redirect_uris[0].clone()
    } else {
        return AuthorizeError::InvalidRequest(
            "redirect_uri required when multiple URIs registered".into(),
        )
        .into_json_response();
    };

    // From here, errors redirect to the validated redirect_uri
    let state_param = params.state.clone();

    // Validate code_challenge (strip padding for clients that include it)
    let code_challenge = match &params.code_challenge {
        Some(cc) => cc.trim_end_matches('=').to_string(),
        None => {
            tracing::warn!(client_id = %client_id, "missing code_challenge");
            return AuthorizeError::InvalidRequest("missing code_challenge (PKCE required)".into())
                .into_redirect_response(&redirect_uri, state_param.as_deref());
        }
    };

    // Validate code_challenge_method
    match &params.code_challenge_method {
        Some(m) if m == "S256" => {}
        Some(m) => {
            tracing::warn!(client_id = %client_id, method = %m, "unsupported code_challenge_method");
            return AuthorizeError::InvalidRequest(format!(
                "unsupported code_challenge_method: {m}, only S256 is supported"
            ))
            .into_redirect_response(&redirect_uri, state_param.as_deref());
        }
        None => {
            return AuthorizeError::InvalidRequest(
                "missing code_challenge_method".into(),
            )
            .into_redirect_response(&redirect_uri, state_param.as_deref());
        }
    }

    // Parse scopes
    let scopes = params
        .scope
        .as_ref()
        .map(|s| s.split_whitespace().map(String::from).collect());

    // Call the provider
    let auth_params = AuthorizationParams {
        state: params.state.clone(),
        scopes,
        code_challenge,
        redirect_uri: redirect_uri.clone(),
        redirect_uri_provided_explicitly,
        resource: params.resource.clone(),
    };

    match state.provider.authorize(&client, auth_params).await {
        Ok(redirect_url) => {
            tracing::info!(client_id = %client_id, "authorize succeeded, redirecting");
            let mut resp = StatusCode::FOUND.into_response();
            resp.headers_mut().insert(
                "location",
                HeaderValue::from_str(&redirect_url).unwrap_or_else(|_| {
                    HeaderValue::from_static("/")
                }),
            );
            resp.headers_mut()
                .insert("cache-control", HeaderValue::from_static("no-store"));
            resp.headers_mut()
                .insert("pragma", HeaderValue::from_static("no-cache"));
            resp
        }
        Err(e) => {
            tracing::warn!(client_id = %client_id, "authorize provider returned error");
            e.into_redirect_response(&redirect_uri, state_param.as_deref())
        }
    }
}
