use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::config::AuthSettings;
use crate::types::OAuthAuthorizationServerMetadata;

/// Shared state for the metadata handler.
pub type MetadataState = Arc<OAuthAuthorizationServerMetadata>;

/// Build the metadata object from settings.
pub fn build_metadata(settings: &AuthSettings) -> OAuthAuthorizationServerMetadata {
    let registration_endpoint = if settings.client_registration_options.enabled {
        Some(settings.endpoint_url("/register"))
    } else {
        None
    };
    let revocation_endpoint = if settings.revocation_options.enabled {
        Some(settings.endpoint_url("/revoke"))
    } else {
        None
    };
    OAuthAuthorizationServerMetadata {
        issuer: settings.issuer_url.clone(),
        authorization_endpoint: settings.endpoint_url("/authorize"),
        token_endpoint: settings.endpoint_url("/token"),
        registration_endpoint,
        revocation_endpoint,
        jwks_uri: None,
        scopes_supported: settings
            .client_registration_options
            .valid_scopes
            .clone(),
        response_types_supported: vec!["code".into()],
        grant_types_supported: vec!["authorization_code".into(), "refresh_token".into()],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_post".into(),
            "client_secret_basic".into(),
            "none".into(),
        ],
        code_challenge_methods_supported: vec!["S256".into()],
        service_documentation: settings.service_documentation_url.clone(),
        client_id_metadata_document_supported: None,
        extra: Default::default(),
    }
}

/// GET /.well-known/oauth-authorization-server
pub async fn metadata_handler(State(meta): State<MetadataState>) -> Response {
    let mut resp = Json(&*meta).into_response();
    resp.headers_mut().insert(
        "cache-control",
        HeaderValue::from_static("public, max-age=3600"),
    );
    resp
}
