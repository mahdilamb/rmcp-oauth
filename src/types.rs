use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── OAuth 2.0 Token Response (RFC 6749 §5.1) ──

/// Access token response returned by the token endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    pub access_token: String,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

// ── Client Metadata (RFC 7591) ──

/// Metadata about an OAuth client, provided during registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClientMetadata {
    pub redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
}

/// Full client information including server-assigned fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClientInformationFull {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    #[serde(flatten)]
    pub metadata: OAuthClientMetadata,
}

// ── Authorization Server Metadata (RFC 8414) ──

/// OAuth 2.0 Authorization Server Metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_metadata_document_supported: Option<bool>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

// ── Protected Resource Metadata (RFC 9728) ──

/// Metadata about a protected resource (the MCP server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_methods_supported: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

// ── Provider-side domain types ──

/// Parameters passed to the provider's authorize method.
#[derive(Debug, Clone)]
pub struct AuthorizationParams {
    pub state: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub code_challenge: String,
    pub redirect_uri: String,
    pub redirect_uri_provided_explicitly: bool,
    pub resource: Option<String>,
}

/// An authorization code stored by the provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub scopes: Vec<String>,
    /// Unix timestamp (seconds) when the code expires.
    pub expires_at: i64,
    pub client_id: String,
    pub code_challenge: String,
    pub redirect_uri: String,
    pub redirect_uri_provided_explicitly: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// An access token stored by the provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub token: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// A refresh token stored by the provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub token: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}
