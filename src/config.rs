/// Options for dynamic client registration (RFC 7591).
#[derive(Debug, Clone, Default)]
pub struct ClientRegistrationOptions {
    pub enabled: bool,
    pub client_secret_expiry_seconds: Option<i64>,
    pub valid_scopes: Option<Vec<String>>,
    pub default_scopes: Option<Vec<String>>,
}

/// Options for token revocation (RFC 7009).
#[derive(Debug, Clone, Default)]
pub struct RevocationOptions {
    pub enabled: bool,
}

/// Top-level settings for the OAuth authorization layer.
#[derive(Debug, Clone)]
pub struct AuthSettings {
    /// The OAuth authorization server issuer identifier (e.g. `"https://auth.example.com"`).
    pub issuer_url: String,
    /// Canonical URI of the MCP server for RFC 8707 resource binding.
    pub resource_server_url: String,
    /// URL prefix for functional endpoints (`/authorize`, `/token`, etc.).
    /// Well-known endpoints are always served at the root.
    pub route_prefix: String,
    /// Scopes required for accessing protected MCP endpoints.
    pub required_scopes: Option<Vec<String>>,
    pub client_registration_options: ClientRegistrationOptions,
    pub revocation_options: RevocationOptions,
    /// Optional URL to service documentation (included in metadata).
    pub service_documentation_url: Option<String>,
}

impl AuthSettings {
    /// Helper: build the full URL for a functional endpoint.
    pub fn endpoint_url(&self, path: &str) -> String {
        format!("{}{}{}", self.issuer_url, self.route_prefix, path)
    }
}
