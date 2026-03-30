use async_trait::async_trait;

use crate::error::{AuthorizeError, ProviderError, RegistrationError, TokenError};
use crate::types::{
    AccessToken, AuthorizationCode, AuthorizationParams, OAuthClientInformationFull, OAuthToken,
    RefreshToken,
};

/// Trait that custom OAuth providers must implement.
///
/// This is the server-side equivalent of FastMCP's `OAuthAuthorizationServerProvider`.
/// Implement this trait to plug in your own authorization logic (e.g. backed by a
/// database, or delegating to Google/GitHub OAuth).
#[async_trait]
pub trait OAuthAuthorizationServerProvider: Send + Sync + 'static {
    /// Look up a registered client by its client_id.
    async fn get_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthClientInformationFull>, ProviderError>;

    /// Register a new client (RFC 7591 dynamic client registration).
    async fn register_client(
        &self,
        client_info: OAuthClientInformationFull,
    ) -> Result<OAuthClientInformationFull, RegistrationError>;

    /// Handle an authorization request. Returns a redirect URL (e.g. consent page).
    async fn authorize(
        &self,
        client: &OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> Result<String, AuthorizeError>;

    /// Load a previously issued authorization code.
    async fn load_authorization_code(
        &self,
        client: &OAuthClientInformationFull,
        authorization_code: &str,
    ) -> Result<Option<AuthorizationCode>, ProviderError>;

    /// Exchange an authorization code for tokens. The provider should invalidate the code.
    async fn exchange_authorization_code(
        &self,
        client: &OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> Result<OAuthToken, TokenError>;

    /// Load a previously issued refresh token.
    async fn load_refresh_token(
        &self,
        client: &OAuthClientInformationFull,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, ProviderError>;

    /// Exchange a refresh token for new tokens.
    async fn exchange_refresh_token(
        &self,
        client: &OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: Option<Vec<String>>,
    ) -> Result<OAuthToken, TokenError>;

    /// Load an access token by its string value.
    async fn load_access_token(
        &self,
        token: &str,
    ) -> Result<Option<AccessToken>, ProviderError>;

    /// Revoke a token (access or refresh).
    async fn revoke_token(
        &self,
        token: &str,
        token_type_hint: Option<&str>,
    ) -> Result<(), ProviderError>;

    /// Handle the redirect from an upstream identity provider.
    ///
    /// `params` contains the raw query parameters forwarded from the upstream redirect
    /// (typically `code`, `state`, and possibly `error`/`error_description`).
    ///
    /// Returns a redirect URL — usually the MCP client's `redirect_uri` with an MCP
    /// authorization code appended, e.g. `https://client.example.com/cb?code=XYZ&state=ABC`.
    ///
    /// The default implementation returns an error indicating the callback is not supported.
    async fn handle_callback(
        &self,
        params: std::collections::HashMap<String, String>,
    ) -> Result<String, AuthorizeError> {
        let _ = params;
        Err(AuthorizeError::InvalidRequest(
            "callback endpoint not supported by this provider".into(),
        ))
    }
}

/// Simplified trait for token verification only (used by middleware).
#[async_trait]
pub trait TokenVerifier: Send + Sync + 'static {
    async fn verify_access_token(
        &self,
        token: &str,
    ) -> Result<Option<AccessToken>, ProviderError>;
}

/// Blanket implementation: any full provider can be used as a token verifier.
#[async_trait]
impl<T: OAuthAuthorizationServerProvider> TokenVerifier for T {
    async fn verify_access_token(
        &self,
        token: &str,
    ) -> Result<Option<AccessToken>, ProviderError> {
        self.load_access_token(token).await
    }
}
