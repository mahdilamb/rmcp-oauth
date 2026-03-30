use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use rmcp_oauth::error::{AuthorizeError, ProviderError, RegistrationError, TokenError};
use rmcp_oauth::types::*;
use rmcp_oauth::OAuthAuthorizationServerProvider;
use tokio::sync::RwLock;

/// In-memory OAuth provider for tests.
#[derive(Default, Clone)]
pub struct InMemoryProvider {
    pub clients: Arc<RwLock<HashMap<String, OAuthClientInformationFull>>>,
    pub authorization_codes: Arc<RwLock<HashMap<String, AuthorizationCode>>>,
    pub access_tokens: Arc<RwLock<HashMap<String, AccessToken>>>,
    pub refresh_tokens: Arc<RwLock<HashMap<String, RefreshToken>>>,
}

impl InMemoryProvider {
    pub async fn with_client(self, client: OAuthClientInformationFull) -> Self {
        self.clients
            .write()
            .await
            .insert(client.client_id.clone(), client);
        self
    }

    pub async fn with_authorization_code(self, code: AuthorizationCode) -> Self {
        self.authorization_codes
            .write()
            .await
            .insert(code.code.clone(), code);
        self
    }

    pub async fn with_access_token(self, token: AccessToken) -> Self {
        self.access_tokens
            .write()
            .await
            .insert(token.token.clone(), token);
        self
    }

    pub async fn with_refresh_token(self, token: RefreshToken) -> Self {
        self.refresh_tokens
            .write()
            .await
            .insert(token.token.clone(), token);
        self
    }
}

#[async_trait]
impl OAuthAuthorizationServerProvider for InMemoryProvider {
    async fn get_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthClientInformationFull>, ProviderError> {
        Ok(self.clients.read().await.get(client_id).cloned())
    }

    async fn register_client(
        &self,
        client_info: OAuthClientInformationFull,
    ) -> Result<OAuthClientInformationFull, RegistrationError> {
        self.clients
            .write()
            .await
            .insert(client_info.client_id.clone(), client_info.clone());
        Ok(client_info)
    }

    async fn authorize(
        &self,
        _client: &OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> Result<String, AuthorizeError> {
        // Return a fake consent URL with the state preserved
        let mut url = "http://localhost/consent?session=test123".to_string();
        if let Some(state) = &params.state {
            url.push_str(&format!("&state={state}"));
        }
        Ok(url)
    }

    async fn load_authorization_code(
        &self,
        _client: &OAuthClientInformationFull,
        authorization_code: &str,
    ) -> Result<Option<AuthorizationCode>, ProviderError> {
        Ok(self
            .authorization_codes
            .read()
            .await
            .get(authorization_code)
            .cloned())
    }

    async fn exchange_authorization_code(
        &self,
        _client: &OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> Result<OAuthToken, TokenError> {
        // Remove the code (single-use)
        self.authorization_codes
            .write()
            .await
            .remove(&authorization_code.code);

        Ok(OAuthToken {
            access_token: "test_access_token".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some("test_refresh_token".into()),
            scope: Some(authorization_code.scopes.join(" ")),
        })
    }

    async fn load_refresh_token(
        &self,
        _client: &OAuthClientInformationFull,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, ProviderError> {
        Ok(self
            .refresh_tokens
            .read()
            .await
            .get(refresh_token)
            .cloned())
    }

    async fn exchange_refresh_token(
        &self,
        _client: &OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: Option<Vec<String>>,
    ) -> Result<OAuthToken, TokenError> {
        let scope = scopes.unwrap_or(refresh_token.scopes);
        Ok(OAuthToken {
            access_token: "new_access_token".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some("new_refresh_token".into()),
            scope: Some(scope.join(" ")),
        })
    }

    async fn load_access_token(
        &self,
        token: &str,
    ) -> Result<Option<AccessToken>, ProviderError> {
        Ok(self.access_tokens.read().await.get(token).cloned())
    }

    async fn revoke_token(
        &self,
        token: &str,
        _token_type_hint: Option<&str>,
    ) -> Result<(), ProviderError> {
        self.access_tokens.write().await.remove(token);
        self.refresh_tokens.write().await.remove(token);
        Ok(())
    }
}

// ── Test fixture helpers ──

pub fn test_client() -> OAuthClientInformationFull {
    OAuthClientInformationFull {
        client_id: "test-client".into(),
        client_secret: None,
        client_id_issued_at: Some(1000000),
        client_secret_expires_at: None,
        metadata: OAuthClientMetadata {
            redirect_uris: vec!["http://localhost:3000/callback".into()],
            client_name: Some("Test Client".into()),
            client_uri: None,
            logo_uri: None,
            scope: None,
            grant_types: Some(vec!["authorization_code".into()]),
            response_types: Some(vec!["code".into()]),
            token_endpoint_auth_method: Some("none".into()),
            application_type: Some("native".into()),
            contacts: None,
            tos_uri: None,
            policy_uri: None,
        },
    }
}

pub fn test_settings() -> rmcp_oauth::AuthSettings {
    rmcp_oauth::config::AuthSettings {
        issuer_url: "https://auth.example.com".into(),
        resource_server_url: "https://mcp.example.com".into(),
        route_prefix: "".into(),
        required_scopes: None,
        client_registration_options: rmcp_oauth::config::ClientRegistrationOptions {
            enabled: true,
            client_secret_expiry_seconds: None,
            valid_scopes: Some(vec!["read".into(), "write".into()]),
            default_scopes: Some(vec!["read".into()]),
        },
        revocation_options: rmcp_oauth::config::RevocationOptions { enabled: true },
        service_documentation_url: None,
    }
}
