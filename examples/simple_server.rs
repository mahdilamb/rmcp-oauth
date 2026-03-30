//! A standalone OAuth 2.1 authorization server using an in-memory provider.
//!
//! Run with:
//!   cargo run --example simple_server
//!
//! Then explore:
//!   curl http://localhost:3000/.well-known/oauth-authorization-server | jq
//!   curl http://localhost:3000/.well-known/oauth-protected-resource | jq
//!   curl -X POST http://localhost:3000/register \
//!     -H 'Content-Type: application/json' \
//!     -d '{"redirect_uris":["http://localhost:9999/callback"],"token_endpoint_auth_method":"none"}'

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use rmcp_oauth::config::{AuthSettings, ClientRegistrationOptions, RevocationOptions};
use rmcp_oauth::error::{AuthorizeError, ProviderError, RegistrationError, TokenError};
use rmcp_oauth::provider::OAuthAuthorizationServerProvider;
use rmcp_oauth::types::*;
use tokio::sync::RwLock;

/// In-memory OAuth provider backed by HashMaps.
#[derive(Default)]
struct InMemoryProvider {
    clients: RwLock<HashMap<String, OAuthClientInformationFull>>,
    codes: RwLock<HashMap<String, AuthorizationCode>>,
    access_tokens: RwLock<HashMap<String, AccessToken>>,
    refresh_tokens: RwLock<HashMap<String, RefreshToken>>,
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
        client: &OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> Result<String, AuthorizeError> {
        // In a real implementation, this would render a consent page or redirect
        // to an external IdP. Here we auto-approve and issue a code.
        let code = uuid::Uuid::new_v4().to_string();
        let auth_code = AuthorizationCode {
            code: code.clone(),
            scopes: params.scopes.unwrap_or_default(),
            expires_at: chrono::Utc::now().timestamp() + 600,
            client_id: client.client_id.clone(),
            code_challenge: params.code_challenge,
            redirect_uri: params.redirect_uri.clone(),
            redirect_uri_provided_explicitly: params.redirect_uri_provided_explicitly,
            resource: params.resource,
        };
        self.codes.write().await.insert(code.clone(), auth_code);

        // Redirect back to the client with the code
        let mut redirect = params.redirect_uri;
        let sep = if redirect.contains('?') { '&' } else { '?' };
        redirect.push(sep);
        redirect.push_str(&format!("code={code}"));
        if let Some(state) = params.state {
            redirect.push_str(&format!("&state={state}"));
        }
        Ok(redirect)
    }

    async fn load_authorization_code(
        &self,
        _client: &OAuthClientInformationFull,
        authorization_code: &str,
    ) -> Result<Option<AuthorizationCode>, ProviderError> {
        Ok(self.codes.read().await.get(authorization_code).cloned())
    }

    async fn exchange_authorization_code(
        &self,
        _client: &OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> Result<OAuthToken, TokenError> {
        self.codes.write().await.remove(&authorization_code.code);

        let access_token = uuid::Uuid::new_v4().to_string();
        let refresh_token = uuid::Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now().timestamp() + 3600;

        self.access_tokens.write().await.insert(
            access_token.clone(),
            AccessToken {
                token: access_token.clone(),
                client_id: authorization_code.client_id.clone(),
                scopes: authorization_code.scopes.clone(),
                expires_at: Some(expires_at),
                resource: authorization_code.resource,
            },
        );

        self.refresh_tokens.write().await.insert(
            refresh_token.clone(),
            RefreshToken {
                token: refresh_token.clone(),
                client_id: authorization_code.client_id,
                scopes: authorization_code.scopes.clone(),
                expires_at: None,
            },
        );

        Ok(OAuthToken {
            access_token,
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some(refresh_token),
            scope: Some(authorization_code.scopes.join(" ")),
        })
    }

    async fn load_refresh_token(
        &self,
        _client: &OAuthClientInformationFull,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, ProviderError> {
        Ok(self.refresh_tokens.read().await.get(refresh_token).cloned())
    }

    async fn exchange_refresh_token(
        &self,
        _client: &OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: Option<Vec<String>>,
    ) -> Result<OAuthToken, TokenError> {
        let scopes = scopes.unwrap_or(refresh_token.scopes);
        let new_access = uuid::Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now().timestamp() + 3600;

        self.access_tokens.write().await.insert(
            new_access.clone(),
            AccessToken {
                token: new_access.clone(),
                client_id: refresh_token.client_id,
                scopes: scopes.clone(),
                expires_at: Some(expires_at),
                resource: None,
            },
        );

        Ok(OAuthToken {
            access_token: new_access,
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: Some(scopes.join(" ")),
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

#[tokio::main]
async fn main() {
    let settings = AuthSettings {
        issuer_url: "http://localhost:3000".into(),
        resource_server_url: "http://localhost:3000".into(),
        route_prefix: "".into(),
        required_scopes: None,
        client_registration_options: ClientRegistrationOptions {
            enabled: true,
            valid_scopes: Some(vec!["read".into(), "write".into()]),
            default_scopes: Some(vec!["read".into()]),
            ..Default::default()
        },
        revocation_options: RevocationOptions { enabled: true },
        service_documentation_url: None,
    };

    let provider = Arc::new(InMemoryProvider::default());
    let app = rmcp_oauth::build_oauth_router(provider, settings);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("failed to bind");
    println!("OAuth server listening on http://127.0.0.1:3000");
    println!("  GET  /.well-known/oauth-authorization-server");
    println!("  GET  /.well-known/oauth-protected-resource");
    println!("  POST /register");
    println!("  GET  /authorize");
    println!("  POST /token");
    println!("  POST /revoke");
    axum::serve(listener, app).await.unwrap();
}
