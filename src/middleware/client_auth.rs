use std::collections::HashMap;
use std::sync::Arc;

use axum::http::HeaderMap;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use subtle::ConstantTimeEq;

use crate::error::TokenError;
use crate::provider::OAuthAuthorizationServerProvider;
use crate::types::OAuthClientInformationFull;

/// Authenticates clients for the token and revocation endpoints.
pub struct ClientAuthenticator {
    pub provider: Arc<dyn OAuthAuthorizationServerProvider>,
}

impl ClientAuthenticator {
    /// Authenticate a client from request headers and form body.
    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
        form: &HashMap<String, String>,
    ) -> Result<OAuthClientInformationFull, TokenError> {
        // Try to extract client credentials from Basic auth header first
        if let Some(auth) = headers.get("authorization") {
            if let Ok(auth_str) = auth.to_str() {
                if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                    tracing::debug!("using HTTP Basic authentication");
                    return self.authenticate_basic(encoded, form).await;
                }
            }
        }

        // Fall back to client_id from form body
        let client_id = form
            .get("client_id")
            .ok_or_else(|| TokenError::InvalidClient("missing client_id".into()))?;

        tracing::debug!(client_id = %client_id, "using form-body client authentication");

        let client = match self
            .provider
            .get_client(client_id)
            .await
            .map_err(|e| TokenError::ServerError(e.0))?
        {
            Some(c) => c,
            None => {
                tracing::warn!(client_id = %client_id, "client not found");
                return Err(TokenError::InvalidClient("unknown client".into()));
            }
        };

        let auth_method = client
            .metadata
            .token_endpoint_auth_method
            .as_deref()
            .unwrap_or("none");

        match auth_method {
            "none" => {
                tracing::debug!(client_id = %client.client_id, auth_method = "none", "client authenticated");
                Ok(client)
            }
            "client_secret_post" => {
                let provided_secret = form
                    .get("client_secret")
                    .ok_or_else(|| TokenError::InvalidClient("missing client_secret".into()))?;
                self.verify_secret(&client, provided_secret)?;
                tracing::debug!(client_id = %client.client_id, auth_method = "client_secret_post", "client authenticated");
                Ok(client)
            }
            _ => {
                tracing::warn!(client_id = %client.client_id, auth_method = %auth_method, "unsupported auth method");
                Err(TokenError::InvalidClient(format!(
                    "unsupported auth method: {auth_method}"
                )))
            }
        }
    }

    async fn authenticate_basic(
        &self,
        encoded: &str,
        _form: &HashMap<String, String>,
    ) -> Result<OAuthClientInformationFull, TokenError> {
        let decoded = STANDARD.decode(encoded.trim()).map_err(|_| {
            tracing::warn!("invalid Basic auth encoding");
            TokenError::InvalidClient("invalid Basic encoding".into())
        })?;
        let decoded_str = String::from_utf8(decoded).map_err(|_| {
            tracing::warn!("invalid Basic auth encoding");
            TokenError::InvalidClient("invalid Basic encoding".into())
        })?;

        let (client_id_encoded, secret_encoded) = decoded_str
            .split_once(':')
            .ok_or_else(|| TokenError::InvalidClient("invalid Basic format".into()))?;

        // URL-decode per RFC 6749
        let client_id = urlencoding::decode(client_id_encoded)
            .map_err(|_| TokenError::InvalidClient("invalid client_id encoding".into()))?;
        let provided_secret = urlencoding::decode(secret_encoded)
            .map_err(|_| TokenError::InvalidClient("invalid secret encoding".into()))?;

        let client = self
            .provider
            .get_client(&client_id)
            .await
            .map_err(|e| TokenError::ServerError(e.0))?
            .ok_or_else(|| TokenError::InvalidClient("unknown client".into()))?;

        tracing::debug!(client_id = %client_id, "Basic auth client found, verifying secret");
        self.verify_secret(&client, &provided_secret)?;
        Ok(client)
    }

    fn verify_secret(
        &self,
        client: &OAuthClientInformationFull,
        provided: &str,
    ) -> Result<(), TokenError> {
        let stored = client
            .client_secret
            .as_deref()
            .ok_or_else(|| TokenError::InvalidClient("client has no secret".into()))?;

        // Check expiry
        if let Some(expires_at) = client.client_secret_expires_at {
            if expires_at > 0 {
                let now = chrono::Utc::now().timestamp();
                if now >= expires_at {
                    tracing::warn!(client_id = %client.client_id, "client_secret expired");
                    return Err(TokenError::InvalidClient("client_secret expired".into()));
                }
            }
        }

        // Constant-time comparison
        if !bool::from(
            provided
                .as_bytes()
                .ct_eq(stored.as_bytes()),
        ) {
            tracing::warn!(client_id = %client.client_id, "client_secret mismatch");
            return Err(TokenError::InvalidClient("invalid client_secret".into()));
        }

        Ok(())
    }
}
