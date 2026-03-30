use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use crate::config::AuthSettings;
use crate::cors::oauth_cors_layer;
use crate::handlers::authorize::{AuthorizeState, authorize_handler, authorize_post_handler};
use crate::handlers::callback::{CallbackState, callback_handler};
use crate::handlers::metadata::{MetadataState, build_metadata, metadata_handler};
use crate::handlers::protected_resource::{
    ProtectedResourceState, protected_resource_handler,
};
use crate::handlers::register::{RegisterState, register_handler};
use crate::handlers::revoke::{RevokeState, revoke_handler};
use crate::handlers::token::{TokenState, token_handler};
use crate::middleware::bearer_auth::AuthState;
use crate::provider::{OAuthAuthorizationServerProvider, TokenVerifier};
use crate::types::ProtectedResourceMetadata;

/// Build the complete OAuth router with all endpoints.
///
/// The returned `Router` can be merged with your MCP application's router:
///
/// ```ignore
/// let app = Router::new()
///     .merge(oauth_router)
///     .merge(protected_mcp_router);
/// ```
pub fn build_oauth_router(
    provider: Arc<dyn OAuthAuthorizationServerProvider>,
    settings: AuthSettings,
) -> Router {
    let cors = oauth_cors_layer();
    tracing::info!(route_prefix = %settings.route_prefix, "building OAuth router");

    // Build metadata objects
    let as_metadata: MetadataState = Arc::new(build_metadata(&settings));
    let pr_metadata: ProtectedResourceState = Arc::new(ProtectedResourceMetadata {
        resource: settings.resource_server_url.clone(),
        authorization_servers: vec![settings.issuer_url.clone()],
        scopes_supported: settings
            .client_registration_options
            .valid_scopes
            .clone(),
        bearer_methods_supported: Some(vec!["header".into()]),
        extra: Default::default(),
    });

    // Well-known endpoints (always at root, with CORS)
    let well_known = Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata_handler).with_state(as_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_handler).with_state(pr_metadata),
        )
        .layer(cors.clone());

    // Authorization and callback endpoints (no CORS — browser redirect only)
    let prefix = &settings.route_prefix;
    let authorize_state = Arc::new(AuthorizeState {
        provider: provider.clone(),
        client_registration_options: settings.client_registration_options.clone(),
    });
    let authorize = Router::new().route(
        &format!("{prefix}/authorize"),
        get(authorize_handler)
            .post(authorize_post_handler)
            .with_state(authorize_state),
    );
    let callback_state = Arc::new(CallbackState {
        provider: provider.clone(),
    });
    let callback = Router::new().route(
        &format!("{prefix}/auth/callback"),
        get(callback_handler).with_state(callback_state),
    );

    // Token endpoint (with CORS)
    let token_state = Arc::new(TokenState {
        provider: provider.clone(),
    });
    let token = Router::new()
        .route(
            &format!("{prefix}/token"),
            post(token_handler).with_state(token_state),
        )
        .layer(cors.clone());

    let mut router = Router::new()
        .merge(well_known)
        .merge(authorize)
        .merge(callback)
        .merge(token);

    // Conditionally add registration endpoint
    if settings.client_registration_options.enabled {
        let register_state = Arc::new(RegisterState {
            provider: provider.clone(),
            options: settings.client_registration_options.clone(),
        });
        let register = Router::new()
            .route(
                &format!("{prefix}/register"),
                post(register_handler).with_state(register_state),
            )
            .layer(cors.clone());
        router = router.merge(register);
        tracing::info!("dynamic client registration endpoint enabled");
    }

    // Conditionally add revocation endpoint
    if settings.revocation_options.enabled {
        let revoke_state = Arc::new(RevokeState {
            provider: provider.clone(),
        });
        let revoke = Router::new()
            .route(
                &format!("{prefix}/revoke"),
                post(revoke_handler).with_state(revoke_state),
            )
            .layer(cors);
        router = router.merge(revoke);
        tracing::info!("token revocation endpoint enabled");
    }

    tracing::debug!(
        issuer = %settings.issuer_url,
        resource = %settings.resource_server_url,
        "OAuth router ready"
    );
    router
}

/// Build the `AuthState` for use with the bearer auth middleware.
///
/// ```ignore
/// let auth_state = build_auth_state(provider, &settings);
/// let protected = Router::new()
///     .nest_service("/mcp", mcp_service)
///     .layer(axum::middleware::from_fn_with_state(
///         auth_state,
///         rmcp_oauth::middleware::bearer_auth::bearer_auth_middleware,
///     ));
/// ```
pub fn build_auth_state<T: TokenVerifier>(
    verifier: Arc<T>,
    settings: &AuthSettings,
) -> Arc<AuthState> {
    let resource_metadata_url = format!(
        "{}/.well-known/oauth-protected-resource",
        settings.resource_server_url
    );
    Arc::new(AuthState {
        verifier,
        resource_metadata_url,
        required_scopes: settings.required_scopes.clone(),
    })
}
