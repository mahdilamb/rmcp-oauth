mod helpers;

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use axum::routing::get;
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

use helpers::InMemoryProvider;
use rmcp_oauth::config::{AuthSettings, ClientRegistrationOptions, RevocationOptions};
use rmcp_oauth::middleware::bearer_auth::{AuthState, bearer_auth_middleware};
use rmcp_oauth::provider::TokenVerifier;
use rmcp_oauth::types::AccessToken;

fn test_auth_settings() -> AuthSettings {
    AuthSettings {
        issuer_url: "https://auth.example.com".into(),
        resource_server_url: "https://mcp.example.com".into(),
        route_prefix: "".into(),
        required_scopes: Some(vec!["read".into()]),
        client_registration_options: ClientRegistrationOptions::default(),
        revocation_options: RevocationOptions::default(),
        service_documentation_url: None,
    }
}

async fn protected_handler() -> &'static str {
    "ok"
}

async fn build_protected_app(provider: Arc<InMemoryProvider>) -> Router {
    let auth_state = Arc::new(AuthState {
        verifier: provider as Arc<dyn TokenVerifier>,
        resource_metadata_url: "https://mcp.example.com/.well-known/oauth-protected-resource"
            .into(),
        required_scopes: Some(vec!["read".into()]),
    });
    Router::new()
        .route("/protected", get(protected_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth_state,
            bearer_auth_middleware,
        ))
}

#[tokio::test]
async fn no_auth_header_returns_401() {
    let provider = Arc::new(InMemoryProvider::default());
    let app = build_protected_app(provider).await;
    let req = Request::get("/protected").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);

    let www_auth = resp.headers().get("www-authenticate").unwrap().to_str().unwrap();
    assert!(www_auth.contains("Bearer"));
    assert!(www_auth.contains("resource_metadata="));
}

#[tokio::test]
async fn invalid_token_returns_401() {
    let provider = Arc::new(InMemoryProvider::default());
    let app = build_protected_app(provider).await;
    let req = Request::get("/protected")
        .header("authorization", "Bearer invalid_token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);

    let www_auth = resp.headers().get("www-authenticate").unwrap().to_str().unwrap();
    assert!(www_auth.contains("invalid_token"));
}

#[tokio::test]
async fn expired_token_returns_401() {
    let provider = Arc::new(
        InMemoryProvider::default()
            .with_access_token(AccessToken {
                token: "expired_tok".into(),
                client_id: "client1".into(),
                scopes: vec!["read".into()],
                expires_at: Some(1000), // long past
                resource: None,
            })
            .await,
    );
    let app = build_protected_app(provider).await;
    let req = Request::get("/protected")
        .header("authorization", "Bearer expired_tok")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);

    let www_auth = resp.headers().get("www-authenticate").unwrap().to_str().unwrap();
    assert!(www_auth.contains("token expired"));
}

#[tokio::test]
async fn valid_token_passes_through() {
    let provider = Arc::new(
        InMemoryProvider::default()
            .with_access_token(AccessToken {
                token: "good_tok".into(),
                client_id: "client1".into(),
                scopes: vec!["read".into(), "write".into()],
                expires_at: Some(chrono::Utc::now().timestamp() + 3600),
                resource: None,
            })
            .await,
    );
    let app = build_protected_app(provider).await;
    let req = Request::get("/protected")
        .header("authorization", "Bearer good_tok")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
async fn insufficient_scope_returns_403() {
    let provider = Arc::new(
        InMemoryProvider::default()
            .with_access_token(AccessToken {
                token: "limited_tok".into(),
                client_id: "client1".into(),
                scopes: vec!["write".into()], // missing "read"
                expires_at: Some(chrono::Utc::now().timestamp() + 3600),
                resource: None,
            })
            .await,
    );
    let app = build_protected_app(provider).await;
    let req = Request::get("/protected")
        .header("authorization", "Bearer limited_tok")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403);

    let www_auth = resp.headers().get("www-authenticate").unwrap().to_str().unwrap();
    assert!(www_auth.contains("insufficient_scope"));
    assert!(www_auth.contains("read"));
}

#[tokio::test]
async fn no_required_scopes_any_token_works() {
    let provider = Arc::new(
        InMemoryProvider::default()
            .with_access_token(AccessToken {
                token: "any_tok".into(),
                client_id: "client1".into(),
                scopes: vec![],
                expires_at: None,
                resource: None,
            })
            .await,
    );
    let auth_state = Arc::new(AuthState {
        verifier: provider as Arc<dyn TokenVerifier>,
        resource_metadata_url: "https://mcp.example.com/.well-known/oauth-protected-resource"
            .into(),
        required_scopes: None, // no scopes required
    });
    let app = Router::new()
        .route("/protected", get(protected_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth_state,
            bearer_auth_middleware,
        ));

    let req = Request::get("/protected")
        .header("authorization", "Bearer any_tok")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}
