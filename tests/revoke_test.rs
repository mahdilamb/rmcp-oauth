mod helpers;

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

use helpers::{InMemoryProvider, test_client, test_settings};
use rmcp_oauth::build_oauth_router;
use rmcp_oauth::types::AccessToken;

fn revoke_request(body: &str) -> Request<Body> {
    Request::post("/revoke")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn revoke_valid_token_returns_200() {
    let provider = Arc::new(
        InMemoryProvider::default()
            .with_client(test_client())
            .await
            .with_access_token(AccessToken {
                token: "tok123".into(),
                client_id: "test-client".into(),
                scopes: vec!["read".into()],
                expires_at: None,
                resource: None,
            })
            .await,
    );
    let app = build_oauth_router(provider, test_settings());
    let resp = app
        .oneshot(revoke_request("token=tok123&client_id=test-client"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn revoke_unknown_token_returns_200() {
    let provider = Arc::new(
        InMemoryProvider::default()
            .with_client(test_client())
            .await,
    );
    let app = build_oauth_router(provider, test_settings());
    let resp = app
        .oneshot(revoke_request("token=nonexistent&client_id=test-client"))
        .await
        .unwrap();
    // Per RFC 7009: always 200
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn revoke_missing_token_returns_400() {
    let provider = Arc::new(
        InMemoryProvider::default()
            .with_client(test_client())
            .await,
    );
    let app = build_oauth_router(provider, test_settings());
    let resp = app
        .oneshot(revoke_request("client_id=test-client"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn revoke_disabled_returns_404() {
    let provider = Arc::new(InMemoryProvider::default());
    let mut settings = test_settings();
    settings.revocation_options.enabled = false;
    let app = build_oauth_router(provider, settings);

    let resp = app
        .oneshot(revoke_request("token=tok&client_id=test-client"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
