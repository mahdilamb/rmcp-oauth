mod helpers;

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

use helpers::{InMemoryProvider, test_settings};
use rmcp_oauth::build_oauth_router;
use rmcp_oauth::types::OAuthClientInformationFull;

fn build_app() -> axum::Router {
    let provider = Arc::new(InMemoryProvider::default());
    build_oauth_router(provider, test_settings())
}

fn register_request(body: &str) -> Request<Body> {
    Request::post("/register")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn valid_registration_returns_201() {
    let app = build_app();
    let body = r#"{
        "redirect_uris": ["http://localhost:3000/callback"],
        "client_name": "Test App",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post"
    }"#;
    let resp = app.oneshot(register_request(body)).await.unwrap();
    assert_eq!(resp.status(), 201);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let client: OAuthClientInformationFull = serde_json::from_slice(&body).unwrap();

    assert!(!client.client_id.is_empty());
    assert!(client.client_secret.is_some());
    assert_eq!(client.client_secret.as_ref().unwrap().len(), 64); // 32 bytes hex
    assert!(client.client_id_issued_at.is_some());
}

#[tokio::test]
async fn registration_with_none_auth_has_no_secret() {
    let app = build_app();
    let body = r#"{
        "redirect_uris": ["http://localhost:3000/callback"],
        "token_endpoint_auth_method": "none"
    }"#;
    let resp = app.oneshot(register_request(body)).await.unwrap();
    assert_eq!(resp.status(), 201);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let client: OAuthClientInformationFull = serde_json::from_slice(&body).unwrap();
    assert!(client.client_secret.is_none());
}

#[tokio::test]
async fn empty_redirect_uris_returns_400() {
    let app = build_app();
    let body = r#"{"redirect_uris": []}"#;
    let resp = app.oneshot(register_request(body)).await.unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn invalid_scope_returns_400() {
    let app = build_app();
    let body = r#"{
        "redirect_uris": ["http://localhost:3000/callback"],
        "scope": "admin"
    }"#;
    let resp = app.oneshot(register_request(body)).await.unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn registration_disabled_returns_404() {
    let provider = Arc::new(InMemoryProvider::default());
    let mut settings = test_settings();
    settings.client_registration_options.enabled = false;
    let app = build_oauth_router(provider, settings);

    let body = r#"{"redirect_uris": ["http://localhost:3000/callback"]}"#;
    let resp = app.oneshot(register_request(body)).await.unwrap();
    // 404 because route is not registered
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn default_scopes_applied_when_none_provided() {
    let app = build_app();
    let body = r#"{
        "redirect_uris": ["http://localhost:3000/callback"],
        "token_endpoint_auth_method": "none"
    }"#;
    let resp = app.oneshot(register_request(body)).await.unwrap();
    assert_eq!(resp.status(), 201);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let client: OAuthClientInformationFull = serde_json::from_slice(&body).unwrap();
    assert_eq!(client.metadata.scope.as_deref(), Some("read"));
}
