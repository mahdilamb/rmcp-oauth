mod helpers;

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

use helpers::{InMemoryProvider, test_settings};
use rmcp_oauth::build_oauth_router;
use rmcp_oauth::types::{OAuthAuthorizationServerMetadata, ProtectedResourceMetadata};

fn build_app() -> axum::Router {
    let provider = Arc::new(InMemoryProvider::default());
    let settings = test_settings();
    build_oauth_router(provider, settings)
}

#[tokio::test]
async fn metadata_endpoint_returns_valid_json() {
    let app = build_app();
    let req = Request::get("/.well-known/oauth-authorization-server")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let meta: OAuthAuthorizationServerMetadata = serde_json::from_slice(&body).unwrap();

    assert_eq!(meta.issuer, "https://auth.example.com");
    assert_eq!(
        meta.authorization_endpoint,
        "https://auth.example.com/authorize"
    );
    assert_eq!(meta.token_endpoint, "https://auth.example.com/token");
    assert_eq!(meta.code_challenge_methods_supported, vec!["S256"]);
    assert_eq!(meta.response_types_supported, vec!["code"]);
}

#[tokio::test]
async fn metadata_includes_registration_when_enabled() {
    let app = build_app();
    let req = Request::get("/.well-known/oauth-authorization-server")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let meta: OAuthAuthorizationServerMetadata = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        meta.registration_endpoint.as_deref(),
        Some("https://auth.example.com/register")
    );
}

#[tokio::test]
async fn metadata_excludes_registration_when_disabled() {
    let provider = Arc::new(InMemoryProvider::default());
    let mut settings = test_settings();
    settings.client_registration_options.enabled = false;
    let app = build_oauth_router(provider, settings);

    let req = Request::get("/.well-known/oauth-authorization-server")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let meta: OAuthAuthorizationServerMetadata = serde_json::from_slice(&body).unwrap();

    assert!(meta.registration_endpoint.is_none());
}

#[tokio::test]
async fn metadata_has_cache_control_header() {
    let app = build_app();
    let req = Request::get("/.well-known/oauth-authorization-server")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "public, max-age=3600"
    );
}

#[tokio::test]
async fn protected_resource_metadata_returns_valid_json() {
    let app = build_app();
    let req = Request::get("/.well-known/oauth-protected-resource")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let meta: ProtectedResourceMetadata = serde_json::from_slice(&body).unwrap();

    assert_eq!(meta.resource, "https://mcp.example.com");
    assert_eq!(meta.authorization_servers, vec!["https://auth.example.com"]);
}

#[tokio::test]
async fn protected_resource_has_cache_control() {
    let app = build_app();
    let req = Request::get("/.well-known/oauth-protected-resource")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "public, max-age=3600"
    );
}
