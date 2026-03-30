mod helpers;

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

use helpers::{InMemoryProvider, test_settings};
use rmcp_oauth::build_oauth_router;

#[tokio::test]
async fn all_routes_respond() {
    let provider = Arc::new(InMemoryProvider::default());
    let app = build_oauth_router(provider, test_settings());

    // GET endpoints
    for path in &[
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
    ] {
        let req = Request::get(*path).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_ne!(resp.status(), 404, "route {path} should exist");
    }

    // POST endpoints
    for path in &["/token", "/register", "/revoke"] {
        let req = Request::post(*path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_ne!(resp.status(), 404, "route {path} should exist");
    }

    // Authorize accepts GET
    let req = Request::get("/authorize").body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), 404, "GET /authorize should exist");
}

#[tokio::test]
async fn route_prefix_works() {
    let provider = Arc::new(InMemoryProvider::default());
    let mut settings = test_settings();
    settings.route_prefix = "/oauth".into();
    let app = build_oauth_router(provider, settings);

    // Prefixed token endpoint should exist
    let req = Request::post("/oauth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), 404);

    // Un-prefixed token endpoint should NOT exist
    let req = Request::post("/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 404);

    // Well-known endpoints always at root
    let req = Request::get("/.well-known/oauth-authorization-server")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn cors_on_token_endpoint() {
    let provider = Arc::new(InMemoryProvider::default());
    let app = build_oauth_router(provider, test_settings());

    let req = Request::builder()
        .method("OPTIONS")
        .uri("/token")
        .header("origin", "http://example.com")
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(resp.headers().contains_key("access-control-allow-origin"));
}

#[tokio::test]
async fn no_cors_on_authorize_endpoint() {
    let provider = Arc::new(InMemoryProvider::default());
    let app = build_oauth_router(provider, test_settings());

    let req = Request::builder()
        .method("OPTIONS")
        .uri("/authorize")
        .header("origin", "http://example.com")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Authorize does not have CORS, so no CORS headers
    assert!(!resp.headers().contains_key("access-control-allow-origin"));
}

#[tokio::test]
async fn router_can_merge_with_plain_router() {
    let provider = Arc::new(InMemoryProvider::default());
    let oauth_router = build_oauth_router(provider, test_settings());
    let other = axum::Router::new().route(
        "/health",
        axum::routing::get(|| async { "ok" }),
    );
    let app = axum::Router::new().merge(oauth_router).merge(other);

    let req = Request::get("/health").body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let req = Request::get("/.well-known/oauth-authorization-server")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}
