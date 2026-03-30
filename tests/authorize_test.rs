mod helpers;

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

use helpers::{InMemoryProvider, test_client, test_settings};
use rmcp_oauth::build_oauth_router;

async fn build_app() -> axum::Router {
    let provider = Arc::new(
        InMemoryProvider::default()
            .with_client(test_client())
            .await,
    );
    build_oauth_router(provider, test_settings())
}

fn authorize_url(params: &str) -> String {
    format!("/authorize?{params}")
}

#[tokio::test]
async fn missing_response_type_returns_400() {
    let app = build_app().await;
    let req = Request::get(authorize_url("client_id=test-client"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"], "invalid_request");
}

#[tokio::test]
async fn unsupported_response_type_returns_400() {
    let app = build_app().await;
    let req = Request::get(authorize_url(
        "client_id=test-client&response_type=token",
    ))
    .body(Body::empty())
    .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn missing_client_id_returns_400() {
    let app = build_app().await;
    let req = Request::get(authorize_url("response_type=code"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn unknown_client_returns_400_not_redirect() {
    let app = build_app().await;
    let req = Request::get(authorize_url(
        "response_type=code&client_id=unknown&redirect_uri=http://evil.com/cb&code_challenge=abc&code_challenge_method=S256",
    ))
    .body(Body::empty())
    .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Must be 400 JSON, not a redirect (we don't trust the redirect_uri)
    assert_eq!(resp.status(), 400);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"], "invalid_request");
}

#[tokio::test]
async fn invalid_redirect_uri_returns_400() {
    let app = build_app().await;
    let req = Request::get(authorize_url(
        "response_type=code&client_id=test-client&redirect_uri=http://evil.com/callback&code_challenge=abc&code_challenge_method=S256",
    ))
    .body(Body::empty())
    .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn missing_code_challenge_returns_redirect_error() {
    let app = build_app().await;
    let req = Request::get(authorize_url(
        "response_type=code&client_id=test-client&redirect_uri=http://localhost:3000/callback",
    ))
    .body(Body::empty())
    .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Should redirect with error
    assert_eq!(resp.status(), 302);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("error=invalid_request"));
}

#[tokio::test]
async fn unsupported_code_challenge_method_returns_redirect_error() {
    let app = build_app().await;
    let req = Request::get(authorize_url(
        "response_type=code&client_id=test-client&redirect_uri=http://localhost:3000/callback&code_challenge=abc&code_challenge_method=plain",
    ))
    .body(Body::empty())
    .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 302);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("error=invalid_request"));
    assert!(location.contains("S256"));
}

#[tokio::test]
async fn valid_request_returns_302_redirect() {
    let app = build_app().await;
    let req = Request::get(authorize_url(
        "response_type=code&client_id=test-client&redirect_uri=http://localhost:3000/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=xyz",
    ))
    .body(Body::empty())
    .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 302);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("http://localhost/consent"));
    assert!(location.contains("state=xyz"));
}

#[tokio::test]
async fn valid_request_has_cache_control() {
    let app = build_app().await;
    let req = Request::get(authorize_url(
        "response_type=code&client_id=test-client&code_challenge=abc&code_challenge_method=S256",
    ))
    .body(Body::empty())
    .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 302);
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "no-store"
    );
}
