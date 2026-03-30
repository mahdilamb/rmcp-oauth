mod helpers;

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

use helpers::{InMemoryProvider, test_client, test_settings};
use rmcp_oauth::build_oauth_router;
use rmcp_oauth::types::{AuthorizationCode, OAuthToken, RefreshToken};

// PKCE test values (RFC 7636 Appendix B)
const CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CODE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn test_auth_code() -> AuthorizationCode {
    AuthorizationCode {
        code: "test-code".into(),
        scopes: vec!["read".into(), "write".into()],
        expires_at: chrono::Utc::now().timestamp() + 600,
        client_id: "test-client".into(),
        code_challenge: CODE_CHALLENGE.into(),
        redirect_uri: "http://localhost:3000/callback".into(),
        redirect_uri_provided_explicitly: true,
        resource: None,
    }
}

fn test_refresh_token() -> RefreshToken {
    RefreshToken {
        token: "test-refresh".into(),
        client_id: "test-client".into(),
        scopes: vec!["read".into(), "write".into()],
        expires_at: None,
    }
}

async fn build_app() -> axum::Router {
    let provider = Arc::new(
        InMemoryProvider::default()
            .with_client(test_client())
            .await
            .with_authorization_code(test_auth_code())
            .await
            .with_refresh_token(test_refresh_token())
            .await,
    );
    build_oauth_router(provider, test_settings())
}

fn token_request(body: &str) -> Request<Body> {
    Request::post("/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn missing_grant_type_returns_400() {
    let app = build_app().await;
    let resp = app.oneshot(token_request("code=test-code")).await.unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"], "invalid_request");
}

#[tokio::test]
async fn unsupported_grant_type_returns_400() {
    let app = build_app().await;
    let resp = app
        .oneshot(token_request(
            "grant_type=client_credentials&client_id=test-client",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn valid_authorization_code_exchange() {
    let app = build_app().await;
    let body = format!(
        "grant_type=authorization_code&code=test-code&redirect_uri=http://localhost:3000/callback&client_id=test-client&code_verifier={CODE_VERIFIER}"
    );
    let resp = app.oneshot(token_request(&body)).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let token: OAuthToken = serde_json::from_slice(&body).unwrap();
    assert_eq!(token.token_type, "Bearer");
    assert!(!token.access_token.is_empty());
}

#[tokio::test]
async fn invalid_code_verifier_returns_400() {
    let app = build_app().await;
    let body =
        "grant_type=authorization_code&code=test-code&redirect_uri=http://localhost:3000/callback&client_id=test-client&code_verifier=wrong-verifier";
    let resp = app.oneshot(token_request(body)).await.unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"], "invalid_grant");
    assert!(err["error_description"]
        .as_str()
        .unwrap()
        .contains("PKCE"));
}

#[tokio::test]
async fn missing_code_verifier_returns_400() {
    let app = build_app().await;
    let body = "grant_type=authorization_code&code=test-code&redirect_uri=http://localhost:3000/callback&client_id=test-client";
    let resp = app.oneshot(token_request(body)).await.unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"], "invalid_request");
}

#[tokio::test]
async fn expired_code_returns_400() {
    let provider = Arc::new(
        InMemoryProvider::default()
            .with_client(test_client())
            .await
            .with_authorization_code(AuthorizationCode {
                expires_at: 1000, // long past
                ..test_auth_code()
            })
            .await,
    );
    let app = build_oauth_router(provider, test_settings());
    let body = format!(
        "grant_type=authorization_code&code=test-code&redirect_uri=http://localhost:3000/callback&client_id=test-client&code_verifier={CODE_VERIFIER}"
    );
    let resp = app.oneshot(token_request(&body)).await.unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"], "invalid_grant");
}

#[tokio::test]
async fn redirect_uri_mismatch_returns_400() {
    let app = build_app().await;
    let body = format!(
        "grant_type=authorization_code&code=test-code&redirect_uri=http://other.com/cb&client_id=test-client&code_verifier={CODE_VERIFIER}"
    );
    let resp = app.oneshot(token_request(&body)).await.unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"], "invalid_grant");
}

#[tokio::test]
async fn valid_refresh_token_exchange() {
    let app = build_app().await;
    let body = "grant_type=refresh_token&refresh_token=test-refresh&client_id=test-client";
    let resp = app.oneshot(token_request(body)).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let token: OAuthToken = serde_json::from_slice(&body).unwrap();
    assert_eq!(token.token_type, "Bearer");
}

#[tokio::test]
async fn refresh_scope_escalation_returns_400() {
    let app = build_app().await;
    let body =
        "grant_type=refresh_token&refresh_token=test-refresh&client_id=test-client&scope=admin";
    let resp = app.oneshot(token_request(body)).await.unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"], "invalid_scope");
}

#[tokio::test]
async fn token_response_has_cache_headers() {
    let app = build_app().await;
    let body = format!(
        "grant_type=authorization_code&code=test-code&redirect_uri=http://localhost:3000/callback&client_id=test-client&code_verifier={CODE_VERIFIER}"
    );
    let resp = app.oneshot(token_request(&body)).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(resp.headers().get("pragma").unwrap(), "no-cache");
}

#[tokio::test]
async fn padded_code_challenge_accepted() {
    // Some clients (e.g. mcp-remote) send code_challenge with base64 padding
    let provider = Arc::new(
        InMemoryProvider::default()
            .with_client(test_client())
            .await
            .with_authorization_code(AuthorizationCode {
                code_challenge: format!("{CODE_CHALLENGE}="),
                ..test_auth_code()
            })
            .await,
    );
    let app = build_oauth_router(provider, test_settings());
    let body = format!(
        "grant_type=authorization_code&code=test-code&redirect_uri=http://localhost:3000/callback&client_id=test-client&code_verifier={CODE_VERIFIER}"
    );
    let resp = app.oneshot(token_request(&body)).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let token: OAuthToken = serde_json::from_slice(&body).unwrap();
    assert_eq!(token.token_type, "Bearer");
}

#[tokio::test]
async fn code_not_found_returns_400() {
    let app = build_app().await;
    let body = format!(
        "grant_type=authorization_code&code=nonexistent&redirect_uri=http://localhost:3000/callback&client_id=test-client&code_verifier={CODE_VERIFIER}"
    );
    let resp = app.oneshot(token_request(&body)).await.unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"], "invalid_grant");
}
