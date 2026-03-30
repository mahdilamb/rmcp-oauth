use axum::http::Method;
use tower_http::cors::CorsLayer;

/// Build a permissive CORS layer for OAuth endpoints.
///
/// Applied to: metadata, token, registration, revocation.
/// NOT applied to: authorization (browser redirect only).
pub fn oauth_cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(tower_http::cors::Any)
}
