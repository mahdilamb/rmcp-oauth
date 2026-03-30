//! Example: OAuth-protected MCP server using rmcp + rmcp-oauth.
//!
//! This example shows how to compose an rmcp `StreamableHttpService` with
//! rmcp-oauth's authorization layer so that the `/mcp` endpoint requires
//! a valid Bearer token.
//!
//! **Note:** This example requires the `rmcp` crate with server features.
//! Add to Cargo.toml:
//!
//! ```toml
//! [dependencies]
//! rmcp = { version = "1", features = ["server", "transport-streamable-http-server"] }
//! tokio-util = { version = "0.7", features = ["sync"] }
//! ```
//!
//! This file is illustrative and won't compile without rmcp in dependencies.
//! It demonstrates the integration pattern.

fn main() {
    // This example is documentation-only. See the code below for the pattern.
    println!("See source code for the integration pattern.");
}

// ─── Integration pattern (pseudo-code) ───────────────────────────────────────
//
// use std::sync::Arc;
//
// use axum::Router;
// use rmcp::transport::streamable_http_server::{
//     StreamableHttpServerConfig, StreamableHttpService,
//     session::local::LocalSessionManager,
// };
// use rmcp_oauth::config::{AuthSettings, ClientRegistrationOptions, RevocationOptions};
// use rmcp_oauth::middleware::bearer_auth::bearer_auth_middleware;
//
// // 1. Define your MCP server handler (implements rmcp::ServerHandler)
// struct MyMcpHandler;
//
// // impl rmcp::ServerHandler for MyMcpHandler { ... }
//
// #[tokio::main]
// async fn main() -> anyhow::Result<()> {
//     // 2. Configure OAuth settings
//     let settings = AuthSettings {
//         issuer_url: "https://auth.example.com".into(),
//         resource_server_url: "https://mcp.example.com".into(),
//         route_prefix: "".into(),
//         required_scopes: Some(vec!["mcp:access".into()]),
//         client_registration_options: ClientRegistrationOptions {
//             enabled: true,
//             ..Default::default()
//         },
//         revocation_options: RevocationOptions { enabled: true },
//         service_documentation_url: None,
//     };
//
//     // 3. Create provider (your custom implementation)
//     let provider = Arc::new(MyDatabaseProvider::new().await);
//
//     // 4. Build OAuth router (handles /.well-known/*, /authorize, /token, etc.)
//     let oauth_router = rmcp_oauth::build_oauth_router(
//         provider.clone(),
//         settings.clone(),
//     );
//
//     // 5. Build auth middleware state
//     let auth_state = rmcp_oauth::build_auth_state(provider, &settings);
//
//     // 6. Create the MCP service
//     let ct = tokio_util::sync::CancellationToken::new();
//     let mcp_service = StreamableHttpService::new(
//         || Ok(MyMcpHandler),
//         Arc::new(LocalSessionManager::default()),
//         StreamableHttpServerConfig::default()
//             .with_cancellation_token(ct.child_token()),
//     );
//
//     // 7. Protect MCP endpoint with Bearer auth middleware
//     let protected_mcp = Router::new()
//         .nest_service("/mcp", mcp_service)
//         .layer(axum::middleware::from_fn_with_state(
//             auth_state,
//             bearer_auth_middleware,
//         ));
//
//     // 8. Merge OAuth + protected MCP into one app
//     let app = Router::new()
//         .merge(oauth_router)
//         .merge(protected_mcp);
//
//     // 9. Serve
//     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//     axum::serve(listener, app)
//         .with_graceful_shutdown(async move {
//             tokio::signal::ctrl_c().await.unwrap();
//             ct.cancel();
//         })
//         .await?;
//
//     Ok(())
// }
