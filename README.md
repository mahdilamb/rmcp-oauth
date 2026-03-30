# rmcp-oauth

OAuth 2.1 authorization layer for [rmcp](https://github.com/modelcontextprotocol/rust-sdk) (Rust MCP SDK).

Implements the [MCP Authorization specification](https://modelcontextprotocol.io/specification/draft/basic/authorization) as a composable set of axum routes and middleware. Plug in your own provider to add OAuth to any rmcp-based MCP server.

## Features

- **RFC 8414** — Authorization Server Metadata discovery (`/.well-known/oauth-authorization-server`)
- **RFC 9728** — Protected Resource Metadata (`/.well-known/oauth-protected-resource`)
- **RFC 7591** — Dynamic Client Registration (optional)
- **RFC 7009** — Token Revocation (optional)
- **RFC 7636** — PKCE (S256, mandatory)
- **RFC 8707** — Resource parameter binding
- Bearer token middleware with scope enforcement
- Constant-time secret comparison
- Selective CORS (enabled on token/register/revoke, not on authorize)
- Configurable route prefix for reverse proxy setups

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
rmcp-oauth = { path = "." }  # or from your registry
```

### 1. Implement the provider trait

```rust
use async_trait::async_trait;
use rmcp_oauth::provider::OAuthAuthorizationServerProvider;
use rmcp_oauth::types::*;
use rmcp_oauth::error::*;

struct MyProvider { /* ... */ }

#[async_trait]
impl OAuthAuthorizationServerProvider for MyProvider {
    async fn get_client(&self, client_id: &str)
        -> Result<Option<OAuthClientInformationFull>, ProviderError> { /* ... */ }

    async fn register_client(&self, info: OAuthClientInformationFull)
        -> Result<OAuthClientInformationFull, RegistrationError> { /* ... */ }

    async fn authorize(&self, client: &OAuthClientInformationFull, params: AuthorizationParams)
        -> Result<String, AuthorizeError> { /* ... */ }

    async fn load_authorization_code(&self, client: &OAuthClientInformationFull, code: &str)
        -> Result<Option<AuthorizationCode>, ProviderError> { /* ... */ }

    async fn exchange_authorization_code(&self, client: &OAuthClientInformationFull, code: AuthorizationCode)
        -> Result<OAuthToken, TokenError> { /* ... */ }

    async fn load_refresh_token(&self, client: &OAuthClientInformationFull, token: &str)
        -> Result<Option<RefreshToken>, ProviderError> { /* ... */ }

    async fn exchange_refresh_token(&self, client: &OAuthClientInformationFull, token: RefreshToken, scopes: Option<Vec<String>>)
        -> Result<OAuthToken, TokenError> { /* ... */ }

    async fn load_access_token(&self, token: &str)
        -> Result<Option<AccessToken>, ProviderError> { /* ... */ }

    async fn revoke_token(&self, token: &str, hint: Option<&str>)
        -> Result<(), ProviderError> { /* ... */ }
}
```

### 2. Build the OAuth router

```rust
use std::sync::Arc;
use rmcp_oauth::config::{AuthSettings, ClientRegistrationOptions, RevocationOptions};

let settings = AuthSettings {
    issuer_url: "https://auth.example.com".into(),
    resource_server_url: "https://mcp.example.com".into(),
    route_prefix: "".into(),
    required_scopes: Some(vec!["mcp:access".into()]),
    client_registration_options: ClientRegistrationOptions {
        enabled: true,
        ..Default::default()
    },
    revocation_options: RevocationOptions { enabled: true },
    service_documentation_url: None,
};

let provider = Arc::new(MyProvider::new());
let oauth_router = rmcp_oauth::build_oauth_router(provider.clone(), settings.clone());
```

### 3. Protect your MCP endpoint

```rust
use rmcp_oauth::middleware::bearer_auth::bearer_auth_middleware;

let auth_state = rmcp_oauth::build_auth_state(provider, &settings);

let protected_mcp = axum::Router::new()
    .nest_service("/mcp", your_mcp_service)
    .layer(axum::middleware::from_fn_with_state(
        auth_state,
        bearer_auth_middleware,
    ));

let app = axum::Router::new()
    .merge(oauth_router)
    .merge(protected_mcp);
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/oauth-authorization-server` | Authorization server metadata |
| GET | `/.well-known/oauth-protected-resource` | Protected resource metadata |
| GET/POST | `{prefix}/authorize` | Authorization endpoint |
| POST | `{prefix}/token` | Token endpoint |
| POST | `{prefix}/register` | Dynamic client registration (if enabled) |
| POST | `{prefix}/revoke` | Token revocation (if enabled) |

## Architecture

```
┌─────────────────────────────────────────┐
│                  axum App               │
│                                         │
│  ┌──────────────────┐  ┌────────────┐  │
│  │  OAuth Router    │  │ MCP Router │  │
│  │                  │  │            │  │
│  │  /.well-known/*  │  │  /mcp      │  │
│  │  /authorize      │  │  (rmcp)    │  │
│  │  /token          │  │            │  │
│  │  /register       │  └─────┬──────┘  │
│  │  /revoke         │        │         │
│  └──────────────────┘   Bearer Auth    │
│                         Middleware      │
└─────────────────────────────────────────┘
         │                     │
         ▼                     ▼
   ┌───────────┐        ┌───────────┐
   │  Provider  │        │  Provider │
   │  (auth)    │◄───────│  (verify) │
   └───────────┘        └───────────┘
```

The OAuth router and MCP router are independent axum `Router` instances merged into a single app. The bearer auth middleware sits in front of the MCP endpoint and calls the same provider's `load_access_token` method to verify tokens.

## Route prefix

Functional endpoints support a configurable prefix for reverse proxy setups:

```rust
let settings = AuthSettings {
    route_prefix: "/oauth".into(),
    // ...
};
```

This puts endpoints at `/oauth/authorize`, `/oauth/token`, etc. Well-known paths always remain at the root (`/.well-known/*`) per RFC requirements.

## Provider examples

The provider trait is designed for pluggable backends:

- **In-memory** — See `examples/simple_server.rs`
- **Database-backed** — Store clients, codes, and tokens in PostgreSQL/SQLite
- **Delegating** — Forward `authorize()` to Google/GitHub OAuth, mint local tokens in `exchange_authorization_code()`

## Examples

```bash
# Run the standalone OAuth server
cargo run --example simple_server

# Test metadata discovery
curl http://localhost:3000/.well-known/oauth-authorization-server | jq

# Register a client
curl -X POST http://localhost:3000/register \
  -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["http://localhost:9999/callback"],"token_endpoint_auth_method":"none"}'
```

## License

MIT
