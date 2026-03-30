use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::provider::OAuthAuthorizationServerProvider;

pub struct CallbackState {
    pub provider: Arc<dyn OAuthAuthorizationServerProvider>,
}

/// GET {prefix}/callback
///
/// Receives the redirect from an upstream identity provider and delegates
/// to the provider to complete the authorization flow.
pub async fn callback_handler(
    State(state): State<Arc<CallbackState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    tracing::info!(state = ?params.get("state"), "callback received");

    match state.provider.handle_callback(params).await {
        Ok(redirect_url) => {
            tracing::info!("callback succeeded, redirecting to client");
            let mut resp = StatusCode::FOUND.into_response();
            resp.headers_mut().insert(
                "location",
                HeaderValue::from_str(&redirect_url)
                    .unwrap_or_else(|_| HeaderValue::from_static("/")),
            );
            resp.headers_mut()
                .insert("cache-control", HeaderValue::from_static("no-store"));
            resp.headers_mut()
                .insert("pragma", HeaderValue::from_static("no-cache"));
            resp
        }
        Err(e) => {
            tracing::warn!("callback provider returned error: {:?}", e);
            e.into_json_response()
        }
    }
}
