use rmcp_oauth::types::*;

#[test]
fn oauth_token_serialization() {
    let token = OAuthToken {
        access_token: "abc123".into(),
        token_type: "Bearer".into(),
        expires_in: Some(3600),
        refresh_token: Some("ref456".into()),
        scope: Some("read write".into()),
    };
    let json = serde_json::to_value(&token).unwrap();
    assert_eq!(json["access_token"], "abc123");
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["expires_in"], 3600);
    assert_eq!(json["refresh_token"], "ref456");
    assert_eq!(json["scope"], "read write");
}

#[test]
fn oauth_token_optional_fields_omitted() {
    let token = OAuthToken {
        access_token: "abc123".into(),
        token_type: "Bearer".into(),
        expires_in: None,
        refresh_token: None,
        scope: None,
    };
    let json = serde_json::to_value(&token).unwrap();
    assert!(json.get("expires_in").is_none());
    assert!(json.get("refresh_token").is_none());
    assert!(json.get("scope").is_none());
}

#[test]
fn client_info_full_flattens_metadata() {
    let info = OAuthClientInformationFull {
        client_id: "cid".into(),
        client_secret: Some("secret".into()),
        client_id_issued_at: Some(1000),
        client_secret_expires_at: None,
        metadata: OAuthClientMetadata {
            redirect_uris: vec!["http://localhost/cb".into()],
            client_name: Some("Test".into()),
            client_uri: None,
            logo_uri: None,
            scope: None,
            grant_types: None,
            response_types: None,
            token_endpoint_auth_method: None,
            application_type: None,
            contacts: None,
            tos_uri: None,
            policy_uri: None,
        },
    };
    let json = serde_json::to_value(&info).unwrap();
    // Flattened: redirect_uris at top level
    assert_eq!(json["client_id"], "cid");
    assert_eq!(json["redirect_uris"][0], "http://localhost/cb");
    assert_eq!(json["client_name"], "Test");
    // Optional fields omitted
    assert!(json.get("client_uri").is_none());
}

#[test]
fn authorization_server_metadata_roundtrip() {
    let json_str = r#"{
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"]
    }"#;
    let meta: OAuthAuthorizationServerMetadata = serde_json::from_str(json_str).unwrap();
    assert_eq!(meta.issuer, "https://auth.example.com");
    assert_eq!(meta.code_challenge_methods_supported, vec!["S256"]);
    assert!(meta.registration_endpoint.is_none());

    // Re-serialize and verify
    let val = serde_json::to_value(&meta).unwrap();
    assert!(val.get("registration_endpoint").is_none());
}

#[test]
fn protected_resource_metadata_has_authorization_servers() {
    let meta = ProtectedResourceMetadata {
        resource: "https://mcp.example.com".into(),
        authorization_servers: vec!["https://auth.example.com".into()],
        scopes_supported: Some(vec!["read".into()]),
        bearer_methods_supported: Some(vec!["header".into()]),
        extra: Default::default(),
    };
    let json = serde_json::to_value(&meta).unwrap();
    assert!(json["authorization_servers"].is_array());
    assert_eq!(json["authorization_servers"][0], "https://auth.example.com");
}
