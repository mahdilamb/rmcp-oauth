use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Verify a PKCE S256 code challenge against a code verifier.
///
/// Computes `BASE64URL(SHA256(code_verifier))` and does a constant-time
/// comparison against the stored `code_challenge`.
pub fn verify_pkce_s256(code_verifier: &str, code_challenge: &str) -> bool {
    let digest = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(digest);
    let challenge = code_challenge.trim_end_matches('=');
    computed.as_bytes().ct_eq(challenge.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_test_vector() {
        // From RFC 7636 Appendix B
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce_s256(verifier, expected_challenge));
    }

    #[test]
    fn invalid_verifier_fails() {
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(!verify_pkce_s256("wrong-verifier", challenge));
    }

    #[test]
    fn empty_verifier_fails() {
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(!verify_pkce_s256("", challenge));
    }

    #[test]
    fn padded_challenge_accepted() {
        // Some clients send code_challenge with base64 padding
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let padded_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM=";
        assert!(verify_pkce_s256(verifier, padded_challenge));
    }

    #[test]
    fn double_padded_challenge_accepted() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let padded_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM==";
        assert!(verify_pkce_s256(verifier, padded_challenge));
    }
}
