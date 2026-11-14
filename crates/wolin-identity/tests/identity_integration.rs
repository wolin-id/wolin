use serde_json::json;
use wolin_core::{Principal, WebId, WolinError};
use wolin_identity::{
    DidMethod, DidResolver, JwtSignatureVerifier, OidcValidationOptions, OidcValidator,
};

fn b64url_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
    }
    out
}

fn build_jwt(header: serde_json::Value, payload: serde_json::Value, sig: &[u8]) -> String {
    let h = b64url_encode(header.to_string().as_bytes());
    let p = b64url_encode(payload.to_string().as_bytes());
    let s = b64url_encode(sig);
    format!("{h}.{p}.{s}")
}

#[test]
fn did_key_ed25519_and_secp256k1_resolution() {
    let ed_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"; // gitleaks:allow
    let parsed = DidResolver::parse(ed_did).expect("valid Ed25519 did:key");
    assert_eq!(parsed.method, DidMethod::Key);
    assert_eq!(parsed.canonical_did, ed_did);
    assert_eq!(parsed.issuer, "did:key");
    assert_eq!(parsed.resolution_url, None);

    let doc = DidResolver::resolve_document(ed_did).expect("did document");
    assert_eq!(doc.id, ed_did);
    assert_eq!(doc.verification_method.len(), 1);
    assert_eq!(
        doc.verification_method[0].method_type,
        "Ed25519VerificationKey2020"
    );

    let principal = DidResolver::resolve_principal(ed_did).expect("principal");
    assert_eq!(
        principal,
        Principal::User {
            webid: WebId(ed_did.to_string()),
            issuer: "did:key".to_string(),
        }
    );

    let secp_did = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"; // gitleaks:allow
    let secp_doc = DidResolver::resolve_document(secp_did).expect("valid secp256k1 did:key");
    assert_eq!(
        secp_doc.verification_method[0].method_type,
        "EcdsaSecp256k1VerificationKey2019"
    );
}

#[test]
fn did_nostr_resolution_and_validation() {
    let nostr_did = "did:nostr:7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
    let parsed = DidResolver::parse(nostr_did).expect("valid did:nostr");
    assert_eq!(parsed.method, DidMethod::Nostr);
    assert_eq!(parsed.issuer, "did:nostr");

    let principal = DidResolver::resolve_principal(nostr_did).expect("nostr principal");
    assert_eq!(
        principal,
        Principal::User {
            webid: WebId(nostr_did.to_string()),
            issuer: "did:nostr".to_string(),
        }
    );

    // Uppercase hex, wrong length, and all-zero pubkey must be rejected
    assert!(
        DidResolver::resolve_principal(
            "did:nostr:7E7E9C42A91BFEF19FA929E5FDA1B72E0EBC1A4C1141673E2794234D86ADDF4E"
        )
        .is_err()
    );
    assert!(DidResolver::resolve_principal("did:nostr:abcd1234").is_err());
    assert!(DidResolver::resolve_principal(&format!("did:nostr:{}", "0".repeat(64))).is_err());
}

#[test]
fn did_web_domain_path_port_and_ssrf_guards() {
    let root_web = "did:web:wolin.id";
    let parsed_root = DidResolver::parse(root_web).expect("root did:web");
    assert_eq!(parsed_root.method, DidMethod::Web);
    assert_eq!(parsed_root.issuer, "did:web:wolin.id");
    assert_eq!(
        parsed_root.resolution_url.as_deref(),
        Some("https://wolin.id/.well-known/did.json")
    );

    let nested_web = "did:web:zitadel.acme.corp:orgs:rd:alice#key-1";
    let parsed_nested = DidResolver::parse(nested_web).expect("nested did:web with fragment");
    assert_eq!(
        parsed_nested.canonical_did,
        "did:web:zitadel.acme.corp:orgs:rd:alice"
    );
    assert_eq!(parsed_nested.fragment.as_deref(), Some("key-1"));
    assert_eq!(parsed_nested.issuer, "did:web:zitadel.acme.corp");
    assert_eq!(
        parsed_nested.resolution_url.as_deref(),
        Some("https://zitadel.acme.corp/orgs/rd/alice/did.json")
    );

    let port_web = "did:web:localhost%3a8443:agents:planner";
    let parsed_port = DidResolver::parse(port_web).expect("port-encoded did:web");
    assert_eq!(
        parsed_port.canonical_did,
        "did:web:localhost%3A8443:agents:planner"
    );
    assert_eq!(parsed_port.issuer, "did:web:localhost:8443");
    assert_eq!(
        parsed_port.resolution_url.as_deref(),
        Some("https://localhost:8443/agents/planner/did.json")
    );

    // Reject path traversal, empty segments, encoded slashes, and invalid methods
    for bad in [
        "",
        "http://wolin.id",
        "did:unknown:12345",
        "did:key:notbase58_0OIl",
        "did:key:z12",
        "did:web:",
        "did:web:acme.corp::alice",
        "did:web:acme.corp:..:secret",
        "did:web:acme.corp:%2e%2e:secret",
        "did:web:acme.corp:users%2falice",
        "did:web:localhost%3A99999",
    ] {
        assert!(
            DidResolver::resolve_principal(bad).is_err(),
            "expected {bad:?} to fail validation"
        );
    }
}

#[test]
fn did_delegated_agent_principal_mapping() {
    let agent_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"; // gitleaks:allow
    let delegator = WebId("https://alice.wolin.id/profile#me".to_string());
    let principal = DidResolver::resolve_agent_principal(
        agent_did,
        delegator.clone(),
        vec!["read".to_string(), "append".to_string(), "read".to_string()],
    )
    .expect("delegated agent principal");

    assert_eq!(
        principal,
        Principal::Agent {
            agent_id: agent_did.to_string(),
            delegated_by: delegator,
            scope: vec!["read".to_string(), "append".to_string()],
        }
    );
}

#[test]
fn oidc_zitadel_user_and_agent_delegation_claims() {
    let now = 1_763_000_000_i64;
    let issuer = "https://auth.zitadel.acme.corp";

    // 1. Enterprise ZITADEL User JWT with single string aud & space-delimited scope
    let user_jwt = build_jwt(
        json!({ "alg": "RS256", "typ": "JWT", "kid": "zitadel-k1" }),
        json!({
            "iss": issuer,
            "sub": "289011223344",
            "aud": "wolin-pod-gateway",
            "iat": now - 60,
            "exp": now + 3600,
            "scope": "openid profile email read write",
            "urn:zitadel:iam:org:id": "acme-org-01"
        }),
        b"valid-sig-bytes",
    );

    let opts = OidcValidationOptions::new(issuer)
        .with_audience("wolin-pod-gateway")
        .with_now(now);

    let parsed_claims = OidcValidator::parse_jwt_claims(&user_jwt).expect("parse claims");
    assert_eq!(parsed_claims.org_id.as_deref(), Some("acme-org-01"));
    assert_eq!(
        parsed_claims.scopes,
        vec!["openid", "profile", "email", "read", "write"]
    );

    let user_principal =
        OidcValidator::validate_with_options(&user_jwt, &opts).expect("valid user jwt");
    assert_eq!(
        user_principal,
        Principal::User {
            webid: WebId(format!("{issuer}#289011223344")),
            issuer: issuer.to_string(),
        }
    );

    // 2. Solid-OIDC + RFC 8693 `act` Agent Delegation JWT with array aud & scopes array
    let agent_jwt = build_jwt(
        json!({ "alg": "EdDSA", "typ": "at+jwt" }),
        json!({
            "iss": issuer,
            "sub": "289011223344",
            "webid": "https://alice.acme.corp/profile#me",
            "aud": ["wolin-pod-gateway", "https://pod.acme.corp"],
            "iat": now - 10,
            "nbf": now - 5,
            "exp": now + 300,
            "scopes": ["read", "append"],
            "act": { "sub": "did:web:acme.corp:agents:research-bot" }
        }),
        b"ed25519-sig",
    );

    let agent_principal =
        OidcValidator::validate_with_options(&agent_jwt, &opts).expect("valid delegated agent jwt");
    assert_eq!(
        agent_principal,
        Principal::Agent {
            agent_id: "did:web:acme.corp:agents:research-bot".to_string(),
            delegated_by: WebId("https://alice.acme.corp/profile#me".to_string()),
            scope: vec!["read".to_string(), "append".to_string()],
        }
    );
}

#[test]
fn oidc_rejects_expired_wrong_issuer_wrong_aud_and_alg_none() {
    let now = 1_763_000_000_i64;
    let issuer = "https://auth.zitadel.acme.corp";
    let opts = OidcValidationOptions::new(issuer)
        .with_audience("wolin-api")
        .with_now(now);

    // Expired token
    let expired_jwt = build_jwt(
        json!({ "alg": "RS256" }),
        json!({ "iss": issuer, "sub": "u1", "aud": "wolin-api", "exp": now }),
        b"sig",
    );
    assert!(matches!(
        OidcValidator::validate_with_options(&expired_jwt, &opts),
        Err(WolinError::Unauthenticated(_))
    ));

    // Wrong issuer
    let wrong_iss_jwt = build_jwt(
        json!({ "alg": "RS256" }),
        json!({ "iss": "https://evil.idp.example", "sub": "u1", "aud": "wolin-api", "exp": now + 600 }),
        b"sig",
    );
    assert!(OidcValidator::validate_with_options(&wrong_iss_jwt, &opts).is_err());

    // Wrong audience
    let wrong_aud_jwt = build_jwt(
        json!({ "alg": "RS256" }),
        json!({ "iss": issuer, "sub": "u1", "aud": ["other-service"], "exp": now + 600 }),
        b"sig",
    );
    assert!(OidcValidator::validate_with_options(&wrong_aud_jwt, &opts).is_err());

    // alg: none attack
    let alg_none_jwt = build_jwt(
        json!({ "alg": "none" }),
        json!({ "iss": issuer, "sub": "u1", "aud": "wolin-api", "exp": now + 600 }),
        b"sig",
    );
    assert!(OidcValidator::validate_with_options(&alg_none_jwt, &opts).is_err());

    // Empty signature attack
    let empty_sig_jwt = build_jwt(
        json!({ "alg": "RS256" }),
        json!({ "iss": issuer, "sub": "u1", "aud": "wolin-api", "exp": now + 600 }),
        b"",
    );
    assert!(OidcValidator::validate_with_options(&empty_sig_jwt, &opts).is_err());
}

struct MockVerifier {
    expected_kid: &'static str,
}

impl JwtSignatureVerifier for MockVerifier {
    fn verify(
        &self,
        alg: &str,
        kid: Option<&str>,
        _signing_input: &[u8],
        signature: &[u8],
    ) -> wolin_core::Result<()> {
        if alg == "EdDSA" && kid == Some(self.expected_kid) && signature == b"trusted-ed25519-sig" {
            Ok(())
        } else {
            Err(WolinError::Unauthenticated(
                "Cryptographic signature verification failed".to_string(),
            ))
        }
    }
}

#[test]
fn oidc_custom_signature_verifier_enforced() {
    let now = 1_763_000_000_i64;
    let issuer = "https://auth.wolin.id";
    let opts = OidcValidationOptions::new(issuer).with_now(now);
    let verifier = MockVerifier {
        expected_kid: "key-2026",
    };

    let valid_jwt = build_jwt(
        json!({ "alg": "EdDSA", "kid": "key-2026" }),
        json!({ "iss": issuer, "sub": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "aud": "wolin", "exp": now + 300 }), // gitleaks:allow
        b"trusted-ed25519-sig",
    );
    let p = OidcValidator::validate_with_verifier(&valid_jwt, &opts, &verifier)
        .expect("verified signature");
    assert!(matches!(p, Principal::User { .. }));

    let forged_jwt = build_jwt(
        json!({ "alg": "EdDSA", "kid": "key-2026" }),
        json!({ "iss": issuer, "sub": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "aud": "wolin", "exp": now + 300 }), // gitleaks:allow
        b"forged-sig",
    );
    assert!(OidcValidator::validate_with_verifier(&forged_jwt, &opts, &verifier).is_err());
}
