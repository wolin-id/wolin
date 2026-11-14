use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Path,
    http::{Method, Request, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tower::ServiceExt;
use wolin_identity::{
    HttpWebIdDereferencer, JwtSignatureVerifier, OidcValidationOptions, WebIdDereferencer,
    compute_jwk_thumbprint_sha256, sha256_base64url,
};
use wolin_policy::PolicyEngine;
use wolin_server::{
    AppState, LdpConfig, build_router,
    ldp::{LDP_BASIC_CONTAINER, LDP_INBOX_REL, LDP_RESOURCE, PIM_STORAGE, PIM_STORAGE_REL},
};
use wolin_storage::{
    SemanticGraphStore,
    rdf_io::RdfFormat,
    rdf_model::{NamedNode, NamedOrBlankNode, Term},
};

const LOCAL_WOLIN_ISSUER: &str = "https://auth.wolin.id";
const INRUPT_ISSUER: &str = "https://login.inrupt.com";
const EVIL_ISSUER: &str = "https://evil.idp.example";
const TEST_NOW: i64 = 1_763_500_000;

fn b64url(bytes: &[u8]) -> String {
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

fn build_jwt(header_val: Value, payload_val: Value, sig: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        b64url(header_val.to_string().as_bytes()),
        b64url(payload_val.to_string().as_bytes()),
        b64url(sig)
    )
}

/// Real ECDSA P-256 (`ES256`) DPoP client keypair matching `@inrupt/solid-client-authn`.
struct DpopClientKey {
    key_pair: EcdsaKeyPair,
    public_jwk: Value,
    jkt: String,
    rng: SystemRandom,
}

impl DpopClientKey {
    fn generate() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generate P-256 PKCS8");
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .expect("load P-256 keypair");
        let pub_bytes = key_pair.public_key().as_ref();
        // Uncompressed SEC1 point: 0x04 || X (32 bytes) || Y (32 bytes)
        assert_eq!(pub_bytes.len(), 65);
        assert_eq!(pub_bytes[0], 0x04);
        let x_b64 = b64url(&pub_bytes[1..33]);
        let y_b64 = b64url(&pub_bytes[33..65]);
        let public_jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64
        });
        let jkt = compute_jwk_thumbprint_sha256(&public_jwk).expect("RFC 7638 JWK thumbprint");
        Self {
            key_pair,
            public_jwk,
            jkt,
            rng,
        }
    }

    fn sign_dpop_proof(
        &self,
        htm: &str,
        htu: &str,
        jti: &str,
        iat: i64,
        access_token: Option<&str>,
    ) -> String {
        let header_val = json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": self.public_jwk
        });
        let mut payload_val = json!({
            "jti": jti,
            "htm": htm,
            "htu": htu,
            "iat": iat
        });
        if let Some(tok) = access_token {
            payload_val["ath"] = Value::String(sha256_base64url(tok.as_bytes()));
        }
        let h_b64 = b64url(header_val.to_string().as_bytes());
        let p_b64 = b64url(payload_val.to_string().as_bytes());
        let signing_input = format!("{h_b64}.{p_b64}");
        let sig = self
            .key_pair
            .sign(&self.rng, signing_input.as_bytes())
            .expect("ES256 DPoP sign");
        format!("{signing_input}.{}", b64url(sig.as_ref()))
    }
}

/// Verifier accepting signed tokens from both `INRUPT_ISSUER`, `LOCAL_WOLIN_ISSUER`, and `EVIL_ISSUER`
/// (simulating multi-IdP JWKS cryptographic verification so trust-chain isolation is tested purely on `solid:oidcIssuer`).
struct FederatedJwksMockVerifier;

impl JwtSignatureVerifier for FederatedJwksMockVerifier {
    fn verify(
        &self,
        alg: &str,
        _kid: Option<&str>,
        _signing_input: &[u8],
        signature: &[u8],
    ) -> wolin_core::Result<()> {
        if matches!(alg, "ES256" | "EdDSA" | "RS256") && signature == b"federated-jwks-valid-sig" {
            Ok(())
        } else {
            Err(wolin_core::WolinError::Unauthenticated(
                "Invalid IdP JWS signature".to_string(),
            ))
        }
    }
}

/// Spawn a mock external Solid WebID Profile server (e.g., `id.inrupt.com` simulator) on `127.0.0.1:0`.
async fn spawn_external_webid_server() -> (String, oneshot::Sender<()>) {
    let app = Router::new().route(
        "/{user}/profile/card",
        get(|Path(user): Path<String>| async move {
            match user.as_str() {
                "alice" => {
                    let ttl = format!(
                        "@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
                         @prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
                         @prefix pim: <http://www.w3.org/ns/pim/space#> .\n\
                         <> a foaf:PersonalProfileDocument ; foaf:primaryTopic <#me> .\n\
                         <#me> a foaf:Person ;\n\
                             foaf:name \"Alice Inrupt\" ;\n\
                             solid:oidcIssuer <{INRUPT_ISSUER}> ;\n\
                             pim:storage <https://storage.inrupt.com/alice/> .\n"
                    );
                    (StatusCode::OK, [(header::CONTENT_TYPE, "text/turtle")], ttl).into_response()
                }
                "bob" => {
                    let jsonld = json!({
                        "@id": "#me",
                        "@type": "http://xmlns.com/foaf/0.1/Person",
                        "http://www.w3.org/ns/solid/terms#oidcIssuer": {
                            "@id": INRUPT_ISSUER
                        }
                    });
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/ld+json")],
                        jsonld.to_string(),
                    )
                        .into_response()
                }
                "unlinked" => {
                    let ttl = "@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
                               <#me> a foaf:Person ; foaf:name \"No OIDC Issuer\" .\n";
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "text/turtle")],
                        ttl.to_string(),
                    )
                        .into_response()
                }
                _ => StatusCode::NOT_FOUND.into_response(),
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock WebID server");
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });
    (format!("http://{addr}"), tx)
}

fn mint_solid_oidc_dpop_token(
    issuer: &str,
    webid: &str,
    jkt: &str,
    aud: Value,
    exp: i64,
) -> String {
    build_jwt(
        json!({ "alg": "ES256", "typ": "at+jwt", "kid": "idp-key-1" }),
        json!({
            "iss": issuer,
            "sub": webid,
            "webid": webid,
            "aud": aud,
            "client_id": "https://my-solid-app.example/id",
            "iat": TEST_NOW - 10,
            "exp": exp,
            "cnf": { "jkt": jkt }
        }),
        b"federated-jwks-valid-sig",
    )
}

#[tokio::test]
async fn solid_oidc_external_webid_dereferencing_trust_chain_and_dpop_security() {
    let (ext_origin, _shutdown_ext) = spawn_external_webid_server().await;
    let alice_ext_webid = format!("{ext_origin}/alice/profile/card#me");
    let bob_ext_webid = format!("{ext_origin}/bob/profile/card#me");
    let unlinked_ext_webid = format!("{ext_origin}/unlinked/profile/card#me");

    // Production HttpWebIdDereferencer MUST block plain HTTP loopback & metadata SSRF fail-closed
    let prod_deref = HttpWebIdDereferencer::new().expect("prod dereferencer");
    assert!(prod_deref.dereference(&alice_ext_webid).await.is_err());
    assert!(
        prod_deref
            .dereference("https://169.254.169.254/latest/meta-data#me")
            .await
            .is_err()
    );

    // Loopback-enabled dereferencer for local integration harness
    let test_deref =
        Arc::new(HttpWebIdDereferencer::new_allow_loopback_http().expect("loopback dereferencer"));

    let base_url = "http://127.0.0.1:4000";
    let config = LdpConfig::new(base_url, "wolin://pod")
        .with_oidc_options(
            OidcValidationOptions::new(LOCAL_WOLIN_ISSUER)
                .with_audience("wolin-server")
                .with_now(TEST_NOW),
        )
        .with_jwt_verifier(Arc::new(FederatedJwksMockVerifier))
        .with_webid_dereferencer(test_deref)
        .with_policy_clock(TEST_NOW);

    let state = AppState::new_in_memory(PolicyEngine::new(), config)
        .await
        .expect("init AppState");
    let app = build_router(state);

    // Provision a Pod owned by Alice's external Inrupt WebID
    let prov_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/pods")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "pod_id": "alice",
                        "owner_webid": alice_ext_webid,
                        "display_name": "Alice Inrupt"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(prov_resp.status(), StatusCode::CREATED);

    let alice_dpop = DpopClientKey::generate();
    let alice_token = mint_solid_oidc_dpop_token(
        INRUPT_ISSUER,
        &alice_ext_webid,
        &alice_dpop.jkt,
        json!(["solid", "https://my-solid-app.example/id"]),
        TEST_NOW + 600,
    );

    // 1. Valid Solid-OIDC DPoP PUT to `/pods/alice/private/secret.ttl` -> 201 Created
    let target_path = "/pods/alice/private/secret.ttl";
    let target_htu = format!("{base_url}{target_path}");
    let proof_1 = alice_dpop.sign_dpop_proof(
        "PUT",
        &target_htu,
        "jti-put-1",
        TEST_NOW,
        Some(&alice_token),
    );
    let put_priv = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(target_path)
                .header(header::AUTHORIZATION, format!("DPoP {alice_token}"))
                .header("DPoP", &proof_1)
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<#vault> <http://purl.org/dc/terms/title> \"Inrupt Federated Secret\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_priv.status(), StatusCode::CREATED);

    // 2. DPoP Replay Attack: reusing identical `proof_1` (`jti-put-1`) MUST fail with 401!
    let replay_attempt = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(target_path)
                .header(header::AUTHORIZATION, format!("DPoP {alice_token}"))
                .header("DPoP", &proof_1)
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#vault> <#tamper> \"replayed\" ."))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay_attempt.status(), StatusCode::UNAUTHORIZED);

    // 3. DPoP `htm` Method Mismatch: proof signed for GET used on DELETE -> 401!
    let get_proof = alice_dpop.sign_dpop_proof(
        "GET",
        &target_htu,
        "jti-method-mismatch",
        TEST_NOW,
        Some(&alice_token),
    );
    let method_mismatch = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(target_path)
                .header(header::AUTHORIZATION, format!("DPoP {alice_token}"))
                .header("DPoP", get_proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(method_mismatch.status(), StatusCode::UNAUTHORIZED);

    // 4. DPoP `htu` Target URI Mismatch: proof signed for `/pods/alice/public/` used on private -> 401!
    let wrong_htu_proof = alice_dpop.sign_dpop_proof(
        "GET",
        &format!("{base_url}/pods/alice/public/"),
        "jti-htu-mismatch",
        TEST_NOW,
        Some(&alice_token),
    );
    let htu_mismatch = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(target_path)
                .header(header::AUTHORIZATION, format!("DPoP {alice_token}"))
                .header("DPoP", wrong_htu_proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(htu_mismatch.status(), StatusCode::UNAUTHORIZED);

    // 5. Bearer Downgrade Attack: `cnf.jkt`-bound DPoP token sent as `Bearer` -> 401!
    let bearer_downgrade = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(target_path)
                .header(header::AUTHORIZATION, format!("Bearer {alice_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bearer_downgrade.status(), StatusCode::UNAUTHORIZED);

    // 6. Spoofed / Untrusted OIDC Issuer (`evil.idp.example` claiming Alice's WebID) -> 401!
    let evil_dpop = DpopClientKey::generate();
    let spoofed_token = mint_solid_oidc_dpop_token(
        EVIL_ISSUER,
        &alice_ext_webid,
        &evil_dpop.jkt,
        json!("solid"),
        TEST_NOW + 600,
    );
    let evil_proof = evil_dpop.sign_dpop_proof(
        "GET",
        &target_htu,
        "jti-evil-1",
        TEST_NOW,
        Some(&spoofed_token),
    );
    let spoof_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(target_path)
                .header(header::AUTHORIZATION, format!("DPoP {spoofed_token}"))
                .header("DPoP", evil_proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(spoof_resp.status(), StatusCode::UNAUTHORIZED);

    // 7. Unlinked WebID profile (missing `solid:oidcIssuer`) -> 401!
    let unlinked_token = mint_solid_oidc_dpop_token(
        INRUPT_ISSUER,
        &unlinked_ext_webid,
        &evil_dpop.jkt,
        json!("solid"),
        TEST_NOW + 600,
    );
    let unlinked_proof = evil_dpop.sign_dpop_proof(
        "GET",
        &format!("{base_url}/pods/alice/public/"),
        "jti-unlinked-1",
        TEST_NOW,
        Some(&unlinked_token),
    );
    let unlinked_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/pods/alice/public/")
                .header(header::AUTHORIZATION, format!("DPoP {unlinked_token}"))
                .header("DPoP", unlinked_proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unlinked_resp.status(), StatusCode::UNAUTHORIZED);

    // 8. External JSON-LD WebID user (`bob`) can POST LDN notification to `/pods/alice/inbox/`,
    //    cannot GET `/pods/alice/inbox/` (403), while Alice CAN read her inbox!
    let bob_dpop = DpopClientKey::generate();
    let bob_token = mint_solid_oidc_dpop_token(
        INRUPT_ISSUER,
        &bob_ext_webid,
        &bob_dpop.jkt,
        json!("solid"),
        TEST_NOW + 600,
    );
    let inbox_htu = format!("{base_url}/pods/alice/inbox/");
    let bob_post_proof = bob_dpop.sign_dpop_proof(
        "POST",
        &inbox_htu,
        "jti-bob-ldn-1",
        TEST_NOW,
        Some(&bob_token),
    );
    let ldn_post = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/pods/alice/inbox/")
                .header(header::AUTHORIZATION, format!("DPoP {bob_token}"))
                .header("DPoP", bob_post_proof)
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<> a <http://www.w3.org/ns/activitystreams#Announce> .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ldn_post.status(), StatusCode::CREATED);

    let bob_get_proof = bob_dpop.sign_dpop_proof(
        "GET",
        &inbox_htu,
        "jti-bob-ldn-read",
        TEST_NOW,
        Some(&bob_token),
    );
    let bob_inbox_read = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/pods/alice/inbox/")
                .header(header::AUTHORIZATION, format!("DPoP {bob_token}"))
                .header("DPoP", bob_get_proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_inbox_read.status(), StatusCode::FORBIDDEN);

    let alice_inbox_proof = alice_dpop.sign_dpop_proof(
        "GET",
        &inbox_htu,
        "jti-alice-inbox-read",
        TEST_NOW,
        Some(&alice_token),
    );
    let alice_inbox_read = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/pods/alice/inbox/")
                .header(header::AUTHORIZATION, format!("DPoP {alice_token}"))
                .header("DPoP", alice_inbox_proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(alice_inbox_read.status(), StatusCode::OK);
    let inbox_ttl = String::from_utf8(
        to_bytes(alice_inbox_read.into_body(), 65_536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(inbox_ttl.contains("http://www.w3.org/ns/ldp#contains"));
}

#[tokio::test]
async fn dynamic_pod_provisioning_w3c_seed_resources_and_acl_matrix() {
    let base_url = "http://pod.wolin.local";
    let config = LdpConfig::new(base_url, "wolin://pod")
        .with_oidc_options(OidcValidationOptions::new(LOCAL_WOLIN_ISSUER).with_now(TEST_NOW))
        .with_pod_cloud_domain("wolin.cloud")
        .with_policy_clock(TEST_NOW);

    let state = AppState::new_in_memory(PolicyEngine::new(), config)
        .await
        .unwrap();
    let app = build_router(state);

    let owner_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"; // gitleaks:allow
    let stranger_did = "did:nostr:7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";

    // Reject malformed or reserved `pod_id`s
    for bad_id in ["", "Alice", "../etc", "-bad", "bad-", "api", "pods", "mcp"] {
        let bad_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/pods")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "pod_id": bad_id,
                            "owner_webid": owner_did,
                            "display_name": "Bad Pod"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            bad_resp.status(),
            StatusCode::BAD_REQUEST,
            "expected bad pod_id {bad_id:?} to fail with 400"
        );
    }

    // Provision Pod with Turtle-injection attempt in `display_name` (must be safely literal-escaped)
    let tricky_name =
        "Alice \"Wonderland\" . <#injected> a <http://www.w3.org/ns/auth/acl#Authorization> .";
    let create_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/pods")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "pod_id": "alice-01",
                        "owner_webid": owner_did,
                        "display_name": tricky_name
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    assert_eq!(
        create_resp.headers().get(header::LOCATION).unwrap(),
        "http://pod.wolin.local/pods/alice-01/"
    );
    let created_json: Value =
        serde_json::from_slice(&to_bytes(create_resp.into_body(), 65_536).await.unwrap()).unwrap();
    assert_eq!(created_json["pod_id"], "alice-01");
    assert_eq!(
        created_json["webid"],
        "http://pod.wolin.local/pods/alice-01/profile/card#me"
    );
    assert_eq!(
        created_json["storage"],
        "http://pod.wolin.local/pods/alice-01/"
    );
    assert_eq!(
        created_json["inbox"],
        "http://pod.wolin.local/pods/alice-01/inbox/"
    );

    // Duplicate provisioning of `alice-01` -> 409 Conflict
    let dup_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/pods")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "pod_id": "alice-01",
                        "owner_webid": stranger_did,
                        "display_name": "Takeover Attempt"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dup_resp.status(), StatusCode::CONFLICT);

    // Anonymous GET `/pods/alice-01/profile/card` -> 200 OK with valid Turtle (no RDF injection!)
    let card_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/pods/alice-01/profile/card")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(card_resp.status(), StatusCode::OK);
    let card_link = card_resp
        .headers()
        .get(header::LINK)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(card_link.contains(&format!("<{LDP_RESOURCE}>; rel=\"type\"")));
    assert!(card_link.contains(&format!(
        "<http://pod.wolin.local/pods/alice-01/>; rel=\"{PIM_STORAGE_REL}\""
    )));
    assert!(card_link.contains(&format!(
        "<http://pod.wolin.local/pods/alice-01/inbox/>; rel=\"{LDP_INBOX_REL}\""
    )));

    let card_bytes = to_bytes(card_resp.into_body(), 65_536).await.unwrap();
    let parsed_triples = SemanticGraphStore::parse_rdf_triples(
        &card_bytes,
        RdfFormat::Turtle,
        "http://pod.wolin.local/pods/alice-01/profile/card",
    )
    .expect("valid profile card RDF");
    // Ensure `#injected` never materialized as a subject!
    assert!(!parsed_triples.iter().any(|t| matches!(
        &t.subject,
        NamedOrBlankNode::NamedNode(n) if n.as_str().ends_with("#injected")
    )));
    let me_iri = "http://pod.wolin.local/pods/alice-01/profile/card#me";
    assert!(parsed_triples.iter().any(|t| {
        matches!(&t.subject, NamedOrBlankNode::NamedNode(n) if n.as_str() == me_iri)
            && t.predicate.as_str() == PIM_STORAGE_REL
            && matches!(&t.object, Term::NamedNode(o) if o.as_str() == "http://pod.wolin.local/pods/alice-01/")
    }));
    assert!(parsed_triples.iter().any(|t| {
        matches!(&t.subject, NamedOrBlankNode::NamedNode(n) if n.as_str() == me_iri)
            && t.predicate.as_str() == "http://www.w3.org/ns/solid/terms#oidcIssuer"
            && matches!(&t.object, Term::NamedNode(o) if o.as_str() == LOCAL_WOLIN_ISSUER)
    }));
    assert!(parsed_triples.iter().any(|t| {
        matches!(&t.subject, NamedOrBlankNode::NamedNode(n) if n.as_str() == me_iri)
            && t.predicate.as_str() == LDP_INBOX_REL
            && matches!(&t.object, Term::NamedNode(o) if o.as_str() == "http://pod.wolin.local/pods/alice-01/inbox/")
    }));

    // Verify `card.acl`: Anonymous cannot read `.acl` (401), Owner CAN read `.acl` (200)
    let anon_acl = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/pods/alice-01/profile/card.acl")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anon_acl.status(), StatusCode::UNAUTHORIZED);

    let owner_acl = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/pods/alice-01/profile/card.acl")
                .header(header::AUTHORIZATION, format!("DID {owner_did}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(owner_acl.status(), StatusCode::OK);

    // Verify `public/` (Anonymous 200), `private/` (Anonymous 401, Stranger 403, Owner 200), and `.well-known/wolin.json` (Anonymous 200)
    let pub_get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/pods/alice-01/public/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pub_get.status(), StatusCode::OK);

    let priv_anon = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/pods/alice-01/private/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(priv_anon.status(), StatusCode::UNAUTHORIZED);

    let priv_stranger = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/pods/alice-01/private/")
                .header(header::AUTHORIZATION, format!("DID {stranger_did}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(priv_stranger.status(), StatusCode::FORBIDDEN);

    let priv_owner = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/pods/alice-01/private/")
                .header(header::AUTHORIZATION, format!("DID {owner_did}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(priv_owner.status(), StatusCode::OK);

    let wk_pod = app
        .oneshot(
            Request::builder()
                .uri("/pods/alice-01/.well-known/wolin.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wk_pod.status(), StatusCode::OK);
    let wk_pod_json: Value =
        serde_json::from_slice(&to_bytes(wk_pod.into_body(), 65_536).await.unwrap()).unwrap();
    assert_eq!(wk_pod_json["pod_id"], "alice-01");
}

#[tokio::test]
async fn inrupt_solid_client_simulation_discovery_and_dataset_crud() {
    // Bind real loopback TCP listener for authentic HTTP client workflow
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_origin = format!("http://{addr}");

    let test_deref =
        Arc::new(HttpWebIdDereferencer::new_allow_loopback_http().expect("loopback dereferencer"));
    let config = LdpConfig::new(&server_origin, "wolin://pod")
        .with_oidc_options(OidcValidationOptions::new(LOCAL_WOLIN_ISSUER).with_now(TEST_NOW))
        .with_jwt_verifier(Arc::new(FederatedJwksMockVerifier))
        .with_webid_dereferencer(test_deref)
        .with_policy_clock(TEST_NOW);

    let state = AppState::new_in_memory(PolicyEngine::new(), config)
        .await
        .unwrap();
    let app = build_router(state);

    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // 1. Provision Carol's Pod via `POST /api/pods`
    let prov = http
        .post(format!("{server_origin}/api/pods"))
        .header("Content-Type", "application/json")
        .body(
            json!({
                "pod_id": "carol",
                "display_name": "Carol Solid Developer"
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(prov.status(), StatusCode::CREATED);
    let prov_body: Value = serde_json::from_slice(&prov.bytes().await.unwrap()).unwrap();
    let carol_webid = prov_body["webid"].as_str().unwrap().to_string();

    // 2. Simulate `@inrupt/solid-client` `getPodUrlAll(carolWebId)`:
    //    Fetch WebID Profile document (stripping `#me`) and extract `pim:storage`
    let profile_doc_url = carol_webid.split('#').next().unwrap();
    let profile_resp = http
        .get(profile_doc_url)
        .header("Accept", "text/turtle")
        .send()
        .await
        .unwrap();
    assert_eq!(profile_resp.status(), StatusCode::OK);
    let profile_bytes = profile_resp.bytes().await.unwrap();

    let triples =
        SemanticGraphStore::parse_rdf_triples(&profile_bytes, RdfFormat::Turtle, profile_doc_url)
            .unwrap();
    let discovered_storage = triples
        .iter()
        .find_map(|t| {
            if matches!(&t.subject, NamedOrBlankNode::NamedNode(s) if s.as_str() == carol_webid)
                && t.predicate.as_str() == PIM_STORAGE_REL
                && let Term::NamedNode(obj) = &t.object
            {
                return Some(obj.as_str().to_string());
            }
            None
        })
        .expect("discover pim:storage from WebID profile");
    assert_eq!(discovered_storage, format!("{server_origin}/pods/carol/"));

    // 3. Authenticate Carol with Solid-OIDC DPoP (dereferencing her own Wolin WebID card!)
    let carol_dpop = DpopClientKey::generate();
    let carol_token = mint_solid_oidc_dpop_token(
        LOCAL_WOLIN_ISSUER,
        &carol_webid,
        &carol_dpop.jkt,
        json!("solid"),
        TEST_NOW + 600,
    );

    // HEAD storage root -> verify `pim:Storage` and `ldp:BasicContainer` Link headers
    let head_proof = carol_dpop.sign_dpop_proof(
        "HEAD",
        &discovered_storage,
        "jti-carol-head-root",
        TEST_NOW,
        Some(&carol_token),
    );
    let head_root = http
        .head(&discovered_storage)
        .header("Authorization", format!("DPoP {carol_token}"))
        .header("DPoP", head_proof)
        .send()
        .await
        .unwrap();
    assert_eq!(head_root.status(), StatusCode::OK);
    let root_link = head_root
        .headers()
        .get("link")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(root_link.contains(&format!("<{PIM_STORAGE}>; rel=\"type\"")));
    assert!(root_link.contains(&format!("<{LDP_BASIC_CONTAINER}>; rel=\"type\"")));

    // 4. Simulate `saveSolidDatasetAt`: PUT dataset into `{discovered_storage}private/contacts.ttl`
    let dataset_url = format!("{discovered_storage}private/contacts.ttl");
    let put_proof = carol_dpop.sign_dpop_proof(
        "PUT",
        &dataset_url,
        "jti-carol-put-contacts",
        TEST_NOW,
        Some(&carol_token),
    );
    let put_ds = http
        .put(&dataset_url)
        .header("Authorization", format!("DPoP {carol_token}"))
        .header("DPoP", put_proof)
        .header("Content-Type", "text/turtle")
        .header("If-None-Match", "*")
        .body(
            "@prefix vcard: <http://www.w3.org/2006/vcard/ns#> .\n\
             <#ada> a vcard:Individual ; vcard:fn \"Ada Lovelace\" .\n",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(put_ds.status(), StatusCode::CREATED);
    let etag_v1 = put_ds
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // 5. Simulate `saveSolidDatasetAt` incremental update via SPARQL-Update PATCH with `If-Match`
    let patch_proof = carol_dpop.sign_dpop_proof(
        "PATCH",
        &dataset_url,
        "jti-carol-patch-contacts",
        TEST_NOW,
        Some(&carol_token),
    );
    let patch_ds = http
        .patch(&dataset_url)
        .header("Authorization", format!("DPoP {carol_token}"))
        .header("DPoP", patch_proof)
        .header("Content-Type", "application/sparql-update")
        .header("If-Match", &etag_v1)
        .body("INSERT DATA { <#grace> <http://www.w3.org/2006/vcard/ns#fn> \"Grace Hopper\" . }")
        .send()
        .await
        .unwrap();
    assert_eq!(patch_ds.status(), StatusCode::NO_CONTENT);

    // 6. Simulate `getSolidDataset`: read back dataset and verify both Things exist
    let get_proof = carol_dpop.sign_dpop_proof(
        "GET",
        &dataset_url,
        "jti-carol-get-contacts",
        TEST_NOW,
        Some(&carol_token),
    );
    let get_ds = http
        .get(&dataset_url)
        .header("Authorization", format!("DPoP {carol_token}"))
        .header("DPoP", get_proof)
        .header("Accept", "text/turtle")
        .send()
        .await
        .unwrap();
    assert_eq!(get_ds.status(), StatusCode::OK);
    let ds_text = get_ds.text().await.unwrap();
    assert!(ds_text.contains("Ada Lovelace"));
    assert!(ds_text.contains("Grace Hopper"));

    let _ = tx.send(());
}

#[tokio::test]
async fn multi_tenant_subdomain_host_routing_and_cross_pod_isolation() {
    let base_url = "http://pod.wolin.cloud";
    let config = LdpConfig::new(base_url, "wolin://pod")
        .with_oidc_options(OidcValidationOptions::new(LOCAL_WOLIN_ISSUER).with_now(TEST_NOW))
        .with_pod_cloud_domain("wolin.cloud")
        .with_policy_clock(TEST_NOW);

    let state = AppState::new_in_memory(PolicyEngine::new(), config)
        .await
        .unwrap();
    let app = build_router(state);

    let alice_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"; // gitleaks:allow
    let bob_did = "did:nostr:7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";

    for (pod_id, owner, name) in [
        ("alice", alice_did, "Alice Cloud"),
        ("bob", bob_did, "Bob Cloud"),
    ] {
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/pods")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "pod_id": pod_id,
                            "owner_webid": owner,
                            "display_name": name
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
    }

    // 1. Subdomain GET `Host: alice.wolin.cloud` `/profile/card` -> rebases `pim:storage` to `http://alice.wolin.cloud/`
    let sub_card = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/profile/card")
                .header(header::HOST, "alice.wolin.cloud")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sub_card.status(), StatusCode::OK);
    let sub_link = sub_card
        .headers()
        .get(header::LINK)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(sub_link.contains("<http://alice.wolin.cloud/profile/card.acl>; rel=\"acl\""));
    assert!(sub_link.contains(&format!(
        "<http://alice.wolin.cloud/>; rel=\"{PIM_STORAGE_REL}\""
    )));

    let sub_card_bytes = to_bytes(sub_card.into_body(), 65_536).await.unwrap();
    let sub_triples = SemanticGraphStore::parse_rdf_triples(
        &sub_card_bytes,
        RdfFormat::Turtle,
        "http://alice.wolin.cloud/profile/card",
    )
    .unwrap();
    let sub_me = NamedNode::new("http://alice.wolin.cloud/profile/card#me").unwrap();
    assert!(sub_triples.iter().any(|t| {
        t.subject == NamedOrBlankNode::NamedNode(sub_me.clone())
            && t.predicate.as_str() == PIM_STORAGE_REL
            && matches!(&t.object, Term::NamedNode(o) if o.as_str() == "http://alice.wolin.cloud/")
    }));

    // 2. Write via subdomain `Host: alice.wolin.cloud` `PUT /private/notes.ttl`
    let sub_put = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/private/notes.ttl")
                .header(header::HOST, "alice.wolin.cloud")
                .header(header::AUTHORIZATION, format!("DID {alice_did}"))
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<#n1> <http://purl.org/dc/terms/title> \"Subdomain Written Note\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sub_put.status(), StatusCode::CREATED);
    assert_eq!(
        sub_put.headers().get(header::LOCATION).unwrap(),
        "http://alice.wolin.cloud/private/notes.ttl"
    );

    // 3. Read same resource via path-based routing `Host: pod.wolin.cloud` `/pods/alice/private/notes.ttl` -> 200 OK!
    let path_get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/pods/alice/private/notes.ttl")
                .header(header::HOST, "pod.wolin.cloud")
                .header(header::AUTHORIZATION, format!("DID {alice_did}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(path_get.status(), StatusCode::OK);
    let path_ttl = String::from_utf8(
        to_bytes(path_get.into_body(), 65_536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(path_ttl.contains("Subdomain Written Note"));

    // 4. Cross-tenant isolation:
    //    - Bob on `Host: bob.wolin.cloud` `/private/notes.ttl` -> 404 Not Found
    //    - Bob on `Host: alice.wolin.cloud` `/private/notes.ttl` -> 403 Forbidden
    let bob_own_sub = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/private/notes.ttl")
                .header(header::HOST, "bob.wolin.cloud")
                .header(header::AUTHORIZATION, format!("DID {bob_did}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_own_sub.status(), StatusCode::NOT_FOUND);

    let bob_cross_tenant = app
        .oneshot(
            Request::builder()
                .uri("/private/notes.ttl")
                .header(header::HOST, "alice.wolin.cloud")
                .header(header::AUTHORIZATION, format!("DID {bob_did}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_cross_tenant.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn concurrent_pod_provisioning_race_and_persistent_restart_rehydration() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::Barrier;

    static SEQ: AtomicU64 = AtomicU64::new(0);
    let idx = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "wolin_pod_cloud_persist_{}_{nanos}_{idx}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let base_url = "http://pod.wolin.cloud";
    let make_cfg = || {
        LdpConfig::new(base_url, "wolin://pod")
            .with_oidc_options(OidcValidationOptions::new(LOCAL_WOLIN_ISSUER).with_now(TEST_NOW))
            .with_pod_cloud_domain("wolin.cloud")
            .with_policy_clock(TEST_NOW)
    };

    let owner_a = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"; // gitleaks:allow
    let owner_b = "did:nostr:7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";

    {
        let state = AppState::new_persistent(&dir, PolicyEngine::new(), make_cfg())
            .await
            .unwrap();
        let app = build_router(state);
        let barrier = Arc::new(Barrier::new(2));

        let app1 = app.clone();
        let b1 = barrier.clone();
        let t1 = tokio::spawn(async move {
            b1.wait().await;
            app1.oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/pods")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "pod_id": "racepod",
                            "owner_webid": owner_a,
                            "display_name": "Winner A"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        });

        let app2 = app.clone();
        let b2 = barrier.clone();
        let t2 = tokio::spawn(async move {
            b2.wait().await;
            app2.oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/pods")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "pod_id": "racepod",
                            "owner_webid": owner_b,
                            "display_name": "Contender B"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        });

        let (s1, s2) = tokio::join!(t1, t2);
        let mut statuses = vec![s1.unwrap(), s2.unwrap()];
        statuses.sort_by_key(|s| s.as_u16());
        assert_eq!(statuses, vec![StatusCode::CREATED, StatusCode::CONFLICT]);

        // Also provision deterministic `persistpod` owned by `owner_a` and write a private dataset
        let p_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/pods")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "pod_id": "persistpod",
                            "owner_webid": owner_a,
                            "display_name": "Persistent Pod"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(p_resp.status(), StatusCode::CREATED);

        let put_priv = app
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/private/vault.ttl")
                    .header(header::HOST, "persistpod.wolin.cloud")
                    .header(header::AUTHORIZATION, format!("DID {owner_a}"))
                    .header(header::CONTENT_TYPE, "text/turtle")
                    .body(Body::from(
                        "<#k> <http://purl.org/dc/terms/title> \"Survived Restart\" .",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_priv.status(), StatusCode::CREATED);
    }

    // Reopen fresh AppState from disk and verify seeded `.acl` rules + data rehydrate cleanly!
    {
        let reopened = AppState::new_persistent(&dir, PolicyEngine::new(), make_cfg())
            .await
            .unwrap();
        let app = build_router(reopened);

        let info_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/pods/persistpod")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(info_resp.status(), StatusCode::OK);

        let stranger_get = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/private/vault.ttl")
                    .header(header::HOST, "persistpod.wolin.cloud")
                    .header(header::AUTHORIZATION, format!("DID {owner_b}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stranger_get.status(), StatusCode::FORBIDDEN);

        let owner_get = app
            .oneshot(
                Request::builder()
                    .uri("/private/vault.ttl")
                    .header(header::HOST, "persistpod.wolin.cloud")
                    .header(header::AUTHORIZATION, format!("DID {owner_a}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(owner_get.status(), StatusCode::OK);
    }

    let _ = std::fs::remove_dir_all(&dir);
}
