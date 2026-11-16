use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use serde_json::json;
use tower::ServiceExt;
use wolin_core::{ResourceUri, WebId};
use wolin_identity::OidcValidationOptions;
use wolin_policy::{AccessMode, AcpPolicy, PolicyEngine, SubjectMatcher};
use wolin_server::{
    AppState, DEFAULT_ASSET_OFFLOAD_MIN_BYTES, LdpConfig,
    assets::{sign_asset_token, verify_asset_token},
    build_router,
};

const BASE_URL: &str = "https://pod.wolin.id";
const ASSET_PUBLIC_BASE_URL: &str = "https://auth.wolin.id/assets";
const ASSET_SECRET: &str = "wolin-test-shared-hmac-secret-2026";
const POD_PREFIX: &str = "wolin://pod";
const POD_CLOUD_DOMAIN: &str = "wolin.id";
const TEST_ISSUER: &str = "https://auth.wolin.id";
const TEST_NOW: i64 = 1_763_500_000;

const ALICE_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"; // gitleaks:allow
const BOB_DID: &str = "did:nostr:7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";

fn alice_auth() -> String {
    format!("DID {ALICE_DID}")
}

fn bob_auth() -> String {
    format!("DID {BOB_DID}")
}

async fn setup_pod_cloud_with_offload() -> (Router, Arc<AppState>) {
    let config = LdpConfig::new(BASE_URL, POD_PREFIX)
        .with_pod_cloud_domain(POD_CLOUD_DOMAIN)
        .with_oidc_options(OidcValidationOptions::new(TEST_ISSUER).with_now(TEST_NOW))
        .with_policy_clock(TEST_NOW)
        .with_asset_signing_secret(ASSET_SECRET)
        .with_asset_public_base_url(ASSET_PUBLIC_BASE_URL)
        .with_asset_offload_min_bytes(DEFAULT_ASSET_OFFLOAD_MIN_BYTES);

    let state = AppState::new_in_memory(PolicyEngine::new(), config)
        .await
        .expect("in-memory AppState");
    let app = build_router(state.clone());

    let prov = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/pods")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "pod_id": "alice",
                        "owner_webid": ALICE_DID,
                        "display_name": "Alice"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(prov.status(), StatusCode::CREATED);

    (app, state)
}

#[tokio::test]
async fn wac_and_acp_denials_return_403_and_never_leak_signed_asset_urls() {
    let (app, state) = setup_pod_cloud_with_offload().await;

    let large_payload = vec![0xAB_u8; DEFAULT_ASSET_OFFLOAD_MIN_BYTES as usize + 1024];

    // Alice uploads a large private binary blob under /pods/alice/private/vault.bin
    let put_priv = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/private/vault.bin")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(large_payload.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_priv.status(), StatusCode::CREATED);

    // 1. WAC denial: Bob requests private large blob (both plain GET and ?download=signed) -> 403, no Location
    for uri in [
        "/pods/alice/private/vault.bin",
        "/pods/alice/private/vault.bin?download=signed",
    ] {
        let bob_get = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .header(header::AUTHORIZATION, bob_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bob_get.status(), StatusCode::FORBIDDEN);
        assert!(
            bob_get.headers().get(header::LOCATION).is_none(),
            "403 response must never leak signed Location header for {uri}"
        );
        let err_body =
            String::from_utf8(to_bytes(bob_get.into_body(), 8192).await.unwrap().to_vec()).unwrap();
        assert!(!err_body.contains("sig="));
    }

    // Anonymous caller -> 401 Unauthorized, no Location
    let anon_get = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/pods/alice/private/vault.bin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anon_get.status(), StatusCode::UNAUTHORIZED);
    assert!(anon_get.headers().get(header::LOCATION).is_none());

    // 2. Explicit ACP deny overrides WAC Public Read -> 403 Forbidden, no Location
    let put_pub = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/public/restricted-video.mp4")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "video/mp4")
                .body(Body::from(large_payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_pub.status(), StatusCode::CREATED);

    state.with_policy_mut(|engine| {
        engine.add_acp_policy(AcpPolicy {
            id: "acp-deny-bob-video".to_string(),
            targets: vec![ResourceUri(
                "wolin://pod/pods/alice/public/restricted-video.mp4".to_string(),
            )],
            inherited_containers: Vec::new(),
            all_of: Vec::new(),
            any_of: vec![SubjectMatcher::WebId(WebId(BOB_DID.to_string()))],
            none_of: Vec::new(),
            allow: Vec::new(),
            deny: vec![AccessMode::Read],
        });
    });

    let bob_acp_denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/pods/alice/public/restricted-video.mp4")
                .header(header::AUTHORIZATION, bob_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_acp_denied.status(), StatusCode::FORBIDDEN);
    assert!(bob_acp_denied.headers().get(header::LOCATION).is_none());
}

#[tokio::test]
async fn authorized_large_blob_returns_302_signed_url_while_small_and_rdf_serve_200_directly() {
    let (app, state) = setup_pod_cloud_with_offload().await;

    // 1. Upload large binary blob (exactly 256 KiB threshold)
    let large_bytes = vec![0x5A_u8; DEFAULT_ASSET_OFFLOAD_MIN_BYTES as usize];
    let put_large = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/private/dataset.tar.zst")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "application/zstd")
                .body(Body::from(large_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_large.status(), StatusCode::CREATED);
    let large_etag = put_large
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Authorized GET on large blob -> 302 Found with valid 60s exp + HMAC-SHA256 sig
    let get_large = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/pods/alice/private/dataset.tar.zst")
                .header(header::AUTHORIZATION, alice_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_large.status(), StatusCode::FOUND);
    assert_eq!(
        get_large.headers().get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    assert_eq!(
        get_large.headers().get(header::ETAG).unwrap(),
        large_etag.as_str()
    );

    let location = get_large
        .headers()
        .get(header::LOCATION)
        .expect("302 Location header")
        .to_str()
        .unwrap()
        .to_string();
    let expected_exp = TEST_NOW + 60;
    let expected_sig = sign_asset_token(
        ASSET_SECRET,
        "GET",
        "alice",
        "/private/dataset.tar.zst",
        expected_exp,
    );
    assert_eq!(
        location,
        format!(
            "https://auth.wolin.id/assets/alice/private/dataset.tar.zst?exp={expected_exp}&sig={expected_sig}"
        )
    );
    assert!(verify_asset_token(
        ASSET_SECRET,
        "GET",
        "alice",
        "/private/dataset.tar.zst",
        expected_exp,
        &expected_sig
    ));
    let redirect_body = to_bytes(get_large.into_body(), 1024).await.unwrap();
    assert!(redirect_body.is_empty(), "302 body must be empty");

    // Subdomain routing (`Host: alice.wolin.id` GET `/private/dataset.tar.zst`) mints the exact same signed URL
    let sub_get = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/private/dataset.tar.zst")
                .header(header::HOST, "alice.wolin.id")
                .header(header::AUTHORIZATION, alice_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sub_get.status(), StatusCode::FOUND);
    assert_eq!(
        sub_get.headers().get(header::LOCATION).unwrap(),
        location.as_str()
    );

    // HEAD on large blob still returns 200 OK metadata without 302 redirect, and If-None-Match returns 304
    let head_large = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri("/pods/alice/private/dataset.tar.zst")
                .header(header::AUTHORIZATION, alice_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(head_large.status(), StatusCode::OK);
    assert!(head_large.headers().get(header::LOCATION).is_none());

    let inm_large = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/pods/alice/private/dataset.tar.zst")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::IF_NONE_MATCH, &large_etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inm_large.status(), StatusCode::NOT_MODIFIED);

    // 2. Small binary blob (< 256 KiB) serves directly 200 OK by default, and 302s when ?download=signed is passed
    let small_bytes = b"small-avatar-png-bytes".to_vec();
    let put_small = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/public/avatar.png")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "image/png")
                .body(Body::from(small_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_small.status(), StatusCode::CREATED);

    let get_small = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/pods/alice/public/avatar.png")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_small.status(), StatusCode::OK);
    assert!(get_small.headers().get(header::LOCATION).is_none());
    let served_small = to_bytes(get_small.into_body(), 4096).await.unwrap();
    assert_eq!(served_small.as_ref(), small_bytes.as_slice());

    // Explicit ?download=signed on small binary blob triggers 302 signed URL offload
    let get_small_signed = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/pods/alice/public/avatar.png?download=signed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_small_signed.status(), StatusCode::FOUND);
    assert_eq!(
        get_small_signed
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap(),
        "private, no-store"
    );
    let small_sig = sign_asset_token(
        ASSET_SECRET,
        "GET",
        "alice",
        "/public/avatar.png",
        expected_exp,
    );
    assert_eq!(
        get_small_signed
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
        format!(
            "https://auth.wolin.id/assets/alice/public/avatar.png?exp={expected_exp}&sig={small_sig}"
        )
    );

    // Non-GET with ?download=signed or unknown query params must still fail closed with 400 Bad Request
    let put_query_rejected = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/public/avatar.png?download=signed")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "image/png")
                .body(Body::from(b"bad".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_query_rejected.status(), StatusCode::BAD_REQUEST);

    // 3. RDF resources (RdfSource and Container) ALWAYS serve directly 200 OK (even with ?download=signed or large RDF)
    let mut big_turtle = String::with_capacity(300_000);
    for idx in 0..4500 {
        big_turtle.push_str(&format!(
            "<#item-{idx}> <http://purl.org/dc/terms/title> \"Structured RDF Entry Number {idx:05}\" .\n"
        ));
    }
    assert!(big_turtle.len() as u64 > DEFAULT_ASSET_OFFLOAD_MIN_BYTES);

    let put_rdf = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/public/graph.ttl")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(big_turtle))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_rdf.status(), StatusCode::CREATED);

    for rdf_uri in [
        "/pods/alice/public/graph.ttl",
        "/pods/alice/public/graph.ttl?download=signed",
        "/pods/alice/profile/card",
        "/pods/alice/public/",
    ] {
        let get_rdf = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(rdf_uri)
                    .header(header::ACCEPT, "text/turtle")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            get_rdf.status(),
            StatusCode::OK,
            "RDF resource {rdf_uri} must serve 200 directly"
        );
        assert!(get_rdf.headers().get(header::LOCATION).is_none());
    }

    // 4. Retiring / tombstoning the Pod purges WAC governance and blocks signed URL minting with 403 Forbidden
    state
        .retire_pod("alice", "account_deleted", TEST_NOW + 5)
        .await
        .expect("retire alice pod");

    let get_retired = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/pods/alice/private/dataset.tar.zst")
                .header(header::AUTHORIZATION, alice_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_retired.status(), StatusCode::FORBIDDEN);
    assert!(get_retired.headers().get(header::LOCATION).is_none());
}
