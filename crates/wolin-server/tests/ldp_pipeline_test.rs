use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    Router,
};
use serde_json::json;
use tower::ServiceExt;
use wolin_core::{ResourceUri, WebId};
use wolin_identity::{JwtSignatureVerifier, OidcValidationOptions};
use wolin_policy::{AccessMode, AcpPolicy, DelegationGrant, PolicyEngine, SubjectMatcher, WacRule};
use wolin_server::{
    build_router,
    ldp::{LDP_BASIC_CONTAINER, LDP_NON_RDF_SOURCE, LDP_RDF_SOURCE, LDP_RESOURCE},
    AppState, LdpConfig,
};
use wolin_storage::{PhysicalStore, SemanticGraphStore};

const BASE_URL: &str = "http://pod.wolin.local";
const POD_PREFIX: &str = "wolin://pod";
const TEST_ISSUER: &str = "https://auth.zitadel.acme.corp";
const TEST_NOW: i64 = 1_763_000_000;

const ALICE_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"; // gitleaks:allow
const BOB_DID: &str = "did:nostr:7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(label: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let idx = SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "wolin_ldp_test_{label}_{}_{nanos}_{idx}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp test dir");
        Self { path }
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

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

fn build_jwt(
    header_json: serde_json::Value,
    payload_json: serde_json::Value,
    sig: &[u8],
) -> String {
    format!(
        "{}.{}.{}",
        b64url(header_json.to_string().as_bytes()),
        b64url(payload_json.to_string().as_bytes()),
        b64url(sig)
    )
}

async fn setup_alice_pod() -> (Router, Arc<AppState>) {
    let mut engine = PolicyEngine::new();
    engine.add_wac_rule(WacRule {
        id: "alice-owner-all".to_string(),
        access_to: vec![ResourceUri("wolin://pod/alice".to_string())],
        default_for: vec![ResourceUri("wolin://pod/alice/".to_string())],
        subjects: vec![SubjectMatcher::WebId(WebId(ALICE_DID.to_string()))],
        modes: vec![
            AccessMode::Read,
            AccessMode::Write,
            AccessMode::Append,
            AccessMode::Control,
        ],
    });
    engine.add_wac_rule(WacRule {
        id: "public-read".to_string(),
        access_to: vec![ResourceUri("wolin://pod/public".to_string())],
        default_for: vec![ResourceUri("wolin://pod/public/".to_string())],
        subjects: vec![SubjectMatcher::Public],
        modes: vec![AccessMode::Read],
    });

    let config = LdpConfig::new(BASE_URL, POD_PREFIX)
        .with_oidc_options(
            OidcValidationOptions::new(TEST_ISSUER)
                .with_audience("wolin-ldp")
                .with_now(TEST_NOW),
        )
        .with_policy_clock(TEST_NOW);

    let state = AppState::new_in_memory(engine, config)
        .await
        .expect("in-memory AppState");
    let app = build_router(state.clone());
    (app, state)
}

fn alice_auth() -> String {
    format!("DID {ALICE_DID}")
}

fn bob_auth() -> String {
    format!("DID {BOB_DID}")
}

#[tokio::test]
async fn system_discovery_and_health_endpoints() {
    let (app, _state) = setup_alice_pod().await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(resp.into_body(), 65_536).await.unwrap()).unwrap();
    assert_eq!(body["status"], "healthy");

    let wk = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/wolin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wk.status(), StatusCode::OK);
    let wk_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(wk.into_body(), 65_536).await.unwrap()).unwrap();
    assert_eq!(wk_json["storage_backend"], "opendal+oxigraph");

    // Mutating /health must fail with 405 Method Not Allowed
    let del_health = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_health.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn ldp_container_lifecycle_hierarchy_and_headers() {
    let (app, _state) = setup_alice_pod().await;

    // 1. PUT /alice/ container
    let put_alice = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/alice/")
                .header(header::AUTHORIZATION, alice_auth())
                .header(
                    header::LINK,
                    format!("<{LDP_BASIC_CONTAINER}>; rel=\"type\""),
                )
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<> <http://purl.org/dc/terms/title> \"Alice Sovereign Pod\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_alice.status(), StatusCode::CREATED);
    assert_eq!(
        put_alice.headers().get(header::LOCATION).unwrap(),
        "http://pod.wolin.local/alice/"
    );
    let link_hdr = put_alice
        .headers()
        .get(header::LINK)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(link_hdr.contains(&format!("<{LDP_BASIC_CONTAINER}>; rel=\"type\"")));
    assert!(link_hdr.contains(&format!("<{LDP_RESOURCE}>; rel=\"type\"")));
    assert!(link_hdr.contains("<http://pod.wolin.local/alice/.acl>; rel=\"acl\""));
    assert!(put_alice.headers().contains_key("wac-allow"));
    assert!(put_alice.headers().contains_key("accept-post"));

    // 2. POST child BasicContainer `docs` inside `/alice/`
    let post_docs = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/alice/")
                .header(header::AUTHORIZATION, alice_auth())
                .header("Slug", "docs")
                .header(
                    header::LINK,
                    format!("<{LDP_BASIC_CONTAINER}>; rel=\"type\""),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post_docs.status(), StatusCode::CREATED);
    assert_eq!(
        post_docs.headers().get(header::LOCATION).unwrap(),
        "http://pod.wolin.local/alice/docs/"
    );

    // 3. POST direct RDF resource inside `/alice/` and grandchild inside `/alice/docs/`
    let post_readme = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/alice/")
                .header(header::AUTHORIZATION, alice_auth())
                .header("Slug", "readme.ttl")
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<#doc> <http://purl.org/dc/terms/title> \"Pod Root Readme\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post_readme.status(), StatusCode::CREATED);
    assert_eq!(
        post_readme.headers().get(header::LOCATION).unwrap(),
        "http://pod.wolin.local/alice/readme.ttl"
    );

    // Duplicate POST with identical Slug `readme.ttl` MUST NOT overwrite existing resource
    let post_dup = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/alice/")
                .header(header::AUTHORIZATION, alice_auth())
                .header("Slug", "readme.ttl")
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<#doc> <http://purl.org/dc/terms/title> \"Second Copy\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post_dup.status(), StatusCode::CREATED);
    let dup_loc = post_dup
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(dup_loc, "http://pod.wolin.local/alice/readme.ttl");
    assert!(dup_loc.starts_with("http://pod.wolin.local/alice/readme.ttl-"));

    // Clean up duplicate sibling
    let dup_path = dup_loc.strip_prefix(BASE_URL).unwrap();
    let del_dup = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(dup_path)
                .header(header::AUTHORIZATION, alice_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_dup.status(), StatusCode::NO_CONTENT);

    // Grandchild inside `/alice/docs/`
    let post_grandchild = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/alice/docs/")
                .header(header::AUTHORIZATION, alice_auth())
                .header("Slug", "q4.ttl")
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<#report> <http://purl.org/dc/terms/title> \"Q4 Report\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post_grandchild.status(), StatusCode::CREATED);

    // 4. GET `/alice/` as N-Triples: verify direct children ONLY in `ldp:contains`
    let get_alice = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/alice/")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::ACCEPT, "application/n-triples")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_alice.status(), StatusCode::OK);
    let alice_nt = String::from_utf8(
        to_bytes(get_alice.into_body(), 65_536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(alice_nt.contains("Alice Sovereign Pod"));
    assert!(alice_nt.contains(
        "<http://pod.wolin.local/alice/> <http://www.w3.org/ns/ldp#contains> <http://pod.wolin.local/alice/docs/>"
    ));
    assert!(alice_nt.contains(
        "<http://pod.wolin.local/alice/> <http://www.w3.org/ns/ldp#contains> <http://pod.wolin.local/alice/readme.ttl>"
    ));
    assert!(
        !alice_nt.contains("q4.ttl"),
        "grandchild must not appear directly in parent container ldp:contains"
    );

    // 5. Client attempting to spoof server-managed `ldp:contains` -> 409 Conflict
    let spoof_contains = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/alice/docs/")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<> <http://www.w3.org/ns/ldp#contains> <http://evil.example/fake> .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(spoof_contains.status(), StatusCode::CONFLICT);

    // 6. Slash hierarchy conflict: PUT `/alice/docs` (leaf) when `/alice/docs/` container exists -> 409
    let slash_conflict = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/alice/docs")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<> <http://purl.org/dc/terms/title> \"Bad\" ."))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(slash_conflict.status(), StatusCode::CONFLICT);

    // 7. Non-empty container DELETE `/alice/docs/` -> 409 Conflict; after deleting child -> 204 No Content
    let del_nonempty = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/alice/docs/")
                .header(header::AUTHORIZATION, alice_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_nonempty.status(), StatusCode::CONFLICT);

    let del_child = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/alice/docs/q4.ttl")
                .header(header::AUTHORIZATION, alice_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_child.status(), StatusCode::NO_CONTENT);

    let get_deleted = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/alice/docs/q4.ttl")
                .header(header::AUTHORIZATION, alice_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_deleted.status(), StatusCode::NOT_FOUND);

    let del_empty_docs = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/alice/docs/")
                .header(header::AUTHORIZATION, alice_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_empty_docs.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn rdf_content_negotiation_and_etag_preconditions() {
    let (app, _state) = setup_alice_pod().await;

    // 1. PUT RDF resource as JSON-LD (`application/ld+json`)
    let jsonld_payload = json!({
        "@context": {
            "foaf": "http://xmlns.com/foaf/0.1/"
        },
        "@id": "#me",
        "@type": "foaf:Person",
        "foaf:name": "Alice"
    });

    let put_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/alice/profile")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "application/ld+json")
                .body(Body::from(jsonld_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_resp.status(), StatusCode::CREATED);
    let link = put_resp
        .headers()
        .get(header::LINK)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(link.contains(&format!("<{LDP_RDF_SOURCE}>; rel=\"type\"")));
    let etag_v1 = put_resp
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // 2. GET with default Accept (Turtle)
    let get_ttl = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/alice/profile")
                .header(header::AUTHORIZATION, alice_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_ttl.status(), StatusCode::OK);
    assert_eq!(
        get_ttl.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/turtle"
    );
    let ttl_str = String::from_utf8(
        to_bytes(get_ttl.into_body(), 65_536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(ttl_str.contains("Alice"));
    assert!(ttl_str.contains("http://xmlns.com/foaf/0.1/Person"));

    // 3. GET with weighted Accept preferring `application/n-triples`
    let get_nt = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/alice/profile")
                .header(header::AUTHORIZATION, alice_auth())
                .header(
                    header::ACCEPT,
                    "text/turtle;q=0.5, application/n-triples;q=0.9, application/ld+json;q=0.8",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_nt.status(), StatusCode::OK);
    assert_eq!(
        get_nt.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/n-triples"
    );
    let nt_str =
        String::from_utf8(to_bytes(get_nt.into_body(), 65_536).await.unwrap().to_vec()).unwrap();
    assert!(nt_str.contains(
        "<http://pod.wolin.local/alice/profile#me> <http://xmlns.com/foaf/0.1/name> \"Alice\""
    ));

    // 4. GET with `text/turtle;q=0, application/ld+json;q=1.0` -> JSON-LD
    let get_jsonld = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/alice/profile")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::ACCEPT, "text/turtle;q=0, application/ld+json;q=1.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_jsonld.status(), StatusCode::OK);
    assert_eq!(
        get_jsonld.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/ld+json"
    );
    let parsed_jsonld: serde_json::Value =
        serde_json::from_slice(&to_bytes(get_jsonld.into_body(), 65_536).await.unwrap()).unwrap();
    assert!(parsed_jsonld.is_array());
    assert!(parsed_jsonld.to_string().contains("Alice"));

    // 5. Unsupported Accept `image/png` -> 406 Not Acceptable
    let get_406 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/alice/profile")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::ACCEPT, "image/png")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_406.status(), StatusCode::NOT_ACCEPTABLE);

    // 6. Malformed Turtle PUT -> 400 Bad Request AND preserves existing profile intact
    let bad_put = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/alice/profile")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("@prefix broken <unclosed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_put.status(), StatusCode::BAD_REQUEST);

    // HEAD + If-None-Match + If-Match preconditions
    let head_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri("/alice/profile")
                .header(header::AUTHORIZATION, alice_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(head_resp.status(), StatusCode::OK);
    assert_eq!(
        head_resp.headers().get(header::ETAG).unwrap(),
        etag_v1.as_str()
    );
    assert!(to_bytes(head_resp.into_body(), 65_536)
        .await
        .unwrap()
        .is_empty());

    let not_mod = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/alice/profile")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::IF_NONE_MATCH, &etag_v1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(not_mod.status(), StatusCode::NOT_MODIFIED);

    // If-None-Match: * on existing resource PUT -> 412 Precondition Failed
    let put_if_none = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/alice/profile")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::IF_NONE_MATCH, "*")
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<#me> <http://xmlns.com/foaf/0.1/name> \"Overwrite\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_if_none.status(), StatusCode::PRECONDITION_FAILED);

    // Stale If-Match on PUT -> 412 Precondition Failed
    let put_stale = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/alice/profile")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::IF_MATCH, "\"stale-etag\"")
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<#me> <http://xmlns.com/foaf/0.1/name> \"Overwrite\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_stale.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn non_rdf_binary_octet_stream_crud_and_limits() {
    let mut engine = PolicyEngine::new();
    engine.add_wac_rule(WacRule {
        id: "alice-owner".to_string(),
        access_to: vec![],
        default_for: vec![ResourceUri("wolin://pod/alice/".to_string())],
        subjects: vec![SubjectMatcher::WebId(WebId(ALICE_DID.to_string()))],
        modes: vec![AccessMode::Read, AccessMode::Write],
    });
    let config = LdpConfig::new(BASE_URL, POD_PREFIX).with_max_body_bytes(128);
    let state = AppState::new_in_memory(engine, config).await.unwrap();
    let app = build_router(state);

    let binary_payload: Vec<u8> = vec![0x00, 0xFF, 0x13, 0x37, 0x80, 0xFE, 0x42];

    // PUT binary blob (`application/octet-stream`)
    let put_bin = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/alice/media/key.bin")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(binary_payload.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_bin.status(), StatusCode::CREATED);
    let link = put_bin
        .headers()
        .get(header::LINK)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(link.contains(&format!("<{LDP_NON_RDF_SOURCE}>; rel=\"type\"")));

    // GET binary blob with `Accept: application/octet-stream`
    let get_bin = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/alice/media/key.bin")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::ACCEPT, "application/octet-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_bin.status(), StatusCode::OK);
    assert_eq!(
        get_bin.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
    let fetched = to_bytes(get_bin.into_body(), 1024).await.unwrap().to_vec();
    assert_eq!(fetched, binary_payload);

    // Incompatible Accept `text/turtle` on binary NonRDFSource -> 406 Not Acceptable
    let get_406 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/alice/media/key.bin")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::ACCEPT, "text/turtle")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_406.status(), StatusCode::NOT_ACCEPTABLE);

    // SPARQL-Update PATCH on NonRDFSource -> 409 Conflict
    let patch_bin = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/alice/media/key.bin")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "application/sparql-update")
                .body(Body::from(
                    "INSERT DATA { <http://example.org/s> <http://example.org/p> \"v\" . }",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(patch_bin.status(), StatusCode::CONFLICT);

    // Oversized payload (> 128 bytes) -> 413 Payload Too Large
    let oversized = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/alice/media/huge.bin")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(vec![0xABu8; 256]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn sparql_update_patch_modes_and_graph_isolation() {
    let (app, state) = setup_alice_pod().await;

    // Grant Bob Append-only access on `/alice/inbox/` and `/alice/inbox/feed.ttl`
    state.with_policy_mut(|engine| {
        engine.add_wac_rule(WacRule {
            id: "bob-append-inbox".to_string(),
            access_to: vec![ResourceUri("wolin://pod/alice/inbox".to_string())],
            default_for: vec![ResourceUri("wolin://pod/alice/inbox/".to_string())],
            subjects: vec![SubjectMatcher::WebId(WebId(BOB_DID.to_string()))],
            modes: vec![AccessMode::Append],
        });
    });

    // Seed `/alice/inbox/feed.ttl` and `/alice/vault.ttl` as Alice
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/alice/vault.ttl")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#secret> <https://wolin.io/ns#pin> \"9999\" ."))
                .unwrap(),
        )
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/alice/inbox/feed.ttl")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<#entry1> <http://purl.org/dc/terms/title> \"Initial Entry\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // 1. Wrong PATCH Content-Type -> 415 Unsupported Media Type
    let wrong_ct = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/alice/inbox/feed.ttl")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("INSERT DATA { <#x> <#y> \"z\" . }"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_ct.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // 2. Append-only Bob CAN execute pure `INSERT DATA` (including literal containing "GRAPH <...>")
    let bob_insert = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/alice/inbox/feed.ttl")
                .header(header::AUTHORIZATION, bob_auth())
                .header(header::CONTENT_TYPE, "application/sparql-update")
                .body(Body::from(
                    "INSERT DATA { <#entry2> <http://purl.org/dc/terms/title> \"Appended Note about GRAPH <x>\" . }",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_insert.status(), StatusCode::NO_CONTENT);

    // 3. Append-only Bob CANNOT execute `DELETE DATA` or `DELETE/INSERT WHERE` -> 403 Forbidden BEFORE mutation!
    for forbidden_sparql in [
        "DELETE DATA { <#entry1> <http://purl.org/dc/terms/title> \"Initial Entry\" . }",
        "DELETE { ?s ?p ?o } INSERT { <#pwn> <#k> \"1\" } WHERE { ?s ?p ?o }",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PATCH)
                    .uri("/alice/inbox/feed.ttl")
                    .header(header::AUTHORIZATION, bob_auth())
                    .header(header::CONTENT_TYPE, "application/sparql-update")
                    .body(Body::from(forbidden_sparql))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // 4. Named-graph escape attempt in SPARQL-Update MUST be rejected (400 Bad Request) without touching vault!
    let escape_patch = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/alice/inbox/feed.ttl")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "application/sparql-update")
                .body(Body::from(
                    "INSERT DATA { GRAPH <http://pod.wolin.local/alice/vault.ttl> { <#injected> <https://wolin.io/ns#pin> \"0000\" . } }",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(escape_patch.status(), StatusCode::BAD_REQUEST);

    // 5. Alice (with Read + Write) executes `DELETE/INSERT WHERE` on `/alice/inbox/feed.ttl`
    let alice_modify = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/alice/inbox/feed.ttl")
                .header(header::AUTHORIZATION, alice_auth())
                .header(header::CONTENT_TYPE, "application/sparql-update")
                .body(Body::from(
                    "DELETE { <#entry1> <http://purl.org/dc/terms/title> \"Initial Entry\" } \
                     INSERT { <#entry1> <http://purl.org/dc/terms/title> \"Edited Entry\" } \
                     WHERE { <#entry1> <http://purl.org/dc/terms/title> \"Initial Entry\" }",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(alice_modify.status(), StatusCode::NO_CONTENT);

    // Verify feed.ttl has Edited Entry + Bob's Appended Note, and vault.ttl was NEVER polluted
    let get_feed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/alice/inbox/feed.ttl")
                .header(header::AUTHORIZATION, alice_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let feed_ttl = String::from_utf8(
        to_bytes(get_feed.into_body(), 65_536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(feed_ttl.contains("Edited Entry"));
    assert!(!feed_ttl.contains("Initial Entry"));
    assert!(feed_ttl.contains("Appended Note about GRAPH <x>"));

    let get_vault = app
        .oneshot(
            Request::builder()
                .uri("/alice/vault.ttl")
                .header(header::AUTHORIZATION, alice_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let vault_ttl = String::from_utf8(
        to_bytes(get_vault.into_body(), 65_536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(vault_ttl.contains("9999"));
    assert!(!vault_ttl.contains("0000"));
}

struct StrictEdDsaVerifier;

impl JwtSignatureVerifier for StrictEdDsaVerifier {
    fn verify(
        &self,
        alg: &str,
        _kid: Option<&str>,
        _signing_input: &[u8],
        signature: &[u8],
    ) -> wolin_core::Result<()> {
        if alg == "EdDSA" && signature == b"verified-ed25519-sig" {
            Ok(())
        } else {
            Err(wolin_core::WolinError::Unauthenticated(
                "Invalid JWS signature".to_string(),
            ))
        }
    }
}

#[tokio::test]
async fn wac_acp_oidc_did_and_agent_delegation_enforcement() {
    let alice_webid = WebId("https://alice.acme.corp/profile#me".to_string());
    let agent_did = "did:web:acme.corp:agents:Summarizer";

    let mut engine = PolicyEngine::with_explicit_delegation_required(true);
    engine.add_wac_rule(WacRule {
        id: "alice-eng-owner".to_string(),
        access_to: vec![ResourceUri("wolin://pod/acme/eng".to_string())],
        default_for: vec![ResourceUri("wolin://pod/acme/eng/".to_string())],
        subjects: vec![SubjectMatcher::WebId(alice_webid.clone())],
        modes: vec![
            AccessMode::Read,
            AccessMode::Write,
            AccessMode::Append,
            AccessMode::Control,
        ],
    });
    engine.add_wac_rule(WacRule {
        id: "public-docs-read".to_string(),
        access_to: vec![],
        default_for: vec![ResourceUri("wolin://pod/public/".to_string())],
        subjects: vec![SubjectMatcher::Public],
        modes: vec![AccessMode::Read],
    });
    engine.add_acp_policy(AcpPolicy {
        id: "deny-agent-secrets-and-roadmap".to_string(),
        targets: vec![ResourceUri("wolin://pod/acme/eng/roadmap.ttl".to_string())],
        inherited_containers: vec![ResourceUri("wolin://pod/acme/eng/secrets/".to_string())],
        all_of: vec![],
        any_of: vec![SubjectMatcher::AgentId(agent_did.to_string())],
        none_of: vec![],
        allow: vec![],
        deny: vec![AccessMode::Read, AccessMode::Write, AccessMode::Append],
    });

    let config = LdpConfig::new(BASE_URL, POD_PREFIX)
        .with_oidc_options(
            OidcValidationOptions::new(TEST_ISSUER)
                .with_audience("wolin-ldp")
                .with_now(TEST_NOW),
        )
        .with_jwt_verifier(Arc::new(StrictEdDsaVerifier))
        .with_policy_clock(TEST_NOW);

    let state = AppState::new_in_memory(engine, config).await.unwrap();
    let app = build_router(state.clone());

    let alice_jwt = build_jwt(
        json!({ "alg": "EdDSA" }),
        json!({
            "iss": TEST_ISSUER,
            "sub": "alice-01",
            "webid": alice_webid.0,
            "aud": "wolin-ldp",
            "exp": TEST_NOW + 600,
            "scope": "read write"
        }),
        b"verified-ed25519-sig",
    );

    let agent_jwt = build_jwt(
        json!({ "alg": "EdDSA" }),
        json!({
            "iss": TEST_ISSUER,
            "sub": "alice-01",
            "webid": alice_webid.0,
            "aud": "wolin-ldp",
            "exp": TEST_NOW + 600,
            "scope": "read write append",
            "act": { "sub": agent_did }
        }),
        b"verified-ed25519-sig",
    );

    // 1. Anonymous PUT on private `/acme/eng/spec.ttl` MUST fail with 401 + WWW-Authenticate BEFORE touching storage!
    let anon_put = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/acme/eng/spec.ttl")
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#s> <#p> \"unauth\" ."))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anon_put.status(), StatusCode::UNAUTHORIZED);
    assert!(anon_put.headers().contains_key(header::WWW_AUTHENTICATE));
    assert!(state.graph_store.is_empty().unwrap());

    // 2. Seed `/acme/eng/spec.ttl`, `/acme/eng/secrets/keys.ttl`, and `/public/hello.ttl` as Alice (allow Alice on /public too)
    state.with_policy_mut(|eng| {
        eng.add_wac_rule(WacRule {
            id: "alice-public-write".to_string(),
            access_to: vec![],
            default_for: vec![ResourceUri("wolin://pod/public/".to_string())],
            subjects: vec![SubjectMatcher::WebId(alice_webid.clone())],
            modes: vec![AccessMode::Write],
        });
    });

    for (path, ttl) in [
        (
            "/acme/eng/spec.ttl",
            "<#spec> <http://purl.org/dc/terms/title> \"Architecture\" .",
        ),
        (
            "/acme/eng/secrets/keys.ttl",
            "<#k> <https://wolin.io/ns#secret> \"top-secret\" .",
        ),
        (
            "/public/hello.ttl",
            "<#hi> <http://purl.org/dc/terms/title> \"Public Welcome\" .",
        ),
    ] {
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(path)
                    .header(header::AUTHORIZATION, format!("Bearer {alice_jwt}"))
                    .header(header::CONTENT_TYPE, "text/turtle")
                    .body(Body::from(ttl))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
    }

    // 3. Anonymous CAN GET `/public/hello.ttl`, CANNOT PUT `/public/hello.ttl` (401)
    let pub_get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/public/hello.ttl")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pub_get.status(), StatusCode::OK);

    // Forged signature or `alg: none` JWT on `/public/hello.ttl` MUST return 401 (never downgrade to Anonymous!)
    let forged_jwt = build_jwt(
        json!({ "alg": "EdDSA" }),
        json!({ "iss": TEST_ISSUER, "sub": "alice-01", "aud": "wolin-ldp", "exp": TEST_NOW + 600 }),
        b"bad-sig",
    );
    for bad_auth in [
        format!("Bearer {forged_jwt}"),
        "DID did:key:invalid_0OIl".to_string(),
        "Basic dXNlcjpwYXNz".to_string(),
    ] {
        let bad_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/public/hello.ttl")
                    .header(header::AUTHORIZATION, bad_auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_resp.status(), StatusCode::UNAUTHORIZED);
    }

    // 4. Authenticated Bob (`DID`) denied on Alice's `/acme/eng/spec.ttl` -> 403 Forbidden
    let bob_denied = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/acme/eng/spec.ttl")
                .header(header::AUTHORIZATION, bob_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_denied.status(), StatusCode::FORBIDDEN);

    // 5. Delegated Agent BEFORE DelegationGrant registration -> 403 Forbidden
    let agent_before = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/acme/eng/spec.ttl")
                .header(header::AUTHORIZATION, format!("Bearer {agent_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(agent_before.status(), StatusCode::FORBIDDEN);

    // Register attenuated Read+Append DelegationGrant for `/acme/eng/`
    state.with_policy_mut(|eng| {
        eng.add_delegation_grant(DelegationGrant {
            grant_id: "grant-eng-1".to_string(),
            agent_id: agent_did.to_string(),
            delegated_by: alice_webid.clone(),
            allowed_modes: vec![AccessMode::Read, AccessMode::Append],
            resource_scopes: vec![ResourceUri("wolin://pod/acme/eng/".to_string())],
            expires_at: Some(TEST_NOW + 300),
            revoked: false,
        });
    });

    // Agent CAN Read `/acme/eng/spec.ttl` -> 200 OK
    let agent_read = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/acme/eng/spec.ttl")
                .header(header::AUTHORIZATION, format!("Bearer {agent_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(agent_read.status(), StatusCode::OK);

    // Agent CANNOT PUT/DELETE `/acme/eng/spec.ttl` (grant lacks Write) -> 403 Forbidden
    let agent_put = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/acme/eng/spec.ttl")
                .header(header::AUTHORIZATION, format!("Bearer {agent_jwt}"))
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#x> <#y> \"tamper\" ."))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(agent_put.status(), StatusCode::FORBIDDEN);

    // Agent CANNOT Read `/acme/eng/secrets/keys.ttl` (ACP deny overrides parent grant!) -> 403 Forbidden
    let agent_secret = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/acme/eng/secrets/keys.ttl")
                .header(header::AUTHORIZATION, format!("Bearer {agent_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(agent_secret.status(), StatusCode::FORBIDDEN);

    // Agent CANNOT POST with crafted `Slug: roadmap.ttl` bypassing ACP target deny -> 403 Forbidden
    let agent_slug_bypass = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/acme/eng/")
                .header(header::AUTHORIZATION, format!("Bearer {agent_jwt}"))
                .header("Slug", "roadmap.ttl")
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#r> <#p> \"bypass\" ."))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(agent_slug_bypass.status(), StatusCode::FORBIDDEN);

    // Revoking DelegationGrant immediately blocks subsequent Agent reads -> 403 Forbidden
    state.with_policy_mut(|eng| {
        assert!(eng.revoke_delegation("grant-eng-1"));
    });
    let agent_after_revoke = app
        .oneshot(
            Request::builder()
                .uri("/acme/eng/spec.ttl")
                .header(header::AUTHORIZATION, format!("Bearer {agent_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(agent_after_revoke.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn live_http_wac_acl_governance_persistence_and_adversarial_uri_guards() {
    let blob_dir = TempDirGuard::new("blobs");
    let graph_dir = TempDirGuard::new("graph");

    let mut engine = PolicyEngine::new();
    engine.add_wac_rule(WacRule {
        id: "alice-pod-root".to_string(),
        access_to: vec![ResourceUri("wolin://pod/alice".to_string())],
        default_for: vec![ResourceUri("wolin://pod/alice/".to_string())],
        subjects: vec![SubjectMatcher::WebId(WebId(ALICE_DID.to_string()))],
        modes: vec![
            AccessMode::Read,
            AccessMode::Write,
            AccessMode::Append,
            AccessMode::Control,
        ],
    });
    // Give Bob Write (but NOT Control!) on `/alice/collab/`
    engine.add_wac_rule(WacRule {
        id: "bob-collab-editor".to_string(),
        access_to: vec![ResourceUri("wolin://pod/alice/collab".to_string())],
        default_for: vec![ResourceUri("wolin://pod/alice/collab/".to_string())],
        subjects: vec![SubjectMatcher::WebId(WebId(BOB_DID.to_string()))],
        modes: vec![AccessMode::Read, AccessMode::Write],
    });

    let config = LdpConfig::new(BASE_URL, POD_PREFIX);

    {
        let physical = PhysicalStore::new_fs(blob_dir.path.to_str().unwrap()).unwrap();
        let graph = SemanticGraphStore::open(&graph_dir.path).unwrap();
        let state = AppState::new(physical, graph, engine.clone(), config.clone())
            .await
            .unwrap();
        let app = build_router(state);

        // Seed `/alice/shared/memo.ttl`
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/alice/shared/memo.ttl")
                    .header(header::AUTHORIZATION, alice_auth())
                    .header(header::CONTENT_TYPE, "text/turtle")
                    .body(Body::from(
                        "<#memo> <http://purl.org/dc/terms/title> \"Shared Strategy\" .",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);

        // Bob (has Write on `/alice/collab/`, NO Control) CANNOT PUT `/alice/collab/.acl` -> 403 Forbidden
        let bob_acl_put = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/alice/collab/.acl")
                    .header(header::AUTHORIZATION, bob_auth())
                    .header(header::CONTENT_TYPE, "text/turtle")
                    .body(Body::from(
                        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
                         <#pwn> a acl:Authorization ; acl:agentClass <http://xmlns.com/foaf/0.1/Agent> ; acl:accessTo <./> ; acl:mode acl:Read .",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bob_acl_put.status(), StatusCode::FORBIDDEN);

        // Alice CANNOT inject cross-pod ACL rules inside `/alice/shared/.acl` targeting `/bob/vault/` -> 403 Forbidden
        let cross_scope_acl = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/alice/shared/.acl")
                    .header(header::AUTHORIZATION, alice_auth())
                    .header(header::CONTENT_TYPE, "text/turtle")
                    .body(Body::from(format!(
                        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
                         <#bad> a acl:Authorization ; acl:agent <{BOB_DID}> ; acl:accessTo <{BASE_URL}/bob/vault/> ; acl:mode acl:Read ."
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_scope_acl.status(), StatusCode::FORBIDDEN);

        // Before `.acl`: Bob gets 403 on `/alice/shared/memo.ttl`
        let bob_before = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/alice/shared/memo.ttl")
                    .header(header::AUTHORIZATION, bob_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bob_before.status(), StatusCode::FORBIDDEN);

        // Alice (Control) PUTs valid W3C WAC `/alice/shared/.acl` granting Bob `acl:Read` on `<./>`
        let put_acl = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/alice/shared/.acl")
                    .header(header::AUTHORIZATION, alice_auth())
                    .header(header::CONTENT_TYPE, "text/turtle")
                    .body(Body::from(format!(
                        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
                         <#bobRead> a acl:Authorization ;\n\
                             acl:agent <{BOB_DID}> ;\n\
                             acl:accessTo <./> ;\n\
                             acl:default <./> ;\n\
                             acl:mode acl:Read ."
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_acl.status(), StatusCode::CREATED);

        // Bob IMMEDIATELY gains `GET` (200 OK) on `/alice/shared/memo.ttl`, still denied `PUT` (403)
        let bob_read = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/alice/shared/memo.ttl")
                    .header(header::AUTHORIZATION, bob_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bob_read.status(), StatusCode::OK);

        let bob_write = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/alice/shared/memo.ttl")
                    .header(header::AUTHORIZATION, bob_auth())
                    .header(header::CONTENT_TYPE, "text/turtle")
                    .body(Body::from("<#m> <#p> \"tamper\" ."))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bob_write.status(), StatusCode::FORBIDDEN);

        // Alice DELETEs `/alice/shared/.acl` -> Bob's access is immediately revoked!
        let del_acl = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/alice/shared/.acl")
                    .header(header::AUTHORIZATION, alice_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del_acl.status(), StatusCode::NO_CONTENT);

        let bob_revoked = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/alice/shared/memo.ttl")
                    .header(header::AUTHORIZATION, bob_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bob_revoked.status(), StatusCode::FORBIDDEN);

        // Adversarial URI & Slug attacks -> 400 Bad Request
        for bad_uri in [
            "/alice/../bob/secret",
            "/alice/%2e%2e/bob/secret",
            "/alice/%2fsecret",
            "/alice//shared/memo.ttl",
            "/alice/shared/memo.ttl?bypass=1",
            "/__wolin_meta/catalog.json",
            "/alice/shared/.acl/",
            "/alice/shared/memo.ttl.acl.acl",
        ] {
            let r = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(bad_uri)
                        .header(header::AUTHORIZATION, alice_auth())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                r.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 for adversarial URI {bad_uri}"
            );
        }

        // Adversarial Slug privilege escalation (`Slug: pwn.acl` or `Slug: ../escape`) -> 400 Bad Request
        for bad_slug in ["pwn.acl", ".acl", "../escape", "sub/path", "__wolin_meta"] {
            let r = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/alice/collab/")
                        .header(header::AUTHORIZATION, bob_auth())
                        .header("Slug", bad_slug)
                        .header(header::CONTENT_TYPE, "text/turtle")
                        .body(Body::from("<#x> <#y> \"z\" ."))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                r.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 for malicious Slug {bad_slug}"
            );
        }
    }

    // Reopen persistent stores from disk and verify `/alice/shared/` + `/alice/shared/memo.ttl` survived restart!
    let reopened_physical = PhysicalStore::new_fs(blob_dir.path.to_str().unwrap()).unwrap();
    let reopened_graph = SemanticGraphStore::open(&graph_dir.path).unwrap();
    let reopened_state = AppState::new(reopened_physical, reopened_graph, engine, config)
        .await
        .unwrap();
    let reopened_app = build_router(reopened_state);

    let persisted_get = reopened_app
        .oneshot(
            Request::builder()
                .uri("/alice/shared/memo.ttl")
                .header(header::AUTHORIZATION, alice_auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(persisted_get.status(), StatusCode::OK);
    let body_text = String::from_utf8(
        to_bytes(persisted_get.into_body(), 65_536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body_text.contains("Shared Strategy"));
}
