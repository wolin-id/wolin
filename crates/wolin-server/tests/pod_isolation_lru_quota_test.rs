use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt;
use wolin_core::{ResourceUri, WebId};
use wolin_policy::{AccessMode, PolicyEngine, SubjectMatcher, WacRule};
use wolin_server::{AppState, LdpConfig, build_router};
use wolin_storage::{PhysicalStore, SemanticGraphStore};

const BASE_URL: &str = "http://pod.wolin.cloud";
const POD_PREFIX: &str = "wolin://pod";
const CLOUD_DOMAIN: &str = "wolin.cloud";

const ALICE_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"; // gitleaks:allow
const BOB_DID: &str = "did:nostr:7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
const CAROL_DID: &str = "did:web:carol.wolin.id";

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
            "wolin_pod_isolation_test_{label}_{}_{nanos}_{idx}",
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

fn build_multi_pod_policy() -> PolicyEngine {
    let mut engine = PolicyEngine::new();
    for (pod_id, did) in [("alice", ALICE_DID), ("bob", BOB_DID), ("carol", CAROL_DID)] {
        engine.add_wac_rule(WacRule {
            id: format!("{pod_id}-owner"),
            access_to: vec![ResourceUri(format!("{POD_PREFIX}/pods/{pod_id}"))],
            default_for: vec![ResourceUri(format!("{POD_PREFIX}/pods/{pod_id}/"))],
            subjects: vec![SubjectMatcher::WebId(WebId(did.to_string()))],
            modes: vec![
                AccessMode::Read,
                AccessMode::Write,
                AccessMode::Append,
                AccessMode::Control,
            ],
        });
    }
    engine.add_wac_rule(WacRule {
        id: "system-public-owner".to_string(),
        access_to: vec![ResourceUri(format!("{POD_PREFIX}/public"))],
        default_for: vec![ResourceUri(format!("{POD_PREFIX}/public/"))],
        subjects: vec![SubjectMatcher::WebId(WebId(ALICE_DID.to_string()))],
        modes: vec![AccessMode::Read, AccessMode::Write, AccessMode::Append],
    });
    engine.add_wac_rule(WacRule {
        id: "system-public-read".to_string(),
        access_to: vec![ResourceUri(format!("{POD_PREFIX}/public"))],
        default_for: vec![ResourceUri(format!("{POD_PREFIX}/public/"))],
        subjects: vec![SubjectMatcher::Public],
        modes: vec![AccessMode::Read],
    });
    engine
}

async fn post_mcp(app: &Router, auth: Option<&str>, payload: Value) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(a) = auth {
        builder = builder.header(header::AUTHORIZATION, a);
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::from(payload.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let val: Value = serde_json::from_slice(&bytes).unwrap();
    (status, val)
}

#[tokio::test]
async fn physical_directory_separation_and_zero_cross_tenant_graph_leakage() {
    let storage = TempDirGuard::new("physical_separation");
    let cfg = LdpConfig::new(BASE_URL, POD_PREFIX).with_pod_cloud_domain(CLOUD_DOMAIN);
    let state = AppState::new_persistent(&storage.path, build_multi_pod_policy(), cfg)
        .await
        .expect("init persistent AppState");
    let app = build_router(Arc::clone(&state));

    // Provision `alice` and `bob` via POST /api/pods
    for (pod_id, owner_did, name) in [
        ("alice", ALICE_DID, "Alice Isolated Pod"),
        ("bob", BOB_DID, "Bob Isolated Pod"),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/pods")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "pod_id": pod_id,
                            "owner_webid": owner_did,
                            "display_name": name
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // Write private RDF to Alice via `/pods/alice/...` and to Bob via subdomain `Host: bob.wolin.cloud`
    let put_alice = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/private/vault.ttl")
                .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<#secret> <http://purl.org/dc/terms/title> \"AlicePhysicalVault\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_alice.status(), StatusCode::CREATED);

    let put_bob = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/private/vault.ttl")
                .header(header::HOST, "bob.wolin.cloud")
                .header(header::AUTHORIZATION, format!("DID {BOB_DID}"))
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<#secret> <http://purl.org/dc/terms/title> \"BobSubdomainVault\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_bob.status(), StatusCode::CREATED);

    // Write non-pod system route `/public/system-announcement.ttl`
    let put_system = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/public/system-announcement.ttl")
                .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<#sys> <http://purl.org/dc/terms/title> \"GlobalSystemNotice\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_system.status(), StatusCode::CREATED);

    // 1. Verify separate physical RocksDB directories exist on disk
    let sys_graph_dir = storage.path.join("graph");
    let alice_graph_dir = storage.path.join("pods").join("alice").join("graph");
    let bob_graph_dir = storage.path.join("pods").join("bob").join("graph");
    assert!(sys_graph_dir.is_dir());
    assert!(alice_graph_dir.is_dir());
    assert!(bob_graph_dir.is_dir());

    // 2. Direct physical store inspection: zero cross-tenant quad leakage!
    let alice_store = state.pod_stores.get_or_open("alice").unwrap();
    let bob_store = state.pod_stores.get_or_open("bob").unwrap();

    let alice_dump = String::from_utf8(alice_store.dump_nquads().unwrap()).unwrap();
    let bob_dump = String::from_utf8(bob_store.dump_nquads().unwrap()).unwrap();
    let sys_dump = String::from_utf8(state.graph_store.dump_nquads().unwrap()).unwrap();

    assert!(alice_dump.contains("AlicePhysicalVault"));
    assert!(!alice_dump.contains("BobSubdomainVault"));
    assert!(!alice_dump.contains("GlobalSystemNotice"));

    assert!(bob_dump.contains("BobSubdomainVault"));
    assert!(!bob_dump.contains("AlicePhysicalVault"));
    assert!(!bob_dump.contains("GlobalSystemNotice"));

    assert!(sys_dump.contains("GlobalSystemNotice"));
    assert!(!sys_dump.contains("AlicePhysicalVault"));
    assert!(!sys_dump.contains("BobSubdomainVault"));

    // 3. Verify non-pod system route AND MCP SPARQL work cleanly across isolated stores
    let get_sys = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/public/system-announcement.ttl")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_sys.status(), StatusCode::OK);

    let (_, bob_mcp) = post_mcp(
        &app,
        Some(&format!("DID {BOB_DID}")),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wolin_query_semantic",
                "arguments": {
                    "query": "SELECT ?title WHERE { ?s <http://purl.org/dc/terms/title> ?title }",
                    "target_uri": "wolin://pod/pods/bob/private/"
                }
            }
        }),
    )
    .await;
    assert_eq!(bob_mcp["result"]["isError"], false);
    let bob_rows: Value =
        serde_json::from_str(bob_mcp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(bob_rows["row_count"], 1);
    assert_eq!(bob_rows["rows"][0]["title"]["value"], "BobSubdomainVault");
}

#[tokio::test]
async fn lru_eviction_and_transparent_cold_reopen_with_max_open_pods_two() {
    let storage = TempDirGuard::new("lru_eviction");
    let cfg = LdpConfig::new(BASE_URL, POD_PREFIX)
        .with_pod_cloud_domain(CLOUD_DOMAIN)
        .with_max_open_pods(2);

    let state = AppState::new_persistent(&storage.path, build_multi_pod_policy(), cfg)
        .await
        .expect("init persistent AppState with max_open_pods=2");
    let app = build_router(Arc::clone(&state));
    assert_eq!(state.pod_stores.max_open_pods(), 2);

    // Access 3 pods (`alice`, `bob`, `carol`) sequentially via HTTP PUT
    for (pod_id, did, label) in [
        ("alice", ALICE_DID, "AliceColdDurableData"),
        ("bob", BOB_DID, "BobColdDurableData"),
        ("carol", CAROL_DID, "CarolHotData"),
    ] {
        let put = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/pods/{pod_id}/dataset.ttl"))
                    .header(header::AUTHORIZATION, format!("DID {did}"))
                    .header(header::CONTENT_TYPE, "text/turtle")
                    .body(Body::from(format!(
                        "<#item> <http://purl.org/dc/terms/title> \"{label}\" ."
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put.status(), StatusCode::CREATED);
        assert!(state.pod_stores.open_pod_count() <= 2);
    }

    // Verify LRU bounded at 2: `alice` was evicted when `carol` opened!
    assert_eq!(state.pod_stores.open_pod_count(), 2);
    assert!(!state.pod_stores.is_pod_open("alice"));
    assert!(state.pod_stores.is_pod_open("bob"));
    assert!(state.pod_stores.is_pod_open("carol"));
    assert_eq!(state.pod_stores.eviction_count(), 1);

    // Cold re-open `alice` via subdomain HTTP GET (`Host: alice.wolin.cloud`) -> evicts `bob`, data 100% intact!
    let get_alice = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dataset.ttl")
                .header(header::HOST, "alice.wolin.cloud")
                .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_alice.status(), StatusCode::OK);
    let alice_ttl = String::from_utf8(
        to_bytes(get_alice.into_body(), 65_536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(alice_ttl.contains("AliceColdDurableData"));

    assert_eq!(state.pod_stores.open_pod_count(), 2);
    assert!(state.pod_stores.is_pod_open("alice"));
    assert!(!state.pod_stores.is_pod_open("bob"));
    assert_eq!(state.pod_stores.eviction_count(), 2);

    // Cold re-open `bob` via Native MCP `wolin_read_resource` -> evicts `carol`, data 100% intact!
    let (_, bob_read) = post_mcp(
        &app,
        Some(&format!("DID {BOB_DID}")),
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "wolin_read_resource",
                "arguments": {
                    "uri": "wolin://pod/pods/bob/dataset.ttl"
                }
            }
        }),
    )
    .await;
    assert_eq!(bob_read["result"]["isError"], false);
    assert!(
        bob_read["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("BobColdDurableData")
    );
    assert_eq!(state.pod_stores.open_pod_count(), 2);
    assert!(state.pod_stores.is_pod_open("bob"));
    assert!(!state.pod_stores.is_pod_open("carol"));
    assert_eq!(state.pod_stores.eviction_count(), 3);
}

#[tokio::test]
async fn per_pod_storage_quota_enforcement_rejects_oversized_writes_leaving_data_intact() {
    let storage = TempDirGuard::new("pod_quota");
    // Tight 500-byte per-pod quota while single-request `max_body_bytes` stays 16 MiB
    let cfg = LdpConfig::new(BASE_URL, POD_PREFIX)
        .with_pod_cloud_domain(CLOUD_DOMAIN)
        .with_pod_quota_bytes(500);

    let state = AppState::new_persistent(&storage.path, build_multi_pod_policy(), cfg)
        .await
        .expect("init persistent AppState with 500B quota");
    let app = build_router(Arc::clone(&state));

    // 1. Seed valid container `/pods/alice/` (empty, 0 bytes) + `/pods/alice/notes.ttl` (~90 bytes) + `/pods/alice/small.bin` (120 bytes)
    let put_dir = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/")
                .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_dir.status(), StatusCode::CREATED);

    let initial_ttl = "<#n1> <http://purl.org/dc/terms/title> \"OriginalSafeNote\" .";
    let put_note = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/notes.ttl")
                .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(initial_ttl))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_note.status(), StatusCode::CREATED);
    let original_note_etag = put_note
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let put_small_bin = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/small.bin")
                .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(vec![b'a'; 120]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_small_bin.status(), StatusCode::CREATED);
    let usage_after_seed = state.pod_stores.pod_usage_bytes("alice");
    assert!(usage_after_seed > 150 && usage_after_seed <= 300);

    // 2. Oversized PUT new binary (`600` bytes > `500` quota) -> 507 Insufficient Storage
    let put_over_bin = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/huge.bin")
                .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(vec![b'X'; 600]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_over_bin.status(), StatusCode::INSUFFICIENT_STORAGE);

    // 3. Oversized PUT overwrite on `/pods/alice/notes.ttl` -> 507 Insufficient Storage, original note & ETag untouched!
    let huge_ttl = format!(
        "<#n1> <http://purl.org/dc/terms/description> \"{}\" .",
        "Z".repeat(600)
    );
    let put_over_note = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/notes.ttl")
                .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(huge_ttl))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_over_note.status(), StatusCode::INSUFFICIENT_STORAGE);

    // 4. Oversized POST to `/pods/alice/` -> 507 Insufficient Storage
    let post_over = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/pods/alice/")
                .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                .header("Slug", "too-big")
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(vec![b'P'; 450]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post_over.status(), StatusCode::INSUFFICIENT_STORAGE);

    // 5. Oversized SPARQL-Update PATCH on `/pods/alice/notes.ttl` -> 507 Insufficient Storage
    let patch_over = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/pods/alice/notes.ttl")
                .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                .header(header::CONTENT_TYPE, "application/sparql-update")
                .body(Body::from(format!(
                    "INSERT DATA {{ <#extra> <http://purl.org/dc/terms/description> \"{}\" . }}",
                    "Q".repeat(450)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(patch_over.status(), StatusCode::INSUFFICIENT_STORAGE);

    // Verify existing `/pods/alice/notes.ttl` data, ETag, and usage are 100% untouched!
    assert_eq!(state.pod_stores.pod_usage_bytes("alice"), usage_after_seed);
    let get_note = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/pods/alice/notes.ttl")
                .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_note.status(), StatusCode::OK);
    assert_eq!(
        get_note.headers().get(header::ETAG).unwrap(),
        original_note_etag.as_str()
    );
    let note_body = String::from_utf8(
        to_bytes(get_note.into_body(), 65_536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(note_body.contains("OriginalSafeNote"));
    assert!(!note_body.contains("ZZZZ"));
    assert!(!note_body.contains("QQQQ"));

    // 6. Sibling tenant `bob` has an independent 500-byte quota and is unaffected by `alice`
    let bob_put = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/bob/own.bin")
                .header(header::AUTHORIZATION, format!("DID {BOB_DID}"))
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(vec![b'B'; 350]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_put.status(), StatusCode::CREATED);

    // 7. DELETE `/pods/alice/small.bin` frees 120 bytes so a subsequent 250-byte write succeeds!
    let del_small = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/pods/alice/small.bin")
                .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_small.status(), StatusCode::NO_CONTENT);

    let put_reclaimed = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/reclaimed.bin")
                .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(vec![b'R'; 250]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_reclaimed.status(), StatusCode::CREATED);

    // 8. Provisioning a new Pod (`dave`) when `pod_quota_bytes` (500B) < seeded footprint -> 507 Insufficient Storage with zero residue
    let over_provision = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/pods")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "pod_id": "dave",
                        "owner_webid": ALICE_DID,
                        "display_name": "Dave Over Quota"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(over_provision.status(), StatusCode::INSUFFICIENT_STORAGE);
    assert!(!state.pod_stores.is_pod_open("dave"));
    let dave_info = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/pods/dave")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dave_info.status(), StatusCode::NOT_FOUND);

    // 9. Non-container `/pods`, `/pods.acl`, `/pods/alice`, and `/pods/alice.acl` are rejected fail-closed (400 Bad Request)
    for bad_uri in ["/pods", "/pods.acl", "/pods/alice", "/pods/alice.acl"] {
        let bad_put = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(bad_uri)
                    .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                    .header(header::CONTENT_TYPE, "text/turtle")
                    .body(Body::from(
                        "<#x> <http://purl.org/dc/terms/title> \"bad\" .",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_put.status(), StatusCode::BAD_REQUEST, "URI {bad_uri}");
    }
}

#[tokio::test]
async fn appstate_new_with_fs_stores_persists_per_pod_graphs_and_legacy_catalog_sizes() {
    let blob_dir = TempDirGuard::new("appstate_new_blobs");
    let graph_dir = TempDirGuard::new("appstate_new_graph");
    let cfg = LdpConfig::new(BASE_URL, POD_PREFIX)
        .with_pod_cloud_domain(CLOUD_DOMAIN)
        .with_pod_quota_bytes(50_000);

    {
        let physical = PhysicalStore::new_fs(blob_dir.path.to_str().unwrap()).unwrap();
        let graph = SemanticGraphStore::open(&graph_dir.path).unwrap();
        let state = AppState::new(physical.clone(), graph, PolicyEngine::new(), cfg.clone())
            .await
            .unwrap();
        let app = build_router(state);

        let prov = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/pods")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "pod_id": "alice",
                            "owner_webid": ALICE_DID,
                            "display_name": "Alice Restartable"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(prov.status(), StatusCode::CREATED);

        // Simulate legacy catalog.json without `size_bytes` fields to verify backward-compatible backfill
        let raw_cat = physical.get("__wolin_meta/catalog.json").await.unwrap();
        let mut cat_json: Value = serde_json::from_slice(&raw_cat).unwrap();
        for (_k, entry) in cat_json["entries"].as_object_mut().unwrap().iter_mut() {
            entry.as_object_mut().unwrap().remove("size_bytes");
        }
        physical
            .put_with_content_type(
                "__wolin_meta/catalog.json",
                serde_json::to_vec(&cat_json).unwrap(),
                "application/json",
            )
            .await
            .unwrap();
    }

    // Re-open via `AppState::new` on the same directories -> per-pod ACLs, triples, and quota usage survive!
    let physical_reopened = PhysicalStore::new_fs(blob_dir.path.to_str().unwrap()).unwrap();
    let graph_reopened = SemanticGraphStore::open(&graph_dir.path).unwrap();
    let state_reopened = AppState::new(physical_reopened, graph_reopened, PolicyEngine::new(), cfg)
        .await
        .unwrap();
    assert!(state_reopened.pod_stores.pod_usage_bytes("alice") > 1_000);

    let app_reopened = build_router(state_reopened);
    let card_get = app_reopened
        .oneshot(
            Request::builder()
                .uri("/pods/alice/profile/card")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(card_get.status(), StatusCode::OK);
}
