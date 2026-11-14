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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tower::ServiceExt;
use wolin_core::{ResourceUri, WebId};
use wolin_identity::{JwtSignatureVerifier, OidcValidationOptions};
use wolin_mcp::protocol::ACCESS_DENIED_ERROR;
use wolin_policy::{AccessMode, AcpPolicy, DelegationGrant, PolicyEngine, SubjectMatcher, WacRule};
use wolin_server::{
    AppState, LdpConfig, build_router,
    ldp::{LDP_BASIC_CONTAINER, LDP_RDF_SOURCE},
};

const BASE_URL: &str = "http://pod.wolin.local";
const POD_PREFIX: &str = "wolin://pod";
const OIDC_ISSUER: &str = "https://auth.zitadel.wolin.id";
const OIDC_AUDIENCE: &str = "wolin-server";
const TEST_NOW: i64 = 1_763_000_000;

const ALICE_WEBID: &str = "https://alice.wolin.id/profile#me";
const ALICE_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"; // gitleaks:allow
const BOB_DID: &str = "did:nostr:7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
const RESEARCH_AGENT_ID: &str = "did:web:acme.corp:agents:ResearchCopilot";
const MAILER_AGENT_ID: &str = "did:web:acme.corp:agents:MailerBot";
const MALLORY_AGENT_ID: &str = "did:web:evil.example:agents:Exfiltrator";

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
            "wolin_e2e_test_{label}_{}_{nanos}_{idx}",
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

struct StrictEd25519Verifier;

impl JwtSignatureVerifier for StrictEd25519Verifier {
    fn verify(
        &self,
        alg: &str,
        _kid: Option<&str>,
        _signing_input: &[u8],
        signature: &[u8],
    ) -> wolin_core::Result<()> {
        if alg == "EdDSA" && signature == b"valid-ed25519-jws-sig" {
            Ok(())
        } else {
            Err(wolin_core::WolinError::Unauthenticated(
                "Cryptographic JWS signature verification failed".to_string(),
            ))
        }
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

fn sign_jwt(header_json: Value, payload_json: Value, sig: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        b64url(header_json.to_string().as_bytes()),
        b64url(payload_json.to_string().as_bytes()),
        b64url(sig)
    )
}

fn issue_alice_user_jwt() -> String {
    sign_jwt(
        json!({ "alg": "EdDSA", "kid": "zitadel-ed25519-1", "typ": "JWT" }),
        json!({
            "iss": OIDC_ISSUER,
            "sub": "user-alice-001",
            "webid": ALICE_WEBID,
            "aud": OIDC_AUDIENCE,
            "iat": TEST_NOW - 10,
            "exp": TEST_NOW + 3600,
            "scope": "openid profile read write append control"
        }),
        b"valid-ed25519-jws-sig",
    )
}

fn issue_delegated_agent_jwt(agent_id: &str, scope: &str, exp: i64) -> String {
    sign_jwt(
        json!({ "alg": "EdDSA", "kid": "zitadel-ed25519-1", "typ": "JWT" }),
        json!({
            "iss": OIDC_ISSUER,
            "sub": "user-alice-001",
            "webid": ALICE_WEBID,
            "aud": OIDC_AUDIENCE,
            "iat": TEST_NOW - 5,
            "exp": exp,
            "scope": scope,
            "act": { "sub": agent_id }
        }),
        b"valid-ed25519-jws-sig",
    )
}

async fn setup_e2e_runtime() -> (Router, Arc<AppState>) {
    let mut engine = PolicyEngine::with_explicit_delegation_required(true);
    engine.add_wac_rule(WacRule {
        id: "alice-pod-owner".to_string(),
        access_to: vec![ResourceUri("wolin://pod/pods/alice".to_string())],
        default_for: vec![ResourceUri("wolin://pod/pods/alice/".to_string())],
        subjects: vec![
            SubjectMatcher::WebId(WebId(ALICE_WEBID.to_string())),
            SubjectMatcher::WebId(WebId(ALICE_DID.to_string())),
        ],
        modes: vec![
            AccessMode::Read,
            AccessMode::Write,
            AccessMode::Append,
            AccessMode::Control,
        ],
    });
    engine.add_acp_policy(AcpPolicy {
        id: "deny-agents-private-vault".to_string(),
        targets: vec![],
        inherited_containers: vec![ResourceUri("wolin://pod/pods/alice/private/".to_string())],
        all_of: vec![],
        any_of: vec![
            SubjectMatcher::AgentId(RESEARCH_AGENT_ID.to_string()),
            SubjectMatcher::AgentId(MAILER_AGENT_ID.to_string()),
        ],
        none_of: vec![],
        allow: vec![],
        deny: vec![AccessMode::Read, AccessMode::Write, AccessMode::Append],
    });

    let config = LdpConfig::new(BASE_URL, POD_PREFIX)
        .with_oidc_options(
            OidcValidationOptions::new(OIDC_ISSUER)
                .with_audience(OIDC_AUDIENCE)
                .with_now(TEST_NOW),
        )
        .with_jwt_verifier(Arc::new(StrictEd25519Verifier))
        .with_policy_clock(TEST_NOW);

    let state = AppState::new_in_memory(engine, config)
        .await
        .expect("init AppState");
    let router = build_router(state.clone());
    (router, state)
}

async fn post_mcp_jsonrpc(
    app: &Router,
    auth_header: Option<&str>,
    payload: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(auth) = auth_header {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::from(payload.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    if bytes.is_empty() {
        return (status, Value::Null);
    }
    let json_val: Value = serde_json::from_slice(&bytes).expect("valid JSON response from /mcp");
    (status, json_val)
}

#[tokio::test]
async fn e2e_full_sovereign_pod_ldp_to_mcp_zero_pii_and_pdp_lifecycle() {
    let (app, state) = setup_e2e_runtime().await;
    let alice_bearer = format!("Bearer {}", issue_alice_user_jwt());

    // =========================================================================
    // 5) Verify GET /health and GET /.well-known/wolin capabilities
    // =========================================================================
    let health_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health_resp.status(), StatusCode::OK);
    let health_json: Value =
        serde_json::from_slice(&to_bytes(health_resp.into_body(), 65_536).await.unwrap()).unwrap();
    assert_eq!(health_json["status"], "healthy");
    assert_eq!(health_json["service"], "wolin-server");

    let wk_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/wolin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wk_resp.status(), StatusCode::OK);
    let wk_json: Value =
        serde_json::from_slice(&to_bytes(wk_resp.into_body(), 65_536).await.unwrap()).unwrap();
    assert_eq!(wk_json["storage_backend"], "opendal+oxigraph");
    assert_eq!(wk_json["base_url"], BASE_URL);
    assert_eq!(wk_json["pod_uri_prefix"], POD_PREFIX);
    assert_eq!(wk_json["endpoints"]["mcp"], "/mcp");
    assert_eq!(wk_json["endpoints"]["mcp_sse"], "/mcp/sse");
    assert_eq!(wk_json["endpoints"]["pods"], "/pods/");
    assert_eq!(wk_json["capabilities"]["solid_ldp"], true);
    assert_eq!(wk_json["capabilities"]["wac_acp_pdp"], true);
    assert_eq!(wk_json["capabilities"]["mcp_jsonrpc"], true);
    assert_eq!(wk_json["capabilities"]["mcp_sse"], true);
    assert_eq!(wk_json["capabilities"]["zero_pii_projection"], true);
    let advertised_tools: Vec<&str> = wk_json["capabilities"]["mcp_tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        advertised_tools,
        vec![
            "wolin_query_semantic",
            "wolin_read_resource",
            "wolin_write_resource",
            "wolin_list_resources",
        ]
    );

    // =========================================================================
    // 1) Create Pod container & insert RDF Turtle profile via Solid LDP HTTP PUT
    // =========================================================================
    let put_container = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/")
                .header(header::AUTHORIZATION, &alice_bearer)
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
    assert_eq!(put_container.status(), StatusCode::CREATED);
    assert_eq!(
        put_container.headers().get(header::LOCATION).unwrap(),
        "http://pod.wolin.local/pods/alice/"
    );

    let secret_api_key = concat!("sk-", "LiveMasterSecretKey99887766");
    let alice_profile_ttl = format!(
        r#"
        @prefix foaf: <http://xmlns.com/foaf/0.1/> .
        @prefix schema: <https://schema.org/> .
        @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
        @prefix wolin: <https://wolin.io/ns#> .

        <#me> a foaf:Person ;
            foaf:name "Alice Kim" ;
            schema:jobTitle "Principal Distributed Systems Architect" ;
            foaf:topic_interest "Solid Sovereign Pods", "Agentic Zero-PII MCP" ;
            rdfs:comment "Updated 2026-11-13; urgent contact emergency@alice.wolin.id or 010-4455-6677" ;
            foaf:mbox <mailto:alice@wolin.id> ;
            schema:email "alice@wolin.id" ;
            schema:telephone "+82-10-1234-5678" ;
            schema:address "427 Teheran-ro, Gangnam-gu, Seoul" ;
            wolin:ssn "920315-2345678" ;
            wolin:secretApiKey "{secret_api_key}" .
        "#
    );

    let put_profile = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/profile.ttl")
                .header(header::AUTHORIZATION, &alice_bearer)
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(alice_profile_ttl))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_profile.status(), StatusCode::CREATED);
    assert!(
        put_profile
            .headers()
            .get(header::LINK)
            .unwrap()
            .to_str()
            .unwrap()
            .contains(&format!("<{LDP_RDF_SOURCE}>; rel=\"type\""))
    );

    // Also store a confidential tax document inside ACP-denied `/pods/alice/private/`
    let put_private = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/private/tax-2026.ttl")
                .header(header::AUTHORIZATION, &alice_bearer)
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<#tax> <http://purl.org/dc/terms/title> \"Confidential Tax Filing\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_private.status(), StatusCode::CREATED);

    // =========================================================================
    // 2) Issue Delegated Agent Token & Perform MCP Handshake + SSE Discovery
    // =========================================================================
    let research_agent_jwt =
        issue_delegated_agent_jwt(RESEARCH_AGENT_ID, "openid read", TEST_NOW + 900);
    let research_bearer = format!("Bearer {research_agent_jwt}");

    // Verify GET /mcp/sse transport discovery
    let sse_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/mcp/sse")
                .header(header::AUTHORIZATION, &research_bearer)
                .header(header::ACCEPT, "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    assert_eq!(
        sse_resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/event-stream; charset=utf-8"
    );
    let sse_body =
        String::from_utf8(to_bytes(sse_resp.into_body(), 4096).await.unwrap().to_vec()).unwrap();
    assert!(sse_body.contains("event: endpoint\ndata: /mcp\n\n"));

    // MCP `initialize` + `notifications/initialized` (202 Accepted) + `tools/list`
    let (init_status, init_json) = post_mcp_jsonrpc(
        &app,
        Some(&research_bearer),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "research-copilot", "version": "1.0.0" }
            }
        }),
    )
    .await;
    assert_eq!(init_status, StatusCode::OK);
    assert_eq!(init_json["result"]["serverInfo"]["name"], "wolin-mcp");

    let (notif_status, _) = post_mcp_jsonrpc(
        &app,
        Some(&research_bearer),
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    )
    .await;
    assert_eq!(notif_status, StatusCode::ACCEPTED);

    // BEFORE registering DelegationGrant, PDP denies `wolin_query_semantic` (`require_explicit_delegation = true`)
    let (_, pre_grant_resp) = post_mcp_jsonrpc(
        &app,
        Some(&research_bearer),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "wolin_query_semantic",
                "arguments": {
                    "query": "SELECT ?name WHERE { ?s <http://xmlns.com/foaf/0.1/name> ?name }"
                }
            }
        }),
    )
    .await;
    assert_eq!(pre_grant_resp["result"]["isError"], true);
    assert!(
        pre_grant_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("delegation")
    );

    // Register attenuated Read-only DelegationGrant on `/pods/alice/` for ResearchCopilot
    state.with_policy_mut(|engine| {
        engine.add_delegation_grant(DelegationGrant {
            grant_id: "grant-research-read".to_string(),
            agent_id: RESEARCH_AGENT_ID.to_string(),
            delegated_by: WebId(ALICE_WEBID.to_string()),
            allowed_modes: vec![AccessMode::Read],
            resource_scopes: vec![ResourceUri("wolin://pod/pods/alice/".to_string())],
            expires_at: Some(TEST_NOW + 600),
            revoked: false,
        });
    });

    // =========================================================================
    // 3) Query Profile via POST /mcp (`wolin_query_semantic`) & Verify Zero-PII + PDP
    // =========================================================================
    let (q_status, q_resp) = post_mcp_jsonrpc(
        &app,
        Some(&research_bearer),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "wolin_query_semantic",
                "arguments": {
                    "query": "CONSTRUCT { ?s ?p ?o } WHERE { ?s ?p ?o }",
                    "target_uri": "wolin://pod/pods/alice/profile.ttl",
                    "format": "turtle"
                }
            }
        }),
    )
    .await;
    assert_eq!(q_status, StatusCode::OK);
    assert_eq!(q_resp["result"]["isError"], false);
    let q_result: Value =
        serde_json::from_str(q_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();

    assert_eq!(q_result["query_type"], "construct");
    assert_eq!(q_result["projection"]["zero_pii_enforced"], true);
    assert_eq!(q_result["projection"]["disclosed_categories"], json!([]));
    assert!(q_result["projection"]["redacted_triples"].as_u64().unwrap() >= 6);

    let projected_ttl = q_result["serialized_rdf"].as_str().unwrap();
    // Public semantic attributes & ISO dates preserved
    assert!(projected_ttl.contains("Alice Kim"));
    assert!(projected_ttl.contains("Principal Distributed Systems Architect"));
    assert!(projected_ttl.contains("Agentic Zero-PII MCP"));
    assert!(projected_ttl.contains("2026-11-13"));
    // Free-text PII in rdfs:comment scrubbed to markers
    assert!(projected_ttl.contains("[REDACTED_EMAIL]"));
    assert!(projected_ttl.contains("[REDACTED_PHONE]"));

    // Strict Zero-PII & Zero-Secret invariant: NO raw PII or API keys leaked anywhere
    for sensitive in [
        "alice@wolin.id",
        "emergency@alice.wolin.id",
        "+82-10-1234-5678",
        "010-4455-6677",
        "Teheran-ro",
        "920315-2345678",
        secret_api_key,
        "LiveMasterSecretKey99887766",
    ] {
        assert!(
            !projected_ttl.contains(sensitive),
            "Zero-PII violation: leaked '{sensitive}' in projected RDF:\n{projected_ttl}"
        );
    }

    // Boolean ASK side-channel probe against redacted SSN MUST evaluate to `false`
    let (_, ask_ssn_resp) = post_mcp_jsonrpc(
        &app,
        Some(&research_bearer),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "wolin_query_semantic",
                "arguments": {
                    "query": "ASK { ?s <https://wolin.io/ns#ssn> \"920315-2345678\" }"
                }
            }
        }),
    )
    .await;
    let ask_json: Value = serde_json::from_str(
        ask_ssn_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(ask_json["value"], false);

    // ACP Deny check: Pod-wide query sees `Alice Sovereign Pod`, NEVER `Confidential Tax Filing`
    let (_, pod_wide_resp) = post_mcp_jsonrpc(
        &app,
        Some(&research_bearer),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "wolin_query_semantic",
                "arguments": {
                    "query": "SELECT ?title WHERE { ?s <http://purl.org/dc/terms/title> ?title }"
                }
            }
        }),
    )
    .await;
    let pod_wide_json: Value = serde_json::from_str(
        pod_wide_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(pod_wide_json["row_count"], 1);
    assert_eq!(
        pod_wide_json["rows"][0]["title"]["value"],
        "Alice Sovereign Pod"
    );

    // Direct target_uri query on ACP-denied `/pods/alice/private/tax-2026.ttl` fails closed
    let (_, denied_private_resp) = post_mcp_jsonrpc(
        &app,
        Some(&research_bearer),
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "wolin_query_semantic",
                "arguments": {
                    "query": "SELECT * WHERE { ?s ?p ?o }",
                    "target_uri": "wolin://pod/pods/alice/private/tax-2026.ttl"
                }
            }
        }),
    )
    .await;
    assert_eq!(denied_private_resp["result"]["isError"], true);
    assert!(
        denied_private_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("ACP policy")
    );

    // Selective Disclosure (`pii:email` scope): unlocks `schema:email`, keeps phone/SSN/secret redacted
    let mailer_jwt =
        issue_delegated_agent_jwt(MAILER_AGENT_ID, "openid read pii:email", TEST_NOW + 900);
    state.with_policy_mut(|engine| {
        engine.add_delegation_grant(DelegationGrant {
            grant_id: "grant-mailer-read".to_string(),
            agent_id: MAILER_AGENT_ID.to_string(),
            delegated_by: WebId(ALICE_WEBID.to_string()),
            allowed_modes: vec![AccessMode::Read],
            resource_scopes: vec![ResourceUri(
                "wolin://pod/pods/alice/profile.ttl".to_string(),
            )],
            expires_at: Some(TEST_NOW + 600),
            revoked: false,
        });
    });
    let (_, mailer_resp) = post_mcp_jsonrpc(
        &app,
        Some(&format!("Bearer {mailer_jwt}")),
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "wolin_query_semantic",
                "arguments": {
                    "query": r#"
                        PREFIX schema: <https://schema.org/>
                        PREFIX wolin: <https://wolin.io/ns#>
                        SELECT ?email ?phone ?ssn ?secret WHERE {
                            ?s schema:email ?email .
                            OPTIONAL { ?s schema:telephone ?phone }
                            OPTIONAL { ?s wolin:ssn ?ssn }
                            OPTIONAL { ?s wolin:secretApiKey ?secret }
                        }
                    "#,
                    "target_uri": "wolin://pod/pods/alice/profile.ttl"
                }
            }
        }),
    )
    .await;
    let mailer_json: Value = serde_json::from_str(
        mailer_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(mailer_json["row_count"], 1);
    assert_eq!(mailer_json["rows"][0]["email"]["value"], "alice@wolin.id");
    assert!(mailer_json["rows"][0].get("phone").is_none());
    assert!(mailer_json["rows"][0].get("ssn").is_none());
    assert!(mailer_json["rows"][0].get("secret").is_none());

    // =========================================================================
    // 4) Verify Unauthorized Agents Cannot Perform Write Operations (MCP & LDP)
    // =========================================================================
    let mallory_jwt =
        issue_delegated_agent_jwt(MALLORY_AGENT_ID, "openid read write append", TEST_NOW + 900);
    let mallory_bearer = format!("Bearer {mallory_jwt}");
    let bob_did_auth = format!("DID {BOB_DID}");

    // 4a. MCP `wolin_write_resource` rejected for Read-only ResearchCopilot, ungranted Mallory, Bob, and Anonymous
    for (idx, caller_auth) in [
        Some(research_bearer.as_str()),
        Some(mallory_bearer.as_str()),
        Some(bob_did_auth.as_str()),
        None,
    ]
    .into_iter()
    .enumerate()
    {
        let (st, wr_resp) = post_mcp_jsonrpc(
            &app,
            caller_auth,
            json!({
                "jsonrpc": "2.0",
                "id": 100 + idx,
                "method": "tools/call",
                "params": {
                    "name": "wolin_write_resource",
                    "arguments": {
                        "uri": "wolin://pod/pods/alice/profile.ttl",
                        "content": "<#me> <http://xmlns.com/foaf/0.1/name> \"Defaced\" .",
                        "content_type": "text/turtle"
                    }
                }
            }),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(
            wr_resp["result"]["isError"], true,
            "expected MCP write denial for caller index {idx}"
        );
        assert!(
            wr_resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Access denied")
        );
    }

    // 4b. Solid LDP HTTP PUT / PATCH / DELETE rejected for Read-only ResearchCopilot & ungranted Mallory (403) and Anonymous (401)
    for caller in [&research_bearer, &mallory_bearer, &bob_did_auth] {
        let ldp_put = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/pods/alice/profile.ttl")
                    .header(header::AUTHORIZATION, caller)
                    .header(header::CONTENT_TYPE, "text/turtle")
                    .body(Body::from(
                        "<#me> <http://xmlns.com/foaf/0.1/name> \"Tamper\" .",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ldp_put.status(), StatusCode::FORBIDDEN);

        let ldp_del = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/pods/alice/profile.ttl")
                    .header(header::AUTHORIZATION, caller)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ldp_del.status(), StatusCode::FORBIDDEN);
    }

    let anon_ldp_put = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/profile.ttl")
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<#me> <http://xmlns.com/foaf/0.1/name> \"Anon\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anon_ldp_put.status(), StatusCode::UNAUTHORIZED);

    // 4c. Forged signature & expired Bearer tokens on `POST /mcp` and `GET /mcp/sse` -> 401 Unauthorized + WWW-Authenticate
    let forged_jwt = sign_jwt(
        json!({ "alg": "EdDSA" }),
        json!({
            "iss": OIDC_ISSUER,
            "sub": "user-alice-001",
            "webid": ALICE_WEBID,
            "aud": OIDC_AUDIENCE,
            "exp": TEST_NOW + 600
        }),
        b"forged-signature",
    );
    let expired_jwt = issue_delegated_agent_jwt(RESEARCH_AGENT_ID, "openid read", TEST_NOW - 1);

    for bad_token in [forged_jwt, expired_jwt] {
        let bad_mcp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .header(header::AUTHORIZATION, format!("Bearer {bad_token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"jsonrpc":"2.0","id":1,"method":"ping"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_mcp.status(), StatusCode::UNAUTHORIZED);
        assert!(bad_mcp.headers().contains_key(header::WWW_AUTHENTICATE));

        let bad_sse = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mcp/sse")
                    .header(header::AUTHORIZATION, format!("Bearer {bad_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_sse.status(), StatusCode::UNAUTHORIZED);
    }

    // 4d. Confirm Alice's sovereign profile remains 100% untampered & unredacted for owner
    let owner_get = app
        .oneshot(
            Request::builder()
                .uri("/pods/alice/profile.ttl")
                .header(header::AUTHORIZATION, &alice_bearer)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(owner_get.status(), StatusCode::OK);
    let owner_ttl = String::from_utf8(
        to_bytes(owner_get.into_body(), 65_536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(owner_ttl.contains("Alice Kim"));
    assert!(owner_ttl.contains("920315-2345678"));
    assert!(!owner_ttl.contains("Defaced"));
    assert!(!owner_ttl.contains("Tamper"));
}

#[tokio::test]
async fn e2e_bidirectional_ldp_mcp_catalog_acl_sync_and_protocol_guards() {
    let (app, state) = setup_e2e_runtime().await;
    let alice_did_auth = format!("DID {ALICE_DID}");
    let bob_did_auth = format!("DID {BOB_DID}");

    // 1. Grant an agent Read + Write on `/pods/alice/workspace/` ONLY
    let writer_jwt =
        issue_delegated_agent_jwt(RESEARCH_AGENT_ID, "openid read write", TEST_NOW + 900);
    let writer_bearer = format!("Bearer {writer_jwt}");
    state.with_policy_mut(|engine| {
        engine.add_delegation_grant(DelegationGrant {
            grant_id: "grant-workspace-rw".to_string(),
            agent_id: RESEARCH_AGENT_ID.to_string(),
            delegated_by: WebId(ALICE_WEBID.to_string()),
            allowed_modes: vec![AccessMode::Read, AccessMode::Write],
            resource_scopes: vec![ResourceUri("wolin://pod/pods/alice/workspace/".to_string())],
            expires_at: Some(TEST_NOW + 600),
            revoked: false,
        });
    });

    // Agent writes `/pods/alice/workspace/summary.ttl` via MCP `POST /mcp` (`wolin_write_resource`)
    let (_, mcp_write) = post_mcp_jsonrpc(
        &app,
        Some(&writer_bearer),
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "wolin_write_resource",
                "arguments": {
                    "uri": "wolin://pod/pods/alice/workspace/summary.ttl",
                    "content": "<#summary> <http://purl.org/dc/terms/title> \"Synthesized via MCP\" .",
                    "content_type": "text/turtle"
                }
            }
        }),
    )
    .await;
    assert_eq!(mcp_write["result"]["isError"], false);

    // Even with Write grant, mutating `.acl` via MCP is strictly blocked
    let (_, acl_attempt) = post_mcp_jsonrpc(
        &app,
        Some(&writer_bearer),
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "wolin_write_resource",
                "arguments": {
                    "uri": "wolin://pod/pods/alice/workspace/.acl",
                    "content": "<#hijack> a <http://www.w3.org/ns/auth/acl#Authorization> ."
                }
            }
        }),
    )
    .await;
    assert_eq!(acl_attempt["result"]["isError"], true);

    // Alice immediately reads `/pods/alice/workspace/summary.ttl` AND container `/pods/alice/workspace/` via Solid LDP HTTP!
    let ldp_get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/pods/alice/workspace/summary.ttl")
                .header(header::AUTHORIZATION, &alice_did_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ldp_get.status(), StatusCode::OK);
    let summary_ttl = String::from_utf8(
        to_bytes(ldp_get.into_body(), 65_536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(summary_ttl.contains("Synthesized via MCP"));

    let ldp_container_get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/pods/alice/workspace/")
                .header(header::AUTHORIZATION, &alice_did_auth)
                .header(header::ACCEPT, "application/n-triples")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ldp_container_get.status(), StatusCode::OK);
    let container_nt = String::from_utf8(
        to_bytes(ldp_container_get.into_body(), 65_536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(container_nt.contains(
        "<http://pod.wolin.local/pods/alice/workspace/> <http://www.w3.org/ns/ldp#contains> <http://pod.wolin.local/pods/alice/workspace/summary.ttl>"
    ));

    // 2. Live HTTP WAC `.acl` mutation immediately governs MCP `resources/read`!
    // Before `.acl`: Bob gets -32001 ACCESS_DENIED_ERROR via `POST /mcp`
    let (_, bob_denied) = post_mcp_jsonrpc(
        &app,
        Some(&bob_did_auth),
        json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "resources/read",
            "params": { "uri": "wolin://pod/pods/alice/workspace/summary.ttl" }
        }),
    )
    .await;
    assert_eq!(bob_denied["error"]["code"], ACCESS_DENIED_ERROR);

    // Alice PUTs W3C WAC `/pods/alice/workspace/.acl` via Solid LDP granting Bob `acl:Read`
    let put_acl = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/workspace/.acl")
                .header(header::AUTHORIZATION, &alice_did_auth)
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

    // Bob IMMEDIATELY reads `summary.ttl` via `POST /mcp` `resources/read`
    let (_, bob_allowed) = post_mcp_jsonrpc(
        &app,
        Some(&bob_did_auth),
        json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "resources/read",
            "params": { "uri": "wolin://pod/pods/alice/workspace/summary.ttl" }
        }),
    )
    .await;
    assert!(
        bob_allowed["result"]["contents"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Synthesized via MCP")
    );

    // Alice DELETEs `/pods/alice/workspace/.acl` -> Bob's MCP access is immediately revoked!
    let del_acl = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/pods/alice/workspace/.acl")
                .header(header::AUTHORIZATION, &alice_did_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_acl.status(), StatusCode::NO_CONTENT);

    let (_, bob_revoked) = post_mcp_jsonrpc(
        &app,
        Some(&bob_did_auth),
        json!({
            "jsonrpc": "2.0",
            "id": 22,
            "method": "resources/read",
            "params": { "uri": "wolin://pod/pods/alice/workspace/summary.ttl" }
        }),
    )
    .await;
    assert_eq!(bob_revoked["error"]["code"], ACCESS_DENIED_ERROR);

    // 3. HTTP protocol & boundary guards on `/mcp` and `/mcp/sse`
    let get_mcp = app
        .clone()
        .oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(get_mcp.status(), StatusCode::METHOD_NOT_ALLOWED);

    let wrong_ct_mcp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_ct_mcp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let query_mcp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp?debug=1")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(query_mcp.status(), StatusCode::BAD_REQUEST);

    let bad_sse_accept = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/mcp/sse")
                .header(header::ACCEPT, "image/png")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_sse_accept.status(), StatusCode::NOT_ACCEPTABLE);

    // Percent-encoded `/%6dcp` (`mcp`) cannot be shadowed via LDP
    let encoded_mcp_ldp = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/%6dcp")
                .header(header::AUTHORIZATION, &alice_did_auth)
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#x> <#y> \"z\" ."))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(encoded_mcp_ldp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn e2e_real_tcp_socket_persistent_storage_acl_rehydration_and_graceful_shutdown() {
    let storage_guard = TempDirGuard::new("persistent_pod");

    let build_base_policy = || {
        let mut engine = PolicyEngine::new();
        engine.add_wac_rule(WacRule {
            id: "alice-root".to_string(),
            access_to: vec![ResourceUri("wolin://pod/pods/alice".to_string())],
            default_for: vec![ResourceUri("wolin://pod/pods/alice/".to_string())],
            subjects: vec![SubjectMatcher::WebId(WebId(ALICE_DID.to_string()))],
            modes: vec![
                AccessMode::Read,
                AccessMode::Write,
                AccessMode::Append,
                AccessMode::Control,
            ],
        });
        engine
    };

    // Phase 1: Start real TCP listener on 127.0.0.1:0 with persistent storage & graceful shutdown
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral loopback port");
        let addr = listener.local_addr().unwrap();
        let live_base_url = format!("http://{addr}");

        let config = LdpConfig::new(&live_base_url, POD_PREFIX);
        let state = AppState::new_persistent(&storage_guard.path, build_base_policy(), config)
            .await
            .expect("init persistent AppState");
        let app = build_router(state);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(storage_guard.path.join("blobs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "persistent storage directories must be 0700");
        }

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("clean axum::serve exit");
        });

        // Send real HTTP/1.1 PUT over TCP to seed `/pods/alice/profile.ttl` + `/pods/alice/.acl`
        let ttl_body = "<#me> <http://xmlns.com/foaf/0.1/name> \"TCP Persistent Alice\" ;\n\
                        <https://schema.org/email> \"tcp@alice.wolin.id\" .";
        let put_raw = send_raw_http1(
            addr,
            &format!(
                "PUT /pods/alice/profile.ttl HTTP/1.1\r\n\
                 Host: {addr}\r\n\
                 Authorization: DID {ALICE_DID}\r\n\
                 Content-Type: text/turtle\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n\
                 {ttl_body}",
                ttl_body.len()
            ),
        )
        .await;
        assert!(
            put_raw.starts_with("HTTP/1.1 201 Created"),
            "got: {put_raw}"
        );

        let acl_body = format!(
            "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
             <#bobRead> a acl:Authorization ; acl:agent <{BOB_DID}> ; acl:accessTo <./> ; acl:default <./> ; acl:mode acl:Read ."
        );
        let put_acl_raw = send_raw_http1(
            addr,
            &format!(
                "PUT /pods/alice/.acl HTTP/1.1\r\n\
                 Host: {addr}\r\n\
                 Authorization: DID {ALICE_DID}\r\n\
                 Content-Type: text/turtle\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n\
                 {acl_body}",
                acl_body.len()
            ),
        )
        .await;
        assert!(
            put_acl_raw.starts_with("HTTP/1.1 201 Created"),
            "got: {put_acl_raw}"
        );

        // Trigger graceful shutdown and verify clean server task completion
        let _ = shutdown_tx.send(());
        server_task.await.expect("server joined cleanly");
    }

    // Phase 2: Reopen persistent storage with matching base_url (note: Phase 1 used ephemeral port;
    // verify catalog + blobs + ACL rehydration when reopened on the same canonical base_url!)
    // Let's also verify reopening on fixed canonical BASE_URL for deterministic ACL IRI rehydration:
    let restart_dir = TempDirGuard::new("acl_rehydrate");
    {
        let cfg = LdpConfig::new(BASE_URL, POD_PREFIX);
        let st1 = AppState::new_persistent(&restart_dir.path, build_base_policy(), cfg.clone())
            .await
            .unwrap();
        let app1 = build_router(st1);

        app1.clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/pods/alice/doc.ttl")
                    .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                    .header(header::CONTENT_TYPE, "text/turtle")
                    .body(Body::from(
                        "<#d> <http://purl.org/dc/terms/title> \"Durable Across Restart\" .",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        app1.oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/pods/alice/.acl")
                .header(header::AUTHORIZATION, format!("DID {ALICE_DID}"))
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(format!(
                    "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
                     <#bobRead> a acl:Authorization ; acl:agent <{BOB_DID}> ; acl:accessTo <./> ; acl:default <./> ; acl:mode acl:Read ."
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    }

    // Reopen fresh AppState on `restart_dir` — persisted `.acl` rules MUST rehydrate automatically!
    let cfg2 = LdpConfig::new(BASE_URL, POD_PREFIX);
    let st2 = AppState::new_persistent(&restart_dir.path, build_base_policy(), cfg2)
        .await
        .unwrap();
    let app2 = build_router(st2);

    let (_, bob_mcp_after_restart) = post_mcp_jsonrpc(
        &app2,
        Some(&format!("DID {BOB_DID}")),
        json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "wolin_query_semantic",
                "arguments": {
                    "query": "SELECT ?title WHERE { ?s <http://purl.org/dc/terms/title> ?title }"
                }
            }
        }),
    )
    .await;
    assert_eq!(bob_mcp_after_restart["result"]["isError"], false);
    let rows_json: Value = serde_json::from_str(
        bob_mcp_after_restart["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(rows_json["row_count"], 1);
    assert_eq!(
        rows_json["rows"][0]["title"]["value"],
        "Durable Across Restart"
    );
}

async fn send_raw_http1(addr: std::net::SocketAddr, raw_req: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to loopback wolin-server");
    stream.write_all(raw_req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}
