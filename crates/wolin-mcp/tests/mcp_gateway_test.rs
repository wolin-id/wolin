use std::sync::Arc;

use serde_json::{json, Value};
use wolin_core::{Principal, ResourceUri, WebId};
use wolin_identity::{DidResolver, OidcValidationOptions, OidcValidator};
use wolin_mcp::protocol::{
    JsonRpcRequest, McpContentItem, McpToolCall, ACCESS_DENIED_ERROR, INVALID_PARAMS,
    INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR, RESOURCE_NOT_FOUND_ERROR,
};
use wolin_mcp::{DisclosurePolicy, McpAgentServer, McpGatewayConfig, PiiCategory};
use wolin_policy::{AccessMode, AcpPolicy, DelegationGrant, PolicyEngine, SubjectMatcher, WacRule};

const BASE_URL: &str = "http://pod.wolin.local";
const POD_PREFIX: &str = "wolin://pod";
const TEST_ISSUER: &str = "https://auth.zitadel.acme.corp";
const TEST_NOW: i64 = 1_763_000_000;

const ALICE_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"; // gitleaks:allow
const BOB_DID: &str = "did:nostr:7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";

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

fn std_b64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
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
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}

fn build_jwt(header_json: Value, payload_json: Value) -> String {
    format!(
        "{}.{}.{}",
        b64url(header_json.to_string().as_bytes()),
        b64url(payload_json.to_string().as_bytes()),
        b64url(b"test-signature-bytes")
    )
}

fn extract_tool_json(res: &wolin_mcp::protocol::McpToolResult) -> Value {
    assert!(
        !res.is_error,
        "expected tool success, got error: {:?}",
        res.content
    );
    let Some(McpContentItem::Text { text }) = res.content.first() else {
        panic!("expected text content item");
    };
    serde_json::from_str(text).expect("valid JSON in tool result text")
}

fn extract_tool_error_text(res: &wolin_mcp::protocol::McpToolResult) -> &str {
    assert!(
        res.is_error,
        "expected tool error (`isError: true`), got success"
    );
    let Some(McpContentItem::Text { text }) = res.content.first() else {
        panic!("expected text content item");
    };
    text.as_str()
}

fn build_default_gateway(explicit_delegation: bool) -> McpAgentServer {
    let mut engine = PolicyEngine::with_explicit_delegation_required(explicit_delegation);
    engine.add_wac_rule(WacRule {
        id: "alice-owner".to_string(),
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
        id: "bob-owner".to_string(),
        access_to: vec![ResourceUri("wolin://pod/bob".to_string())],
        default_for: vec![ResourceUri("wolin://pod/bob/".to_string())],
        subjects: vec![SubjectMatcher::WebId(WebId(BOB_DID.to_string()))],
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

    let config = McpGatewayConfig::new(BASE_URL, POD_PREFIX).with_policy_clock(TEST_NOW);
    McpAgentServer::new_in_memory(engine, config).expect("init in-memory MCP gateway")
}

#[tokio::test]
async fn mcp_jsonrpc_handshake_discovery_notifications_and_batch_protocol() {
    let gw = build_default_gateway(false);
    let alice = DidResolver::resolve_principal(ALICE_DID).expect("alice DID");

    // 1. Initialize with flexible protocol version negotiation + unknown `_meta` tolerance
    let init_raw = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": { "roots": { "listChanged": true } },
            "clientInfo": { "name": "hermes-agent", "version": "1.0.0" },
            "_meta": null
        }
    })
    .to_string();

    let init_resp_str = gw
        .handle_jsonrpc_str(&alice, &init_raw)
        .await
        .expect("initialize must emit a JSON-RPC response");
    let init_resp: Value = serde_json::from_str(&init_resp_str).unwrap();
    assert_eq!(init_resp["jsonrpc"], "2.0");
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["protocolVersion"], "2026-07-28");
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "wolin-mcp");
    assert!(init_resp["result"]["capabilities"]["tools"].is_object());
    assert!(init_resp["result"]["capabilities"]["resources"].is_object());

    // 2. Notification (`notifications/initialized` without `id`) must produce NO response
    let notif = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    })
    .to_string();
    assert!(gw.handle_jsonrpc_str(&alice, &notif).await.is_none());

    // 3. Discovery stubs (`prompts/list`, `resources/templates/list`, `ping`) succeed cleanly
    for (id, method, key) in [
        (2, "prompts/list", Some("prompts")),
        (3, "resources/templates/list", Some("resourceTemplates")),
        (4, "ping", None),
    ] {
        let raw = json!({ "jsonrpc": "2.0", "id": id, "method": method }).to_string();
        let out: Value =
            serde_json::from_str(&gw.handle_jsonrpc_str(&alice, &raw).await.unwrap()).unwrap();
        assert!(
            out.get("error").is_none(),
            "{method} returned unexpected error: {out}"
        );
        if let Some(k) = key {
            assert_eq!(out["result"][k], json!([]));
        }
    }

    // 4. `tools/list` advertises all 4 Wolin MCP tools with strict JSON Schemas
    let list_tools_raw = json!({
        "jsonrpc": "2.0",
        "id": "t-list-1",
        "method": "tools/list",
        "params": { "_meta": { "progressToken": "p1" } }
    })
    .to_string();
    let tools_resp: Value = serde_json::from_str(
        &gw.handle_jsonrpc_str(&alice, &list_tools_raw)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(tools_resp["id"], "t-list-1");
    let tools = tools_resp["result"]["tools"]
        .as_array()
        .expect("tools array");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert_eq!(
        names,
        vec![
            "wolin_query_semantic",
            "wolin_read_resource",
            "wolin_write_resource",
            "wolin_list_resources",
        ]
    );
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert!(tool["inputSchema"]["properties"].is_object());
        assert!(!tool["description"].as_str().unwrap_or_default().is_empty());
    }

    // 5. Malformed JSON, wrong version, bad ID types, unknown method, and batch semantics
    let bad_json = gw
        .handle_jsonrpc_str(&alice, "{not-valid-json")
        .await
        .unwrap();
    let bad_json_val: Value = serde_json::from_str(&bad_json).unwrap();
    assert_eq!(bad_json_val["error"]["code"], PARSE_ERROR);
    assert!(bad_json_val["id"].is_null());

    let empty_batch = gw.handle_jsonrpc_str(&alice, "[]").await.unwrap();
    let empty_batch_val: Value = serde_json::from_str(&empty_batch).unwrap();
    assert_eq!(empty_batch_val["error"]["code"], INVALID_REQUEST);

    for invalid_req in [
        json!({ "jsonrpc": "1.0", "id": 1, "method": "ping" }),
        json!({ "jsonrpc": "2.0", "id": true, "method": "ping" }),
        json!({ "jsonrpc": "2.0", "id": {"nested": 1}, "method": "ping" }),
        json!({ "jsonrpc": "2.0", "id": 1, "method": "" }),
    ] {
        let resp: Value = serde_json::from_str(
            &gw.handle_jsonrpc_str(&alice, &invalid_req.to_string())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp["error"]["code"], INVALID_REQUEST);
    }

    let unknown_method = json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "nonexistent/method"
    });
    let unk_resp: Value = serde_json::from_str(
        &gw.handle_jsonrpc_str(&alice, &unknown_method.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(unk_resp["error"]["code"], METHOD_NOT_FOUND);
    assert_eq!(unk_resp["id"], 99);

    // Malformed `tools/call` envelope (non-object arguments) -> -32602 Invalid params
    let bad_call_params = json!({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "tools/call",
        "params": { "name": "wolin_read_resource", "arguments": "not-an-object" }
    });
    let bad_call_resp: Value = serde_json::from_str(
        &gw.handle_jsonrpc_str(&alice, &bad_call_params.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(bad_call_resp["error"]["code"], INVALID_PARAMS);

    // Mixed batch: 2 requests + 1 notification -> exactly 2 responses
    let batch = json!([
        { "jsonrpc": "2.0", "id": "b1", "method": "ping" },
        { "jsonrpc": "2.0", "method": "notifications/initialized" },
        { "jsonrpc": "2.0", "id": "b2", "method": "tools/list" }
    ]);
    let batch_out: Value = serde_json::from_str(
        &gw.handle_jsonrpc_str(&alice, &batch.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    let batch_arr = batch_out.as_array().expect("batch array response");
    assert_eq!(batch_arr.len(), 2);
    assert_eq!(batch_arr[0]["id"], "b1");
    assert_eq!(batch_arr[1]["id"], "b2");

    // Notification-only batch -> None
    let notif_batch = json!([
        { "jsonrpc": "2.0", "method": "notifications/initialized" },
        { "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": 1 } }
    ]);
    assert!(gw
        .handle_jsonrpc_str(&alice, &notif_batch.to_string())
        .await
        .is_none());
}

#[tokio::test]
async fn mcp_tools_crud_rdf_binary_list_and_etag_preconditions() {
    let gw = build_default_gateway(false);
    let alice = DidResolver::resolve_principal(ALICE_DID).expect("alice DID");

    // 1. Write RDF Turtle resource via `tools/call` JSON-RPC wire interface
    let turtle_doc = r#"
        @prefix foaf: <http://xmlns.com/foaf/0.1/> .
        @prefix dcterms: <http://purl.org/dc/terms/> .
        <#roadmap> dcterms:title "Wolin MCP Semantic Gateway" ;
                   foaf:maker <https://alice.wolin.id/profile#me> .
    "#;
    let write_rpc = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "wolin_write_resource",
            "arguments": {
                "uri": "wolin://pod/alice/notes/roadmap.ttl",
                "content": turtle_doc,
                "content_type": "text/turtle"
            }
        }
    });
    let write_wire: Value = serde_json::from_str(
        &gw.handle_jsonrpc_str(&alice, &write_rpc.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(write_wire["result"]["isError"], false);
    let write_meta: Value =
        serde_json::from_str(write_wire["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(write_meta["uri"], "wolin://pod/alice/notes/roadmap.ttl");
    assert_eq!(write_meta["kind"], "RdfSource");
    assert_eq!(write_meta["created"], true);
    assert_eq!(write_meta["triples_written"], 2);
    let etag_v1 = write_meta["etag"].as_str().unwrap().to_string();

    // 2. Write binary Non-RDF blob via `wolin_write_resource` (`encoding: "base64"`)
    let raw_binary: Vec<u8> = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0xFF];
    let write_bin = gw
        .call_tool(
            &alice,
            McpToolCall {
                name: "wolin_write_resource".to_string(),
                arguments: json!({
                    "uri": "/alice/assets/badge.png",
                    "content": std_b64(&raw_binary),
                    "content_type": "image/png",
                    "encoding": "base64"
                }),
            },
        )
        .await;
    let bin_meta = extract_tool_json(&write_bin);
    assert_eq!(bin_meta["kind"], "NonRdfSource");
    assert_eq!(bin_meta["bytes_written"], raw_binary.len());

    // 3. List container contents (direct children vs recursive) via `wolin_list_resources`
    let direct_list = extract_tool_json(
        &gw.call_tool(
            &alice,
            McpToolCall {
                name: "wolin_list_resources".to_string(),
                arguments: json!({ "uri": "wolin://pod/alice/" }),
            },
        )
        .await,
    );
    let direct_names: Vec<&str> = direct_list["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(direct_names, vec!["assets/", "notes/"]);

    let recursive_list = extract_tool_json(
        &gw.call_tool(
            &alice,
            McpToolCall {
                name: "wolin_list_resources".to_string(),
                arguments: json!({ "uri": "wolin://pod/alice", "recursive": true }),
            },
        )
        .await,
    );
    let rec_uris: Vec<&str> = recursive_list["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["uri"].as_str().unwrap())
        .collect();
    assert!(rec_uris.contains(&"wolin://pod/alice/notes/roadmap.ttl"));
    assert!(rec_uris.contains(&"wolin://pod/alice/assets/badge.png"));

    // 4. Read RDF resource in Turtle, N-Triples, and JSON-LD formats
    for (fmt, expected_mime) in [
        ("turtle", "text/turtle"),
        ("ntriples", "application/n-triples"),
        ("jsonld", "application/ld+json"),
    ] {
        let read_res = extract_tool_json(
            &gw.call_tool(
                &alice,
                McpToolCall {
                    name: "wolin_read_resource".to_string(),
                    arguments: json!({
                        "uri": "wolin://pod/alice/notes/roadmap.ttl",
                        "format": fmt
                    }),
                },
            )
            .await,
        );
        assert_eq!(read_res["content_type"], expected_mime);
        assert!(read_res["data"]
            .as_str()
            .unwrap()
            .contains("Wolin MCP Semantic Gateway"));
    }

    // 5. Read binary resource via both `wolin_read_resource` tool and MCP `resources/read` + `resources/list`
    let read_bin_tool = extract_tool_json(
        &gw.call_tool(
            &alice,
            McpToolCall {
                name: "wolin_read_resource".to_string(),
                arguments: json!({ "uri": "wolin://pod/alice/assets/badge.png" }),
            },
        )
        .await,
    );
    assert_eq!(read_bin_tool["encoding"], "base64");
    assert_eq!(read_bin_tool["data"], std_b64(&raw_binary));

    let res_list_rpc = json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "resources/list"
    });
    let res_list_wire: Value = serde_json::from_str(
        &gw.handle_jsonrpc_str(&alice, &res_list_rpc.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    let mcp_resources = res_list_wire["result"]["resources"].as_array().unwrap();
    assert!(mcp_resources.iter().any(
        |r| r["uri"] == "wolin://pod/alice/notes/roadmap.ttl" && r["mimeType"] == "text/turtle"
    ));
    assert!(mcp_resources
        .iter()
        .any(|r| r["uri"] == "wolin://pod/alice/assets/badge.png" && r["mimeType"] == "image/png"));

    let res_read_rpc = json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "resources/read",
        "params": { "uri": "wolin://pod/alice/assets/badge.png" }
    });
    let res_read_wire: Value = serde_json::from_str(
        &gw.handle_jsonrpc_str(&alice, &res_read_rpc.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        res_read_wire["result"]["contents"][0]["blob"],
        std_b64(&raw_binary)
    );
    assert_eq!(
        res_read_wire["result"]["contents"][0]["mimeType"],
        "image/png"
    );

    // Missing resource via `resources/read` returns standard MCP -32002
    let missing_rpc = json!({
        "jsonrpc": "2.0",
        "id": 22,
        "method": "resources/read",
        "params": { "uri": "wolin://pod/alice/notes/does-not-exist.ttl" }
    });
    let missing_wire: Value = serde_json::from_str(
        &gw.handle_jsonrpc_str(&alice, &missing_rpc.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(missing_wire["error"]["code"], RESOURCE_NOT_FOUND_ERROR);

    // 6. Optimistic concurrency control (`if_match`) on `wolin_write_resource`
    let stale_write = gw
        .call_tool(
            &alice,
            McpToolCall {
                name: "wolin_write_resource".to_string(),
                arguments: json!({
                    "uri": "wolin://pod/alice/notes/roadmap.ttl",
                    "content": "<#roadmap> <http://purl.org/dc/terms/title> \"Stale Overwrite\" .",
                    "content_type": "text/turtle",
                    "if_match": "\"stale-etag-000\""
                }),
            },
        )
        .await;
    assert!(extract_tool_error_text(&stale_write).contains("If-Match"));

    let valid_update = extract_tool_json(
        &gw.call_tool(
            &alice,
            McpToolCall {
                name: "wolin_write_resource".to_string(),
                arguments: json!({
                    "uri": "wolin://pod/alice/notes/roadmap.ttl",
                    "content": "<#roadmap> <http://purl.org/dc/terms/title> \"Wolin v2 Updated\" .",
                    "content_type": "text/turtle",
                    "if_match": etag_v1
                }),
            },
        )
        .await,
    );
    assert_eq!(valid_update["created"], false);
    assert_ne!(valid_update["etag"].as_str().unwrap(), etag_v1);
}

#[tokio::test]
async fn semantic_query_zero_pii_redaction_and_selective_disclosure_by_agent_scope() {
    let gw = build_default_gateway(false);
    let alice = DidResolver::resolve_principal(ALICE_DID).expect("alice DID");

    let profile_ttl = r#"
        @prefix foaf: <http://xmlns.com/foaf/0.1/> .
        @prefix schema: <https://schema.org/> .
        @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
        @prefix wolin: <https://wolin.io/ns#> .

        <#me> a foaf:Person ;
            foaf:name "Alice Kim" ;
            foaf:topic_interest "Semantic Web", "Agentic Sovereign Pods" ;
            rdfs:comment "Public bio; emergency contact backup@private.wolin.id or 010-9988-7766" ;
            foaf:mbox <mailto:alice@private.wolin.id> ;
            schema:email "alice@private.wolin.id" ;
            schema:telephone "+82-10-1234-5678" ;
            schema:address "123 Teheran-ro, Gangnam-gu, Seoul" ;
            wolin:ssn "900101-1234567" ;
            wolin:secretApiKey "sk-live-supersecret999999" .
    "#;

    let wr = gw
        .call_tool(
            &alice,
            McpToolCall {
                name: "wolin_write_resource".to_string(),
                arguments: json!({
                    "uri": "wolin://pod/alice/profile.ttl",
                    "content": profile_ttl,
                    "content_type": "text/turtle"
                }),
            },
        )
        .await;
    assert!(!wr.is_error);

    // A. Default Agent (`scope: ["read"]`) -> Strict Zero-PII Projection
    let zero_pii_agent = Principal::Agent {
        agent_id: "research-assistant".to_string(),
        delegated_by: WebId(ALICE_DID.to_string()),
        scope: vec!["read".to_string()],
    };

    let construct_all = extract_tool_json(
        &gw.call_tool(
            &zero_pii_agent,
            McpToolCall {
                name: "wolin_query_semantic".to_string(),
                arguments: json!({
                    "query": "CONSTRUCT { ?s ?p ?o } WHERE { ?s ?p ?o }",
                    "format": "turtle"
                }),
            },
        )
        .await,
    );
    assert_eq!(construct_all["query_type"], "construct");
    assert_eq!(construct_all["projection"]["zero_pii_enforced"], true);
    assert_eq!(
        construct_all["projection"]["disclosed_categories"],
        json!([])
    );
    assert!(
        construct_all["projection"]["redacted_triples"]
            .as_u64()
            .unwrap()
            >= 6
    );

    let serialized_ttl = construct_all["serialized_rdf"].as_str().unwrap();
    assert!(serialized_ttl.contains("Alice Kim"));
    assert!(serialized_ttl.contains("Agentic Sovereign Pods"));
    // Structured PII & secrets MUST NOT appear anywhere in projected output
    for forbidden in [
        "alice@private.wolin.id",
        "backup@private.wolin.id",
        "+82-10-1234-5678",
        "010-9988-7766",
        "Teheran-ro",
        "900101-1234567",
        "sk-live-supersecret999999",
    ] {
        assert!(
            !serialized_ttl.contains(forbidden),
            "Zero-PII projection leaked '{forbidden}' in:\n{serialized_ttl}"
        );
    }
    assert!(serialized_ttl.contains("[REDACTED_EMAIL]"));
    assert!(serialized_ttl.contains("[REDACTED_PHONE]"));

    // Verify Zero-Side-Channel: boolean ASK & FILTER probes against redacted PII/secrets MUST return false / 0 rows
    let ask_ssn = extract_tool_json(
        &gw.call_tool(
            &zero_pii_agent,
            McpToolCall {
                name: "wolin_query_semantic".to_string(),
                arguments: json!({
                    "query": "ASK { ?s <https://wolin.io/ns#ssn> \"900101-1234567\" }"
                }),
            },
        )
        .await,
    );
    assert_eq!(ask_ssn["value"], false);

    let filter_secret = extract_tool_json(
        &gw.call_tool(
            &zero_pii_agent,
            McpToolCall {
                name: "wolin_query_semantic".to_string(),
                arguments: json!({
                    "query": "SELECT ?s WHERE { ?s ?p ?o FILTER(CONTAINS(STR(?o), \"sk-live\")) }"
                }),
            },
        )
        .await,
    );
    assert_eq!(filter_secret["row_count"], 0);

    // Also verify `wolin_read_resource` enforces Zero-PII on RDF reads for restricted agents!
    let read_rdf_agent = extract_tool_json(
        &gw.call_tool(
            &zero_pii_agent,
            McpToolCall {
                name: "wolin_read_resource".to_string(),
                arguments: json!({ "uri": "wolin://pod/alice/profile.ttl" }),
            },
        )
        .await,
    );
    let agent_read_ttl = read_rdf_agent["data"].as_str().unwrap();
    assert!(!agent_read_ttl.contains("900101-1234567"));
    assert!(!agent_read_ttl.contains("sk-live-supersecret999999"));
    assert!(!agent_read_ttl.contains("alice@private.wolin.id"));

    // B. Selective Disclosure (`scope: ["read", "pii:email"]`) -> Email unlocked, Phone/SSN/Secret still redacted!
    let email_agent = Principal::Agent {
        agent_id: "calendar-mailer".to_string(),
        delegated_by: WebId(ALICE_DID.to_string()),
        scope: vec!["read".to_string(), "pii:email".to_string()],
    };
    let select_email = extract_tool_json(
        &gw.call_tool(
            &email_agent,
            McpToolCall {
                name: "wolin_query_semantic".to_string(),
                arguments: json!({
                    "query": r#"
                        PREFIX schema: <https://schema.org/>
                        PREFIX wolin: <https://wolin.io/ns#>
                        SELECT ?email ?phone ?ssn ?secret WHERE {
                            ?s schema:email ?email .
                            OPTIONAL { ?s schema:telephone ?phone }
                            OPTIONAL { ?s wolin:ssn ?ssn }
                            OPTIONAL { ?s wolin:secretApiKey ?secret }
                        }
                    "#
                }),
            },
        )
        .await,
    );
    assert_eq!(select_email["row_count"], 1);
    assert_eq!(
        select_email["rows"][0]["email"]["value"],
        "alice@private.wolin.id"
    );
    assert!(select_email["rows"][0].get("phone").is_none());
    assert!(select_email["rows"][0].get("ssn").is_none());
    assert!(select_email["rows"][0].get("secret").is_none());

    // C. Full-PII Agent (`scope: ["read", "pii:full"]`) -> PII unlocked, raw `secretApiKey` STILL redacted!
    let full_pii_agent = Principal::Agent {
        agent_id: "tax-filing-agent".to_string(),
        delegated_by: WebId(ALICE_DID.to_string()),
        scope: vec!["read".to_string(), "pii:full".to_string()],
    };
    let select_full = extract_tool_json(
        &gw.call_tool(
            &full_pii_agent,
            McpToolCall {
                name: "wolin_query_semantic".to_string(),
                arguments: json!({
                    "query": r#"
                        PREFIX wolin: <https://wolin.io/ns#>
                        SELECT ?ssn ?secret WHERE {
                            ?s wolin:ssn ?ssn .
                            OPTIONAL { ?s wolin:secretApiKey ?secret }
                        }
                    "#
                }),
            },
        )
        .await,
    );
    assert_eq!(select_full["row_count"], 1);
    assert_eq!(select_full["rows"][0]["ssn"]["value"], "900101-1234567");
    assert!(
        select_full["rows"][0].get("secret").is_none(),
        "raw secretApiKey must never be exposed to any AI agent"
    );

    // D. Server-side DisclosurePolicy attenuates over-broad agent token claims
    gw.with_disclosure_mut(|policy: &mut DisclosurePolicy| {
        policy.set_agent_allowed_categories(
            "tax-filing-agent",
            WebId(ALICE_DID.to_string()),
            [PiiCategory::Email],
        );
    });
    let attenuated = extract_tool_json(
        &gw.call_tool(
            &full_pii_agent,
            McpToolCall {
                name: "wolin_query_semantic".to_string(),
                arguments: json!({
                    "query": "ASK { ?s <https://wolin.io/ns#ssn> ?ssn }"
                }),
            },
        )
        .await,
    );
    assert_eq!(
        attenuated["value"], false,
        "server-side DisclosurePolicy must attenuate token pii:full down to Email only"
    );

    // E. Human Sovereign Owner (`Principal::User`) sees their own full data unredacted
    let owner_select = extract_tool_json(
        &gw.call_tool(
            &alice,
            McpToolCall {
                name: "wolin_query_semantic".to_string(),
                arguments: json!({
                    "query": "SELECT ?ssn WHERE { ?s <https://wolin.io/ns#ssn> ?ssn }"
                }),
            },
        )
        .await,
    );
    assert_eq!(owner_select["projection"]["zero_pii_enforced"], false);
    assert_eq!(owner_select["rows"][0]["ssn"]["value"], "900101-1234567");
}

#[tokio::test]
async fn pdp_agent_delegation_lifecycle_acp_deny_and_cross_tenant_isolation() {
    let gw = build_default_gateway(true);
    let alice = DidResolver::resolve_principal(ALICE_DID).expect("alice DID");
    let bob = DidResolver::resolve_principal(BOB_DID).expect("bob DID");

    // Seed Alice engineering spec, Alice secret keys, and Bob's private vault
    for (principal, uri, ttl) in [
        (
            &alice,
            "wolin://pod/alice/eng/spec.ttl",
            "<#spec> <http://purl.org/dc/terms/title> \"Public Architecture Spec\" .",
        ),
        (
            &alice,
            "wolin://pod/alice/eng/secrets/keys.ttl",
            "<#keys> <http://purl.org/dc/terms/title> \"Master Signing Keys\" .",
        ),
        (
            &bob,
            "wolin://pod/bob/vault/diary.ttl",
            "<#diary> <http://purl.org/dc/terms/title> \"Bob Private Diary\" .",
        ),
    ] {
        let res = gw
            .call_tool(
                principal,
                McpToolCall {
                    name: "wolin_write_resource".to_string(),
                    arguments: json!({ "uri": uri, "content": ttl, "content_type": "text/turtle" }),
                },
            )
            .await;
        assert!(!res.is_error);
    }

    // Add ACP deny blocking the agent on `wolin://pod/alice/eng/secrets/`
    let agent_id = "did:web:acme.corp:agents:Coder";
    gw.with_policy_mut(|engine| {
        engine.add_acp_policy(AcpPolicy {
            id: "deny-coder-secrets".to_string(),
            targets: vec![],
            inherited_containers: vec![ResourceUri("wolin://pod/alice/eng/secrets/".to_string())],
            all_of: vec![],
            any_of: vec![SubjectMatcher::AgentId(agent_id.to_string())],
            none_of: vec![],
            allow: vec![],
            deny: vec![AccessMode::Read, AccessMode::Write, AccessMode::Append],
        });
    });

    // Resolve delegated Agent Principal via real ZITADEL OIDC JWT validation (`wolin-identity`)
    let jwt = build_jwt(
        json!({ "alg": "RS256", "kid": "zitadel-k1", "typ": "JWT" }),
        json!({
            "iss": TEST_ISSUER,
            "sub": ALICE_DID,
            "aud": "wolin-mcp",
            "exp": TEST_NOW + 3600,
            "iat": TEST_NOW - 10,
            "scope": "openid read write",
            "act": { "sub": agent_id }
        }),
    );
    let oidc_opts = OidcValidationOptions::new(TEST_ISSUER)
        .with_audience("wolin-mcp")
        .with_now(TEST_NOW);
    let coder_agent =
        OidcValidator::validate_with_options(&jwt, &oidc_opts).expect("valid OIDC agent JWT");

    // 1. Before issuing `DelegationGrant`, `require_explicit_delegation = true` rejects ALL actions
    for call in [
        McpToolCall {
            name: "wolin_read_resource".to_string(),
            arguments: json!({ "uri": "wolin://pod/alice/eng/spec.ttl" }),
        },
        McpToolCall {
            name: "wolin_list_resources".to_string(),
            arguments: json!({ "uri": "wolin://pod/alice/eng/" }),
        },
        McpToolCall {
            name: "wolin_write_resource".to_string(),
            arguments: json!({
                "uri": "wolin://pod/alice/eng/new.ttl",
                "content": "<#n> <http://purl.org/dc/terms/title> \"Unauthorized\" ."
            }),
        },
        McpToolCall {
            name: "wolin_query_semantic".to_string(),
            arguments: json!({ "query": "SELECT ?s ?p ?o WHERE { ?s ?p ?o }" }),
        },
    ] {
        let denied = gw.call_tool(&coder_agent, call).await;
        assert!(extract_tool_error_text(&denied).contains("delegation"));
    }

    // `resources/read` and `resources/list` also fail closed with ACCESS_DENIED_ERROR (-32001)
    let denied_res_read: Value = serde_json::from_str(
        &gw.handle_jsonrpc_str(
            &coder_agent,
            &json!({
                "jsonrpc": "2.0",
                "id": 30,
                "method": "resources/read",
                "params": { "uri": "wolin://pod/alice/eng/spec.ttl" }
            })
            .to_string(),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    assert_eq!(denied_res_read["error"]["code"], ACCESS_DENIED_ERROR);

    let denied_res_list: Value = serde_json::from_str(
        &gw.handle_jsonrpc_str(
            &coder_agent,
            &json!({ "jsonrpc": "2.0", "id": 31, "method": "resources/list" }).to_string(),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    assert_eq!(denied_res_list["error"]["code"], ACCESS_DENIED_ERROR);

    // 2. Grant Read-only delegation on `wolin://pod/alice/eng/`
    gw.with_policy_mut(|engine| {
        engine.add_delegation_grant(DelegationGrant {
            grant_id: "grant-eng-read".to_string(),
            agent_id: agent_id.to_string(),
            delegated_by: WebId(ALICE_DID.to_string()),
            allowed_modes: vec![AccessMode::Read],
            resource_scopes: vec![ResourceUri("wolin://pod/alice/eng/".to_string())],
            expires_at: Some(TEST_NOW + 600),
            revoked: false,
        });
    });

    // Agent can now read `spec.ttl`
    let spec_read = extract_tool_json(
        &gw.call_tool(
            &coder_agent,
            McpToolCall {
                name: "wolin_read_resource".to_string(),
                arguments: json!({ "uri": "wolin://pod/alice/eng/spec.ttl" }),
            },
        )
        .await,
    );
    assert!(spec_read["data"]
        .as_str()
        .unwrap()
        .contains("Public Architecture Spec"));

    // Write is STILL denied because grant only allows `AccessMode::Read` (even though JWT had `write` scope!)
    let write_attempt = gw
        .call_tool(
            &coder_agent,
            McpToolCall {
                name: "wolin_write_resource".to_string(),
                arguments: json!({
                    "uri": "wolin://pod/alice/eng/spec.ttl",
                    "content": "<#spec> <http://purl.org/dc/terms/title> \"Tampered\" ."
                }),
            },
        )
        .await;
    assert!(write_attempt.is_error);

    // ACP deny blocks `secrets/keys.ttl` (including percent-encoded `%73ecrets`)
    for blocked_uri in [
        "wolin://pod/alice/eng/secrets/keys.ttl",
        "wolin://pod/alice/eng/%73ecrets/keys.ttl",
        "wolin://pod/bob/vault/diary.ttl",
    ] {
        let blocked = gw
            .call_tool(
                &coder_agent,
                McpToolCall {
                    name: "wolin_read_resource".to_string(),
                    arguments: json!({ "uri": blocked_uri }),
                },
            )
            .await;
        assert!(blocked.is_error, "expected {blocked_uri} to be denied");
    }

    // `wolin_list_resources` on `/alice/eng/` hides ACP-denied `secrets/`!
    let eng_list = extract_tool_json(
        &gw.call_tool(
            &coder_agent,
            McpToolCall {
                name: "wolin_list_resources".to_string(),
                arguments: json!({ "uri": "wolin://pod/alice/eng/", "recursive": true }),
            },
        )
        .await,
    );
    let listed_uris: Vec<&str> = eng_list["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["uri"].as_str().unwrap())
        .collect();
    assert_eq!(listed_uris, vec!["wolin://pod/alice/eng/spec.ttl"]);

    // `wolin_query_semantic` across the entire pod isolates ONLY `spec.ttl` — zero leak from `secrets/` or `bob/vault/`!
    let pod_wide_query = extract_tool_json(
        &gw.call_tool(
            &coder_agent,
            McpToolCall {
                name: "wolin_query_semantic".to_string(),
                arguments: json!({
                    "query": "SELECT ?title WHERE { ?s <http://purl.org/dc/terms/title> ?title }"
                }),
            },
        )
        .await,
    );
    assert_eq!(pod_wide_query["row_count"], 1);
    assert_eq!(
        pod_wide_query["rows"][0]["title"]["value"],
        "Public Architecture Spec"
    );

    // 3. Issue Write grant on `wolin://pod/alice/eng/`, verify write works, but `.acl` mutation is strictly blocked!
    gw.with_policy_mut(|engine| {
        engine.add_delegation_grant(DelegationGrant {
            grant_id: "grant-eng-write".to_string(),
            agent_id: agent_id.to_string(),
            delegated_by: WebId(ALICE_DID.to_string()),
            allowed_modes: vec![AccessMode::Read, AccessMode::Write],
            resource_scopes: vec![ResourceUri("wolin://pod/alice/eng/".to_string())],
            expires_at: Some(TEST_NOW + 600),
            revoked: false,
        });
    });

    let valid_agent_write = gw
        .call_tool(
            &coder_agent,
            McpToolCall {
                name: "wolin_write_resource".to_string(),
                arguments: json!({
                    "uri": "wolin://pod/alice/eng/changelog.ttl",
                    "content": "<#log> <http://purl.org/dc/terms/title> \"Agent Commit 1\" ."
                }),
            },
        )
        .await;
    assert!(!valid_agent_write.is_error);

    // Attempting to write `.acl` via MCP `wolin_write_resource` MUST fail closed (even for owner or agent!)
    for caller in [&coder_agent, &alice] {
        let acl_write = gw
            .call_tool(
                caller,
                McpToolCall {
                    name: "wolin_write_resource".to_string(),
                    arguments: json!({
                        "uri": "wolin://pod/alice/eng/.acl",
                        "content": "<#hijack> a <http://www.w3.org/ns/auth/acl#Authorization> ."
                    }),
                },
            )
            .await;
        assert!(
            acl_write.is_error,
            "MCP wolin_write_resource must never mutate .acl governance"
        );
    }

    // 4. Privilege escalation attempt: Bob delegates an agent targeting Alice's pod
    let bob_escalating_agent = Principal::Agent {
        agent_id: "bob-bot".to_string(),
        delegated_by: WebId(BOB_DID.to_string()),
        scope: vec!["read".to_string(), "write".to_string()],
    };
    gw.with_policy_mut(|engine| {
        engine.add_delegation_grant(DelegationGrant {
            grant_id: "bob-forged-grant-on-alice".to_string(),
            agent_id: "bob-bot".to_string(),
            delegated_by: WebId(BOB_DID.to_string()),
            allowed_modes: vec![AccessMode::Read],
            resource_scopes: vec![ResourceUri("wolin://pod/alice/eng/".to_string())],
            expires_at: Some(TEST_NOW + 600),
            revoked: false,
        });
    });
    let escalation = gw
        .call_tool(
            &bob_escalating_agent,
            McpToolCall {
                name: "wolin_read_resource".to_string(),
                arguments: json!({ "uri": "wolin://pod/alice/eng/spec.ttl" }),
            },
        )
        .await;
    assert!(extract_tool_error_text(&escalation).contains("Privilege escalation"));

    // 5. Revoking grants immediately terminates agent access across all tools & protocol handlers
    gw.with_policy_mut(|engine| {
        assert!(engine.revoke_delegation("grant-eng-read"));
        assert!(engine.revoke_delegation("grant-eng-write"));
    });
    let post_revoke = gw
        .call_tool(
            &coder_agent,
            McpToolCall {
                name: "wolin_read_resource".to_string(),
                arguments: json!({ "uri": "wolin://pod/alice/eng/spec.ttl" }),
            },
        )
        .await;
    assert!(post_revoke.is_error);

    // 6. Expired DelegationGrant (`expires_at <= TEST_NOW`) is rejected fail-closed
    gw.with_policy_mut(|engine| {
        engine.add_delegation_grant(DelegationGrant {
            grant_id: "grant-expired".to_string(),
            agent_id: agent_id.to_string(),
            delegated_by: WebId(ALICE_DID.to_string()),
            allowed_modes: vec![AccessMode::Read],
            resource_scopes: vec![ResourceUri("wolin://pod/alice/eng/".to_string())],
            expires_at: Some(TEST_NOW),
            revoked: false,
        });
    });
    let expired_attempt = gw
        .call_tool(
            &coder_agent,
            McpToolCall {
                name: "wolin_query_semantic".to_string(),
                arguments: json!({
                    "query": "SELECT ?s ?p ?o WHERE { ?s ?p ?o }",
                    "target_uri": "wolin://pod/alice/eng/spec.ttl"
                }),
            },
        )
        .await;
    assert!(expired_attempt.is_error);
}

#[tokio::test]
async fn adversarial_sparql_ssrf_traversal_limits_and_concurrent_writes() {
    let mut engine = PolicyEngine::new();
    engine.add_wac_rule(WacRule {
        id: "alice-owner".to_string(),
        access_to: vec![ResourceUri("wolin://pod/alice".to_string())],
        default_for: vec![ResourceUri("wolin://pod/alice/".to_string())],
        subjects: vec![SubjectMatcher::WebId(WebId(ALICE_DID.to_string()))],
        modes: vec![AccessMode::Read, AccessMode::Write, AccessMode::Append],
    });
    let config = McpGatewayConfig::new(BASE_URL, POD_PREFIX)
        .with_policy_clock(TEST_NOW)
        .with_max_message_bytes(4096)
        .with_max_resource_bytes(1024);
    let gw = Arc::new(McpAgentServer::new_in_memory(engine, config).unwrap());
    let alice = DidResolver::resolve_principal(ALICE_DID).expect("alice DID");

    // 1. SPARQL Update mutations and SSRF `SERVICE` clauses in `wolin_query_semantic` are blocked
    for forbidden_sparql in [
        "INSERT DATA { <https://x.org/s> <https://x.org/p> \"injected\" }",
        "DELETE WHERE { ?s ?p ?o }",
        "DROP ALL",
        "SELECT * WHERE { SERVICE <http://169.254.169.254/latest/meta-data/> { ?s ?p ?o } }",
    ] {
        let res = gw
            .call_tool(
                &alice,
                McpToolCall {
                    name: "wolin_query_semantic".to_string(),
                    arguments: json!({ "query": forbidden_sparql }),
                },
            )
            .await;
        assert!(
            res.is_error,
            "expected forbidden SPARQL '{forbidden_sparql}' to be rejected"
        );
    }

    // 2. Path traversal, encoded delimiters, reserved metadata, and foreign origins are blocked
    for bad_uri in [
        "wolin://pod/alice/../../etc/passwd",
        "wolin://pod/alice/%2e%2e/bob/secret.ttl",
        "wolin://pod/alice/notes%2fsecret.ttl",
        "wolin://pod/__wolin_meta/catalog.json",
        "/__wolin_meta/catalog.json",
        "https://evil.attacker.org/alice/profile.ttl",
        "file:///etc/shadow",
        "wolin://pod/alice/doc.ttl?bypass=1",
        "wolin://pod/alice/doc.ttl#frag",
    ] {
        let res = gw
            .call_tool(
                &alice,
                McpToolCall {
                    name: "wolin_read_resource".to_string(),
                    arguments: json!({ "uri": bad_uri }),
                },
            )
            .await;
        assert!(res.is_error, "expected bad URI '{bad_uri}' to be rejected");
    }

    // 3. Payload size limits enforced on both JSON-RPC envelope and `wolin_write_resource`
    let huge_rpc = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{{\"pad\":\"{}\"}}}}",
        "A".repeat(5000)
    );
    let huge_resp: Value =
        serde_json::from_str(&gw.handle_jsonrpc_str(&alice, &huge_rpc).await.unwrap()).unwrap();
    assert_eq!(huge_resp["error"]["code"], INVALID_REQUEST);

    let huge_write = gw
        .call_tool(
            &alice,
            McpToolCall {
                name: "wolin_write_resource".to_string(),
                arguments: json!({
                    "uri": "wolin://pod/alice/too_big.txt",
                    "content": "X".repeat(2048),
                    "content_type": "text/plain"
                }),
            },
        )
        .await;
    assert!(huge_write.is_error);

    // 4. Concurrent `wolin_write_resource` calls preserve 100% catalog & semantic graph integrity
    let mut tasks = Vec::new();
    for idx in 0..16u32 {
        let gw_clone = gw.clone();
        let alice_clone = alice.clone();
        tasks.push(tokio::spawn(async move {
            let uri = format!("wolin://pod/alice/concurrent/item_{idx:02}.ttl");
            let ttl = format!("<#item> <http://purl.org/dc/terms/identifier> \"item-{idx:02}\" .");
            let req = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: Some(wolin_mcp::protocol::JsonRpcId::Number(idx as i64)),
                method: "tools/call".to_string(),
                params: Some(json!({
                    "name": "wolin_write_resource",
                    "arguments": {
                        "uri": uri,
                        "content": ttl,
                        "content_type": "text/turtle"
                    }
                })),
            };
            let resp = gw_clone
                .handle_jsonrpc_value(&alice_clone, serde_json::to_value(req).unwrap())
                .await
                .expect("JSON-RPC response");
            assert_eq!(resp["result"]["isError"], false);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }

    let listed = extract_tool_json(
        &gw.call_tool(
            &alice,
            McpToolCall {
                name: "wolin_list_resources".to_string(),
                arguments: json!({ "uri": "wolin://pod/alice/concurrent/" }),
            },
        )
        .await,
    );
    assert_eq!(listed["count"], 16);

    let count_select = extract_tool_json(
        &gw.call_tool(
            &alice,
            McpToolCall {
                name: "wolin_query_semantic".to_string(),
                arguments: json!({
                    "query": "SELECT ?id WHERE { ?s <http://purl.org/dc/terms/identifier> ?id } ORDER BY ?id"
                }),
            },
        )
        .await,
    );
    assert_eq!(count_select["row_count"], 16);
    assert_eq!(count_select["rows"][0]["id"]["value"], "item-00");
    assert_eq!(count_select["rows"][15]["id"]["value"], "item-15");
}

#[tokio::test]
async fn adversarial_rdf_star_streaming_bounds_etag_oracle_and_strict_schema_guards() {
    let gw = build_default_gateway(false);
    let alice = DidResolver::resolve_principal(ALICE_DID).expect("alice DID");
    let restricted_agent = Principal::Agent {
        agent_id: "zero-pii-auditor".to_string(),
        delegated_by: WebId(ALICE_DID.to_string()),
        scope: vec!["read".to_string()],
    };

    // 1. Write RDF with secret + PII + 30 normal triples to test ETag secret oracle & streaming Cartesian join
    let mut bulk_ttl = String::from(
        "@prefix wolin: <https://wolin.io/ns#> .\n\
         @prefix schema: <https://schema.org/> .\n\
         <#me> wolin:secretApiKey \"super-secret-pin-9999\" ;\n\
               schema:email \"hidden@alice.wolin.id\" .\n",
    );
    for idx in 0..30 {
        bulk_ttl.push_str(&format!("<#n{idx}> wolin:tag \"tag-{idx:02}\" .\n"));
    }

    let owner_write = extract_tool_json(
        &gw.call_tool(
            &alice,
            McpToolCall {
                name: "wolin_write_resource".to_string(),
                arguments: json!({
                    "uri": "wolin://pod/alice/dataset.ttl",
                    "content": bulk_ttl,
                    "content_type": "text/turtle"
                }),
            },
        )
        .await,
    );
    let raw_owner_etag = owner_write["etag"].as_str().unwrap().to_string();

    // Agent reading redacted RDF MUST NOT receive raw unredacted owner ETag (prevents PIN/SSN length/hash brute-force)
    let agent_read = extract_tool_json(
        &gw.call_tool(
            &restricted_agent,
            McpToolCall {
                name: "wolin_read_resource".to_string(),
                arguments: json!({ "uri": "wolin://pod/alice/dataset.ttl" }),
            },
        )
        .await,
    );
    assert_ne!(
        agent_read["etag"].as_str().unwrap(),
        raw_owner_etag,
        "Redacted RDF read must compute ETag over projected output, never leaking raw owner ETag"
    );

    // 2. 4-way cross-join (`30^4 = 810,000` virtual combinations) streams cleanly via `.take(limit + 1)` without OOM
    let cartesian_select = extract_tool_json(
        &gw.call_tool(
            &restricted_agent,
            McpToolCall {
                name: "wolin_query_semantic".to_string(),
                arguments: json!({
                    "query": "SELECT ?a ?b ?c ?d WHERE { ?a ?p1 ?o1 . ?b ?p2 ?o2 . ?c ?p3 ?o3 . ?d ?p4 ?o4 }",
                    "target_uri": "wolin://pod/alice",
                    "limit": 5
                }),
            },
        )
        .await,
    );
    assert_eq!(cartesian_select["row_count"], 5);
    assert_eq!(cartesian_select["truncated"], true);

    // 3. Relative IRI resolution in SPARQL (`</alice/dataset.ttl#n0>`) preserved via `base_url`
    let rel_ask = extract_tool_json(
        &gw.call_tool(
            &restricted_agent,
            McpToolCall {
                name: "wolin_query_semantic".to_string(),
                arguments: json!({
                    "query": "ASK { </alice/dataset.ttl#n0> <https://wolin.io/ns#tag> \"tag-00\" }"
                }),
            },
        )
        .await,
    );
    assert_eq!(rel_ask["value"], true);

    // 4. Non-string `if_match`, unknown argument keys (`uri` typo on query), non-bool `recursive`, and empty `content_type` fail closed
    for bad_call in [
        McpToolCall {
            name: "wolin_write_resource".to_string(),
            arguments: json!({
                "uri": "wolin://pod/alice/dataset.ttl",
                "content": "<#x> <https://wolin.io/ns#tag> \"bad\" .",
                "if_match": 12345
            }),
        },
        McpToolCall {
            name: "wolin_write_resource".to_string(),
            arguments: json!({
                "uri": "wolin://pod/alice/dataset.ttl",
                "content": "raw",
                "content_type": ""
            }),
        },
        McpToolCall {
            name: "wolin_query_semantic".to_string(),
            arguments: json!({
                "query": "SELECT * WHERE { ?s ?p ?o }",
                "uri": "wolin://pod/alice/dataset.ttl"
            }),
        },
        McpToolCall {
            name: "wolin_query_semantic".to_string(),
            arguments: json!({
                "query": "SELECT * WHERE { ?s ?p ?o }",
                "target_uri": 999
            }),
        },
        McpToolCall {
            name: "wolin_list_resources".to_string(),
            arguments: json!({
                "uri": "wolin://pod/alice/",
                "recursive": "true"
            }),
        },
    ] {
        let rejected = gw.call_tool(&alice, bad_call).await;
        assert!(
            rejected.is_error,
            "expected strict argument validation failure"
        );
    }

    // 5. `application/octet-stream` UTF-8 secret text blob is scrubbed for restricted agents
    let secret_txt = format!(
        "token={} email=leak@alice.wolin.id",
        concat!("sk-", "SecretOctet987654")
    );
    let wr_octet = gw
        .call_tool(
            &alice,
            McpToolCall {
                name: "wolin_write_resource".to_string(),
                arguments: json!({
                    "uri": "wolin://pod/alice/raw_dump.bin",
                    "content": std_b64(secret_txt.as_bytes()),
                    "content_type": "application/octet-stream",
                    "encoding": "base64"
                }),
            },
        )
        .await;
    assert!(!wr_octet.is_error);

    let agent_octet = extract_tool_json(
        &gw.call_tool(
            &restricted_agent,
            McpToolCall {
                name: "wolin_read_resource".to_string(),
                arguments: json!({ "uri": "wolin://pod/alice/raw_dump.bin" }),
            },
        )
        .await,
    );
    let decoded_agent_bytes =
        wolin_mcp::uri::base64_decode(agent_octet["data"].as_str().unwrap()).unwrap();
    let decoded_str = String::from_utf8(decoded_agent_bytes).unwrap();
    assert!(!decoded_str.contains("SecretOctet987654"));
    assert!(!decoded_str.contains("leak@alice.wolin.id"));
    assert!(decoded_str.contains("[REDACTED_SECRET]"));
    assert!(decoded_str.contains("[REDACTED_EMAIL]"));
}
