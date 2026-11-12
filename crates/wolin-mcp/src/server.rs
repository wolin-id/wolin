use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use tracing::{info, warn};
use wolin_core::{Principal, ResourceKind, ResourceUri, Result};
use wolin_policy::{AccessDecision, AccessMode, PolicyEngine};
use wolin_storage::{
    rdf_io::{JsonLdProfileSet, RdfFormat},
    rdf_model::{
        GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Subject, Term, Triple,
    },
    rdf_sparql::{Query as SparqlQuery, QueryResults},
    ConstructGraph, PhysicalStore, RdfTerm, RdfTriple, SemanticGraphStore, SparqlBindingRow,
    SparqlBindingSet,
};

use crate::projection::{project_triples, DisclosurePolicy, DisclosureProfile};
use crate::protocol::{
    JsonRpcErrorObject, JsonRpcId, JsonRpcRequest, JsonRpcResponse, McpImplementationInfo,
    McpInitializeResult, McpListResourcesResult, McpListToolsResult, McpReadResourceResult,
    McpResourceContents, McpResourceDescriptor, McpResourcesCapability, McpServerCapabilities,
    McpToolCall, McpToolDescriptor, McpToolResult, McpToolsCapability, ACCESS_DENIED_ERROR,
    DEFAULT_MCP_PROTOCOL_VERSION, INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, JSONRPC_VERSION,
    METHOD_NOT_FOUND, PARSE_ERROR, RESOURCE_NOT_FOUND_ERROR,
};
use crate::uri::{
    base64_decode, base64_encode, compute_etag, map_named_graph_to_resolved_uri,
    resolve_catalog_key, resolve_pod_uri, CatalogEntry, PodCatalog, ResolvedPodUri,
};

const DEFAULT_MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_MAX_RESOURCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_BATCH_REQUESTS: usize = 64;
const MAX_SPARQL_QUERY_BYTES: usize = 64 * 1024;
const DEFAULT_SPARQL_LIMIT: usize = 250;
const MAX_SPARQL_LIMIT: usize = 1000;
const MAX_SANDBOX_QUADS: usize = 100_000;
const SPARQL_EXECUTION_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_LIST_LIMIT: usize = 100;
const MAX_LIST_LIMIT: usize = 500;

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const LDP_RESOURCE: &str = "http://www.w3.org/ns/ldp#Resource";
const LDP_CONTAINER: &str = "http://www.w3.org/ns/ldp#Container";
const LDP_BASIC_CONTAINER: &str = "http://www.w3.org/ns/ldp#BasicContainer";
const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";

enum BoundedSparqlOutput {
    Select {
        bindings: SparqlBindingSet,
        truncated: bool,
    },
    Construct {
        graph: ConstructGraph,
        truncated: bool,
    },
    Ask {
        value: bool,
    },
}

/// Configuration for [`McpAgentServer`].
#[derive(Debug, Clone)]
pub struct McpGatewayConfig {
    pub base_url: String,
    pub pod_uri_prefix: String,
    pub max_message_bytes: usize,
    pub max_resource_bytes: usize,
    pub policy_clock_epoch_secs: Option<i64>,
}

impl Default for McpGatewayConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:4000".to_string(),
            pod_uri_prefix: "wolin://pod".to_string(),
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_resource_bytes: DEFAULT_MAX_RESOURCE_BYTES,
            policy_clock_epoch_secs: None,
        }
    }
}

impl McpGatewayConfig {
    pub fn new(base_url: impl Into<String>, pod_uri_prefix: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            pod_uri_prefix: pod_uri_prefix.into().trim_end_matches('/').to_string(),
            ..Self::default()
        }
    }

    pub fn with_policy_clock(mut self, epoch_secs: i64) -> Self {
        self.policy_clock_epoch_secs = Some(epoch_secs);
        self
    }

    pub fn with_max_message_bytes(mut self, max_bytes: usize) -> Self {
        self.max_message_bytes = max_bytes;
        self
    }

    pub fn with_max_resource_bytes(mut self, max_bytes: usize) -> Self {
        self.max_resource_bytes = max_bytes;
        self
    }
}

/// Native MCP JSON-RPC 2.0 & Semantic Projection Gateway for Sovereign Solid Pods.
#[derive(Clone)]
pub struct McpAgentServer {
    physical_store: PhysicalStore,
    graph_store: SemanticGraphStore,
    policy_engine: Arc<RwLock<PolicyEngine>>,
    disclosure_policy: Arc<RwLock<DisclosurePolicy>>,
    catalog_lock: Arc<tokio::sync::RwLock<()>>,
    config: McpGatewayConfig,
}

pub type McpGateway = McpAgentServer;

impl McpAgentServer {
    pub fn new(
        physical_store: PhysicalStore,
        graph_store: SemanticGraphStore,
        policy_engine: PolicyEngine,
        config: McpGatewayConfig,
    ) -> Self {
        Self::with_shared_state(
            physical_store,
            graph_store,
            Arc::new(RwLock::new(policy_engine)),
            Arc::new(RwLock::new(DisclosurePolicy::new())),
            Arc::new(tokio::sync::RwLock::new(())),
            config,
        )
    }

    pub fn with_shared_state(
        physical_store: PhysicalStore,
        graph_store: SemanticGraphStore,
        policy_engine: Arc<RwLock<PolicyEngine>>,
        disclosure_policy: Arc<RwLock<DisclosurePolicy>>,
        catalog_lock: Arc<tokio::sync::RwLock<()>>,
        config: McpGatewayConfig,
    ) -> Self {
        Self {
            physical_store,
            graph_store,
            policy_engine,
            disclosure_policy,
            catalog_lock,
            config,
        }
    }

    pub fn new_in_memory(policy_engine: PolicyEngine, config: McpGatewayConfig) -> Result<Self> {
        let physical_store = PhysicalStore::new_memory()?;
        let graph_store = SemanticGraphStore::new_in_memory()?;
        Ok(Self::new(
            physical_store,
            graph_store,
            policy_engine,
            config,
        ))
    }

    pub fn with_disclosure_policy(self, policy: DisclosurePolicy) -> Self {
        {
            let mut guard = self
                .disclosure_policy
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *guard = policy;
        }
        self
    }

    pub fn with_policy_mut<R>(&self, f: impl FnOnce(&mut PolicyEngine) -> R) -> R {
        let mut guard = self
            .policy_engine
            .write()
            .unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    pub fn with_disclosure_mut<R>(&self, f: impl FnOnce(&mut DisclosurePolicy) -> R) -> R {
        let mut guard = self
            .disclosure_policy
            .write()
            .unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    pub fn physical_store(&self) -> &PhysicalStore {
        &self.physical_store
    }

    pub fn graph_store(&self) -> &SemanticGraphStore {
        &self.graph_store
    }

    pub fn config(&self) -> &McpGatewayConfig {
        &self.config
    }

    /// Process a raw UTF-8 JSON-RPC 2.0 message (single request, notification, or batch).
    /// Returns `None` for JSON-RPC notifications (messages omitting `id`).
    pub async fn handle_jsonrpc_str(
        &self,
        principal: &Principal,
        raw_json: &str,
    ) -> Option<String> {
        if raw_json.len() > self.config.max_message_bytes {
            let err = JsonRpcResponse::error(
                JsonRpcId::Null,
                INVALID_REQUEST,
                format!(
                    "JSON-RPC message exceeds maximum allowed size of {} bytes",
                    self.config.max_message_bytes
                ),
            );
            return serde_json::to_string(&err).ok();
        }

        let parsed: Value = match serde_json::from_str(raw_json) {
            Ok(v) => v,
            Err(e) => {
                let err = JsonRpcResponse::error(
                    JsonRpcId::Null,
                    PARSE_ERROR,
                    format!("Invalid JSON payload: {e}"),
                );
                return serde_json::to_string(&err).ok();
            }
        };

        let response_val = self.handle_jsonrpc_value(principal, parsed).await?;
        serde_json::to_string(&response_val).ok()
    }

    /// Process a parsed JSON-RPC 2.0 `Value` (single object or batch array).
    pub async fn handle_jsonrpc_value(
        &self,
        principal: &Principal,
        payload: Value,
    ) -> Option<Value> {
        match payload {
            Value::Object(map) => self
                .dispatch_single_object(principal, map)
                .await
                .and_then(|r| serde_json::to_value(r).ok()),
            Value::Array(items) => {
                if items.is_empty() {
                    return serde_json::to_value(JsonRpcResponse::error(
                        JsonRpcId::Null,
                        INVALID_REQUEST,
                        "JSON-RPC batch array must not be empty",
                    ))
                    .ok();
                }
                if items.len() > MAX_BATCH_REQUESTS {
                    return serde_json::to_value(JsonRpcResponse::error(
                        JsonRpcId::Null,
                        INVALID_REQUEST,
                        format!("JSON-RPC batch exceeds maximum of {MAX_BATCH_REQUESTS} items"),
                    ))
                    .ok();
                }

                let mut responses = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        Value::Object(map) => {
                            if let Some(resp) = self.dispatch_single_object(principal, map).await {
                                if let Ok(v) = serde_json::to_value(resp) {
                                    responses.push(v);
                                }
                            }
                        }
                        _ => {
                            if let Ok(v) = serde_json::to_value(JsonRpcResponse::error(
                                JsonRpcId::Null,
                                INVALID_REQUEST,
                                "Batch item must be a JSON-RPC request object",
                            )) {
                                responses.push(v);
                            }
                        }
                    }
                }

                if responses.is_empty() {
                    None
                } else {
                    Some(Value::Array(responses))
                }
            }
            _ => serde_json::to_value(JsonRpcResponse::error(
                JsonRpcId::Null,
                INVALID_REQUEST,
                "Top-level JSON-RPC payload must be an object or non-empty array",
            ))
            .ok(),
        }
    }

    /// Advertise the 4 Wolin MCP tools with strict JSON Schemas (`additionalProperties: false`).
    pub fn list_tools(&self) -> Vec<McpToolDescriptor> {
        vec![
            McpToolDescriptor {
                name: "wolin_query_semantic".to_string(),
                description: "Execute a read-only SPARQL 1.1 SELECT, CONSTRUCT, DESCRIBE, or ASK query over PDP-authorized Solid Pod RDF graphs with agent-scoped Zero-PII selective disclosure."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "query": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_SPARQL_QUERY_BYTES,
                            "description": "Read-only SPARQL 1.1 query (SELECT, CONSTRUCT, DESCRIBE, ASK). Mutations and federated SERVICE clauses are rejected."
                        },
                        "target_uri": {
                            "type": "string",
                            "minLength": 1,
                            "description": "Optional Pod resource or container URI (e.g. 'wolin://pod/alice/profile.ttl') to scope the query."
                        },
                        "format": {
                            "type": "string",
                            "enum": ["json", "turtle", "ntriples"],
                            "default": "json",
                            "description": "Serialization format for CONSTRUCT/DESCRIBE graph outputs."
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_SPARQL_LIMIT,
                            "default": DEFAULT_SPARQL_LIMIT,
                            "description": "Maximum SELECT bindings or CONSTRUCT triples returned."
                        }
                    },
                    "required": ["query"]
                }),
            },
            McpToolDescriptor {
                name: "wolin_read_resource".to_string(),
                description: "Read a Solid Pod resource (LDP RDF source, container, or binary Non-RDF blob) subject to WAC/ACP Read authorization and agent Zero-PII projection."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "uri": {
                            "type": "string",
                            "minLength": 1,
                            "description": "Target Pod resource URI ('wolin://pod/...' or '/...')."
                        },
                        "format": {
                            "type": "string",
                            "enum": ["turtle", "ntriples", "jsonld"],
                            "default": "turtle",
                            "description": "Desired RDF serialization format for RDF sources and containers."
                        }
                    },
                    "required": ["uri"]
                }),
            },
            McpToolDescriptor {
                name: "wolin_write_resource".to_string(),
                description: "Create or overwrite a Solid Pod resource (LDP RDF source, container, or binary Non-RDF blob) under WAC/ACP Write authorization. Preconditions: live PDP Write permit and optional If-Match ETag check. Reversibility: cleanly reversible via subsequent write; mutating '.acl' governance files is forbidden."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "uri": {
                            "type": "string",
                            "minLength": 1,
                            "description": "Target Pod resource URI ('wolin://pod/...' or '/...'). Container URIs end with '/'."
                        },
                        "content": {
                            "type": "string",
                            "description": "UTF-8 RDF/text content, or RFC 4648 base64 string when encoding is 'base64'."
                        },
                        "content_type": {
                            "type": "string",
                            "minLength": 3,
                            "default": "text/turtle",
                            "description": "MIME media type (e.g. 'text/turtle', 'application/n-triples', 'application/ld+json', 'text/plain', 'image/png', 'application/octet-stream')."
                        },
                        "encoding": {
                            "type": "string",
                            "enum": ["utf-8", "base64"],
                            "default": "utf-8",
                            "description": "Payload encoding of 'content'."
                        },
                        "if_match": {
                            "type": "string",
                            "minLength": 1,
                            "description": "Optional live ETag precondition to prevent lost updates."
                        }
                    },
                    "required": ["uri", "content"]
                }),
            },
            McpToolDescriptor {
                name: "wolin_list_resources".to_string(),
                description: "List Solid Pod resources and sub-containers under WAC/ACP container Read authorization, automatically filtering out unauthorized or ACP-denied entries."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "uri": {
                            "type": "string",
                            "minLength": 1,
                            "default": format!("{}/", self.config.pod_uri_prefix),
                            "description": "Target Pod container URI ('wolin://pod/alice/' or '/alice/')."
                        },
                        "recursive": {
                            "type": "boolean",
                            "default": false,
                            "description": "List all permitted descendants recursively instead of direct children only."
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_LIST_LIMIT,
                            "default": DEFAULT_LIST_LIMIT,
                            "description": "Maximum number of entries to return."
                        }
                    }
                }),
            },
        ]
    }

    /// Execute an MCP tool call on behalf of `principal`.
    /// Domain, validation, and authorization failures return `McpToolResult { is_error: true, ... }`
    /// per MCP tool execution error semantics.
    pub async fn call_tool(&self, principal: &Principal, call: McpToolCall) -> McpToolResult {
        let started = Instant::now();
        let actor = principal_audit_label(principal);
        let safe_tool = sanitize_for_audit(&call.name);
        info!(
            audit = "[AUDIT_REQUEST]",
            caller = %actor,
            tool = %safe_tool,
            "MCP tool invocation received"
        );

        let Some(args) = call.arguments.as_object() else {
            warn!(
                audit = "[AUDIT_DENIED]",
                caller = %actor,
                tool = %safe_tool,
                latency_us = started.elapsed().as_micros() as u64,
                "Rejected non-object tool arguments"
            );
            return McpToolResult::err_text("Tool arguments must be a JSON object");
        };

        let result = match call.name.as_str() {
            "wolin_query_semantic" => self.exec_query_semantic(principal, args).await,
            "wolin_read_resource" => self.exec_read_resource(principal, args).await,
            "wolin_write_resource" => self.exec_write_resource(principal, args).await,
            "wolin_list_resources" => self.exec_list_resources(principal, args).await,
            unknown => {
                McpToolResult::err_text(format!("Unknown tool: {}", sanitize_for_audit(unknown)))
            }
        };

        let latency_us = started.elapsed().as_micros() as u64;
        if result.is_error {
            warn!(
                audit = "[AUDIT_DENIED]",
                caller = %actor,
                tool = %safe_tool,
                latency_us,
                "MCP tool call ended with error/denial"
            );
        } else {
            info!(
                audit = "[AUDIT_SUCCESS]",
                caller = %actor,
                tool = %safe_tool,
                latency_us,
                "MCP tool call succeeded"
            );
        }

        result
    }

    /// Convenience wrapper returning `wolin_core::Result<McpToolResult>`.
    pub async fn handle_tool_call(
        &self,
        principal: &Principal,
        call: McpToolCall,
    ) -> Result<McpToolResult> {
        Ok(self.call_tool(principal, call).await)
    }

    /// Standard MCP `resources/list` handler filtered by live PDP `Read` permissions.
    pub async fn list_resources(
        &self,
        principal: &Principal,
        cursor: Option<&str>,
    ) -> std::result::Result<McpListResourcesResult, JsonRpcErrorObject> {
        let started = Instant::now();
        let actor = principal_audit_label(principal);
        info!(
            audit = "[AUDIT_REQUEST]",
            caller = %actor,
            method = "resources/list",
            "MCP resources/list received"
        );

        let res = self.list_resources_inner(principal, cursor).await;
        let latency_us = started.elapsed().as_micros() as u64;
        match &res {
            Ok(_) => info!(
                audit = "[AUDIT_SUCCESS]",
                caller = %actor,
                method = "resources/list",
                latency_us,
                "MCP resources/list succeeded"
            ),
            Err(_) => warn!(
                audit = "[AUDIT_DENIED]",
                caller = %actor,
                method = "resources/list",
                latency_us,
                "MCP resources/list denied/failed"
            ),
        }
        res
    }

    async fn list_resources_inner(
        &self,
        principal: &Principal,
        cursor: Option<&str>,
    ) -> std::result::Result<McpListResourcesResult, JsonRpcErrorObject> {
        let offset = match cursor {
            None | Some("") => 0usize,
            Some(c) => c.parse::<usize>().map_err(|_| {
                JsonRpcErrorObject::new(
                    INVALID_PARAMS,
                    format!("Invalid pagination cursor '{}'", sanitize_for_audit(c)),
                )
            })?,
        };

        let _read_guard = self.catalog_lock.read().await;
        let catalog = PodCatalog::load_or_init(&self.physical_store)
            .await
            .map_err(|e| JsonRpcErrorObject::new(INTERNAL_ERROR, e.to_string()))?;

        let mut permitted_leafs = Vec::new();
        let mut any_entry_permitted = false;
        let mut first_deny_reason: Option<String> = None;

        for (key, entry) in &catalog.entries {
            if key.ends_with(".acl") {
                continue;
            }
            let Ok(resolved) =
                resolve_catalog_key(key, &self.config.base_url, &self.config.pod_uri_prefix)
            else {
                continue;
            };
            match self.evaluate_pdp(principal, &resolved.policy_target, AccessMode::Read) {
                AccessDecision::Permit => {
                    any_entry_permitted = true;
                    if entry.kind != ResourceKind::Container {
                        let leaf_name = resolved
                            .canonical_path
                            .trim_end_matches('/')
                            .rsplit('/')
                            .next()
                            .unwrap_or(&resolved.canonical_path)
                            .to_string();
                        permitted_leafs.push(McpResourceDescriptor {
                            uri: resolved.display_uri,
                            name: leaf_name,
                            description: Some(format!("{:?} Pod resource", entry.kind)),
                            mime_type: Some(entry.content_type.clone()),
                        });
                    }
                }
                AccessDecision::Deny { reason } => {
                    if first_deny_reason.is_none() {
                        first_deny_reason = Some(reason);
                    }
                }
            }
        }

        // Reject unauthorized/revoked/ungranted AI agents with zero read authority on the Pod
        if matches!(principal, Principal::Agent { .. }) && !any_entry_permitted {
            let root_uri = ResourceUri(self.config.pod_uri_prefix.clone());
            let root_dec = self.evaluate_pdp(principal, &root_uri, AccessMode::Read);
            if !root_dec.is_permit() {
                let reason = match root_dec {
                    AccessDecision::Deny { reason } => reason,
                    AccessDecision::Permit => first_deny_reason
                        .unwrap_or_else(|| "Agent lacks read authorization on Pod".to_string()),
                };
                return Err(JsonRpcErrorObject::new(
                    ACCESS_DENIED_ERROR,
                    format!("Access denied: {reason}"),
                ));
            }
        }

        let total = permitted_leafs.len();
        let slice_end = offset.saturating_add(DEFAULT_LIST_LIMIT).min(total);
        let page = if offset < total {
            permitted_leafs[offset..slice_end].to_vec()
        } else {
            Vec::new()
        };
        let next_cursor = if slice_end < total {
            Some(slice_end.to_string())
        } else {
            None
        };

        Ok(McpListResourcesResult {
            resources: page,
            next_cursor,
        })
    }

    /// Standard MCP `resources/read` handler enforcing PDP `Read` and Zero-PII RDF projection.
    pub async fn read_resource(
        &self,
        principal: &Principal,
        uri: &str,
    ) -> std::result::Result<McpReadResourceResult, JsonRpcErrorObject> {
        let started = Instant::now();
        let actor = principal_audit_label(principal);
        let safe_uri = sanitize_for_audit(uri);
        info!(
            audit = "[AUDIT_REQUEST]",
            caller = %actor,
            method = "resources/read",
            uri = %safe_uri,
            "MCP resources/read received"
        );

        let res = self.read_resource_inner(principal, uri).await;
        let latency_us = started.elapsed().as_micros() as u64;
        match &res {
            Ok(_) => info!(
                audit = "[AUDIT_SUCCESS]",
                caller = %actor,
                method = "resources/read",
                uri = %safe_uri,
                latency_us,
                "MCP resources/read succeeded"
            ),
            Err(_) => warn!(
                audit = "[AUDIT_DENIED]",
                caller = %actor,
                method = "resources/read",
                uri = %safe_uri,
                latency_us,
                "MCP resources/read denied/failed"
            ),
        }
        res
    }

    async fn read_resource_inner(
        &self,
        principal: &Principal,
        uri: &str,
    ) -> std::result::Result<McpReadResourceResult, JsonRpcErrorObject> {
        let resolved = resolve_pod_uri(
            uri,
            &self.config.base_url,
            &self.config.pod_uri_prefix,
            false,
        )
        .map_err(|e| JsonRpcErrorObject::new(INVALID_PARAMS, e.to_string()))?;

        if resolved.is_acl && !matches!(principal, Principal::User { .. }) {
            return Err(JsonRpcErrorObject::new(
                ACCESS_DENIED_ERROR,
                "Access denied: AI agents and anonymous callers cannot read '.acl' governance documents",
            ));
        }

        let mode = if resolved.is_acl {
            AccessMode::Control
        } else {
            AccessMode::Read
        };
        if let AccessDecision::Deny { reason } =
            self.evaluate_pdp(principal, &resolved.policy_target, mode)
        {
            return Err(JsonRpcErrorObject::new(
                ACCESS_DENIED_ERROR,
                format!("Access denied: {reason}"),
            ));
        }

        // Hold catalog read lock across storage read for snapshot consistency (prevents torn reads)
        let _read_guard = self.catalog_lock.read().await;
        let catalog = PodCatalog::load_or_init(&self.physical_store)
            .await
            .map_err(|e| JsonRpcErrorObject::new(INTERNAL_ERROR, e.to_string()))?;

        let Some(entry) = catalog.entries.get(&resolved.catalog_key).cloned() else {
            return Err(JsonRpcErrorObject::new(
                RESOURCE_NOT_FOUND_ERROR,
                format!("Pod resource '{}' not found", resolved.display_uri),
            ));
        };

        match entry.kind {
            ResourceKind::Container | ResourceKind::RdfSource => {
                let raw_triples = self
                    .collect_rdf_or_container_triples(principal, &catalog, &resolved, entry.kind)
                    .map_err(|e| JsonRpcErrorObject::new(INTERNAL_ERROR, e.to_string()))?;
                let projected = if resolved.is_acl {
                    raw_triples
                } else {
                    self.apply_disclosure_projection(principal, &raw_triples)
                        .triples
                };
                let bytes = SemanticGraphStore::serialize_triples(&projected, RdfFormat::Turtle)
                    .map_err(|e| JsonRpcErrorObject::new(INTERNAL_ERROR, e.to_string()))?;
                if bytes.len() > self.config.max_resource_bytes {
                    return Err(JsonRpcErrorObject::new(
                        INVALID_REQUEST,
                        "Serialized RDF resource exceeds maximum outbound size budget",
                    ));
                }
                let text = String::from_utf8(bytes)
                    .map_err(|e| JsonRpcErrorObject::new(INTERNAL_ERROR, e.to_string()))?;
                Ok(McpReadResourceResult {
                    contents: vec![McpResourceContents {
                        uri: resolved.display_uri,
                        mime_type: Some("text/turtle".to_string()),
                        text: Some(text),
                        blob: None,
                    }],
                })
            }
            ResourceKind::NonRdfSource => {
                let meta = self
                    .physical_store
                    .stat(&resolved.blob_key)
                    .await
                    .map_err(|e| {
                        JsonRpcErrorObject::new(RESOURCE_NOT_FOUND_ERROR, e.to_string())
                    })?;
                let max_blob = self.max_outbound_blob_bytes();
                if meta.content_length > max_blob as u64 {
                    return Err(JsonRpcErrorObject::new(
                        INVALID_REQUEST,
                        format!(
                            "Pod blob '{}' ({} bytes) exceeds maximum outbound limit ({max_blob} bytes)",
                            resolved.display_uri, meta.content_length
                        ),
                    ));
                }

                let bytes = self
                    .physical_store
                    .get(&resolved.blob_key)
                    .await
                    .map_err(|e| {
                        JsonRpcErrorObject::new(RESOURCE_NOT_FOUND_ERROR, e.to_string())
                    })?;
                if is_scrubbable_utf8_media_type(&entry.content_type) {
                    if let Ok(raw_text) = String::from_utf8(bytes.clone()) {
                        let scrubbed = self.scrub_text_for_principal(principal, &raw_text);
                        return Ok(McpReadResourceResult {
                            contents: vec![McpResourceContents {
                                uri: resolved.display_uri,
                                mime_type: Some(entry.content_type),
                                text: Some(scrubbed),
                                blob: None,
                            }],
                        });
                    }
                }
                let final_bytes =
                    self.scrub_binary_fallback_if_utf8_text(principal, &entry.content_type, bytes);
                Ok(McpReadResourceResult {
                    contents: vec![McpResourceContents {
                        uri: resolved.display_uri,
                        mime_type: Some(entry.content_type),
                        text: None,
                        blob: Some(base64_encode(&final_bytes)),
                    }],
                })
            }
        }
    }

    async fn dispatch_single_object(
        &self,
        principal: &Principal,
        map: Map<String, Value>,
    ) -> Option<JsonRpcResponse> {
        let has_id_member = map.contains_key("id");
        let parsed_id = match map.get("id") {
            Some(v) => match JsonRpcId::from_json_value(v) {
                Ok(id) => Some(id),
                Err(msg) => {
                    return Some(JsonRpcResponse::error(
                        JsonRpcId::Null,
                        INVALID_REQUEST,
                        msg,
                    ))
                }
            },
            None => None,
        };

        let error_id = parsed_id.clone().unwrap_or(JsonRpcId::Null);

        match map.get("jsonrpc") {
            Some(Value::String(v)) if v == JSONRPC_VERSION => {}
            _ => {
                return Some(JsonRpcResponse::error(
                    error_id,
                    INVALID_REQUEST,
                    "Missing or unsupported 'jsonrpc' version (expected '2.0')",
                ));
            }
        }

        let method = match map.get("method") {
            Some(Value::String(m)) if !m.trim().is_empty() => m.as_str(),
            _ => {
                return Some(JsonRpcResponse::error(
                    error_id,
                    INVALID_REQUEST,
                    "Missing or empty 'method' string in JSON-RPC request",
                ));
            }
        };

        let params = map.get("params");
        if let Some(p) = params {
            if !matches!(p, Value::Object(_) | Value::Array(_) | Value::Null) {
                return if has_id_member {
                    Some(JsonRpcResponse::error(
                        error_id,
                        INVALID_PARAMS,
                        "JSON-RPC 'params' must be an object or array",
                    ))
                } else {
                    None
                };
            }
        }

        // JSON-RPC 2.0 Notification (`id` member omitted): execute silently and emit NO response.
        if !has_id_member {
            return None;
        }
        let req_id = parsed_id.unwrap_or(JsonRpcId::Null);

        let outcome: std::result::Result<Value, JsonRpcErrorObject> = match method {
            "initialize" => self.rpc_initialize(params),
            "ping" => Ok(json!({})),
            "tools/list" => self.rpc_tools_list(params),
            "tools/call" => self.rpc_tools_call(principal, params).await,
            "resources/list" => self.rpc_resources_list(principal, params).await,
            "resources/read" => self.rpc_resources_read(principal, params).await,
            "resources/templates/list" => Ok(json!({ "resourceTemplates": [] })),
            "prompts/list" => Ok(json!({ "prompts": [] })),
            unknown => Err(JsonRpcErrorObject::new(
                METHOD_NOT_FOUND,
                format!("Method not found: {}", sanitize_for_audit(unknown)),
            )),
        };

        match outcome {
            Ok(res_val) => Some(JsonRpcResponse::success(req_id, res_val)),
            Err(err_obj) => Some(JsonRpcResponse::from_error_object(req_id, err_obj)),
        }
    }

    fn rpc_initialize(
        &self,
        params: Option<&Value>,
    ) -> std::result::Result<Value, JsonRpcErrorObject> {
        let negotiated_version = match params {
            None | Some(Value::Null) => DEFAULT_MCP_PROTOCOL_VERSION.to_string(),
            Some(Value::Object(obj)) => match obj.get("protocolVersion") {
                None | Some(Value::Null) => DEFAULT_MCP_PROTOCOL_VERSION.to_string(),
                Some(Value::String(ver)) if is_valid_mcp_date_version(ver) => ver.clone(),
                _ => {
                    return Err(JsonRpcErrorObject::new(
                        INVALID_PARAMS,
                        "Invalid 'protocolVersion': expected valid YYYY-MM-DD calendar date",
                    ));
                }
            },
            _ => {
                return Err(JsonRpcErrorObject::new(
                    INVALID_PARAMS,
                    "'initialize' params must be a JSON object",
                ));
            }
        };

        let init = McpInitializeResult {
            protocol_version: negotiated_version,
            capabilities: McpServerCapabilities {
                tools: McpToolsCapability {
                    list_changed: false,
                },
                resources: McpResourcesCapability {
                    subscribe: false,
                    list_changed: false,
                },
                prompts: None,
            },
            server_info: McpImplementationInfo {
                name: "wolin-mcp".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        };
        serde_json::to_value(init).map_err(|e| {
            JsonRpcErrorObject::new(INTERNAL_ERROR, format!("Serialization failed: {e}"))
        })
    }

    fn rpc_tools_list(
        &self,
        params: Option<&Value>,
    ) -> std::result::Result<Value, JsonRpcErrorObject> {
        match params {
            None | Some(Value::Null) => {}
            Some(Value::Object(obj)) => {
                if let Some(cursor_val) = obj.get("cursor") {
                    if !cursor_val.is_null() {
                        let c = cursor_val.as_str().ok_or_else(|| {
                            JsonRpcErrorObject::new(INVALID_PARAMS, "'cursor' must be a string")
                        })?;
                        if !c.is_empty() {
                            return Err(JsonRpcErrorObject::new(
                                INVALID_PARAMS,
                                format!("Unknown tools/list cursor '{}'", sanitize_for_audit(c)),
                            ));
                        }
                    }
                }
            }
            _ => {
                return Err(JsonRpcErrorObject::new(
                    INVALID_PARAMS,
                    "'tools/list' params must be a JSON object",
                ));
            }
        }
        let res = McpListToolsResult {
            tools: self.list_tools(),
        };
        serde_json::to_value(res).map_err(|e| {
            JsonRpcErrorObject::new(INTERNAL_ERROR, format!("Serialization failed: {e}"))
        })
    }

    async fn rpc_tools_call(
        &self,
        principal: &Principal,
        params: Option<&Value>,
    ) -> std::result::Result<Value, JsonRpcErrorObject> {
        let Some(Value::Object(obj)) = params else {
            return Err(JsonRpcErrorObject::new(
                INVALID_PARAMS,
                "'tools/call' requires a params object with 'name'",
            ));
        };
        let name = match obj.get("name") {
            Some(Value::String(s)) if !s.trim().is_empty() => s.clone(),
            _ => {
                return Err(JsonRpcErrorObject::new(
                    INVALID_PARAMS,
                    "'tools/call' requires non-empty string 'name'",
                ));
            }
        };
        let arguments = match obj.get("arguments") {
            None | Some(Value::Null) => json!({}),
            Some(v @ Value::Object(_)) => v.clone(),
            _ => {
                return Err(JsonRpcErrorObject::new(
                    INVALID_PARAMS,
                    "'tools/call' field 'arguments' must be a JSON object",
                ));
            }
        };

        let tool_result = self
            .call_tool(principal, McpToolCall { name, arguments })
            .await;
        serde_json::to_value(tool_result).map_err(|e| {
            JsonRpcErrorObject::new(INTERNAL_ERROR, format!("Serialization failed: {e}"))
        })
    }

    async fn rpc_resources_list(
        &self,
        principal: &Principal,
        params: Option<&Value>,
    ) -> std::result::Result<Value, JsonRpcErrorObject> {
        let cursor = match params {
            None | Some(Value::Null) => None,
            Some(Value::Object(obj)) => match obj.get("cursor") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => Some(s.as_str()),
                _ => {
                    return Err(JsonRpcErrorObject::new(
                        INVALID_PARAMS,
                        "'cursor' must be a string",
                    ));
                }
            },
            _ => {
                return Err(JsonRpcErrorObject::new(
                    INVALID_PARAMS,
                    "'resources/list' params must be a JSON object",
                ));
            }
        };

        let result = self.list_resources(principal, cursor).await?;
        serde_json::to_value(result).map_err(|e| {
            JsonRpcErrorObject::new(INTERNAL_ERROR, format!("Serialization failed: {e}"))
        })
    }

    async fn rpc_resources_read(
        &self,
        principal: &Principal,
        params: Option<&Value>,
    ) -> std::result::Result<Value, JsonRpcErrorObject> {
        let Some(Value::Object(obj)) = params else {
            return Err(JsonRpcErrorObject::new(
                INVALID_PARAMS,
                "'resources/read' requires a params object with 'uri'",
            ));
        };
        let uri = match obj.get("uri") {
            Some(Value::String(s)) if !s.trim().is_empty() => s.as_str(),
            _ => {
                return Err(JsonRpcErrorObject::new(
                    INVALID_PARAMS,
                    "'resources/read' requires non-empty string 'uri'",
                ));
            }
        };

        let result = self.read_resource(principal, uri).await?;
        serde_json::to_value(result).map_err(|e| {
            JsonRpcErrorObject::new(INTERNAL_ERROR, format!("Serialization failed: {e}"))
        })
    }

    // -------------------------------------------------------------------------
    // Tool 1: wolin_query_semantic
    // -------------------------------------------------------------------------
    async fn exec_query_semantic(
        &self,
        principal: &Principal,
        args: &Map<String, Value>,
    ) -> McpToolResult {
        if let Err(msg) = reject_unknown_args(args, &["query", "target_uri", "format", "limit"]) {
            return McpToolResult::err_text(msg);
        }

        let Some(query_str) = args.get("query").and_then(Value::as_str) else {
            return McpToolResult::err_text("Missing required string argument 'query'");
        };
        let trimmed_query = query_str.trim();
        if trimmed_query.is_empty() || trimmed_query.len() > MAX_SPARQL_QUERY_BYTES {
            return McpToolResult::err_text(format!(
                "SPARQL query must be between 1 and {MAX_SPARQL_QUERY_BYTES} bytes"
            ));
        }

        let limit = match args.get("limit") {
            None | Some(Value::Null) => DEFAULT_SPARQL_LIMIT,
            Some(v) => match v.as_u64() {
                Some(n) if (1..=MAX_SPARQL_LIMIT as u64).contains(&n) => n as usize,
                _ => {
                    return McpToolResult::err_text(format!(
                        "'limit' must be an integer between 1 and {MAX_SPARQL_LIMIT}"
                    ));
                }
            },
        };

        let output_format = match args.get("format") {
            None | Some(Value::Null) => "turtle",
            Some(Value::String(s)) => match s.as_str() {
                "json" | "turtle" => "turtle",
                "ntriples" => "ntriples",
                other => {
                    return McpToolResult::err_text(format!(
                        "Unsupported 'format' '{other}'; expected 'json', 'turtle', or 'ntriples'"
                    ));
                }
            },
            Some(_) => return McpToolResult::err_text("Argument 'format' must be a string"),
        };

        // Parse & enforce read-only SPARQL 1.1 Query with configured Pod base IRI
        let parsed_query = match SparqlQuery::parse(trimmed_query, Some(&self.config.base_url)) {
            Ok(q) => q,
            Err(e) => {
                return McpToolResult::err_text(format!("Invalid read-only SPARQL query: {e}"))
            }
        };
        if contains_federated_service_clause(&parsed_query.to_string())
            || contains_federated_service_clause(trimmed_query)
        {
            return McpToolResult::err_text(
                "Federated SPARQL 'SERVICE' clauses are forbidden (SSRF protection)",
            );
        }

        let raw_target_opt = match extract_optional_nonempty_str(args, "target_uri") {
            Ok(opt) => opt,
            Err(msg) => return McpToolResult::err_text(msg),
        };

        // Hold catalog read lock across graph enumeration & triple reads for snapshot consistency
        let _read_guard = self.catalog_lock.read().await;
        let catalog = match PodCatalog::load_or_init(&self.physical_store).await {
            Ok(c) => c,
            Err(e) => return McpToolResult::err_text(e.to_string()),
        };

        let scoped_target = match raw_target_opt {
            Some(raw_target) => {
                let mut resolved = match resolve_pod_uri(
                    raw_target,
                    &self.config.base_url,
                    &self.config.pod_uri_prefix,
                    false,
                ) {
                    Ok(r) => r,
                    Err(e) => return McpToolResult::err_text(e.to_string()),
                };
                if resolved.is_acl {
                    return McpToolResult::err_text(
                        "Access denied: '.acl' governance graphs cannot be queried via wolin_query_semantic",
                    );
                }
                // Upgrade container path without trailing `/` when registered as a Container in PodCatalog
                if !resolved.is_container {
                    let container_candidate = format!("{}/", resolved.catalog_key);
                    if catalog
                        .entries
                        .get(&container_candidate)
                        .is_some_and(|e| e.kind == ResourceKind::Container)
                    {
                        if let Ok(upgraded) = resolve_pod_uri(
                            raw_target,
                            &self.config.base_url,
                            &self.config.pod_uri_prefix,
                            true,
                        ) {
                            resolved = upgraded;
                        }
                    }
                }
                if let AccessDecision::Deny { reason } =
                    self.evaluate_pdp(principal, &resolved.policy_target, AccessMode::Read)
                {
                    return McpToolResult::err_text(format!("Access denied: {reason}"));
                }
                Some(resolved)
            }
            None => None,
        };

        let (disclosure_profile, disclosure_snapshot) = {
            let guard = self
                .disclosure_policy
                .read()
                .unwrap_or_else(|e| e.into_inner());
            (DisclosureProfile::resolve(principal, &guard), guard.clone())
        };

        let mut staged_quads: Vec<Quad> = Vec::new();
        let mut projected_graphs = 0usize;
        let mut total_redacted_triples = 0usize;
        let mut first_deny_reason: Option<String> = None;

        // 1. Project PDP-permitted Cataloged Named Graphs (deterministic sorted order)
        let mut named_graphs: Vec<NamedNode> = Vec::new();
        for ng_res in self.graph_store.inner().named_graphs() {
            match ng_res {
                Ok(NamedOrBlankNode::NamedNode(n)) => named_graphs.push(n),
                Ok(NamedOrBlankNode::BlankNode(_)) => {}
                Err(e) => {
                    return McpToolResult::err_text(format!(
                        "Oxigraph named_graphs read failed: {e}"
                    ))
                }
            }
        }
        named_graphs.sort();

        for gn in named_graphs {
            let graph_iri = gn.as_str();
            let Some(graph_resolved) = map_named_graph_to_resolved_uri(
                graph_iri,
                &self.config.base_url,
                &self.config.pod_uri_prefix,
            ) else {
                continue;
            };

            // Enforce catalog membership so uncommitted/orphaned graphs or non-RDF entries cannot leak
            match catalog.entries.get(&graph_resolved.catalog_key) {
                Some(entry)
                    if matches!(
                        entry.kind,
                        ResourceKind::RdfSource | ResourceKind::Container
                    ) => {}
                _ => continue,
            }

            if let Some(ref filter) = scoped_target {
                if !target_scope_matches_graph(
                    &filter.policy_target.0,
                    filter.is_container,
                    &graph_resolved.policy_target.0,
                ) {
                    continue;
                }
            }

            match self.evaluate_pdp(principal, &graph_resolved.policy_target, AccessMode::Read) {
                AccessDecision::Permit => {
                    let raw_triples = match self.graph_store.get_named_graph_triples(graph_iri) {
                        Ok(t) => t,
                        Err(e) => return McpToolResult::err_text(e.to_string()),
                    };
                    let proj =
                        project_triples(&raw_triples, &disclosure_profile, &disclosure_snapshot);
                    total_redacted_triples += proj.redacted_triples;
                    projected_graphs += 1;

                    let needed = proj.triples.len().saturating_mul(2);
                    if staged_quads.len().saturating_add(needed) > MAX_SANDBOX_QUADS {
                        return McpToolResult::err_text(format!(
                            "Projected semantic dataset exceeds maximum sandbox budget ({MAX_SANDBOX_QUADS} quads); narrow query with 'target_uri'"
                        ));
                    }

                    for t in proj.triples {
                        staged_quads.push(Quad::new(
                            t.subject.clone(),
                            t.predicate.clone(),
                            t.object.clone(),
                            GraphName::NamedNode(gn.clone()),
                        ));
                        staged_quads.push(Quad::new(
                            t.subject,
                            t.predicate,
                            t.object,
                            GraphName::DefaultGraph,
                        ));
                    }
                }
                AccessDecision::Deny { reason } => {
                    if first_deny_reason.is_none() {
                        first_deny_reason = Some(reason);
                    }
                }
            }
        }

        // 2. Project DefaultGraph triples strictly under Pod root authorization (no '/semantic' path collision or '||' ACP bypass)
        if scoped_target.is_none() {
            let mut default_triples = Vec::new();
            for q_res in self.graph_store.inner().quads_for_pattern(
                None,
                None,
                None,
                Some(GraphNameRef::DefaultGraph),
            ) {
                match q_res {
                    Ok(q) => default_triples.push(Triple::from(q)),
                    Err(e) => {
                        return McpToolResult::err_text(format!(
                            "Oxigraph default graph read failed: {e}"
                        ))
                    }
                }
            }
            if !default_triples.is_empty() {
                let root_uri = ResourceUri(self.config.pod_uri_prefix.clone());
                match self.evaluate_pdp(principal, &root_uri, AccessMode::Read) {
                    AccessDecision::Permit => {
                        let proj = project_triples(
                            &default_triples,
                            &disclosure_profile,
                            &disclosure_snapshot,
                        );
                        if staged_quads.len().saturating_add(proj.triples.len()) > MAX_SANDBOX_QUADS
                        {
                            return McpToolResult::err_text(format!(
                                "Projected semantic dataset exceeds maximum sandbox budget ({MAX_SANDBOX_QUADS} quads)"
                            ));
                        }
                        total_redacted_triples += proj.redacted_triples;
                        projected_graphs += 1;
                        for t in proj.triples {
                            staged_quads.push(Quad::new(
                                t.subject,
                                t.predicate,
                                t.object,
                                GraphName::DefaultGraph,
                            ));
                        }
                    }
                    AccessDecision::Deny { reason } => {
                        if first_deny_reason.is_none() {
                            first_deny_reason = Some(reason);
                        }
                    }
                }
            }
        }

        // 3. Fail closed if caller has zero authorized graphs AND no Pod Read permission
        if projected_graphs == 0 && scoped_target.is_none() {
            let root_uri = ResourceUri(self.config.pod_uri_prefix.clone());
            let root_dec = self.evaluate_pdp(principal, &root_uri, AccessMode::Read);
            if !root_dec.is_permit() {
                let catalog_permitted = catalog.entries.keys().any(|k| {
                    !k.ends_with(".acl")
                        && resolve_catalog_key(
                            k,
                            &self.config.base_url,
                            &self.config.pod_uri_prefix,
                        )
                        .is_ok_and(|r| {
                            self.evaluate_pdp(principal, &r.policy_target, AccessMode::Read)
                                .is_permit()
                        })
                });
                if !catalog_permitted {
                    let reason = match root_dec {
                        AccessDecision::Deny { reason } => reason,
                        AccessDecision::Permit => first_deny_reason
                            .unwrap_or_else(|| "No readable semantic graphs permitted".to_string()),
                    };
                    return McpToolResult::err_text(format!("Access denied: {reason}"));
                }
            }
        }
        drop(_read_guard);

        // 4. Offload sandbox materialization + bounded streaming SPARQL evaluation to blocking pool with deadline
        let blocking_task = tokio::task::spawn_blocking(move || {
            execute_bounded_sparql_in_sandbox(staged_quads, parsed_query, limit)
        });

        let query_output = match tokio::time::timeout(SPARQL_EXECUTION_TIMEOUT, blocking_task).await
        {
            Ok(Ok(Ok(out))) => out,
            Ok(Ok(Err(err_msg))) => return McpToolResult::err_text(err_msg),
            Ok(Err(join_err)) => {
                return McpToolResult::err_text(format!(
                    "SPARQL worker execution error: {join_err}"
                ))
            }
            Err(_) => {
                return McpToolResult::err_text("SPARQL query exceeded execution time budget (5s)")
            }
        };

        let projection_meta = json!({
            "zero_pii_enforced": disclosure_profile.zero_pii_enforced,
            "disclosed_categories": disclosure_profile.allowed_categories,
            "projected_graphs": projected_graphs,
            "redacted_triples": total_redacted_triples,
        });

        let max_outbound = self.config.max_message_bytes.saturating_div(2).max(1024);

        match query_output {
            BoundedSparqlOutput::Select {
                bindings,
                truncated,
            } => {
                let row_count = bindings.rows.len();
                let payload = json!({
                    "query_type": "select",
                    "variables": bindings.variables,
                    "rows": bindings.rows,
                    "row_count": row_count,
                    "truncated": truncated,
                    "projection": projection_meta,
                });
                let text = match serde_json::to_string(&payload) {
                    Ok(s) => s,
                    Err(e) => return McpToolResult::err_text(e.to_string()),
                };
                if text.len() > self.config.max_message_bytes {
                    return McpToolResult::err_text(
                        "SPARQL SELECT result exceeds maximum outbound message size; reduce 'limit'",
                    );
                }
                McpToolResult::ok_text(text)
            }
            BoundedSparqlOutput::Construct { graph, truncated } => {
                let (serialized, mime) = if output_format == "ntriples" {
                    match graph.to_ntriples() {
                        Ok(s) => (s, "application/n-triples"),
                        Err(e) => return McpToolResult::err_text(e.to_string()),
                    }
                } else {
                    match graph.to_turtle() {
                        Ok(s) => (s, "text/turtle"),
                        Err(e) => return McpToolResult::err_text(e.to_string()),
                    }
                };
                if serialized.len() > max_outbound {
                    return McpToolResult::err_text(
                        "SPARQL CONSTRUCT graph exceeds maximum outbound message size; reduce 'limit'",
                    );
                }
                let triple_count = graph.triples.len();
                McpToolResult::ok_json(&json!({
                    "query_type": "construct",
                    "triples": graph.triples,
                    "triple_count": triple_count,
                    "serialized_rdf": serialized,
                    "rdf_format": mime,
                    "truncated": truncated,
                    "projection": projection_meta,
                }))
            }
            BoundedSparqlOutput::Ask { value } => McpToolResult::ok_json(&json!({
                "query_type": "ask",
                "value": value,
                "projection": projection_meta,
            })),
        }
    }

    // -------------------------------------------------------------------------
    // Tool 2: wolin_read_resource
    // -------------------------------------------------------------------------
    async fn exec_read_resource(
        &self,
        principal: &Principal,
        args: &Map<String, Value>,
    ) -> McpToolResult {
        if let Err(msg) = reject_unknown_args(args, &["uri", "format"]) {
            return McpToolResult::err_text(msg);
        }

        let Some(raw_uri) = args.get("uri").and_then(Value::as_str) else {
            return McpToolResult::err_text("Missing required string argument 'uri'");
        };
        let resolved = match resolve_pod_uri(
            raw_uri,
            &self.config.base_url,
            &self.config.pod_uri_prefix,
            false,
        ) {
            Ok(r) => r,
            Err(e) => return McpToolResult::err_text(e.to_string()),
        };

        if resolved.is_acl && !matches!(principal, Principal::User { .. }) {
            return McpToolResult::err_text(
                "Access denied: AI agents and anonymous callers cannot read '.acl' governance documents",
            );
        }

        let mode = if resolved.is_acl {
            AccessMode::Control
        } else {
            AccessMode::Read
        };
        if let AccessDecision::Deny { reason } =
            self.evaluate_pdp(principal, &resolved.policy_target, mode)
        {
            return McpToolResult::err_text(format!("Access denied: {reason}"));
        }

        let (rdf_format, rdf_mime) = match args.get("format") {
            None | Some(Value::Null) => (RdfFormat::Turtle, "text/turtle"),
            Some(Value::String(s)) => match s.as_str() {
                "turtle" => (RdfFormat::Turtle, "text/turtle"),
                "ntriples" => (RdfFormat::NTriples, "application/n-triples"),
                "jsonld" => (
                    RdfFormat::JsonLd {
                        profile: JsonLdProfileSet::empty(),
                    },
                    "application/ld+json",
                ),
                other => {
                    return McpToolResult::err_text(format!(
                        "Unsupported RDF format '{other}'; expected 'turtle', 'ntriples', or 'jsonld'"
                    ));
                }
            },
            Some(_) => return McpToolResult::err_text("Argument 'format' must be a string"),
        };

        // Hold catalog read lock across storage read for snapshot consistency
        let _read_guard = self.catalog_lock.read().await;
        let catalog = match PodCatalog::load_or_init(&self.physical_store).await {
            Ok(c) => c,
            Err(e) => return McpToolResult::err_text(e.to_string()),
        };

        let Some(entry) = catalog.entries.get(&resolved.catalog_key).cloned() else {
            return McpToolResult::err_text(format!(
                "Pod resource '{}' not found",
                resolved.display_uri
            ));
        };

        let restricted_caller = !matches!(principal, Principal::User { .. });

        match entry.kind {
            ResourceKind::Container | ResourceKind::RdfSource => {
                let raw_triples = match self
                    .collect_rdf_or_container_triples(principal, &catalog, &resolved, entry.kind)
                {
                    Ok(t) => t,
                    Err(e) => return McpToolResult::err_text(e.to_string()),
                };
                let (triples_to_serialize, redacted_count) = if resolved.is_acl {
                    (raw_triples, 0usize)
                } else {
                    let proj = self.apply_disclosure_projection(principal, &raw_triples);
                    (proj.triples, proj.redacted_triples)
                };

                let serialized = match SemanticGraphStore::serialize_triples(
                    &triples_to_serialize,
                    rdf_format,
                ) {
                    Ok(b) => {
                        if b.len() > self.config.max_resource_bytes {
                            return McpToolResult::err_text(
                                "Serialized RDF resource exceeds maximum outbound size budget",
                            );
                        }
                        match String::from_utf8(b) {
                            Ok(s) => s,
                            Err(e) => return McpToolResult::err_text(e.to_string()),
                        }
                    }
                    Err(e) => return McpToolResult::err_text(e.to_string()),
                };

                // Prevent unkeyed ETag length/hash oracle on redacted RDF triples
                let effective_etag = if restricted_caller && redacted_count > 0 {
                    match SemanticGraphStore::serialize_triples(
                        &triples_to_serialize,
                        RdfFormat::NTriples,
                    ) {
                        Ok(nt) => compute_etag(&nt),
                        Err(e) => return McpToolResult::err_text(e.to_string()),
                    }
                } else {
                    entry.etag
                };

                McpToolResult::ok_json(&json!({
                    "uri": resolved.display_uri,
                    "kind": entry.kind,
                    "content_type": rdf_mime,
                    "etag": effective_etag,
                    "encoding": "utf-8",
                    "data": serialized,
                    "redacted_triples": redacted_count,
                }))
            }
            ResourceKind::NonRdfSource => {
                let meta = match self.physical_store.stat(&resolved.blob_key).await {
                    Ok(m) => m,
                    Err(e) => return McpToolResult::err_text(e.to_string()),
                };
                let max_blob = self.max_outbound_blob_bytes();
                if meta.content_length > max_blob as u64 {
                    return McpToolResult::err_text(format!(
                        "Pod blob '{}' ({} bytes) exceeds maximum outbound limit ({max_blob} bytes)",
                        resolved.display_uri, meta.content_length
                    ));
                }

                let bytes = match self.physical_store.get(&resolved.blob_key).await {
                    Ok(b) => b,
                    Err(e) => return McpToolResult::err_text(e.to_string()),
                };

                if is_scrubbable_utf8_media_type(&entry.content_type) {
                    if let Ok(raw_text) = String::from_utf8(bytes.clone()) {
                        let scrubbed = self.scrub_text_for_principal(principal, &raw_text);
                        let effective_etag = if restricted_caller && scrubbed != raw_text {
                            compute_etag(scrubbed.as_bytes())
                        } else {
                            entry.etag
                        };
                        return McpToolResult::ok_json(&json!({
                            "uri": resolved.display_uri,
                            "kind": entry.kind,
                            "content_type": entry.content_type,
                            "etag": effective_etag,
                            "encoding": "utf-8",
                            "data": scrubbed,
                            "redacted_triples": 0,
                        }));
                    }
                }

                let orig_etag = entry.etag;
                let final_bytes =
                    self.scrub_binary_fallback_if_utf8_text(principal, &entry.content_type, bytes);
                let effective_etag = if restricted_caller {
                    compute_etag(&final_bytes)
                } else {
                    orig_etag
                };

                McpToolResult::ok_json(&json!({
                    "uri": resolved.display_uri,
                    "kind": entry.kind,
                    "content_type": entry.content_type,
                    "etag": effective_etag,
                    "encoding": "base64",
                    "data": base64_encode(&final_bytes),
                    "redacted_triples": 0,
                }))
            }
        }
    }

    // -------------------------------------------------------------------------
    // Tool 3: wolin_write_resource
    // -------------------------------------------------------------------------
    async fn exec_write_resource(
        &self,
        principal: &Principal,
        args: &Map<String, Value>,
    ) -> McpToolResult {
        if let Err(msg) = reject_unknown_args(
            args,
            &["uri", "content", "content_type", "encoding", "if_match"],
        ) {
            return McpToolResult::err_text(msg);
        }

        let Some(raw_uri) = args.get("uri").and_then(Value::as_str) else {
            return McpToolResult::err_text("Missing required string argument 'uri'");
        };
        let Some(raw_content) = args.get("content").and_then(Value::as_str) else {
            return McpToolResult::err_text("Missing required string argument 'content'");
        };

        let encoding = match extract_optional_nonempty_str(args, "encoding") {
            Ok(Some(enc)) => enc,
            Ok(None) => "utf-8",
            Err(msg) => return McpToolResult::err_text(msg),
        };
        let content_type_raw = match extract_optional_nonempty_str(args, "content_type") {
            Ok(Some(ct)) => ct,
            Ok(None) => "text/turtle",
            Err(msg) => return McpToolResult::err_text(msg),
        };
        let content_type = content_type_raw
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !is_valid_mime_essence(&content_type) {
            return McpToolResult::err_text(format!(
                "Invalid MIME 'content_type' '{content_type_raw}'"
            ));
        }

        let if_match_opt = match extract_optional_nonempty_str(args, "if_match") {
            Ok(opt) => opt,
            Err(msg) => return McpToolResult::err_text(msg),
        };

        let resolved = match resolve_pod_uri(
            raw_uri,
            &self.config.base_url,
            &self.config.pod_uri_prefix,
            false,
        ) {
            Ok(r) => r,
            Err(e) => return McpToolResult::err_text(e.to_string()),
        };

        // Block all '.acl' mutations via MCP to prevent privilege escalation / policy desync
        if resolved.is_acl {
            let _ = self.evaluate_pdp(principal, &resolved.policy_target, AccessMode::Control);
            return McpToolResult::err_text(
                "Access denied: mutating '.acl' access control policies via MCP tool 'wolin_write_resource' is forbidden",
            );
        }

        // Enforce WAC/ACP Write authorization BEFORE decoding or mutating storage
        if let AccessDecision::Deny { reason } =
            self.evaluate_pdp(principal, &resolved.policy_target, AccessMode::Write)
        {
            return McpToolResult::err_text(format!("Access denied: {reason}"));
        }

        let payload_bytes = match encoding {
            "utf-8" => {
                if raw_content.len() > self.config.max_resource_bytes {
                    return McpToolResult::err_text(format!(
                        "Resource payload exceeds maximum allowed size of {} bytes",
                        self.config.max_resource_bytes
                    ));
                }
                raw_content.as_bytes().to_vec()
            }
            "base64" => {
                if raw_content.len() > self.config.max_resource_bytes.saturating_mul(2) {
                    return McpToolResult::err_text(format!(
                        "Encoded payload exceeds maximum allowed size of {} bytes",
                        self.config.max_resource_bytes
                    ));
                }
                let decoded = match base64_decode(raw_content) {
                    Ok(b) => b,
                    Err(e) => return McpToolResult::err_text(e.to_string()),
                };
                if decoded.len() > self.config.max_resource_bytes {
                    return McpToolResult::err_text(format!(
                        "Decoded resource exceeds maximum allowed size of {} bytes",
                        self.config.max_resource_bytes
                    ));
                }
                decoded
            }
            other => {
                return McpToolResult::err_text(format!(
                    "Unsupported 'encoding' '{other}'; expected 'utf-8' or 'base64'"
                ));
            }
        };

        enum StagedWrite {
            Container {
                triples: Vec<Triple>,
            },
            Rdf {
                triples: Vec<Triple>,
            },
            Blob {
                content_type: String,
                bytes: Vec<u8>,
            },
        }

        let staged = if resolved.is_container {
            let triples = if payload_bytes.is_empty() {
                if parse_rdf_media_type(&content_type).is_none() {
                    return McpToolResult::err_text(format!(
                        "Unsupported Content-Type '{content_type}' for LDP BasicContainer"
                    ));
                }
                Vec::new()
            } else {
                let Some(fmt) = parse_rdf_media_type(&content_type) else {
                    return McpToolResult::err_text(format!(
                        "Unsupported Content-Type '{content_type}' for LDP BasicContainer"
                    ));
                };
                match SemanticGraphStore::parse_rdf_triples(
                    &payload_bytes,
                    fmt,
                    &resolved.graph_iri,
                ) {
                    Ok(t) => t,
                    Err(e) => return McpToolResult::err_text(e.to_string()),
                }
            };
            if triples.iter().any(|t| t.predicate.as_str() == LDP_CONTAINS) {
                return McpToolResult::err_text(
                    "Server-managed ldp:contains triples cannot be set directly by clients",
                );
            }
            StagedWrite::Container { triples }
        } else if let Some(fmt) = parse_rdf_media_type(&content_type) {
            let triples = match SemanticGraphStore::parse_rdf_triples(
                &payload_bytes,
                fmt,
                &resolved.graph_iri,
            ) {
                Ok(t) => t,
                Err(e) => return McpToolResult::err_text(e.to_string()),
            };
            StagedWrite::Rdf { triples }
        } else {
            StagedWrite::Blob {
                content_type: content_type.clone(),
                bytes: payload_bytes.clone(),
            }
        };

        // Re-verify PDP authorization immediately before committing state under write lock
        let _write_guard = self.catalog_lock.write().await;
        if let AccessDecision::Deny { reason } =
            self.evaluate_pdp(principal, &resolved.policy_target, AccessMode::Write)
        {
            return McpToolResult::err_text(format!("Access denied: {reason}"));
        }

        let mut catalog = match PodCatalog::load_or_init(&self.physical_store).await {
            Ok(c) => c,
            Err(e) => return McpToolResult::err_text(e.to_string()),
        };

        if let Err(conflict_msg) = validate_hierarchy_for_write(&catalog, &resolved) {
            return McpToolResult::err_text(conflict_msg);
        }

        let existing = catalog.entries.get(&resolved.catalog_key).cloned();
        if let Some(expected_etag) = if_match_opt {
            let trimmed = expected_etag.trim();
            let matched = match existing.as_ref() {
                None => false,
                Some(entry) => {
                    trimmed == "*" || trimmed.split(',').any(|tok| tok.trim() == entry.etag)
                }
            };
            if !matched {
                return McpToolResult::err_text(
                    "If-Match precondition failed: live resource ETag does not match",
                );
            }
        }

        ensure_parent_containers(&mut catalog, &resolved);

        let bytes_written = payload_bytes.len();
        // Write new storage representation BEFORE cleaning up any superseded representation
        let (kind, stored_ct, new_etag, triples_written) = match staged {
            StagedWrite::Container { triples } => {
                let count = triples.len();
                let canonical_nt =
                    match SemanticGraphStore::serialize_triples(&triples, RdfFormat::NTriples) {
                        Ok(b) => b,
                        Err(e) => return McpToolResult::err_text(e.to_string()),
                    };
                if let Err(e) = self
                    .graph_store
                    .replace_named_graph_triples(&resolved.graph_iri, &triples)
                {
                    return McpToolResult::err_text(e.to_string());
                }
                (
                    ResourceKind::Container,
                    "text/turtle".to_string(),
                    compute_etag(&canonical_nt),
                    Some(count),
                )
            }
            StagedWrite::Rdf { triples } => {
                let count = triples.len();
                let canonical_nt =
                    match SemanticGraphStore::serialize_triples(&triples, RdfFormat::NTriples) {
                        Ok(b) => b,
                        Err(e) => return McpToolResult::err_text(e.to_string()),
                    };
                if let Err(e) = self
                    .graph_store
                    .replace_named_graph_triples(&resolved.graph_iri, &triples)
                {
                    return McpToolResult::err_text(e.to_string());
                }
                if let Some(ref prev) = existing {
                    if prev.kind == ResourceKind::NonRdfSource {
                        if let Err(e) = self.physical_store.delete(&resolved.blob_key).await {
                            return McpToolResult::err_text(e.to_string());
                        }
                    }
                }
                (
                    ResourceKind::RdfSource,
                    "text/turtle".to_string(),
                    compute_etag(&canonical_nt),
                    Some(count),
                )
            }
            StagedWrite::Blob {
                content_type,
                bytes,
            } => {
                let etag = compute_etag(&bytes);
                if let Err(e) = self
                    .physical_store
                    .put_with_content_type(&resolved.blob_key, bytes, &content_type)
                    .await
                {
                    return McpToolResult::err_text(e.to_string());
                }
                if let Some(ref prev) = existing {
                    if prev.kind == ResourceKind::RdfSource {
                        if let Err(e) = self.graph_store.delete_named_graph(&resolved.graph_iri) {
                            return McpToolResult::err_text(e.to_string());
                        }
                    }
                }
                (ResourceKind::NonRdfSource, content_type, etag, None)
            }
        };

        catalog.entries.insert(
            resolved.catalog_key.clone(),
            CatalogEntry {
                path: resolved.catalog_key.clone(),
                kind,
                content_type: stored_ct.clone(),
                etag: new_etag.clone(),
            },
        );
        if let Err(e) = catalog.persist(&self.physical_store).await {
            if existing.is_none() {
                match kind {
                    ResourceKind::Container | ResourceKind::RdfSource => {
                        let _ = self.graph_store.delete_named_graph(&resolved.graph_iri);
                    }
                    ResourceKind::NonRdfSource => {
                        let _ = self.physical_store.delete(&resolved.blob_key).await;
                    }
                }
            }
            return McpToolResult::err_text(e.to_string());
        }

        McpToolResult::ok_json(&json!({
            "uri": resolved.display_uri,
            "kind": kind,
            "content_type": stored_ct,
            "etag": new_etag,
            "created": existing.is_none(),
            "triples_written": triples_written,
            "bytes_written": bytes_written,
        }))
    }

    // -------------------------------------------------------------------------
    // Tool 4: wolin_list_resources
    // -------------------------------------------------------------------------
    async fn exec_list_resources(
        &self,
        principal: &Principal,
        args: &Map<String, Value>,
    ) -> McpToolResult {
        if let Err(msg) = reject_unknown_args(args, &["uri", "recursive", "limit"]) {
            return McpToolResult::err_text(msg);
        }

        let raw_uri = match extract_optional_nonempty_str(args, "uri") {
            Ok(Some(u)) => u,
            Ok(None) => "/",
            Err(msg) => return McpToolResult::err_text(msg),
        };

        let recursive = match args.get("recursive") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return McpToolResult::err_text("Argument 'recursive' must be a boolean"),
        };

        let limit = match args.get("limit") {
            None | Some(Value::Null) => DEFAULT_LIST_LIMIT,
            Some(v) => match v.as_u64() {
                Some(n) if (1..=MAX_LIST_LIMIT as u64).contains(&n) => n as usize,
                _ => {
                    return McpToolResult::err_text(format!(
                        "'limit' must be an integer between 1 and {MAX_LIST_LIMIT}"
                    ));
                }
            },
        };

        let resolved = match resolve_pod_uri(
            raw_uri,
            &self.config.base_url,
            &self.config.pod_uri_prefix,
            true,
        ) {
            Ok(r) => r,
            Err(e) => return McpToolResult::err_text(e.to_string()),
        };

        if resolved.is_acl {
            return McpToolResult::err_text("Cannot list contents of an '.acl' auxiliary resource");
        }

        if let AccessDecision::Deny { reason } =
            self.evaluate_pdp(principal, &resolved.policy_target, AccessMode::Read)
        {
            return McpToolResult::err_text(format!("Access denied: {reason}"));
        }

        let _read_guard = self.catalog_lock.read().await;
        let catalog = match PodCatalog::load_or_init(&self.physical_store).await {
            Ok(c) => c,
            Err(e) => return McpToolResult::err_text(e.to_string()),
        };

        match catalog.entries.get(&resolved.catalog_key) {
            Some(entry) if entry.kind == ResourceKind::Container => {}
            _ => {
                return McpToolResult::err_text(format!(
                    "Target Pod container '{}' not found",
                    resolved.display_uri
                ));
            }
        }

        let container_prefix = &resolved.catalog_key;
        let mut items = Vec::new();
        let mut truncated = false;

        for (key, entry) in &catalog.entries {
            if key == container_prefix || key.ends_with(".acl") {
                continue;
            }
            let Some(rel) = key.strip_prefix(container_prefix.as_str()) else {
                continue;
            };
            if rel.is_empty() {
                continue;
            }
            let trimmed_rel = rel.strip_suffix('/').unwrap_or(rel);
            if !recursive && trimmed_rel.contains('/') {
                continue;
            }

            let Ok(child_resolved) =
                resolve_catalog_key(key, &self.config.base_url, &self.config.pod_uri_prefix)
            else {
                continue;
            };

            if !self
                .evaluate_pdp(principal, &child_resolved.policy_target, AccessMode::Read)
                .is_permit()
            {
                continue;
            }

            if items.len() >= limit {
                truncated = true;
                break;
            }

            items.push(json!({
                "uri": child_resolved.display_uri,
                "name": rel,
                "kind": entry.kind,
                "content_type": entry.content_type,
                "etag": entry.etag,
            }));
        }

        let count = items.len();
        McpToolResult::ok_json(&json!({
            "container_uri": resolved.display_uri,
            "entries": items,
            "count": count,
            "truncated": truncated,
        }))
    }

    // -------------------------------------------------------------------------
    // Internal PDP & Projection Helpers
    // -------------------------------------------------------------------------
    fn max_outbound_blob_bytes(&self) -> usize {
        // Ensure base64-encoded blob (`ceil(n/3)*4`) fits comfortably inside `max_message_bytes`
        let msg_budget = self.config.max_message_bytes.saturating_mul(3) / 4;
        self.config
            .max_resource_bytes
            .min(msg_budget.saturating_sub(512).max(256))
    }

    fn evaluate_pdp(
        &self,
        principal: &Principal,
        target: &ResourceUri,
        mode: AccessMode,
    ) -> AccessDecision {
        let engine = self.policy_engine.read().unwrap_or_else(|e| e.into_inner());
        match self.config.policy_clock_epoch_secs {
            Some(ts) => engine.evaluate_policy_at(principal, target, mode, ts),
            None => engine.evaluate_policy(principal, target, mode),
        }
    }

    fn apply_disclosure_projection(
        &self,
        principal: &Principal,
        triples: &[Triple],
    ) -> crate::projection::ProjectedTriples {
        let guard = self
            .disclosure_policy
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let profile = DisclosureProfile::resolve(principal, &guard);
        project_triples(triples, &profile, &guard)
    }

    fn scrub_text_for_principal(&self, principal: &Principal, raw: &str) -> String {
        let profile = {
            let guard = self
                .disclosure_policy
                .read()
                .unwrap_or_else(|e| e.into_inner());
            DisclosureProfile::resolve(principal, &guard)
        };
        if !profile.zero_pii_enforced && !profile.redact_secrets {
            raw.to_string()
        } else {
            crate::projection::scrub_literal_text(raw, &profile)
        }
    }

    fn scrub_binary_fallback_if_utf8_text(
        &self,
        principal: &Principal,
        content_type: &str,
        bytes: Vec<u8>,
    ) -> Vec<u8> {
        let primary = content_type
            .split(';')
            .next()
            .unwrap_or(content_type)
            .trim();
        if primary == "application/octet-stream" && !bytes.contains(&0) {
            if let Ok(text) = std::str::from_utf8(&bytes) {
                return self.scrub_text_for_principal(principal, text).into_bytes();
            }
        }
        bytes
    }

    fn collect_rdf_or_container_triples(
        &self,
        principal: &Principal,
        catalog: &PodCatalog,
        resolved: &ResolvedPodUri,
        kind: ResourceKind,
    ) -> Result<Vec<Triple>> {
        let mut triples = self
            .graph_store
            .get_named_graph_triples(&resolved.graph_iri)?;

        if kind == ResourceKind::Container {
            let container_node = NamedNode::new(&resolved.graph_iri).map_err(|e| {
                wolin_core::WolinError::Internal(format!("Invalid container IRI: {e}"))
            })?;
            let rdf_type_node = NamedNode::new(RDF_TYPE).unwrap();
            for type_iri in [LDP_BASIC_CONTAINER, LDP_CONTAINER, LDP_RESOURCE] {
                triples.push(Triple::new(
                    Subject::NamedNode(container_node.clone()),
                    rdf_type_node.clone(),
                    Term::NamedNode(NamedNode::new(type_iri).unwrap()),
                ));
            }

            let contains_pred = NamedNode::new(LDP_CONTAINS).unwrap();
            for key in catalog.entries.keys() {
                if key == &resolved.catalog_key || key.ends_with(".acl") {
                    continue;
                }
                let Some(rel) = key.strip_prefix(resolved.catalog_key.as_str()) else {
                    continue;
                };
                let trimmed = rel.strip_suffix('/').unwrap_or(rel);
                if trimmed.is_empty() || trimmed.contains('/') {
                    continue;
                }
                let Ok(child_res) =
                    resolve_catalog_key(key, &self.config.base_url, &self.config.pod_uri_prefix)
                else {
                    continue;
                };
                if !self
                    .evaluate_pdp(principal, &child_res.policy_target, AccessMode::Read)
                    .is_permit()
                {
                    continue;
                }
                if let Ok(child_node) = NamedNode::new(&child_res.graph_iri) {
                    triples.push(Triple::new(
                        Subject::NamedNode(container_node.clone()),
                        contains_pred.clone(),
                        Term::NamedNode(child_node),
                    ));
                }
            }
        }

        Ok(triples)
    }
}

fn execute_bounded_sparql_in_sandbox(
    staged_quads: Vec<Quad>,
    parsed_query: SparqlQuery,
    limit: usize,
) -> std::result::Result<BoundedSparqlOutput, String> {
    let sandbox = SemanticGraphStore::new_in_memory().map_err(|e| e.to_string())?;
    sandbox
        .insert_quads(staged_quads)
        .map_err(|e| e.to_string())?;

    let results = sandbox
        .inner()
        .query(parsed_query)
        .map_err(|e| format!("SPARQL query evaluation failed: {e}"))?;

    match results {
        QueryResults::Solutions(solutions) => {
            let variables: Vec<String> = solutions
                .variables()
                .iter()
                .map(|v| v.as_str().to_string())
                .collect();
            let mut rows = Vec::with_capacity(limit.min(64));
            let mut truncated = false;

            for sol_res in solutions.take(limit.saturating_add(1)) {
                let sol = sol_res.map_err(|e| format!("SPARQL solution evaluation failed: {e}"))?;
                if rows.len() >= limit {
                    truncated = true;
                    break;
                }
                let mut row = SparqlBindingRow::new();
                for (var, term) in sol.iter() {
                    row.insert(var.as_str().to_string(), RdfTerm::from(term));
                }
                rows.push(row);
            }

            Ok(BoundedSparqlOutput::Select {
                bindings: SparqlBindingSet { variables, rows },
                truncated,
            })
        }
        QueryResults::Graph(triples_iter) => {
            let mut triples = Vec::with_capacity(limit.min(64));
            let mut truncated = false;

            for triple_res in triples_iter.take(limit.saturating_add(1)) {
                let triple =
                    triple_res.map_err(|e| format!("SPARQL graph evaluation failed: {e}"))?;
                if triples.len() >= limit {
                    truncated = true;
                    break;
                }
                triples.push(RdfTriple::from(triple));
            }

            Ok(BoundedSparqlOutput::Construct {
                graph: ConstructGraph { triples },
                truncated,
            })
        }
        QueryResults::Boolean(value) => Ok(BoundedSparqlOutput::Ask { value }),
    }
}

fn reject_unknown_args(
    args: &Map<String, Value>,
    allowed: &[&str],
) -> std::result::Result<(), String> {
    for key in args.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!(
                "Unknown tool argument '{}'; allowed arguments: {}",
                sanitize_for_audit(key),
                allowed.join(", ")
            ));
        }
    }
    Ok(())
}

fn extract_optional_nonempty_str<'a>(
    args: &'a Map<String, Value>,
    key: &str,
) -> std::result::Result<Option<&'a str>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Err(format!("Argument '{key}' must not be an empty string"))
            } else {
                Ok(Some(trimmed))
            }
        }
        Some(_) => Err(format!("Argument '{key}' must be a string")),
    }
}

fn is_valid_mime_essence(mime: &str) -> bool {
    let Some((t, sub)) = mime.split_once('/') else {
        return false;
    };
    !t.is_empty()
        && !sub.is_empty()
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'+'))
        && sub
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'+'))
}

fn sanitize_for_audit(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(256));
    for ch in raw.chars().take(256) {
        if ch.is_control() {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    out
}

fn principal_audit_label(principal: &Principal) -> String {
    match principal {
        Principal::User { webid, issuer } => format!(
            "[USER] webid={} iss={}",
            sanitize_for_audit(&webid.0),
            sanitize_for_audit(issuer)
        ),
        Principal::Agent {
            agent_id,
            delegated_by,
            ..
        } => format!(
            "[AGENT] id={} delegator={}",
            sanitize_for_audit(agent_id),
            sanitize_for_audit(&delegated_by.0)
        ),
        Principal::Anonymous => "[ANONYMOUS]".to_string(),
    }
}

fn is_valid_mcp_date_version(ver: &str) -> bool {
    let b = ver.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let Ok(year) = ver[0..4].parse::<u16>() else {
        return false;
    };
    let Ok(month) = ver[5..7].parse::<u8>() else {
        return false;
    };
    let Ok(day) = ver[8..10].parse::<u8>() else {
        return false;
    };
    (2024..=2099).contains(&year) && (1..=12).contains(&month) && (1..=31).contains(&day)
}

fn parse_rdf_media_type(media_type: &str) -> Option<RdfFormat> {
    match media_type {
        "text/turtle" | "application/x-turtle" => Some(RdfFormat::Turtle),
        "application/n-triples" => Some(RdfFormat::NTriples),
        "application/ld+json" => Some(RdfFormat::JsonLd {
            profile: JsonLdProfileSet::empty(),
        }),
        _ => None,
    }
}

fn is_scrubbable_utf8_media_type(ct: &str) -> bool {
    let primary = ct.split(';').next().unwrap_or(ct).trim();
    primary.starts_with("text/")
        || primary.ends_with("+json")
        || primary.ends_with("+xml")
        || matches!(
            primary,
            "application/json"
                | "application/xml"
                | "application/yaml"
                | "application/x-yaml"
                | "application/x-ndjson"
                | "image/svg+xml"
        )
}

fn contains_federated_service_clause(sparql: &str) -> bool {
    let bytes = sparql.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut in_iri = false;
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if in_iri {
            if b == b'>' {
                in_iri = false;
            }
            i += 1;
            continue;
        }

        match b {
            b'\'' => in_single = true,
            b'"' => in_double = true,
            b'<' => in_iri = true,
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            _ if b.is_ascii_alphabetic() => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let prev_var = start > 0 && matches!(bytes[start - 1], b'?' | b'$' | b':');
                if !prev_var && sparql[start..i].eq_ignore_ascii_case("SERVICE") {
                    return true;
                }
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

fn target_scope_matches_graph(
    scope_policy_uri: &str,
    scope_is_container: bool,
    graph_policy_uri: &str,
) -> bool {
    if graph_policy_uri == scope_policy_uri {
        return true;
    }
    if scope_is_container {
        return graph_policy_uri.starts_with(scope_policy_uri)
            && graph_policy_uri.as_bytes().get(scope_policy_uri.len()) == Some(&b'/');
    }
    false
}

fn validate_hierarchy_for_write(
    catalog: &PodCatalog,
    resolved: &ResolvedPodUri,
) -> std::result::Result<(), String> {
    if resolved.canonical_path == "/" {
        return Ok(());
    }

    if resolved.is_container {
        let leaf_peer = resolved.catalog_key.trim_end_matches('/');
        if catalog.entries.contains_key(leaf_peer) {
            return Err(format!(
                "Hierarchy conflict: cannot create container '{}' because leaf resource '{leaf_peer}' exists",
                resolved.display_uri
            ));
        }
    } else {
        let container_peer = format!("{}/", resolved.catalog_key);
        if catalog.entries.contains_key(&container_peer) {
            return Err(format!(
                "Hierarchy conflict: cannot write leaf '{}' because container '{container_peer}' exists",
                resolved.display_uri
            ));
        }
    }

    let trimmed = resolved.canonical_path.trim_matches('/');
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.len() > 1 {
        let mut rel_prefix = String::new();
        for seg in &parts[..parts.len() - 1] {
            rel_prefix.push('/');
            rel_prefix.push_str(seg);
            if catalog.entries.contains_key(&rel_prefix) {
                return Err(format!(
                    "Hierarchy conflict: ancestor '{rel_prefix}' is a leaf resource, not a container"
                ));
            }
        }
    }

    Ok(())
}

fn ensure_parent_containers(catalog: &mut PodCatalog, resolved: &ResolvedPodUri) {
    if resolved.canonical_path == "/" || resolved.is_acl {
        return;
    }

    let trimmed = resolved.canonical_path.trim_matches('/');
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.len() <= 1 {
        return;
    }

    let mut current_rel = String::from("/");
    for seg in &parts[..parts.len() - 1] {
        current_rel.push_str(seg);
        current_rel.push('/');
        catalog
            .entries
            .entry(current_rel.clone())
            .or_insert_with(|| CatalogEntry {
                path: current_rel.clone(),
                kind: ResourceKind::Container,
                content_type: "text/turtle".to_string(),
                etag: compute_etag(current_rel.as_bytes()),
            });
    }
}

// Unused import suppression guard: JsonRpcRequest is part of protocol public API
const _: Option<JsonRpcRequest> = None;
