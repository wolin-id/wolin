//! Wolin Server: Integrated Solid LDP + WAC/ACP + Native MCP HTTP Runtime.

pub mod auth;
pub mod error;
pub mod ldp;
pub mod mcp;
pub mod pods;

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use axum::{
    Router,
    extract::State,
    response::Json,
    routing::{any, get, post},
};
use ldp::LdpCatalog;
use serde_json::json;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use wolin_identity::{
    DpopReplayCache, HttpWebIdDereferencer, JwtSignatureVerifier, OidcValidationOptions,
    WebIdDereferencer,
};
use wolin_mcp::{DisclosurePolicy, McpAgentServer, McpGatewayConfig};
use wolin_policy::PolicyEngine;
pub use wolin_storage::{
    DEFAULT_MAX_OPEN_PODS, DEFAULT_POD_QUOTA_BYTES, PhysicalStore, PodStoreManager,
    SemanticGraphStore,
};

const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Configuration for the Solid LDP, WAC/ACP, and MCP HTTP pipeline.
#[derive(Clone)]
pub struct LdpConfig {
    /// Public HTTP origin for canonical RDF base IRIs, `Location`, `ldp:contains`, and `rel="acl"`.
    pub base_url: String,
    /// Canonical `ResourceUri` prefix evaluated by [`PolicyEngine`] (e.g. `"wolin://pod"`).
    pub pod_uri_prefix: String,
    /// OIDC / ZITADEL JWT validation parameters.
    pub oidc_options: OidcValidationOptions,
    /// Optional cryptographic JWT signature verifier.
    pub jwt_verifier: Option<Arc<dyn JwtSignatureVerifier>>,
    /// Maximum accepted HTTP request body size in bytes.
    pub max_body_bytes: usize,
    /// Optional deterministic UNIX epoch timestamp override for policy evaluation in tests.
    pub policy_clock_epoch_secs: Option<i64>,
    /// Sovereign Pod Cloud root domain for Host-header subdomain routing (`{pod_id}.{pod_cloud_domain}`).
    pub pod_cloud_domain: String,
    /// Optional Solid-OIDC external WebID RDF Profile dereferencer.
    pub webid_dereferencer: Option<Arc<dyn WebIdDereferencer>>,
    /// Whether the Native MCP HTTP/SSE gateway (`/mcp`, `/mcp/sse`) is enabled.
    pub mcp_enabled: bool,
    /// Maximum number of concurrently open per-pod RocksDB graph stores in the LRU cache.
    pub max_open_pods: usize,
    /// Default logical storage quota in bytes per tenant Pod (`1 GiB` default).
    pub default_pod_quota_bytes: u64,
    /// Operator-configured reserved/tombstoned `pod_id` handles blocked on `POST /api/pods`.
    pub reserved_pods: BTreeSet<String>,
    /// Optional shared admin Bearer token guarding `/api/pods` provisioning and retirement.
    pub admin_token: Option<String>,
}

impl Default for LdpConfig {
    fn default() -> Self {
        let default_deref = HttpWebIdDereferencer::new()
            .ok()
            .map(|d| Arc::new(d) as Arc<dyn WebIdDereferencer>);
        Self {
            base_url: "http://127.0.0.1:4000".to_string(),
            pod_uri_prefix: "wolin://pod".to_string(),
            oidc_options: OidcValidationOptions::new("https://auth.wolin.id"),
            jwt_verifier: None,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            policy_clock_epoch_secs: None,
            pod_cloud_domain: "wolin.cloud".to_string(),
            webid_dereferencer: default_deref,
            mcp_enabled: true,
            max_open_pods: DEFAULT_MAX_OPEN_PODS,
            default_pod_quota_bytes: DEFAULT_POD_QUOTA_BYTES,
            reserved_pods: BTreeSet::new(),
            admin_token: None,
        }
    }
}

impl LdpConfig {
    pub fn new(base_url: impl Into<String>, pod_uri_prefix: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            pod_uri_prefix: pod_uri_prefix.into().trim_end_matches('/').to_string(),
            ..Self::default()
        }
    }

    pub fn with_oidc_options(mut self, oidc_options: OidcValidationOptions) -> Self {
        self.oidc_options = oidc_options;
        self
    }

    pub fn with_jwt_verifier(mut self, verifier: Arc<dyn JwtSignatureVerifier>) -> Self {
        self.jwt_verifier = Some(verifier);
        self
    }

    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    pub fn with_policy_clock(mut self, epoch_secs: i64) -> Self {
        self.policy_clock_epoch_secs = Some(epoch_secs);
        self
    }

    pub fn with_pod_cloud_domain(mut self, domain: impl Into<String>) -> Self {
        self.pod_cloud_domain = domain.into().trim().trim_matches('.').to_ascii_lowercase();
        self
    }

    pub fn with_webid_dereferencer(mut self, dereferencer: Arc<dyn WebIdDereferencer>) -> Self {
        self.webid_dereferencer = Some(dereferencer);
        self
    }

    pub fn without_webid_dereferencer(mut self) -> Self {
        self.webid_dereferencer = None;
        self
    }

    pub fn with_mcp_enabled(mut self, enabled: bool) -> Self {
        self.mcp_enabled = enabled;
        self
    }

    pub fn with_max_open_pods(mut self, max_open_pods: usize) -> Self {
        self.max_open_pods = max_open_pods;
        self
    }

    pub fn with_pod_quota_bytes(mut self, quota_bytes: u64) -> Self {
        self.default_pod_quota_bytes = quota_bytes;
        self
    }

    pub fn with_reserved_pods<I, S>(mut self, pods: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.reserved_pods = pods
            .into_iter()
            .map(|s| s.into().trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        self
    }

    pub fn with_admin_token(mut self, token: impl Into<String>) -> Self {
        let trimmed = token.into().trim().to_string();
        self.admin_token = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        };
        self
    }
}

/// Shared application state across Axum Solid LDP, Native MCP, and system discovery endpoints.
pub struct AppState {
    pub physical_store: PhysicalStore,
    pub graph_store: SemanticGraphStore,
    pub pod_stores: PodStoreManager,
    pub policy_engine: Arc<RwLock<PolicyEngine>>,
    pub disclosure_policy: Arc<RwLock<DisclosurePolicy>>,
    pub catalog_lock: Arc<tokio::sync::RwLock<()>>,
    pub catalog: tokio::sync::RwLock<LdpCatalog>,
    pub mcp_server: McpAgentServer,
    pub dpop_replay_cache: Arc<DpopReplayCache>,
    pub config: LdpConfig,
}

impl AppState {
    /// Construct [`AppState`], loading persisted LDP catalog metadata and rehydrating `.acl`
    /// WAC rules into a unified runtime shared across Solid LDP and [`McpAgentServer`].
    pub async fn new(
        physical_store: PhysicalStore,
        graph_store: SemanticGraphStore,
        policy_engine: PolicyEngine,
        config: LdpConfig,
    ) -> wolin_core::Result<Arc<Self>> {
        let pod_stores = PodStoreManager::from_stores(
            &physical_store,
            graph_store.clone(),
            config.max_open_pods,
            config.default_pod_quota_bytes,
        )?;
        Self::new_with_pod_stores(
            physical_store,
            graph_store,
            pod_stores,
            policy_engine,
            config,
        )
        .await
    }

    /// Construct [`AppState`] with an explicit [`PodStoreManager`].
    pub async fn new_with_pod_stores(
        physical_store: PhysicalStore,
        graph_store: SemanticGraphStore,
        pod_stores: PodStoreManager,
        mut policy_engine: PolicyEngine,
        config: LdpConfig,
    ) -> wolin_core::Result<Arc<Self>> {
        let catalog = LdpCatalog::load_or_init(&physical_store).await?;
        pod_stores.replace_all_pod_usages(catalog.all_pod_usages());
        ldp::rehydrate_persisted_acl_rules(&pod_stores, &catalog, &mut policy_engine, &config)?;

        let policy_arc = Arc::new(RwLock::new(policy_engine));
        let disclosure_arc = Arc::new(RwLock::new(DisclosurePolicy::new()));
        let catalog_lock = Arc::new(tokio::sync::RwLock::new(()));

        let mut mcp_config = McpGatewayConfig::new(&config.base_url, &config.pod_uri_prefix)
            .with_max_resource_bytes(config.max_body_bytes)
            .with_reserved_pods(config.reserved_pods.iter().cloned());
        if let Some(ts) = config.policy_clock_epoch_secs {
            mcp_config = mcp_config.with_policy_clock(ts);
        }

        let mcp_server = McpAgentServer::with_shared_pod_stores(
            physical_store.clone(),
            graph_store.clone(),
            pod_stores.clone(),
            Arc::clone(&policy_arc),
            Arc::clone(&disclosure_arc),
            Arc::clone(&catalog_lock),
            mcp_config,
        );

        Ok(Arc::new(Self {
            physical_store,
            graph_store,
            pod_stores,
            policy_engine: policy_arc,
            disclosure_policy: disclosure_arc,
            catalog_lock,
            catalog: tokio::sync::RwLock::new(catalog),
            mcp_server,
            dpop_replay_cache: Arc::new(DpopReplayCache::new(8_192)),
            config,
        }))
    }

    /// Create an ephemeral in-memory [`AppState`] with the given [`PolicyEngine`] and [`LdpConfig`].
    pub async fn new_in_memory(
        policy_engine: PolicyEngine,
        config: LdpConfig,
    ) -> wolin_core::Result<Arc<Self>> {
        let physical_store = PhysicalStore::new_memory()?;
        let graph_store = SemanticGraphStore::new_in_memory()?;
        Self::new(physical_store, graph_store, policy_engine, config).await
    }

    /// Create a disk-backed persistent [`AppState`] rooted at `storage_dir`
    /// (`blobs/`, system `graph/`, and per-pod `pods/{pod_id}/graph/`).
    pub async fn new_persistent(
        storage_dir: impl AsRef<Path>,
        policy_engine: PolicyEngine,
        config: LdpConfig,
    ) -> wolin_core::Result<Arc<Self>> {
        let root = storage_dir.as_ref();
        let blobs_dir = root.join("blobs");
        let graph_dir = root.join("graph");
        let pods_dir = root.join("pods");
        ensure_private_dir(root)?;
        ensure_private_dir(&blobs_dir)?;
        ensure_private_dir(&graph_dir)?;
        ensure_private_dir(&pods_dir)?;

        let blobs_str = blobs_dir.to_str().ok_or_else(|| {
            wolin_core::WolinError::InvalidFormat(
                "Storage directory path must be valid UTF-8".into(),
            )
        })?;
        let physical_store = PhysicalStore::new_fs(blobs_str)?;
        let graph_store = SemanticGraphStore::open_bounded(&graph_dir, 64)?;
        let pod_stores = PodStoreManager::new_persistent_with_system_store(
            root,
            graph_store.clone(),
            config.max_open_pods,
            config.default_pod_quota_bytes,
        )?;
        Self::new_with_pod_stores(
            physical_store,
            graph_store,
            pod_stores,
            policy_engine,
            config,
        )
        .await
    }

    /// Mutate the live [`PolicyEngine`] safely under write lock (shared by LDP and MCP).
    pub fn with_policy_mut<R>(&self, f: impl FnOnce(&mut PolicyEngine) -> R) -> R {
        let mut guard = self
            .policy_engine
            .write()
            .unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    /// Mutate the live [`DisclosurePolicy`] safely under write lock.
    pub fn with_disclosure_mut<R>(&self, f: impl FnOnce(&mut DisclosurePolicy) -> R) -> R {
        let mut guard = self
            .disclosure_policy
            .write()
            .unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    /// Refresh the in-memory LDP catalog snapshot from `physical_store` under the shared catalog lock.
    pub async fn sync_catalog_from_store(&self) -> Result<(), error::LdpError> {
        let _read_guard = self.catalog_lock.read().await;
        let fresh = LdpCatalog::load_or_init(&self.physical_store).await?;
        self.pod_stores
            .replace_all_pod_usages(fresh.all_pod_usages());
        let mut cat_guard = self.catalog.write().await;
        *cat_guard = fresh;
        Ok(())
    }

    /// Permanently retire `pod_id` into the persistent LDP tombstone ledger, removing its
    /// catalog entries, physical blobs, per-pod RocksDB store, and governance policies so
    /// it can never be re-claimed or read/written.
    pub async fn retire_pod(
        &self,
        pod_id: &str,
        reason: &str,
        retired_at: i64,
    ) -> Result<ldp::PodTombstone, error::LdpError> {
        let clean_pod_id = pod_id.trim().to_ascii_lowercase();
        PodStoreManager::validate_legacy_pod_segment(&clean_pod_id)?;

        let clean_reason = reason.trim();
        if clean_reason.is_empty() || clean_reason.len() > 512 {
            return Err(error::LdpError::BadRequest(
                "Tombstone retirement reason must be between 1 and 512 characters".to_string(),
            ));
        }

        let _io_guard = self.catalog_lock.write().await;
        let mut catalog = self.catalog.write().await;
        *catalog = LdpCatalog::load_or_init(&self.physical_store).await?;

        let tombstone = catalog
            .tombstones
            .entry(clean_pod_id.clone())
            .or_insert_with(|| ldp::PodTombstone {
                reason: clean_reason.to_string(),
                retired_at,
            })
            .clone();

        let pod_prefix = format!("/pods/{clean_pod_id}/");
        let removed_paths: Vec<(String, wolin_core::ResourceKind)> = catalog
            .entries
            .keys()
            .filter(|k| k.starts_with(&pod_prefix))
            .filter_map(|k| catalog.entries.get(k).map(|e| (k.clone(), e.kind)))
            .collect();

        for (path, kind) in &removed_paths {
            if *kind == wolin_core::ResourceKind::NonRdfSource {
                self.physical_store
                    .delete(&ldp::blob_key_for_path(path))
                    .await?;
            }
            catalog.entries.remove(path);
        }

        self.pod_stores.purge_pod_storage(&clean_pod_id)?;
        catalog.persist(&self.physical_store).await?;

        let base = self.config.base_url.trim_end_matches('/');
        let path_webid = format!("{base}/pods/{clean_pod_id}/profile/card#me");
        let mut pod_webids = vec![path_webid];
        if !self.config.pod_cloud_domain.is_empty() {
            pod_webids.push(format!(
                "https://{clean_pod_id}.{}/profile/card#me",
                self.config.pod_cloud_domain
            ));
            pod_webids.push(format!(
                "http://{clean_pod_id}.{}/profile/card#me",
                self.config.pod_cloud_domain
            ));
        }
        let pod_webid_refs: Vec<&str> = pod_webids.iter().map(String::as_str).collect();
        let pod_resource_prefix = format!(
            "{}/pods/{clean_pod_id}/",
            self.config.pod_uri_prefix.trim_end_matches('/')
        );
        {
            let mut engine = self
                .policy_engine
                .write()
                .unwrap_or_else(|e| e.into_inner());
            engine.purge_pod_governance(
                &pod_resource_prefix,
                &format!("acl-doc:{pod_prefix}"),
                &pod_webid_refs,
            );
        }

        Ok(tombstone)
    }
}

fn ensure_private_dir(path: &Path) -> wolin_core::Result<()> {
    std::fs::create_dir_all(path).map_err(|e| {
        wolin_core::WolinError::Storage(format!(
            "Failed to create storage directory {:?}: {e}",
            path
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            wolin_core::WolinError::Storage(format!(
                "Failed to set 0700 permissions on {:?}: {e}",
                path
            ))
        })?;
    }
    Ok(())
}

/// Build the Axum 0.8 router serving system discovery, Native MCP (`/mcp`, `/mcp/sse`),
/// and the Solid LDP + WAC/ACP pipeline (`/*path` & `/pods/{pod_id}/{*path}`).
pub fn build_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/health", get(health_check))
        .route("/healthz", get(health_check))
        .route("/.well-known/wolin", get(well_known_wolin))
        .route("/api/pods", post(pods::handle_provision_pod))
        .route(
            "/api/pods/{pod_id}",
            get(pods::handle_get_pod_info).delete(pods::handle_retire_pod),
        );

    router = if state.config.mcp_enabled {
        router
            .route("/mcp", post(mcp::handle_mcp_post))
            .route("/mcp/sse", get(mcp::handle_mcp_sse))
    } else {
        router
            .route("/mcp", any(mcp::handle_mcp_disabled))
            .route("/mcp/sse", any(mcp::handle_mcp_disabled))
    };

    router
        .fallback(ldp::handle_ldp_request)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().include_headers(false)),
        )
        .with_state(state)
}

pub async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "service": "wolin-server",
        "version": env!("CARGO_PKG_VERSION"),
        "motto": "One Identity. Infinite Reflections. (月印千江)"
    }))
}

pub async fn well_known_wolin(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mcp_enabled = state.config.mcp_enabled;
    let mcp_tools: Vec<String> = if mcp_enabled {
        state
            .mcp_server
            .list_tools()
            .into_iter()
            .map(|t| t.name)
            .collect()
    } else {
        Vec::new()
    };

    let mut protocols = vec!["solid-0.11", "wac-2.0", "acp-1.0", "oidc-1.0"];
    if mcp_enabled {
        protocols.insert(3, "mcp-2024-11-05");
    }

    let mut endpoints = serde_json::Map::from_iter([
        ("health".to_string(), json!("/health")),
        ("healthz".to_string(), json!("/healthz")),
        ("discovery".to_string(), json!("/.well-known/wolin")),
        ("ldp_root".to_string(), json!("/")),
        ("pods".to_string(), json!("/pods/")),
        ("pod_provisioning".to_string(), json!("/api/pods")),
    ]);
    if mcp_enabled {
        endpoints.insert("mcp".to_string(), json!("/mcp"));
        endpoints.insert("mcp_sse".to_string(), json!("/mcp/sse"));
    }

    Json(json!({
        "wolin_version": env!("CARGO_PKG_VERSION"),
        "base_url": state.config.base_url,
        "pod_uri_prefix": state.config.pod_uri_prefix,
        "protocols": protocols,
        "storage_backend": "opendal+oxigraph",
        "identity_mesh": ["webid", "did:key", "did:web", "did:nostr", "zitadel-oidc"],
        "endpoints": endpoints,
        "capabilities": {
            "solid_ldp": true,
            "solid_oidc_dpop": true,
            "multi_tenant_pod_cloud": true,
            "per_pod_physical_isolation": true,
            "bounded_pod_lru_cache": true,
            "per_pod_storage_quota": true,
            "wac_acp_pdp": true,
            "mcp_jsonrpc": mcp_enabled,
            "mcp_sse": mcp_enabled,
            "zero_pii_projection": true,
            "mcp_tools": mcp_tools
        }
    }))
}

/// Parsed command-line configuration for the `wolin-server` binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCliConfig {
    pub host: IpAddr,
    pub port: u16,
    pub storage_dir: Option<PathBuf>,
    pub base_url: Option<String>,
    pub pod_uri_prefix: String,
    pub pod_cloud_domain: String,
    pub oidc_issuer: String,
    pub oidc_audience: Option<String>,
    pub owner_webid: Option<String>,
    pub require_explicit_delegation: bool,
    pub mcp_enabled: bool,
    pub max_body_bytes: usize,
    pub max_open_pods: usize,
    pub pod_quota_bytes: u64,
    pub reserved_pods: BTreeSet<String>,
    pub admin_token: Option<String>,
}

impl Default for ServerCliConfig {
    fn default() -> Self {
        Self {
            host: IpAddr::from([127, 0, 0, 1]),
            port: 4000,
            storage_dir: None,
            base_url: None,
            pod_uri_prefix: "wolin://pod".to_string(),
            pod_cloud_domain: "wolin.cloud".to_string(),
            oidc_issuer: "https://auth.wolin.id".to_string(),
            oidc_audience: None,
            owner_webid: None,
            require_explicit_delegation: false,
            mcp_enabled: true,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_open_pods: DEFAULT_MAX_OPEN_PODS,
            pod_quota_bytes: DEFAULT_POD_QUOTA_BYTES,
            reserved_pods: BTreeSet::new(),
            admin_token: None,
        }
    }
}

impl ServerCliConfig {
    pub fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }

    /// Loopback/interface socket address targeted by `--healthcheck`.
    pub fn healthcheck_addr(&self) -> SocketAddr {
        let ip = match self.host {
            IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::from([127, 0, 0, 1]),
            IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
            concrete => concrete,
        };
        SocketAddr::new(ip, self.port)
    }

    pub fn effective_base_url(&self) -> String {
        match &self.base_url {
            Some(url) => url.trim_end_matches('/').to_string(),
            None => match self.host {
                IpAddr::V4(v4) => format!("http://{v4}:{}", self.port),
                IpAddr::V6(v6) => format!("http://[{v6}]:{}", self.port),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliParseOutcome {
    Run(ServerCliConfig),
    Healthcheck(ServerCliConfig),
    Help(String),
    Version(String),
}

impl ServerCliConfig {
    pub fn usage() -> String {
        format!(
            "wolin-server {} — Universal Identity & Sovereign Pod Persistence Fabric\n\n\
             USAGE:\n  \
               wolin-server [OPTIONS]\n\n\
             PRECEDENCE:\n  \
               CLI flag > WOLIN_* environment variable > built-in default\n\n\
             OPTIONS:\n  \
               --listen-addr <IP:PORT>            Bind socket address [env: WOLIN_LISTEN_ADDR] (default: 127.0.0.1:4000)\n  \
               --host <IP>                        Bind IP literal [env: WOLIN_HOST] (default: 127.0.0.1)\n  \
               -p, --port <PORT>                  Bind TCP port [env: WOLIN_PORT] (default: 4000)\n  \
               -d, --storage-dir <DIR>            Persistent storage root [env: WOLIN_STORAGE_DIR] (use 'memory' for ephemeral)\n  \
               --in-memory                        Force ephemeral in-memory storage (overrides WOLIN_STORAGE_DIR)\n  \
               --base-url <URL>                   Public canonical Pod base URL [env: WOLIN_BASE_URL]\n  \
               --pod-prefix <URI>                 Canonical PDP Pod URI prefix [env: WOLIN_POD_PREFIX] (default: wolin://pod)\n  \
               --pod-cloud-domain <DOMAIN>        Multi-tenant subdomain root [env: WOLIN_POD_CLOUD_DOMAIN] (default: wolin.cloud)\n  \
               --oidc-issuer <URL>                Expected OIDC / ZITADEL issuer [env: WOLIN_OIDC_ISSUER] (default: https://auth.wolin.id)\n  \
               --oidc-audience <AUD>              Optional required OIDC audience [env: WOLIN_OIDC_AUDIENCE]\n  \
               --owner-webid <WEBID_OR_DID>       Bootstrap WAC owner on Pod root [env: WOLIN_OWNER_WEBID]\n  \
               --require-explicit-delegation      Require DelegationGrant for AI agents [env: WOLIN_REQUIRE_EXPLICIT_DELEGATION]\n  \
               --no-require-explicit-delegation   Disable explicit DelegationGrant requirement\n  \
               --mcp-enabled <BOOL>               Enable/disable Native MCP gateway [env: WOLIN_MCP_ENABLED] (default: true)\n  \
               --no-mcp                           Shorthand for --mcp-enabled false\n  \
               --max-body-bytes <BYTES>           Maximum HTTP payload bytes [env: WOLIN_MAX_BODY_BYTES] (default: 16777216)\n  \
               --max-open-pods <COUNT>            Max open per-pod RocksDB stores [env: WOLIN_MAX_OPEN_PODS] (default: 256)\n  \
               --pod-quota-bytes <BYTES>          Default per-pod storage quota in bytes [env: WOLIN_DEFAULT_POD_QUOTA_BYTES] (default: 1073741824)\n  \
               --reserved-pods <CSV>              Comma-separated reserved/tombstoned pod_ids [env: WOLIN_RESERVED_PODS]\n  \
               --admin-token <TOKEN>              Shared Bearer token for /api/pods admin lifecycle [env: WOLIN_ADMIN_TOKEN]\n  \
               --healthcheck                      Probe local /healthz endpoint and exit 0 if healthy\n  \
               -h, --help                         Print help information\n  \
               -V, --version                      Print version information",
            env!("CARGO_PKG_VERSION")
        )
    }

    /// Parse process CLI arguments layered on top of `WOLIN_*` OS environment variables.
    pub fn parse_from_os() -> Result<CliParseOutcome, String> {
        Self::parse_from_with_env(std::env::args(), |k| std::env::var(k).ok())
    }

    /// Parse CLI arguments without reading OS environment variables (pure / deterministic).
    pub fn parse_from<I, S>(args: I) -> Result<CliParseOutcome, String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::parse_from_with_env(args, |_| None)
    }

    /// Parse CLI arguments layered over an injected `WOLIN_*` environment lookup
    /// (`CLI flag > WOLIN_* env var > default`).
    pub fn parse_from_with_env<I, S, F>(args: I, get_env: F) -> Result<CliParseOutcome, String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
        F: Fn(&str) -> Option<String>,
    {
        let collected: Vec<String> = args.into_iter().map(Into::into).collect();
        for raw_arg in collected.iter().skip(1) {
            match raw_arg.as_str() {
                "-h" | "--help" => return Ok(CliParseOutcome::Help(Self::usage())),
                "-V" | "--version" => {
                    return Ok(CliParseOutcome::Version(format!(
                        "wolin-server {}",
                        env!("CARGO_PKG_VERSION")
                    )));
                }
                _ => {}
            }
        }

        let mut cfg = Self::default();
        cfg.apply_env(&get_env)?;

        let mut healthcheck_mode = false;
        let mut iter = collected.into_iter();
        let _bin = iter.next();

        while let Some(raw_arg) = iter.next() {
            let (flag, inline_val) = if raw_arg.starts_with("--") {
                match raw_arg.split_once('=') {
                    Some((k, v)) => (k, Some(v.to_string())),
                    None => (raw_arg.as_str(), None),
                }
            } else {
                (raw_arg.as_str(), None)
            };

            match flag {
                "--healthcheck" => {
                    reject_inline_value(&inline_val, "--healthcheck")?;
                    healthcheck_mode = true;
                }
                "--in-memory" => {
                    reject_inline_value(&inline_val, "--in-memory")?;
                    cfg.storage_dir = None;
                }
                "--require-explicit-delegation" => {
                    cfg.require_explicit_delegation = match inline_val {
                        Some(v) => parse_bool(&v, "--require-explicit-delegation")?,
                        None => true,
                    };
                }
                "--no-require-explicit-delegation" => {
                    reject_inline_value(&inline_val, "--no-require-explicit-delegation")?;
                    cfg.require_explicit_delegation = false;
                }
                "--mcp-enabled" => {
                    let val = take_val(inline_val, &mut iter, "--mcp-enabled")?;
                    cfg.mcp_enabled = parse_bool(&val, "--mcp-enabled")?;
                }
                "--no-mcp" => {
                    reject_inline_value(&inline_val, "--no-mcp")?;
                    cfg.mcp_enabled = false;
                }
                "--listen-addr" => {
                    let val = take_val(inline_val, &mut iter, "--listen-addr")?;
                    let addr = parse_listen_addr(&val, "--listen-addr")?;
                    cfg.host = addr.ip();
                    cfg.port = addr.port();
                }
                "--host" => {
                    let val = take_val(inline_val, &mut iter, "--host")?;
                    cfg.host = parse_host(&val, "--host")?;
                }
                "-p" | "--port" => {
                    let val = take_val(inline_val, &mut iter, "--port")?;
                    cfg.port = parse_port(&val, "--port")?;
                }
                "-d" | "--storage-dir" => {
                    let val = take_val(inline_val, &mut iter, "--storage-dir")?;
                    cfg.storage_dir = parse_storage_dir(&val, "--storage-dir")?;
                }
                "--base-url" => {
                    let val = take_val(inline_val, &mut iter, "--base-url")?;
                    cfg.base_url = Some(parse_base_url(&val, "--base-url")?);
                }
                "--pod-prefix" => {
                    let val = take_val(inline_val, &mut iter, "--pod-prefix")?;
                    cfg.pod_uri_prefix = parse_pod_prefix(&val, "--pod-prefix")?;
                }
                "--pod-cloud-domain" => {
                    let val = take_val(inline_val, &mut iter, "--pod-cloud-domain")?;
                    cfg.pod_cloud_domain = parse_cloud_domain(&val, "--pod-cloud-domain")?;
                }
                "--oidc-issuer" => {
                    let val = take_val(inline_val, &mut iter, "--oidc-issuer")?;
                    cfg.oidc_issuer = parse_oidc_issuer(&val, "--oidc-issuer")?;
                }
                "--oidc-audience" => {
                    let val = take_val(inline_val, &mut iter, "--oidc-audience")?;
                    if val.trim().is_empty() {
                        return Err("--oidc-audience must not be empty".to_string());
                    }
                    cfg.oidc_audience = Some(val.trim().to_string());
                }
                "--owner-webid" => {
                    let val = take_val(inline_val, &mut iter, "--owner-webid")?;
                    cfg.owner_webid = Some(parse_owner_webid(&val, "--owner-webid")?);
                }
                "--max-body-bytes" => {
                    let val = take_val(inline_val, &mut iter, "--max-body-bytes")?;
                    cfg.max_body_bytes = parse_max_body_bytes(&val, "--max-body-bytes")?;
                }
                "--max-open-pods" => {
                    let val = take_val(inline_val, &mut iter, "--max-open-pods")?;
                    cfg.max_open_pods = parse_max_open_pods(&val, "--max-open-pods")?;
                }
                "--pod-quota-bytes" => {
                    let val = take_val(inline_val, &mut iter, "--pod-quota-bytes")?;
                    cfg.pod_quota_bytes = parse_pod_quota_bytes(&val, "--pod-quota-bytes")?;
                }
                "--reserved-pods" => {
                    let val = take_val(inline_val, &mut iter, "--reserved-pods")?;
                    cfg.reserved_pods = parse_reserved_pods(&val, "--reserved-pods", true)?;
                }
                "--admin-token" => {
                    let val = take_val(inline_val, &mut iter, "--admin-token")?;
                    if val.trim().is_empty() {
                        return Err("--admin-token must not be empty".to_string());
                    }
                    cfg.admin_token = Some(val.trim().to_string());
                }
                unknown => {
                    return Err(format!(
                        "Unknown CLI flag '{unknown}'. Run with --help for usage."
                    ));
                }
            }
        }

        if healthcheck_mode {
            Ok(CliParseOutcome::Healthcheck(cfg))
        } else {
            Ok(CliParseOutcome::Run(cfg))
        }
    }

    fn apply_env<F>(&mut self, get_env: &F) -> Result<(), String>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(val) = non_empty_env(get_env, "WOLIN_LISTEN_ADDR") {
            let addr = parse_listen_addr(&val, "WOLIN_LISTEN_ADDR")?;
            self.host = addr.ip();
            self.port = addr.port();
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_HOST") {
            self.host = parse_host(&val, "WOLIN_HOST")?;
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_PORT") {
            self.port = parse_port(&val, "WOLIN_PORT")?;
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_STORAGE_DIR") {
            self.storage_dir = parse_storage_dir(&val, "WOLIN_STORAGE_DIR")?;
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_BASE_URL") {
            self.base_url = Some(parse_base_url(&val, "WOLIN_BASE_URL")?);
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_POD_PREFIX") {
            self.pod_uri_prefix = parse_pod_prefix(&val, "WOLIN_POD_PREFIX")?;
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_POD_CLOUD_DOMAIN") {
            self.pod_cloud_domain = parse_cloud_domain(&val, "WOLIN_POD_CLOUD_DOMAIN")?;
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_OIDC_ISSUER") {
            self.oidc_issuer = parse_oidc_issuer(&val, "WOLIN_OIDC_ISSUER")?;
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_OIDC_AUDIENCE") {
            self.oidc_audience = Some(val);
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_OWNER_WEBID") {
            self.owner_webid = Some(parse_owner_webid(&val, "WOLIN_OWNER_WEBID")?);
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_REQUIRE_EXPLICIT_DELEGATION") {
            self.require_explicit_delegation =
                parse_bool(&val, "WOLIN_REQUIRE_EXPLICIT_DELEGATION")?;
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_MCP_ENABLED") {
            self.mcp_enabled = parse_bool(&val, "WOLIN_MCP_ENABLED")?;
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_MAX_BODY_BYTES") {
            self.max_body_bytes = parse_max_body_bytes(&val, "WOLIN_MAX_BODY_BYTES")?;
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_MAX_OPEN_PODS") {
            self.max_open_pods = parse_max_open_pods(&val, "WOLIN_MAX_OPEN_PODS")?;
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_DEFAULT_POD_QUOTA_BYTES") {
            self.pod_quota_bytes = parse_pod_quota_bytes(&val, "WOLIN_DEFAULT_POD_QUOTA_BYTES")?;
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_RESERVED_PODS") {
            self.reserved_pods = parse_reserved_pods(&val, "WOLIN_RESERVED_PODS", false)?;
        }
        if let Some(val) = non_empty_env(get_env, "WOLIN_ADMIN_TOKEN") {
            self.admin_token = Some(val);
        }
        Ok(())
    }
}

fn non_empty_env<F>(get_env: &F, key: &str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    get_env(key).and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn take_val<I: Iterator<Item = String>>(
    inline_val: Option<String>,
    iter: &mut I,
    flag: &str,
) -> Result<String, String> {
    match inline_val {
        Some(v) => Ok(v),
        None => match iter.next() {
            Some(v) if !v.starts_with('-') => Ok(v),
            Some(next_flag) => Err(format!(
                "Missing value for CLI option '{flag}' (got flag '{next_flag}')"
            )),
            None => Err(format!("Missing value for CLI option '{flag}'")),
        },
    }
}

fn reject_inline_value(inline_val: &Option<String>, flag: &str) -> Result<(), String> {
    if inline_val.is_some() {
        Err(format!("Flag '{flag}' does not take a value"))
    } else {
        Ok(())
    }
}

fn parse_listen_addr(val: &str, source: &str) -> Result<SocketAddr, String> {
    val.trim().parse::<SocketAddr>().map_err(|_| {
        format!("Invalid socket address (expected IP:PORT literal) for {source}: '{val}'")
    })
}

fn parse_host(val: &str, source: &str) -> Result<IpAddr, String> {
    val.trim()
        .parse::<IpAddr>()
        .map_err(|_| format!("Invalid IP literal for {source}: '{val}'"))
}

fn parse_port(val: &str, source: &str) -> Result<u16, String> {
    val.trim()
        .parse::<u16>()
        .map_err(|_| format!("Invalid TCP port for {source}: '{val}'"))
}

fn parse_storage_dir(val: &str, source: &str) -> Result<Option<PathBuf>, String> {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Err(format!("{source} must not be empty"));
    }
    if matches!(trimmed.to_ascii_lowercase().as_str(), "memory" | ":memory:") {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(trimmed)))
}

fn parse_base_url(val: &str, source: &str) -> Result<String, String> {
    let validated =
        pods::validate_http_uri(val.trim(), source).map_err(|e| format!("{source}: {e:?}"))?;
    Ok(validated.trim_end_matches('/').to_string())
}

fn parse_oidc_issuer(val: &str, source: &str) -> Result<String, String> {
    pods::validate_http_uri(val.trim(), source).map_err(|e| format!("{source}: {e:?}"))
}

fn parse_owner_webid(val: &str, source: &str) -> Result<String, String> {
    pods::normalize_and_validate_owner_webid(val).map_err(|e| format!("{source}: {e:?}"))
}

fn parse_pod_prefix(val: &str, source: &str) -> Result<String, String> {
    let clean = val.trim().trim_end_matches('/');
    if clean.is_empty()
        || clean
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(format!(
            "{source} must be a non-empty URI without whitespace"
        ));
    }
    Ok(clean.to_string())
}

fn parse_cloud_domain(val: &str, source: &str) -> Result<String, String> {
    let clean = val.trim().trim_matches('.').to_ascii_lowercase();
    if clean.is_empty() || clean.len() > 253 {
        return Err(format!("{source} must be a valid non-empty DNS domain"));
    }
    for label in clean.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(format!(
                "Invalid DNS domain for {source}: '{val}' (expected bare domain like 'example.org')"
            ));
        }
    }
    Ok(clean)
}

fn parse_max_body_bytes(val: &str, source: &str) -> Result<usize, String> {
    let parsed = val
        .trim()
        .parse::<usize>()
        .map_err(|_| format!("Invalid integer for {source}: '{val}'"))?;
    if parsed == 0 {
        return Err(format!("{source} must be greater than 0"));
    }
    Ok(parsed)
}

fn parse_max_open_pods(val: &str, source: &str) -> Result<usize, String> {
    let parsed = val
        .trim()
        .parse::<usize>()
        .map_err(|_| format!("Invalid integer for {source}: '{val}'"))?;
    if parsed == 0 {
        return Err(format!("{source} must be greater than 0"));
    }
    Ok(parsed)
}

fn parse_pod_quota_bytes(val: &str, source: &str) -> Result<u64, String> {
    let parsed = val
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("Invalid integer for {source}: '{val}'"))?;
    if parsed == 0 {
        return Err(format!("{source} must be greater than 0"));
    }
    Ok(parsed)
}

fn parse_reserved_pods(
    val: &str,
    source: &str,
    allow_empty_clear: bool,
) -> Result<BTreeSet<String>, String> {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        if allow_empty_clear {
            return Ok(BTreeSet::new());
        }
        return Err(format!("{source} must not be empty"));
    }

    let mut out = BTreeSet::new();
    for raw_part in trimmed.split(',') {
        let part = raw_part.trim();
        if part.is_empty() {
            continue;
        }
        let lower = part.to_ascii_lowercase();
        PodStoreManager::validate_pod_id_syntax(&lower)
            .map_err(|e| format!("Invalid pod_id '{part}' in {source}: {e}"))?;
        out.insert(lower);
    }

    if out.is_empty() {
        return Err(format!(
            "{source} must contain at least one valid pod_id handle"
        ));
    }
    Ok(out)
}

fn parse_bool(val: &str, source: &str) -> Result<bool, String> {
    match val.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(format!(
            "Invalid boolean for {source}: '{val}' (expected true/false/1/0)"
        )),
    }
}

/// Probe the configured local `/healthz` HTTP endpoint (used by `wolin-server --healthcheck`).
pub async fn run_healthcheck_probe(cfg: &ServerCliConfig) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr = cfg.healthcheck_addr();
    let probe = async {
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| format!("Failed to connect to {addr}: {e}"))?;
        let req = format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("Failed to write healthcheck request: {e}"))?;
        let mut buf = Vec::with_capacity(1024);
        stream
            .take(16 * 1024)
            .read_to_end(&mut buf)
            .await
            .map_err(|e| format!("Failed to read healthcheck response: {e}"))?;
        let text = String::from_utf8_lossy(&buf);
        let status_ok = text.starts_with("HTTP/1.1 200 ") || text.starts_with("HTTP/1.0 200 ");
        if status_ok && text.contains("\"healthy\"") {
            Ok(())
        } else {
            Err(format!("Unhealthy response from {addr}/healthz"))
        }
    };

    tokio::time::timeout(std::time::Duration::from_secs(4), probe)
        .await
        .map_err(|_| format!("Timed out probing {addr}/healthz"))?
}

/// Wait for OS termination signal (`SIGINT` / Ctrl+C or Unix `SIGTERM`) for clean Axum shutdown.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sigterm) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sigterm.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received SIGINT, initiating graceful shutdown");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_cli_parser_defaults_overrides_and_validation() {
        let CliParseOutcome::Run(default_cfg) =
            ServerCliConfig::parse_from(["wolin-server"]).expect("default CLI parse")
        else {
            panic!("expected Run");
        };
        assert_eq!(default_cfg.port, 4000);
        assert_eq!(default_cfg.effective_base_url(), "http://127.0.0.1:4000");
        assert!(default_cfg.storage_dir.is_none());

        let CliParseOutcome::Run(custom) = ServerCliConfig::parse_from([
            "wolin-server",
            "--host",
            "127.0.0.1",
            "-p",
            "9090",
            "--storage-dir",
            "/tmp/wolin-test-pod",
            "--base-url",
            "https://pod.acme.corp/",
            "--oidc-issuer",
            "https://id.acme.corp",
            "--oidc-audience",
            "wolin-mcp",
            "--owner-webid",
            "did:web:alice.acme.corp",
            "--require-explicit-delegation",
            "--max-body-bytes",
            "1048576",
        ])
        .expect("custom CLI parse") else {
            panic!("expected Run");
        };
        assert_eq!(custom.port, 9090);
        assert_eq!(custom.effective_base_url(), "https://pod.acme.corp");
        assert_eq!(
            custom.storage_dir,
            Some(PathBuf::from("/tmp/wolin-test-pod"))
        );
        assert!(custom.require_explicit_delegation);
        assert_eq!(custom.max_body_bytes, 1_048_576);

        assert!(matches!(
            ServerCliConfig::parse_from(["wolin-server", "--help"]).unwrap(),
            CliParseOutcome::Help(_)
        ));
        assert!(matches!(
            ServerCliConfig::parse_from(["wolin-server", "--version"]).unwrap(),
            CliParseOutcome::Version(_)
        ));

        // Reject hostname in --host (require IP literal), bad port, unknown flags
        assert!(ServerCliConfig::parse_from(["wolin-server", "--host", "localhost"]).is_err());
        assert!(ServerCliConfig::parse_from(["wolin-server", "--port", "99999"]).is_err());
        assert!(ServerCliConfig::parse_from(["wolin-server", "--unknown"]).is_err());
    }

    #[test]
    fn unit_env_vars_populate_all_fields_when_cli_absent() {
        use std::collections::HashMap;

        let env_map = HashMap::from([
            ("WOLIN_LISTEN_ADDR", "0.0.0.0:8443"),
            ("WOLIN_STORAGE_DIR", "/data/wolin"),
            ("WOLIN_BASE_URL", "https://pod.home.example/"),
            ("WOLIN_POD_PREFIX", "wolin://home/"),
            ("WOLIN_POD_CLOUD_DOMAIN", ".Home.Example."),
            ("WOLIN_OIDC_ISSUER", "https://auth.home.example"),
            ("WOLIN_OIDC_AUDIENCE", "wolin-home"),
            ("WOLIN_OWNER_WEBID", "did:web:owner.home.example"),
            ("WOLIN_REQUIRE_EXPLICIT_DELEGATION", "true"),
            ("WOLIN_MCP_ENABLED", "false"),
            ("WOLIN_MAX_BODY_BYTES", "4194304"),
        ]);

        let CliParseOutcome::Run(cfg) =
            ServerCliConfig::parse_from_with_env(["wolin-server"], |k| {
                env_map.get(k).map(|v| (*v).to_string())
            })
            .expect("env parse should succeed")
        else {
            panic!("expected Run");
        };

        assert_eq!(cfg.host, IpAddr::from([0, 0, 0, 0]));
        assert_eq!(cfg.port, 8443);
        assert_eq!(cfg.listen_addr(), "0.0.0.0:8443".parse().unwrap());
        assert_eq!(cfg.storage_dir, Some(PathBuf::from("/data/wolin")));
        assert_eq!(cfg.effective_base_url(), "https://pod.home.example");
        assert_eq!(cfg.pod_uri_prefix, "wolin://home");
        assert_eq!(cfg.pod_cloud_domain, "home.example");
        assert_eq!(cfg.oidc_issuer, "https://auth.home.example");
        assert_eq!(cfg.oidc_audience.as_deref(), Some("wolin-home"));
        assert_eq!(
            cfg.owner_webid.as_deref(),
            Some("did:web:owner.home.example")
        );
        assert!(cfg.require_explicit_delegation);
        assert!(!cfg.mcp_enabled);
        assert_eq!(cfg.max_body_bytes, 4_194_304);
    }

    #[test]
    fn unit_cli_flags_override_env_vars_and_empty_env_uses_defaults() {
        use std::collections::HashMap;

        let env_map = HashMap::from([
            ("WOLIN_LISTEN_ADDR", "0.0.0.0:8080"),
            ("WOLIN_STORAGE_DIR", "/env/data"),
            ("WOLIN_BASE_URL", "https://env.example.org"),
            ("WOLIN_POD_PREFIX", "wolin://env"),
            ("WOLIN_POD_CLOUD_DOMAIN", "env.example.org"),
            ("WOLIN_OIDC_ISSUER", "https://auth.env.example.org"),
            ("WOLIN_OIDC_AUDIENCE", "env-aud"),
            ("WOLIN_OWNER_WEBID", "did:web:env.example.org"),
            ("WOLIN_REQUIRE_EXPLICIT_DELEGATION", "true"),
            ("WOLIN_MCP_ENABLED", "false"),
            ("WOLIN_MAX_BODY_BYTES", "2097152"),
        ]);

        let CliParseOutcome::Run(cfg) = ServerCliConfig::parse_from_with_env(
            [
                "wolin-server",
                "--listen-addr",
                "127.0.0.1:9000",
                "--storage-dir",
                "/cli/data",
                "--base-url",
                "https://cli.example.org/",
                "--pod-prefix",
                "wolin://cli/",
                "--pod-cloud-domain",
                "cli.example.org",
                "--oidc-issuer",
                "https://auth.cli.example.org",
                "--oidc-audience",
                "cli-aud",
                "--owner-webid",
                "did:web:cli.example.org",
                "--no-require-explicit-delegation",
                "--mcp-enabled",
                "true",
                "--max-body-bytes",
                "8388608",
            ],
            |k| env_map.get(k).map(|v| (*v).to_string()),
        )
        .expect("CLI override parse should succeed") else {
            panic!("expected Run");
        };

        assert_eq!(cfg.listen_addr(), "127.0.0.1:9000".parse().unwrap());
        assert_eq!(cfg.storage_dir, Some(PathBuf::from("/cli/data")));
        assert_eq!(cfg.effective_base_url(), "https://cli.example.org");
        assert_eq!(cfg.pod_uri_prefix, "wolin://cli");
        assert_eq!(cfg.pod_cloud_domain, "cli.example.org");
        assert_eq!(cfg.oidc_issuer, "https://auth.cli.example.org");
        assert_eq!(cfg.oidc_audience.as_deref(), Some("cli-aud"));
        assert_eq!(cfg.owner_webid.as_deref(), Some("did:web:cli.example.org"));
        assert!(!cfg.require_explicit_delegation);
        assert!(cfg.mcp_enabled);
        assert_eq!(cfg.max_body_bytes, 8_388_608);

        // Partial CLI override: WOLIN_LISTEN_ADDR sets 0.0.0.0:8080, CLI -p 9090 overrides port only
        let CliParseOutcome::Run(partial) =
            ServerCliConfig::parse_from_with_env(["wolin-server", "-p", "9090", "--no-mcp"], |k| {
                match k {
                    "WOLIN_LISTEN_ADDR" => Some("0.0.0.0:8080".to_string()),
                    "WOLIN_MCP_ENABLED" => Some("true".to_string()),
                    _ => None,
                }
            })
            .expect("partial CLI override")
        else {
            panic!("expected Run");
        };
        assert_eq!(partial.host, IpAddr::from([0, 0, 0, 0]));
        assert_eq!(partial.port, 9090);
        assert!(!partial.mcp_enabled);

        // WOLIN_HOST + WOLIN_PORT + blank optional env vars (as in .env files)
        let CliParseOutcome::Run(host_port_cfg) =
            ServerCliConfig::parse_from_with_env(["wolin-server"], |k| match k {
                "WOLIN_HOST" => Some("::1".to_string()),
                "WOLIN_PORT" => Some("7070".to_string()),
                "WOLIN_OWNER_WEBID" => Some("".to_string()),
                "WOLIN_STORAGE_DIR" => Some("   ".to_string()),
                "WOLIN_BASE_URL" => Some("".to_string()),
                _ => None,
            })
            .expect("host/port + blank optional env parse")
        else {
            panic!("expected Run");
        };
        assert_eq!(host_port_cfg.listen_addr(), "[::1]:7070".parse().unwrap());
        assert_eq!(host_port_cfg.effective_base_url(), "http://[::1]:7070");
        assert!(host_port_cfg.storage_dir.is_none());
        assert!(host_port_cfg.owner_webid.is_none());
    }

    #[test]
    fn unit_invalid_env_vars_and_listen_addr_fail_closed() {
        let bad_envs = [
            ("WOLIN_LISTEN_ADDR", "localhost:4000"),
            ("WOLIN_LISTEN_ADDR", "127.0.0.1"),
            ("WOLIN_HOST", "localhost"),
            ("WOLIN_PORT", "70000"),
            ("WOLIN_BASE_URL", "ftp://bad.example"),
            ("WOLIN_BASE_URL", "https://"),
            ("WOLIN_BASE_URL", "https://pod.example.org?bad=1"),
            ("WOLIN_OIDC_ISSUER", "not-a-url"),
            ("WOLIN_OWNER_WEBID", "not-a-uri"),
            ("WOLIN_POD_CLOUD_DOMAIN", "https://example.org"),
            ("WOLIN_MCP_ENABLED", "maybe"),
            ("WOLIN_REQUIRE_EXPLICIT_DELEGATION", "2"),
            ("WOLIN_MAX_BODY_BYTES", "0"),
            ("WOLIN_MAX_BODY_BYTES", "notanumber"),
        ];

        for (key, bad_val) in bad_envs {
            let res = ServerCliConfig::parse_from_with_env(["wolin-server"], |k| {
                (k == key).then(|| bad_val.to_string())
            });
            assert!(res.is_err(), "expected {key}={bad_val} to fail closed");
        }

        // Prevent missing option values from swallowing subsequent flags
        assert!(
            ServerCliConfig::parse_from(["wolin-server", "--owner-webid", "--no-mcp"]).is_err()
        );
        assert!(
            ServerCliConfig::parse_from([
                "wolin-server",
                "--oidc-audience",
                "--require-explicit-delegation",
            ])
            .is_err()
        );
        assert!(
            ServerCliConfig::parse_from(["wolin-server", "--listen-addr", "localhost:4000"])
                .is_err()
        );

        // DID canonicalization + WOLIN_STORAGE_DIR=memory + --in-memory + --healthcheck
        let CliParseOutcome::Healthcheck(hc_cfg) = ServerCliConfig::parse_from_with_env(
            ["wolin-server", "--in-memory", "--healthcheck"],
            |k| match k {
                "WOLIN_LISTEN_ADDR" => Some("0.0.0.0:4567".to_string()),
                "WOLIN_STORAGE_DIR" => Some("/data".to_string()),
                "WOLIN_OWNER_WEBID" => Some("did:web:Alice.Example.org".to_string()),
                _ => None,
            },
        )
        .expect("healthcheck + canonical DID parse") else {
            panic!("expected Healthcheck");
        };
        assert!(hc_cfg.storage_dir.is_none());
        assert_eq!(hc_cfg.healthcheck_addr(), "127.0.0.1:4567".parse().unwrap());
        assert_eq!(
            hc_cfg.owner_webid.as_deref(),
            Some("did:web:alice.example.org")
        );

        let CliParseOutcome::Run(mem_env_cfg) =
            ServerCliConfig::parse_from_with_env(["wolin-server"], |k| {
                (k == "WOLIN_STORAGE_DIR").then(|| "memory".to_string())
            })
            .expect("WOLIN_STORAGE_DIR=memory parse")
        else {
            panic!("expected Run");
        };
        assert!(mem_env_cfg.storage_dir.is_none());

        // --help and --version must succeed even if an environment variable is malformed
        assert!(matches!(
            ServerCliConfig::parse_from_with_env(["wolin-server", "--help"], |_| {
                Some("invalid".to_string())
            })
            .expect("--help ignores bad env"),
            CliParseOutcome::Help(_)
        ));
        assert!(matches!(
            ServerCliConfig::parse_from_with_env(["wolin-server", "--version"], |_| {
                Some("invalid".to_string())
            })
            .expect("--version ignores bad env"),
            CliParseOutcome::Version(_)
        ));
    }

    #[tokio::test]
    async fn unit_healthz_endpoint_and_mcp_disabled_mode() {
        use axum::{
            body::{Body, to_bytes},
            http::{Method, Request, StatusCode, header},
        };
        use tower::ServiceExt;

        let cfg = LdpConfig::new("http://pod.wolin.local", "wolin://pod").with_mcp_enabled(false);
        let state = AppState::new_in_memory(PolicyEngine::new(), cfg)
            .await
            .expect("init in-memory state");
        let app = build_router(state);

        // GET /healthz -> 200 OK
        let hz = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(hz.status(), StatusCode::OK);
        let hz_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(hz.into_body(), 65_536).await.unwrap()).unwrap();
        assert_eq!(hz_json["status"], "healthy");

        // DELETE /healthz -> 405 Method Not Allowed
        let del_hz = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del_hz.status(), StatusCode::METHOD_NOT_ALLOWED);

        // Percent-encoded /%68ealthz/probe must be rejected as reserved system path, not stored in LDP
        let enc_hz = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/%68ealthz/probe")
                    .header(header::CONTENT_TYPE, "text/turtle")
                    .body(Body::from("<> <http://purl.org/dc/terms/title> \"bad\" ."))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enc_hz.status(), StatusCode::BAD_REQUEST);

        // GET /.well-known/wolin reflects disabled MCP and advertises /healthz
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
        assert_eq!(wk_json["endpoints"]["healthz"], "/healthz");
        assert!(wk_json["endpoints"].get("mcp").is_none());
        assert_eq!(wk_json["capabilities"]["mcp_jsonrpc"], false);
        assert_eq!(wk_json["capabilities"]["mcp_sse"], false);
        assert_eq!(wk_json["capabilities"]["mcp_tools"], json!([]));

        // POST /mcp, GET /mcp, and GET /mcp/sse all return 404 Not Found when MCP is disabled
        let mcp_post = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mcp_post.status(), StatusCode::NOT_FOUND);

        let mcp_get = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/mcp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mcp_get.status(), StatusCode::NOT_FOUND);

        let mcp_sse = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mcp/sse")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mcp_sse.status(), StatusCode::NOT_FOUND);

        // Custom base_url host (e.g. wolin.example.org under pod_cloud_domain example.org)
        // must NOT be misrouted as a tenant subdomain, and run_healthcheck_probe succeeds on TCP.
        let custom_cfg = LdpConfig::new("https://wolin.example.org", "wolin://pod")
            .with_pod_cloud_domain("example.org");
        let custom_state = AppState::new_in_memory(PolicyEngine::new(), custom_cfg)
            .await
            .unwrap();
        let custom_app = build_router(custom_state);

        let create_pod = custom_app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/pods")
                    .header(header::HOST, "wolin.example.org")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"pod_id":"alice"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_pod.status(), StatusCode::CREATED);

        let card = custom_app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/pods/alice/profile/card")
                    .header(header::HOST, "wolin.example.org")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(card.status(), StatusCode::OK);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound_port = listener.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            let _ = axum::serve(listener, custom_app).await;
        });
        let probe_cfg = ServerCliConfig {
            host: IpAddr::from([0, 0, 0, 0]),
            port: bound_port,
            ..ServerCliConfig::default()
        };
        run_healthcheck_probe(&probe_cfg)
            .await
            .expect("live healthcheck probe should succeed");
        srv.abort();
    }

    #[test]
    fn unit_pod_lru_and_quota_cli_and_env_parsing() {
        let CliParseOutcome::Run(defaults) =
            ServerCliConfig::parse_from(["wolin-server"]).expect("default parse")
        else {
            panic!("expected Run");
        };
        assert_eq!(defaults.max_open_pods, 256);
        assert_eq!(defaults.pod_quota_bytes, 1_073_741_824);

        let CliParseOutcome::Run(from_env) =
            ServerCliConfig::parse_from_with_env(["wolin-server"], |k| match k {
                "WOLIN_MAX_OPEN_PODS" => Some("64".to_string()),
                "WOLIN_DEFAULT_POD_QUOTA_BYTES" => Some("536870912".to_string()),
                _ => None,
            })
            .expect("env parse")
        else {
            panic!("expected Run");
        };
        assert_eq!(from_env.max_open_pods, 64);
        assert_eq!(from_env.pod_quota_bytes, 536_870_912);

        let CliParseOutcome::Run(cli_override) = ServerCliConfig::parse_from_with_env(
            [
                "wolin-server",
                "--max-open-pods",
                "16",
                "--pod-quota-bytes=10485760",
            ],
            |k| match k {
                "WOLIN_MAX_OPEN_PODS" => Some("64".to_string()),
                "WOLIN_DEFAULT_POD_QUOTA_BYTES" => Some("536870912".to_string()),
                _ => None,
            },
        )
        .expect("CLI override") else {
            panic!("expected Run");
        };
        assert_eq!(cli_override.max_open_pods, 16);
        assert_eq!(cli_override.pod_quota_bytes, 10_485_760);

        for (bad_env, bad_val) in [
            ("WOLIN_MAX_OPEN_PODS", "0"),
            ("WOLIN_MAX_OPEN_PODS", "abc"),
            ("WOLIN_DEFAULT_POD_QUOTA_BYTES", "0"),
            ("WOLIN_DEFAULT_POD_QUOTA_BYTES", "-5"),
        ] {
            assert!(
                ServerCliConfig::parse_from_with_env(["wolin-server"], |k| {
                    (k == bad_env).then(|| bad_val.to_string())
                })
                .is_err(),
                "expected {bad_env}={bad_val} to fail closed"
            );
        }
        assert!(ServerCliConfig::parse_from(["wolin-server", "--max-open-pods", "0"]).is_err());
        assert!(ServerCliConfig::parse_from(["wolin-server", "--pod-quota-bytes", "0"]).is_err());
    }

    #[test]
    fn unit_reserved_pods_cli_and_env_parsing() {
        let CliParseOutcome::Run(defaults) =
            ServerCliConfig::parse_from(["wolin-server"]).expect("default parse")
        else {
            panic!("expected Run");
        };
        assert!(defaults.reserved_pods.is_empty());

        let CliParseOutcome::Run(from_env) =
            ServerCliConfig::parse_from_with_env(["wolin-server"], |k| {
                (k == "WOLIN_RESERVED_PODS")
                    .then(|| "vip-one, Retired-Pod , founder-2025,".to_string())
            })
            .expect("WOLIN_RESERVED_PODS parse")
        else {
            panic!("expected Run");
        };
        assert_eq!(
            from_env
                .reserved_pods
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["founder-2025", "retired-pod", "vip-one"]
        );

        // CLI --reserved-pods overrides WOLIN_RESERVED_PODS, and --reserved-pods="" clears it
        let CliParseOutcome::Run(cli_override) = ServerCliConfig::parse_from_with_env(
            [
                "wolin-server",
                "--reserved-pods",
                "custom-alpha,custom-beta",
            ],
            |k| (k == "WOLIN_RESERVED_PODS").then(|| "vip-one".to_string()),
        )
        .expect("CLI --reserved-pods override") else {
            panic!("expected Run");
        };
        assert_eq!(
            cli_override
                .reserved_pods
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["custom-alpha", "custom-beta"]
        );

        let CliParseOutcome::Run(cleared) =
            ServerCliConfig::parse_from_with_env(["wolin-server", "--reserved-pods="], |k| {
                (k == "WOLIN_RESERVED_PODS").then(|| "vip-one".to_string())
            })
            .expect("CLI --reserved-pods= empty clear")
        else {
            panic!("expected Run");
        };
        assert!(cleared.reserved_pods.is_empty());

        // Malformed handles in WOLIN_RESERVED_PODS or --reserved-pods must fail closed
        for bad_csv in [
            "ab",
            "xn--bad",
            "-leading",
            "trailing-",
            "bad_pod",
            "../etc",
            ",,,",
        ] {
            assert!(
                ServerCliConfig::parse_from_with_env(["wolin-server"], |k| {
                    (k == "WOLIN_RESERVED_PODS").then(|| bad_csv.to_string())
                })
                .is_err(),
                "expected WOLIN_RESERVED_PODS='{bad_csv}' to fail closed"
            );
        }
    }
}
