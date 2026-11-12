//! Wolin Server: Integrated Solid LDP + WAC/ACP + Native MCP HTTP Runtime.

pub mod auth;
pub mod error;
pub mod ldp;
pub mod mcp;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use axum::{
    extract::State,
    response::Json,
    routing::{get, post},
    Router,
};
use ldp::LdpCatalog;
use serde_json::json;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use wolin_identity::{JwtSignatureVerifier, OidcValidationOptions};
use wolin_mcp::{DisclosurePolicy, McpAgentServer, McpGatewayConfig};
use wolin_policy::PolicyEngine;
use wolin_storage::{PhysicalStore, SemanticGraphStore};

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
}

impl Default for LdpConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:4000".to_string(),
            pod_uri_prefix: "wolin://pod".to_string(),
            oidc_options: OidcValidationOptions::new("https://auth.wolin.id"),
            jwt_verifier: None,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            policy_clock_epoch_secs: None,
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
}

/// Shared application state across Axum Solid LDP, Native MCP, and system discovery endpoints.
pub struct AppState {
    pub physical_store: PhysicalStore,
    pub graph_store: SemanticGraphStore,
    pub policy_engine: Arc<RwLock<PolicyEngine>>,
    pub disclosure_policy: Arc<RwLock<DisclosurePolicy>>,
    pub catalog_lock: Arc<tokio::sync::RwLock<()>>,
    pub catalog: tokio::sync::RwLock<LdpCatalog>,
    pub mcp_server: McpAgentServer,
    pub config: LdpConfig,
}

impl AppState {
    /// Construct [`AppState`], loading persisted LDP catalog metadata and rehydrating `.acl`
    /// WAC rules into a unified runtime shared across Solid LDP and [`McpAgentServer`].
    pub async fn new(
        physical_store: PhysicalStore,
        graph_store: SemanticGraphStore,
        mut policy_engine: PolicyEngine,
        config: LdpConfig,
    ) -> wolin_core::Result<Arc<Self>> {
        let catalog = LdpCatalog::load_or_init(&physical_store).await?;
        ldp::rehydrate_persisted_acl_rules(&graph_store, &catalog, &mut policy_engine, &config)?;

        let policy_arc = Arc::new(RwLock::new(policy_engine));
        let disclosure_arc = Arc::new(RwLock::new(DisclosurePolicy::new()));
        let catalog_lock = Arc::new(tokio::sync::RwLock::new(()));

        let mut mcp_config = McpGatewayConfig::new(&config.base_url, &config.pod_uri_prefix)
            .with_max_resource_bytes(config.max_body_bytes);
        if let Some(ts) = config.policy_clock_epoch_secs {
            mcp_config = mcp_config.with_policy_clock(ts);
        }

        let mcp_server = McpAgentServer::with_shared_state(
            physical_store.clone(),
            graph_store.clone(),
            Arc::clone(&policy_arc),
            Arc::clone(&disclosure_arc),
            Arc::clone(&catalog_lock),
            mcp_config,
        );

        Ok(Arc::new(Self {
            physical_store,
            graph_store,
            policy_engine: policy_arc,
            disclosure_policy: disclosure_arc,
            catalog_lock,
            catalog: tokio::sync::RwLock::new(catalog),
            mcp_server,
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

    /// Create a disk-backed persistent [`AppState`] rooted at `storage_dir` (`blobs/` + `graph/`).
    pub async fn new_persistent(
        storage_dir: impl AsRef<Path>,
        policy_engine: PolicyEngine,
        config: LdpConfig,
    ) -> wolin_core::Result<Arc<Self>> {
        let root = storage_dir.as_ref();
        let blobs_dir = root.join("blobs");
        let graph_dir = root.join("graph");
        ensure_private_dir(root)?;
        ensure_private_dir(&blobs_dir)?;
        ensure_private_dir(&graph_dir)?;

        let blobs_str = blobs_dir.to_str().ok_or_else(|| {
            wolin_core::WolinError::InvalidFormat(
                "Storage directory path must be valid UTF-8".into(),
            )
        })?;
        let physical_store = PhysicalStore::new_fs(blobs_str)?;
        let graph_store = SemanticGraphStore::open(&graph_dir)?;
        Self::new(physical_store, graph_store, policy_engine, config).await
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
        let mut cat_guard = self.catalog.write().await;
        *cat_guard = fresh;
        Ok(())
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
    Router::new()
        .route("/health", get(health_check))
        .route("/.well-known/wolin", get(well_known_wolin))
        .route("/mcp", post(mcp::handle_mcp_post))
        .route("/mcp/sse", get(mcp::handle_mcp_sse))
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
    let mcp_tools: Vec<String> = state
        .mcp_server
        .list_tools()
        .into_iter()
        .map(|t| t.name)
        .collect();

    Json(json!({
        "wolin_version": env!("CARGO_PKG_VERSION"),
        "base_url": state.config.base_url,
        "pod_uri_prefix": state.config.pod_uri_prefix,
        "protocols": ["solid-0.11", "wac-2.0", "acp-1.0", "mcp-2024-11-05", "oidc-1.0"],
        "storage_backend": "opendal+oxigraph",
        "identity_mesh": ["webid", "did:key", "did:web", "did:nostr", "zitadel-oidc"],
        "endpoints": {
            "health": "/health",
            "discovery": "/.well-known/wolin",
            "ldp_root": "/",
            "pods": "/pods/",
            "mcp": "/mcp",
            "mcp_sse": "/mcp/sse"
        },
        "capabilities": {
            "solid_ldp": true,
            "wac_acp_pdp": true,
            "mcp_jsonrpc": true,
            "mcp_sse": true,
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
    pub oidc_issuer: String,
    pub oidc_audience: Option<String>,
    pub owner_webid: Option<String>,
    pub require_explicit_delegation: bool,
    pub max_body_bytes: usize,
}

impl Default for ServerCliConfig {
    fn default() -> Self {
        Self {
            host: IpAddr::from([127, 0, 0, 1]),
            port: 4000,
            storage_dir: None,
            base_url: None,
            pod_uri_prefix: "wolin://pod".to_string(),
            oidc_issuer: "https://auth.wolin.id".to_string(),
            oidc_audience: None,
            owner_webid: None,
            require_explicit_delegation: false,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

impl ServerCliConfig {
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
    Help(String),
    Version(String),
}

impl ServerCliConfig {
    pub fn usage() -> String {
        format!(
            "wolin-server {} — Universal Identity & Sovereign Pod Persistence Fabric\n\n\
             USAGE:\n  \
               wolin-server [OPTIONS]\n\n\
             OPTIONS:\n  \
               --host <IP>                     Bind IP literal (default: 127.0.0.1)\n  \
               -p, --port <PORT>               Bind TCP port (default: 4000)\n  \
               -d, --storage-dir <DIR>         Persistent storage root (omit for ephemeral in-memory)\n  \
               --base-url <URL>                Public canonical Pod base URL\n  \
               --pod-prefix <URI>              Canonical PDP Pod URI prefix (default: wolin://pod)\n  \
               --oidc-issuer <URL>             Expected OIDC / ZITADEL token issuer\n  \
               --oidc-audience <AUD>           Optional required OIDC token audience\n  \
               --owner-webid <WEBID_OR_DID>    Bootstrap full WAC owner access on Pod root\n  \
               --require-explicit-delegation   Require explicit DelegationGrant for AI agents\n  \
               --max-body-bytes <BYTES>        Maximum HTTP request payload bytes (default: 16777216)\n  \
               -h, --help                      Print help information\n  \
               -V, --version                   Print version information",
            env!("CARGO_PKG_VERSION")
        )
    }

    pub fn parse_from<I, S>(args: I) -> Result<CliParseOutcome, String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut iter = args.into_iter().map(Into::into);
        let _bin = iter.next();
        let mut cfg = Self::default();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "-h" | "--help" => return Ok(CliParseOutcome::Help(Self::usage())),
                "-V" | "--version" => {
                    return Ok(CliParseOutcome::Version(format!(
                        "wolin-server {}",
                        env!("CARGO_PKG_VERSION")
                    )));
                }
                "--require-explicit-delegation" => {
                    cfg.require_explicit_delegation = true;
                }
                "--host" => {
                    let val = next_val(&mut iter, "--host")?;
                    cfg.host = val
                        .parse::<IpAddr>()
                        .map_err(|_| format!("Invalid IP literal for --host: '{val}'"))?;
                }
                "-p" | "--port" => {
                    let val = next_val(&mut iter, "--port")?;
                    cfg.port = val
                        .parse::<u16>()
                        .map_err(|_| format!("Invalid TCP port for --port: '{val}'"))?;
                }
                "-d" | "--storage-dir" => {
                    let val = next_val(&mut iter, "--storage-dir")?;
                    if val.trim().is_empty() {
                        return Err("--storage-dir must not be empty".to_string());
                    }
                    cfg.storage_dir = Some(PathBuf::from(val));
                }
                "--base-url" => {
                    let val = next_val(&mut iter, "--base-url")?;
                    if !(val.starts_with("http://") || val.starts_with("https://")) {
                        return Err("--base-url must start with http:// or https://".to_string());
                    }
                    cfg.base_url = Some(val.trim_end_matches('/').to_string());
                }
                "--pod-prefix" => {
                    let val = next_val(&mut iter, "--pod-prefix")?;
                    if val.trim().is_empty() {
                        return Err("--pod-prefix must not be empty".to_string());
                    }
                    cfg.pod_uri_prefix = val.trim_end_matches('/').to_string();
                }
                "--oidc-issuer" => {
                    let val = next_val(&mut iter, "--oidc-issuer")?;
                    if val.trim().is_empty() {
                        return Err("--oidc-issuer must not be empty".to_string());
                    }
                    cfg.oidc_issuer = val;
                }
                "--oidc-audience" => {
                    let val = next_val(&mut iter, "--oidc-audience")?;
                    if val.trim().is_empty() {
                        return Err("--oidc-audience must not be empty".to_string());
                    }
                    cfg.oidc_audience = Some(val);
                }
                "--owner-webid" => {
                    let val = next_val(&mut iter, "--owner-webid")?;
                    if val.trim().is_empty() {
                        return Err("--owner-webid must not be empty".to_string());
                    }
                    cfg.owner_webid = Some(val);
                }
                "--max-body-bytes" => {
                    let val = next_val(&mut iter, "--max-body-bytes")?;
                    let parsed = val
                        .parse::<usize>()
                        .map_err(|_| format!("Invalid integer for --max-body-bytes: '{val}'"))?;
                    if parsed == 0 {
                        return Err("--max-body-bytes must be greater than 0".to_string());
                    }
                    cfg.max_body_bytes = parsed;
                }
                unknown => {
                    return Err(format!(
                        "Unknown CLI flag '{unknown}'. Run with --help for usage."
                    ));
                }
            }
        }

        Ok(CliParseOutcome::Run(cfg))
    }
}

fn next_val<I: Iterator<Item = String>>(iter: &mut I, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("Missing value for CLI option '{flag}'"))
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
}
