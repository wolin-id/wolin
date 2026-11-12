//! Wolin Server: Integrated Solid LDP + WAC/ACP + Identity HTTP Runtime.

pub mod auth;
pub mod error;
pub mod ldp;

use std::sync::{Arc, RwLock};

use axum::{response::Json, routing::get, Router};
use ldp::LdpCatalog;
use serde_json::json;
use wolin_identity::{JwtSignatureVerifier, OidcValidationOptions};
use wolin_policy::PolicyEngine;
use wolin_storage::{PhysicalStore, SemanticGraphStore};

const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Configuration for the Solid LDP & WAC/ACP HTTP pipeline.
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

/// Shared application state across Axum LDP and system endpoints.
pub struct AppState {
    pub physical_store: PhysicalStore,
    pub graph_store: SemanticGraphStore,
    pub policy_engine: RwLock<PolicyEngine>,
    pub catalog: tokio::sync::RwLock<LdpCatalog>,
    pub config: LdpConfig,
}

impl AppState {
    /// Construct [`AppState`], loading any persisted LDP catalog metadata from `physical_store`.
    pub async fn new(
        physical_store: PhysicalStore,
        graph_store: SemanticGraphStore,
        policy_engine: PolicyEngine,
        config: LdpConfig,
    ) -> wolin_core::Result<Arc<Self>> {
        let catalog = LdpCatalog::load_or_init(&physical_store).await?;
        Ok(Arc::new(Self {
            physical_store,
            graph_store,
            policy_engine: RwLock::new(policy_engine),
            catalog: tokio::sync::RwLock::new(catalog),
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

    /// Mutate the live [`PolicyEngine`] safely under write lock.
    pub fn with_policy_mut<R>(&self, f: impl FnOnce(&mut PolicyEngine) -> R) -> R {
        let mut guard = self
            .policy_engine
            .write()
            .unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }
}

/// Build the Axum 0.8 router serving system discovery routes and the Solid LDP + WAC pipeline.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/.well-known/wolin", get(well_known_wolin))
        .fallback(ldp::handle_ldp_request)
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

pub async fn well_known_wolin() -> Json<serde_json::Value> {
    Json(json!({
        "wolin_version": "0.1.0",
        "protocols": ["solid-0.11", "wac-2.0", "mcp-2024-11-05", "oidc-1.0"],
        "storage_backend": "opendal+oxigraph",
        "identity_mesh": ["webid", "did:key", "did:nostr", "zitadel-oidc"]
    }))
}
