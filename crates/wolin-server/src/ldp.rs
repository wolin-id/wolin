use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wolin_core::{Principal, ResourceKind, ResourceUri, WebId};
use wolin_policy::{AccessDecision, AccessMode, PolicyEngine, SubjectMatcher, WacRule};
#[allow(deprecated)]
use wolin_storage::{
    PhysicalStore, PodStoreManager, SemanticGraphStore,
    rdf_io::{JsonLdProfileSet, RdfFormat},
    rdf_model::{NamedNode, NamedOrBlankNode, Term, Triple},
    rdf_sparql::Update as SparqlUpdate,
};

use crate::{
    AppState, LdpConfig,
    assets::{DEFAULT_ASSET_SIGNING_TTL_SECS, build_signed_asset_redirect_url},
    auth::extract_principal_for_request,
    error::LdpError,
    pods::extract_subdomain_pod,
};

const CATALOG_META_KEY: &str = "__wolin_meta/catalog.json";
const RESERVED_META_SEG: &str = "__wolin_meta";
const MAX_URI_LEN: usize = 2048;
const MAX_SLUG_LEN: usize = 255;

pub const LDP_NS: &str = "http://www.w3.org/ns/ldp#";
pub const LDP_RESOURCE: &str = "http://www.w3.org/ns/ldp#Resource";
pub const LDP_RDF_SOURCE: &str = "http://www.w3.org/ns/ldp#RDFSource";
pub const LDP_NON_RDF_SOURCE: &str = "http://www.w3.org/ns/ldp#NonRDFSource";
pub const LDP_CONTAINER: &str = "http://www.w3.org/ns/ldp#Container";
pub const LDP_BASIC_CONTAINER: &str = "http://www.w3.org/ns/ldp#BasicContainer";
pub const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";
pub const LDP_INBOX_REL: &str = "http://www.w3.org/ns/ldp#inbox";
pub const PIM_STORAGE: &str = "http://www.w3.org/ns/pim/space#Storage";
pub const PIM_STORAGE_REL: &str = "http://www.w3.org/ns/pim/space#storage";
pub const SOLID_OIDC_ISSUER: &str = "http://www.w3.org/ns/solid/terms#oidcIssuer";
pub const FOAF_PERSON: &str = "http://xmlns.com/foaf/0.1/Person";
pub const FOAF_PERSONAL_PROFILE_DOCUMENT: &str =
    "http://xmlns.com/foaf/0.1/PersonalProfileDocument";

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const ACL_AUTHORIZATION: &str = "http://www.w3.org/ns/auth/acl#Authorization";
const ACL_AGENT: &str = "http://www.w3.org/ns/auth/acl#agent";
const ACL_AGENT_CLASS: &str = "http://www.w3.org/ns/auth/acl#agentClass";
const ACL_ACCESS_TO: &str = "http://www.w3.org/ns/auth/acl#accessTo";
const ACL_DEFAULT: &str = "http://www.w3.org/ns/auth/acl#default";
const ACL_DEFAULT_FOR_NEW: &str = "http://www.w3.org/ns/auth/acl#defaultForNew";
const ACL_MODE: &str = "http://www.w3.org/ns/auth/acl#mode";
const ACL_READ: &str = "http://www.w3.org/ns/auth/acl#Read";
const ACL_WRITE: &str = "http://www.w3.org/ns/auth/acl#Write";
const ACL_APPEND: &str = "http://www.w3.org/ns/auth/acl#Append";
const ACL_CONTROL: &str = "http://www.w3.org/ns/auth/acl#Control";
const ACL_AUTHENTICATED_AGENT: &str = "http://www.w3.org/ns/auth/acl#AuthenticatedAgent";
const FOAF_AGENT: &str = "http://xmlns.com/foaf/0.1/Agent";
const FOAF_AUTHENTICATED_AGENT: &str = "http://xmlns.com/foaf/0.1/AuthenticatedAgent";

const ALLOW_CONTAINER: &str = "OPTIONS, HEAD, GET, POST, PUT, PATCH, DELETE";
const ALLOW_RDF_SOURCE: &str = "OPTIONS, HEAD, GET, PUT, PATCH, DELETE";
const ALLOW_NON_RDF_SOURCE: &str = "OPTIONS, HEAD, GET, PUT, DELETE";
const ALLOW_ACL: &str = "OPTIONS, HEAD, GET, PUT, PATCH, DELETE";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdpEntry {
    pub path: String,
    pub kind: ResourceKind,
    pub content_type: String,
    pub etag: String,
    #[serde(default)]
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodTombstone {
    pub reason: String,
    pub retired_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdpCatalog {
    pub entries: BTreeMap<String, LdpEntry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tombstones: BTreeMap<String, PodTombstone>,
}

impl Default for LdpCatalog {
    fn default() -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(
            "/".to_string(),
            LdpEntry {
                path: "/".to_string(),
                kind: ResourceKind::Container,
                content_type: "text/turtle".to_string(),
                etag: compute_etag(b"root-container-v0"),
                size_bytes: 0,
            },
        );
        Self {
            entries,
            tombstones: BTreeMap::new(),
        }
    }
}

impl LdpCatalog {
    pub async fn load_or_init(physical_store: &PhysicalStore) -> wolin_core::Result<Self> {
        if physical_store.exists(CATALOG_META_KEY).await? {
            let bytes = physical_store.get(CATALOG_META_KEY).await?;
            let mut catalog: Self = serde_json::from_slice(&bytes).map_err(|e| {
                wolin_core::WolinError::Storage(format!("Corrupt LDP catalog metadata: {e}"))
            })?;
            for entry in catalog.entries.values_mut() {
                if entry.size_bytes == 0
                    && entry.kind != ResourceKind::Container
                    && let Some(inferred) = infer_size_from_wolin_etag(&entry.etag)
                {
                    entry.size_bytes = inferred;
                }
            }
            catalog
                .entries
                .entry("/".to_string())
                .or_insert_with(|| LdpEntry {
                    path: "/".to_string(),
                    kind: ResourceKind::Container,
                    content_type: "text/turtle".to_string(),
                    etag: compute_etag(b"root-container-v0"),
                    size_bytes: 0,
                });
            Ok(catalog)
        } else {
            Ok(Self::default())
        }
    }

    pub async fn persist(&self, physical_store: &PhysicalStore) -> Result<(), LdpError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|e| LdpError::Internal(format!("Catalog serialize failed: {e}")))?;
        physical_store
            .put_with_content_type(CATALOG_META_KEY, bytes, "application/json")
            .await?;
        Ok(())
    }

    pub fn pod_usage_bytes(&self, pod_id: &str) -> u64 {
        self.entries
            .values()
            .filter(|entry| {
                PodStoreManager::pod_id_from_canonical_path(&entry.path)
                    .ok()
                    .flatten()
                    == Some(pod_id)
            })
            .fold(0u64, |acc, entry| acc.saturating_add(entry.size_bytes))
    }

    pub fn all_pod_usages(&self) -> HashMap<String, u64> {
        let mut totals = HashMap::new();
        for entry in self.entries.values() {
            if entry.size_bytes == 0 {
                continue;
            }
            if let Ok(Some(pod_id)) = PodStoreManager::pod_id_from_canonical_path(&entry.path) {
                let cur = totals.entry(pod_id.to_string()).or_insert(0u64);
                *cur = cur.saturating_add(entry.size_bytes);
            }
        }
        totals
    }

    pub fn direct_children(&self, container_path: &str) -> Vec<&LdpEntry> {
        self.entries
            .values()
            .filter(|entry| {
                if entry.path == container_path || is_acl_canonical_path(&entry.path) {
                    return false;
                }
                let Some(rel) = entry.path.strip_prefix(container_path) else {
                    return false;
                };
                let trimmed = rel.strip_suffix('/').unwrap_or(rel);
                !trimmed.is_empty() && !trimmed.contains('/')
            })
            .collect()
    }
}

fn infer_size_from_wolin_etag(etag: &str) -> Option<u64> {
    let inner = etag.strip_prefix('"')?.strip_suffix('"')?;
    let (hash_hex, len_hex) = inner.split_once('-')?;
    if hash_hex.len() != 32 || !hash_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(len_hex, 16).ok()
}

#[derive(Debug, Clone)]
pub(crate) struct LdpTarget {
    pub(crate) canonical_path: String,
    pub(crate) is_container_path: bool,
    pub(crate) is_acl: bool,
    pub(crate) acl_path: String,
    pub(crate) policy_target: ResourceUri,
    pub(crate) subdomain_ctx: Option<(String, String)>,
    pub(crate) force_signed_download: bool,
}

impl LdpTarget {
    fn external_iri(&self, base_url: &str, canonical_path: &str) -> String {
        if let Some((ref pod_id, ref sub_origin)) = self.subdomain_ctx {
            let pod_root = format!("/pods/{pod_id}/");
            if canonical_path == pod_root {
                return format!("{}/", sub_origin.trim_end_matches('/'));
            }
            if let Some(rel) = canonical_path.strip_prefix(&pod_root) {
                return http_iri(sub_origin, &format!("/{rel}"));
            }
        }
        http_iri(base_url, canonical_path)
    }

    fn rebase_triples_for_storage(&self, base_url: &str, triples: Vec<Triple>) -> Vec<Triple> {
        let Some((ref pod_id, ref sub_origin)) = self.subdomain_ctx else {
            return triples;
        };
        let from_prefix = format!("{}/", sub_origin.trim_end_matches('/'));
        let to_prefix = format!("{}/pods/{pod_id}/", base_url.trim_end_matches('/'));
        rebase_triples(triples, &from_prefix, &to_prefix)
    }

    fn rebase_triples_for_response(&self, base_url: &str, triples: Vec<Triple>) -> Vec<Triple> {
        let Some((ref pod_id, ref sub_origin)) = self.subdomain_ctx else {
            return triples;
        };
        let from_prefix = format!("{}/pods/{pod_id}/", base_url.trim_end_matches('/'));
        let to_prefix = format!("{}/", sub_origin.trim_end_matches('/'));
        rebase_triples(triples, &from_prefix, &to_prefix)
    }
}

pub async fn handle_ldp_request(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Result<Response, LdpError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let body = req.into_body();

    if method == Method::GET
        && uri.path() == "/"
        && headers.get(header::AUTHORIZATION).is_none()
        && let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok())
        && accept.to_ascii_lowercase().contains("text/html")
        && let Ok(Some((pod_id, _))) =
            crate::pods::extract_subdomain_pod(&headers, &uri, &state.config)
        && !state.config.reserved_pods.contains(&pod_id)
    {
        let cloud_domain = state.config.pod_cloud_domain.trim();
        let target_url = format!("https://auth.{cloud_domain}/passport/{pod_id}");
        if let Ok(loc) = HeaderValue::from_str(&target_url) {
            return Ok((StatusCode::FOUND, [(header::LOCATION, loc)]).into_response());
        }
    }

    let principal = extract_principal_for_request(&method, &uri, &headers, &state).await?;
    let target = parse_ldp_target(&method, &uri, &headers, &state.config)?;

    match method {
        Method::OPTIONS => handle_options(&state, &principal, &target).await,
        Method::GET => handle_get_or_head(&state, &principal, &target, &headers, false).await,
        Method::HEAD => handle_get_or_head(&state, &principal, &target, &headers, true).await,
        Method::PUT => handle_put(&state, &principal, &target, &headers, body).await,
        Method::POST => handle_post(&state, &principal, &target, &headers, body).await,
        Method::PATCH => handle_patch(&state, &principal, &target, &headers, body).await,
        Method::DELETE => handle_delete(&state, &principal, &target, &headers).await,
        _ => {
            // Authorize Read before revealing method capabilities
            let mode = if target.is_acl {
                AccessMode::Control
            } else {
                AccessMode::Read
            };
            authorize(&state, &principal, &target.policy_target, mode)?;
            Err(LdpError::MethodNotAllowed {
                allow: ALLOW_CONTAINER,
                message: format!("HTTP method {} is not supported on LDP resources", method),
            })
        }
    }
}

async fn handle_options(
    state: &AppState,
    principal: &Principal,
    target: &LdpTarget,
) -> Result<Response, LdpError> {
    let required_mode = if target.is_acl {
        AccessMode::Control
    } else {
        AccessMode::Read
    };
    authorize(state, principal, &target.policy_target, required_mode)?;
    let target_pod_id =
        PodStoreManager::pod_id_from_canonical_path(&target.canonical_path)?.map(str::to_string);

    let catalog = state.catalog.read().await;
    if let Some(ref pod_id) = target_pod_id
        && (state.config.reserved_pods.contains(pod_id) || catalog.tombstones.contains_key(pod_id))
    {
        return Err(LdpError::NotFound(format!(
            "LDP resource '{}' not found",
            target.canonical_path
        )));
    }
    let kind = catalog
        .entries
        .get(&target.canonical_path)
        .map(|e| e.kind)
        .unwrap_or(if target.is_container_path {
            ResourceKind::Container
        } else {
            ResourceKind::RdfSource
        });
    drop(catalog);

    let mut resp = StatusCode::NO_CONTENT.into_response();
    attach_ldp_headers(resp.headers_mut(), state, principal, target, kind, None)?;
    Ok(resp)
}

async fn handle_get_or_head(
    state: &AppState,
    principal: &Principal,
    target: &LdpTarget,
    headers: &HeaderMap,
    head_only: bool,
) -> Result<Response, LdpError> {
    let required_mode = if target.is_acl {
        AccessMode::Control
    } else {
        AccessMode::Read
    };
    authorize(state, principal, &target.policy_target, required_mode)?;
    let target_pod_id =
        PodStoreManager::pod_id_from_canonical_path(&target.canonical_path)?.map(str::to_string);

    let catalog = state.catalog.read().await;
    if let Some(ref pod_id) = target_pod_id
        && (state.config.reserved_pods.contains(pod_id) || catalog.tombstones.contains_key(pod_id))
    {
        return Err(LdpError::NotFound(format!(
            "LDP resource '{}' not found",
            target.canonical_path
        )));
    }
    let Some(entry) = catalog.entries.get(&target.canonical_path).cloned() else {
        return Err(LdpError::NotFound(format!(
            "LDP resource '{}' not found",
            target.canonical_path
        )));
    };

    let resource_iri = http_iri(&state.config.base_url, &entry.path);

    match entry.kind {
        ResourceKind::Container => {
            let negotiated_format = negotiate_rdf_format(headers)?;
            let children = catalog.direct_children(&entry.path);
            let mut etag_material = entry.etag.clone();
            let target_graph_store = state.pod_stores.store_for_path(&entry.path)?;
            let mut triples = target_graph_store.get_named_graph_triples(&resource_iri)?;

            let container_node = NamedNode::new(&resource_iri)
                .map_err(|e| LdpError::Internal(format!("Invalid container IRI: {e}")))?;
            let rdf_type_node = NamedNode::new(RDF_TYPE).unwrap();
            for type_iri in [LDP_BASIC_CONTAINER, LDP_CONTAINER, LDP_RESOURCE] {
                triples.push(Triple::new(
                    NamedOrBlankNode::NamedNode(container_node.clone()),
                    rdf_type_node.clone(),
                    Term::NamedNode(NamedNode::new(type_iri).unwrap()),
                ));
            }
            if entry.path == "/" || is_pod_root_path(&entry.path) {
                let pim_storage_node = NamedNode::new(PIM_STORAGE).unwrap();
                let storage_triple = Triple::new(
                    NamedOrBlankNode::NamedNode(container_node.clone()),
                    rdf_type_node.clone(),
                    Term::NamedNode(pim_storage_node),
                );
                if !triples.contains(&storage_triple) {
                    triples.push(storage_triple);
                }
            }

            let contains_pred = NamedNode::new(LDP_CONTAINS).unwrap();
            for child in children {
                etag_material.push('|');
                etag_material.push_str(&child.path);
                etag_material.push(':');
                etag_material.push_str(&child.etag);
                let child_iri = http_iri(&state.config.base_url, &child.path);
                let child_node = NamedNode::new(&child_iri)
                    .map_err(|e| LdpError::Internal(format!("Invalid child IRI: {e}")))?;
                triples.push(Triple::new(
                    NamedOrBlankNode::NamedNode(container_node.clone()),
                    contains_pred.clone(),
                    Term::NamedNode(child_node),
                ));
            }
            drop(catalog);

            let effective_etag = compute_etag(etag_material.as_bytes());
            if if_none_match_satisfied(headers, &effective_etag) {
                let mut resp = StatusCode::NOT_MODIFIED.into_response();
                attach_ldp_headers(
                    resp.headers_mut(),
                    state,
                    principal,
                    target,
                    ResourceKind::Container,
                    Some(&effective_etag),
                )?;
                return Ok(resp);
            }
            check_if_match_get(headers, &effective_etag)?;

            let rebased = target.rebase_triples_for_response(&state.config.base_url, triples);
            let serialized = SemanticGraphStore::serialize_triples(&rebased, negotiated_format)?;
            build_payload_response(
                state,
                principal,
                target,
                ResourceKind::Container,
                rdf_format_media_type(negotiated_format),
                &effective_etag,
                serialized,
                head_only,
            )
        }

        ResourceKind::RdfSource => {
            let negotiated_format = negotiate_rdf_format(headers)?;
            drop(catalog);

            if if_none_match_satisfied(headers, &entry.etag) {
                let mut resp = StatusCode::NOT_MODIFIED.into_response();
                attach_ldp_headers(
                    resp.headers_mut(),
                    state,
                    principal,
                    target,
                    ResourceKind::RdfSource,
                    Some(&entry.etag),
                )?;
                return Ok(resp);
            }
            check_if_match_get(headers, &entry.etag)?;

            let target_graph_store = state.pod_stores.store_for_path(&entry.path)?;
            let triples = target_graph_store.get_named_graph_triples(&resource_iri)?;
            let rebased = target.rebase_triples_for_response(&state.config.base_url, triples);
            let serialized = SemanticGraphStore::serialize_triples(&rebased, negotiated_format)?;
            build_payload_response(
                state,
                principal,
                target,
                ResourceKind::RdfSource,
                rdf_format_media_type(negotiated_format),
                &entry.etag,
                serialized,
                head_only,
            )
        }

        ResourceKind::NonRdfSource => {
            check_accept_for_non_rdf(headers, &entry.content_type)?;
            drop(catalog);

            if if_none_match_satisfied(headers, &entry.etag) {
                let mut resp = StatusCode::NOT_MODIFIED.into_response();
                attach_ldp_headers(
                    resp.headers_mut(),
                    state,
                    principal,
                    target,
                    ResourceKind::NonRdfSource,
                    Some(&entry.etag),
                )?;
                return Ok(resp);
            }
            check_if_match_get(headers, &entry.etag)?;

            if !head_only
                && let (Some(secret), Some(asset_base_url), Some(pod_id)) = (
                    state.config.asset_signing_secret.as_deref(),
                    state.config.asset_public_base_url.as_deref(),
                    target_pod_id.as_deref(),
                )
                && (entry.size_bytes >= state.config.asset_offload_min_bytes
                    || target.force_signed_download)
                && let Some(resource_path) = entry.path.strip_prefix(&format!("/pods/{pod_id}"))
                && resource_path.starts_with('/')
                && resource_path.len() > 1
            {
                let now_secs = state.config.policy_clock_epoch_secs.unwrap_or_else(|| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0)
                });
                let exp = now_secs.saturating_add(DEFAULT_ASSET_SIGNING_TTL_SECS);
                let signed_url = build_signed_asset_redirect_url(
                    asset_base_url,
                    secret,
                    pod_id,
                    resource_path,
                    exp,
                );
                let loc_val = HeaderValue::from_str(&signed_url).map_err(|e| {
                    LdpError::Internal(format!("Invalid signed asset redirect Location: {e}"))
                })?;
                let mut resp = StatusCode::FOUND.into_response();
                attach_ldp_headers(
                    resp.headers_mut(),
                    state,
                    principal,
                    target,
                    ResourceKind::NonRdfSource,
                    Some(&entry.etag),
                )?;
                resp.headers_mut().insert(header::LOCATION, loc_val);
                resp.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("private, no-store"),
                );
                return Ok(resp);
            }

            let blob_key = blob_key_for_path(&entry.path);
            let bytes = state.physical_store.get(&blob_key).await?;
            build_payload_response(
                state,
                principal,
                target,
                ResourceKind::NonRdfSource,
                &entry.content_type,
                &entry.etag,
                bytes,
                head_only,
            )
        }
    }
}

async fn handle_put(
    state: &AppState,
    principal: &Principal,
    target: &LdpTarget,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, LdpError> {
    let required_mode = if target.is_acl {
        AccessMode::Control
    } else {
        AccessMode::Write
    };
    // Enforce WAC / ACP authorization BEFORE reading payload or mutating storage.
    authorize(state, principal, &target.policy_target, required_mode)?;
    let target_pod_id =
        PodStoreManager::pod_id_from_canonical_path(&target.canonical_path)?.map(str::to_string);

    let body_bytes = read_bounded_body(body, state.config.max_body_bytes).await?;
    let link_types = parse_link_type_iris(headers)?;
    let requested_container =
        link_types.contains(LDP_BASIC_CONTAINER) || link_types.contains(LDP_CONTAINER);
    let requested_rdf_source = link_types.contains(LDP_RDF_SOURCE);
    let requested_non_rdf = link_types.contains(LDP_NON_RDF_SOURCE);

    if requested_container && requested_non_rdf {
        return Err(LdpError::BadRequest(
            "Conflicting LDP BasicContainer and NonRDFSource Link types".to_string(),
        ));
    }

    let raw_ct = extract_media_type(headers);
    let resource_iri = http_iri(&state.config.base_url, &target.canonical_path);
    let parse_base_iri = target.external_iri(&state.config.base_url, &target.canonical_path);

    enum PreparedWrite {
        Container {
            triples: Vec<Triple>,
        },
        Rdf {
            triples: Vec<Triple>,
        },
        Acl {
            triples: Vec<Triple>,
            rules: Vec<WacRule>,
        },
        Blob {
            content_type: String,
            bytes: Vec<u8>,
        },
    }

    let prepared = if target.is_acl {
        if requested_container || requested_non_rdf {
            return Err(LdpError::BadRequest(
                "ACL auxiliary resource must be an RDFSource".to_string(),
            ));
        }
        let rdf_fmt = match raw_ct.as_deref() {
            None => RdfFormat::Turtle,
            Some(ct) => parse_rdf_media_type(ct).ok_or_else(|| {
                LdpError::UnsupportedMediaType(format!(
                    "Unsupported Content-Type '{ct}' for Solid .acl resource"
                ))
            })?,
        };
        let parsed = SemanticGraphStore::parse_rdf_triples(&body_bytes, rdf_fmt, &parse_base_iri)?;
        let triples = target.rebase_triples_for_storage(&state.config.base_url, parsed);
        let rules = extract_wac_rules_from_acl_triples(&state.config, target, &triples)?;
        PreparedWrite::Acl { triples, rules }
    } else if target.is_container_path || requested_container {
        if !target.is_container_path {
            return Err(LdpError::BadRequest(
                "Solid LDP BasicContainer URI must end with '/'".to_string(),
            ));
        }
        let triples = if body_bytes.is_empty() {
            if let Some(ct) = raw_ct.as_deref()
                && parse_rdf_media_type(ct).is_none()
            {
                return Err(LdpError::UnsupportedMediaType(format!(
                    "Unsupported Content-Type '{ct}' for LDP BasicContainer"
                )));
            }
            Vec::new()
        } else {
            let ct = raw_ct.as_deref().unwrap_or("text/turtle");
            let rdf_fmt = parse_rdf_media_type(ct).ok_or_else(|| {
                LdpError::UnsupportedMediaType(format!(
                    "Unsupported Content-Type '{ct}' for LDP BasicContainer"
                ))
            })?;
            let parsed =
                SemanticGraphStore::parse_rdf_triples(&body_bytes, rdf_fmt, &parse_base_iri)?;
            target.rebase_triples_for_storage(&state.config.base_url, parsed)
        };
        reject_client_contains_triples(&triples)?;
        PreparedWrite::Container { triples }
    } else {
        match raw_ct.as_deref() {
            Some(ct) if !requested_non_rdf && parse_rdf_media_type(ct).is_some() => {
                let rdf_fmt = parse_rdf_media_type(ct).unwrap();
                let parsed =
                    SemanticGraphStore::parse_rdf_triples(&body_bytes, rdf_fmt, &parse_base_iri)?;
                let triples = target.rebase_triples_for_storage(&state.config.base_url, parsed);
                PreparedWrite::Rdf { triples }
            }
            None if requested_rdf_source => {
                let parsed = SemanticGraphStore::parse_rdf_triples(
                    &body_bytes,
                    RdfFormat::Turtle,
                    &parse_base_iri,
                )?;
                let triples = target.rebase_triples_for_storage(&state.config.base_url, parsed);
                PreparedWrite::Rdf { triples }
            }
            Some(ct) if requested_rdf_source => {
                return Err(LdpError::UnsupportedMediaType(format!(
                    "Unsupported RDF Content-Type '{ct}' for LDP RDFSource"
                )));
            }
            Some(ct) => PreparedWrite::Blob {
                content_type: ct.to_string(),
                bytes: body_bytes,
            },
            None => PreparedWrite::Blob {
                content_type: "application/octet-stream".to_string(),
                bytes: body_bytes,
            },
        }
    };

    let _io_guard = state.catalog_lock.write().await;
    let mut catalog = state.catalog.write().await;
    *catalog = LdpCatalog::load_or_init(&state.physical_store).await?;
    if let Some(ref pod_id) = target_pod_id
        && (state.config.reserved_pods.contains(pod_id) || catalog.tombstones.contains_key(pod_id))
    {
        return Err(LdpError::Conflict(format!(
            "Pod '{pod_id}' is reserved or retired and cannot be modified"
        )));
    }
    validate_hierarchy_for_write(&catalog, &target.canonical_path, target.is_container_path)?;

    let existing = catalog.entries.get(&target.canonical_path).cloned();
    check_write_preconditions(headers, existing.as_ref().map(|e| e.etag.as_str()))?;
    let old_size_bytes = existing.as_ref().map(|e| e.size_bytes).unwrap_or(0);
    let target_graph_store = state.pod_stores.store_for_path(&target.canonical_path)?;

    let (kind, stored_ct, new_etag, new_size_bytes, projected_pod_usage) = match prepared {
        PreparedWrite::Container { triples } => {
            let canonical_nt =
                SemanticGraphStore::serialize_triples(&triples, RdfFormat::NTriples)?;
            let new_sz = canonical_nt.len() as u64;
            let proj_usage = if let Some(ref pod_id) = target_pod_id {
                let cur = catalog.pod_usage_bytes(pod_id);
                Some(
                    state
                        .pod_stores
                        .check_quota_delta(pod_id, cur, old_size_bytes, new_sz)?,
                )
            } else {
                None
            };
            target_graph_store.replace_named_graph_triples(&resource_iri, &triples)?;
            (
                ResourceKind::Container,
                "text/turtle".to_string(),
                compute_etag(&canonical_nt),
                new_sz,
                proj_usage,
            )
        }
        PreparedWrite::Rdf { triples } => {
            let canonical_nt =
                SemanticGraphStore::serialize_triples(&triples, RdfFormat::NTriples)?;
            let new_sz = canonical_nt.len() as u64;
            let proj_usage = if let Some(ref pod_id) = target_pod_id {
                let cur = catalog.pod_usage_bytes(pod_id);
                Some(
                    state
                        .pod_stores
                        .check_quota_delta(pod_id, cur, old_size_bytes, new_sz)?,
                )
            } else {
                None
            };
            if let Some(ref prev) = existing
                && prev.kind == ResourceKind::NonRdfSource
            {
                let _ = state
                    .physical_store
                    .delete(&blob_key_for_path(&target.canonical_path))
                    .await;
            }
            target_graph_store.replace_named_graph_triples(&resource_iri, &triples)?;
            (
                ResourceKind::RdfSource,
                "text/turtle".to_string(),
                compute_etag(&canonical_nt),
                new_sz,
                proj_usage,
            )
        }
        PreparedWrite::Acl { triples, rules } => {
            let canonical_nt =
                SemanticGraphStore::serialize_triples(&triples, RdfFormat::NTriples)?;
            let new_sz = canonical_nt.len() as u64;
            let proj_usage = if let Some(ref pod_id) = target_pod_id {
                let cur = catalog.pod_usage_bytes(pod_id);
                Some(
                    state
                        .pod_stores
                        .check_quota_delta(pod_id, cur, old_size_bytes, new_sz)?,
                )
            } else {
                None
            };
            target_graph_store.replace_named_graph_triples(&resource_iri, &triples)?;
            let rule_prefix = acl_rule_prefix(&target.canonical_path);
            {
                let mut engine = state
                    .policy_engine
                    .write()
                    .unwrap_or_else(|e| e.into_inner());
                engine.remove_wac_rules_by_prefix(&rule_prefix);
                for rule in rules {
                    engine.add_wac_rule(rule);
                }
            }
            (
                ResourceKind::RdfSource,
                "text/turtle".to_string(),
                compute_etag(&canonical_nt),
                new_sz,
                proj_usage,
            )
        }
        PreparedWrite::Blob {
            content_type,
            bytes,
        } => {
            let new_sz = bytes.len() as u64;
            let proj_usage = if let Some(ref pod_id) = target_pod_id {
                let cur = catalog.pod_usage_bytes(pod_id);
                Some(
                    state
                        .pod_stores
                        .check_quota_delta(pod_id, cur, old_size_bytes, new_sz)?,
                )
            } else {
                None
            };
            if let Some(ref prev) = existing
                && prev.kind == ResourceKind::RdfSource
            {
                let _ = target_graph_store.delete_named_graph(&resource_iri);
            }
            let etag = compute_etag(&bytes);
            let blob_key = blob_key_for_path(&target.canonical_path);
            state
                .physical_store
                .put_with_content_type(&blob_key, bytes, &content_type)
                .await?;
            (
                ResourceKind::NonRdfSource,
                content_type,
                etag,
                new_sz,
                proj_usage,
            )
        }
    };

    ensure_parent_containers(&mut catalog, &target.canonical_path);

    catalog.entries.insert(
        target.canonical_path.clone(),
        LdpEntry {
            path: target.canonical_path.clone(),
            kind,
            content_type: stored_ct,
            etag: new_etag.clone(),
            size_bytes: new_size_bytes,
        },
    );
    catalog.persist(&state.physical_store).await?;
    if let (Some(pod_id), Some(used)) = (target_pod_id.as_deref(), projected_pod_usage) {
        state.pod_stores.record_pod_usage(pod_id, used);
    }
    drop(catalog);
    drop(_io_guard);

    let status = if existing.is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    };
    let mut resp = status.into_response();
    if status == StatusCode::CREATED
        && let Ok(loc) = HeaderValue::from_str(&parse_base_iri)
    {
        resp.headers_mut().insert(header::LOCATION, loc);
    }
    attach_ldp_headers(
        resp.headers_mut(),
        state,
        principal,
        target,
        kind,
        Some(&new_etag),
    )?;
    Ok(resp)
}

async fn handle_post(
    state: &AppState,
    principal: &Principal,
    target: &LdpTarget,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, LdpError> {
    if target.is_acl {
        authorize(state, principal, &target.policy_target, AccessMode::Control)?;
        return Err(LdpError::MethodNotAllowed {
            allow: ALLOW_ACL,
            message: "POST is not allowed on .acl auxiliary resources".to_string(),
        });
    }

    // Enforce WAC / ACP Append permission BEFORE reading body or mutating storage.
    authorize(state, principal, &target.policy_target, AccessMode::Append)?;

    if !target.is_container_path {
        return Err(LdpError::MethodNotAllowed {
            allow: ALLOW_RDF_SOURCE,
            message: "POST is only supported on LDP Containers (paths ending with '/')".to_string(),
        });
    }

    let slug_opt = parse_slug_header(headers)?;
    let body_bytes = read_bounded_body(body, state.config.max_body_bytes).await?;
    let link_types = parse_link_type_iris(headers)?;
    let requested_container =
        link_types.contains(LDP_BASIC_CONTAINER) || link_types.contains(LDP_CONTAINER);
    let requested_rdf_source = link_types.contains(LDP_RDF_SOURCE);
    let requested_non_rdf = link_types.contains(LDP_NON_RDF_SOURCE);

    if requested_container && requested_non_rdf {
        return Err(LdpError::BadRequest(
            "Conflicting LDP BasicContainer and NonRDFSource Link types".to_string(),
        ));
    }

    let raw_ct = extract_media_type(headers);

    let _io_guard = state.catalog_lock.write().await;
    let mut catalog = state.catalog.write().await;
    *catalog = LdpCatalog::load_or_init(&state.physical_store).await?;
    match catalog.entries.get(&target.canonical_path) {
        Some(entry) if entry.kind == ResourceKind::Container => {}
        _ => {
            return Err(LdpError::NotFound(format!(
                "Target LDP container '{}' does not exist",
                target.canonical_path
            )));
        }
    }

    let base_slug = slug_opt.unwrap_or_else(|| Uuid::new_v4().to_string());
    let candidate_leaf = format!("{}{}", target.canonical_path, base_slug);
    let candidate_container = format!("{}{}/", target.canonical_path, base_slug);
    let final_slug = if catalog.entries.contains_key(&candidate_leaf)
        || catalog.entries.contains_key(&candidate_container)
    {
        format!("{base_slug}-{}", Uuid::new_v4().simple())
    } else {
        base_slug
    };

    let child_path = if requested_container {
        format!("{}{}/", target.canonical_path, final_slug)
    } else {
        format!("{}{}", target.canonical_path, final_slug)
    };
    let mut child_target =
        build_ldp_target_from_canonical(&child_path, &state.config.pod_uri_prefix);
    child_target.subdomain_ctx = target.subdomain_ctx.clone();

    // Ensure child URI does not trigger an explicit ACP deny rule (e.g. via crafted Slug).
    ensure_no_explicit_acp_deny(
        state,
        principal,
        &child_target.policy_target,
        AccessMode::Append,
    )?;

    let child_iri = http_iri(&state.config.base_url, &child_path);
    let ext_child_iri = child_target.external_iri(&state.config.base_url, &child_path);
    let child_pod_id =
        PodStoreManager::pod_id_from_canonical_path(&child_path)?.map(str::to_string);
    if let Some(ref pod_id) = child_pod_id
        && (state.config.reserved_pods.contains(pod_id) || catalog.tombstones.contains_key(pod_id))
    {
        return Err(LdpError::Conflict(format!(
            "Pod '{pod_id}' is reserved or retired and cannot be modified"
        )));
    }
    let child_graph_store = state.pod_stores.store_for_path(&child_path)?;

    let (child_kind, stored_ct, new_etag, new_size_bytes, projected_pod_usage) =
        if requested_container {
            let triples = if body_bytes.is_empty() {
                if let Some(ct) = raw_ct.as_deref()
                    && parse_rdf_media_type(ct).is_none()
                {
                    return Err(LdpError::UnsupportedMediaType(format!(
                        "Unsupported Content-Type '{ct}' for LDP BasicContainer"
                    )));
                }
                Vec::new()
            } else {
                let ct = raw_ct.as_deref().unwrap_or("text/turtle");
                let rdf_fmt = parse_rdf_media_type(ct).ok_or_else(|| {
                    LdpError::UnsupportedMediaType(format!(
                        "Unsupported Content-Type '{ct}' for LDP BasicContainer"
                    ))
                })?;
                let parsed =
                    SemanticGraphStore::parse_rdf_triples(&body_bytes, rdf_fmt, &ext_child_iri)?;
                child_target.rebase_triples_for_storage(&state.config.base_url, parsed)
            };
            reject_client_contains_triples(&triples)?;
            let canonical_nt =
                SemanticGraphStore::serialize_triples(&triples, RdfFormat::NTriples)?;
            let new_sz = canonical_nt.len() as u64;
            let proj_usage = if let Some(ref pod_id) = child_pod_id {
                let cur = catalog.pod_usage_bytes(pod_id);
                Some(state.pod_stores.check_quota_delta(pod_id, cur, 0, new_sz)?)
            } else {
                None
            };
            child_graph_store.replace_named_graph_triples(&child_iri, &triples)?;
            (
                ResourceKind::Container,
                "text/turtle".to_string(),
                compute_etag(&canonical_nt),
                new_sz,
                proj_usage,
            )
        } else {
            match raw_ct.as_deref() {
                Some(ct) if !requested_non_rdf && parse_rdf_media_type(ct).is_some() => {
                    let rdf_fmt = parse_rdf_media_type(ct).unwrap();
                    let parsed = SemanticGraphStore::parse_rdf_triples(
                        &body_bytes,
                        rdf_fmt,
                        &ext_child_iri,
                    )?;
                    let triples =
                        child_target.rebase_triples_for_storage(&state.config.base_url, parsed);
                    let canonical_nt =
                        SemanticGraphStore::serialize_triples(&triples, RdfFormat::NTriples)?;
                    let new_sz = canonical_nt.len() as u64;
                    let proj_usage = if let Some(ref pod_id) = child_pod_id {
                        let cur = catalog.pod_usage_bytes(pod_id);
                        Some(state.pod_stores.check_quota_delta(pod_id, cur, 0, new_sz)?)
                    } else {
                        None
                    };
                    child_graph_store.replace_named_graph_triples(&child_iri, &triples)?;
                    (
                        ResourceKind::RdfSource,
                        "text/turtle".to_string(),
                        compute_etag(&canonical_nt),
                        new_sz,
                        proj_usage,
                    )
                }
                None if requested_rdf_source => {
                    let parsed = SemanticGraphStore::parse_rdf_triples(
                        &body_bytes,
                        RdfFormat::Turtle,
                        &ext_child_iri,
                    )?;
                    let triples =
                        child_target.rebase_triples_for_storage(&state.config.base_url, parsed);
                    let canonical_nt =
                        SemanticGraphStore::serialize_triples(&triples, RdfFormat::NTriples)?;
                    let new_sz = canonical_nt.len() as u64;
                    let proj_usage = if let Some(ref pod_id) = child_pod_id {
                        let cur = catalog.pod_usage_bytes(pod_id);
                        Some(state.pod_stores.check_quota_delta(pod_id, cur, 0, new_sz)?)
                    } else {
                        None
                    };
                    child_graph_store.replace_named_graph_triples(&child_iri, &triples)?;
                    (
                        ResourceKind::RdfSource,
                        "text/turtle".to_string(),
                        compute_etag(&canonical_nt),
                        new_sz,
                        proj_usage,
                    )
                }
                Some(ct) if requested_rdf_source => {
                    return Err(LdpError::UnsupportedMediaType(format!(
                        "Unsupported RDF Content-Type '{ct}' for LDP RDFSource"
                    )));
                }
                Some(ct) => {
                    let new_sz = body_bytes.len() as u64;
                    let proj_usage = if let Some(ref pod_id) = child_pod_id {
                        let cur = catalog.pod_usage_bytes(pod_id);
                        Some(state.pod_stores.check_quota_delta(pod_id, cur, 0, new_sz)?)
                    } else {
                        None
                    };
                    let etag = compute_etag(&body_bytes);
                    let blob_key = blob_key_for_path(&child_path);
                    state
                        .physical_store
                        .put_with_content_type(&blob_key, body_bytes, ct)
                        .await?;
                    (
                        ResourceKind::NonRdfSource,
                        ct.to_string(),
                        etag,
                        new_sz,
                        proj_usage,
                    )
                }
                None => {
                    let new_sz = body_bytes.len() as u64;
                    let proj_usage = if let Some(ref pod_id) = child_pod_id {
                        let cur = catalog.pod_usage_bytes(pod_id);
                        Some(state.pod_stores.check_quota_delta(pod_id, cur, 0, new_sz)?)
                    } else {
                        None
                    };
                    let etag = compute_etag(&body_bytes);
                    let blob_key = blob_key_for_path(&child_path);
                    state
                        .physical_store
                        .put_with_content_type(&blob_key, body_bytes, "application/octet-stream")
                        .await?;
                    (
                        ResourceKind::NonRdfSource,
                        "application/octet-stream".to_string(),
                        etag,
                        new_sz,
                        proj_usage,
                    )
                }
            }
        };

    catalog.entries.insert(
        child_path.clone(),
        LdpEntry {
            path: child_path,
            kind: child_kind,
            content_type: stored_ct,
            etag: new_etag.clone(),
            size_bytes: new_size_bytes,
        },
    );
    catalog.persist(&state.physical_store).await?;
    if let (Some(pod_id), Some(used)) = (child_pod_id.as_deref(), projected_pod_usage) {
        state.pod_stores.record_pod_usage(pod_id, used);
    }
    drop(catalog);
    drop(_io_guard);

    let mut resp = StatusCode::CREATED.into_response();
    if let Ok(loc) = HeaderValue::from_str(&ext_child_iri) {
        resp.headers_mut().insert(header::LOCATION, loc);
    }
    attach_ldp_headers(
        resp.headers_mut(),
        state,
        principal,
        &child_target,
        child_kind,
        Some(&new_etag),
    )?;
    Ok(resp)
}

async fn handle_patch(
    state: &AppState,
    principal: &Principal,
    target: &LdpTarget,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, LdpError> {
    // Preliminary auth gate so unauthenticated/unauthorized callers cannot probe Content-Type or send large bodies.
    // Note: At minimum `Append` (or `Control` on .acl) is required for any PATCH.
    let min_mode = if target.is_acl {
        AccessMode::Control
    } else {
        AccessMode::Append
    };
    authorize(state, principal, &target.policy_target, min_mode)?;
    let target_pod_id =
        PodStoreManager::pod_id_from_canonical_path(&target.canonical_path)?.map(str::to_string);

    match extract_media_type(headers).as_deref() {
        Some("application/sparql-update") => {}
        other => {
            return Err(LdpError::UnsupportedMediaType(format!(
                "Solid LDP PATCH requires 'Content-Type: application/sparql-update', got {:?}",
                other
            )));
        }
    }

    let body_bytes = read_bounded_body(body, state.config.max_body_bytes).await?;
    let sparql_text = std::str::from_utf8(&body_bytes).map_err(|_| {
        LdpError::BadRequest("SPARQL-Update payload must be valid UTF-8".to_string())
    })?;
    if sparql_text.trim().is_empty() {
        return Err(LdpError::BadRequest(
            "SPARQL-Update payload must not be empty".to_string(),
        ));
    }

    let resource_iri = http_iri(&state.config.base_url, &target.canonical_path);
    let ext_resource_iri = target.external_iri(&state.config.base_url, &target.canonical_path);
    #[allow(deprecated)]
    let parsed_update = SparqlUpdate::parse(sparql_text, Some(&ext_resource_iri))
        .map_err(|e| LdpError::BadRequest(format!("Invalid SPARQL-Update syntax: {e}")))?;

    let patch_profile = classify_sparql_update(&parsed_update)?;

    // Enforce full mode requirements (Write and/or Read) BEFORE reading/mutating storage!
    if !target.is_acl {
        if patch_profile.requires_write {
            authorize(state, principal, &target.policy_target, AccessMode::Write)?;
        }
        if patch_profile.requires_read {
            authorize(state, principal, &target.policy_target, AccessMode::Read)?;
        }
    }

    let _io_guard = state.catalog_lock.write().await;
    let mut catalog = state.catalog.write().await;
    *catalog = LdpCatalog::load_or_init(&state.physical_store).await?;
    if let Some(pod_id) = PodStoreManager::pod_id_from_canonical_path(&target.canonical_path)?
        && (state.config.reserved_pods.contains(pod_id) || catalog.tombstones.contains_key(pod_id))
    {
        return Err(LdpError::Conflict(format!(
            "Pod '{pod_id}' is reserved or retired and cannot be modified"
        )));
    }
    validate_hierarchy_for_write(&catalog, &target.canonical_path, target.is_container_path)?;

    let existing = catalog.entries.get(&target.canonical_path).cloned();
    check_write_preconditions(headers, existing.as_ref().map(|e| e.etag.as_str()))?;
    let old_size_bytes = existing.as_ref().map(|e| e.size_bytes).unwrap_or(0);
    let target_graph_store = state.pod_stores.store_for_path(&target.canonical_path)?;

    let current_triples = match &existing {
        Some(entry) if entry.kind == ResourceKind::NonRdfSource => {
            return Err(LdpError::Conflict(
                "SPARQL-Update PATCH cannot be applied to a NonRDFSource binary resource"
                    .to_string(),
            ));
        }
        Some(_) => {
            let stored = target_graph_store.get_named_graph_triples(&resource_iri)?;
            target.rebase_triples_for_response(&state.config.base_url, stored)
        }
        None => {
            if target.is_container_path || patch_profile.requires_write {
                return Err(LdpError::NotFound(format!(
                    "Target RDF resource '{}' does not exist",
                    target.canonical_path
                )));
            }
            Vec::new()
        }
    };

    // Execute SPARQL Update inside an isolated single-resource in-memory store.
    let sandbox = SemanticGraphStore::new_in_memory()?;
    for triple in &current_triples {
        let quad = wolin_storage::rdf_model::Quad::new(
            triple.subject.clone(),
            triple.predicate.clone(),
            triple.object.clone(),
            wolin_storage::rdf_model::GraphName::DefaultGraph,
        );
        sandbox.insert_quad(&quad)?;
    }

    sandbox
        .inner()
        .update(parsed_update)
        .map_err(|e| LdpError::BadRequest(format!("SPARQL-Update evaluation failed: {e}")))?;

    if sandbox.inner().named_graphs().next().is_some() {
        return Err(LdpError::BadRequest(
            "SPARQL-Update PATCH must not create or mutate named graphs".to_string(),
        ));
    }

    let mut sandbox_triples = Vec::new();
    for quad_res in sandbox.inner().quads_for_pattern(
        None,
        None,
        None,
        Some(wolin_storage::rdf_model::GraphNameRef::DefaultGraph),
    ) {
        let quad =
            quad_res.map_err(|e| LdpError::Internal(format!("Sandbox quad read failed: {e}")))?;
        sandbox_triples.push(Triple::from(quad));
    }
    let updated_triples =
        target.rebase_triples_for_storage(&state.config.base_url, sandbox_triples);

    if target.is_container_path {
        reject_client_contains_triples(&updated_triples)?;
    }

    let acl_rules = if target.is_acl {
        Some(extract_wac_rules_from_acl_triples(
            &state.config,
            target,
            &updated_triples,
        )?)
    } else {
        None
    };

    let canonical_nt =
        SemanticGraphStore::serialize_triples(&updated_triples, RdfFormat::NTriples)?;
    let new_size_bytes = canonical_nt.len() as u64;
    let projected_pod_usage = if let Some(ref pod_id) = target_pod_id {
        let cur = catalog.pod_usage_bytes(pod_id);
        Some(
            state
                .pod_stores
                .check_quota_delta(pod_id, cur, old_size_bytes, new_size_bytes)?,
        )
    } else {
        None
    };

    target_graph_store.replace_named_graph_triples(&resource_iri, &updated_triples)?;
    let new_etag = compute_etag(&canonical_nt);
    ensure_parent_containers(&mut catalog, &target.canonical_path);

    if let Some(rules) = acl_rules {
        let rule_prefix = acl_rule_prefix(&target.canonical_path);
        let mut engine = state
            .policy_engine
            .write()
            .unwrap_or_else(|e| e.into_inner());
        engine.remove_wac_rules_by_prefix(&rule_prefix);
        for rule in rules {
            engine.add_wac_rule(rule);
        }
    }

    let kind = existing
        .as_ref()
        .map(|e| e.kind)
        .unwrap_or(ResourceKind::RdfSource);

    catalog.entries.insert(
        target.canonical_path.clone(),
        LdpEntry {
            path: target.canonical_path.clone(),
            kind,
            content_type: "text/turtle".to_string(),
            etag: new_etag.clone(),
            size_bytes: new_size_bytes,
        },
    );
    catalog.persist(&state.physical_store).await?;
    if let (Some(pod_id), Some(used)) = (target_pod_id.as_deref(), projected_pod_usage) {
        state.pod_stores.record_pod_usage(pod_id, used);
    }
    drop(catalog);
    drop(_io_guard);

    let status = if existing.is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    };
    let mut resp = status.into_response();
    if status == StatusCode::CREATED
        && let Ok(loc) = HeaderValue::from_str(&ext_resource_iri)
    {
        resp.headers_mut().insert(header::LOCATION, loc);
    }
    attach_ldp_headers(
        resp.headers_mut(),
        state,
        principal,
        target,
        kind,
        Some(&new_etag),
    )?;
    Ok(resp)
}

async fn handle_delete(
    state: &AppState,
    principal: &Principal,
    target: &LdpTarget,
    headers: &HeaderMap,
) -> Result<Response, LdpError> {
    let required_mode = if target.is_acl {
        AccessMode::Control
    } else {
        AccessMode::Write
    };
    // Enforce WAC / ACP authorization BEFORE inspecting or mutating storage.
    authorize(state, principal, &target.policy_target, required_mode)?;
    let target_pod_id =
        PodStoreManager::pod_id_from_canonical_path(&target.canonical_path)?.map(str::to_string);

    if target.canonical_path == "/" {
        return Err(LdpError::MethodNotAllowed {
            allow: "OPTIONS, HEAD, GET, POST, PUT, PATCH",
            message: "Root LDP container '/' cannot be deleted".to_string(),
        });
    }

    let _io_guard = state.catalog_lock.write().await;
    let mut catalog = state.catalog.write().await;
    *catalog = LdpCatalog::load_or_init(&state.physical_store).await?;
    if let Some(ref pod_id) = target_pod_id
        && (state.config.reserved_pods.contains(pod_id) || catalog.tombstones.contains_key(pod_id))
    {
        return Err(LdpError::Conflict(format!(
            "Pod '{pod_id}' is reserved or retired and cannot be modified"
        )));
    }
    let Some(entry) = catalog.entries.get(&target.canonical_path).cloned() else {
        return Err(LdpError::NotFound(format!(
            "LDP resource '{}' not found",
            target.canonical_path
        )));
    };

    check_write_preconditions(headers, Some(entry.etag.as_str()))?;

    if entry.kind == ResourceKind::Container {
        let has_children = catalog
            .entries
            .keys()
            .any(|k| k != &entry.path && k != &target.acl_path && k.starts_with(&entry.path));
        if has_children {
            return Err(LdpError::Conflict(format!(
                "Cannot delete non-empty LDP BasicContainer '{}'",
                entry.path
            )));
        }
    }

    let resource_iri = http_iri(&state.config.base_url, &entry.path);
    let target_graph_store = state.pod_stores.store_for_path(&entry.path)?;
    match entry.kind {
        ResourceKind::Container | ResourceKind::RdfSource => {
            target_graph_store.delete_named_graph(&resource_iri)?;
        }
        ResourceKind::NonRdfSource => {
            state
                .physical_store
                .delete(&blob_key_for_path(&entry.path))
                .await?;
        }
    }

    if target.is_acl {
        let prefix = acl_rule_prefix(&target.canonical_path);
        state
            .policy_engine
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove_wac_rules_by_prefix(&prefix);
    } else if catalog.entries.remove(&target.acl_path).is_some() {
        let acl_iri = http_iri(&state.config.base_url, &target.acl_path);
        let _ = target_graph_store.delete_named_graph(&acl_iri);
        let prefix = acl_rule_prefix(&target.acl_path);
        state
            .policy_engine
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove_wac_rules_by_prefix(&prefix);
    }

    catalog.entries.remove(&target.canonical_path);
    catalog.persist(&state.physical_store).await?;
    if let Some(ref pod_id) = target_pod_id {
        state
            .pod_stores
            .record_pod_usage(pod_id, catalog.pod_usage_bytes(pod_id));
    }
    drop(catalog);
    drop(_io_guard);

    Ok(StatusCode::NO_CONTENT.into_response())
}

fn evaluate_decision(
    engine: &PolicyEngine,
    state: &AppState,
    principal: &Principal,
    target: &ResourceUri,
    mode: AccessMode,
) -> AccessDecision {
    match state.config.policy_clock_epoch_secs {
        Some(ts) => engine.evaluate_policy_at(principal, target, mode, ts),
        None => engine.evaluate_policy(principal, target, mode),
    }
}

fn authorize(
    state: &AppState,
    principal: &Principal,
    target: &ResourceUri,
    mode: AccessMode,
) -> Result<(), LdpError> {
    let decision = {
        let engine = state
            .policy_engine
            .read()
            .unwrap_or_else(|e| e.into_inner());
        evaluate_decision(&engine, state, principal, target, mode)
    };

    match decision {
        AccessDecision::Permit => Ok(()),
        AccessDecision::Deny { reason } => match principal {
            Principal::Anonymous => Err(LdpError::Unauthenticated(reason)),
            _ => Err(LdpError::Forbidden(reason)),
        },
    }
}

fn ensure_no_explicit_acp_deny(
    state: &AppState,
    principal: &Principal,
    child_target: &ResourceUri,
    mode: AccessMode,
) -> Result<(), LdpError> {
    let decision = {
        let engine = state
            .policy_engine
            .read()
            .unwrap_or_else(|e| e.into_inner());
        evaluate_decision(&engine, state, principal, child_target, mode)
    };

    if let AccessDecision::Deny { reason } = decision
        && reason.contains("ACP policy")
    {
        return match principal {
            Principal::Anonymous => Err(LdpError::Unauthenticated(reason)),
            _ => Err(LdpError::Forbidden(reason)),
        };
    }
    Ok(())
}

async fn read_bounded_body(body: Body, max_bytes: usize) -> Result<Vec<u8>, LdpError> {
    to_bytes(body, max_bytes)
        .await
        .map(|b| b.to_vec())
        .map_err(|_| {
            LdpError::PayloadTooLarge(format!(
                "Request body exceeds maximum allowed size of {max_bytes} bytes"
            ))
        })
}

#[allow(clippy::too_many_arguments)]
fn build_payload_response(
    state: &AppState,
    principal: &Principal,
    target: &LdpTarget,
    kind: ResourceKind,
    content_type: &str,
    etag: &str,
    bytes: Vec<u8>,
    head_only: bool,
) -> Result<Response, LdpError> {
    let len_str = bytes.len().to_string();
    let mut resp = if head_only {
        StatusCode::OK.into_response()
    } else {
        (StatusCode::OK, bytes).into_response()
    };

    let ct_val = HeaderValue::from_str(content_type)
        .map_err(|_| LdpError::Internal("Invalid stored Content-Type header value".to_string()))?;
    resp.headers_mut().insert(header::CONTENT_TYPE, ct_val);
    if let Ok(cl) = HeaderValue::from_str(&len_str) {
        resp.headers_mut().insert(header::CONTENT_LENGTH, cl);
    }

    attach_ldp_headers(
        resp.headers_mut(),
        state,
        principal,
        target,
        kind,
        Some(etag),
    )?;
    Ok(resp)
}

fn attach_ldp_headers(
    headers: &mut HeaderMap,
    state: &AppState,
    principal: &Principal,
    target: &LdpTarget,
    kind: ResourceKind,
    etag: Option<&str>,
) -> Result<(), LdpError> {
    let acl_iri = target.external_iri(&state.config.base_url, &target.acl_path);
    let mut link_parts = match kind {
        ResourceKind::Container => {
            let mut v = vec![
                format!("<{LDP_BASIC_CONTAINER}>; rel=\"type\""),
                format!("<{LDP_CONTAINER}>; rel=\"type\""),
                format!("<{LDP_RESOURCE}>; rel=\"type\""),
            ];
            if target.canonical_path == "/" || is_pod_root_path(&target.canonical_path) {
                v.push(format!("<{PIM_STORAGE}>; rel=\"type\""));
            }
            v
        }
        ResourceKind::RdfSource => vec![
            format!("<{LDP_RDF_SOURCE}>; rel=\"type\""),
            format!("<{LDP_RESOURCE}>; rel=\"type\""),
        ],
        ResourceKind::NonRdfSource => vec![
            format!("<{LDP_NON_RDF_SOURCE}>; rel=\"type\""),
            format!("<{LDP_RESOURCE}>; rel=\"type\""),
        ],
    };
    link_parts.push(format!("<{acl_iri}>; rel=\"acl\""));

    if let Some(pod_id) = enclosing_pod_id(&target.canonical_path) {
        let pod_root_canonical = format!("/pods/{pod_id}/");
        let ext_pod_root = target.external_iri(&state.config.base_url, &pod_root_canonical);
        let ext_inbox = format!("{ext_pod_root}inbox/");
        link_parts.push(format!("<{ext_pod_root}>; rel=\"{PIM_STORAGE_REL}\""));
        link_parts.push(format!("<{ext_inbox}>; rel=\"{LDP_INBOX_REL}\""));
    }

    let link_value = link_parts.join(", ");
    let link_hdr = HeaderValue::from_str(&link_value)
        .map_err(|e| LdpError::Internal(format!("Invalid Link header value: {e}")))?;
    headers.insert(header::LINK, link_hdr);

    let allow = if target.is_acl {
        ALLOW_ACL
    } else {
        match kind {
            ResourceKind::Container => ALLOW_CONTAINER,
            ResourceKind::RdfSource => ALLOW_RDF_SOURCE,
            ResourceKind::NonRdfSource => ALLOW_NON_RDF_SOURCE,
        }
    };
    headers.insert(header::ALLOW, HeaderValue::from_static(allow));
    headers.insert(
        header::VARY,
        HeaderValue::from_static("Accept, Authorization, Host"),
    );

    if matches!(kind, ResourceKind::Container | ResourceKind::RdfSource) {
        headers.insert(
            HeaderName::from_static("accept-patch"),
            HeaderValue::from_static("application/sparql-update"),
        );
    }
    if kind == ResourceKind::Container {
        headers.insert(
            HeaderName::from_static("accept-post"),
            HeaderValue::from_static(
                "text/turtle, application/n-triples, application/ld+json, application/octet-stream, */*",
            ),
        );
    }

    let wac_allow = compute_wac_allow(state, principal, &target.policy_target);
    if let Ok(val) = HeaderValue::from_str(&wac_allow) {
        headers.insert(HeaderName::from_static("wac-allow"), val);
    }

    if let Some(tag) = etag
        && let Ok(val) = HeaderValue::from_str(tag)
    {
        headers.insert(header::ETAG, val);
    }

    Ok(())
}

fn compute_wac_allow(state: &AppState, principal: &Principal, target: &ResourceUri) -> String {
    let engine = state
        .policy_engine
        .read()
        .unwrap_or_else(|e| e.into_inner());

    let fmt_modes = |p: &Principal| -> String {
        let mut allowed = Vec::new();
        for (mode, label) in [
            (AccessMode::Read, "read"),
            (AccessMode::Write, "write"),
            (AccessMode::Append, "append"),
            (AccessMode::Control, "control"),
        ] {
            if evaluate_decision(&engine, state, p, target, mode).is_permit() {
                allowed.push(label);
            }
        }
        allowed.join(" ")
    };

    let user_modes = fmt_modes(principal);
    let public_modes = fmt_modes(&Principal::Anonymous);
    format!("user=\"{user_modes}\",public=\"{public_modes}\"")
}

fn parse_ldp_target(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    config: &LdpConfig,
) -> Result<LdpTarget, LdpError> {
    let force_signed_download = match uri.query() {
        None => false,
        Some("download=signed") if *method == Method::GET => true,
        Some(_) => {
            return Err(LdpError::BadRequest(
                "Query parameters are not permitted on Solid LDP resource URIs".to_string(),
            ));
        }
    };

    if let Some((pod_id, sub_origin)) = extract_subdomain_pod(headers, uri, config)? {
        let rewritten = rewrite_subdomain_path(uri.path(), &pod_id)?;
        let mut target = parse_ldp_path_str(&rewritten, &config.pod_uri_prefix)?;
        target.subdomain_ctx = Some((pod_id, sub_origin));
        target.force_signed_download = force_signed_download;
        return Ok(target);
    }

    let mut target = parse_ldp_path_str(uri.path(), &config.pod_uri_prefix)?;
    target.force_signed_download = force_signed_download;
    Ok(target)
}

fn rewrite_subdomain_path(raw_path: &str, pod_id: &str) -> Result<String, LdpError> {
    if raw_path.is_empty() || !raw_path.starts_with('/') || raw_path.len() > MAX_URI_LEN {
        return Err(LdpError::BadRequest(
            "Invalid LDP URI path length or missing leading '/'".to_string(),
        ));
    }
    if raw_path == "/" {
        return Ok(format!("/pods/{pod_id}/"));
    }
    Ok(format!("/pods/{pod_id}{raw_path}"))
}

fn parse_ldp_path_str(raw_path: &str, pod_prefix: &str) -> Result<LdpTarget, LdpError> {
    if raw_path.is_empty() || !raw_path.starts_with('/') || raw_path.len() > MAX_URI_LEN {
        return Err(LdpError::BadRequest(
            "Invalid LDP URI path length or missing leading '/'".to_string(),
        ));
    }
    if raw_path.bytes().any(|b| {
        b.is_ascii_control() || b.is_ascii_whitespace() || matches!(b, b'\\' | b'?' | b'#')
    }) {
        return Err(LdpError::BadRequest(
            "Invalid characters in LDP URI path".to_string(),
        ));
    }

    if raw_path == "/" {
        return Ok(build_ldp_target_from_canonical("/", pod_prefix));
    }

    let is_container_path = raw_path.ends_with('/');
    let trimmed = if is_container_path {
        &raw_path[1..raw_path.len() - 1]
    } else {
        &raw_path[1..]
    };

    if trimmed.is_empty() || trimmed.ends_with('/') {
        return Err(LdpError::BadRequest(
            "Empty '//' path segment rejected".to_string(),
        ));
    }

    let raw_segments: Vec<&str> = trimmed.split('/').collect();
    let mut decoded_segments = Vec::with_capacity(raw_segments.len());

    for (idx, seg) in raw_segments.iter().enumerate() {
        if seg.is_empty() {
            return Err(LdpError::BadRequest(
                "Empty '//' interior path segment rejected".to_string(),
            ));
        }
        let decoded = decode_uri_segment(seg)?;
        if decoded == RESERVED_META_SEG || decoded.starts_with("__wolin_") {
            return Err(LdpError::BadRequest(format!(
                "Reserved metadata path segment '{decoded}' cannot be accessed via LDP"
            )));
        }
        if idx == 0
            && (decoded == ".well-known"
                || decoded == "health"
                || decoded == "healthz"
                || decoded == "mcp"
                || decoded == "api")
        {
            return Err(LdpError::BadRequest(format!(
                "Reserved system path segment '{decoded}' cannot be accessed via LDP"
            )));
        }
        let is_last = idx + 1 == raw_segments.len();
        if decoded.ends_with(".acl")
            && (!is_last || is_container_path || decoded.ends_with(".acl.acl"))
        {
            return Err(LdpError::BadRequest(
                "Invalid '.acl' auxiliary path placement".to_string(),
            ));
        }
        decoded_segments.push(decoded);
    }

    let mut canonical = String::with_capacity(raw_path.len());
    for seg in &decoded_segments {
        canonical.push('/');
        canonical.push_str(seg);
    }
    if is_container_path {
        canonical.push('/');
    }

    let _ = PodStoreManager::pod_id_from_canonical_path(&canonical)?;
    Ok(build_ldp_target_from_canonical(&canonical, pod_prefix))
}

pub(crate) fn build_ldp_target_from_canonical(canonical_path: &str, pod_prefix: &str) -> LdpTarget {
    let clean_prefix = pod_prefix.trim_end_matches('/');

    if canonical_path == "/" {
        let policy_uri = if clean_prefix.is_empty() {
            "/".to_string()
        } else {
            clean_prefix.to_string()
        };
        return LdpTarget {
            canonical_path: "/".to_string(),
            is_container_path: true,
            is_acl: false,
            acl_path: "/.acl".to_string(),
            policy_target: ResourceUri(policy_uri),
            subdomain_ctx: None,
            force_signed_download: false,
        };
    }

    if canonical_path == "/.acl" {
        let policy_uri = if clean_prefix.is_empty() {
            "/".to_string()
        } else {
            clean_prefix.to_string()
        };
        return LdpTarget {
            canonical_path: "/.acl".to_string(),
            is_container_path: false,
            is_acl: true,
            acl_path: "/.acl".to_string(),
            policy_target: ResourceUri(policy_uri),
            subdomain_ctx: None,
            force_signed_download: false,
        };
    }

    if let Some(container_prefix) = canonical_path.strip_suffix("/.acl") {
        // Container ACL: `/alice/docs/.acl` governs `/alice/docs/` -> policy `wolin://pod/alice/docs`
        let policy_uri = format!("{clean_prefix}{container_prefix}");
        return LdpTarget {
            canonical_path: canonical_path.to_string(),
            is_container_path: false,
            is_acl: true,
            acl_path: canonical_path.to_string(),
            policy_target: ResourceUri(policy_uri),
            subdomain_ctx: None,
            force_signed_download: false,
        };
    }

    if let Some(governed_leaf) = canonical_path.strip_suffix(".acl") {
        // Leaf resource ACL: `/alice/docs/note.ttl.acl` governs `/alice/docs/note.ttl`
        let policy_uri = format!("{clean_prefix}{governed_leaf}");
        return LdpTarget {
            canonical_path: canonical_path.to_string(),
            is_container_path: false,
            is_acl: true,
            acl_path: canonical_path.to_string(),
            policy_target: ResourceUri(policy_uri),
            subdomain_ctx: None,
            force_signed_download: false,
        };
    }

    if canonical_path.ends_with('/') {
        let trimmed = canonical_path.trim_end_matches('/');
        LdpTarget {
            canonical_path: canonical_path.to_string(),
            is_container_path: true,
            is_acl: false,
            acl_path: format!("{canonical_path}.acl"),
            policy_target: ResourceUri(format!("{clean_prefix}{trimmed}")),
            subdomain_ctx: None,
            force_signed_download: false,
        }
    } else {
        LdpTarget {
            canonical_path: canonical_path.to_string(),
            is_container_path: false,
            is_acl: false,
            acl_path: format!("{canonical_path}.acl"),
            policy_target: ResourceUri(format!("{clean_prefix}{canonical_path}")),
            subdomain_ctx: None,
            force_signed_download: false,
        }
    }
}

fn is_pod_root_path(canonical_path: &str) -> bool {
    let Some(rest) = canonical_path.strip_prefix("/pods/") else {
        return false;
    };
    let Some(pod_id) = rest.strip_suffix('/') else {
        return false;
    };
    !pod_id.is_empty() && !pod_id.contains('/') && !pod_id.ends_with(".acl")
}

fn enclosing_pod_id(canonical_path: &str) -> Option<&str> {
    let rest = canonical_path.strip_prefix("/pods/")?;
    let (first_seg, _tail) = rest.split_once('/')?;
    if first_seg.is_empty() || first_seg.ends_with(".acl") {
        None
    } else {
        Some(first_seg)
    }
}

fn rebase_iri_str(iri: &str, from_prefix: &str, to_prefix: &str) -> Option<String> {
    if let Some(rest) = iri.strip_prefix(from_prefix) {
        Some(format!("{to_prefix}{rest}"))
    } else if iri == from_prefix.trim_end_matches('/') {
        Some(to_prefix.trim_end_matches('/').to_string())
    } else {
        None
    }
}

fn rebase_triples(triples: Vec<Triple>, from_prefix: &str, to_prefix: &str) -> Vec<Triple> {
    triples
        .into_iter()
        .map(|t| rebase_single_triple(t, from_prefix, to_prefix))
        .collect()
}

fn rebase_single_triple(t: Triple, from_prefix: &str, to_prefix: &str) -> Triple {
    let subject = match t.subject {
        NamedOrBlankNode::NamedNode(n) => {
            match rebase_iri_str(n.as_str(), from_prefix, to_prefix) {
                Some(new_iri) => NamedNode::new(new_iri)
                    .map(NamedOrBlankNode::NamedNode)
                    .unwrap_or(NamedOrBlankNode::NamedNode(n)),
                None => NamedOrBlankNode::NamedNode(n),
            }
        }
        other => other,
    };
    let predicate = match rebase_iri_str(t.predicate.as_str(), from_prefix, to_prefix) {
        Some(new_iri) => NamedNode::new(new_iri).unwrap_or(t.predicate),
        None => t.predicate,
    };
    let object = match t.object {
        Term::NamedNode(n) => match rebase_iri_str(n.as_str(), from_prefix, to_prefix) {
            Some(new_iri) => NamedNode::new(new_iri)
                .map(Term::NamedNode)
                .unwrap_or(Term::NamedNode(n)),
            None => Term::NamedNode(n),
        },
        other => other,
    };
    Triple::new(subject, predicate, object)
}

fn is_acl_canonical_path(path: &str) -> bool {
    path.ends_with(".acl")
}

fn decode_uri_segment(seg: &str) -> Result<String, LdpError> {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = seg.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return Err(LdpError::BadRequest(
                    "Truncated percent-encoding in URI segment".to_string(),
                ));
            }
            let hi = hex_nibble(bytes[i + 1])?;
            let lo = hex_nibble(bytes[i + 2])?;
            let decoded = (hi << 4) | lo;
            if matches!(
                decoded,
                b'/' | b'\\' | b'.' | b'?' | b'#' | 0x00..=0x20 | 0x7f
            ) {
                return Err(LdpError::BadRequest(
                    "Encoded delimiter, dot, or control byte rejected in URI".to_string(),
                ));
            }
            if is_unreserved_or_pchar(decoded) || decoded >= 0x80 {
                out.push(decoded);
            } else {
                out.push(b'%');
                out.push(HEX_UPPER[hi as usize]);
                out.push(HEX_UPPER[lo as usize]);
            }
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }

    let s = String::from_utf8(out)
        .map_err(|_| LdpError::BadRequest("Non-UTF-8 percent-encoded URI segment".to_string()))?;
    if s == "." || s == ".." {
        return Err(LdpError::BadRequest(
            "Relative dot path traversal segment rejected".to_string(),
        ));
    }
    Ok(s)
}

fn is_unreserved_or_pchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b':' | b'@')
}

fn hex_nibble(b: u8) -> Result<u8, LdpError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(LdpError::BadRequest(
            "Malformed hex digit in percent-encoding".to_string(),
        )),
    }
}

pub(crate) fn http_iri(base_url: &str, canonical_path: &str) -> String {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let base = base_url.trim_end_matches('/');
    if canonical_path == "/" {
        return format!("{base}/");
    }

    let mut encoded = String::with_capacity(base.len() + canonical_path.len() + 8);
    encoded.push_str(base);
    let trailing_slash = canonical_path.ends_with('/');
    let trimmed = canonical_path.trim_matches('/');
    for seg in trimmed.split('/') {
        encoded.push('/');
        let bytes = seg.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'%'
                && i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit()
            {
                encoded.push('%');
                encoded.push(bytes[i + 1] as char);
                encoded.push(bytes[i + 2] as char);
                i += 3;
            } else if is_unreserved_or_pchar(b)
                || matches!(
                    b,
                    b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
                )
            {
                encoded.push(b as char);
                i += 1;
            } else {
                encoded.push('%');
                encoded.push(HEX_UPPER[(b >> 4) as usize] as char);
                encoded.push(HEX_UPPER[(b & 0x0f) as usize] as char);
                i += 1;
            }
        }
    }
    if trailing_slash {
        encoded.push('/');
    }
    encoded
}

pub(crate) fn blob_key_for_path(canonical_path: &str) -> String {
    format!("blobs/{}", canonical_path.trim_start_matches('/'))
}

fn extract_media_type(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::CONTENT_TYPE)?.to_str().ok()?;
    let primary = raw.split(';').next()?.trim().to_ascii_lowercase();
    if primary.is_empty() {
        None
    } else {
        Some(primary)
    }
}

fn parse_rdf_media_type(media_type: &str) -> Option<RdfFormat> {
    match media_type.trim().to_ascii_lowercase().as_str() {
        "text/turtle" | "application/x-turtle" => Some(RdfFormat::Turtle),
        "application/n-triples" => Some(RdfFormat::NTriples),
        "application/ld+json" => Some(RdfFormat::JsonLd {
            profile: JsonLdProfileSet::empty(),
        }),
        _ => None,
    }
}

fn rdf_format_media_type(format: RdfFormat) -> &'static str {
    match format {
        RdfFormat::NTriples => "application/n-triples",
        RdfFormat::JsonLd { .. } => "application/ld+json",
        _ => "text/turtle",
    }
}

/// RFC 9110 §12.5.1 content negotiation across `text/turtle`, `application/n-triples`,
/// and `application/ld+json`. Defaults to `text/turtle` when `Accept` is omitted.
fn negotiate_rdf_format(headers: &HeaderMap) -> Result<RdfFormat, LdpError> {
    let accept_values: Vec<&HeaderValue> = headers.get_all(header::ACCEPT).iter().collect();
    if accept_values.is_empty() {
        return Ok(RdfFormat::Turtle);
    }

    let candidates = [
        ("text", "turtle", RdfFormat::Turtle),
        ("application", "n-triples", RdfFormat::NTriples),
        (
            "application",
            "ld+json",
            RdfFormat::JsonLd {
                profile: JsonLdProfileSet::empty(),
            },
        ),
    ];

    let mut ranges = Vec::new();
    for hv in accept_values {
        let s = hv
            .to_str()
            .map_err(|_| LdpError::BadRequest("Malformed Accept header".to_string()))?;
        for part in s.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            ranges.push(parse_accept_range(trimmed)?);
        }
    }

    if ranges.is_empty() {
        return Ok(RdfFormat::Turtle);
    }

    let mut best: Option<(u32, u8, RdfFormat)> = None;
    for (c_type, c_sub, fmt) in candidates {
        // Find the highest-specificity matching range in `Accept`
        let mut matched_rule: Option<(u8, u32)> = None;
        for range in &ranges {
            let specificity = if range.main_type == c_type && range.sub_type == c_sub {
                3u8
            } else if range.main_type == c_type && range.sub_type == "*" {
                2u8
            } else if range.main_type == "*" && range.sub_type == "*" {
                1u8
            } else {
                0u8
            };
            if specificity > 0 {
                match matched_rule {
                    None => matched_rule = Some((specificity, range.q_millis)),
                    Some((prev_spec, prev_q))
                        if specificity > prev_spec
                            || (specificity == prev_spec && range.q_millis > prev_q) =>
                    {
                        matched_rule = Some((specificity, range.q_millis));
                    }
                    _ => {}
                }
            }
        }

        if let Some((spec, q)) = matched_rule
            && q > 0
        {
            let candidate_rank = (q, spec);
            if best.is_none_or(|(best_q, best_spec, _)| candidate_rank > (best_q, best_spec)) {
                best = Some((q, spec, fmt));
            }
        }
    }

    best.map(|(_, _, fmt)| fmt).ok_or_else(|| {
        LdpError::NotAcceptable(
            "Requested Accept media type is not supported; available RDF formats: text/turtle, application/n-triples, application/ld+json"
                .to_string(),
        )
    })
}

fn check_accept_for_non_rdf(headers: &HeaderMap, stored_ct: &str) -> Result<(), LdpError> {
    let accept_values: Vec<&HeaderValue> = headers.get_all(header::ACCEPT).iter().collect();
    if accept_values.is_empty() {
        return Ok(());
    }

    let (s_type, s_sub) = stored_ct
        .split_once('/')
        .unwrap_or(("application", "octet-stream"));
    let mut ranges = Vec::new();
    for hv in accept_values {
        let s = hv
            .to_str()
            .map_err(|_| LdpError::BadRequest("Malformed Accept header".to_string()))?;
        for part in s.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                ranges.push(parse_accept_range(trimmed)?);
            }
        }
    }
    if ranges.is_empty() {
        return Ok(());
    }

    let mut matched: Option<(u8, u32)> = None;
    for range in &ranges {
        let spec = if range.main_type == s_type && range.sub_type == s_sub {
            3u8
        } else if range.main_type == s_type && range.sub_type == "*" {
            2u8
        } else if range.main_type == "*" && range.sub_type == "*" {
            1u8
        } else {
            0u8
        };
        if spec > 0
            && matched.is_none_or(|(ps, pq)| spec > ps || (spec == ps && range.q_millis > pq))
        {
            matched = Some((spec, range.q_millis));
        }
    }

    match matched {
        Some((_, q)) if q > 0 => Ok(()),
        _ => Err(LdpError::NotAcceptable(format!(
            "NonRDFSource media type '{stored_ct}' does not match client Accept header"
        ))),
    }
}

struct AcceptRange {
    main_type: String,
    sub_type: String,
    q_millis: u32,
}

fn parse_accept_range(raw: &str) -> Result<AcceptRange, LdpError> {
    let mut segments = raw.split(';');
    let media = segments.next().unwrap_or_default().trim();
    let Some((t, sub)) = media.split_once('/') else {
        return Err(LdpError::BadRequest(format!(
            "Malformed media range '{media}' in Accept header"
        )));
    };
    let main_type = t.trim().to_ascii_lowercase();
    let sub_type = sub.trim().to_ascii_lowercase();
    if main_type.is_empty() || sub_type.is_empty() {
        return Err(LdpError::BadRequest(
            "Empty type or subtype in Accept header".to_string(),
        ));
    }

    let mut q_millis = 1000u32;
    for param in segments {
        if let Some((k, v)) = param.split_once('=')
            && k.trim().eq_ignore_ascii_case("q")
        {
            let q_val: f32 = v.trim().parse().map_err(|_| {
                LdpError::BadRequest(format!("Invalid quality weight 'q={}' in Accept", v.trim()))
            })?;
            if !(0.0..=1.0).contains(&q_val) {
                return Err(LdpError::BadRequest(
                    "Accept quality weight q must be between 0.0 and 1.0".to_string(),
                ));
            }
            q_millis = (q_val * 1000.0).round() as u32;
        }
    }

    Ok(AcceptRange {
        main_type,
        sub_type,
        q_millis,
    })
}

fn parse_link_type_iris(headers: &HeaderMap) -> Result<BTreeSet<String>, LdpError> {
    let mut types = BTreeSet::new();
    for hv in headers.get_all(header::LINK) {
        let s = hv
            .to_str()
            .map_err(|_| LdpError::BadRequest("Malformed Link header".to_string()))?;
        for item in split_link_values(s) {
            let mut parts = item.split(';');
            let target_part = parts.next().unwrap_or_default().trim();
            let Some(iri) = target_part
                .strip_prefix('<')
                .and_then(|rest| rest.strip_suffix('>'))
            else {
                continue;
            };
            let is_rel_type = parts.any(|param| {
                if let Some((k, v)) = param.split_once('=')
                    && k.trim().eq_ignore_ascii_case("rel")
                {
                    let unquoted = v.trim().trim_matches('"');
                    return unquoted
                        .split_whitespace()
                        .any(|tok| tok.eq_ignore_ascii_case("type"));
                }
                false
            });
            if is_rel_type {
                types.insert(iri.trim().to_string());
            }
        }
    }
    Ok(types)
}

fn split_link_values(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut in_angle = false;
    let mut in_quote = false;
    for (idx, ch) in s.char_indices() {
        match ch {
            '<' if !in_quote => in_angle = true,
            '>' if !in_quote => in_angle = false,
            '"' if !in_angle => in_quote = !in_quote,
            ',' if !in_angle && !in_quote => {
                out.push(s[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    if start <= s.len() {
        let tail = s[start..].trim();
        if !tail.is_empty() {
            out.push(tail);
        }
    }
    out
}

fn parse_slug_header(headers: &HeaderMap) -> Result<Option<String>, LdpError> {
    let Some(raw) = headers.get("slug") else {
        return Ok(None);
    };
    let slug = raw
        .to_str()
        .map_err(|_| LdpError::BadRequest("Malformed Slug header encoding".to_string()))?
        .trim();

    if slug.is_empty() || slug.len() > MAX_SLUG_LEN {
        return Err(LdpError::BadRequest(
            "Slug header must be between 1 and 255 characters".to_string(),
        ));
    }
    if slug.bytes().any(|b| {
        b.is_ascii_control()
            || b.is_ascii_whitespace()
            || matches!(b, b'/' | b'\\' | b'%' | b'?' | b'#')
    }) {
        return Err(LdpError::BadRequest(
            "Slug header must not contain path separators, whitespace, or URI delimiters"
                .to_string(),
        ));
    }
    if slug == "."
        || slug == ".."
        || slug == RESERVED_META_SEG
        || slug.starts_with("__wolin_meta")
        || slug.ends_with(".acl")
    {
        return Err(LdpError::BadRequest(format!(
            "Disallowed or reserved Slug '{slug}'"
        )));
    }
    Ok(Some(slug.to_string()))
}

struct SparqlPatchProfile {
    requires_write: bool,
    requires_read: bool,
}

#[allow(deprecated)]
fn classify_sparql_update(update: &SparqlUpdate) -> Result<SparqlPatchProfile, LdpError> {
    let canonical = update.to_string();
    let mut op_count = 0usize;
    let mut requires_write = false;
    let mut requires_read = false;

    for line in canonical.lines() {
        if line.starts_with("\tGRAPH ") {
            return Err(LdpError::BadRequest(
                "Named GRAPH clauses are not permitted in Solid single-resource SPARQL-Update"
                    .to_string(),
            ));
        }
        if line.is_empty()
            || line.starts_with('\t')
            || line.starts_with('}')
            || line.starts_with("BASE ")
        {
            continue;
        }
        if line.starts_with("LOAD ")
            || line.starts_with("CREATE ")
            || line.starts_with("DROP ")
            || line.starts_with("USING ")
        {
            return Err(LdpError::BadRequest(
                "Dataset management operations (LOAD/CREATE/DROP/USING) are forbidden in LDP PATCH"
                    .to_string(),
            ));
        }
        if line.starts_with("INSERT DATA {") {
            op_count += 1;
        } else if line.starts_with("DELETE DATA {") || line.starts_with("CLEAR ") {
            op_count += 1;
            requires_write = true;
        } else if line.starts_with("DELETE {") || line.starts_with("INSERT {") {
            op_count += 1;
            requires_write = true;
            requires_read = true;
        } else if line.starts_with("WHERE {") {
            requires_write = true;
            requires_read = true;
        }
    }

    if op_count == 0 {
        return Err(LdpError::BadRequest(
            "SPARQL-Update contains no executable update operations".to_string(),
        ));
    }

    Ok(SparqlPatchProfile {
        requires_write,
        requires_read,
    })
}

fn reject_client_contains_triples(triples: &[Triple]) -> Result<(), LdpError> {
    if triples.iter().any(|t| t.predicate.as_str() == LDP_CONTAINS) {
        return Err(LdpError::Conflict(
            "Server-managed ldp:contains containment triples cannot be set directly by clients"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_hierarchy_for_write(
    catalog: &LdpCatalog,
    canonical_path: &str,
    is_container_path: bool,
) -> Result<(), LdpError> {
    if canonical_path == "/" {
        return Ok(());
    }

    if is_container_path {
        let leaf_peer = canonical_path.trim_end_matches('/');
        if catalog.entries.contains_key(leaf_peer) {
            return Err(LdpError::Conflict(format!(
                "Cannot create container '{canonical_path}': conflicting resource '{leaf_peer}' already exists"
            )));
        }
    } else {
        let container_peer = format!("{canonical_path}/");
        if catalog.entries.contains_key(&container_peer) {
            return Err(LdpError::Conflict(format!(
                "Cannot write resource '{canonical_path}': conflicting container '{container_peer}' already exists"
            )));
        }
    }

    // Verify no ancestor segment is a non-container leaf resource
    let trimmed = canonical_path.trim_matches('/');
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.len() > 1 {
        let mut prefix = String::new();
        for seg in &parts[..parts.len() - 1] {
            prefix.push('/');
            prefix.push_str(seg);
            if catalog.entries.contains_key(&prefix) {
                return Err(LdpError::Conflict(format!(
                    "Ancestor '{prefix}' is a non-container resource and cannot contain child resources"
                )));
            }
        }
    }

    Ok(())
}

fn ensure_parent_containers(catalog: &mut LdpCatalog, canonical_path: &str) {
    if canonical_path == "/" || is_acl_canonical_path(canonical_path) {
        // Note: if creating `/alice/docs/.acl` or `/alice/docs/doc.ttl.acl`, ensure parent containers up to `/alice/docs/` exist.
        if let Some(container_prefix) = canonical_path.strip_suffix("/.acl") {
            if !container_prefix.is_empty() {
                ensure_parent_containers(catalog, &format!("{container_prefix}/__leaf"));
            }
        } else if let Some(governed) = canonical_path.strip_suffix(".acl") {
            ensure_parent_containers(catalog, governed);
        }
        return;
    }

    let trimmed = canonical_path.trim_matches('/');
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.len() <= 1 {
        return;
    }

    let mut current = String::from("/");
    for seg in &parts[..parts.len() - 1] {
        current.push_str(seg);
        current.push('/');
        catalog
            .entries
            .entry(current.clone())
            .or_insert_with(|| LdpEntry {
                path: current.clone(),
                kind: ResourceKind::Container,
                content_type: "text/turtle".to_string(),
                etag: compute_etag(current.as_bytes()),
                size_bytes: 0,
            });
    }
}

fn check_write_preconditions(
    headers: &HeaderMap,
    current_etag: Option<&str>,
) -> Result<(), LdpError> {
    if let Some(if_match_hdr) = headers.get(header::IF_MATCH) {
        let s = if_match_hdr
            .to_str()
            .map_err(|_| LdpError::BadRequest("Malformed If-Match header".to_string()))?
            .trim();
        let matched = match current_etag {
            None => false,
            Some(etag) => s == "*" || s.split(',').any(|tok| tok.trim() == etag),
        };
        if !matched {
            return Err(LdpError::PreconditionFailed(
                "If-Match precondition failed".to_string(),
            ));
        }
    }

    if let Some(if_none_match_hdr) = headers.get(header::IF_NONE_MATCH) {
        let s = if_none_match_hdr
            .to_str()
            .map_err(|_| LdpError::BadRequest("Malformed If-None-Match header".to_string()))?
            .trim();
        if let Some(etag) = current_etag
            && (s == "*" || s.split(',').any(|tok| tok.trim() == etag))
        {
            return Err(LdpError::PreconditionFailed(
                "If-None-Match precondition failed: target resource already exists".to_string(),
            ));
        }
    }

    Ok(())
}

fn check_if_match_get(headers: &HeaderMap, current_etag: &str) -> Result<(), LdpError> {
    if let Some(if_match_hdr) = headers.get(header::IF_MATCH) {
        let s = if_match_hdr
            .to_str()
            .map_err(|_| LdpError::BadRequest("Malformed If-Match header".to_string()))?
            .trim();
        if s != "*" && !s.split(',').any(|tok| tok.trim() == current_etag) {
            return Err(LdpError::PreconditionFailed(
                "If-Match precondition failed".to_string(),
            ));
        }
    }
    Ok(())
}

fn if_none_match_satisfied(headers: &HeaderMap, current_etag: &str) -> bool {
    let Some(hdr) = headers.get(header::IF_NONE_MATCH) else {
        return false;
    };
    let Ok(s) = hdr.to_str() else {
        return false;
    };
    let trimmed = s.trim();
    trimmed == "*"
        || trimmed
            .split(',')
            .any(|tok| tok.trim().trim_start_matches("W/") == current_etag)
}

pub(crate) fn compute_etag(bytes: &[u8]) -> String {
    // Deterministic 128-bit dual FNV-1a content fingerprint formatted as a strong HTTP ETag.
    let mut h1: u64 = 0xcbf29ce484222325;
    let mut h2: u64 = 0x84222325cbf29ce4;
    for (idx, &b) in bytes.iter().enumerate() {
        h1 ^= b as u64;
        h1 = h1.wrapping_mul(0x100000001b3);
        h2 ^= (b as u64) ^ ((idx as u64) & 0xff);
        h2 = h2.wrapping_mul(0x100000001b3);
    }
    format!("\"{h1:016x}{h2:016x}-{:x}\"", bytes.len())
}

pub(crate) fn acl_rule_prefix(acl_canonical_path: &str) -> String {
    format!("acl-doc:{acl_canonical_path}#")
}

pub(crate) fn rehydrate_persisted_acl_rules(
    pod_stores: &PodStoreManager,
    catalog: &LdpCatalog,
    policy_engine: &mut PolicyEngine,
    config: &crate::LdpConfig,
) -> wolin_core::Result<()> {
    for path in catalog.entries.keys() {
        if !is_acl_canonical_path(path) {
            continue;
        }
        if let Some(rest) = path.strip_prefix("/pods/")
            && let Some((seg, _)) = rest.split_once('/')
            && (config.reserved_pods.contains(seg) || catalog.tombstones.contains_key(seg))
        {
            continue;
        }
        let target = build_ldp_target_from_canonical(path, &config.pod_uri_prefix);
        let acl_iri = http_iri(&config.base_url, path);
        let store = match pod_stores.store_for_path(path) {
            Ok(s) => s,
            Err(wolin_core::WolinError::InvalidFormat(msg)) => {
                tracing::warn!(
                    acl_path = %path,
                    reason = %msg,
                    "Skipping persisted .acl under legacy or newly-reserved pod_id during startup rehydration"
                );
                continue;
            }
            Err(e) => return Err(e),
        };
        let triples = store.get_named_graph_triples(&acl_iri)?;
        if triples.is_empty() {
            continue;
        }
        if let Ok(rules) = extract_wac_rules_from_acl_triples(config, &target, &triples) {
            let prefix = acl_rule_prefix(path);
            policy_engine.remove_wac_rules_by_prefix(&prefix);
            for rule in rules {
                policy_engine.add_wac_rule(rule);
            }
        }
    }
    Ok(())
}

pub(crate) fn extract_wac_rules_from_acl_triples(
    config: &crate::LdpConfig,
    acl_target: &LdpTarget,
    triples: &[Triple],
) -> Result<Vec<WacRule>, LdpError> {
    let mut grouped: BTreeMap<String, Vec<&Triple>> = BTreeMap::new();
    for t in triples {
        let key = match &t.subject {
            NamedOrBlankNode::NamedNode(n) => format!("I:{}", n.as_str()),
            NamedOrBlankNode::BlankNode(b) => format!("B:{}", b.as_str()),
        };
        grouped.entry(key).or_default().push(t);
    }

    let governed_is_container =
        acl_target.canonical_path == "/.acl" || acl_target.canonical_path.ends_with("/.acl");
    let prefix = acl_rule_prefix(&acl_target.canonical_path);
    let mut rules = Vec::new();

    for (idx, (_subj_key, subj_triples)) in grouped.into_iter().enumerate() {
        let is_auth = subj_triples.iter().any(|t| {
            (t.predicate.as_str() == RDF_TYPE
                && matches!(&t.object, Term::NamedNode(n) if n.as_str() == ACL_AUTHORIZATION))
                || matches!(
                    t.predicate.as_str(),
                    ACL_MODE | ACL_ACCESS_TO | ACL_DEFAULT | ACL_DEFAULT_FOR_NEW
                )
        });
        if !is_auth {
            continue;
        }

        let mut subjects = Vec::new();
        let mut modes = Vec::new();
        let mut access_to = Vec::new();
        let mut default_for = Vec::new();

        for t in subj_triples {
            let pred = t.predicate.as_str();
            let Term::NamedNode(obj_node) = &t.object else {
                return Err(LdpError::BadRequest(format!(
                    "Invalid non-IRI object on ACL predicate '{pred}'"
                )));
            };
            let obj_iri = obj_node.as_str();

            match pred {
                ACL_AGENT => {
                    let normalized = if obj_iri.starts_with("did:") {
                        wolin_identity::DidResolver::parse(obj_iri)
                            .map(|p| p.canonical_did)
                            .map_err(|e| {
                                LdpError::BadRequest(format!("Invalid DID in acl:agent: {e}"))
                            })?
                    } else {
                        obj_iri.to_string()
                    };
                    subjects.push(SubjectMatcher::WebId(WebId(normalized)));
                }
                ACL_AGENT_CLASS => match obj_iri {
                    FOAF_AGENT => subjects.push(SubjectMatcher::Public),
                    ACL_AUTHENTICATED_AGENT | FOAF_AUTHENTICATED_AGENT => {
                        subjects.push(SubjectMatcher::Authenticated)
                    }
                    other => {
                        return Err(LdpError::BadRequest(format!(
                            "Unsupported acl:agentClass '{other}'"
                        )));
                    }
                },
                ACL_MODE => match obj_iri {
                    ACL_READ => modes.push(AccessMode::Read),
                    ACL_WRITE => modes.push(AccessMode::Write),
                    ACL_APPEND => modes.push(AccessMode::Append),
                    ACL_CONTROL => modes.push(AccessMode::Control),
                    other => {
                        return Err(LdpError::BadRequest(format!(
                            "Unsupported acl:mode '{other}'"
                        )));
                    }
                },
                ACL_ACCESS_TO => {
                    let mapped = map_acl_target_iri_to_policy_uri(config, obj_iri)?;
                    if mapped != acl_target.policy_target {
                        return Err(LdpError::Forbidden(format!(
                            "ACL document '{}' cannot govern external resource '{}'",
                            acl_target.canonical_path, obj_iri
                        )));
                    }
                    access_to.push(mapped);
                }
                ACL_DEFAULT | ACL_DEFAULT_FOR_NEW => {
                    if !governed_is_container {
                        return Err(LdpError::BadRequest(
                            "acl:default is only valid on container .acl documents".to_string(),
                        ));
                    }
                    let mapped = map_acl_target_iri_to_policy_uri(config, obj_iri)?;
                    if mapped != acl_target.policy_target {
                        return Err(LdpError::Forbidden(format!(
                            "ACL document '{}' cannot set acl:default for external container '{}'",
                            acl_target.canonical_path, obj_iri
                        )));
                    }
                    default_for.push(mapped);
                }
                _ => {}
            }
        }

        if subjects.is_empty()
            || modes.is_empty()
            || (access_to.is_empty() && default_for.is_empty())
        {
            return Err(LdpError::BadRequest(
                "Incomplete acl:Authorization block: requires subject, acl:mode, and acl:accessTo/acl:default"
                    .to_string(),
            ));
        }

        rules.push(WacRule {
            id: format!("{prefix}{idx}"),
            access_to,
            default_for,
            subjects,
            modes,
        });
    }

    Ok(rules)
}

fn map_acl_target_iri_to_policy_uri(
    config: &crate::LdpConfig,
    raw_iri: &str,
) -> Result<ResourceUri, LdpError> {
    let base = config.base_url.trim_end_matches('/');
    let pod_prefix = config.pod_uri_prefix.trim_end_matches('/');

    if let Some(rel_path) = raw_iri.strip_prefix(base) {
        let normalized_http_path = if rel_path.is_empty() { "/" } else { rel_path };
        let parsed = parse_ldp_path_str(normalized_http_path, pod_prefix)?;
        if parsed.is_acl {
            return Err(LdpError::BadRequest(
                "acl:accessTo / acl:default must reference the governed resource, not .acl itself"
                    .to_string(),
            ));
        }
        return Ok(parsed.policy_target);
    }

    if raw_iri == pod_prefix || raw_iri == format!("{pod_prefix}/") {
        return Ok(ResourceUri(pod_prefix.to_string()));
    }
    if let Some(rel_path) = raw_iri.strip_prefix(pod_prefix)
        && rel_path.starts_with('/')
    {
        let parsed = parse_ldp_path_str(rel_path, pod_prefix)?;
        if parsed.is_acl {
            return Err(LdpError::BadRequest(
                "acl:accessTo / acl:default must reference the governed resource, not .acl itself"
                    .to_string(),
            ));
        }
        return Ok(parsed.policy_target);
    }

    Err(LdpError::Forbidden(format!(
        "ACL target IRI '{raw_iri}' does not belong to pod '{base}'"
    )))
}
