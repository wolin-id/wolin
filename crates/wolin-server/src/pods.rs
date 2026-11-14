use std::sync::Arc;

use axum::{
    Json,
    body::to_bytes,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use wolin_core::{Principal, ResourceKind};
use wolin_identity::DidResolver;
use wolin_storage::{
    SemanticGraphStore,
    rdf_io::RdfFormat,
    rdf_model::{Literal, NamedNode, NamedOrBlankNode, Term, Triple},
};

use crate::{
    AppState, LdpConfig,
    auth::{effective_scheme, extract_principal_for_request},
    error::LdpError,
    ldp::{
        FOAF_PERSON, FOAF_PERSONAL_PROFILE_DOCUMENT, LDP_INBOX_REL, LdpCatalog, LdpEntry,
        PIM_STORAGE, PIM_STORAGE_REL, SOLID_OIDC_ISSUER, acl_rule_prefix, blob_key_for_path,
        build_ldp_target_from_canonical, compute_etag, extract_wac_rules_from_acl_triples,
        http_iri,
    },
};

const MAX_POD_ID_LEN: usize = 63;
const MAX_DISPLAY_NAME_LEN: usize = 256;
const MAX_PROVISION_BODY_BYTES: usize = 64 * 1024;

const INFRA_SUBDOMAINS: &[&str] = &["pod", "pods", "api", "auth", "login", "id", "www", "mcp"];
const RESERVED_POD_IDS: &[&str] = &[
    "pod",
    "pods",
    "api",
    "auth",
    "login",
    "id",
    "www",
    "mcp",
    "health",
    "public",
    "private",
    "admin",
    "system",
    "well-known",
];

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const DCTERMS_TITLE: &str = "http://purl.org/dc/terms/title";
const FOAF_NAME: &str = "http://xmlns.com/foaf/0.1/name";
const FOAF_MAKER: &str = "http://xmlns.com/foaf/0.1/maker";
const FOAF_PRIMARY_TOPIC: &str = "http://xmlns.com/foaf/0.1/primaryTopic";
const FOAF_AGENT: &str = "http://xmlns.com/foaf/0.1/Agent";
const VCARD_INDIVIDUAL: &str = "http://www.w3.org/2006/vcard/ns#Individual";
const VCARD_FN: &str = "http://www.w3.org/2006/vcard/ns#fn";
const OWL_SAME_AS: &str = "http://www.w3.org/2002/07/owl#sameAs";

const ACL_AUTHORIZATION: &str = "http://www.w3.org/ns/auth/acl#Authorization";
const ACL_AGENT: &str = "http://www.w3.org/ns/auth/acl#agent";
const ACL_AGENT_CLASS: &str = "http://www.w3.org/ns/auth/acl#agentClass";
const ACL_AUTHENTICATED_AGENT: &str = "http://www.w3.org/ns/auth/acl#AuthenticatedAgent";
const ACL_ACCESS_TO: &str = "http://www.w3.org/ns/auth/acl#accessTo";
const ACL_DEFAULT: &str = "http://www.w3.org/ns/auth/acl#default";
const ACL_MODE: &str = "http://www.w3.org/ns/auth/acl#mode";
const ACL_READ: &str = "http://www.w3.org/ns/auth/acl#Read";
const ACL_WRITE: &str = "http://www.w3.org/ns/auth/acl#Write";
const ACL_APPEND: &str = "http://www.w3.org/ns/auth/acl#Append";
const ACL_CONTROL: &str = "http://www.w3.org/ns/auth/acl#Control";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionPodRequest {
    pub pod_id: String,
    #[serde(default)]
    pub owner_webid: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub oidc_issuer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionPodResponse {
    pub pod_id: String,
    pub pod_url: String,
    pub subdomain_url: String,
    pub webid: String,
    pub owner_webid: String,
    pub display_name: String,
    pub storage: String,
    pub inbox: String,
    pub seeded_resources: Vec<String>,
}

/// Validate that `pod_id` is a safe RFC 1123 lowercase DNS label (`[a-z0-9-]`, 1..=63 chars)
/// and does not collide with reserved infrastructure/system routes.
pub fn validate_pod_id(pod_id: &str) -> Result<(), LdpError> {
    if pod_id.is_empty() || pod_id.len() > MAX_POD_ID_LEN {
        return Err(LdpError::BadRequest(
            "pod_id must be between 1 and 63 lowercase characters".to_string(),
        ));
    }
    if pod_id.starts_with('-')
        || pod_id.ends_with('-')
        || pod_id.starts_with("__wolin_")
        || !pod_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(LdpError::BadRequest(
            "pod_id must contain only lowercase ASCII letters, digits, or interior hyphens"
                .to_string(),
        ));
    }
    if RESERVED_POD_IDS.contains(&pod_id) {
        return Err(LdpError::BadRequest(format!(
            "pod_id '{pod_id}' is reserved for system infrastructure"
        )));
    }
    Ok(())
}

/// Inspect `Host` header (or request URI authority) to resolve tenant subdomain routing
/// (`{pod_id}.{pod_cloud_domain}` -> `Some((pod_id, external_subdomain_origin))`).
/// Infrastructure hosts (e.g. `pod.wolin.cloud`, `api.wolin.cloud`) return `Ok(None)`.
pub fn extract_subdomain_pod(
    headers: &HeaderMap,
    uri: &Uri,
    config: &LdpConfig,
) -> Result<Option<(String, String)>, LdpError> {
    let cloud_domain = config.pod_cloud_domain.trim();
    if cloud_domain.is_empty() {
        return Ok(None);
    }

    let raw_authority = match headers.get(header::HOST) {
        Some(hv) => hv
            .to_str()
            .map_err(|_| LdpError::BadRequest("Malformed Host header encoding".to_string()))?
            .trim(),
        None => match uri.authority() {
            Some(auth) => auth.as_str(),
            None => return Ok(None),
        },
    };

    if raw_authority.is_empty() {
        return Ok(None);
    }
    if raw_authority.bytes().any(|b| {
        b.is_ascii_whitespace() || b.is_ascii_control() || matches!(b, b'/' | b'\\' | b'@')
    }) {
        return Err(LdpError::BadRequest(
            "Invalid characters in Host header".to_string(),
        ));
    }

    let (host_part, port_opt) = split_host_and_port(raw_authority)?;
    let host_lower = host_part.to_ascii_lowercase();

    if host_lower == cloud_domain {
        return Ok(None);
    }

    let suffix = format!(".{cloud_domain}");
    let Some(sub_label) = host_lower.strip_suffix(&suffix) else {
        return Ok(None);
    };

    if INFRA_SUBDOMAINS.contains(&sub_label) {
        return Ok(None);
    }

    if sub_label.contains('.') {
        return Err(LdpError::BadRequest(
            "Multi-level tenant subdomains are not permitted".to_string(),
        ));
    }
    validate_pod_id(sub_label)?;

    let scheme = effective_scheme(uri, headers, config);
    let external_origin = match port_opt {
        Some(port) => format!("{scheme}://{host_lower}:{port}"),
        None => format!("{scheme}://{host_lower}"),
    };

    Ok(Some((sub_label.to_string(), external_origin)))
}

fn split_host_and_port(authority: &str) -> Result<(&str, Option<u16>), LdpError> {
    if authority.starts_with('[') {
        let Some(end_bracket) = authority.find(']') else {
            return Err(LdpError::BadRequest(
                "Malformed IPv6 literal in Host header".to_string(),
            ));
        };
        let host = &authority[..=end_bracket];
        let rest = &authority[end_bracket + 1..];
        if rest.is_empty() {
            return Ok((host, None));
        }
        let Some(port_str) = rest.strip_prefix(':') else {
            return Err(LdpError::BadRequest(
                "Malformed port suffix in Host header".to_string(),
            ));
        };
        let port = port_str
            .parse::<u16>()
            .map_err(|_| LdpError::BadRequest("Invalid TCP port in Host header".to_string()))?;
        return Ok((host, Some(port)));
    }

    match authority.split_once(':') {
        Some((h, port_str)) => {
            if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
                return Err(LdpError::BadRequest(
                    "Invalid TCP port in Host header".to_string(),
                ));
            }
            let port = port_str
                .parse::<u16>()
                .map_err(|_| LdpError::BadRequest("Invalid TCP port in Host header".to_string()))?;
            Ok((h, Some(port)))
        }
        None => Ok((authority, None)),
    }
}

/// Dynamic Multi-tenant Pod Provisioning (`POST /api/pods`).
///
/// Atomically creates `/pods/{pod_id}/` and seeds standard W3C Solid resources:
/// - `/pods/{pod_id}/profile/card` (`foaf:Person`, `pim:storage`, `solid:oidcIssuer`, `ldp:inbox`)
/// - `/pods/{pod_id}/profile/card.acl` (Public Read WAC + Owner full WAC)
/// - `/pods/{pod_id}/inbox/` & `.acl` (Authenticated LDN Append + Owner full WAC)
/// - `/pods/{pod_id}/public/` & `.acl` (Public Read WAC + Owner full WAC)
/// - `/pods/{pod_id}/private/` & `.acl` (Owner-only WAC)
/// - `/pods/{pod_id}/.well-known/wolin.json` & `.acl` (Pod & MCP discovery metadata)
pub async fn handle_provision_pod(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Result<Response, LdpError> {
    if req.uri().query().is_some() {
        return Err(LdpError::BadRequest(
            "Query parameters are not permitted on /api/pods".to_string(),
        ));
    }

    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Fail-closed validation if caller supplies an Authorization header.
    let caller = extract_principal_for_request(&method, &uri, &headers, &state).await?;

    if let Some(raw_ct) = headers.get(header::CONTENT_TYPE) {
        let ct_str = raw_ct
            .to_str()
            .map_err(|_| LdpError::BadRequest("Malformed Content-Type header".to_string()))?;
        let media = ct_str
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if media != "application/json" {
            return Err(LdpError::UnsupportedMediaType(format!(
                "Pod provisioning requires 'Content-Type: application/json', got '{media}'"
            )));
        }
    }

    let max_bytes = state.config.max_body_bytes.min(MAX_PROVISION_BODY_BYTES);
    let body_bytes = to_bytes(req.into_body(), max_bytes).await.map_err(|_| {
        LdpError::PayloadTooLarge(format!(
            "Provisioning payload exceeds maximum allowed size of {max_bytes} bytes"
        ))
    })?;

    let payload: ProvisionPodRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| LdpError::BadRequest(format!("Malformed provisioning JSON payload: {e}")))?;

    let pod_id = payload.pod_id.trim();
    validate_pod_id(pod_id)?;

    let base_url = state.config.base_url.trim_end_matches('/');
    let pod_root_path = format!("/pods/{pod_id}/");
    let pod_root_iri = http_iri(base_url, &pod_root_path);
    let card_path = format!("/pods/{pod_id}/profile/card");
    let card_iri = http_iri(base_url, &card_path);
    let pod_webid = format!("{card_iri}#me");
    let inbox_iri = format!("{pod_root_iri}inbox/");

    let owner_webid = match payload.owner_webid {
        Some(ref raw) => normalize_and_validate_owner_webid(raw)?,
        None => match &caller {
            Principal::User { webid, .. } => webid.0.clone(),
            _ => pod_webid.clone(),
        },
    };

    let display_name = match payload.display_name {
        Some(ref raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.len() > MAX_DISPLAY_NAME_LEN {
                return Err(LdpError::BadRequest(
                    "display_name must be between 1 and 256 characters".to_string(),
                ));
            }
            if trimmed.bytes().any(|b| b.is_ascii_control()) {
                return Err(LdpError::BadRequest(
                    "display_name must not contain control characters".to_string(),
                ));
            }
            trimmed.to_string()
        }
        None => pod_id.to_string(),
    };

    let oidc_issuer = match payload.oidc_issuer {
        Some(ref raw_iss) => validate_http_uri(raw_iss.trim(), "oidc_issuer")?,
        None => state.config.oidc_options.expected_issuer.trim().to_string(),
    };

    let scheme = effective_scheme(&uri, &headers, &state.config);
    let subdomain_url = if state.config.pod_cloud_domain.is_empty() {
        pod_root_iri.clone()
    } else {
        format!("{scheme}://{pod_id}.{}/", state.config.pod_cloud_domain)
    };

    // Acquire write lock across full check + seed + persist transaction.
    let _io_guard = state.catalog_lock.write().await;
    let mut catalog = state.catalog.write().await;
    *catalog = LdpCatalog::load_or_init(&state.physical_store).await?;

    if catalog.entries.contains_key(&pod_root_path) {
        return Err(LdpError::Conflict(format!(
            "Pod '{pod_id}' is already provisioned"
        )));
    }

    catalog
        .entries
        .entry("/pods/".to_string())
        .or_insert_with(|| LdpEntry {
            path: "/pods/".to_string(),
            kind: ResourceKind::Container,
            content_type: "text/turtle".to_string(),
            etag: compute_etag(b"/pods/"),
        });

    let subdomain_webid = format!("{subdomain_url}profile/card#me");
    let mut owner_list = vec![pod_webid.clone()];
    if owner_webid != pod_webid {
        owner_list.insert(0, owner_webid.clone());
    }
    if subdomain_webid != pod_webid && !owner_list.contains(&subdomain_webid) {
        owner_list.push(subdomain_webid);
    }
    let owners: Vec<&str> = owner_list.iter().map(String::as_str).collect();

    let mut seeded_paths = Vec::new();
    let mut compiled_wac_batches = Vec::new();

    // 1. Pod Root Container `/pods/{pod_id}/`
    let root_triples = vec![
        named_triple(&pod_root_iri, RDF_TYPE, PIM_STORAGE)?,
        literal_triple(&pod_root_iri, DCTERMS_TITLE, &display_name)?,
        named_triple(&pod_root_iri, LDP_INBOX_REL, &inbox_iri)?,
    ];
    store_rdf_entry(
        &state,
        &mut catalog,
        &pod_root_path,
        ResourceKind::Container,
        &root_triples,
    )?;
    seeded_paths.push(pod_root_path.clone());

    // 2. Pod Root ACL `/pods/{pod_id}/.acl` (Owner Read/Write/Append/Control + default)
    let root_acl_path = format!("/pods/{pod_id}/.acl");
    let root_acl_iri = http_iri(base_url, &root_acl_path);
    let root_acl_triples = build_acl_triples(
        &root_acl_iri,
        &pod_root_iri,
        true,
        &owners,
        AclGrantProfile::OwnerOnly,
    )?;
    let root_acl_rules =
        compile_acl_entry(&state, &mut catalog, &root_acl_path, &root_acl_triples)?;
    compiled_wac_batches.push((acl_rule_prefix(&root_acl_path), root_acl_rules));
    seeded_paths.push(root_acl_path);

    // 3. Profile Container `/pods/{pod_id}/profile/`
    let profile_dir_path = format!("/pods/{pod_id}/profile/");
    store_rdf_entry(
        &state,
        &mut catalog,
        &profile_dir_path,
        ResourceKind::Container,
        &[],
    )?;
    seeded_paths.push(profile_dir_path);

    // 4. WebID Profile Card `/pods/{pod_id}/profile/card`
    let mut card_triples = vec![
        named_triple(&card_iri, RDF_TYPE, FOAF_PERSONAL_PROFILE_DOCUMENT)?,
        named_triple(&card_iri, FOAF_MAKER, &pod_webid)?,
        named_triple(&card_iri, FOAF_PRIMARY_TOPIC, &pod_webid)?,
        named_triple(&pod_webid, RDF_TYPE, FOAF_PERSON)?,
        named_triple(&pod_webid, RDF_TYPE, VCARD_INDIVIDUAL)?,
        literal_triple(&pod_webid, FOAF_NAME, &display_name)?,
        literal_triple(&pod_webid, VCARD_FN, &display_name)?,
        named_triple(&pod_webid, PIM_STORAGE_REL, &pod_root_iri)?,
        named_triple(&pod_webid, LDP_INBOX_REL, &inbox_iri)?,
        named_triple(&pod_webid, SOLID_OIDC_ISSUER, &oidc_issuer)?,
    ];
    if owner_webid != pod_webid {
        card_triples.push(named_triple(&pod_webid, OWL_SAME_AS, &owner_webid)?);
        card_triples.push(named_triple(&owner_webid, PIM_STORAGE_REL, &pod_root_iri)?);
        card_triples.push(named_triple(&owner_webid, LDP_INBOX_REL, &inbox_iri)?);
    }
    store_rdf_entry(
        &state,
        &mut catalog,
        &card_path,
        ResourceKind::RdfSource,
        &card_triples,
    )?;
    seeded_paths.push(card_path.clone());

    // 5. Profile Card ACL `/pods/{pod_id}/profile/card.acl` (Public Read + Owner full)
    let card_acl_path = format!("{card_path}.acl");
    let card_acl_iri = http_iri(base_url, &card_acl_path);
    let card_acl_triples = build_acl_triples(
        &card_acl_iri,
        &card_iri,
        false,
        &owners,
        AclGrantProfile::PublicRead,
    )?;
    let card_acl_rules =
        compile_acl_entry(&state, &mut catalog, &card_acl_path, &card_acl_triples)?;
    compiled_wac_batches.push((acl_rule_prefix(&card_acl_path), card_acl_rules));
    seeded_paths.push(card_acl_path);

    // 6. LDN Inbox Container `/pods/{pod_id}/inbox/` + `.acl` (Authenticated Append + Owner full)
    let inbox_path = format!("/pods/{pod_id}/inbox/");
    store_rdf_entry(
        &state,
        &mut catalog,
        &inbox_path,
        ResourceKind::Container,
        &[],
    )?;
    seeded_paths.push(inbox_path);

    let inbox_acl_path = format!("/pods/{pod_id}/inbox/.acl");
    let inbox_acl_iri = http_iri(base_url, &inbox_acl_path);
    let inbox_acl_triples = build_acl_triples(
        &inbox_acl_iri,
        &inbox_iri,
        true,
        &owners,
        AclGrantProfile::AuthenticatedAppendOnContainer,
    )?;
    let inbox_acl_rules =
        compile_acl_entry(&state, &mut catalog, &inbox_acl_path, &inbox_acl_triples)?;
    compiled_wac_batches.push((acl_rule_prefix(&inbox_acl_path), inbox_acl_rules));
    seeded_paths.push(inbox_acl_path);

    // 7. Public Container `/pods/{pod_id}/public/` + `.acl` (Public Read + default + Owner full)
    let public_path = format!("/pods/{pod_id}/public/");
    let public_iri = http_iri(base_url, &public_path);
    store_rdf_entry(
        &state,
        &mut catalog,
        &public_path,
        ResourceKind::Container,
        &[],
    )?;
    seeded_paths.push(public_path);

    let public_acl_path = format!("/pods/{pod_id}/public/.acl");
    let public_acl_iri = http_iri(base_url, &public_acl_path);
    let public_acl_triples = build_acl_triples(
        &public_acl_iri,
        &public_iri,
        true,
        &owners,
        AclGrantProfile::PublicRead,
    )?;
    let public_acl_rules =
        compile_acl_entry(&state, &mut catalog, &public_acl_path, &public_acl_triples)?;
    compiled_wac_batches.push((acl_rule_prefix(&public_acl_path), public_acl_rules));
    seeded_paths.push(public_acl_path);

    // 8. Private Container `/pods/{pod_id}/private/` + `.acl` (Owner-only)
    let private_path = format!("/pods/{pod_id}/private/");
    let private_iri = http_iri(base_url, &private_path);
    store_rdf_entry(
        &state,
        &mut catalog,
        &private_path,
        ResourceKind::Container,
        &[],
    )?;
    seeded_paths.push(private_path);

    let private_acl_path = format!("/pods/{pod_id}/private/.acl");
    let private_acl_iri = http_iri(base_url, &private_acl_path);
    let private_acl_triples = build_acl_triples(
        &private_acl_iri,
        &private_iri,
        true,
        &owners,
        AclGrantProfile::OwnerOnly,
    )?;
    let private_acl_rules = compile_acl_entry(
        &state,
        &mut catalog,
        &private_acl_path,
        &private_acl_triples,
    )?;
    compiled_wac_batches.push((acl_rule_prefix(&private_acl_path), private_acl_rules));
    seeded_paths.push(private_acl_path);

    // 9. `.well-known/wolin.json` Pod & AI Agent MCP discovery manifest + `.acl`
    let wk_dir_path = format!("/pods/{pod_id}/.well-known/");
    store_rdf_entry(
        &state,
        &mut catalog,
        &wk_dir_path,
        ResourceKind::Container,
        &[],
    )?;
    seeded_paths.push(wk_dir_path);

    let wk_doc_path = format!("/pods/{pod_id}/.well-known/wolin.json");
    let wk_doc_iri = http_iri(base_url, &wk_doc_path);
    let wk_payload = serde_json::to_vec_pretty(&json!({
        "pod_id": pod_id,
        "display_name": display_name,
        "webid": pod_webid,
        "owner_webid": owner_webid,
        "storage": pod_root_iri,
        "subdomain_url": subdomain_url,
        "inbox": inbox_iri,
        "oidc_issuer": oidc_issuer,
        "mcp": {
            "endpoint": format!("{base_url}/mcp"),
            "sse": format!("{base_url}/mcp/sse"),
            "pod_resource_prefix": format!("{}/pods/{pod_id}/", state.config.pod_uri_prefix.trim_end_matches('/'))
        }
    }))
    .map_err(|e| LdpError::Internal(format!("Failed to serialize pod wolin.json: {e}")))?;
    let wk_etag = compute_etag(&wk_payload);
    state
        .physical_store
        .put_with_content_type(
            &blob_key_for_path(&wk_doc_path),
            wk_payload,
            "application/json",
        )
        .await?;
    catalog.entries.insert(
        wk_doc_path.clone(),
        LdpEntry {
            path: wk_doc_path.clone(),
            kind: ResourceKind::NonRdfSource,
            content_type: "application/json".to_string(),
            etag: wk_etag,
        },
    );
    seeded_paths.push(wk_doc_path.clone());

    let wk_acl_path = format!("{wk_doc_path}.acl");
    let wk_acl_iri = http_iri(base_url, &wk_acl_path);
    let wk_acl_triples = build_acl_triples(
        &wk_acl_iri,
        &wk_doc_iri,
        false,
        &owners,
        AclGrantProfile::PublicRead,
    )?;
    let wk_acl_rules = compile_acl_entry(&state, &mut catalog, &wk_acl_path, &wk_acl_triples)?;
    compiled_wac_batches.push((acl_rule_prefix(&wk_acl_path), wk_acl_rules));
    seeded_paths.push(wk_acl_path);

    // Commit catalog to OpenDAL physical store, then activate WAC rules in PolicyEngine.
    catalog.persist(&state.physical_store).await?;
    {
        let mut engine = state
            .policy_engine
            .write()
            .unwrap_or_else(|e| e.into_inner());
        for (prefix, rules) in compiled_wac_batches {
            engine.remove_wac_rules_by_prefix(&prefix);
            for rule in rules {
                engine.add_wac_rule(rule);
            }
        }
    }
    drop(catalog);
    drop(_io_guard);

    let resp_payload = ProvisionPodResponse {
        pod_id: pod_id.to_string(),
        pod_url: pod_root_iri.clone(),
        subdomain_url,
        webid: pod_webid,
        owner_webid,
        display_name,
        storage: pod_root_iri.clone(),
        inbox: inbox_iri,
        seeded_resources: seeded_paths,
    };

    let mut resp = (StatusCode::CREATED, Json(resp_payload)).into_response();
    if let Ok(loc) = HeaderValue::from_str(&pod_root_iri) {
        resp.headers_mut().insert(header::LOCATION, loc);
    }
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    Ok(resp)
}

/// Inspect public metadata of a provisioned Pod (`GET /api/pods/{pod_id}`).
pub async fn handle_get_pod_info(
    State(state): State<Arc<AppState>>,
    Path(pod_id): Path<String>,
    req: Request,
) -> Result<Response, LdpError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let _caller = extract_principal_for_request(&method, &uri, &headers, &state).await?;

    validate_pod_id(&pod_id)?;
    let wk_doc_path = format!("/pods/{pod_id}/.well-known/wolin.json");
    let catalog = state.catalog.read().await;
    if !catalog.entries.contains_key(&format!("/pods/{pod_id}/")) {
        return Err(LdpError::NotFound(format!("Pod '{pod_id}' not found")));
    }
    drop(catalog);

    let bytes = state
        .physical_store
        .get(&blob_key_for_path(&wk_doc_path))
        .await?;
    let mut resp = (StatusCode::OK, bytes).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

#[derive(Clone, Copy)]
enum AclGrantProfile {
    OwnerOnly,
    PublicRead,
    AuthenticatedAppendOnContainer,
}

fn build_acl_triples(
    acl_doc_iri: &str,
    governed_iri: &str,
    is_container: bool,
    owners: &[&str],
    profile: AclGrantProfile,
) -> Result<Vec<Triple>, LdpError> {
    let mut triples = Vec::new();
    let owner_subj = format!("{acl_doc_iri}#owner");
    triples.push(named_triple(&owner_subj, RDF_TYPE, ACL_AUTHORIZATION)?);
    triples.push(named_triple(&owner_subj, ACL_ACCESS_TO, governed_iri)?);
    if is_container {
        triples.push(named_triple(&owner_subj, ACL_DEFAULT, governed_iri)?);
    }
    for owner in owners {
        triples.push(named_triple(&owner_subj, ACL_AGENT, owner)?);
    }
    for mode in [ACL_READ, ACL_WRITE, ACL_APPEND, ACL_CONTROL] {
        triples.push(named_triple(&owner_subj, ACL_MODE, mode)?);
    }

    match profile {
        AclGrantProfile::OwnerOnly => {}
        AclGrantProfile::PublicRead => {
            let pub_subj = format!("{acl_doc_iri}#public");
            triples.push(named_triple(&pub_subj, RDF_TYPE, ACL_AUTHORIZATION)?);
            triples.push(named_triple(&pub_subj, ACL_ACCESS_TO, governed_iri)?);
            if is_container {
                triples.push(named_triple(&pub_subj, ACL_DEFAULT, governed_iri)?);
            }
            triples.push(named_triple(&pub_subj, ACL_AGENT_CLASS, FOAF_AGENT)?);
            triples.push(named_triple(&pub_subj, ACL_MODE, ACL_READ)?);
        }
        AclGrantProfile::AuthenticatedAppendOnContainer => {
            let append_subj = format!("{acl_doc_iri}#authenticated-append");
            triples.push(named_triple(&append_subj, RDF_TYPE, ACL_AUTHORIZATION)?);
            triples.push(named_triple(&append_subj, ACL_ACCESS_TO, governed_iri)?);
            triples.push(named_triple(
                &append_subj,
                ACL_AGENT_CLASS,
                ACL_AUTHENTICATED_AGENT,
            )?);
            triples.push(named_triple(&append_subj, ACL_MODE, ACL_APPEND)?);
        }
    }

    Ok(triples)
}

fn store_rdf_entry(
    state: &AppState,
    catalog: &mut LdpCatalog,
    canonical_path: &str,
    kind: ResourceKind,
    triples: &[Triple],
) -> Result<(), LdpError> {
    let graph_iri = http_iri(&state.config.base_url, canonical_path);
    state
        .graph_store
        .replace_named_graph_triples(&graph_iri, triples)?;
    let canonical_nt = SemanticGraphStore::serialize_triples(triples, RdfFormat::NTriples)?;
    let etag = compute_etag(&canonical_nt);
    catalog.entries.insert(
        canonical_path.to_string(),
        LdpEntry {
            path: canonical_path.to_string(),
            kind,
            content_type: "text/turtle".to_string(),
            etag,
        },
    );
    Ok(())
}

fn compile_acl_entry(
    state: &AppState,
    catalog: &mut LdpCatalog,
    acl_canonical_path: &str,
    triples: &[Triple],
) -> Result<Vec<wolin_policy::WacRule>, LdpError> {
    let target = build_ldp_target_from_canonical(acl_canonical_path, &state.config.pod_uri_prefix);
    let rules = extract_wac_rules_from_acl_triples(&state.config, &target, triples)?;
    store_rdf_entry(
        state,
        catalog,
        acl_canonical_path,
        ResourceKind::RdfSource,
        triples,
    )?;
    Ok(rules)
}

fn named_triple(subj: &str, pred: &str, obj: &str) -> Result<Triple, LdpError> {
    let s = NamedNode::new(subj)
        .map_err(|e| LdpError::BadRequest(format!("Invalid RDF subject IRI '{subj}': {e}")))?;
    let p = NamedNode::new(pred)
        .map_err(|e| LdpError::Internal(format!("Invalid RDF predicate IRI '{pred}': {e}")))?;
    let o = NamedNode::new(obj)
        .map_err(|e| LdpError::BadRequest(format!("Invalid RDF object IRI '{obj}': {e}")))?;
    Ok(Triple::new(
        NamedOrBlankNode::NamedNode(s),
        p,
        Term::NamedNode(o),
    ))
}

fn literal_triple(subj: &str, pred: &str, literal_value: &str) -> Result<Triple, LdpError> {
    let s = NamedNode::new(subj)
        .map_err(|e| LdpError::BadRequest(format!("Invalid RDF subject IRI '{subj}': {e}")))?;
    let p = NamedNode::new(pred)
        .map_err(|e| LdpError::Internal(format!("Invalid RDF predicate IRI '{pred}': {e}")))?;
    Ok(Triple::new(
        NamedOrBlankNode::NamedNode(s),
        p,
        Term::Literal(Literal::new_simple_literal(literal_value)),
    ))
}

fn normalize_and_validate_owner_webid(raw: &str) -> Result<String, LdpError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 2048 {
        return Err(LdpError::BadRequest(
            "owner_webid must be a non-empty valid WebID or DID URI".to_string(),
        ));
    }
    if trimmed.starts_with("did:") {
        let parsed = DidResolver::parse(trimmed)
            .map_err(|e| LdpError::BadRequest(format!("Invalid DID in owner_webid: {e}")))?;
        return Ok(parsed.canonical_did);
    }
    validate_http_uri_allow_fragment(trimmed, "owner_webid")
}

fn validate_http_uri(raw: &str, field: &str) -> Result<String, LdpError> {
    if raw.contains('?') || raw.contains('#') {
        return Err(LdpError::BadRequest(format!(
            "{field} must not contain query or fragment components"
        )));
    }
    validate_http_uri_allow_fragment(raw, field)
}

fn validate_http_uri_allow_fragment(raw: &str, field: &str) -> Result<String, LdpError> {
    if raw.is_empty()
        || raw.len() > 2048
        || raw
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || matches!(b, b'\\' | b'?'))
    {
        return Err(LdpError::BadRequest(format!("Invalid {field} URI '{raw}'")));
    }
    let _ = NamedNode::new(raw)
        .map_err(|e| LdpError::BadRequest(format!("Invalid {field} IRI '{raw}': {e}")))?;
    let rest = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))
        .ok_or_else(|| {
            LdpError::BadRequest(format!("{field} must start with 'https://' or 'http://'"))
        })?;
    let authority = rest.split(['/', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(LdpError::BadRequest(format!(
            "{field} must contain a valid host authority without userinfo"
        )));
    }
    Ok(raw.to_string())
}
