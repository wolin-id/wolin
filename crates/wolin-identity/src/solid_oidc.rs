use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oxigraph::io::{JsonLdProfileSet, RdfFormat, RdfParser};
use oxigraph::model::{Subject, Term};
use ring::digest::{digest, SHA256};
use ring::signature::{
    RsaPublicKeyComponents, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED,
    ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PSS_2048_8192_SHA256,
};
use serde::{Deserialize, Serialize};
use wolin_core::{Result, WolinError};

use crate::oidc::base64url_decode_segment;

pub const SOLID_OIDC_ISSUER_IRI: &str = "http://www.w3.org/ns/solid/terms#oidcIssuer";
pub const PIM_STORAGE_IRI: &str = "http://www.w3.org/ns/pim/space#storage";
pub const LDP_INBOX_IRI: &str = "http://www.w3.org/ns/ldp#inbox";

const MAX_WEBID_URI_LEN: usize = 2048;
const MAX_WEBID_PROFILE_BYTES: usize = 512 * 1024;
const MAX_DPOP_JWT_LEN: usize = 8192;
const MAX_DPOP_JTI_LEN: usize = 256;
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 5;
const DEFAULT_REPLAY_MAX_ENTRIES: usize = 8192;

const FORBIDDEN_JWK_PRIVATE_FIELDS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Parsed W3C Solid WebID Profile RDF document metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebIdProfile {
    pub webid: String,
    pub oidc_issuers: Vec<String>,
    pub storages: Vec<String>,
    pub inboxes: Vec<String>,
}

impl WebIdProfile {
    /// Parse a WebID Profile RDF document (`Turtle`, `JSON-LD`, or `N-Triples`) and extract
    /// `solid:oidcIssuer`, `pim:storage`, and `ldp:inbox` triples for `webid`.
    pub fn parse_rdf(
        webid: &str,
        document_iri: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<Self> {
        if body.len() > MAX_WEBID_PROFILE_BYTES {
            return Err(WolinError::Unauthenticated(
                "WebID Profile RDF document exceeds maximum allowed size".to_string(),
            ));
        }

        let rdf_format = match content_type {
            None => RdfFormat::Turtle,
            Some(raw_ct) => {
                let media = raw_ct
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase();
                match media.as_str() {
                    "" | "text/turtle" | "application/x-turtle" | "text/n3" => RdfFormat::Turtle,
                    "application/n-triples" | "text/plain" => RdfFormat::NTriples,
                    "application/ld+json" | "application/json" => RdfFormat::JsonLd {
                        profile: JsonLdProfileSet::empty(),
                    },
                    other => {
                        return Err(WolinError::Unauthenticated(format!(
                            "Unsupported WebID Profile Content-Type '{other}'"
                        )));
                    }
                }
            }
        };

        let parser = RdfParser::from_format(rdf_format)
            .without_named_graphs()
            .with_base_iri(document_iri)
            .map_err(|e| {
                WolinError::Unauthenticated(format!(
                    "Invalid WebID Profile base IRI '{document_iri}': {e}"
                ))
            })?
            .rename_blank_nodes();

        let mut oidc_issuers = Vec::new();
        let mut storages = Vec::new();
        let mut inboxes = Vec::new();
        let mut seen_iss = HashSet::new();
        let mut seen_storage = HashSet::new();
        let mut seen_inbox = HashSet::new();

        for quad_res in parser.for_slice(body) {
            let quad = quad_res.map_err(|e| {
                WolinError::Unauthenticated(format!("Malformed WebID Profile RDF payload: {e}"))
            })?;
            let Subject::NamedNode(ref subj_node) = quad.subject else {
                continue;
            };
            if subj_node.as_str() != webid {
                continue;
            }
            let Term::NamedNode(ref obj_node) = quad.object else {
                continue;
            };
            let obj_str = obj_node.as_str();
            if quad.predicate.as_str() == SOLID_OIDC_ISSUER_IRI {
                if seen_iss.insert(obj_str.to_string()) {
                    oidc_issuers.push(obj_str.to_string());
                }
            } else if quad.predicate.as_str() == PIM_STORAGE_IRI {
                if seen_storage.insert(obj_str.to_string()) {
                    storages.push(obj_str.to_string());
                }
            } else if quad.predicate.as_str() == LDP_INBOX_IRI
                && seen_inbox.insert(obj_str.to_string())
            {
                inboxes.push(obj_str.to_string());
            }
        }

        Ok(Self {
            webid: webid.to_string(),
            oidc_issuers,
            storages,
            inboxes,
        })
    }

    /// Verify W3C Solid-OIDC trust chain: `<webid> solid:oidcIssuer <expected_issuer>`.
    pub fn verify_oidc_issuer(&self, expected_issuer: &str) -> Result<()> {
        let trimmed = expected_issuer.trim();
        if trimmed.is_empty() {
            return Err(WolinError::Unauthenticated(
                "Solid-OIDC token issuer must not be empty".to_string(),
            ));
        }
        if self.oidc_issuers.iter().any(|iss| iss == trimmed) {
            Ok(())
        } else {
            Err(WolinError::Unauthenticated(format!(
                "Solid-OIDC trust chain verification failed: WebID '{}' does not authorize oidcIssuer '{trimmed}'",
                self.webid
            )))
        }
    }
}

/// Pluggable Solid-OIDC WebID Profile RDF dereferencer.
pub trait WebIdDereferencer: Send + Sync {
    fn dereference<'a>(
        &'a self,
        webid: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<WebIdProfile>> + Send + 'a>>;
}

/// Production-hardened HTTP(S) WebID Profile dereferencer with SSRF, redirect, timeout,
/// DNS-rebinding, and streaming payload size guards.
pub struct HttpWebIdDereferencer {
    allow_loopback_http: bool,
    timeout: Duration,
}

impl HttpWebIdDereferencer {
    /// Construct a production WebID dereferencer requiring `https://` and non-private global IPs.
    pub fn new() -> Result<Self> {
        Ok(Self {
            allow_loopback_http: false,
            timeout: Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS),
        })
    }

    /// Construct a loopback-capable dereferencer for isolated local integration tests (`http://127.0.0.1:<port>`).
    /// Non-loopback private/link-local/metadata IPs remain strictly blocked.
    pub fn new_allow_loopback_http() -> Result<Self> {
        Ok(Self {
            allow_loopback_http: true,
            timeout: Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS),
        })
    }

    async fn fetch_profile(&self, webid: &str) -> Result<WebIdProfile> {
        if webid.is_empty() || webid.len() > MAX_WEBID_URI_LEN {
            return Err(WolinError::Unauthenticated(
                "WebID URI is empty or exceeds maximum length".to_string(),
            ));
        }
        if webid
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
        {
            return Err(WolinError::Unauthenticated(
                "WebID URI contains invalid whitespace, backslash, or control characters"
                    .to_string(),
            ));
        }

        let doc_iri = webid.split('#').next().unwrap_or(webid);
        let parsed_url = reqwest::Url::parse(doc_iri).map_err(|e| {
            WolinError::Unauthenticated(format!("Malformed WebID URI '{webid}': {e}"))
        })?;

        if !parsed_url.username().is_empty() || parsed_url.password().is_some() {
            return Err(WolinError::Unauthenticated(
                "Userinfo credentials are forbidden in WebID URIs".to_string(),
            ));
        }
        if parsed_url.query().is_some() {
            return Err(WolinError::Unauthenticated(
                "Query strings are forbidden in Solid WebID Profile URIs".to_string(),
            ));
        }

        let scheme = parsed_url.scheme();
        if scheme != "https" && !(self.allow_loopback_http && scheme == "http") {
            return Err(WolinError::Unauthenticated(format!(
                "WebID dereferencing requires 'https://' scheme (got '{scheme}://')"
            )));
        }

        let host_str = parsed_url.host_str().ok_or_else(|| {
            WolinError::Unauthenticated("WebID URI missing host authority".to_string())
        })?;
        let host_lower = host_str.to_ascii_lowercase();
        if host_lower.ends_with(".internal")
            || host_lower.ends_with(".local")
            || host_lower.ends_with(".arpa")
        {
            return Err(WolinError::Unauthenticated(
                "Internal/reserved DNS suffix blocked in WebID dereferencing".to_string(),
            ));
        }

        let port = parsed_url.port_or_known_default().ok_or_else(|| {
            WolinError::Unauthenticated("WebID URI has unknown default port".to_string())
        })?;

        let resolved_addrs: Vec<SocketAddr> = match host_str
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
        {
            Ok(ip) => vec![SocketAddr::new(ip, port)],
            Err(_) => tokio::time::timeout(self.timeout, tokio::net::lookup_host((host_str, port)))
                .await
                .map_err(|_| {
                    WolinError::Unauthenticated("WebID DNS resolution timed out".to_string())
                })?
                .map_err(|e| {
                    WolinError::Unauthenticated(format!(
                        "WebID DNS resolution failed for '{host_str}': {e}"
                    ))
                })?
                .collect(),
        };

        if resolved_addrs.is_empty() {
            return Err(WolinError::Unauthenticated(
                "WebID host resolved to zero addresses".to_string(),
            ));
        }

        for sock_addr in &resolved_addrs {
            let ip = sock_addr.ip();
            if self.allow_loopback_http && ip.is_loopback() {
                continue;
            }
            if scheme == "http" {
                return Err(WolinError::Unauthenticated(
                    "Plain HTTP WebID dereferencing is restricted to loopback in test mode"
                        .to_string(),
                ));
            }
            if !is_public_global_ip(ip) {
                return Err(WolinError::Unauthenticated(format!(
                    "SSRF blocked: WebID host '{host_str}' resolved to non-public address"
                )));
            }
        }

        let mut client_builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(self.timeout)
            .connect_timeout(self.timeout);

        if host_str.trim_matches(['[', ']']).parse::<IpAddr>().is_err() {
            client_builder = client_builder.resolve_to_addrs(host_str, &resolved_addrs);
        }

        let client = client_builder.build().map_err(|e| {
            WolinError::Internal(format!("Failed to initialize WebID HTTP client: {e}"))
        })?;

        let mut resp = client
            .get(parsed_url)
            .header(
                reqwest::header::ACCEPT,
                "text/turtle, application/ld+json;q=0.9, application/n-triples;q=0.8",
            )
            .send()
            .await
            .map_err(|e| {
                WolinError::Unauthenticated(format!("Failed to dereference WebID Profile: {e}"))
            })?;

        if resp.status() != reqwest::StatusCode::OK {
            return Err(WolinError::Unauthenticated(format!(
                "WebID Profile dereference returned HTTP {}",
                resp.status().as_u16()
            )));
        }

        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|hv| hv.to_str().ok())
            .map(str::to_string);

        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| {
            WolinError::Unauthenticated(format!("Error reading WebID Profile response stream: {e}"))
        })? {
            if body.len().saturating_add(chunk.len()) > MAX_WEBID_PROFILE_BYTES {
                return Err(WolinError::Unauthenticated(
                    "WebID Profile response exceeded maximum allowed byte budget".to_string(),
                ));
            }
            body.extend_from_slice(&chunk);
        }

        WebIdProfile::parse_rdf(webid, doc_iri, content_type.as_deref(), &body)
    }
}

impl WebIdDereferencer for HttpWebIdDereferencer {
    fn dereference<'a>(
        &'a self,
        webid: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<WebIdProfile>> + Send + 'a>> {
        Box::pin(async move { self.fetch_profile(webid).await })
    }
}

fn is_public_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                return is_public_v4(mapped_v4);
            }
            let segs = v6.segments();
            // Reject loopback (::1), unspecified (::), multicast (ff00::/8),
            // unique local (fc00::/7), link-local (fe80::/10), documentation (2001:db8::/32)
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && (segs[0] & 0xfe00) != 0xfc00
                && (segs[0] & 0xffc0) != 0xfe80
                && !(segs[0] == 0x2001 && segs[1] == 0x0db8)
        }
    }
}

fn is_public_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    !v4.is_private()
        && !v4.is_loopback()
        && !v4.is_link_local()
        && !v4.is_broadcast()
        && !v4.is_documentation()
        && !v4.is_unspecified()
        && !v4.is_multicast()
        && o[0] != 0
        && !(o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000) // RFC 6598 CGNAT 100.64.0.0/10
        && !(o[0] == 198 && (o[1] == 18 || o[1] == 19)) // RFC 2544 benchmarking
        && o[0] < 240 // Reserved Class E
}

/// Validated RFC 9449 DPoP proof claims and verified public JWK thumbprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopProofClaims {
    pub jti: String,
    pub htm: String,
    pub htu: String,
    pub iat: i64,
    pub ath: Option<String>,
    pub jkt: String,
}

struct ReplayState {
    order: VecDeque<(String, i64)>,
    active: HashMap<String, i64>,
}

/// Bounded anti-replay cache for RFC 9449 DPoP `jti` identifiers scoped by JWK thumbprint `jkt`.
pub struct DpopReplayCache {
    max_entries: usize,
    inner: Mutex<ReplayState>,
}

impl Default for DpopReplayCache {
    fn default() -> Self {
        Self::new(DEFAULT_REPLAY_MAX_ENTRIES)
    }
}

impl DpopReplayCache {
    pub fn new(max_entries: usize) -> Self {
        let cap = max_entries.max(1);
        Self {
            max_entries: cap,
            inner: Mutex::new(ReplayState {
                order: VecDeque::new(),
                active: HashMap::new(),
            }),
        }
    }

    pub fn check_and_record(
        &self,
        jkt: &str,
        jti: &str,
        now_epoch_secs: i64,
        ttl_secs: i64,
    ) -> Result<()> {
        let composite_key = format!("{jkt}:{jti}");
        let expires_at = now_epoch_secs.saturating_add(ttl_secs.max(1));

        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        while let Some((front_key, exp)) = guard.order.front() {
            let expired_ts = *exp;
            if expired_ts <= now_epoch_secs {
                let expired_key = front_key.clone();
                guard.order.pop_front();
                if guard.active.get(&expired_key) == Some(&expired_ts) {
                    guard.active.remove(&expired_key);
                }
            } else {
                break;
            }
        }

        if let Some(&existing_exp) = guard.active.get(&composite_key) {
            if existing_exp > now_epoch_secs {
                return Err(WolinError::Unauthenticated(
                    "DPoP proof replay detected: duplicate 'jti'".to_string(),
                ));
            }
            guard.active.remove(&composite_key);
        }

        while guard.active.len() >= self.max_entries {
            let Some((oldest_key, oldest_exp)) = guard.order.pop_front() else {
                break;
            };
            if guard.active.get(&oldest_key) == Some(&oldest_exp) {
                guard.active.remove(&oldest_key);
            }
        }

        guard.active.insert(composite_key.clone(), expires_at);
        guard.order.push_back((composite_key, expires_at));
        Ok(())
    }
}

/// Request-bound validation parameters for RFC 9449 DPoP proof verification.
pub struct DpopValidationContext<'a> {
    pub expected_htm: &'a str,
    pub expected_htus: &'a [String],
    pub access_token: &'a str,
    pub now_epoch_secs: Option<i64>,
    pub max_iat_skew_secs: i64,
    pub replay_cache: Option<&'a DpopReplayCache>,
}

#[derive(Debug, Deserialize)]
struct DpopHeader {
    typ: String,
    alg: String,
    jwk: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct RawDpopPayload {
    jti: Option<String>,
    htm: Option<String>,
    htu: Option<String>,
    iat: Option<i64>,
    #[serde(default)]
    ath: Option<String>,
}

/// Cryptographically verify an RFC 9449 DPoP proof JWT against HTTP method, target URI,
/// freshness window, optional `ath` access-token hash, and optional `jti` anti-replay cache.
pub fn verify_dpop_proof(
    dpop_jwt: &str,
    ctx: &DpopValidationContext<'_>,
) -> Result<DpopProofClaims> {
    if dpop_jwt.is_empty() || dpop_jwt.len() > MAX_DPOP_JWT_LEN {
        return Err(WolinError::Unauthenticated(
            "DPoP proof JWT is empty or exceeds maximum allowed size".to_string(),
        ));
    }
    if dpop_jwt
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(WolinError::Unauthenticated(
            "DPoP proof JWT must not contain whitespace or control characters".to_string(),
        ));
    }

    let mut parts = dpop_jwt.split('.');
    let header_b64 = parts.next().unwrap_or_default();
    let payload_b64 = parts.next().unwrap_or_default();
    let sig_b64 = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || header_b64.is_empty()
        || payload_b64.is_empty()
        || sig_b64.is_empty()
    {
        return Err(WolinError::Unauthenticated(
            "Invalid compact DPoP JWT format".to_string(),
        ));
    }

    let header_bytes = base64url_decode_segment(header_b64)?;
    let header_val: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| WolinError::Unauthenticated(format!("Malformed DPoP JWT header JSON: {e}")))?;
    if header_val
        .as_object()
        .is_none_or(|obj| obj.contains_key("crit"))
    {
        return Err(WolinError::Unauthenticated(
            "Unsupported 'crit' extension in DPoP JWT header".to_string(),
        ));
    }

    let header: DpopHeader = serde_json::from_value(header_val).map_err(|e| {
        WolinError::Unauthenticated(format!("Missing required DPoP header fields: {e}"))
    })?;

    if !header.typ.trim().eq_ignore_ascii_case("dpop+jwt") {
        return Err(WolinError::Unauthenticated(format!(
            "Invalid DPoP header typ '{}': expected 'dpop+jwt'",
            header.typ
        )));
    }

    let sig_bytes = base64url_decode_segment(sig_b64)?;
    if sig_bytes.is_empty() {
        return Err(WolinError::Unauthenticated(
            "Empty DPoP signature rejected".to_string(),
        ));
    }

    let signing_input = format!("{header_b64}.{payload_b64}");
    verify_jwk_signature(
        header.alg.trim(),
        &header.jwk,
        signing_input.as_bytes(),
        &sig_bytes,
    )?;

    let jkt = compute_jwk_thumbprint_sha256(&header.jwk)?;

    let payload_bytes = base64url_decode_segment(payload_b64)?;
    let raw_payload: RawDpopPayload = serde_json::from_slice(&payload_bytes).map_err(|e| {
        WolinError::Unauthenticated(format!("Malformed DPoP JWT payload JSON: {e}"))
    })?;

    let jti = raw_payload
        .jti
        .ok_or_else(|| WolinError::Unauthenticated("Missing DPoP 'jti' claim".to_string()))?;
    if jti.trim().is_empty()
        || jti.len() > MAX_DPOP_JTI_LEN
        || jti.bytes().any(|b| b.is_ascii_control())
    {
        return Err(WolinError::Unauthenticated(
            "Invalid DPoP 'jti' claim".to_string(),
        ));
    }

    let htm = raw_payload
        .htm
        .ok_or_else(|| WolinError::Unauthenticated("Missing DPoP 'htm' claim".to_string()))?;
    if !htm.eq_ignore_ascii_case(ctx.expected_htm) {
        return Err(WolinError::Unauthenticated(format!(
            "DPoP 'htm' mismatch: expected '{}', got '{htm}'",
            ctx.expected_htm
        )));
    }

    let htu = raw_payload
        .htu
        .ok_or_else(|| WolinError::Unauthenticated("Missing DPoP 'htu' claim".to_string()))?;
    let normalized_proof_htu = normalize_htu(&htu)?;
    let htu_matched = ctx
        .expected_htus
        .iter()
        .any(|candidate| normalize_htu(candidate).is_ok_and(|norm| norm == normalized_proof_htu));
    if !htu_matched {
        return Err(WolinError::Unauthenticated(format!(
            "DPoP 'htu' mismatch: proof target '{htu}' does not match request URI"
        )));
    }

    let iat = raw_payload
        .iat
        .ok_or_else(|| WolinError::Unauthenticated("Missing DPoP 'iat' claim".to_string()))?;
    let now = match ctx.now_epoch_secs {
        Some(ts) => ts,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|e| WolinError::Internal(format!("System clock error: {e}")))?,
    };
    let skew = ctx.max_iat_skew_secs.max(1);
    if iat < now.saturating_sub(skew) || iat > now.saturating_add(skew) {
        return Err(WolinError::Unauthenticated(
            "DPoP proof 'iat' timestamp is outside the acceptable freshness window".to_string(),
        ));
    }

    if !ctx.access_token.is_empty() {
        let ath = raw_payload.ath.as_deref().ok_or_else(|| {
            WolinError::Unauthenticated(
                "DPoP proof missing required RFC 9449 'ath' access token hash".to_string(),
            )
        })?;
        let expected_ath = sha256_base64url(ctx.access_token.as_bytes());
        if ath != expected_ath {
            return Err(WolinError::Unauthenticated(
                "DPoP proof 'ath' hash does not match presented access token".to_string(),
            ));
        }
    } else if let Some(ref ath) = raw_payload.ath {
        if ath.trim().is_empty() {
            return Err(WolinError::Unauthenticated(
                "DPoP proof 'ath' claim must not be empty".to_string(),
            ));
        }
    }

    if let Some(cache) = ctx.replay_cache {
        cache.check_and_record(&jkt, &jti, now, skew.saturating_mul(2))?;
    }

    Ok(DpopProofClaims {
        jti,
        htm,
        htu,
        iat,
        ath: raw_payload.ath,
        jkt,
    })
}

fn verify_jwk_signature(
    alg: &str,
    jwk: &serde_json::Value,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<()> {
    let obj = jwk.as_object().ok_or_else(|| {
        WolinError::Unauthenticated("DPoP header 'jwk' must be a JSON object".to_string())
    })?;
    for priv_key in FORBIDDEN_JWK_PRIVATE_FIELDS {
        if obj.contains_key(*priv_key) {
            return Err(WolinError::Unauthenticated(
                "DPoP header 'jwk' must not contain private key material".to_string(),
            ));
        }
    }

    let kty = obj
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WolinError::Unauthenticated("DPoP JWK missing 'kty' string".to_string()))?;

    match (alg, kty) {
        ("ES256", "EC") => {
            let crv = obj.get("crv").and_then(|v| v.as_str()).unwrap_or_default();
            if crv != "P-256" {
                return Err(WolinError::Unauthenticated(
                    "ES256 DPoP JWK requires crv 'P-256'".to_string(),
                ));
            }
            let x = decode_jwk_coord(obj, "x", 32)?;
            let y = decode_jwk_coord(obj, "y", 32)?;
            let mut uncompressed = Vec::with_capacity(65);
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(&x);
            uncompressed.extend_from_slice(&y);
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &uncompressed)
                .verify(signing_input, signature)
                .map_err(|_| {
                    WolinError::Unauthenticated(
                        "DPoP ES256 cryptographic signature verification failed".to_string(),
                    )
                })
        }
        ("ES384", "EC") => {
            let crv = obj.get("crv").and_then(|v| v.as_str()).unwrap_or_default();
            if crv != "P-384" {
                return Err(WolinError::Unauthenticated(
                    "ES384 DPoP JWK requires crv 'P-384'".to_string(),
                ));
            }
            let x = decode_jwk_coord(obj, "x", 48)?;
            let y = decode_jwk_coord(obj, "y", 48)?;
            let mut uncompressed = Vec::with_capacity(97);
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(&x);
            uncompressed.extend_from_slice(&y);
            UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &uncompressed)
                .verify(signing_input, signature)
                .map_err(|_| {
                    WolinError::Unauthenticated(
                        "DPoP ES384 cryptographic signature verification failed".to_string(),
                    )
                })
        }
        ("EdDSA", "OKP") => {
            let crv = obj.get("crv").and_then(|v| v.as_str()).unwrap_or_default();
            if crv != "Ed25519" {
                return Err(WolinError::Unauthenticated(
                    "EdDSA DPoP JWK requires crv 'Ed25519'".to_string(),
                ));
            }
            let x = decode_jwk_coord(obj, "x", 32)?;
            UnparsedPublicKey::new(&ED25519, &x)
                .verify(signing_input, signature)
                .map_err(|_| {
                    WolinError::Unauthenticated(
                        "DPoP EdDSA cryptographic signature verification failed".to_string(),
                    )
                })
        }
        ("RS256" | "PS256", "RSA") => {
            let n_b64 = obj.get("n").and_then(|v| v.as_str()).ok_or_else(|| {
                WolinError::Unauthenticated("RSA DPoP JWK missing 'n'".to_string())
            })?;
            let e_b64 = obj.get("e").and_then(|v| v.as_str()).ok_or_else(|| {
                WolinError::Unauthenticated("RSA DPoP JWK missing 'e'".to_string())
            })?;
            let n = base64url_decode_segment(n_b64)?;
            let e = base64url_decode_segment(e_b64)?;
            if n.len() < 256 || e.is_empty() || n[0] == 0 || e[0] == 0 {
                return Err(WolinError::Unauthenticated(
                    "Invalid or undersized RSA modulus/exponent in DPoP JWK".to_string(),
                ));
            }
            let rsa_pk = RsaPublicKeyComponents { n: &n, e: &e };
            let params = if alg == "PS256" {
                &RSA_PSS_2048_8192_SHA256
            } else {
                &RSA_PKCS1_2048_8192_SHA256
            };
            rsa_pk
                .verify(params, signing_input, signature)
                .map_err(|_| {
                    WolinError::Unauthenticated(
                        "DPoP RSA cryptographic signature verification failed".to_string(),
                    )
                })
        }
        _ => Err(WolinError::Unauthenticated(format!(
            "Unsupported or mismatched DPoP alg '{alg}' and JWK kty '{kty}'"
        ))),
    }
}

fn decode_jwk_coord(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    expected_len: usize,
) -> Result<Vec<u8>> {
    let b64 = obj.get(field).and_then(|v| v.as_str()).ok_or_else(|| {
        WolinError::Unauthenticated(format!("DPoP JWK missing '{field}' coordinate"))
    })?;
    let bytes = base64url_decode_segment(b64)?;
    if bytes.len() != expected_len {
        return Err(WolinError::Unauthenticated(format!(
            "DPoP JWK coordinate '{field}' has invalid byte length {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn normalize_htu(raw: &str) -> Result<String> {
    if raw.is_empty()
        || raw.len() > MAX_WEBID_URI_LEN
        || raw
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || matches!(b, b'?' | b'#'))
    {
        return Err(WolinError::Unauthenticated(
            "DPoP 'htu' must be a valid HTTP(S) URI without query or fragment".to_string(),
        ));
    }
    let parsed = reqwest::Url::parse(raw).map_err(|_| {
        WolinError::Unauthenticated("Malformed URI in DPoP 'htu' claim".to_string())
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(WolinError::Unauthenticated(
            "Disallowed scheme, userinfo, query, or fragment in DPoP 'htu'".to_string(),
        ));
    }
    let host = parsed.host_str().ok_or_else(|| {
        WolinError::Unauthenticated("Missing host in DPoP 'htu' claim".to_string())
    })?;
    let authority = match parsed.port() {
        Some(p) => format!("{}:{p}", host.to_ascii_lowercase()),
        None => host.to_ascii_lowercase(),
    };
    Ok(format!(
        "{}://{authority}{}",
        parsed.scheme(),
        parsed.path()
    ))
}

/// Compute an RFC 7638 §3.1 canonical SHA-256 JWK Thumbprint (unpadded Base64URL).
pub fn compute_jwk_thumbprint_sha256(jwk: &serde_json::Value) -> Result<String> {
    let obj = jwk
        .as_object()
        .ok_or_else(|| WolinError::InvalidFormat("JWK must be a JSON object".to_string()))?;
    for priv_key in FORBIDDEN_JWK_PRIVATE_FIELDS {
        if obj.contains_key(*priv_key) {
            return Err(WolinError::InvalidFormat(
                "Private JWK parameters cannot be included in public JWK".to_string(),
            ));
        }
    }

    let kty = obj
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WolinError::InvalidFormat("JWK missing 'kty'".to_string()))?;

    let canonical_json = match kty {
        "EC" => {
            let crv = req_jwk_str(obj, "crv")?;
            let x = req_jwk_str(obj, "x")?;
            let y = req_jwk_str(obj, "y")?;
            let _ = base64url_decode_segment(x)?;
            let _ = base64url_decode_segment(y)?;
            format!(
                "{{\"crv\":{},\"kty\":\"EC\",\"x\":{},\"y\":{}}}",
                json_escape(crv),
                json_escape(x),
                json_escape(y)
            )
        }
        "OKP" => {
            let crv = req_jwk_str(obj, "crv")?;
            let x = req_jwk_str(obj, "x")?;
            let _ = base64url_decode_segment(x)?;
            format!(
                "{{\"crv\":{},\"kty\":\"OKP\",\"x\":{}}}",
                json_escape(crv),
                json_escape(x)
            )
        }
        "RSA" => {
            let e = req_jwk_str(obj, "e")?;
            let n = req_jwk_str(obj, "n")?;
            let _ = base64url_decode_segment(e)?;
            let _ = base64url_decode_segment(n)?;
            format!(
                "{{\"e\":{},\"kty\":\"RSA\",\"n\":{}}}",
                json_escape(e),
                json_escape(n)
            )
        }
        other => {
            return Err(WolinError::InvalidFormat(format!(
                "Unsupported JWK kty '{other}' for RFC 7638 thumbprint"
            )));
        }
    };

    Ok(sha256_base64url(canonical_json.as_bytes()))
}

fn req_jwk_str<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str> {
    let val = obj
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| WolinError::InvalidFormat(format!("JWK missing required '{key}' string")))?;
    if val.is_empty() {
        return Err(WolinError::InvalidFormat(format!(
            "JWK field '{key}' must not be empty"
        )));
    }
    Ok(val)
}

fn json_escape(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// Compute SHA-256 digest encoded as unpadded RFC 4648 §5 Base64URL.
pub fn sha256_base64url(data: &[u8]) -> String {
    let hash = digest(&SHA256, data);
    base64url_encode(hash.as_ref())
}

fn base64url_encode(bytes: &[u8]) -> String {
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

#[allow(dead_code)]
const _: Ipv6Addr = Ipv6Addr::LOCALHOST;

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;

    #[test]
    fn unit_eddsa_dpop_proof_private_jwk_rejection_and_bounded_replay_cache() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let x_b64 = base64url_encode(kp.public_key().as_ref());

        // Reject JWK containing private key field "d"
        let leaked_jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x_b64,
            "d": x_b64
        });
        assert!(compute_jwk_thumbprint_sha256(&leaked_jwk).is_err());

        let pub_jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x_b64
        });
        let jkt = compute_jwk_thumbprint_sha256(&pub_jwk).unwrap();

        let access_tok = "sample-access-token";
        let hdr = base64url_encode(
            json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": pub_jwk})
                .to_string()
                .as_bytes(),
        );
        let pay = base64url_encode(
            json!({
                "jti": "jti-1",
                "htm": "PUT",
                "htu": "https://alice.wolin.cloud/private/doc.ttl",
                "iat": 1_763_500_000_i64,
                "ath": sha256_base64url(access_tok.as_bytes())
            })
            .to_string()
            .as_bytes(),
        );
        let input = format!("{hdr}.{pay}");
        let sig = base64url_encode(kp.sign(input.as_bytes()).as_ref());
        let dpop_jwt = format!("{input}.{sig}");

        let cache = DpopReplayCache::new(2);
        let expected_htus = vec!["https://alice.wolin.cloud/private/doc.ttl".to_string()];
        let ctx = DpopValidationContext {
            expected_htm: "PUT",
            expected_htus: &expected_htus,
            access_token: access_tok,
            now_epoch_secs: Some(1_763_500_005),
            max_iat_skew_secs: 60,
            replay_cache: Some(&cache),
        };

        let verified = verify_dpop_proof(&dpop_jwt, &ctx).unwrap();
        assert_eq!(verified.jkt, jkt);
        // Immediate replay fails
        assert!(verify_dpop_proof(&dpop_jwt, &ctx).is_err());

        // Missing 'ath' when access_token is present MUST fail
        let pay_no_ath = base64url_encode(
            json!({
                "jti": "jti-no-ath",
                "htm": "PUT",
                "htu": "https://alice.wolin.cloud/private/doc.ttl",
                "iat": 1_763_500_000_i64
            })
            .to_string()
            .as_bytes(),
        );
        let in2 = format!("{hdr}.{pay_no_ath}");
        let sig2 = base64url_encode(kp.sign(in2.as_bytes()).as_ref());
        assert!(verify_dpop_proof(&format!("{in2}.{sig2}"), &ctx).is_err());
    }

    #[test]
    fn unit_ssrf_ip_classifier_blocks_private_cgnat_metadata_and_mapped_ipv6() {
        for blocked in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            let ip: IpAddr = blocked.parse().unwrap();
            assert!(!is_public_global_ip(ip), "expected {blocked} to be blocked");
        }
        let pub_ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(is_public_global_ip(pub_ip));
    }
}
