use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use wolin_core::{Principal, Result, WebId, WolinError};

use crate::did::DidResolver;

const MAX_JWT_LEN: usize = 16_384;
const MAX_SCOPES: usize = 128;
const ALLOWED_ASYMMETRIC_ALGS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
];

/// Multi-part country-code second-level domains requiring 3 labels for an organizational root.
const MULTIPART_CCTLDS: &[&str] = &[
    "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr", "re.kr", "pe.kr", "co.uk", "org.uk", "ac.uk",
    "gov.uk", "me.uk", "net.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.jp",
    "ne.jp", "or.jp", "ac.jp", "go.jp", "com.br", "org.br", "com.cn", "org.cn", "com.tw", "com.sg",
    "com.hk", "co.nz", "co.in", "co.za",
];

/// Multi-tenant cloud & IdP hosting suffixes (including regional subdomains like `*.us1.zitadel.cloud`)
/// where cross-host WebID trust MUST NOT be inferred (only exact `host_a == host_b` is allowed).
const SHARED_MULTI_TENANT_CLOUD_SUFFIXES: &[&str] = &[
    "zitadel.cloud",
    "auth0.com",
    "okta.com",
    "oktapreview.com",
    "onmicrosoft.com",
    "github.io",
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "herokuapp.com",
    "fly.dev",
    "onrender.com",
    "amazonaws.com",
];

/// RFC 8693 OAuth 2.0 Token Exchange `act` (Actor) claim for single-hop agent delegation.
/// Nested `act` chains are rejected fail-closed to prevent multi-hop confused-deputy escalation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorClaim {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<serde_json::Value>,
}

/// RFC 7800 / RFC 9449 Proof-of-Possession `cnf` confirmation claim (`{"jkt": "..."}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmationClaim {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
}

/// Validated / normalized OIDC & ZITADEL token claims
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub scopes: Vec<String>,
    pub webid: Option<String>,
    pub azp: Option<String>,
    pub act: Option<ActorClaim>,
    pub delegated_by: Option<String>,
    pub org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<ConfirmationClaim>,
}

/// Validation parameters for enterprise OIDC / ZITADEL tokens
#[derive(Debug, Clone)]
pub struct OidcValidationOptions {
    pub expected_issuer: String,
    pub expected_audience: Option<String>,
    pub clock_skew_leeway_secs: i64,
    pub now_epoch_secs: Option<i64>,
}

impl OidcValidationOptions {
    pub fn new(expected_issuer: impl Into<String>) -> Self {
        Self {
            expected_issuer: expected_issuer.into(),
            expected_audience: None,
            clock_skew_leeway_secs: 0,
            now_epoch_secs: None,
        }
    }

    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audience = Some(audience.into());
        self
    }

    pub fn with_now(mut self, now_epoch_secs: i64) -> Self {
        self.now_epoch_secs = Some(now_epoch_secs);
        self
    }

    pub fn with_leeway(mut self, secs: i64) -> Self {
        self.clock_skew_leeway_secs = secs;
        self
    }
}

/// Pluggable cryptographic JWT signature verifier (JWKS / Ed25519 / RSA / ECDSA / DPoP)
pub trait JwtSignatureVerifier: Send + Sync {
    fn verify(
        &self,
        alg: &str,
        kid: Option<&str>,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<()>;
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

struct JwtEnvelope<'a> {
    header: JwtHeader,
    header_b64: &'a str,
    payload_b64: &'a str,
    signature: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawAudience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Deserialize)]
struct RawOidcClaims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<RawAudience>,
    exp: Option<i64>,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    nbf: Option<i64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    webid: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    act: Option<ActorClaim>,
    #[serde(default)]
    delegated_by: Option<String>,
    #[serde(default, rename = "urn:zitadel:iam:org:id")]
    org_id: Option<String>,
    #[serde(default)]
    cnf: Option<ConfirmationClaim>,
}

pub struct OidcValidator;

impl OidcValidator {
    /// Validate compact JWT envelope & OIDC claims for pre-authenticated ingress/gateway flows.
    /// For untrusted bearer tokens requiring JWS cryptographic verification, call
    /// [`OidcValidator::validate_with_verifier`].
    pub fn validate_claims(token: &str, issuer: &str) -> Result<Principal> {
        let options = OidcValidationOptions::new(issuer);
        Self::validate_with_options(token, &options)
    }

    /// Validate compact JWT envelope & OIDC claims against `OidcValidationOptions`.
    /// For untrusted bearer tokens requiring JWS cryptographic verification, call
    /// [`OidcValidator::validate_with_verifier`].
    pub fn validate_with_options(
        token: &str,
        options: &OidcValidationOptions,
    ) -> Result<Principal> {
        let envelope = Self::decode_jwt_envelope(token)?;
        let claims = Self::decode_jwt_payload(envelope.payload_b64)?;
        reject_dpop_bound_token_without_proof(&claims)?;
        Self::validate_parsed_claims(&claims, options)
    }

    /// Cryptographically verify the JWT signature FIRST (before untrusted payload JSON parsing),
    /// then validate OIDC claims and map to `Principal`.
    pub fn validate_with_verifier(
        token: &str,
        options: &OidcValidationOptions,
        verifier: &dyn JwtSignatureVerifier,
    ) -> Result<Principal> {
        let envelope = Self::decode_jwt_envelope(token)?;
        let signing_input = format!("{}.{}", envelope.header_b64, envelope.payload_b64);
        verifier.verify(
            &envelope.header.alg,
            envelope.header.kid.as_deref(),
            signing_input.as_bytes(),
            &envelope.signature,
        )?;
        let claims = Self::decode_jwt_payload(envelope.payload_b64)?;
        reject_dpop_bound_token_without_proof(&claims)?;
        Self::validate_parsed_claims(&claims, options)
    }

    /// Parse a compact JWT into normalized `OidcClaims` after structural & header checks.
    pub fn parse_jwt_claims(token: &str) -> Result<OidcClaims> {
        let envelope = Self::decode_jwt_envelope(token)?;
        Self::decode_jwt_payload(envelope.payload_b64)
    }

    /// Validate a Solid-OIDC Bearer or DPoP token, performing external WebID Profile RDF
    /// dereferencing and `<webid> solid:oidcIssuer <iss>` verification when required.
    pub async fn validate_solid_oidc(
        token: &str,
        options: &OidcValidationOptions,
        verifier: Option<&dyn JwtSignatureVerifier>,
        dereferencer: Option<&dyn crate::solid_oidc::WebIdDereferencer>,
        dpop_proof_and_ctx: Option<(&str, &crate::solid_oidc::DpopValidationContext<'_>)>,
    ) -> Result<Principal> {
        let envelope = Self::decode_jwt_envelope(token)?;
        if let Some(v) = verifier {
            let signing_input = format!("{}.{}", envelope.header_b64, envelope.payload_b64);
            v.verify(
                &envelope.header.alg,
                envelope.header.kid.as_deref(),
                signing_input.as_bytes(),
                &envelope.signature,
            )?;
        }

        let claims = Self::decode_jwt_payload(envelope.payload_b64)?;

        match dpop_proof_and_ctx {
            Some((dpop_jwt, dpop_ctx)) => {
                let proof = crate::solid_oidc::verify_dpop_proof(dpop_jwt, dpop_ctx)?;
                let expected_jkt = claims
                    .cnf
                    .as_ref()
                    .and_then(|c| c.jkt.as_deref())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        WolinError::Unauthenticated(
                            "DPoP access token missing required 'cnf.jkt' key-binding claim"
                                .to_string(),
                        )
                    })?;
                if expected_jkt != proof.jkt {
                    return Err(WolinError::Unauthenticated(
                        "DPoP proof JWK thumbprint does not match token 'cnf.jkt' claim"
                            .to_string(),
                    ));
                }
            }
            None => {
                reject_dpop_bound_token_without_proof(&claims)?;
            }
        }

        // Fast path: local configured OIDC issuer with same-org WebID or DID principal.
        if claims.iss == options.expected_issuer.trim()
            && let Ok(local_principal) = Self::validate_parsed_claims(&claims, options)
        {
            return Ok(local_principal);
        }

        // Federated Solid-OIDC path: validate core claims + dereference WebID RDF Profile.
        let Some(deref) = dereferencer else {
            return Self::validate_parsed_claims(&claims, options);
        };

        validate_solid_oidc_temporal_and_aud_claims(&claims, options)?;

        if !is_valid_solid_issuer_uri(&claims.iss) {
            return Err(WolinError::Unauthenticated(
                "Solid-OIDC 'iss' claim must be a valid HTTP(S) URI without userinfo, query, or fragment"
                    .to_string(),
            ));
        }

        if let Some(ref act) = claims.act
            && act.act.is_some()
        {
            return Err(WolinError::Unauthenticated(
                "Nested multi-hop RFC 8693 'act' chains are rejected".to_string(),
            ));
        }

        let raw_webid = if let Some(ref delegator) = claims.delegated_by {
            delegator.trim()
        } else if let Some(ref explicit_webid) = claims.webid {
            explicit_webid.trim()
        } else {
            let sub_trimmed = claims.sub.trim();
            if sub_trimmed.starts_with("https://") || sub_trimmed.starts_with("http://") {
                sub_trimmed
            } else {
                return Err(WolinError::Unauthenticated(
                    "External Solid-OIDC token missing dereferenceable HTTP(S) 'webid' claim"
                        .to_string(),
                ));
            }
        };

        if !(raw_webid.starts_with("https://") || raw_webid.starts_with("http://")) {
            return Err(WolinError::Unauthenticated(
                "External Solid-OIDC 'webid' claim must be an HTTP(S) URI".to_string(),
            ));
        }

        let profile = deref.dereference(raw_webid).await?;
        profile.verify_oidc_issuer(&claims.iss)?;

        if claims.delegated_by.is_some() || claims.act.is_some() {
            let raw_agent = match claims.act {
                Some(ref act) => act.sub.trim(),
                None => claims.sub.trim(),
            };
            if raw_agent.is_empty() {
                return Err(WolinError::Unauthenticated(
                    "Delegated agent identifier cannot be empty".to_string(),
                ));
            }
            let agent_id = canonicalize_did_if_did(raw_agent)?;
            Ok(Principal::Agent {
                agent_id,
                delegated_by: WebId(raw_webid.to_string()),
                scope: claims.scopes.clone(),
            })
        } else {
            Ok(Principal::User {
                webid: WebId(raw_webid.to_string()),
                issuer: claims.iss.clone(),
            })
        }
    }

    /// Validate pre-parsed `OidcClaims` and map to `Principal::User` or `Principal::Agent`.
    pub fn validate_parsed_claims(
        claims: &OidcClaims,
        options: &OidcValidationOptions,
    ) -> Result<Principal> {
        if options.clock_skew_leeway_secs < 0 {
            return Err(WolinError::InvalidFormat(
                "Clock skew leeway must be non-negative".to_string(),
            ));
        }

        let expected_iss = options.expected_issuer.trim();
        if expected_iss.is_empty() {
            return Err(WolinError::Unauthenticated(
                "Expected OIDC issuer must not be empty".to_string(),
            ));
        }
        if claims.iss.trim().is_empty() || claims.iss != expected_iss {
            return Err(WolinError::Unauthenticated(format!(
                "OIDC issuer mismatch: expected '{expected_iss}', got '{}'",
                claims.iss
            )));
        }

        if claims.sub.trim().is_empty() {
            return Err(WolinError::Unauthenticated(
                "OIDC subject (sub) claim must not be empty".to_string(),
            ));
        }

        if claims.aud.is_empty() || claims.aud.iter().any(|a| a.trim().is_empty()) {
            return Err(WolinError::Unauthenticated(
                "OIDC audience (aud) claim must be non-empty".to_string(),
            ));
        }
        if let Some(ref expected_aud) = options.expected_audience
            && !claims.aud.iter().any(|a| a == expected_aud)
        {
            return Err(WolinError::Unauthenticated(format!(
                "OIDC audience mismatch: expected '{expected_aud}'"
            )));
        }

        let now = match options.now_epoch_secs {
            Some(ts) => ts,
            None => current_epoch_secs()?,
        };
        let leeway = options.clock_skew_leeway_secs;

        if claims.exp <= 0 || now >= claims.exp.saturating_add(leeway) {
            return Err(WolinError::Unauthenticated(
                "OIDC token has expired".to_string(),
            ));
        }

        if let Some(nbf) = claims.nbf
            && now.saturating_add(leeway) < nbf
        {
            return Err(WolinError::Unauthenticated(
                "OIDC token is not yet valid (nbf)".to_string(),
            ));
        }

        if let Some(iat) = claims.iat {
            if claims.exp <= iat {
                return Err(WolinError::Unauthenticated(
                    "OIDC token expiration (exp) must be greater than issued-at (iat)".to_string(),
                ));
            }
            if iat > now.saturating_add(leeway) {
                return Err(WolinError::Unauthenticated(
                    "OIDC token issued-at (iat) is in the future".to_string(),
                ));
            }
        }

        map_claims_to_principal(claims)
    }

    fn decode_jwt_envelope(token: &str) -> Result<JwtEnvelope<'_>> {
        if token.is_empty() || token.len() > MAX_JWT_LEN {
            return Err(WolinError::Unauthenticated(
                "JWT token empty or exceeds maximum allowed size".to_string(),
            ));
        }
        if token
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(WolinError::Unauthenticated(
                "JWT token must not contain whitespace or control characters".to_string(),
            ));
        }

        let mut parts = token.split('.');
        let header_b64 = parts.next().unwrap_or_default();
        let payload_b64 = parts.next().unwrap_or_default();
        let sig_b64 = parts.next().unwrap_or_default();

        if parts.next().is_some()
            || header_b64.is_empty()
            || payload_b64.is_empty()
            || sig_b64.is_empty()
        {
            return Err(WolinError::Unauthenticated(
                "Invalid compact JWT format: expected non-empty header.payload.signature"
                    .to_string(),
            ));
        }

        let header_bytes = base64url_decode(header_b64)?;
        let header_val: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| WolinError::Unauthenticated(format!("Invalid JWT header JSON: {e}")))?;

        // RFC 7515 §4.1.11: Reject ANY `crit` key presence (including `[]` and `null`).
        if header_val
            .as_object()
            .is_none_or(|obj| obj.contains_key("crit"))
        {
            return Err(WolinError::Unauthenticated(
                "Unsupported or malformed critical ('crit') JWT header extension".to_string(),
            ));
        }

        let header: JwtHeader = serde_json::from_value(header_val)
            .map_err(|e| WolinError::Unauthenticated(format!("Invalid JWT header fields: {e}")))?;

        let alg_trimmed = header.alg.trim();
        if !ALLOWED_ASYMMETRIC_ALGS.contains(&alg_trimmed) {
            return Err(WolinError::Unauthenticated(format!(
                "Disallowed or insecure JWT alg '{alg_trimmed}': only asymmetric OIDC algorithms permitted"
            )));
        }

        let signature = base64url_decode(sig_b64)?;
        if signature.is_empty() {
            return Err(WolinError::Unauthenticated(
                "Empty JWT signature rejected".to_string(),
            ));
        }

        Ok(JwtEnvelope {
            header,
            header_b64,
            payload_b64,
            signature,
        })
    }

    fn decode_jwt_payload(payload_b64: &str) -> Result<OidcClaims> {
        let payload_bytes = base64url_decode(payload_b64)?;
        let raw_claims: RawOidcClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| WolinError::Unauthenticated(format!("Invalid JWT claims JSON: {e}")))?;
        normalize_raw_claims(raw_claims)
    }
}

fn normalize_raw_claims(raw: RawOidcClaims) -> Result<OidcClaims> {
    let iss = raw.iss.ok_or_else(|| {
        WolinError::Unauthenticated("Missing required OIDC 'iss' claim".to_string())
    })?;
    let sub = raw.sub.ok_or_else(|| {
        WolinError::Unauthenticated("Missing required OIDC 'sub' claim".to_string())
    })?;
    let exp = raw.exp.ok_or_else(|| {
        WolinError::Unauthenticated("Missing required OIDC 'exp' claim".to_string())
    })?;

    let aud = match raw.aud {
        Some(RawAudience::Single(s)) => vec![s],
        Some(RawAudience::Multiple(v)) => v,
        None => {
            return Err(WolinError::Unauthenticated(
                "Missing required OIDC 'aud' claim".to_string(),
            ));
        }
    };

    let mut seen: HashSet<String> = HashSet::new();
    let mut scopes: Vec<String> = Vec::new();

    if let Some(scope_str) = raw.scope {
        for item in scope_str.split_whitespace() {
            if !item.is_empty() {
                if scopes.len() >= MAX_SCOPES {
                    return Err(WolinError::Unauthenticated(format!(
                        "OIDC scopes exceed maximum allowed count ({MAX_SCOPES})"
                    )));
                }
                if seen.insert(item.to_string()) {
                    scopes.push(item.to_string());
                }
            }
        }
    }
    if let Some(scope_vec) = raw.scopes {
        if scope_vec.len() > MAX_SCOPES {
            return Err(WolinError::Unauthenticated(format!(
                "OIDC scopes array exceeds maximum allowed count ({MAX_SCOPES})"
            )));
        }
        for item in scope_vec {
            let trimmed = item.trim();
            if !trimmed.is_empty() {
                if scopes.len() >= MAX_SCOPES {
                    return Err(WolinError::Unauthenticated(format!(
                        "OIDC scopes exceed maximum allowed count ({MAX_SCOPES})"
                    )));
                }
                if seen.insert(trimmed.to_string()) {
                    scopes.push(trimmed.to_string());
                }
            }
        }
    }

    Ok(OidcClaims {
        iss,
        sub,
        aud,
        exp,
        iat: raw.iat,
        nbf: raw.nbf,
        scopes,
        webid: raw.webid,
        azp: raw.azp.or(raw.client_id),
        act: raw.act,
        delegated_by: raw.delegated_by,
        org_id: raw.org_id,
        cnf: raw.cnf,
    })
}

fn canonicalize_did_if_did(id: &str) -> Result<String> {
    if id.starts_with("did:") {
        let parsed = DidResolver::parse(id).map_err(|e| {
            WolinError::Unauthenticated(format!("Invalid DID inside OIDC claim '{id}': {e}"))
        })?;
        Ok(parsed.canonical_did)
    } else {
        Ok(id.to_string())
    }
}

fn map_claims_to_principal(claims: &OidcClaims) -> Result<Principal> {
    if let Some(ref act) = claims.act
        && act.act.is_some()
    {
        return Err(WolinError::Unauthenticated(
            "Nested multi-hop RFC 8693 'act' chains are rejected".to_string(),
        ));
    }

    let canonical_sub = canonicalize_did_if_did(claims.sub.trim())?;

    if let Some(ref delegator) = claims.delegated_by {
        let delegator_trimmed = delegator.trim();
        if delegator_trimmed.is_empty() {
            return Err(WolinError::Unauthenticated(
                "OIDC 'delegated_by' claim cannot be empty".to_string(),
            ));
        }
        let canonical_delegator = canonicalize_did_if_did(delegator_trimmed)?;
        verify_claim_uri_authority_bound_to_issuer(
            &claims.iss,
            &canonical_sub,
            &canonical_delegator,
        )?;

        let raw_agent = match claims.act {
            Some(ref act) => act.sub.trim(),
            None => claims.sub.trim(),
        };
        if raw_agent.is_empty() {
            return Err(WolinError::Unauthenticated(
                "Delegated agent identifier cannot be empty".to_string(),
            ));
        }
        let agent_id = canonicalize_did_if_did(raw_agent)?;

        return Ok(Principal::Agent {
            agent_id,
            delegated_by: WebId(canonical_delegator),
            scope: claims.scopes.clone(),
        });
    }

    if let Some(ref act) = claims.act {
        let raw_agent = act.sub.trim();
        if raw_agent.is_empty() {
            return Err(WolinError::Unauthenticated(
                "OIDC actor ('act.sub') claim cannot be empty".to_string(),
            ));
        }
        let agent_id = canonicalize_did_if_did(raw_agent)?;
        let delegator_webid =
            resolve_user_webid(&claims.iss, &canonical_sub, claims.webid.as_deref())?;
        return Ok(Principal::Agent {
            agent_id,
            delegated_by: delegator_webid,
            scope: claims.scopes.clone(),
        });
    }

    let webid = resolve_user_webid(&claims.iss, &canonical_sub, claims.webid.as_deref())?;
    Ok(Principal::User {
        webid,
        issuer: claims.iss.clone(),
    })
}

fn resolve_user_webid(iss: &str, canonical_sub: &str, webid_claim: Option<&str>) -> Result<WebId> {
    if let Some(explicit) = webid_claim {
        let trimmed = explicit.trim();
        if trimmed.is_empty() {
            return Err(WolinError::Unauthenticated(
                "OIDC 'webid' claim cannot be empty when present".to_string(),
            ));
        }
        let canonical_webid = canonicalize_did_if_did(trimmed)?;
        verify_claim_uri_authority_bound_to_issuer(iss, canonical_sub, &canonical_webid)?;
        return Ok(WebId(canonical_webid));
    }

    if canonical_sub.starts_with("did:key:") || canonical_sub.starts_with("did:nostr:") {
        Ok(WebId(canonical_sub.to_string()))
    } else if canonical_sub.starts_with("did:web:")
        || canonical_sub.starts_with("https://")
        || canonical_sub.starts_with("http://")
    {
        verify_claim_uri_authority_bound_to_issuer(iss, canonical_sub, canonical_sub)?;
        Ok(WebId(canonical_sub.to_string()))
    } else {
        Ok(WebId(format!("{iss}#{canonical_sub}")))
    }
}

/// Prevent Cross-IdP WebID/Delegator spoofing:
/// - `did:key` / `did:nostr` in `webid`/`delegated_by` is only valid if it equals the authenticated `sub`.
/// - `did:web` / `http(s)://` URIs must strictly reject `userinfo@host` authority confusion and
///   share the same private organizational trust domain as `iss` (never colliding on `co.kr`,
///   `co.uk`, `zitadel.cloud`, `auth0.com`, etc.).
fn verify_claim_uri_authority_bound_to_issuer(
    iss: &str,
    canonical_sub: &str,
    asserted_id: &str,
) -> Result<()> {
    if asserted_id.starts_with("did:key:") || asserted_id.starts_with("did:nostr:") {
        if asserted_id == canonical_sub {
            return Ok(());
        }
        return Err(WolinError::Unauthenticated(
            "OIDC claim cannot assert an unbound sovereign did:key or did:nostr principal"
                .to_string(),
        ));
    }

    let iss_host = extract_strict_http_host(iss).ok_or_else(|| {
        WolinError::Unauthenticated("OIDC issuer must be a valid HTTP(S) origin URI".to_string())
    })?;

    let claim_host = if let Some(rest) = asserted_id.strip_prefix("did:web:") {
        let raw_seg = rest.split([':', '#']).next().unwrap_or_default();
        let host_only = raw_seg
            .to_ascii_lowercase()
            .split("%3a")
            .next()
            .unwrap_or_default()
            .to_string();
        if !is_valid_strict_hostname(&host_only) {
            return Err(WolinError::Unauthenticated(
                "Malformed did:web hostname in OIDC claim".to_string(),
            ));
        }
        host_only
    } else if asserted_id.starts_with("https://") || asserted_id.starts_with("http://") {
        extract_strict_http_host(asserted_id).ok_or_else(|| {
            WolinError::Unauthenticated(
                "Malformed or userinfo-spoofed HTTP(S) WebID URI in OIDC claim".to_string(),
            )
        })?
    } else {
        return Err(WolinError::Unauthenticated(
            "Asserted WebID/delegator must be a valid HTTP(S) or DID URI".to_string(),
        ));
    };

    if !same_org_trust_domain(&iss_host, &claim_host) {
        return Err(WolinError::Unauthenticated(format!(
            "Cross-IdP WebID spoofing blocked: claim host '{claim_host}' not bound to issuer '{iss_host}'"
        )));
    }
    Ok(())
}

fn extract_strict_http_host(uri: &str) -> Option<String> {
    if uri
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
    {
        return None;
    }
    let rest = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    // Reject RFC 3986 `userinfo@host` authority confusion and percent-encoded host tricks
    if authority.is_empty() || authority.contains('@') || authority.contains('%') {
        return None;
    }

    let host = match authority.split_once(':') {
        Some((h, port_str)) => {
            if port_str.is_empty()
                || port_str.len() > 5
                || port_str.starts_with('0')
                || !port_str.bytes().all(|b| b.is_ascii_digit())
                || port_str.parse::<u16>().is_err()
            {
                return None;
            }
            h.to_ascii_lowercase()
        }
        None => authority.to_ascii_lowercase(),
    };

    if is_valid_strict_hostname(&host) {
        Some(host)
    } else {
        None
    }
}

fn is_valid_strict_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    if host == "localhost" {
        return true;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

fn same_org_trust_domain(host_a: &str, host_b: &str) -> bool {
    if host_a == host_b {
        return true;
    }
    match (org_root_domain(host_a), org_root_domain(host_b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn org_root_domain(host: &str) -> Option<String> {
    if host == "localhost" {
        return Some("localhost".to_string());
    }
    for cloud_suffix in SHARED_MULTI_TENANT_CLOUD_SUFFIXES {
        if host == *cloud_suffix
            || (host.ends_with(cloud_suffix)
                && host.as_bytes().get(host.len() - cloud_suffix.len() - 1) == Some(&b'.'))
        {
            return None;
        }
    }

    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    let tld = labels[labels.len() - 1];
    // Reject IP literals as org roots
    if !tld.as_bytes()[0].is_ascii_lowercase() {
        return None;
    }

    let last_two = format!("{}.{}", labels[labels.len() - 2], tld);
    if MULTIPART_CCTLDS.contains(&last_two.as_str()) {
        if labels.len() < 3 {
            None
        } else {
            Some(format!(
                "{}.{}.{}",
                labels[labels.len() - 3],
                labels[labels.len() - 2],
                tld
            ))
        }
    } else {
        Some(last_two)
    }
}

fn current_epoch_secs() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| WolinError::Internal(format!("System clock before UNIX_EPOCH: {e}")))
}

fn validate_solid_oidc_temporal_and_aud_claims(
    claims: &OidcClaims,
    options: &OidcValidationOptions,
) -> Result<()> {
    if options.clock_skew_leeway_secs < 0 {
        return Err(WolinError::InvalidFormat(
            "Clock skew leeway must be non-negative".to_string(),
        ));
    }
    if claims.iss.trim().is_empty() {
        return Err(WolinError::Unauthenticated(
            "Solid-OIDC 'iss' claim must not be empty".to_string(),
        ));
    }
    if claims.sub.trim().is_empty() {
        return Err(WolinError::Unauthenticated(
            "Solid-OIDC 'sub' claim must not be empty".to_string(),
        ));
    }
    if claims.aud.is_empty() || claims.aud.iter().any(|a| a.trim().is_empty()) {
        return Err(WolinError::Unauthenticated(
            "Solid-OIDC 'aud' claim must be non-empty".to_string(),
        ));
    }
    if let Some(ref expected_aud) = options.expected_audience {
        let matches_expected_or_solid =
            claims.aud.iter().any(|a| a == expected_aud || a == "solid");
        if !matches_expected_or_solid {
            return Err(WolinError::Unauthenticated(format!(
                "Solid-OIDC audience mismatch: expected '{expected_aud}' or 'solid'"
            )));
        }
    }

    let now = match options.now_epoch_secs {
        Some(ts) => ts,
        None => current_epoch_secs()?,
    };
    let leeway = options.clock_skew_leeway_secs;

    if claims.exp <= 0 || now >= claims.exp.saturating_add(leeway) {
        return Err(WolinError::Unauthenticated(
            "OIDC token has expired".to_string(),
        ));
    }
    if let Some(nbf) = claims.nbf
        && now.saturating_add(leeway) < nbf
    {
        return Err(WolinError::Unauthenticated(
            "OIDC token is not yet valid (nbf)".to_string(),
        ));
    }
    if let Some(iat) = claims.iat {
        if claims.exp <= iat {
            return Err(WolinError::Unauthenticated(
                "OIDC token expiration (exp) must be greater than issued-at (iat)".to_string(),
            ));
        }
        if iat > now.saturating_add(leeway) {
            return Err(WolinError::Unauthenticated(
                "OIDC token issued-at (iat) is in the future".to_string(),
            ));
        }
    }
    Ok(())
}

fn is_valid_solid_issuer_uri(iss: &str) -> bool {
    if iss.is_empty()
        || iss.len() > 2048
        || iss
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
    {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(iss) else {
        return false;
    };
    matches!(url.scheme(), "https" | "http")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

pub(crate) fn base64url_decode_segment(input: &str) -> Result<Vec<u8>> {
    base64url_decode(input)
}

fn reject_dpop_bound_token_without_proof(claims: &OidcClaims) -> Result<()> {
    if claims.cnf.is_some() {
        return Err(WolinError::Unauthenticated(
            "DPoP-bound access token ('cnf') cannot be used without a verified DPoP proof"
                .to_string(),
        ));
    }
    Ok(())
}

/// Strict RFC 7515 §2 canonical unpadded Base64URL decoder (rejects `=` padding and non-zero pad bits).
fn base64url_decode(input: &str) -> Result<Vec<u8>> {
    if input.contains('=') || input.len() % 4 == 1 {
        return Err(WolinError::Unauthenticated(
            "Invalid or non-canonical base64url segment in JWT".to_string(),
        ));
    }

    let mut out = Vec::with_capacity((input.len() * 3) / 4);
    let bytes = input.as_bytes();
    let mut i = 0;

    while i + 4 <= bytes.len() {
        let a = b64url_val(bytes[i])? as u32;
        let b = b64url_val(bytes[i + 1])? as u32;
        let c = b64url_val(bytes[i + 2])? as u32;
        let d = b64url_val(bytes[i + 3])? as u32;
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
        out.push((n & 0xff) as u8);
        i += 4;
    }

    let rem = bytes.len() - i;
    if rem == 2 {
        let a = b64url_val(bytes[i])? as u32;
        let b = b64url_val(bytes[i + 1])? as u32;
        if (b & 0x0f) != 0 {
            return Err(WolinError::Unauthenticated(
                "Non-canonical trailing bits in base64url JWT segment".to_string(),
            ));
        }
        let n = (a << 18) | (b << 12);
        out.push(((n >> 16) & 0xff) as u8);
    } else if rem == 3 {
        let a = b64url_val(bytes[i])? as u32;
        let b = b64url_val(bytes[i + 1])? as u32;
        let c = b64url_val(bytes[i + 2])? as u32;
        if (c & 0x03) != 0 {
            return Err(WolinError::Unauthenticated(
                "Non-canonical trailing bits in base64url JWT segment".to_string(),
            ));
        }
        let n = (a << 18) | (b << 12) | (c << 6);
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
    }

    Ok(out)
}

fn b64url_val(b: u8) -> Result<u8> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(WolinError::Unauthenticated(
            "Invalid character in base64url JWT segment".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_base64url_rejects_malformed_padded_and_noncanonical_segments() {
        assert!(base64url_decode("abc+def").is_err());
        assert!(base64url_decode("abc/def").is_err());
        assert!(base64url_decode("abcde").is_err());
        assert!(base64url_decode("YWJj=").is_err());
        assert!(base64url_decode("ab====").is_err());
        assert!(base64url_decode("QR").is_err());
    }

    #[test]
    fn unit_validate_parsed_claims_explicit_delegated_by_and_did_canonicalization() {
        let claims = OidcClaims {
            iss: "https://zitadel.wolin.id".to_string(),
            sub: "agent-worker-7".to_string(),
            aud: vec!["wolin-mcp".to_string()],
            exp: 2_000_000_000,
            iat: Some(1_999_999_000),
            nbf: Some(1_999_999_000),
            scopes: vec!["read".to_string()],
            webid: None,
            azp: Some("mcp-client".to_string()),
            act: Some(ActorClaim {
                sub: "did:web:WOLIN.ID:agents:%53ummarizer".to_string(),
                act: None,
            }),
            delegated_by: Some("did:web:wolin.id:users:%61lice".to_string()),
            org_id: None,
            cnf: None,
        };
        let opts = OidcValidationOptions::new("https://zitadel.wolin.id")
            .with_audience("wolin-mcp")
            .with_now(1_999_999_500);
        let principal = OidcValidator::validate_parsed_claims(&claims, &opts).unwrap();
        assert_eq!(
            principal,
            Principal::Agent {
                agent_id: "did:web:wolin.id:agents:Summarizer".to_string(),
                delegated_by: WebId("did:web:wolin.id:users:alice".to_string()),
                scope: vec!["read".to_string()],
            }
        );
    }

    #[test]
    fn unit_cross_idp_userinfo_cctld_cloud_and_unbound_did_key_spoofing_blocked() {
        let make_claim = |iss: &str, webid: &str| OidcClaims {
            iss: iss.to_string(),
            sub: "attacker".to_string(),
            aud: vec!["wolin".to_string()],
            exp: 2_000_001_000,
            iat: Some(2_000_000_000),
            nbf: None,
            scopes: vec!["read".to_string()],
            webid: Some(webid.to_string()),
            azp: None,
            act: None,
            delegated_by: None,
            org_id: None,
            cnf: None,
        };

        // 1. userinfo@host authority confusion
        let c1 = make_claim(
            "https://evil.idp.example",
            "https://evil.idp.example:443@trusted-idp.corp/profile#admin", // gitleaks:allow
        );
        assert!(
            OidcValidator::validate_parsed_claims(
                &c1,
                &OidcValidationOptions::new("https://evil.idp.example").with_now(2_000_000_100)
            )
            .is_err()
        );

        // 2. Multi-part ccTLD (.co.kr) cross-org collision
        let c2 = make_claim("https://evil.co.kr", "https://samsung.co.kr/profile#ceo");
        assert!(
            OidcValidator::validate_parsed_claims(
                &c2,
                &OidcValidationOptions::new("https://evil.co.kr").with_now(2_000_000_100)
            )
            .is_err()
        );

        // 3. Multi-tenant IdP cloud (.zitadel.cloud & regional .us1.zitadel.cloud) cross-tenant collision
        for (iss, victim) in [
            (
                "https://evil-tenant.zitadel.cloud",
                "https://victim-tenant.zitadel.cloud/u#1",
            ),
            (
                "https://evil-tenant.us1.zitadel.cloud",
                "https://victim-tenant.us1.zitadel.cloud/u#1",
            ),
            (
                "https://evil.us.auth0.com",
                "https://victim.us.auth0.com/u#1",
            ),
        ] {
            let c3 = make_claim(iss, victim);
            assert!(
                OidcValidator::validate_parsed_claims(
                    &c3,
                    &OidcValidationOptions::new(iss).with_now(2_000_000_100)
                )
                .is_err()
            );
        }

        // Exact same tenant host on ZITADEL Cloud IS allowed
        let same_tenant = make_claim(
            "https://acme.us1.zitadel.cloud",
            "https://acme.us1.zitadel.cloud/users/alice",
        );
        assert!(
            OidcValidator::validate_parsed_claims(
                &same_tenant,
                &OidcValidationOptions::new("https://acme.us1.zitadel.cloud")
                    .with_now(2_000_000_100)
            )
            .is_ok()
        );

        // 4. Unbound did:key asserted in `webid` when `sub != did:key:...`
        let c4 = make_claim(
            "https://evil.idp.example",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", // gitleaks:allow
        );
        assert!(
            OidcValidator::validate_parsed_claims(
                &c4,
                &OidcValidationOptions::new("https://evil.idp.example").with_now(2_000_000_100)
            )
            .is_err()
        );

        // 5. Same 3-label org under .co.kr IS allowed
        let valid_kr = make_claim(
            "https://sso.samsung.co.kr",
            "https://pod.samsung.co.kr/alice#me",
        );
        assert!(
            OidcValidator::validate_parsed_claims(
                &valid_kr,
                &OidcValidationOptions::new("https://sso.samsung.co.kr").with_now(2_000_000_100)
            )
            .is_ok()
        );
    }

    fn b64url_encode_test(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
        let mut i = 0;
        while i + 3 <= bytes.len() {
            let n =
                ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
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

    #[test]
    fn unit_empty_and_null_crit_header_and_nested_act_rejected() {
        let payload_b64 = b64url_encode_test(
            serde_json::json!({
                "iss": "https://id.wolin.id",
                "sub": "u1",
                "aud": "wolin",
                "exp": 2_000_001_000_i64
            })
            .to_string()
            .as_bytes(),
        );
        let sig_b64 = b64url_encode_test(b"sig-bytes");
        let opts = OidcValidationOptions::new("https://id.wolin.id").with_now(2_000_000_000);

        for bad_hdr in [
            serde_json::json!({"alg": "EdDSA", "crit": []}),
            serde_json::json!({"alg": "EdDSA", "crit": null}),
            serde_json::json!({"alg": "EdDSA", "crit": ["exp"]}),
        ] {
            let hdr_b64 = b64url_encode_test(bad_hdr.to_string().as_bytes());
            let jwt = format!("{hdr_b64}.{payload_b64}.{sig_b64}");
            let err = OidcValidator::validate_with_options(&jwt, &opts).unwrap_err();
            assert!(
                err.to_string().contains("crit"),
                "expected crit rejection error, got: {err}"
            );
        }

        let nested_act = OidcClaims {
            iss: "https://zitadel.wolin.id".to_string(),
            sub: "u1".to_string(),
            aud: vec!["wolin".to_string()],
            exp: 2_000_001_000,
            iat: Some(2_000_000_000),
            nbf: None,
            scopes: vec!["read".to_string()],
            webid: None,
            azp: None,
            act: Some(ActorClaim {
                sub: "agent-1".to_string(),
                act: Some(serde_json::json!({"sub": "agent-2"})),
            }),
            delegated_by: None,
            org_id: None,
            cnf: None,
        };
        let wolin_opts =
            OidcValidationOptions::new("https://zitadel.wolin.id").with_now(2_000_000_100);
        assert!(OidcValidator::validate_parsed_claims(&nested_act, &wolin_opts).is_err());
    }

    #[test]
    fn unit_nbf_and_future_iat_rejected() {
        let mut claims = OidcClaims {
            iss: "https://zitadel.wolin.id".to_string(),
            sub: "u1".to_string(),
            aud: vec!["wolin".to_string()],
            exp: 2_000_001_000,
            iat: Some(2_000_000_000),
            nbf: Some(2_000_000_500),
            scopes: vec![],
            webid: None,
            azp: None,
            act: None,
            delegated_by: None,
            org_id: None,
            cnf: None,
        };
        let opts = OidcValidationOptions::new("https://zitadel.wolin.id").with_now(2_000_000_100);
        assert!(OidcValidator::validate_parsed_claims(&claims, &opts).is_err());

        claims.nbf = None;
        claims.iat = Some(2_000_000_500);
        assert!(OidcValidator::validate_parsed_claims(&claims, &opts).is_err());
    }
}
