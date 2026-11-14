use axum::http::{HeaderMap, Method, Uri, header};
use wolin_core::Principal;
use wolin_identity::{DidResolver, DpopValidationContext, OidcValidator};

use crate::{AppState, LdpConfig, error::LdpError, pods::extract_subdomain_pod};

const DEFAULT_DPOP_MAX_SKEW_SECS: i64 = 300;

/// Synchronous local credential extractor for unit/local-only callers without external WebID I/O.
pub fn extract_principal(headers: &HeaderMap, config: &LdpConfig) -> Result<Principal, LdpError> {
    let Some((scheme, token)) = parse_authorization_header(headers)? else {
        return Ok(Principal::Anonymous);
    };

    if scheme.eq_ignore_ascii_case("Bearer") {
        let principal = match &config.jwt_verifier {
            Some(verifier) => OidcValidator::validate_with_verifier(
                token,
                &config.oidc_options,
                verifier.as_ref(),
            ),
            None => OidcValidator::validate_with_options(token, &config.oidc_options),
        }
        .map_err(|e| LdpError::Unauthenticated(e.to_string()))?;
        Ok(principal)
    } else if scheme.eq_ignore_ascii_case("DID") {
        DidResolver::resolve_principal(token).map_err(|e| LdpError::Unauthenticated(e.to_string()))
    } else {
        Err(LdpError::Unauthenticated(format!(
            "Unsupported synchronous authentication scheme '{scheme}'"
        )))
    }
}

/// Resolve the HTTP caller's [`Principal`] supporting Solid-OIDC external WebID dereferencing,
/// `solid:oidcIssuer` trust chain verification, RFC 9449 `DPoP` proof-of-possession,
/// enterprise OIDC `Bearer` tokens, and sovereign W3C `DID` credentials.
///
/// Any malformed, expired, replayed, or unverified credential fails closed with `401 Unauthorized`.
pub async fn extract_principal_for_request(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    state: &AppState,
) -> Result<Principal, LdpError> {
    let Some((scheme, token)) = parse_authorization_header(headers)? else {
        return Ok(Principal::Anonymous);
    };

    if scheme.eq_ignore_ascii_case("DPoP") {
        let dpop_jwt = extract_single_dpop_header(headers)?;
        let expected_htus = compute_expected_dpop_htus(uri, headers, &state.config)?;
        let dpop_ctx = DpopValidationContext {
            expected_htm: method.as_str(),
            expected_htus: &expected_htus,
            access_token: token,
            now_epoch_secs: state.config.oidc_options.now_epoch_secs,
            max_iat_skew_secs: DEFAULT_DPOP_MAX_SKEW_SECS,
            replay_cache: Some(&state.dpop_replay_cache),
        };
        OidcValidator::validate_solid_oidc(
            token,
            &state.config.oidc_options,
            state.config.jwt_verifier.as_deref(),
            state.config.webid_dereferencer.as_deref(),
            Some((dpop_jwt, &dpop_ctx)),
        )
        .await
        .map_err(|e| LdpError::Unauthenticated(e.to_string()))
    } else if scheme.eq_ignore_ascii_case("Bearer") {
        OidcValidator::validate_solid_oidc(
            token,
            &state.config.oidc_options,
            state.config.jwt_verifier.as_deref(),
            state.config.webid_dereferencer.as_deref(),
            None,
        )
        .await
        .map_err(|e| LdpError::Unauthenticated(e.to_string()))
    } else if scheme.eq_ignore_ascii_case("DID") {
        DidResolver::resolve_principal(token).map_err(|e| LdpError::Unauthenticated(e.to_string()))
    } else {
        Err(LdpError::Unauthenticated(format!(
            "Unsupported authentication scheme '{scheme}'"
        )))
    }
}

fn parse_authorization_header(headers: &HeaderMap) -> Result<Option<(&str, &str)>, LdpError> {
    let mut auth_iter = headers.get_all(header::AUTHORIZATION).iter();
    let Some(raw_header) = auth_iter.next() else {
        return Ok(None);
    };
    if auth_iter.next().is_some() {
        return Err(LdpError::Unauthenticated(
            "Multiple Authorization headers are not permitted".to_string(),
        ));
    }

    let header_str = raw_header
        .to_str()
        .map_err(|_| {
            LdpError::Unauthenticated("Malformed Authorization header encoding".to_string())
        })?
        .trim();

    if header_str.is_empty() {
        return Err(LdpError::Unauthenticated(
            "Empty Authorization header".to_string(),
        ));
    }

    let Some((scheme, credential)) = header_str.split_once(' ') else {
        return Err(LdpError::Unauthenticated(
            "Invalid Authorization header syntax: expected '<Scheme> <token>'".to_string(),
        ));
    };
    let token = credential.trim();
    if token.is_empty() {
        return Err(LdpError::Unauthenticated(
            "Empty Authorization credential".to_string(),
        ));
    }

    Ok(Some((scheme, token)))
}

fn extract_single_dpop_header(headers: &HeaderMap) -> Result<&str, LdpError> {
    let mut dpop_iter = headers.get_all("dpop").iter();
    let Some(raw_dpop) = dpop_iter.next() else {
        return Err(LdpError::Unauthenticated(
            "DPoP Authorization scheme requires a 'DPoP' proof header".to_string(),
        ));
    };
    if dpop_iter.next().is_some() {
        return Err(LdpError::Unauthenticated(
            "Multiple DPoP headers are not permitted".to_string(),
        ));
    }
    let proof_str = raw_dpop
        .to_str()
        .map_err(|_| LdpError::Unauthenticated("Malformed DPoP header encoding".to_string()))?
        .trim();
    if proof_str.is_empty() {
        return Err(LdpError::Unauthenticated(
            "Empty DPoP proof header".to_string(),
        ));
    }
    Ok(proof_str)
}

fn compute_expected_dpop_htus(
    uri: &Uri,
    headers: &HeaderMap,
    config: &LdpConfig,
) -> Result<Vec<String>, LdpError> {
    let path = uri.path();
    let mut candidates = Vec::with_capacity(2);

    if let Some((_pod_id, sub_origin)) = extract_subdomain_pod(headers, uri, config)? {
        candidates.push(format!("{sub_origin}{path}"));
        return Ok(candidates);
    }

    if let (Some(scheme), Some(auth)) = (uri.scheme_str(), uri.authority()) {
        candidates.push(format!("{scheme}://{auth}{path}"));
    }

    if let Some(raw_host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) {
        let host_trimmed = raw_host.trim();
        if !host_trimmed.is_empty()
            && !host_trimmed.bytes().any(|b| {
                b.is_ascii_whitespace() || b.is_ascii_control() || matches!(b, b'/' | b'@')
            })
        {
            let scheme = effective_scheme(uri, headers, config);
            candidates.push(format!("{scheme}://{host_trimmed}{path}"));
        }
    }

    let base = config.base_url.trim_end_matches('/');
    let base_candidate = format!("{base}{path}");
    if !candidates.contains(&base_candidate) {
        candidates.push(base_candidate);
    }

    Ok(candidates)
}

pub(crate) fn effective_scheme<'a>(
    uri: &'a Uri,
    headers: &'a HeaderMap,
    config: &'a LdpConfig,
) -> &'a str {
    if let Some(s) = uri.scheme_str() {
        if s.eq_ignore_ascii_case("https") {
            return "https";
        } else if s.eq_ignore_ascii_case("http") {
            return "http";
        }
    }
    if let Some(xfp) = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        let first = xfp.split(',').next().unwrap_or_default().trim();
        if first.eq_ignore_ascii_case("https") {
            return "https";
        } else if first.eq_ignore_ascii_case("http") {
            return "http";
        }
    }
    if config.base_url.starts_with("https://") {
        "https"
    } else {
        "http"
    }
}
