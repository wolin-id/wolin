use axum::http::{header, HeaderMap};
use wolin_core::Principal;
use wolin_identity::{DidResolver, OidcValidator};

use crate::{error::LdpError, LdpConfig};

/// Resolve the HTTP caller's [`Principal`] from the `Authorization` header.
///
/// - Absent `Authorization` header -> [`Principal::Anonymous`]
/// - `Bearer <jwt>` or `DPoP <jwt>` -> validated via [`OidcValidator`]
/// - `DID <did>` -> resolved via [`DidResolver::resolve_principal`]
/// - Any malformed, expired, or unverified credential -> `401 Unauthorized` (fail-closed;
///   never falls back to `Anonymous`).
pub fn extract_principal(headers: &HeaderMap, config: &LdpConfig) -> Result<Principal, LdpError> {
    let mut auth_iter = headers.get_all(header::AUTHORIZATION).iter();
    let Some(raw_header) = auth_iter.next() else {
        return Ok(Principal::Anonymous);
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

    if scheme.eq_ignore_ascii_case("Bearer") || scheme.eq_ignore_ascii_case("DPoP") {
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
        let principal = DidResolver::resolve_principal(token)
            .map_err(|e| LdpError::Unauthenticated(e.to_string()))?;
        Ok(principal)
    } else {
        Err(LdpError::Unauthenticated(format!(
            "Unsupported authentication scheme '{scheme}'"
        )))
    }
}
