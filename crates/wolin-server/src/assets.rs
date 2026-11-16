//! Short-lived HMAC-SHA256 signed asset URL minting and verification for Edge/R2 egress offload.
//!
//! Authorization (`WAC` / `ACP` / `DelegationGrant`) is evaluated strictly inside `wolin-server`
//! before any token is minted. Edge Workers (`wolin-cloud`) verify the short-lived capability
//! signature over `(method, pod_id, resource_path, exp)` and stream the binary blob directly from R2.

use ring::hmac::{HMAC_SHA256, Key, sign, verify};

use crate::ldp::http_iri;

/// Domain-separation prefix for Wolin short-lived asset offload HMAC-SHA256 signatures.
pub const ASSET_SIGNATURE_DOMAIN: &str = "wolin-asset-v1";

/// Default minimum `NonRDFSource` payload size (`256 KiB`) before `GET` offloads via `302 Found`.
pub const DEFAULT_ASSET_OFFLOAD_MIN_BYTES: u64 = 262_144;

/// Short-lived TTL (`60` seconds) for signed Edge/R2 asset URLs.
pub const DEFAULT_ASSET_SIGNING_TTL_SECS: i64 = 60;

/// Build the canonical newline-delimited signing payload over `(method, pod_id, resource_path, exp)`.
///
/// `resource_path` must be the canonical Pod-relative path starting with `'/'`
/// (for example, `"/media/video.mp4"` for canonical LDP path `"/pods/alice/media/video.mp4"`).
pub fn canonical_asset_signing_input(
    method: &str,
    pod_id: &str,
    resource_path: &str,
    exp: i64,
) -> String {
    debug_assert!(resource_path.starts_with('/'));
    debug_assert!(
        !method.contains('\n') && !pod_id.contains('\n') && !resource_path.contains('\n')
    );
    format!("{ASSET_SIGNATURE_DOMAIN}\n{method}\n{pod_id}\n{resource_path}\n{exp}")
}

/// Compute the 64-character lowercase hex HMAC-SHA256 signature for an asset access tuple.
pub fn sign_asset_token(
    secret: &str,
    method: &str,
    pod_id: &str,
    resource_path: &str,
    exp: i64,
) -> String {
    let key = Key::new(HMAC_SHA256, secret.as_bytes());
    let payload = canonical_asset_signing_input(method, pod_id, resource_path, exp);
    let tag = sign(&key, payload.as_bytes());
    hex_encode_lower(tag.as_ref())
}

/// Verify a 64-character lowercase hex HMAC-SHA256 signature in constant time.
pub fn verify_asset_token(
    secret: &str,
    method: &str,
    pod_id: &str,
    resource_path: &str,
    exp: i64,
    sig_hex: &str,
) -> bool {
    let Some(sig_bytes) = decode_hex_32_lower(sig_hex) else {
        return false;
    };
    let key = Key::new(HMAC_SHA256, secret.as_bytes());
    let payload = canonical_asset_signing_input(method, pod_id, resource_path, exp);
    verify(&key, payload.as_bytes(), &sig_bytes).is_ok()
}

/// Construct the full signed redirect URL `BASE_URL/POD_ID/RESOURCE_PATH?exp=UNIX&sig=HEX`.
pub fn build_signed_asset_redirect_url(
    asset_public_base_url: &str,
    secret: &str,
    pod_id: &str,
    resource_path: &str,
    exp: i64,
) -> String {
    let sig = sign_asset_token(secret, "GET", pod_id, resource_path, exp);
    let pod_scoped_path = format!("/{pod_id}{resource_path}");
    let encoded_url = http_iri(asset_public_base_url, &pod_scoped_path);
    format!("{encoded_url}?exp={exp}&sig={sig}")
}

fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_LOWER[(b >> 4) as usize] as char);
        out.push(HEX_LOWER[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_32_lower(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let raw = hex.as_bytes();
    let mut out = [0u8; 32];
    for (idx, slot) in out.iter_mut().enumerate() {
        let hi = decode_lower_hex_nibble(raw[idx * 2])?;
        let lo = decode_lower_hex_nibble(raw[idx * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn decode_lower_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_hmac_sha256_signing_and_constant_time_verification_vector() {
        let secret = "wolin-shared-edge-hmac-secret-v1";
        let pod_id = "alice";
        let path = "/media/clip.mp4";
        let exp = 1_763_500_060_i64;

        let sig = sign_asset_token(secret, "GET", pod_id, path, exp);
        assert_eq!(
            sig,
            "ccb17ca00b258693ec72093de873eada21d246cd03cc088779bfd41666be31fd"
        );

        assert!(verify_asset_token(secret, "GET", pod_id, path, exp, &sig));
        assert!(!verify_asset_token(secret, "HEAD", pod_id, path, exp, &sig));
        assert!(!verify_asset_token(secret, "GET", "bob", path, exp, &sig));
        assert!(!verify_asset_token(
            secret,
            "GET",
            pod_id,
            "/media/other.mp4",
            exp,
            &sig
        ));
        assert!(!verify_asset_token(
            secret,
            "GET",
            pod_id,
            path,
            exp + 1,
            &sig
        ));
        assert!(!verify_asset_token(
            "wrong-secret",
            "GET",
            pod_id,
            path,
            exp,
            &sig
        ));
        assert!(!verify_asset_token(
            secret,
            "GET",
            pod_id,
            path,
            exp,
            &sig.to_ascii_uppercase()
        ));

        let url = build_signed_asset_redirect_url(
            "https://auth.wolin.id/assets/",
            secret,
            pod_id,
            path,
            exp,
        );
        assert_eq!(
            url,
            format!("https://auth.wolin.id/assets/alice/media/clip.mp4?exp={exp}&sig={sig}")
        );
    }
}
