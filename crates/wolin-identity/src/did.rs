use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use wolin_core::{Principal, Result, WebId, WolinError};

const MAX_DID_LEN: usize = 2048;
const MAX_MULTIBASE_LEN: usize = 512;
const MAX_AGENT_SCOPES: usize = 128;
const BASE58BTC_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Supported W3C / Sovereign DID methods in Wolin
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DidMethod {
    /// Self-certifying cryptographic key (`did:key:z...`)
    Key,
    /// Schnorr secp256k1 x-only public key (`did:nostr:<64-hex>`)
    Nostr,
    /// Enterprise / DNS federated identity (`did:web:<domain>[:path...]`)
    Web,
}

impl DidMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Nostr => "nostr",
            Self::Web => "web",
        }
    }
}

/// Normalized, validated representation of a DID URI
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedDid {
    pub method: DidMethod,
    pub method_specific_id: String,
    pub canonical_did: String,
    pub fragment: Option<String>,
    pub resolution_url: Option<String>,
    pub issuer: String,
}

/// W3C DID Core 1.0 Verification Method entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
}

/// W3C DID Core 1.0 Document projection
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    pub assertion_method: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_endpoint: Option<String>,
}

pub struct DidResolver;

impl DidResolver {
    /// Parse and validate a W3C DID URI (`did:key`, `did:nostr`, `did:web`).
    pub fn parse(did: &str) -> Result<ParsedDid> {
        let (_, parsed) = Self::parse_with_key_type(did)?;
        Ok(parsed)
    }

    /// Resolve a DID string into a W3C DID Document representation.
    pub fn resolve_document(did: &str) -> Result<DidDocument> {
        let (key_type, parsed) = Self::parse_with_key_type(did)?;
        let vm_id = match parsed.method {
            DidMethod::Key => format!("{}#{}", parsed.canonical_did, parsed.method_specific_id),
            DidMethod::Nostr => format!("{}#key-0", parsed.canonical_did),
            DidMethod::Web => format!("{}#owner", parsed.canonical_did),
        };

        let vm = match parsed.method {
            DidMethod::Key => VerificationMethod {
                id: vm_id.clone(),
                method_type: key_type.unwrap_or_else(|| "Ed25519VerificationKey2020".to_string()),
                controller: parsed.canonical_did.clone(),
                public_key_multibase: Some(parsed.method_specific_id.clone()),
                public_key_hex: None,
            },
            DidMethod::Nostr => VerificationMethod {
                id: vm_id.clone(),
                method_type: "EcdsaSecp256k1VerificationKey2019".to_string(),
                controller: parsed.canonical_did.clone(),
                public_key_multibase: None,
                public_key_hex: Some(parsed.method_specific_id.clone()),
            },
            DidMethod::Web => VerificationMethod {
                id: vm_id.clone(),
                method_type: "JsonWebKey2020".to_string(),
                controller: parsed.canonical_did.clone(),
                public_key_multibase: None,
                public_key_hex: None,
            },
        };

        Ok(DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_string()],
            id: parsed.canonical_did,
            verification_method: vec![vm],
            authentication: vec![vm_id.clone()],
            assertion_method: vec![vm_id],
            resolution_endpoint: parsed.resolution_url,
        })
    }

    /// Resolve a DID into a sovereign `Principal::User`.
    pub fn resolve_principal(did: &str) -> Result<Principal> {
        let parsed = Self::parse(did)?;
        Ok(Principal::User {
            webid: WebId(parsed.canonical_did),
            issuer: parsed.issuer,
        })
    }

    /// Resolve a DID-authenticated AI Agent acting on behalf of `delegated_by`.
    pub fn resolve_agent_principal(
        did: &str,
        delegated_by: WebId,
        scope: Vec<String>,
    ) -> Result<Principal> {
        if delegated_by.0.trim().is_empty() {
            return Err(WolinError::InvalidFormat(
                "Delegator WebID must not be empty".to_string(),
            ));
        }
        if scope.len() > MAX_AGENT_SCOPES {
            return Err(WolinError::InvalidFormat(format!(
                "Agent scope list exceeds maximum allowed count ({MAX_AGENT_SCOPES})"
            )));
        }
        let parsed = Self::parse(did)?;
        let mut seen = HashSet::with_capacity(scope.len());
        let mut normalized_scopes = Vec::with_capacity(scope.len());
        for item in scope {
            let trimmed = item.trim();
            if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
                normalized_scopes.push(trimmed.to_string());
            }
        }

        Ok(Principal::Agent {
            agent_id: parsed.canonical_did,
            delegated_by,
            scope: normalized_scopes,
        })
    }

    fn parse_with_key_type(did: &str) -> Result<(Option<String>, ParsedDid)> {
        if did.is_empty() || did.len() > MAX_DID_LEN {
            return Err(WolinError::InvalidFormat(
                "DID must be non-empty and at most 2048 bytes".to_string(),
            ));
        }
        if did
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(WolinError::InvalidFormat(
                "DID must not contain whitespace or control characters".to_string(),
            ));
        }

        let (base_did, fragment) = match did.split_once('#') {
            Some((base, frag)) => {
                if frag.is_empty() || frag.contains('#') {
                    return Err(WolinError::InvalidFormat(
                        "Invalid DID fragment syntax".to_string(),
                    ));
                }
                (base, Some(frag.to_string()))
            }
            None => (did, None),
        };

        if base_did.contains('?') || base_did.contains('/') || base_did.contains('\\') {
            return Err(WolinError::InvalidFormat(
                "Unexpected query or slash in base DID".to_string(),
            ));
        }

        let rest = base_did.strip_prefix("did:").ok_or_else(|| {
            WolinError::InvalidFormat("DID must begin with 'did:' scheme".to_string())
        })?;

        let (method_raw, msid) = rest.split_once(':').ok_or_else(|| {
            WolinError::InvalidFormat("DID missing method-specific identifier".to_string())
        })?;

        if msid.is_empty() {
            return Err(WolinError::InvalidFormat(
                "DID method-specific identifier cannot be empty".to_string(),
            ));
        }

        match method_raw {
            "key" => {
                let key_type = validate_did_key(msid)?;
                let canonical_did = format!("did:key:{msid}");
                Ok((
                    Some(key_type.to_string()),
                    ParsedDid {
                        method: DidMethod::Key,
                        method_specific_id: msid.to_string(),
                        canonical_did,
                        fragment,
                        resolution_url: None,
                        issuer: "did:key".to_string(),
                    },
                ))
            }
            "nostr" => {
                validate_did_nostr(msid)?;
                let canonical_did = format!("did:nostr:{msid}");
                Ok((
                    None,
                    ParsedDid {
                        method: DidMethod::Nostr,
                        method_specific_id: msid.to_string(),
                        canonical_did,
                        fragment,
                        resolution_url: None,
                        issuer: "did:nostr".to_string(),
                    },
                ))
            }
            "web" => {
                let (canonical_msid, authority, resolution_url) = parse_did_web(msid)?;
                let canonical_did = format!("did:web:{canonical_msid}");
                Ok((
                    None,
                    ParsedDid {
                        method: DidMethod::Web,
                        method_specific_id: canonical_msid,
                        canonical_did,
                        fragment,
                        resolution_url: Some(resolution_url),
                        issuer: format!("did:web:{authority}"),
                    },
                ))
            }
            other => Err(WolinError::Unauthenticated(format!(
                "Unsupported DID method: {other}"
            ))),
        }
    }
}

fn validate_did_key(msid: &str) -> Result<&'static str> {
    if msid.len() > MAX_MULTIBASE_LEN {
        return Err(WolinError::InvalidFormat(
            "did:key multibase identifier exceeds maximum length".to_string(),
        ));
    }
    let encoded = msid.strip_prefix('z').ok_or_else(|| {
        WolinError::InvalidFormat("did:key must use base58btc multibase prefix 'z'".to_string())
    })?;
    if encoded.is_empty() {
        return Err(WolinError::InvalidFormat(
            "did:key base58btc payload is empty".to_string(),
        ));
    }

    let decoded = decode_base58btc(encoded)?;
    if decoded.len() < 34 {
        return Err(WolinError::InvalidFormat(
            "did:key decoded key material is too short".to_string(),
        ));
    }

    let key_bytes = &decoded[2..];
    let is_sec1_compressed = matches!(key_bytes.first(), Some(0x02 | 0x03));

    match (decoded[0], decoded[1]) {
        (0xed, 0x01) if decoded.len() == 34 => {
            let is_all_zero = key_bytes.iter().all(|&b| b == 0);
            let is_ed25519_identity =
                key_bytes[0] == 0x01 && key_bytes[1..].iter().all(|&b| b == 0);
            if is_all_zero || is_ed25519_identity {
                return Err(WolinError::InvalidFormat(
                    "Invalid Ed25519 did:key: zero or identity curve point rejected".to_string(),
                ));
            }
            Ok("Ed25519VerificationKey2020")
        }
        (0xe7, 0x01)
            if decoded.len() == 35
                && is_sec1_compressed
                && key_bytes[1..].iter().any(|&b| b != 0) =>
        {
            Ok("EcdsaSecp256k1VerificationKey2019")
        }
        (0x80, 0x24)
            if decoded.len() == 35
                && is_sec1_compressed
                && key_bytes[1..].iter().any(|&b| b != 0) =>
        {
            Ok("JsonWebKey2020")
        }
        (0x81, 0x24)
            if decoded.len() == 51
                && is_sec1_compressed
                && key_bytes[1..].iter().any(|&b| b != 0) =>
        {
            Ok("JsonWebKey2020")
        }
        (0x82, 0x24)
            if decoded.len() == 69
                && is_sec1_compressed
                && key_bytes[1..].iter().any(|&b| b != 0) =>
        {
            Ok("JsonWebKey2020")
        }
        (0xeb, 0x01) if decoded.len() == 98 && key_bytes.iter().any(|&b| b != 0) => {
            Ok("Bls12381G2Key2020")
        }
        (0xec, 0x01) => Err(WolinError::InvalidFormat(
            "Encryption-only X25519 did:key cannot be used as an authentication principal"
                .to_string(),
        )),
        (b0, b1) => Err(WolinError::InvalidFormat(format!(
            "Unsupported or corrupted did:key multicodec header (0x{b0:02x}{b1:02x}, len={})",
            decoded.len()
        ))),
    }
}

fn decode_base58btc(input: &str) -> Result<Vec<u8>> {
    let mut lookup = [255u8; 128];
    for (idx, &ch) in BASE58BTC_ALPHABET.iter().enumerate() {
        lookup[ch as usize] = idx as u8;
    }

    let mut leading_zeros = 0usize;
    for b in input.bytes() {
        if b == b'1' {
            leading_zeros += 1;
        } else {
            break;
        }
    }

    let mut bytes: Vec<u8> = Vec::with_capacity(input.len());
    for ch in input.bytes() {
        if ch >= 128 || lookup[ch as usize] == 255 {
            return Err(WolinError::InvalidFormat(
                "Invalid base58btc character in did:key".to_string(),
            ));
        }
        let mut carry = lookup[ch as usize] as u32;
        for byte in bytes.iter_mut() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = vec![0u8; leading_zeros];
    for b in bytes.into_iter().rev() {
        out.push(b);
    }
    Ok(out)
}

fn validate_did_nostr(msid: &str) -> Result<()> {
    if msid.len() != 64 {
        return Err(WolinError::InvalidFormat(
            "did:nostr public key must be exactly 64 lowercase hex characters".to_string(),
        ));
    }
    if !msid
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(WolinError::InvalidFormat(
            "did:nostr public key must contain only lowercase hexadecimal characters".to_string(),
        ));
    }
    if msid.bytes().all(|b| b == b'0') {
        return Err(WolinError::InvalidFormat(
            "did:nostr public key must not be all zeros".to_string(),
        ));
    }
    Ok(())
}

fn parse_did_web(msid: &str) -> Result<(String, String, String)> {
    let segments: Vec<&str> = msid.split(':').collect();
    if segments.iter().any(|s| s.is_empty()) {
        return Err(WolinError::InvalidFormat(
            "did:web must not contain empty colon-separated segments".to_string(),
        ));
    }

    let raw_host = segments[0];
    let (host_part, port_part) = split_did_web_host_port(raw_host)?;
    let normalized_host = host_part.to_ascii_lowercase();
    validate_dns_hostname(&normalized_host)?;

    let (canonical_host_segment, authority) = match port_part {
        Some(port) => (
            format!("{normalized_host}%3A{port}"),
            format!("{normalized_host}:{port}"),
        ),
        None => (normalized_host.clone(), normalized_host),
    };

    let mut clean_paths: Vec<String> = Vec::with_capacity(segments.len().saturating_sub(1));
    for seg in &segments[1..] {
        clean_paths.push(canonicalize_did_web_path_segment(seg)?);
    }

    let canonical_msid = if clean_paths.is_empty() {
        canonical_host_segment
    } else {
        format!("{canonical_host_segment}:{}", clean_paths.join(":"))
    };

    let resolution_url = if clean_paths.is_empty() {
        format!("https://{authority}/.well-known/did.json")
    } else {
        format!("https://{authority}/{}/did.json", clean_paths.join("/"))
    };

    Ok((canonical_msid, authority, resolution_url))
}

fn split_did_web_host_port(raw_host: &str) -> Result<(&str, Option<u16>)> {
    let lower = raw_host.to_ascii_lowercase();
    if let Some(idx) = lower.find("%3a") {
        let host = &raw_host[..idx];
        let port_str = &raw_host[idx + 3..];
        if host.contains('%') || port_str.contains('%') {
            return Err(WolinError::InvalidFormat(
                "Invalid percent-encoding in did:web host".to_string(),
            ));
        }
        if port_str.is_empty()
            || port_str.len() > 5
            || port_str.starts_with('0')
            || !port_str.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(WolinError::InvalidFormat(
                "Invalid port in did:web identifier".to_string(),
            ));
        }
        let port: u16 = port_str.parse().map_err(|_| {
            WolinError::InvalidFormat("Port out of u16 range in did:web".to_string())
        })?;
        Ok((host, Some(port)))
    } else if raw_host.contains('%') {
        Err(WolinError::InvalidFormat(
            "Disallowed percent-encoding in did:web host".to_string(),
        ))
    } else {
        Ok((raw_host, None))
    }
}

fn validate_dns_hostname(host: &str) -> Result<()> {
    if host.is_empty() || host.len() > 253 {
        return Err(WolinError::InvalidFormat(
            "Invalid did:web hostname length".to_string(),
        ));
    }
    if host == "localhost" {
        return Ok(());
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return Err(WolinError::InvalidFormat(
            "did:web domain must be a qualified hostname or localhost".to_string(),
        ));
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(WolinError::InvalidFormat(
                "Invalid DNS label in did:web hostname".to_string(),
            ));
        }
    }

    let tld = *labels.last().unwrap_or(&"");
    // Block RFC 6761 / internal / mDNS / reverse-DNS suffixes
    if matches!(tld, "localhost" | "local" | "internal" | "arpa") {
        return Err(WolinError::InvalidFormat(format!(
            "Reserved internal DNS suffix '.{tld}' is rejected in did:web"
        )));
    }

    // Block all decimal, hex (0xfe), and octal (0177) IPv4 literals:
    // ICANN/RFC 1123 TLDs must start with an ASCII letter (`a-z`) and be >= 2 chars
    // (either pure alphabetic or valid `xn--` punycode).
    let valid_tld = tld.len() >= 2
        && tld.as_bytes()[0].is_ascii_lowercase()
        && (tld.bytes().all(|b| b.is_ascii_lowercase()) || tld.starts_with("xn--"));
    if !valid_tld {
        return Err(WolinError::InvalidFormat(
            "IP literals and numeric/hex TLDs are prohibited in did:web".to_string(),
        ));
    }

    Ok(())
}

/// Validate and RFC 3986-canonicalize a `did:web` path segment so unreserved
/// `%XX` encodings (e.g. `%53ummarizer` -> `Summarizer`) cannot evade policy matchers.
fn canonicalize_did_web_path_segment(seg: &str) -> Result<String> {
    let bytes = seg.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return Err(WolinError::InvalidFormat(
                    "Truncated percent-encoding in did:web path".to_string(),
                ));
            }
            let hi = hex_val(bytes[i + 1])?;
            let lo = hex_val(bytes[i + 2])?;
            let decoded = (hi << 4) | lo;

            // Block encoded path/URI delimiters, dots, colons, spaces, and control characters
            if matches!(
                decoded,
                b'/' | b'\\' | b'.' | b':' | b'?' | b'#' | 0x00..=0x20 | 0x7f
            ) {
                return Err(WolinError::InvalidFormat(
                    "Encoded delimiter, dot, or control byte forbidden in did:web".to_string(),
                ));
            }

            if is_unreserved_uri_byte(decoded) {
                out.push(decoded as char);
            } else {
                out.push('%');
                out.push(HEX_UPPER[hi as usize] as char);
                out.push(HEX_UPPER[lo as usize] as char);
            }
            i += 3;
        } else if is_unreserved_uri_byte(b) {
            out.push(b as char);
            i += 1;
        } else {
            return Err(WolinError::InvalidFormat(
                "Invalid character in did:web path segment".to_string(),
            ));
        }
    }

    if out.is_empty() || out == "." || out == ".." {
        return Err(WolinError::InvalidFormat(
            "Path traversal segment not allowed in did:web".to_string(),
        ));
    }

    Ok(out)
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn is_unreserved_uri_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn hex_val(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(WolinError::InvalidFormat(
            "Invalid hex digit in percent-encoding".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_did_web_rejects_ipv4_hex_octal_and_internal_suffixes() {
        assert!(DidResolver::parse("did:web:169.254.169.254:latest:meta-data").is_err());
        assert!(DidResolver::parse("did:web:127.0.0.1").is_err());
        assert!(DidResolver::parse("did:web:0xa9.0xfe.0xa9.0xfe").is_err());
        assert!(DidResolver::parse("did:web:0x7f.0x0.0x0.0x1").is_err());
        assert!(DidResolver::parse("did:web:0177.0.0.01").is_err());
        assert!(DidResolver::parse("did:web:metadata.internal").is_err());
        assert!(DidResolver::parse("did:web:printer.local").is_err());
        assert!(DidResolver::parse("did:web:sub.localhost").is_err());
    }

    #[test]
    fn unit_did_web_canonicalizes_unreserved_percent_encoding_and_blocks_delims() {
        let parsed = DidResolver::parse("did:web:acme.corp:agents:%53ummarizer").unwrap();
        assert_eq!(parsed.canonical_did, "did:web:acme.corp:agents:Summarizer");
        assert_eq!(
            parsed.resolution_url.as_deref(),
            Some("https://acme.corp/agents/Summarizer/did.json")
        );

        assert!(DidResolver::parse("did:web:acme.corp:agents:bot%3fadmin=1").is_err());
        assert!(DidResolver::parse("did:web:acme.corp:agents:bot%23frag").is_err());
        assert!(DidResolver::parse("did:web:acme.corp:agents:bot%3asub").is_err());
    }

    #[test]
    fn unit_did_key_rejects_corrupted_length_and_x25519() {
        // Valid base58btc prefix 'z', but wrong Ed25519 payload length
        assert!(
            DidResolver::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta").is_err() // gitleaks:allow
        );
        // Official W3C X25519 key agreement vector must be rejected for authentication principal
        assert!(
            DidResolver::parse("did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc") // gitleaks:allow
                .is_err()
        );

        // SEC1 secp256k1 header [0xe7, 0x01, 0x02] followed by 32 zero X-coordinate bytes -> rejected
        let mut sec1_zero_x = vec![0xe7u8, 0x01, 0x02];
        sec1_zero_x.extend_from_slice(&[0u8; 32]);
        let b58_encode = |data: &[u8]| -> String {
            let mut digits = vec![0u8];
            for &byte in data {
                let mut carry = byte as u32;
                for d in digits.iter_mut() {
                    carry += (*d as u32) * 256;
                    *d = (carry % 58) as u8;
                    carry /= 58;
                }
                while carry > 0 {
                    digits.push((carry % 58) as u8);
                    carry /= 58;
                }
            }
            let mut s = String::new();
            for &b in data {
                if b == 0 {
                    s.push('1');
                } else {
                    break;
                }
            }
            for &d in digits.iter().rev() {
                s.push(BASE58BTC_ALPHABET[d as usize] as char);
            }
            s
        };
        let bad_sec1_did = format!("did:key:z{}", b58_encode(&sec1_zero_x));
        assert!(DidResolver::parse(&bad_sec1_did).is_err());
    }

    #[test]
    fn unit_did_method_as_str() {
        assert_eq!(DidMethod::Key.as_str(), "key");
        assert_eq!(DidMethod::Nostr.as_str(), "nostr");
        assert_eq!(DidMethod::Web.as_str(), "web");
    }
}
