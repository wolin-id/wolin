use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use wolin_core::{ResourceKind, ResourceUri, Result, WolinError};
use wolin_storage::{PhysicalStore, PodStoreManager};

pub const CATALOG_META_KEY: &str = "__wolin_meta/catalog.json";
const RESERVED_META_SEG: &str = "__wolin_meta";
const MAX_URI_LEN: usize = 2048;

/// Catalog entry wire-compatible with `wolin-server`'s `LdpEntry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub path: String,
    pub kind: ResourceKind,
    pub content_type: String,
    pub etag: String,
    #[serde(default)]
    pub size_bytes: u64,
}

/// Persistent Solid Pod catalog stored at `__wolin_meta/catalog.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodCatalog {
    pub entries: BTreeMap<String, CatalogEntry>,
}

impl Default for PodCatalog {
    fn default() -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(
            "/".to_string(),
            CatalogEntry {
                path: "/".to_string(),
                kind: ResourceKind::Container,
                content_type: "text/turtle".to_string(),
                etag: compute_etag(b"root-container-v0"),
                size_bytes: 0,
            },
        );
        Self { entries }
    }
}

impl PodCatalog {
    pub async fn load_or_init(physical_store: &PhysicalStore) -> Result<Self> {
        if physical_store.exists(CATALOG_META_KEY).await? {
            let bytes = physical_store.get(CATALOG_META_KEY).await?;
            let mut catalog: Self = serde_json::from_slice(&bytes)
                .map_err(|e| WolinError::Storage(format!("Corrupt Pod catalog metadata: {e}")))?;
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
                .or_insert_with(|| CatalogEntry {
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

    pub async fn persist(&self, physical_store: &PhysicalStore) -> Result<()> {
        let bytes = serde_json::to_vec(self)
            .map_err(|e| WolinError::Internal(format!("Catalog serialize failed: {e}")))?;
        physical_store
            .put_with_content_type(CATALOG_META_KEY, bytes, "application/json")
            .await
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
}

fn infer_size_from_wolin_etag(etag: &str) -> Option<u64> {
    let inner = etag.strip_prefix('"')?.strip_suffix('"')?;
    let (hash_hex, len_hex) = inner.split_once('-')?;
    if hash_hex.len() != 32 || !hash_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(len_hex, 16).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPodUri {
    /// Canonical Pod prefix (e.g. `"wolin://pod"`).
    pub pod_prefix: String,
    /// Canonical slash-prefixed LDP path (`"/alice/profile.ttl"`, `"/alice/"`, `"/"`).
    pub canonical_path: String,
    /// Key inside `PodCatalog.entries` (always a canonical slash-prefixed LDP path).
    pub catalog_key: String,
    /// Canonical `wolin://...` display URI returned to MCP clients.
    pub display_uri: String,
    /// Canonical leaf-normalized `ResourceUri` evaluated by `PolicyEngine`.
    pub policy_target: ResourceUri,
    /// Named graph IRI in `SemanticGraphStore`.
    pub graph_iri: String,
    /// Physical blob key in `PhysicalStore`.
    pub blob_key: String,
    pub is_container: bool,
    pub is_acl: bool,
}

pub fn resolve_pod_uri(
    raw: &str,
    base_url: &str,
    primary_pod_prefix: &str,
    container_hint: bool,
) -> Result<ResolvedPodUri> {
    if raw.is_empty() || raw.len() > MAX_URI_LEN {
        return Err(WolinError::InvalidFormat(
            "Resource URI is empty or exceeds maximum length".to_string(),
        ));
    }
    if raw.bytes().any(|b| {
        b.is_ascii_control() || b.is_ascii_whitespace() || matches!(b, b'\\' | b'?' | b'#')
    }) {
        return Err(WolinError::InvalidFormat(
            "Resource URI must not contain query, fragment, backslash, whitespace, or control characters"
                .to_string(),
        ));
    }

    let clean_base = base_url.trim_end_matches('/');
    let clean_primary = primary_pod_prefix.trim_end_matches('/');

    let raw_path = if raw.starts_with('/') {
        raw
    } else if raw == clean_base {
        "/"
    } else if let Some(rest) = raw.strip_prefix(clean_base) {
        if !rest.starts_with('/') {
            return Err(WolinError::InvalidFormat(format!(
                "Disallowed external origin in URI '{raw}'"
            )));
        }
        rest
    } else if raw == clean_primary {
        "/"
    } else if let Some(rest) = raw.strip_prefix(clean_primary) {
        if !rest.starts_with('/') {
            return Err(WolinError::InvalidFormat(format!(
                "Disallowed foreign Pod authority in URI '{raw}'; expected '{clean_primary}/...'"
            )));
        }
        rest
    } else {
        return Err(WolinError::InvalidFormat(format!(
            "Unsupported or external URI '{raw}'; expected '{clean_primary}/...' or '/...'"
        )));
    };

    let (mut canonical_path, mut is_container, is_acl) = canonicalize_ldp_path(raw_path)?;
    if container_hint && !is_acl && !is_container {
        canonical_path.push('/');
        is_container = true;
    }

    Ok(build_resolved_from_canonical(
        clean_primary,
        &canonical_path,
        is_container,
        is_acl,
        clean_base,
    ))
}

/// Resolve a catalog key (`"/alice/doc.ttl"`) back into [`ResolvedPodUri`].
pub fn resolve_catalog_key(
    catalog_key: &str,
    base_url: &str,
    primary_pod_prefix: &str,
) -> Result<ResolvedPodUri> {
    resolve_pod_uri(catalog_key, base_url, primary_pod_prefix, false)
}

/// Fail-closed mapper from a `SemanticGraphStore` named graph IRI to a canonical [`ResolvedPodUri`].
/// Rejects `.acl` governance graphs (including percent-encoded `.%61cl`), reserved system paths,
/// and any malformed or foreign origin IRIs by returning `None`.
pub fn map_named_graph_to_resolved_uri(
    graph_iri: &str,
    base_url: &str,
    primary_pod_prefix: &str,
) -> Option<ResolvedPodUri> {
    let resolved = resolve_pod_uri(graph_iri, base_url, primary_pod_prefix, false).ok()?;
    if resolved.is_acl {
        return None;
    }
    Some(resolved)
}

fn canonicalize_ldp_path(raw_path: &str) -> Result<(String, bool, bool)> {
    if raw_path == "/" {
        return Ok(("/".to_string(), true, false));
    }
    if !raw_path.starts_with('/') {
        return Err(WolinError::InvalidFormat(
            "Pod path must begin with '/'".to_string(),
        ));
    }

    let is_container = raw_path.ends_with('/');
    let trimmed = if is_container {
        &raw_path[1..raw_path.len() - 1]
    } else {
        &raw_path[1..]
    };

    if trimmed.is_empty() || trimmed.ends_with('/') {
        return Err(WolinError::InvalidFormat(
            "Empty '//' path segment rejected".to_string(),
        ));
    }

    let raw_segments: Vec<&str> = trimmed.split('/').collect();
    let mut decoded_segments = Vec::with_capacity(raw_segments.len());

    for (idx, seg) in raw_segments.iter().enumerate() {
        if seg.is_empty() {
            return Err(WolinError::InvalidFormat(
                "Empty '//' interior path segment rejected".to_string(),
            ));
        }
        let decoded = decode_uri_segment(seg)?;
        if idx == 0
            && (decoded == RESERVED_META_SEG
                || decoded.starts_with("__wolin_")
                || decoded == ".well-known"
                || decoded == "health"
                || decoded == "healthz"
                || decoded == "mcp"
                || decoded == "api")
        {
            return Err(WolinError::InvalidFormat(format!(
                "Reserved system path segment '{decoded}' cannot be accessed"
            )));
        }
        let is_last = idx + 1 == raw_segments.len();
        if decoded.ends_with(".acl") && (!is_last || is_container || decoded.ends_with(".acl.acl"))
        {
            return Err(WolinError::InvalidFormat(
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
    if is_container {
        canonical.push('/');
    }

    let _ = PodStoreManager::pod_id_from_canonical_path(&canonical)?;
    let is_acl = canonical.ends_with(".acl");
    Ok((canonical, is_container, is_acl))
}

fn build_resolved_from_canonical(
    pod_prefix: &str,
    canonical_path: &str,
    is_container: bool,
    is_acl: bool,
    clean_base: &str,
) -> ResolvedPodUri {
    let catalog_key = canonical_path.to_string();

    let display_uri = if canonical_path == "/" {
        format!("{pod_prefix}/")
    } else {
        format!("{pod_prefix}{canonical_path}")
    };

    let policy_uri_str = if canonical_path == "/" || canonical_path == "/.acl" {
        pod_prefix.to_string()
    } else if let Some(container_prefix) = canonical_path.strip_suffix("/.acl") {
        format!("{pod_prefix}{container_prefix}")
    } else if let Some(governed_leaf) = canonical_path.strip_suffix(".acl") {
        format!("{pod_prefix}{governed_leaf}")
    } else if canonical_path.ends_with('/') {
        format!("{pod_prefix}{}", canonical_path.trim_end_matches('/'))
    } else {
        format!("{pod_prefix}{canonical_path}")
    };

    let graph_iri = http_iri(clean_base, canonical_path);
    let blob_key = format!("blobs/{}", canonical_path.trim_matches('/'));

    ResolvedPodUri {
        pod_prefix: pod_prefix.to_string(),
        canonical_path: canonical_path.to_string(),
        catalog_key,
        display_uri,
        policy_target: ResourceUri(policy_uri_str),
        graph_iri,
        blob_key,
        is_container,
        is_acl,
    }
}

fn decode_uri_segment(seg: &str) -> Result<String> {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = seg.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return Err(WolinError::InvalidFormat(
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
                return Err(WolinError::InvalidFormat(
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

    let s = String::from_utf8(out).map_err(|_| {
        WolinError::InvalidFormat("Non-UTF-8 percent-encoded URI segment".to_string())
    })?;
    if s == "." || s == ".." {
        return Err(WolinError::InvalidFormat(
            "Relative dot path traversal segment rejected".to_string(),
        ));
    }
    Ok(s)
}

fn is_unreserved_or_pchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b':' | b'@')
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(WolinError::InvalidFormat(
            "Malformed hex digit in percent-encoding".to_string(),
        )),
    }
}

pub fn http_iri(base_url: &str, canonical_path: &str) -> String {
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

/// Deterministic 128-bit dual FNV-1a content fingerprint matching `wolin-server`'s strong ETag format.
pub fn compute_etag(bytes: &[u8]) -> String {
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

/// RFC 4648 standard Base64 encoder.
pub fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
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
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}

/// RFC 4648 standard Base64 decoder (tolerates optional ASCII whitespace, rejects malformed padding).
pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if clean.is_empty() {
        return Ok(Vec::new());
    }
    if !clean.len().is_multiple_of(4) {
        return Err(WolinError::InvalidFormat(
            "Invalid base64 payload length (must be a multiple of 4)".to_string(),
        ));
    }

    let val = |b: u8| -> Result<u8> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(WolinError::InvalidFormat(
                "Invalid character in base64 payload".to_string(),
            )),
        }
    };

    let mut out = Vec::with_capacity((clean.len() / 4) * 3);
    let (quads, _) = clean.as_chunks::<4>();
    let chunks = quads.len();
    for (idx, chunk) in quads.iter().enumerate() {
        let is_last = idx + 1 == chunks;
        let pad = chunk.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 || (pad > 0 && !is_last) {
            return Err(WolinError::InvalidFormat(
                "Invalid '=' padding in base64 payload".to_string(),
            ));
        }
        if chunk[..4 - pad].contains(&b'=') {
            return Err(WolinError::InvalidFormat(
                "Non-trailing '=' padding in base64 payload".to_string(),
            ));
        }

        let a = val(chunk[0])? as u32;
        let b = val(chunk[1])? as u32;
        match pad {
            0 => {
                let c = val(chunk[2])? as u32;
                let d = val(chunk[3])? as u32;
                let n = (a << 18) | (b << 12) | (c << 6) | d;
                out.push(((n >> 16) & 0xff) as u8);
                out.push(((n >> 8) & 0xff) as u8);
                out.push((n & 0xff) as u8);
            }
            1 => {
                let c = val(chunk[2])? as u32;
                let n = (a << 18) | (b << 12) | (c << 6);
                out.push(((n >> 16) & 0xff) as u8);
                out.push(((n >> 8) & 0xff) as u8);
            }
            2 => {
                let n = (a << 18) | (b << 12);
                out.push(((n >> 16) & 0xff) as u8);
            }
            _ => unreachable!(),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_base64_roundtrip_and_rejects_malformed_padding() {
        for len in 0..=17usize {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
            let enc = base64_encode(&data);
            let dec = base64_decode(&enc).expect("valid base64 roundtrip");
            assert_eq!(dec, data);
        }
        assert!(base64_decode("abc").is_err());
        assert!(base64_decode("ab=c").is_err());
        assert!(base64_decode("====").is_err());
        assert!(base64_decode("ab$d").is_err());
    }

    #[test]
    fn unit_named_graph_mapper_blocks_encoded_acl_system_and_foreign_authorities() {
        for blocked in [
            "http://pod.wolin.local/alice/.acl",
            "http://pod.wolin.local/alice/.%61cl",
            "http://pod.wolin.local/alice/.acl/",
            "http://pod.wolin.local/__wolin_meta/catalog.json",
            "http://pod.wolin.local/.well-known/wolin",
            "http://pod.wolin.local/health",
            "http://pod.wolin.local/mcp",
            "http://pod.wolin.local/%6dcp",
            "wolin://foreign_pod/alice/doc.ttl",
            "wolin://../escape/doc.ttl",
            "https://external.example/alice/.%61cl",
        ] {
            assert!(
                map_named_graph_to_resolved_uri(blocked, "http://pod.wolin.local", "wolin://pod")
                    .is_none(),
                "expected graph IRI '{blocked}' to be rejected fail-closed"
            );
        }
    }
}
