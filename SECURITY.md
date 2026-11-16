# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Security Architecture

Wolin (月印千江) enforces strict zero-trust boundaries across its runtime:
- **Authentication**: Solid-OIDC + RFC 9449 DPoP proof-of-possession with `jti` replay protection, cryptographic `JwksSignatureVerifier` (`ES256`/`ES384`/`RS256`/`PS256`/`EdDSA`), and `typ: "at+jwt"` enforcement blocking `id_token` confusion.
- **Authorization**: Deterministic W3C WAC / ACP dual Policy Decision Point (`wolin-policy`) with explicit deny precedence, verified before any binary `302` `HMAC-SHA256` (`wolin-asset-v1`) Edge/R2 offload token is minted.
- **Tenant & Handle Isolation**: Subdomain origin isolation (`{pod_id}.{pod_cloud_domain}`), per-Pod physical Oxigraph RocksDB stores with bounded LRU (`256`) and `1 GiB` storage quotas, ~180 reserved handles, and permanent Tombstone defense-in-depth (`410 Gone`).
- **Memory Safety**: Pure Rust AOT runtime with zero unsafe deserialization on untrusted RDF or HTTP payloads.

## Reporting a Vulnerability (Private Vulnerability Reporting)

Please **do not** report security vulnerabilities through public GitHub issues or pull requests.

Instead, submit a private report via **GitHub Security Advisories**:
- https://github.com/wolin-id/wolin/security/advisories/new

### Response SLA
- **Acknowledgment**: Within 48 hours of report submission.
- **Triage & Initial Assessment**: Within 5 business days.
- **Coordinated Disclosure**: We will work with you to validate, patch, and publish a security advisory before public disclosure.
