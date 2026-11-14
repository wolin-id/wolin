# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Security Architecture

Wolin enforces strict zero-trust boundaries across its runtime:
- **Authentication**: Solid-OIDC + RFC 9449 DPoP proof-of-possession with replay protection, plus OIDC / ZITADEL JWT validation.
- **Authorization**: Deterministic W3C WAC / ACP dual Policy Decision Point (`wolin-policy`) with explicit deny precedence.
- **Tenant Isolation**: Subdomain origin isolation (`{pod_id}.{pod_cloud_domain}`) for multi-tenant Pod Cloud deployments.
- **Memory Safety**: Pure Rust AOT runtime with zero unsafe deserialization on untrusted RDF or HTTP payloads.

## Reporting a Vulnerability (Private Vulnerability Reporting)

Please **do not** report security vulnerabilities through public GitHub issues or pull requests.

Instead, submit a private report via **GitHub Security Advisories**:
- https://github.com/wolin-id/wolin/security/advisories/new

### Response SLA
- **Acknowledgment**: Within 48 hours of report submission.
- **Triage & Initial Assessment**: Within 5 business days.
- **Coordinated Disclosure**: We will work with you to validate, patch, and publish a security advisory before public disclosure.
