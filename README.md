<div align="center">

# Wolin (月印千江)

**One Identity. Infinite Reflections. — Sovereign W3C Solid 0.11 Pod Cloud & Self-Hosted Engine in Rust**

**[ English ](README.md)** • **[ 한국어 ](README.ko.md)**

</div>

---

Wolin (`wolin-id/wolin`) is an ultra-lightweight, single-binary Rust engine implementing **W3C Solid 0.11**, **Solid-OIDC + RFC 9449 DPoP (`at+jwt`)**, **Per-Pod Oxigraph RDF/SPARQL 1.1**, **Apache OpenDAL**, **W3C WAC/ACP Policy Enforcement**, and **Native MCP (`/mcp`, `/mcp/sse`)**.

It serves as both:
1. **Self-Hosted Sovereign Pod Server** for home servers, Raspberry Pi / ARM64 mini-PCs, NAS devices, and enterprise on-premises deployments.
2. **Multi-Tenant Production Data Plane** powering Wolin Pod Cloud (`https://pod.wolin.id` & `https://{handle}.wolin.id/`) paired with the passwordless Solid-OIDC Control Plane (`https://auth.wolin.id`).

---

## 1. Crate Architecture

```text
wolin/
├── crates/
│   ├── wolin-core/       # Domain primitives: WebId, Principal, ResourceUri, WolinError
│   ├── wolin-storage/    # OpenDAL (Blob/FS/R2) + Per-Pod Oxigraph RocksDB (Bounded LRU 256 + 1 GiB Quota)
│   ├── wolin-identity/   # W3C DID, Solid-OIDC, JwksSignatureVerifier, RFC 9449 DPoP & at+jwt Guard
│   ├── wolin-policy/     # W3C WAC (.acl) & Inrupt ACP Dual PDP + Scoped DelegationGrant
│   ├── wolin-mcp/        # Scoped semantic projection gateway & Zero-PII disclosure (/mcp, /mcp/sse)
│   └── wolin-server/     # Axum 0.8 + Tokio Solid LDP, Multi-Tenant Router, Tombstones & 302 Asset Offload
```

## 2. Production Capabilities & Verified Footprint

- **Per-Pod Physical Isolation & Quotas**: Dedicated Oxigraph RocksDB per Pod (`graph/pods/{pod_id}/`), bounded LRU handle cache (`256` default via `WOLIN_MAX_OPEN_PODS`), and atomic `1 GiB` per-Pod storage quota (`$0` Free Tier default, `413`/`507` enforcement).
- **Handle Security & Permanent Tombstones**: Enforces `3..32` lowercase ASCII handle rules, ~180 built-in reserved handles (+ `--reserved-pods`), and permanent Tombstone defense-in-depth (`410 Gone` on retired Pods).
- **Zero-Egress Signed Asset Offload**: Validates DPoP + WAC/ACP first, then issues a 60-second `HMAC-SHA256` (`wolin-asset-v1`) `302 Found` redirect (`>= 256 KiB` `NonRDFSource`) for direct Cloudflare R2 edge streaming (`/assets/:pod_id/*`).
- **Cryptographic JWKS & `at+jwt` Verification**: `JwksSignatureVerifier` (`--oidc-jwks-json` / `WOLIN_OIDC_JWKS_JSON` supporting `ES256`, `ES384`, `RS256`, `PS256`, `EdDSA`), DPoP `jti` replay cache, and strict `typ: "at+jwt"` enforcement blocking `id_token` confusion.
- **Verified Footprint & Test Suite**:
  - Single Static Binary: **~17–23 MiB** (Embedded Oxigraph RocksDB, OpenDAL, Axum 0.8, Rustls)
  - Memory Footprint: **15.3 MiB RSS** (`--in-memory`, ~5.9 ms startup) / **21.4 MiB RSS** (persistent idle)
  - Workspace Verification: **85/85** passing unit & integration tests (`cargo test --locked --workspace`).

## 3. Quickstart (`--in-memory` Sandbox & Self-Hosting)

> Wolin does **not** require a separate public devnet: use `wolin-server --in-memory` for instant offline/local development, or claim a **`$0` Free Tier (`1 GiB`)** Pod on [`https://auth.wolin.id`](https://auth.wolin.id) / [`https://pod.wolin.id`](https://pod.wolin.id). For Docker Compose, Caddy automatic HTTPS, Cloudflare Tunnel, and `systemd`, see **[docs/SELF_HOSTING.md](docs/SELF_HOSTING.md)**.

```bash
# Run full workspace test suite (85 tests)
cargo test --locked --workspace

# 1. Zero-config local ephemeral sandbox (~6 ms startup, zero disk state)
cargo run --release -p wolin-server -- --in-memory --port 4000

# 2. Persistent self-hosted Pod server with a custom domain
cargo run --release -p wolin-server -- \
  --host 0.0.0.0 \
  --port 4000 \
  --storage-dir ./data/wolin \
  --base-url https://pod.example.org \
  --pod-cloud-domain example.org
```

## 4. Official SDKs & Ecosystem Repositories

- **Web Portal & Developer Hub**: [`wolin-id/web`](https://github.com/wolin-id/web) ([wolin.id](https://wolin.id), `/llms.txt`, `/llms-full.txt`)
- **Specifications & Strategy**: [`wolin-id/docs`](https://github.com/wolin-id/docs)
- **AI Coding Agent Skills**: [`wolin-id/skills`](https://github.com/wolin-id/skills)
- **3D Metaverse Starter**: [`wolin-id/metaverse-starter`](https://github.com/wolin-id/metaverse-starter)
- **5 Official SDKs**:
  - TypeScript / React: [`wolin-id/sdk-js`](https://github.com/wolin-id/sdk-js) (`@wolin-id/client`, `@wolin-id/react`)
  - Python 3.11+: [`wolin-id/sdk-python`](https://github.com/wolin-id/sdk-python) (`wolin-id`)
  - Unity C#: [`wolin-id/sdk-unity`](https://github.com/wolin-id/sdk-unity) (`id.wolin.unity`)
  - Swift 6: [`wolin-id/sdk-swift`](https://github.com/wolin-id/sdk-swift) (`WolinKit`)
  - Kotlin / Android / JVM: [`wolin-id/sdk-kotlin`](https://github.com/wolin-id/sdk-kotlin) (`id.wolin:sdk-kotlin`)

## 5. License

Dual-licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
