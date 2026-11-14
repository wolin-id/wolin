<div align="center">

# Wolin (月印千江)

**One Identity. Infinite Reflections. — Sovereign W3C Solid 0.11 Pod Cloud & Self-Hosted Engine in Rust**

**[ English ](README.md)** • **[ 한국어 ](README.ko.md)**

</div>

---

Wolin (`wolin-id/wolin`) is an ultra-lightweight, single-binary Rust engine implementing **W3C Solid 0.11**, **Solid-OIDC + RFC 9449 DPoP**, **Oxigraph RDF/SPARQL 1.1**, **Apache OpenDAL**, and **W3C WAC/ACP Policy Enforcement**.

It serves as both:
1. **Self-Hosted Sovereign Pod Server** for home servers, NAS devices, and enterprise on-premises deployments.
2. **Multi-Tenant Data Plane** powering the managed Wolin Pod Cloud ([wolin.id](https://wolin.id)).

---

## 1. Crate Architecture

```text
wolin/
├── crates/
│   ├── wolin-core/       # Domain primitives: WebId, Principal, ResourceUri, WolinError
│   ├── wolin-storage/    # Dual-plane: Apache OpenDAL (Blob) + Oxigraph (RDF/SPARQL 1.1)
│   ├── wolin-identity/   # W3C DID, Solid-OIDC + DPoP, ZITADEL/OIDC JWT Validator
│   ├── wolin-policy/     # W3C WAC (.acl) & ACP (Access Control Policy) Dual PDP
│   ├── wolin-mcp/        # Scoped semantic projection gateway & Zero-PII disclosure
│   └── wolin-server/     # Axum 0.8 + Tokio Solid LDP, /.well-known/wolin, Multi-Tenant Daemon
```

## 2. Verified Performance & Footprint

- **Single Static Binary**: ~17 MiB (Embedded Oxigraph RocksDB, OpenDAL, Axum 0.8, Rustls)
- **Memory Footprint**:
  - Ephemeral In-Memory: **15.3 MiB RSS** (~5.9 ms startup)
  - Persistent RocksDB + FS: **21.4 MiB RSS** (idle) / **23.9 MiB RSS** (under live workload)
- **Workspace Verification**: **63/63** passing unit & integration tests (`cargo test --locked --workspace`).

## 3. Quickstart

```bash
# Run full workspace test suite
cargo test --locked --workspace

# Start a persistent self-hosted Pod server with a custom domain
cargo run --release -p wolin-server -- \
  --host 0.0.0.0 \
  --port 4000 \
  --storage-dir ./data/wolin \
  --base-url https://pod.example.org \
  --pod-cloud-domain example.org
```

## 4. Related Repositories

- **Web Portal**: [`wolin-id/web`](https://github.com/wolin-id/web) ([wolin.id](https://wolin.id))
- **Specifications & Strategy**: [`wolin-id/docs`](https://github.com/wolin-id/docs)

## 5. License

Dual-licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
