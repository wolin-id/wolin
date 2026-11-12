# Wolin Engine (월인 엔진)
> **One Identity. Infinite Reflections.** — Sovereign Pod Cloud Engine & Native AI Agent MCP Runtime

Wolin Engine은 W3C Solid Protocol 및 Decentralized Identity(DID/WebID), Semantic RDF/SPARQL 1.1, Dynamic Delegation(RFC 8693), 그리고 Native AI Agent MCP(Model Context Protocol) 런타임을 통합한 초경량 단일 바이너리 분산 데이터 주권 엔진입니다.

---

## 1. Crate Architecture

```
wolin-engine/
├── crates/
│   ├── wolin-core/       # Domain primitives: WebId, Principal, ResourceUri, WolinError
│   ├── wolin-storage/    # Dual-plane: OpenDAL (Blob) + Oxigraph (RDF/SPARQL)
│   ├── wolin-identity/   # W3C DID Resolver & ZITADEL/Solid-OIDC JWT Validator
│   ├── wolin-policy/     # WAC (.acl) & ACP (Access Control Policy) Dual PDP
│   ├── wolin-mcp/        # JSON-RPC 2.0 MCP Gateway & Zero-PII Selective Disclosure
│   └── wolin-server/     # Axum 0.8 LDP + MCP Unified Runtime & Daemon
```

## 2. Hard Performance Metrics

* **Single Static Binary**: 17 MiB (Embedded Oxigraph RocksDB, OpenDAL, Axum 0.8, Rustls)
* **Memory Footprint**:
  * Ephemeral In-Memory: **15.3 MiB RSS** (5.88ms startup)
  * Persistent RocksDB + FS: **21.4 MiB RSS** (idle) ➔ **23.9 MiB RSS** (under live LDP + MCP workload)
* **Test Coverage**: 56/56 passing tests across the workspace.

## 3. Quickstart

```bash
# Debug build and test
cargo test --locked --workspace

# Run server on port 8080
cargo run -p wolin-server -- --port 8080 --storage-dir ./data/wolin
```
