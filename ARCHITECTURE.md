# WOLIN (月印) System Architecture
> **Universal Identity & Persistence Fabric for the AI Agent Era**

---

## 1. Multi-Crate Monorepo Structure

```
wolin/
├── Cargo.toml                  # Workspace Root
├── VISION.md                   # Core Philosophy & Human-Centric Web3 Vision
├── ARCHITECTURE.md             # Technical Architecture Specification
└── crates/
    ├── wolin-core/             # Core types, WebId, Principal, ResourceUri, Errors
    ├── wolin-storage/          # OpenDAL (Physical Blob/FS) + Oxigraph (RDF Triples/SPARQL)
    ├── wolin-identity/         # WebID discovery, W3C DID, ZITADEL OIDC & DPoP
    ├── wolin-policy/           # WAC/ACP Rule Engine, PDP/PEP, Dynamic Delegation
    ├── wolin-mcp/              # Native MCP (Model Context Protocol) Server for AI Agents
    └── wolin-server/           # Axum + Tokio HTTP LDP and MCP Integrated Server Runtime
```

---

## 2. Component Interaction & Flow

### AI Agent Access Scenario
1. **Agent Handshake:** AI Agent requests access to user data via MCP over HTTP/SSE.
2. **Identity & Scope Resolution:** Agent presents delegated token (DPoP or OIDC JWT signed by User).
3. **Policy Decision (`wolin-policy`):** PDP checks if the requested action conforms to the user's consent policy.
4. **Semantic Projection:** Oxigraph generates a targeted, zero-PII sub-graph projection rather than exposing the whole database.
5. **Execution:** Response is returned to the agent in structured JSON/RDF via MCP tool result.
