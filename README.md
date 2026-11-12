# Wolin (월인 · 月印)

> **Universal Identity & Persistence Fabric**  
> *"One Identity. Infinite Reflections."*

Wolin is a high-performance, Rust-native decentralized identity and persistent semantic data fabric designed for the AI Agent era.

## Core Features
- **Sovereign Data Storage:** W3C Solid Protocol compliant Pods powered by Apache OpenDAL and Oxigraph.
- **Agent-Native MCP Interface:** Direct Model Context Protocol (MCP) gateway enabling AI Agents to query and mutate data under fine-grained user consent.
- **Federated Trust Mesh:** Seamlessly unifies Enterprise IAM (ZITADEL, Keycloak) with decentralized identity (W3C DID, WebID, DPoP).
- **Zero Garbage-Collection & Minimal Footprint:** Engineered in Rust AOT to run smoothly on edge nodes (RAM < 30MB) and cloud clusters alike.

## Building & Testing

```bash
cargo build
cargo test
```

## Documentation
- [VISION.md](VISION.md): The philosophical and technical imperative for human-centric Web3.
- [ARCHITECTURE.md](ARCHITECTURE.md): Multi-crate modular architecture and execution specs.
