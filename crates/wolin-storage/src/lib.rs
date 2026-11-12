//! Wolin Storage: Dual-plane storage combining physical blob/file backend (OpenDAL)
//! and semantic RDF graph store (Oxigraph).

pub mod graph;
pub mod physical;

pub use graph::SemanticGraphStore;
pub use physical::PhysicalStore;
