//! Wolin Storage: Dual-plane storage combining physical blob/file backend (OpenDAL)
//! and semantic RDF graph store (Oxigraph).

pub mod graph;
pub mod physical;
pub mod pod_manager;

pub use graph::{
    ConstructGraph, RdfTerm, RdfTriple, SemanticGraphStore, SparqlBindingRow, SparqlBindingSet,
    SparqlQueryOutput,
};
pub use oxigraph::io as rdf_io;
pub use oxigraph::model as rdf_model;
pub use oxigraph::sparql as rdf_sparql;
pub use physical::{BlobMetadata, PhysicalStore};
pub use pod_manager::{
    DEFAULT_MAX_OPEN_PODS, DEFAULT_POD_QUOTA_BYTES, PodGraphHandle, PodStoreManager,
};
