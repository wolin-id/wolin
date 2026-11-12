//! Wolin Storage: Dual-plane storage combining physical blob/file backend (OpenDAL)
//! and semantic RDF graph store (Oxigraph).

pub mod graph;
pub mod physical;

pub use graph::{
    ConstructGraph, RdfTerm, RdfTriple, SemanticGraphStore, SparqlBindingRow, SparqlBindingSet,
    SparqlQueryOutput,
};
pub use oxigraph::model as rdf_model;
pub use physical::{BlobMetadata, PhysicalStore};
