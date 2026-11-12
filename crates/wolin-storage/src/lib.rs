//! Wolin Storage: Dual-plane storage combining physical blob/file backend (OpenDAL)
//! and semantic RDF graph store (Oxigraph).

pub mod graph;
pub mod physical;

pub use graph::{
    ConstructGraph, RdfTerm, RdfTriple, SemanticGraphStore, SparqlBindingRow, SparqlBindingSet,
    SparqlQueryOutput,
};
pub use oxigraph::io as rdf_io;
pub use oxigraph::model as rdf_model;
pub use oxigraph::sparql as rdf_sparql;
pub use physical::{BlobMetadata, PhysicalStore};
