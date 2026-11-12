use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceUri(pub String);

impl std::fmt::Display for ResourceUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceKind {
    /// LDP Basic Container / Directory
    Container,
    /// LDP RDF Source (Turtle, JSON-LD)
    RdfSource,
    /// Non-RDF Source (Binary, PDF, Image)
    NonRdfSource,
}
