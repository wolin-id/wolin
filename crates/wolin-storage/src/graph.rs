use std::collections::BTreeMap;
use std::path::Path;

use oxigraph::io::{RdfFormat, RdfParser, RdfSerializer};
use oxigraph::model::{
    BlankNode, GraphNameRef, Literal, NamedNode, NamedNodeRef, Quad, QuadRef, Subject, Term, Triple,
};
use oxigraph::sparql::QueryResults;
use oxigraph::store::Store;
use serde::{Deserialize, Serialize};
use wolin_core::{Result, WolinError};

/// Structured representation of an RDF 1.1 Term.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RdfTerm {
    Iri {
        value: String,
    },
    BlankNode {
        id: String,
    },
    Literal {
        value: String,
        datatype: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        language: Option<String>,
    },
    QuotedTriple {
        triple: Box<RdfTriple>,
    },
}

impl RdfTerm {
    pub fn iri(value: impl Into<String>) -> Self {
        Self::Iri {
            value: value.into(),
        }
    }

    pub fn blank_node(id: impl Into<String>) -> Self {
        Self::BlankNode { id: id.into() }
    }

    pub fn simple_literal(value: impl Into<String>) -> Self {
        Self::Literal {
            value: value.into(),
            datatype: "http://www.w3.org/2001/XMLSchema#string".to_string(),
            language: None,
        }
    }

    /// Return the primary string value (IRI string, blank node ID, or literal lexical form).
    pub fn as_str(&self) -> &str {
        match self {
            Self::Iri { value } => value.as_str(),
            Self::BlankNode { id } => id.as_str(),
            Self::Literal { value, .. } => value.as_str(),
            Self::QuotedTriple { triple } => triple.predicate.as_str(),
        }
    }

    pub fn is_iri(&self) -> bool {
        matches!(self, Self::Iri { .. })
    }

    pub fn is_blank_node(&self) -> bool {
        matches!(self, Self::BlankNode { .. })
    }

    pub fn is_literal(&self) -> bool {
        matches!(self, Self::Literal { .. })
    }
}

impl From<&Term> for RdfTerm {
    fn from(term: &Term) -> Self {
        match term {
            Term::NamedNode(node) => Self::Iri {
                value: node.as_str().to_string(),
            },
            Term::BlankNode(bnode) => Self::BlankNode {
                id: bnode.as_str().to_string(),
            },
            Term::Literal(lit) => Self::Literal {
                value: lit.value().to_string(),
                datatype: lit.datatype().as_str().to_string(),
                language: lit.language().map(str::to_string),
            },
            Term::Triple(triple) => Self::QuotedTriple {
                triple: Box::new(RdfTriple::from(triple.as_ref())),
            },
        }
    }
}

impl From<Term> for RdfTerm {
    fn from(term: Term) -> Self {
        Self::from(&term)
    }
}

impl From<&Subject> for RdfTerm {
    fn from(subject: &Subject) -> Self {
        match subject {
            Subject::NamedNode(node) => Self::Iri {
                value: node.as_str().to_string(),
            },
            Subject::BlankNode(bnode) => Self::BlankNode {
                id: bnode.as_str().to_string(),
            },
            Subject::Triple(triple) => Self::QuotedTriple {
                triple: Box::new(RdfTriple::from(triple.as_ref())),
            },
        }
    }
}

impl From<Subject> for RdfTerm {
    fn from(subject: Subject) -> Self {
        Self::from(&subject)
    }
}

impl TryFrom<&RdfTerm> for Term {
    type Error = WolinError;

    fn try_from(term: &RdfTerm) -> Result<Self> {
        match term {
            RdfTerm::Iri { value } => NamedNode::new(value.as_str())
                .map(Term::NamedNode)
                .map_err(|e| WolinError::InvalidFormat(format!("Invalid IRI '{value}': {e}"))),
            RdfTerm::BlankNode { id } => BlankNode::new(id.as_str())
                .map(Term::BlankNode)
                .map_err(|e| WolinError::InvalidFormat(format!("Invalid blank node '{id}': {e}"))),
            RdfTerm::Literal {
                value,
                datatype,
                language,
            } => {
                if let Some(lang) = language {
                    Literal::new_language_tagged_literal(value.as_str(), lang.as_str())
                        .map(Term::Literal)
                        .map_err(|e| {
                            WolinError::InvalidFormat(format!("Invalid language tag '{lang}': {e}"))
                        })
                } else {
                    let dt = NamedNode::new(datatype.as_str()).map_err(|e| {
                        WolinError::InvalidFormat(format!("Invalid datatype IRI '{datatype}': {e}"))
                    })?;
                    Ok(Term::Literal(Literal::new_typed_literal(
                        value.as_str(),
                        dt,
                    )))
                }
            }
            RdfTerm::QuotedTriple { triple } => {
                Ok(Term::Triple(Box::new(Triple::try_from(triple.as_ref())?)))
            }
        }
    }
}

/// Structured RDF triple (`subject`, `predicate` IRI, `object`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RdfTriple {
    pub subject: RdfTerm,
    pub predicate: String,
    pub object: RdfTerm,
}

impl From<&Triple> for RdfTriple {
    fn from(triple: &Triple) -> Self {
        Self {
            subject: RdfTerm::from(&triple.subject),
            predicate: triple.predicate.as_str().to_string(),
            object: RdfTerm::from(&triple.object),
        }
    }
}

impl From<Triple> for RdfTriple {
    fn from(triple: Triple) -> Self {
        Self::from(&triple)
    }
}

impl TryFrom<&RdfTriple> for Triple {
    type Error = WolinError;

    fn try_from(triple: &RdfTriple) -> Result<Self> {
        let subject = match &triple.subject {
            RdfTerm::Iri { value } => {
                Subject::NamedNode(NamedNode::new(value.as_str()).map_err(|e| {
                    WolinError::InvalidFormat(format!("Invalid subject IRI '{value}': {e}"))
                })?)
            }
            RdfTerm::BlankNode { id } => {
                Subject::BlankNode(BlankNode::new(id.as_str()).map_err(|e| {
                    WolinError::InvalidFormat(format!("Invalid subject blank node '{id}': {e}"))
                })?)
            }
            RdfTerm::QuotedTriple { triple } => {
                Subject::Triple(Box::new(Triple::try_from(triple.as_ref())?))
            }
            RdfTerm::Literal { .. } => {
                return Err(WolinError::InvalidFormat(
                    "RDF triple subject cannot be a literal".to_string(),
                ));
            }
        };
        let predicate = NamedNode::new(triple.predicate.as_str()).map_err(|e| {
            WolinError::InvalidFormat(format!("Invalid predicate IRI '{}': {e}", triple.predicate))
        })?;
        let object = Term::try_from(&triple.object)?;
        Ok(Triple::new(subject, predicate, object))
    }
}

/// Single row of variable bindings returned by a SPARQL `SELECT` query.
pub type SparqlBindingRow = BTreeMap<String, RdfTerm>;

/// Structured binding set returned by a SPARQL `SELECT` query.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SparqlBindingSet {
    pub variables: Vec<String>,
    pub rows: Vec<SparqlBindingRow>,
}

impl SparqlBindingSet {
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, SparqlBindingRow> {
        self.rows.iter()
    }
}

/// Structured RDF graph returned by a SPARQL `CONSTRUCT` or `DESCRIBE` query.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ConstructGraph {
    pub triples: Vec<RdfTriple>,
}

impl ConstructGraph {
    pub fn len(&self) -> usize {
        self.triples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.triples.is_empty()
    }

    /// Serialize the constructed graph into N-Triples format.
    pub fn to_ntriples(&self) -> Result<String> {
        self.serialize(RdfFormat::NTriples)
    }

    /// Serialize the constructed graph into Turtle format.
    pub fn to_turtle(&self) -> Result<String> {
        self.serialize(RdfFormat::Turtle)
    }

    fn serialize(&self, format: RdfFormat) -> Result<String> {
        let mut serializer = RdfSerializer::from_format(format).for_writer(Vec::new());
        for rdf_triple in &self.triples {
            let triple = Triple::try_from(rdf_triple)?;
            serializer
                .serialize_triple(&triple)
                .map_err(|e| WolinError::Semantic(format!("RDF serialization error: {e}")))?;
        }
        let bytes = serializer
            .finish()
            .map_err(|e| WolinError::Semantic(format!("RDF serialization finalize error: {e}")))?;
        String::from_utf8(bytes)
            .map_err(|e| WolinError::Internal(format!("Invalid UTF-8 in serialized RDF: {e}")))
    }
}

/// Unified output of an arbitrary SPARQL 1.1 query (`SELECT`, `CONSTRUCT`/`DESCRIBE`, `ASK`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "query_type", rename_all = "snake_case")]
pub enum SparqlQueryOutput {
    Select(SparqlBindingSet),
    Construct(ConstructGraph),
    Ask { value: bool },
}

/// Semantic RDF graph & SPARQL 1.1 store backed by Oxigraph.
#[derive(Clone)]
pub struct SemanticGraphStore {
    store: Store,
}

impl SemanticGraphStore {
    /// Create an isolated in-memory RDF dataset store.
    pub fn new_in_memory() -> Result<Self> {
        let store =
            Store::new().map_err(|e| WolinError::Semantic(format!("Oxigraph init failed: {e}")))?;
        Ok(Self { store })
    }

    /// Open or create a persistent RocksDB-backed RDF store on disk.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let store = Store::open(path)
            .map_err(|e| WolinError::Semantic(format!("Oxigraph open failed: {e}")))?;
        Ok(Self { store })
    }

    /// Access the underlying Oxigraph [`Store`].
    pub fn inner(&self) -> &Store {
        &self.store
    }

    /// Return the total number of quads currently in the store.
    pub fn len(&self) -> Result<usize> {
        self.store
            .len()
            .map_err(|e| WolinError::Semantic(format!("Oxigraph len failed: {e}")))
    }

    /// Return `true` when the store contains zero quads.
    pub fn is_empty(&self) -> Result<bool> {
        self.store
            .is_empty()
            .map_err(|e| WolinError::Semantic(format!("Oxigraph is_empty failed: {e}")))
    }

    /// Parse and atomically insert RDF Turtle triples into the default graph.
    ///
    /// Returns the number of parsed triples inserted in the transaction.
    pub fn insert_turtle(&self, turtle: &str) -> Result<usize> {
        self.insert_turtle_with_options(turtle, None, None)
    }

    /// Parse and atomically insert RDF Turtle triples with an optional `base_iri`
    /// and optional target named graph (`graph_iri`).
    pub fn insert_turtle_with_options(
        &self,
        turtle: &str,
        base_iri: Option<&str>,
        graph_iri: Option<&str>,
    ) -> Result<usize> {
        let mut parser = RdfParser::from_format(RdfFormat::Turtle).without_named_graphs();
        if let Some(base) = base_iri {
            parser = parser.with_base_iri(base).map_err(|e| {
                WolinError::InvalidFormat(format!("Invalid Turtle base IRI '{base}': {e}"))
            })?;
        }
        if let Some(graph) = graph_iri {
            let graph_node = NamedNodeRef::new(graph).map_err(|e| {
                WolinError::InvalidFormat(format!("Invalid target graph IRI '{graph}': {e}"))
            })?;
            parser = parser.with_default_graph(graph_node);
        }
        self.ingest_with_parser(parser, turtle.as_bytes())
    }

    /// Parse and atomically insert N-Triples into the default graph.
    ///
    /// Returns the number of parsed triples inserted in the transaction.
    pub fn insert_ntriples(&self, ntriples: &str) -> Result<usize> {
        let parser = RdfParser::from_format(RdfFormat::NTriples).without_named_graphs();
        self.ingest_with_parser(parser, ntriples.as_bytes())
    }

    /// Parse and atomically insert N-Quads (including named graphs) into the dataset.
    pub fn insert_nquads(&self, nquads: &str) -> Result<usize> {
        let parser = RdfParser::from_format(RdfFormat::NQuads);
        self.ingest_with_parser(parser, nquads.as_bytes())
    }

    /// Insert a single Oxigraph [`Quad`] / [`QuadRef`] into the store.
    ///
    /// Returns `true` if the quad was newly added, or `false` if it was already present.
    pub fn insert_quad<'a>(&self, quad: impl Into<QuadRef<'a>>) -> Result<bool> {
        self.store
            .insert(quad)
            .map_err(|e| WolinError::Semantic(format!("Oxigraph quad insert failed: {e}")))
    }

    /// Atomically insert a batch of Oxigraph [`Quad`]s into the store.
    pub fn insert_quads(&self, quads: impl IntoIterator<Item = impl Into<Quad>>) -> Result<usize> {
        let owned: Vec<Quad> = quads.into_iter().map(Into::into).collect();
        let count = owned.len();
        self.store
            .extend(owned)
            .map_err(|e| WolinError::Semantic(format!("Oxigraph batch quad insert failed: {e}")))?;
        Ok(count)
    }

    /// Remove a single Oxigraph [`Quad`] / [`QuadRef`] from the store.
    pub fn remove_quad<'a>(&self, quad: impl Into<QuadRef<'a>>) -> Result<bool> {
        self.store
            .remove(quad)
            .map_err(|e| WolinError::Semantic(format!("Oxigraph quad remove failed: {e}")))
    }

    /// Execute a SPARQL 1.1 `UPDATE` statement (`INSERT DATA`, `DELETE/INSERT WHERE`, etc.).
    pub fn update(&self, sparql_update: &str) -> Result<()> {
        self.store
            .update(sparql_update)
            .map_err(|e| WolinError::Semantic(format!("SPARQL update failed: {e}")))
    }

    /// Execute a SPARQL 1.1 `SELECT` query and return structured variable bindings.
    pub fn query_select(&self, sparql: &str) -> Result<SparqlBindingSet> {
        match self.execute_sparql(sparql)? {
            SparqlQueryOutput::Select(bindings) => Ok(bindings),
            other => Err(WolinError::InvalidFormat(format!(
                "Expected SPARQL SELECT query, got {}",
                output_kind_name(&other)
            ))),
        }
    }

    /// Execute a SPARQL 1.1 `CONSTRUCT` (or `DESCRIBE`) query and return a structured subgraph.
    pub fn query_construct(&self, sparql: &str) -> Result<ConstructGraph> {
        match self.execute_sparql(sparql)? {
            SparqlQueryOutput::Construct(graph) => Ok(graph),
            other => Err(WolinError::InvalidFormat(format!(
                "Expected SPARQL CONSTRUCT/DESCRIBE query, got {}",
                output_kind_name(&other)
            ))),
        }
    }

    /// Execute a SPARQL 1.1 `ASK` boolean query.
    pub fn query_ask(&self, sparql: &str) -> Result<bool> {
        match self.execute_sparql(sparql)? {
            SparqlQueryOutput::Ask { value } => Ok(value),
            other => Err(WolinError::InvalidFormat(format!(
                "Expected SPARQL ASK query, got {}",
                output_kind_name(&other)
            ))),
        }
    }

    /// Execute any SPARQL 1.1 query (`SELECT`, `CONSTRUCT`/`DESCRIBE`, `ASK`) and return structured output.
    pub fn execute_sparql(&self, sparql: &str) -> Result<SparqlQueryOutput> {
        let results = self
            .store
            .query(sparql)
            .map_err(|e| WolinError::Semantic(format!("SPARQL query failed: {e}")))?;

        match results {
            QueryResults::Solutions(solutions) => {
                let variables = solutions
                    .variables()
                    .iter()
                    .map(|v| v.as_str().to_string())
                    .collect();
                let mut rows = Vec::new();
                for solution in solutions {
                    let solution = solution.map_err(|e| {
                        WolinError::Semantic(format!("SPARQL solution evaluation failed: {e}"))
                    })?;
                    let mut row = SparqlBindingRow::new();
                    for (var, term) in solution.iter() {
                        row.insert(var.as_str().to_string(), RdfTerm::from(term));
                    }
                    rows.push(row);
                }
                Ok(SparqlQueryOutput::Select(SparqlBindingSet {
                    variables,
                    rows,
                }))
            }
            QueryResults::Graph(triples_iter) => {
                let mut triples = Vec::new();
                for triple in triples_iter {
                    let triple = triple.map_err(|e| {
                        WolinError::Semantic(format!("SPARQL graph evaluation failed: {e}"))
                    })?;
                    triples.push(RdfTriple::from(triple));
                }
                Ok(SparqlQueryOutput::Construct(ConstructGraph { triples }))
            }
            QueryResults::Boolean(value) => Ok(SparqlQueryOutput::Ask { value }),
        }
    }

    /// Parse an RDF byte payload (`Turtle`, `NTriples`, `JsonLd`, etc.) into default-graph [`Triple`]s,
    /// resolving relative IRIs against `base_iri` and rejecting named-graph escapes.
    pub fn parse_rdf_triples(
        bytes: &[u8],
        format: RdfFormat,
        base_iri: &str,
    ) -> Result<Vec<Triple>> {
        let parser = RdfParser::from_format(format)
            .without_named_graphs()
            .with_base_iri(base_iri)
            .map_err(|e| {
                WolinError::InvalidFormat(format!("Invalid RDF base IRI '{base_iri}': {e}"))
            })?
            .rename_blank_nodes();

        let mut triples = Vec::new();
        for quad_res in parser.for_slice(bytes) {
            let quad =
                quad_res.map_err(|e| WolinError::InvalidFormat(format!("RDF parse error: {e}")))?;
            triples.push(Triple::from(quad));
        }
        Ok(triples)
    }

    /// Serialize RDF [`Triple`]s into the requested [`RdfFormat`] (`Turtle`, `NTriples`, `JsonLd`).
    pub fn serialize_triples(triples: &[Triple], format: RdfFormat) -> Result<Vec<u8>> {
        let mut serializer = RdfSerializer::from_format(format).for_writer(Vec::new());
        for triple in triples {
            serializer
                .serialize_triple(triple)
                .map_err(|e| WolinError::Semantic(format!("RDF serialization error: {e}")))?;
        }
        serializer
            .finish()
            .map_err(|e| WolinError::Semantic(format!("RDF serialization finalize error: {e}")))
    }

    /// Atomically replace all triples inside named graph `graph_iri` in a single ACID transaction.
    pub fn replace_named_graph_triples(
        &self,
        graph_iri: &str,
        triples: &[Triple],
    ) -> Result<usize> {
        let graph_node = NamedNodeRef::new(graph_iri).map_err(|e| {
            WolinError::InvalidFormat(format!("Invalid named graph IRI '{graph_iri}': {e}"))
        })?;
        let quads: Vec<Quad> = triples
            .iter()
            .map(|t| {
                Quad::new(
                    t.subject.clone(),
                    t.predicate.clone(),
                    t.object.clone(),
                    graph_node,
                )
            })
            .collect();
        let count = quads.len();

        self.store
            .transaction(|mut tx| {
                tx.remove_named_graph(graph_node)?;
                tx.extend(quads.iter())?;
                std::result::Result::<(), oxigraph::store::StorageError>::Ok(())
            })
            .map_err(|e| {
                WolinError::Semantic(format!("Oxigraph named graph replace failed: {e}"))
            })?;
        Ok(count)
    }

    /// Retrieve all [`Triple`]s stored in named graph `graph_iri`.
    pub fn get_named_graph_triples(&self, graph_iri: &str) -> Result<Vec<Triple>> {
        let graph_node = NamedNodeRef::new(graph_iri).map_err(|e| {
            WolinError::InvalidFormat(format!("Invalid named graph IRI '{graph_iri}': {e}"))
        })?;
        let mut triples = Vec::new();
        for quad_res in self.store.quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(graph_node)),
        ) {
            let quad = quad_res
                .map_err(|e| WolinError::Semantic(format!("Oxigraph quad read failed: {e}")))?;
            triples.push(Triple::from(quad));
        }
        Ok(triples)
    }

    /// Delete named graph `graph_iri` and all its triples.
    pub fn delete_named_graph(&self, graph_iri: &str) -> Result<bool> {
        let graph_node = NamedNodeRef::new(graph_iri).map_err(|e| {
            WolinError::InvalidFormat(format!("Invalid named graph IRI '{graph_iri}': {e}"))
        })?;
        self.store
            .remove_named_graph(graph_node)
            .map_err(|e| WolinError::Semantic(format!("Oxigraph remove_named_graph failed: {e}")))
    }

    fn ingest_with_parser(&self, parser: RdfParser, bytes: &[u8]) -> Result<usize> {
        let quads: Vec<Quad> = parser
            .rename_blank_nodes()
            .for_slice(bytes)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| WolinError::InvalidFormat(format!("RDF parse error: {e}")))?;
        let count = quads.len();
        self.store
            .extend(quads)
            .map_err(|e| WolinError::Semantic(format!("Oxigraph RDF ingest failed: {e}")))?;
        Ok(count)
    }
}

fn output_kind_name(output: &SparqlQueryOutput) -> &'static str {
    match output {
        SparqlQueryOutput::Select(_) => "SELECT",
        SparqlQueryOutput::Construct(_) => "CONSTRUCT/DESCRIBE",
        SparqlQueryOutput::Ask { .. } => "ASK",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oxigraph_in_memory_initialization() {
        let store = SemanticGraphStore::new_in_memory().expect("in-memory Oxigraph init");
        assert!(store.is_empty().expect("is_empty check"));
        assert_eq!(store.len().expect("len check"), 0);
    }
}
