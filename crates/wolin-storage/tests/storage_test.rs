use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use wolin_core::WolinError;
use wolin_storage::rdf_model::{GraphName, Literal, NamedNode, Quad};
use wolin_storage::{PhysicalStore, RdfTerm, SemanticGraphStore, SparqlQueryOutput};

struct TempTestDir {
    path: PathBuf,
}

impl TempTestDir {
    fn new(prefix: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let dir_name = format!(
            "wolin_storage_{prefix}_{}_{nanos}_{seq}",
            std::process::id()
        );
        let path = std::env::temp_dir().join(dir_name);
        std::fs::create_dir_all(&path).expect("create temp test dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn path_str(&self) -> &str {
        self.path.to_str().expect("utf-8 temp path")
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[tokio::test]
async fn opendal_memory_blob_crud_and_list() {
    let store = PhysicalStore::new_memory().expect("init memory store");

    assert!(!store.exists("pods/alice/avatar.bin").await.unwrap());
    assert!(matches!(
        store.get("pods/alice/avatar.bin").await,
        Err(WolinError::NotFound(_))
    ));

    // Empty store list returns empty Vec
    assert!(store.list("").await.unwrap().is_empty());

    // Put binary, empty, and nested blobs
    let binary_payload: Vec<u8> = vec![0x00, 0xFF, 0x10, 0x80, 0x42];
    store
        .put_with_content_type(
            "/pods/alice/avatar.bin",
            binary_payload.clone(),
            "application/octet-stream",
        )
        .await
        .unwrap();
    store
        .put("pods/alice/notes/empty.txt", Vec::new())
        .await
        .unwrap();
    store
        .put("pods/alice/notes/daily.md", b"# Wolin Note".to_vec())
        .await
        .unwrap();
    store
        .put(
            "pods/bob/profile.ttl",
            b"<#me> a <http://xmlns.com/foaf/0.1/Person> .".to_vec(),
        )
        .await
        .unwrap();

    assert!(store.exists("pods/alice/avatar.bin").await.unwrap());
    assert_eq!(
        store.get("pods/alice/avatar.bin").await.unwrap(),
        binary_payload
    );
    assert_eq!(
        store.get("pods/alice/notes/empty.txt").await.unwrap(),
        Vec::<u8>::new()
    );

    let meta = store.stat("pods/alice/avatar.bin").await.unwrap();
    assert_eq!(meta.key, "pods/alice/avatar.bin");
    assert_eq!(meta.content_length, 5);
    assert_eq!(
        meta.content_type.as_deref(),
        Some("application/octet-stream")
    );

    // List all blobs
    let all_keys = store.list("/").await.unwrap();
    assert_eq!(
        all_keys,
        vec![
            "pods/alice/avatar.bin",
            "pods/alice/notes/daily.md",
            "pods/alice/notes/empty.txt",
            "pods/bob/profile.ttl",
        ]
    );

    // List scoped directory prefix
    let alice_keys = store.list("pods/alice/").await.unwrap();
    assert_eq!(
        alice_keys,
        vec![
            "pods/alice/avatar.bin",
            "pods/alice/notes/daily.md",
            "pods/alice/notes/empty.txt",
        ]
    );

    // List partial key prefix
    let notes_daily = store.list("pods/alice/notes/d").await.unwrap();
    assert_eq!(notes_daily, vec!["pods/alice/notes/daily.md"]);

    // Overwrite and delete
    store
        .put("pods/alice/notes/daily.md", b"# Updated".to_vec())
        .await
        .unwrap();
    assert_eq!(
        store.get("pods/alice/notes/daily.md").await.unwrap(),
        b"# Updated"
    );

    store.delete("pods/alice/notes/daily.md").await.unwrap();
    // Idempotent second delete
    store.delete("pods/alice/notes/daily.md").await.unwrap();

    assert!(!store.exists("pods/alice/notes/daily.md").await.unwrap());
    assert!(matches!(
        store.get("pods/alice/notes/daily.md").await,
        Err(WolinError::NotFound(_))
    ));
    assert_eq!(
        store.list("pods/alice/").await.unwrap(),
        vec!["pods/alice/avatar.bin", "pods/alice/notes/empty.txt"]
    );
}

#[tokio::test]
async fn opendal_fs_persistence_concurrency_and_path_safety() {
    let dir = TempTestDir::new("fs_blobs");
    let store = PhysicalStore::new_fs(dir.path_str()).expect("init fs store");

    // Reject traversal and malformed keys
    for bad_key in [
        "",
        "/",
        "../escape.txt",
        "pods/../../escape.txt",
        "./local.txt",
        "pods/alice/",
        "pods//double.txt",
        "pods\\backslash.txt",
        "pods/nul\0byte.txt",
    ] {
        assert!(
            matches!(
                store.put(bad_key, b"x".to_vec()).await,
                Err(WolinError::InvalidFormat(_))
            ),
            "expected InvalidFormat for key {bad_key:?}"
        );
    }

    assert!(matches!(
        store.list("../outside").await,
        Err(WolinError::InvalidFormat(_))
    ));
    assert_eq!(
        store.list("nonexistent/prefix/").await.unwrap(),
        Vec::<String>::new()
    );

    // Concurrent writes and reads across tokio tasks
    let mut handles = Vec::new();
    for idx in 0..16u32 {
        let cloned = store.clone();
        handles.push(tokio::spawn(async move {
            let key = format!("pods/concurrent/blob_{idx:02}.dat");
            let payload = format!("payload-{idx}").into_bytes();
            cloned.write(&key, payload.clone()).await.unwrap();
            let fetched = cloned.read(&key).await.unwrap();
            assert_eq!(fetched, payload);
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    // Reopen PhysicalStore on the same directory to verify filesystem persistence
    let reopened = PhysicalStore::new_fs(dir.path_str()).expect("reopen fs store");
    let listed = reopened.list("pods/concurrent/").await.unwrap();
    assert_eq!(listed.len(), 16);
    assert_eq!(listed[0], "pods/concurrent/blob_00.dat");
    assert_eq!(listed[15], "pods/concurrent/blob_15.dat");
    assert_eq!(
        reopened.get("pods/concurrent/blob_07.dat").await.unwrap(),
        b"payload-7"
    );
}

#[test]
fn oxigraph_turtle_ntriples_quads_and_sparql_select() {
    let graph = SemanticGraphStore::new_in_memory().expect("init graph store");

    let turtle = r#"
        @prefix foaf: <http://xmlns.com/foaf/0.1/> .
        @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
        @prefix wolin: <https://wolin.io/ns#> .

        <https://pod.wolin.io/alice#me> a foaf:Person ;
            foaf:name "Alice"@en, "앨리스"@ko ;
            wolin:trustScore "95"^^xsd:integer ;
            foaf:knows <https://pod.wolin.io/bob#me> .
    "#;
    let inserted_ttl = graph.insert_turtle(turtle).unwrap();
    assert_eq!(inserted_ttl, 5);

    let ntriples = r#"
        <https://pod.wolin.io/bob#me> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://xmlns.com/foaf/0.1/Person> .
        <https://pod.wolin.io/bob#me> <http://xmlns.com/foaf/0.1/name> "Bob" .
    "#;
    let inserted_nt = graph.insert_ntriples(ntriples).unwrap();
    assert_eq!(inserted_nt, 2);

    // Direct Quad insertion & deduplication
    let carol = NamedNode::new("https://pod.wolin.io/carol#me").unwrap();
    let foaf_name = NamedNode::new("http://xmlns.com/foaf/0.1/name").unwrap();
    let quad = Quad::new(
        carol.clone(),
        foaf_name.clone(),
        Literal::new_simple_literal("Carol"),
        GraphName::DefaultGraph,
    );
    assert!(graph.insert_quad(&quad).unwrap());
    assert!(!graph.insert_quad(&quad).unwrap());
    assert_eq!(graph.len().unwrap(), 8);

    // SPARQL SELECT with OPTIONAL, FILTER, and ORDER BY
    let select_query = r#"
        PREFIX foaf: <http://xmlns.com/foaf/0.1/>
        PREFIX wolin: <https://wolin.io/ns#>
        SELECT ?person ?name ?score WHERE {
            ?person foaf:name ?name .
            FILTER(lang(?name) = "" || lang(?name) = "ko")
            OPTIONAL { ?person wolin:trustScore ?score }
        }
        ORDER BY ?person
    "#;
    let bindings = graph.query_select(select_query).unwrap();
    assert_eq!(bindings.variables, vec!["person", "name", "score"]);
    assert_eq!(bindings.len(), 3);

    // Row 0: Alice (Korean label + integer trustScore)
    assert_eq!(
        bindings.rows[0].get("person"),
        Some(&RdfTerm::iri("https://pod.wolin.io/alice#me"))
    );
    assert_eq!(
        bindings.rows[0].get("name"),
        Some(&RdfTerm::Literal {
            value: "앨리스".to_string(),
            datatype: "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString".to_string(),
            language: Some("ko".to_string()),
        })
    );
    assert_eq!(
        bindings.rows[0].get("score"),
        Some(&RdfTerm::Literal {
            value: "95".to_string(),
            datatype: "http://www.w3.org/2001/XMLSchema#integer".to_string(),
            language: None,
        })
    );

    // Row 1: Bob (simple literal, unbound OPTIONAL ?score omitted)
    assert_eq!(
        bindings.rows[1].get("person"),
        Some(&RdfTerm::iri("https://pod.wolin.io/bob#me"))
    );
    assert_eq!(
        bindings.rows[1].get("name"),
        Some(&RdfTerm::simple_literal("Bob"))
    );
    assert!(!bindings.rows[1].contains_key("score"));

    // Row 2: Carol
    assert_eq!(
        bindings.rows[2].get("name").map(RdfTerm::as_str),
        Some("Carol")
    );

    // Remove Carol quad and verify via ASK
    assert!(graph.remove_quad(&quad).unwrap());
    assert!(!graph.remove_quad(&quad).unwrap());
    let has_carol = graph
        .query_ask("ASK { <https://pod.wolin.io/carol#me> ?p ?o }")
        .unwrap();
    assert!(!has_carol);

    // Batch quad insert and SPARQL UPDATE mutation
    let dave = NamedNode::new("https://pod.wolin.io/dave#me").unwrap();
    let batch_count = graph
        .insert_quads([Quad::new(
            dave,
            foaf_name,
            Literal::new_simple_literal("Dave"),
            GraphName::DefaultGraph,
        )])
        .unwrap();
    assert_eq!(batch_count, 1);

    graph
        .update(
            "DELETE { <https://pod.wolin.io/dave#me> <http://xmlns.com/foaf/0.1/name> \"Dave\" } \
             INSERT { <https://pod.wolin.io/dave#me> <http://xmlns.com/foaf/0.1/name> \"David\" } \
             WHERE { <https://pod.wolin.io/dave#me> <http://xmlns.com/foaf/0.1/name> \"Dave\" }",
        )
        .unwrap();
    let updated = graph
        .query_select("SELECT ?n WHERE { <https://pod.wolin.io/dave#me> <http://xmlns.com/foaf/0.1/name> ?n }")
        .unwrap();
    assert_eq!(updated.rows[0].get("n").unwrap().as_str(), "David");
}

#[test]
fn oxigraph_sparql_construct_zero_pii_projection_and_named_graphs() {
    let graph = SemanticGraphStore::new_in_memory().expect("init graph store");

    // Ingest private profile into a named graph with base IRI
    let private_profile = r#"
        @prefix foaf: <http://xmlns.com/foaf/0.1/> .
        @prefix wolin: <https://wolin.io/ns#> .

        <#me> a foaf:Person ;
            foaf:name "Yongchol Choi" ;
            foaf:topic_interest "Decentralized Identity", "Semantic Web" ;
            wolin:secretApiKey "sk-live-do-not-expose" ;
            foaf:mbox <mailto:private@example.com> .
    "#;
    let count = graph
        .insert_turtle_with_options(
            private_profile,
            Some("https://pod.wolin.io/user"),
            Some("https://pod.wolin.io/graphs/private"),
        )
        .unwrap();
    assert_eq!(count, 6);

    // Project only non-PII public attributes via SPARQL CONSTRUCT
    let construct_sparql = r#"
        PREFIX foaf: <http://xmlns.com/foaf/0.1/>
        PREFIX wolin: <https://wolin.io/ns#>
        CONSTRUCT {
            ?s a foaf:Agent ;
               wolin:displayName ?name ;
               wolin:interest ?topic .
        }
        WHERE {
            GRAPH <https://pod.wolin.io/graphs/private> {
                ?s a foaf:Person ;
                   foaf:name ?name ;
                   foaf:topic_interest ?topic .
            }
        }
    "#;

    let projected = graph.query_construct(construct_sparql).unwrap();
    // 1 rdf:type + 1 displayName + 2 interest triples = 4 projected triples
    assert_eq!(projected.len(), 4);
    assert!(
        projected
            .triples
            .iter()
            .all(|t| !t.predicate.contains("secretApiKey") && !t.predicate.contains("mbox"))
    );

    // Round-trip projected subgraph through Turtle into an isolated agent view store
    let projected_ttl = projected.to_turtle().unwrap();
    assert!(!projected_ttl.contains("sk-live-do-not-expose"));
    assert!(!projected_ttl.contains("private@example.com"));

    let agent_view = SemanticGraphStore::new_in_memory().unwrap();
    assert_eq!(agent_view.insert_turtle(&projected_ttl).unwrap(), 4);

    if let SparqlQueryOutput::Select(res) = agent_view
        .execute_sparql(
            "SELECT ?topic WHERE { ?s <https://wolin.io/ns#interest> ?topic } ORDER BY ?topic",
        )
        .unwrap()
    {
        let topics: Vec<&str> = res
            .rows
            .iter()
            .map(|r| r.get("topic").unwrap().as_str())
            .collect();
        assert_eq!(topics, vec!["Decentralized Identity", "Semantic Web"]);
    } else {
        panic!("expected Select output");
    }
}

#[test]
fn oxigraph_error_handling_atomicity_and_disk_persistence() {
    let dir = TempTestDir::new("oxigraph_rocksdb");

    {
        let persistent = SemanticGraphStore::open(dir.path()).expect("open rocksdb oxigraph");
        persistent
            .insert_nquads(
                "<https://wolin.io/doc/1> <http://purl.org/dc/terms/title> \"Spec\" <https://wolin.io/g/meta> .",
            )
            .unwrap();
        assert_eq!(persistent.len().unwrap(), 1);

        // Malformed Turtle must fail with InvalidFormat without corrupting existing triples
        let bad_ttl = persistent.insert_turtle("@prefix broken: <http://example.com> <unclosed");
        assert!(matches!(bad_ttl, Err(WolinError::InvalidFormat(_))));
        assert_eq!(persistent.len().unwrap(), 1);

        // Malformed SPARQL must fail with Semantic error
        let bad_sparql = persistent.query_select("SELECT ?x WHERE { ?x ?y ");
        assert!(matches!(bad_sparql, Err(WolinError::Semantic(_))));

        // Mismatched query form must fail with InvalidFormat
        let wrong_form = persistent.query_select("CONSTRUCT { ?s ?p ?o } WHERE { ?s ?p ?o }");
        assert!(matches!(wrong_form, Err(WolinError::InvalidFormat(_))));
        let wrong_construct = persistent.query_construct("SELECT ?s WHERE { ?s ?p ?o }");
        assert!(matches!(wrong_construct, Err(WolinError::InvalidFormat(_))));
    }

    // Reopen persistent store and verify durability
    let reopened = SemanticGraphStore::open(dir.path()).expect("reopen rocksdb oxigraph");
    let rows = reopened
        .query_select(
            "SELECT ?title WHERE { GRAPH <https://wolin.io/g/meta> { <https://wolin.io/doc/1> <http://purl.org/dc/terms/title> ?title } }",
        )
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows.rows[0].get("title").unwrap().as_str(), "Spec");
}

#[tokio::test]
async fn dual_plane_blob_and_semantic_index_roundtrip() {
    let blob_dir = TempTestDir::new("dual_blob");
    let graph_dir = TempTestDir::new("dual_graph");

    let blobs = PhysicalStore::new_fs(blob_dir.path_str()).unwrap();
    let semantic = SemanticGraphStore::open(graph_dir.path()).unwrap();

    let blob_key = "pods/alice/papers/architecture.pdf";
    let pdf_bytes = b"%PDF-1.7\nwolin dual-plane storage verification\n%%EOF".to_vec();
    blobs
        .put_with_content_type(blob_key, pdf_bytes.clone(), "application/pdf")
        .await
        .unwrap();
    let stat = blobs.stat(blob_key).await.unwrap();

    let metadata_ttl = format!(
        r#"
        @prefix dcterms: <http://purl.org/dc/terms/> .
        @prefix wolin: <https://wolin.io/ns#> .
        @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

        <wolin://pod/alice/papers/architecture.pdf>
            dcterms:title "Wolin Dual-Plane Storage Architecture" ;
            dcterms:format "application/pdf" ;
            wolin:blobKey "{}" ;
            wolin:contentLength "{}"^^xsd:integer .
        "#,
        stat.key, stat.content_length
    );
    semantic.insert_turtle(&metadata_ttl).unwrap();

    // Query semantic index to discover physical blob key, then read physical bytes
    let bindings = semantic
        .query_select(
            r#"
            PREFIX dcterms: <http://purl.org/dc/terms/>
            PREFIX wolin: <https://wolin.io/ns#>
            SELECT ?key ?len WHERE {
                ?res dcterms:format "application/pdf" ;
                     wolin:blobKey ?key ;
                     wolin:contentLength ?len .
            }
            "#,
        )
        .unwrap();
    assert_eq!(bindings.len(), 1);
    let resolved_key = bindings.rows[0].get("key").unwrap().as_str();
    assert_eq!(resolved_key, blob_key);

    let retrieved = blobs.get(resolved_key).await.unwrap();
    assert_eq!(retrieved, pdf_bytes);
}
