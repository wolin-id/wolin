use std::collections::{HashMap, VecDeque};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use oxigraph::model::Triple;
use wolin_core::{Result, WolinError};

use crate::{PhysicalStore, SemanticGraphStore, SparqlBindingSet, SparqlQueryOutput};

/// Default maximum number of concurrently open per-pod RocksDB graph stores.
pub const DEFAULT_MAX_OPEN_PODS: usize = 256;

/// Default per-pod logical storage quota in bytes (`1 GiB`).
pub const DEFAULT_POD_QUOTA_BYTES: u64 = 1024 * 1024 * 1024;

const MAX_POD_ID_LEN: usize = 63;
const ROCKSDB_MAX_OPEN_FILES_PER_POD: u32 = 64;

const RESERVED_POD_IDS: &[&str] = &[
    "pod",
    "pods",
    "api",
    "auth",
    "login",
    "id",
    "www",
    "mcp",
    "health",
    "healthz",
    "public",
    "private",
    "admin",
    "system",
    "well-known",
];

enum PodBackend {
    InMemory,
    Persistent { storage_root: PathBuf },
}

/// RAII handle to a [`SemanticGraphStore`] (either a per-pod store or the system store).
/// Synchronizes final RocksDB teardown with cold re-opens so concurrent LRU eviction can
/// never race on the underlying RocksDB `LOCK` file.
#[derive(Clone)]
pub struct PodGraphHandle {
    store: Option<Arc<SemanticGraphStore>>,
    lifecycle_gate: Option<Arc<Mutex<()>>>,
}

impl PodGraphHandle {
    fn system(store: Arc<SemanticGraphStore>) -> Self {
        Self {
            store: Some(store),
            lifecycle_gate: None,
        }
    }

    fn pod(store: Arc<SemanticGraphStore>, gate: Option<Arc<Mutex<()>>>) -> Self {
        Self {
            store: Some(store),
            lifecycle_gate: gate,
        }
    }

    fn inner_ref(&self) -> &SemanticGraphStore {
        self.store
            .as_deref()
            .expect("PodGraphHandle store is present until Drop")
    }

    /// Retrieve all [`Triple`]s stored in named graph `graph_iri`.
    pub fn get_named_graph_triples(&self, graph_iri: &str) -> Result<Vec<Triple>> {
        self.inner_ref().get_named_graph_triples(graph_iri)
    }

    /// Atomically replace all triples inside named graph `graph_iri`.
    pub fn replace_named_graph_triples(
        &self,
        graph_iri: &str,
        triples: &[Triple],
    ) -> Result<usize> {
        self.inner_ref()
            .replace_named_graph_triples(graph_iri, triples)
    }

    /// Delete named graph `graph_iri` and all its triples.
    pub fn delete_named_graph(&self, graph_iri: &str) -> Result<bool> {
        self.inner_ref().delete_named_graph(graph_iri)
    }

    /// Serialize all quads in this store into canonical N-Quads bytes.
    pub fn dump_nquads(&self) -> Result<Vec<u8>> {
        self.inner_ref().dump_nquads()
    }

    /// Return the total number of quads currently in this store.
    pub fn len(&self) -> Result<usize> {
        self.inner_ref().len()
    }

    /// Return `true` when this store contains zero quads.
    pub fn is_empty(&self) -> Result<bool> {
        self.inner_ref().is_empty()
    }

    /// Parse and atomically insert N-Triples into the default graph.
    pub fn insert_ntriples(&self, ntriples: &str) -> Result<usize> {
        self.inner_ref().insert_ntriples(ntriples)
    }

    /// Execute a SPARQL 1.1 `SELECT` query against this store.
    pub fn query_select(&self, sparql: &str) -> Result<SparqlBindingSet> {
        self.inner_ref().query_select(sparql)
    }

    /// Execute a SPARQL 1.1 `ASK` query against this store.
    pub fn query_ask(&self, sparql: &str) -> Result<bool> {
        self.inner_ref().query_ask(sparql)
    }

    /// Execute any SPARQL 1.1 query against this store.
    pub fn execute_sparql(&self, sparql: &str) -> Result<SparqlQueryOutput> {
        self.inner_ref().execute_sparql(sparql)
    }

    /// Flush buffered RocksDB writes to disk.
    pub fn flush(&self) -> Result<()> {
        self.inner_ref().flush()
    }
}

impl Drop for PodGraphHandle {
    fn drop(&mut self) {
        let Some(arc) = self.store.take() else {
            return;
        };
        if let Some(ref gate) = self.lifecycle_gate {
            let _guard = gate.lock().unwrap_or_else(|e| e.into_inner());
            drop(arc);
            return;
        }
        drop(arc);
    }
}

struct LruState {
    open_pods: HashMap<String, Arc<SemanticGraphStore>>,
    lru_order: VecDeque<String>,
    in_flight_evicted: HashMap<String, Weak<SemanticGraphStore>>,
    lifecycle_gates: HashMap<String, Arc<Mutex<()>>>,
    cold_memory_stores: HashMap<String, Arc<SemanticGraphStore>>,
    pod_usage_bytes: HashMap<String, u64>,
    pod_quota_overrides: HashMap<String, u64>,
    eviction_count: u64,
}

struct PodStoreManagerInner {
    backend: PodBackend,
    system_store: Arc<SemanticGraphStore>,
    max_open_pods: usize,
    default_pod_quota_bytes: u64,
    state: Mutex<LruState>,
}

/// Bounded LRU manager for physically isolated per-Pod [`SemanticGraphStore`] instances
/// and per-Pod logical storage quota enforcement.
#[derive(Clone)]
pub struct PodStoreManager {
    inner: Arc<PodStoreManagerInner>,
}

impl PodStoreManager {
    /// Create an in-memory [`PodStoreManager`] with isolated [`SemanticGraphStore`]s per pod.
    pub fn new_in_memory(max_open_pods: usize, default_pod_quota_bytes: u64) -> Result<Self> {
        let system_store = SemanticGraphStore::new_in_memory()?;
        Self::new_in_memory_with_system_store(system_store, max_open_pods, default_pod_quota_bytes)
    }

    /// Create an in-memory [`PodStoreManager`] sharing an existing root/system [`SemanticGraphStore`].
    pub fn new_in_memory_with_system_store(
        system_store: SemanticGraphStore,
        max_open_pods: usize,
        default_pod_quota_bytes: u64,
    ) -> Result<Self> {
        validate_limits(max_open_pods, default_pod_quota_bytes)?;
        Ok(Self {
            inner: Arc::new(PodStoreManagerInner {
                backend: PodBackend::InMemory,
                system_store: Arc::new(system_store),
                max_open_pods,
                default_pod_quota_bytes,
                state: Mutex::new(LruState {
                    open_pods: HashMap::new(),
                    lru_order: VecDeque::new(),
                    in_flight_evicted: HashMap::new(),
                    lifecycle_gates: HashMap::new(),
                    cold_memory_stores: HashMap::new(),
                    pod_usage_bytes: HashMap::new(),
                    pod_quota_overrides: HashMap::new(),
                    eviction_count: 0,
                }),
            }),
        })
    }

    /// Create a disk-backed [`PodStoreManager`] rooted at `storage_root`
    /// (system store at `storage_root/graph/`, per-pod stores at `storage_root/pods/{pod_id}/graph/`).
    pub fn new_persistent(
        storage_root: impl AsRef<Path>,
        max_open_pods: usize,
        default_pod_quota_bytes: u64,
    ) -> Result<Self> {
        let root = storage_root.as_ref();
        ensure_private_dir(root)?;
        let sys_graph_dir = root.join("graph");
        ensure_private_dir(&sys_graph_dir)?;
        let system_store =
            SemanticGraphStore::open_bounded(&sys_graph_dir, ROCKSDB_MAX_OPEN_FILES_PER_POD)?;
        Self::new_persistent_with_system_store(
            root,
            system_store,
            max_open_pods,
            default_pod_quota_bytes,
        )
    }

    /// Create a disk-backed [`PodStoreManager`] sharing an already-opened system [`SemanticGraphStore`].
    pub fn new_persistent_with_system_store(
        storage_root: impl AsRef<Path>,
        system_store: SemanticGraphStore,
        max_open_pods: usize,
        default_pod_quota_bytes: u64,
    ) -> Result<Self> {
        validate_limits(max_open_pods, default_pod_quota_bytes)?;
        let raw_root = storage_root.as_ref();
        let root = if raw_root.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            raw_root.to_path_buf()
        };
        if !root.exists() {
            std::fs::create_dir_all(&root).map_err(|e| {
                WolinError::Storage(format!("Failed to create storage root {:?}: {e}", root))
            })?;
        }
        ensure_private_dir(&root.join("pods"))?;

        Ok(Self {
            inner: Arc::new(PodStoreManagerInner {
                backend: PodBackend::Persistent { storage_root: root },
                system_store: Arc::new(system_store),
                max_open_pods,
                default_pod_quota_bytes,
                state: Mutex::new(LruState {
                    open_pods: HashMap::new(),
                    lru_order: VecDeque::new(),
                    in_flight_evicted: HashMap::new(),
                    lifecycle_gates: HashMap::new(),
                    cold_memory_stores: HashMap::new(),
                    pod_usage_bytes: HashMap::new(),
                    pod_quota_overrides: HashMap::new(),
                    eviction_count: 0,
                }),
            }),
        })
    }

    /// Automatically construct a persistent or in-memory [`PodStoreManager`] matching the backing
    /// mode of `physical_store` and `system_store`.
    pub fn from_stores(
        physical_store: &PhysicalStore,
        system_store: SemanticGraphStore,
        max_open_pods: usize,
        default_pod_quota_bytes: u64,
    ) -> Result<Self> {
        if let Some(storage_root) = infer_pod_storage_root(physical_store, &system_store) {
            Self::new_persistent_with_system_store(
                storage_root,
                system_store,
                max_open_pods,
                default_pod_quota_bytes,
            )
        } else {
            Self::new_in_memory_with_system_store(
                system_store,
                max_open_pods,
                default_pod_quota_bytes,
            )
        }
    }

    /// Validate that `pod_id` is a safe RFC 1123 lowercase DNS label (`[a-z0-9-]`, 1..=63 chars)
    /// and does not collide with reserved infrastructure/system routes or path traversal segments.
    pub fn validate_pod_id(pod_id: &str) -> Result<()> {
        if pod_id.is_empty() || pod_id.len() > MAX_POD_ID_LEN {
            return Err(WolinError::InvalidFormat(
                "pod_id must be between 1 and 63 lowercase characters".to_string(),
            ));
        }
        if pod_id.starts_with('-')
            || pod_id.ends_with('-')
            || pod_id.starts_with("__wolin_")
            || !pod_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(WolinError::InvalidFormat(
                "pod_id must contain only lowercase ASCII letters, digits, or interior hyphens"
                    .to_string(),
            ));
        }
        if RESERVED_POD_IDS.contains(&pod_id) {
            return Err(WolinError::InvalidFormat(format!(
                "pod_id '{pod_id}' is reserved for system infrastructure"
            )));
        }
        Ok(())
    }

    /// Extract the enclosing `pod_id` from a canonical LDP path (`/pods/{pod_id}/...`),
    /// returning `Ok(None)` for non-pod/system paths (`/`, `/public/...`, `/pods/`, `/pods/.acl`).
    /// Fails closed with [`WolinError::InvalidFormat`] if a `/pods/<seg>` leaf (missing trailing
    /// container slash) or invalid `pod_id` segment is supplied.
    pub fn pod_id_from_canonical_path(canonical_path: &str) -> Result<Option<&str>> {
        if canonical_path == "/pods" || canonical_path == "/pods.acl" {
            return Err(WolinError::InvalidFormat(
                "System pods root must be addressed as container '/pods/' (or '/pods/.acl')"
                    .to_string(),
            ));
        }
        let Some(rest) = canonical_path.strip_prefix("/pods/") else {
            return Ok(None);
        };
        if rest.is_empty() || rest == ".acl" {
            return Ok(None);
        }
        let Some((first, _tail)) = rest.split_once('/') else {
            return Err(WolinError::InvalidFormat(
                "Pod resources must reside under container '/pods/{pod_id}/...'".to_string(),
            ));
        };
        Self::validate_pod_id(first)?;
        Ok(Some(first))
    }

    /// Return the root/system [`SemanticGraphStore`] used for non-pod routes.
    pub fn system_store(&self) -> &SemanticGraphStore {
        &self.inner.system_store
    }

    /// Resolve the appropriate [`SemanticGraphStore`] handle for `canonical_path`:
    /// routes `/pods/{pod_id}/...` to that pod's isolated store (opening on demand under bounded LRU),
    /// and all other paths to the root/system store.
    pub fn store_for_path(&self, canonical_path: &str) -> Result<PodGraphHandle> {
        match Self::pod_id_from_canonical_path(canonical_path)? {
            Some(pod_id) => self.get_or_open(pod_id),
            None => Ok(PodGraphHandle::system(Arc::clone(&self.inner.system_store))),
        }
    }

    /// Retrieve or cold-open the isolated [`SemanticGraphStore`] for `pod_id`, updating LRU order
    /// and evicting the least-recently-used open pod store if `max_open_pods` is reached.
    pub fn get_or_open(&self, pod_id: &str) -> Result<PodGraphHandle> {
        Self::validate_pod_id(pod_id)?;

        let mut guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let is_persistent = matches!(self.inner.backend, PodBackend::Persistent { .. });
        let pod_gate = if is_persistent {
            Some(Arc::clone(
                guard
                    .lifecycle_gates
                    .entry(pod_id.to_string())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            ))
        } else {
            None
        };

        // Fast path: cache hit -> promote to MRU back of VecDeque.
        if let Some(existing) = guard.open_pods.get(pod_id).cloned() {
            touch_lru(&mut guard.lru_order, pod_id);
            return Ok(PodGraphHandle::pod(existing, pod_gate));
        }

        // Prune dead Weak handles from prior in-flight evictions.
        guard
            .in_flight_evicted
            .retain(|_, weak| weak.strong_count() > 0);

        // Enforce `max_open_pods` capacity BEFORE opening another store.
        while guard.open_pods.len() >= self.inner.max_open_pods {
            let Some(victim_id) = guard.lru_order.pop_front() else {
                break;
            };
            if let Some(victim_store) = guard.open_pods.remove(&victim_id) {
                self.evict_pod_store_locked(&mut guard, &victim_id, victim_store)?;
            }
        }

        let opened = match &self.inner.backend {
            PodBackend::InMemory => match guard.cold_memory_stores.remove(pod_id) {
                Some(cold) => cold,
                None => Arc::new(SemanticGraphStore::new_in_memory()?),
            },
            PodBackend::Persistent { storage_root } => {
                let gate_ref = pod_gate.as_ref().expect("persistent mode has gate");
                // Synchronize against any concurrent thread finishing the final Drop of an evicted handle
                let _gate_guard = gate_ref.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(reused) = guard
                    .in_flight_evicted
                    .remove(pod_id)
                    .and_then(|w| w.upgrade())
                {
                    reused
                } else {
                    let pod_dir = storage_root.join("pods").join(pod_id);
                    let graph_dir = pod_dir.join("graph");
                    ensure_private_dir(&pod_dir)?;
                    ensure_private_dir(&graph_dir)?;
                    Arc::new(SemanticGraphStore::open_bounded(
                        &graph_dir,
                        ROCKSDB_MAX_OPEN_FILES_PER_POD,
                    )?)
                }
            }
        };

        guard
            .open_pods
            .insert(pod_id.to_string(), Arc::clone(&opened));
        guard.lru_order.push_back(pod_id.to_string());
        Ok(PodGraphHandle::pod(opened, pod_gate))
    }

    fn evict_pod_store_locked(
        &self,
        guard: &mut LruState,
        victim_id: &str,
        victim_store: Arc<SemanticGraphStore>,
    ) -> Result<()> {
        match &self.inner.backend {
            PodBackend::InMemory => {
                guard
                    .cold_memory_stores
                    .insert(victim_id.to_string(), victim_store);
            }
            PodBackend::Persistent { .. } => {
                let flush_res = victim_store.flush();
                let victim_gate = guard.lifecycle_gates.get(victim_id).cloned();
                if let Some(gate) = victim_gate {
                    let _g = gate.lock().unwrap_or_else(|e| e.into_inner());
                    if Arc::strong_count(&victim_store) > 1 {
                        guard
                            .in_flight_evicted
                            .insert(victim_id.to_string(), Arc::downgrade(&victim_store));
                    }
                    drop(victim_store);
                } else {
                    drop(victim_store);
                }
                flush_res?;
            }
        }
        guard.eviction_count += 1;
        Ok(())
    }

    /// Return the physical RocksDB directory path (`storage_dir/pods/{pod_id}/graph`) when persistent,
    /// or `Ok(None)` when running in-memory.
    pub fn pod_graph_dir(&self, pod_id: &str) -> Result<Option<PathBuf>> {
        Self::validate_pod_id(pod_id)?;
        match &self.inner.backend {
            PodBackend::InMemory => Ok(None),
            PodBackend::Persistent { storage_root } => {
                Ok(Some(storage_root.join("pods").join(pod_id).join("graph")))
            }
        }
    }

    /// Return `true` if `pod_id`'s graph store is currently resident in the hot LRU cache.
    pub fn is_pod_open(&self, pod_id: &str) -> bool {
        let guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.open_pods.contains_key(pod_id)
    }

    /// Return the number of currently open per-pod graph stores (`<= max_open_pods`).
    pub fn open_pod_count(&self) -> usize {
        let guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.open_pods.len()
    }

    /// Return currently open `pod_id`s ordered from Least-Recently-Used (front) to Most-Recently-Used (back).
    pub fn open_pod_ids_lru_order(&self) -> Vec<String> {
        let guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.lru_order.iter().cloned().collect()
    }

    /// Return total number of LRU evictions performed since manager initialization.
    pub fn eviction_count(&self) -> u64 {
        let guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.eviction_count
    }

    /// Configured maximum number of concurrently open per-pod stores.
    pub fn max_open_pods(&self) -> usize {
        self.inner.max_open_pods
    }

    /// Configured default per-pod storage quota in bytes.
    pub fn default_pod_quota_bytes(&self) -> u64 {
        self.inner.default_pod_quota_bytes
    }

    /// Effective storage quota in bytes for `pod_id`.
    pub fn pod_quota_bytes(&self, pod_id: &str) -> u64 {
        let guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .pod_quota_overrides
            .get(pod_id)
            .copied()
            .unwrap_or(self.inner.default_pod_quota_bytes)
    }

    /// Override the storage quota in bytes for a specific `pod_id`.
    pub fn set_pod_quota_bytes(&self, pod_id: &str, quota_bytes: u64) -> Result<()> {
        Self::validate_pod_id(pod_id)?;
        if quota_bytes == 0 {
            return Err(WolinError::InvalidFormat(
                "pod_quota_bytes must be greater than 0".to_string(),
            ));
        }
        let mut guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .pod_quota_overrides
            .insert(pod_id.to_string(), quota_bytes);
        Ok(())
    }

    /// Return the tracked logical storage usage in bytes for `pod_id`.
    pub fn pod_usage_bytes(&self, pod_id: &str) -> u64 {
        let guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.pod_usage_bytes.get(pod_id).copied().unwrap_or(0)
    }

    /// Update the tracked logical storage usage in bytes for `pod_id`.
    pub fn record_pod_usage(&self, pod_id: &str, used_bytes: u64) {
        let mut guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if used_bytes == 0 {
            guard.pod_usage_bytes.remove(pod_id);
        } else {
            guard.pod_usage_bytes.insert(pod_id.to_string(), used_bytes);
        }
    }

    /// Atomically replace the entire per-pod usage map from a fresh catalog snapshot,
    /// clearing stale counters for any pods whose usage dropped to zero.
    pub fn replace_all_pod_usages(&self, mut usages: HashMap<String, u64>) {
        usages.retain(|_, &mut v| v > 0);
        let mut guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.pod_usage_bytes = usages;
    }

    /// Verify that replacing `replaced_bytes` with `new_bytes` on top of `current_used_bytes`
    /// stays within `pod_id`'s storage quota, returning the projected usage or [`WolinError::QuotaExceeded`].
    pub fn check_quota_delta(
        &self,
        pod_id: &str,
        current_used_bytes: u64,
        replaced_bytes: u64,
        new_bytes: u64,
    ) -> Result<u64> {
        Self::validate_pod_id(pod_id)?;
        let quota = self.pod_quota_bytes(pod_id);
        let base = current_used_bytes.saturating_sub(replaced_bytes);
        let projected = base.checked_add(new_bytes).ok_or_else(|| {
            WolinError::QuotaExceeded(format!(
                "Pod '{pod_id}' storage quota exceeded (overflow beyond {quota} bytes)"
            ))
        })?;
        if projected > quota {
            return Err(WolinError::QuotaExceeded(format!(
                "Pod '{pod_id}' storage quota exceeded: projected {projected} bytes > limit {quota} bytes"
            )));
        }
        Ok(projected)
    }
}

fn infer_pod_storage_root(
    physical_store: &PhysicalStore,
    system_store: &SemanticGraphStore,
) -> Option<PathBuf> {
    if let (Some(bdir), Some(gdir)) = (physical_store.fs_root(), system_store.storage_dir())
        && bdir.file_name() == Some(OsStr::new("blobs"))
        && gdir.file_name() == Some(OsStr::new("graph"))
        && bdir.parent() == gdir.parent()
        && let Some(raw_parent) = gdir.parent()
    {
        let normalized = if raw_parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            raw_parent
        };
        if normalized != Path::new("/") {
            return Some(normalized.to_path_buf());
        }
    }
    if let Some(gdir) = system_store.storage_dir() {
        let normalized = if gdir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            gdir
        };
        if normalized != Path::new("/") {
            return Some(normalized.to_path_buf());
        }
    }
    physical_store.fs_root().map(|bdir| {
        let base = if bdir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            bdir
        };
        base.join("__wolin_pod_stores")
    })
}

fn touch_lru(lru_order: &mut VecDeque<String>, pod_id: &str) {
    if lru_order.back().is_some_and(|back| back == pod_id) {
        return;
    }
    if let Some(pos) = lru_order.iter().position(|id| id == pod_id) {
        let key = lru_order.remove(pos).expect("index verified");
        lru_order.push_back(key);
    }
}

fn validate_limits(max_open_pods: usize, default_pod_quota_bytes: u64) -> Result<()> {
    if max_open_pods == 0 {
        return Err(WolinError::InvalidFormat(
            "max_open_pods must be at least 1".to_string(),
        ));
    }
    if default_pod_quota_bytes == 0 {
        return Err(WolinError::InvalidFormat(
            "default_pod_quota_bytes must be greater than 0".to_string(),
        ));
    }
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(WolinError::Storage(format!(
            "Refusing symlinked storage directory {:?}",
            path
        )));
    }
    std::fs::create_dir_all(path).map_err(|e| {
        WolinError::Storage(format!(
            "Failed to create storage directory {:?}: {e}",
            path
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            WolinError::Storage(format!("Failed to set 0700 permissions on {:?}: {e}", path))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(label: &str) -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let idx = SEQ.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "wolin_pod_mgr_test_{label}_{}_{nanos}_{idx}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn unit_pod_physical_directory_isolation_and_path_routing() {
        let tmp = TempDirGuard::new("dir_isolation");
        let mgr = PodStoreManager::new_persistent(&tmp.path, 8, DEFAULT_POD_QUOTA_BYTES)
            .expect("init persistent PodStoreManager");

        assert_eq!(
            PodStoreManager::pod_id_from_canonical_path("/").unwrap(),
            None
        );
        assert_eq!(
            PodStoreManager::pod_id_from_canonical_path("/public/hello.ttl").unwrap(),
            None
        );
        assert_eq!(
            PodStoreManager::pod_id_from_canonical_path("/pods/").unwrap(),
            None
        );
        assert_eq!(
            PodStoreManager::pod_id_from_canonical_path("/pods/.acl").unwrap(),
            None
        );
        assert_eq!(
            PodStoreManager::pod_id_from_canonical_path("/pods/alice/").unwrap(),
            Some("alice")
        );
        assert_eq!(
            PodStoreManager::pod_id_from_canonical_path("/pods/alice/.acl").unwrap(),
            Some("alice")
        );
        assert_eq!(
            PodStoreManager::pod_id_from_canonical_path("/pods/alice/profile/card").unwrap(),
            Some("alice")
        );

        for bad in [
            "/pods",
            "/pods.acl",
            "/pods/alice",
            "/pods/alice.acl",
            "/pods/Alice/doc.ttl",
            "/pods/-bad/doc.ttl",
            "/pods/bad-/doc.ttl",
            "/pods/api/doc.ttl",
            "/pods/__wolin_meta/doc.ttl",
        ] {
            assert!(
                PodStoreManager::pod_id_from_canonical_path(bad).is_err(),
                "expected invalid pod segment '{bad}' to fail closed"
            );
        }

        let alice = mgr
            .store_for_path("/pods/alice/notes.ttl")
            .expect("open alice store");
        let bob = mgr
            .store_for_path("/pods/bob/notes.ttl")
            .expect("open bob store");
        let sys = mgr
            .store_for_path("/public/global.ttl")
            .expect("resolve system store");

        alice
            .insert_ntriples(
                "<http://example.org/alice> <http://purl.org/dc/terms/title> \"Alice Secret\" .",
            )
            .unwrap();
        bob.insert_ntriples(
            "<http://example.org/bob> <http://purl.org/dc/terms/title> \"Bob Secret\" .",
        )
        .unwrap();
        sys.insert_ntriples(
            "<http://example.org/sys> <http://purl.org/dc/terms/title> \"System Global\" .",
        )
        .unwrap();

        let alice_dir = mgr.pod_graph_dir("alice").unwrap().unwrap();
        let bob_dir = mgr.pod_graph_dir("bob").unwrap().unwrap();
        assert_eq!(alice_dir, tmp.path.join("pods").join("alice").join("graph"));
        assert_eq!(bob_dir, tmp.path.join("pods").join("bob").join("graph"));
        assert!(alice_dir.is_dir());
        assert!(bob_dir.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&alice_dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&bob_dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }

        // Zero cross-tenant leakage across physical stores
        assert_eq!(alice.len().unwrap(), 1);
        assert_eq!(bob.len().unwrap(), 1);
        assert_eq!(sys.len().unwrap(), 1);
        assert!(
            !alice
                .query_ask("ASK { <http://example.org/bob> ?p ?o }")
                .unwrap()
        );
        assert!(
            !bob.query_ask("ASK { <http://example.org/alice> ?p ?o }")
                .unwrap()
        );
        assert!(
            !sys.query_ask("ASK { <http://example.org/alice> ?p ?o }")
                .unwrap()
        );
    }

    #[test]
    fn unit_lru_eviction_and_cold_reopen_persistent_and_in_memory() {
        // 1. Disk-backed RocksDB LRU eviction (max_open_pods = 2)
        let tmp = TempDirGuard::new("lru_persistent");
        let mgr = PodStoreManager::new_persistent(&tmp.path, 2, DEFAULT_POD_QUOTA_BYTES).unwrap();

        {
            let a = mgr.get_or_open("alice").unwrap();
            a.insert_ntriples(
                "<http://pod.example/alice> <http://xmlns.com/foaf/0.1/name> \"Alice\" .",
            )
            .unwrap();
        }
        {
            let b = mgr.get_or_open("bob").unwrap();
            b.insert_ntriples(
                "<http://pod.example/bob> <http://xmlns.com/foaf/0.1/name> \"Bob\" .",
            )
            .unwrap();
        }
        assert_eq!(mgr.open_pod_count(), 2);
        assert_eq!(mgr.open_pod_ids_lru_order(), vec!["alice", "bob"]);
        assert_eq!(mgr.eviction_count(), 0);

        // Touch `alice` so `bob` becomes Least-Recently-Used
        {
            let _a = mgr.get_or_open("alice").unwrap();
        }
        assert_eq!(mgr.open_pod_ids_lru_order(), vec!["bob", "alice"]);

        // Open `carol` -> must evict `bob` cleanly
        {
            let c = mgr.get_or_open("carol").unwrap();
            c.insert_ntriples(
                "<http://pod.example/carol> <http://xmlns.com/foaf/0.1/name> \"Carol\" .",
            )
            .unwrap();
        }
        assert_eq!(mgr.open_pod_count(), 2);
        assert!(!mgr.is_pod_open("bob"));
        assert!(mgr.is_pod_open("alice"));
        assert!(mgr.is_pod_open("carol"));
        assert_eq!(mgr.open_pod_ids_lru_order(), vec!["alice", "carol"]);
        assert_eq!(mgr.eviction_count(), 1);

        // Cold re-open `bob` -> evicts `alice`, re-opens `bob` from RocksDB with data intact!
        {
            let b_reopened = mgr.get_or_open("bob").unwrap();
            let rows = b_reopened
                .query_select(
                    "SELECT ?n WHERE { <http://pod.example/bob> <http://xmlns.com/foaf/0.1/name> ?n }",
                )
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows.rows[0]["n"].as_str(), "Bob");
        }
        assert_eq!(mgr.open_pod_count(), 2);
        assert!(!mgr.is_pod_open("alice"));
        assert_eq!(mgr.open_pod_ids_lru_order(), vec!["carol", "bob"]);
        assert_eq!(mgr.eviction_count(), 2);

        // Cold re-open `alice` -> data intact as well!
        {
            let a_reopened = mgr.get_or_open("alice").unwrap();
            assert!(
                a_reopened
                    .query_ask(
                        "ASK { <http://pod.example/alice> <http://xmlns.com/foaf/0.1/name> \"Alice\" }"
                    )
                    .unwrap()
            );
        }
        assert_eq!(mgr.eviction_count(), 3);

        // 2. Ephemeral In-Memory LRU eviction (max_open_pods = 2) also preserves data on cold re-open
        let mem_mgr = PodStoreManager::new_in_memory(2, DEFAULT_POD_QUOTA_BYTES).unwrap();
        mem_mgr
            .get_or_open("alice")
            .unwrap()
            .insert_ntriples("<http://m/a> <http://m/p> \"A\" .")
            .unwrap();
        mem_mgr
            .get_or_open("bob")
            .unwrap()
            .insert_ntriples("<http://m/b> <http://m/p> \"B\" .")
            .unwrap();
        mem_mgr
            .get_or_open("carol")
            .unwrap()
            .insert_ntriples("<http://m/c> <http://m/p> \"C\" .")
            .unwrap();
        assert_eq!(mem_mgr.open_pod_count(), 2);
        assert!(!mem_mgr.is_pod_open("alice"));
        assert!(
            mem_mgr
                .get_or_open("alice")
                .unwrap()
                .query_ask("ASK { <http://m/a> <http://m/p> \"A\" }")
                .unwrap()
        );
    }

    #[test]
    fn unit_per_pod_quota_delta_boundaries_and_overrides() {
        let mgr = PodStoreManager::new_in_memory(4, 1_000).unwrap();

        // Exact boundary 1000 bytes -> allowed
        assert_eq!(mgr.check_quota_delta("alice", 600, 0, 400).unwrap(), 1_000);

        // 1 byte over quota -> QuotaExceeded
        let err = mgr.check_quota_delta("alice", 600, 0, 401).unwrap_err();
        assert!(matches!(err, WolinError::QuotaExceeded(_)));

        // Overwrite replacing 500-byte entry with 800-byte entry when current total is 600 -> 600 - 500 + 800 = 900 <= 1000
        assert_eq!(mgr.check_quota_delta("alice", 600, 500, 800).unwrap(), 900);

        // Per-pod override does not affect sibling pods
        mgr.set_pod_quota_bytes("alice", 2_000).unwrap();
        assert_eq!(
            mgr.check_quota_delta("alice", 600, 0, 1_200).unwrap(),
            1_800
        );
        assert!(mgr.check_quota_delta("bob", 600, 0, 500).is_err());
    }

    #[test]
    fn unit_concurrent_lru_thrashing_without_rocksdb_lock_contention() {
        use std::sync::Barrier;
        use std::thread;

        let tmp = TempDirGuard::new("lru_concurrent");
        let mgr = PodStoreManager::new_persistent(&tmp.path, 2, DEFAULT_POD_QUOTA_BYTES).unwrap();
        let pods = ["alice", "bob", "carol", "dave"];
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for worker_id in 0..4usize {
            let mgr_clone = mgr.clone();
            let b = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                b.wait();
                for round in 0..2usize {
                    let pod_id = pods[(worker_id + round) % pods.len()];
                    let store = mgr_clone
                        .get_or_open(pod_id)
                        .expect("concurrent get_or_open must never hit RocksDB LOCK conflict");
                    let stmt = format!(
                        "<http://pod.example/{pod_id}/w{worker_id}_r{round}> <http://purl.org/dc/terms/title> \"{pod_id}\" ."
                    );
                    store.insert_ntriples(&stmt).unwrap();
                }
            }));
        }

        for h in handles {
            h.join().expect("worker panicked");
        }

        assert!(mgr.open_pod_count() <= 2);
        assert!(mgr.eviction_count() > 0);
        for pod_id in pods {
            let store = mgr.get_or_open(pod_id).unwrap();
            assert_eq!(store.len().unwrap(), 2);
        }

        // Regression test for multi-handle (>=3) concurrent Drop + simultaneous cold re-open with max_open_pods = 1
        let race_tmp = TempDirGuard::new("lru_drop_reopen_race");
        let race_mgr =
            PodStoreManager::new_persistent(&race_tmp.path, 1, DEFAULT_POD_QUOTA_BYTES).unwrap();
        for iter in 0..5usize {
            let h1 = race_mgr.get_or_open("alice").unwrap();
            let h2 = h1.clone();
            let h3 = h1.clone();
            h1.insert_ntriples(&format!(
                "<http://pod.example/alice/i{iter}> <http://purl.org/dc/terms/title> \"iter{iter}\" ."
            ))
            .unwrap();
            // Evict `alice` while 3 handles (`h1`, `h2`, `h3`) are still alive
            drop(race_mgr.get_or_open("bob").unwrap());

            let race_barrier = Arc::new(Barrier::new(4));
            let mut race_threads = Vec::new();
            for handle in [h1, h2, h3] {
                let b = Arc::clone(&race_barrier);
                race_threads.push(thread::spawn(move || {
                    b.wait();
                    drop(handle);
                }));
            }
            let reopen_mgr = race_mgr.clone();
            let b = Arc::clone(&race_barrier);
            race_threads.push(thread::spawn(move || {
                b.wait();
                let reopened = reopen_mgr
                    .get_or_open("alice")
                    .expect("re-open during 3-way concurrent Drop must never fail on LOCK");
                assert!(reopened.len().unwrap() > iter);
            }));
            for t in race_threads {
                t.join().expect("race thread panicked");
            }
        }
    }
}
