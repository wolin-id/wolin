use opendal::{
    services::{Fs, Memory},
    ErrorKind, Operator,
};
use serde::{Deserialize, Serialize};
use wolin_core::{Result, WolinError};

/// Metadata summary for a stored physical blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobMetadata {
    pub key: String,
    pub content_length: u64,
    pub content_type: Option<String>,
    pub etag: Option<String>,
}

/// Physical blob storage plane backed by Apache OpenDAL.
#[derive(Clone)]
pub struct PhysicalStore {
    operator: Operator,
}

impl PhysicalStore {
    /// Initialize local filesystem storage rooted at the given directory.
    pub fn new_fs(root: &str) -> Result<Self> {
        let builder = Fs::default().root(root);
        let op = Operator::new(builder)
            .map_err(|e| WolinError::Storage(format!("OpenDAL fs init failed: {e}")))?
            .finish();
        Ok(Self { operator: op })
    }

    /// Initialize an isolated in-memory blob store (for ephemeral pods and tests).
    pub fn new_memory() -> Result<Self> {
        let builder = Memory::default();
        let op = Operator::new(builder)
            .map_err(|e| WolinError::Storage(format!("OpenDAL memory init failed: {e}")))?
            .finish();
        Ok(Self { operator: op })
    }

    /// Wrap an existing configured OpenDAL [`Operator`].
    pub fn from_operator(operator: Operator) -> Self {
        Self { operator }
    }

    /// Access the underlying OpenDAL [`Operator`].
    pub fn inner(&self) -> &Operator {
        &self.operator
    }

    /// Store a blob at `key`, creating or overwriting any existing object.
    pub async fn put(&self, key: &str, data: impl Into<Vec<u8>>) -> Result<()> {
        let clean_key = validate_blob_key(key)?;
        self.operator
            .write(clean_key, data.into())
            .await
            .map_err(|e| map_opendal_error("put", clean_key, e))
    }

    /// Store a blob at `key` with an explicit MIME `content_type`.
    pub async fn put_with_content_type(
        &self,
        key: &str,
        data: impl Into<Vec<u8>>,
        content_type: &str,
    ) -> Result<()> {
        let clean_key = validate_blob_key(key)?;
        self.operator
            .write_with(clean_key, data.into())
            .content_type(content_type)
            .await
            .map_err(|e| map_opendal_error("put", clean_key, e))
    }

    /// Retrieve the raw bytes of a blob at `key`.
    ///
    /// Returns [`WolinError::NotFound`] if the blob does not exist.
    pub async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let clean_key = validate_blob_key(key)?;
        self.operator
            .read(clean_key)
            .await
            .map(|buf| buf.to_vec())
            .map_err(|e| map_opendal_error("get", clean_key, e))
    }

    /// Delete a blob at `key` (idempotent if the key is already absent).
    pub async fn delete(&self, key: &str) -> Result<()> {
        let clean_key = validate_blob_key(key)?;
        self.operator
            .delete(clean_key)
            .await
            .map_err(|e| map_opendal_error("delete", clean_key, e))
    }

    /// Check whether a blob exists at `key`.
    pub async fn exists(&self, key: &str) -> Result<bool> {
        let clean_key = validate_blob_key(key)?;
        self.operator
            .exists(clean_key)
            .await
            .map_err(|e| map_opendal_error("exists", clean_key, e))
    }

    /// Fetch metadata for a stored blob at `key`.
    pub async fn stat(&self, key: &str) -> Result<BlobMetadata> {
        let clean_key = validate_blob_key(key)?;
        let meta = self
            .operator
            .stat(clean_key)
            .await
            .map_err(|e| map_opendal_error("stat", clean_key, e))?;
        if meta.is_dir() {
            return Err(WolinError::NotFound(format!(
                "Blob key '{clean_key}' resolves to a directory"
            )));
        }
        Ok(BlobMetadata {
            key: clean_key.to_string(),
            content_length: meta.content_length(),
            content_type: meta.content_type().map(str::to_string),
            etag: meta.etag().map(str::to_string),
        })
    }

    /// List all stored blob keys matching `prefix` in deterministic lexicographical order.
    ///
    /// Passing `""` or `"/"` lists all blobs in the store.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let clean_prefix = validate_prefix(prefix)?;
        let dir_to_scan = match clean_prefix.rfind('/') {
            Some(idx) => &clean_prefix[..=idx],
            None => "",
        };

        let entries = self
            .operator
            .list_with(dir_to_scan)
            .recursive(true)
            .await
            .map_err(|e| match e.kind() {
                ErrorKind::NotFound => WolinError::NotFound(e.to_string()),
                _ => map_opendal_error("list", clean_prefix, e),
            });

        let entries = match entries {
            Ok(entries) => entries,
            Err(WolinError::NotFound(_)) => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };

        let mut keys: Vec<String> = entries
            .into_iter()
            .filter(|entry| entry.metadata().is_file() && entry.path().starts_with(clean_prefix))
            .map(|entry| entry.path().to_string())
            .collect();
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    /// Alias for [`Self::get`] retained for backward compatibility.
    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.get(path).await
    }

    /// Alias for [`Self::put`] retained for backward compatibility.
    pub async fn write(&self, path: &str, data: Vec<u8>) -> Result<()> {
        self.put(path, data).await
    }
}

fn validate_no_traversal(raw: &str) -> Result<()> {
    if raw.contains('\0') {
        return Err(WolinError::InvalidFormat(
            "Blob path must not contain NUL bytes".to_string(),
        ));
    }
    if raw.contains('\\') {
        return Err(WolinError::InvalidFormat(
            "Blob path must use forward slashes ('/')".to_string(),
        ));
    }
    for segment in raw.split('/') {
        if segment == ".." || segment == "." {
            return Err(WolinError::InvalidFormat(format!(
                "Invalid relative path segment '{segment}' in '{raw}'"
            )));
        }
    }
    Ok(())
}

fn validate_blob_key(key: &str) -> Result<&str> {
    validate_no_traversal(key)?;
    if key.ends_with('/') {
        return Err(WolinError::InvalidFormat(format!(
            "Blob key '{key}' must not end with '/'"
        )));
    }
    let clean = key.trim_start_matches('/');
    if clean.is_empty() {
        return Err(WolinError::InvalidFormat(
            "Blob key must not be empty".to_string(),
        ));
    }
    if clean.split('/').any(str::is_empty) {
        return Err(WolinError::InvalidFormat(format!(
            "Blob key '{key}' contains empty path segments"
        )));
    }
    Ok(clean)
}

fn validate_prefix(prefix: &str) -> Result<&str> {
    validate_no_traversal(prefix)?;
    let clean = prefix.trim_start_matches('/');
    if clean.contains("//") {
        return Err(WolinError::InvalidFormat(format!(
            "Blob prefix '{prefix}' contains empty path segments"
        )));
    }
    Ok(clean)
}

fn map_opendal_error(op: &str, path: &str, err: opendal::Error) -> WolinError {
    match err.kind() {
        ErrorKind::NotFound => WolinError::NotFound(format!("Blob '{path}' not found: {err}")),
        ErrorKind::PermissionDenied => {
            WolinError::Unauthorized(format!("Permission denied on blob '{path}': {err}"))
        }
        ErrorKind::ConfigInvalid => {
            WolinError::InvalidFormat(format!("Invalid storage config on '{path}': {err}"))
        }
        _ => WolinError::Storage(format!("OpenDAL {op} error on '{path}': {err}")),
    }
}
