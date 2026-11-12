use opendal::{services::Fs, Operator};
use wolin_core::{Result, WolinError};

#[derive(Clone)]
pub struct PhysicalStore {
    operator: Operator,
}

impl PhysicalStore {
    /// Initialize local filesystem storage rooted at given directory
    pub fn new_fs(root: &str) -> Result<Self> {
        let builder = Fs::default().root(root);
        let op = Operator::new(builder)
            .map_err(|e| WolinError::Storage(format!("OpenDAL fs init failed: {e}")))?
            .finish();
        Ok(Self { operator: op })
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.operator
            .read(path)
            .await
            .map(|buf| buf.to_vec())
            .map_err(|e| WolinError::Storage(format!("OpenDAL read error: {e}")))
    }

    pub async fn write(&self, path: &str, data: Vec<u8>) -> Result<()> {
        self.operator
            .write(path, data)
            .await
            .map_err(|e| WolinError::Storage(format!("OpenDAL write error: {e}")))
    }

    pub async fn delete(&self, path: &str) -> Result<()> {
        self.operator
            .delete(path)
            .await
            .map_err(|e| WolinError::Storage(format!("OpenDAL delete error: {e}")))
    }
}
