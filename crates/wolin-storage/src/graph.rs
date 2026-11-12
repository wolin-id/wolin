use oxigraph::store::Store;
use wolin_core::{Result, WolinError};

#[derive(Clone)]
pub struct SemanticGraphStore {
    store: Store,
}

impl SemanticGraphStore {
    pub fn new_in_memory() -> Result<Self> {
        let store = Store::new()
            .map_err(|e| WolinError::Semantic(format!("Oxigraph init failed: {e}")))?;
        Ok(Self { store })
    }

    pub fn inner(&self) -> &Store {
        &self.store
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oxigraph_in_memory_initialization() {
        let store = SemanticGraphStore::new_in_memory();
        assert!(store.is_ok());
    }
}
