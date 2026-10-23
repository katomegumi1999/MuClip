use crate::cache::MemoryCache;
use crate::content::{ContentAnalysis, analyze_content, format_preview};
use crate::database::{Database, HistoryItem, PhraseItem};
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MuClipError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Mutex lock poisoned: {0}")]
    LockError(String),
}

pub struct InnerEngine {
    pub db: Database,
    pub cache: MemoryCache,
}

#[derive(uniffi::Object)]
pub struct MuClipEngine {
    inner: Mutex<InnerEngine>,
}

#[uniffi::export]
impl MuClipEngine {
    #[uniffi::constructor]
    pub fn new(db_path: String) -> Result<Arc<Self>, MuClipError> {
        let db = Database::open(&db_path).map_err(|e| MuClipError::DatabaseError(e.to_string()))?;
        let mut cache = MemoryCache::new();
        let _ = cache.load_from_db(&db);
        Ok(Arc::new(Self {
            inner: Mutex::new(InnerEngine { db, cache }),
        }))
    }

    #[uniffi::constructor]
    pub fn new_with_key(
        db_path: String,
        key_hex: Option<String>,
    ) -> Result<Arc<Self>, MuClipError> {
        let db = Database::open_with_key(&db_path, key_hex.as_deref())
            .map_err(|e| MuClipError::DatabaseError(e.to_string()))?;
        let mut cache = MemoryCache::new();
        let _ = cache.load_from_db(&db);
        Ok(Arc::new(Self {
            inner: Mutex::new(InnerEngine { db, cache }),
        }))
    }

    #[uniffi::constructor]
    pub fn new_in_memory() -> Result<Arc<Self>, MuClipError> {
        let db =
            Database::open_in_memory().map_err(|e| MuClipError::DatabaseError(e.to_string()))?;
        let cache = MemoryCache::new();
        Ok(Arc::new(Self {
            inner: Mutex::new(InnerEngine { db, cache }),
        }))
    }

    pub fn add_history(&self, content: String) -> Result<i64, MuClipError> {
        let mut engine = self
            .inner
            .lock()
            .map_err(|e| MuClipError::LockError(e.to_string()))?;
        let InnerEngine { cache, db } = &mut *engine;
        cache.add_item(content, Some(db));
        if let Some(first) = cache.get_items().first() {
            return Ok(first.id);
        }
        Ok(-1)
    }

    pub fn query_history(&self, limit: u32) -> Result<Vec<HistoryItem>, MuClipError> {
        let engine = self
            .inner
            .lock()
            .map_err(|e| MuClipError::LockError(e.to_string()))?;
        let items = match engine.db.query_history(limit as usize) {
            Ok(res) => res,
            Err(_) => engine
                .cache
                .get_items()
                .iter()
                .take(limit as usize)
                .cloned()
                .collect(),
        };
        Ok(items)
    }

    pub fn search_history(
        &self,
        query: String,
        limit: u32,
    ) -> Result<Vec<HistoryItem>, MuClipError> {
        let engine = self
            .inner
            .lock()
            .map_err(|e| MuClipError::LockError(e.to_string()))?;
        let items = engine
            .db
            .search_history(&query, limit as usize)
            .unwrap_or_default();
        Ok(items)
    }

    pub fn delete_history(&self, id: i64) -> Result<bool, MuClipError> {
        let mut engine = self
            .inner
            .lock()
            .map_err(|e| MuClipError::LockError(e.to_string()))?;
        let InnerEngine { cache, db } = &mut *engine;
        cache.remove_item(id);
        let ok = db.delete_history(id).is_ok();
        Ok(ok)
    }

    pub fn clear_all_history(&self) -> Result<bool, MuClipError> {
        let mut engine = self
            .inner
            .lock()
            .map_err(|e| MuClipError::LockError(e.to_string()))?;
        let InnerEngine { cache, db } = &mut *engine;
        cache.clear();
        let ok = db.clear_all_history().is_ok();
        Ok(ok)
    }

    pub fn cleanup_expired_history(&self, days: u32) -> Result<u32, MuClipError> {
        let mut engine = self
            .inner
            .lock()
            .map_err(|e| MuClipError::LockError(e.to_string()))?;
        let count = engine.db.cleanup_expired_history(days).unwrap_or(0);
        Ok(count as u32)
    }

    pub fn add_phrase(&self, content: String) -> Result<i64, MuClipError> {
        let mut engine = self
            .inner
            .lock()
            .map_err(|e| MuClipError::LockError(e.to_string()))?;
        let id = engine
            .db
            .add_phrase(content.trim())
            .map_err(|e| MuClipError::DatabaseError(e.to_string()))?;
        Ok(id)
    }

    pub fn edit_phrase(&self, id: i64, new_content: String) -> Result<bool, MuClipError> {
        let mut engine = self
            .inner
            .lock()
            .map_err(|e| MuClipError::LockError(e.to_string()))?;
        let ok = engine.db.edit_phrase(id, new_content.trim()).is_ok();
        Ok(ok)
    }

    pub fn delete_phrase(&self, id: i64) -> Result<bool, MuClipError> {
        let mut engine = self
            .inner
            .lock()
            .map_err(|e| MuClipError::LockError(e.to_string()))?;
        let ok = engine.db.delete_phrase(id).is_ok();
        Ok(ok)
    }

    pub fn query_phrases(&self) -> Result<Vec<PhraseItem>, MuClipError> {
        let engine = self
            .inner
            .lock()
            .map_err(|e| MuClipError::LockError(e.to_string()))?;
        let items = engine.db.query_phrases().unwrap_or_default();
        Ok(items)
    }

    pub fn search_phrases(&self, query: String) -> Result<Vec<PhraseItem>, MuClipError> {
        let engine = self
            .inner
            .lock()
            .map_err(|e| MuClipError::LockError(e.to_string()))?;
        let items = engine.db.search_phrases(&query).unwrap_or_default();
        Ok(items)
    }

    pub fn update_phrase_used(&self, id: i64) -> Result<bool, MuClipError> {
        let mut engine = self
            .inner
            .lock()
            .map_err(|e| MuClipError::LockError(e.to_string()))?;
        let ok = engine.db.update_phrase_used(id).is_ok();
        Ok(ok)
    }

    pub fn reorder_phrases(&self, ordered_ids: Vec<i64>) -> Result<bool, MuClipError> {
        let mut engine = self
            .inner
            .lock()
            .map_err(|e| MuClipError::LockError(e.to_string()))?;
        let ok = engine.db.reorder_phrases(&ordered_ids).is_ok();
        Ok(ok)
    }

    pub fn flush_to_db(&self) -> Result<(), MuClipError> {
        let mut engine = self
            .inner
            .lock()
            .map_err(|e| MuClipError::LockError(e.to_string()))?;
        let InnerEngine { cache, db } = &mut *engine;
        let _ = cache.flush_to_db(db);
        Ok(())
    }
}

#[uniffi::export]
pub fn muclip_format_preview(text: String, max_chars: u32) -> String {
    format_preview(&text, max_chars as usize)
}

#[uniffi::export]
pub fn muclip_analyze_content(text: String) -> ContentAnalysis {
    analyze_content(&text)
}

#[uniffi::export]
pub fn muclip_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uniffi_engine() {
        let engine = MuClipEngine::new_in_memory().unwrap();
        let id = engine.add_history("Test UniFFI item".to_string()).unwrap();
        assert!(id > 0);

        let items = engine.query_history(10).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].content, "Test UniFFI item");

        let analysis = muclip_analyze_content("https://example.com".to_string());
        assert_eq!(analysis.content_type, crate::content::ContentType::Url);

        let preview = muclip_format_preview("line1\nline2".to_string(), 50);
        assert_eq!(preview, "line1 line2");
    }
}
