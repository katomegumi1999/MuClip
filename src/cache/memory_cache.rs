use crate::database::{Database, HistoryItem};
use chrono::Local;

pub const DEFAULT_MAX_CACHE_ITEMS: usize = 100;
pub const DEFAULT_MAX_CACHE_BYTES: usize = 5 * 1024 * 1024; // 5 MB

pub struct MemoryCache {
    items: Vec<HistoryItem>,
    max_items: usize,
    max_bytes: usize,
    current_bytes: usize,
    dirty: bool,
}

impl Default for MemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl MemoryCache {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_CACHE_ITEMS, DEFAULT_MAX_CACHE_BYTES)
    }

    pub fn with_limits(max_items: usize, max_bytes: usize) -> Self {
        Self {
            items: Vec::new(),
            max_items,
            max_bytes,
            current_bytes: 0,
            dirty: false,
        }
    }

    /// Load recent history from the database into the memory cache.
    pub fn load_from_db(&mut self, db: &Database) -> rusqlite::Result<()> {
        let loaded = db.query_history(self.max_items)?;
        self.items = loaded;
        self.recalculate_bytes();
        self.dirty = false;
        Ok(())
    }

    /// Add a copied text into memory cache.
    /// Handles continuous duplicate detection and LRU promotion.
    /// Returns true if items were changed/added.
    pub fn add_item(&mut self, content: String, db: Option<&mut Database>) -> bool {
        if content.is_empty() {
            return false;
        }

        let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        // 1. Check if the most recent item is exactly identical (continuous duplicate)
        if let Some(first) = self.items.first_mut() {
            if first.content == content {
                first.last_used_at = now;
                self.dirty = true;
                if let Some(database) = db {
                    let _ = database.upsert_history(&content, Some(&first.last_used_at));
                }
                return true;
            }
        }

        // 2. Check if the content already exists elsewhere in the cache
        if let Some(pos) = self.items.iter().position(|i| i.content == content) {
            let mut item = self.items.remove(pos);
            item.last_used_at = now;
            self.items.insert(0, item);
            self.dirty = true;
            if let Some(database) = db {
                let _ = database.upsert_history(&content, Some(&self.items[0].last_used_at));
            }
            return true;
        }

        // 3. New item
        let item_bytes = content.len();
        let new_item = HistoryItem::new(0, content.clone(), now.clone(), now.clone());

        self.items.insert(0, new_item);
        self.current_bytes += item_bytes;
        self.dirty = true;

        // Persist to database immediately or batch
        if let Some(database) = db {
            if let Ok(id) = database.upsert_history(&content, Some(&now)) {
                if let Some(first) = self.items.first_mut() {
                    first.id = id;
                }
            }
        }

        // 4. Enforce cache limits (evict oldest if needed, they remain safe in SQLite)
        self.trim_excess();

        true
    }

    fn trim_excess(&mut self) {
        while self.items.len() > self.max_items || self.current_bytes > self.max_bytes {
            if let Some(evicted) = self.items.pop() {
                self.current_bytes = self.current_bytes.saturating_sub(evicted.content.len());
            } else {
                break;
            }
        }
    }

    fn recalculate_bytes(&mut self) {
        self.current_bytes = self.items.iter().map(|i| i.content.len()).sum();
    }

    /// Delete a single item from the cache.
    pub fn remove_item(&mut self, id: i64) -> bool {
        if let Some(pos) = self.items.iter().position(|i| i.id == id) {
            let removed = self.items.remove(pos);
            self.current_bytes = self.current_bytes.saturating_sub(removed.content.len());
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Clear all cached items.
    pub fn clear(&mut self) {
        self.items.clear();
        self.current_bytes = 0;
        self.dirty = true;
    }

    /// Retrieve a reference to all items currently in memory.
    pub fn get_items(&self) -> &[HistoryItem] {
        &self.items
    }

    /// Search within the memory cache.
    pub fn search(&self, query: &str) -> Vec<HistoryItem> {
        let q = query.to_lowercase();
        self.items
            .iter()
            .filter(|i| i.content.to_lowercase().contains(&q))
            .cloned()
            .collect()
    }

    /// Flush all current memory state into SQLite.
    pub fn flush_to_db(&mut self, db: &mut Database) -> rusqlite::Result<()> {
        if !self.dirty {
            return Ok(());
        }

        for item in &mut self.items {
            let id = db.upsert_history(&item.content, Some(&item.last_used_at))?;
            item.id = id;
        }

        self.dirty = false;
        Ok(())
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_cache_dedup_and_lru() {
        let mut cache = MemoryCache::with_limits(3, 1000);

        // Add item A
        cache.add_item("Item A".to_string(), None);
        assert_eq!(cache.get_items().len(), 1);
        assert_eq!(cache.get_items()[0].content, "Item A");

        // Consecutive duplicate: shouldn't duplicate
        cache.add_item("Item A".to_string(), None);
        assert_eq!(cache.get_items().len(), 1);

        // Add B and C
        cache.add_item("Item B".to_string(), None);
        cache.add_item("Item C".to_string(), None);
        assert_eq!(cache.get_items().len(), 3);
        assert_eq!(cache.get_items()[0].content, "Item C");
        assert_eq!(cache.get_items()[1].content, "Item B");
        assert_eq!(cache.get_items()[2].content, "Item A");

        // Re-copy A: should bring A to front (index 0)
        cache.add_item("Item A".to_string(), None);
        assert_eq!(cache.get_items().len(), 3);
        assert_eq!(cache.get_items()[0].content, "Item A");
        assert_eq!(cache.get_items()[1].content, "Item C");
        assert_eq!(cache.get_items()[2].content, "Item B");

        // Add D: should evict oldest (B) due to max_items = 3
        cache.add_item("Item D".to_string(), None);
        assert_eq!(cache.get_items().len(), 3);
        assert_eq!(cache.get_items()[0].content, "Item D");
        assert_eq!(cache.get_items()[1].content, "Item A");
        assert_eq!(cache.get_items()[2].content, "Item C");
    }

    #[test]
    fn test_memory_cache_search() {
        let mut cache = MemoryCache::new();
        cache.add_item("apple pie".to_string(), None);
        cache.add_item("banana split".to_string(), None);
        cache.add_item("orange juice".to_string(), None);

        let res = cache.search("an");
        assert_eq!(res.len(), 2);
    }
}
