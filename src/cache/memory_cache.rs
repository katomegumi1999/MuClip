use crate::database::{Database, HistoryItem, content_fingerprint};
use chrono::Local;

pub const DEFAULT_MAX_CACHE_ITEMS: usize = 100;
pub const DEFAULT_MAX_CACHE_BYTES: usize = 5 * 1024 * 1024; // 5 MB

pub struct MemoryCache {
    items: Vec<HistoryItem>,
    /// 与 `items` 一一对应的内容指纹。
    ///
    /// 剪贴板里常见的是一条几十上百 KB 的正文，和缓存里每条逐一 `str` 比对，
    /// 单次粘贴就可能比掉几 MB。先比 16 字节指纹，只有命中才去比正文。
    /// **不变式：`hashes.len() == items.len()`，且下标一一对应**——
    /// 任何改动 `items` 增删的实现都必须同步 `hashes`。
    hashes: Vec<[u8; 16]>,
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
            hashes: Vec::new(),
            max_items,
            max_bytes,
            current_bytes: 0,
            dirty: false,
        }
    }

    /// Load recent history from the database into the memory cache.
    pub fn load_from_db(&mut self, db: &Database) -> rusqlite::Result<()> {
        let loaded = db.query_history(self.max_items)?;
        self.hashes = loaded
            .iter()
            .map(|i| content_fingerprint(&i.content))
            .collect();
        self.items = loaded;
        self.recalculate_bytes();
        self.dirty = false;
        Ok(())
    }

    /// 按指纹找位置；指纹撞了再比正文（128 位指纹实际不可能撞，兜底而已）。
    fn find_by_fingerprint(&self, fingerprint: &[u8; 16], content: &str) -> Option<usize> {
        self.hashes
            .iter()
            .enumerate()
            .filter(|(_, h)| *h == fingerprint)
            .map(|(i, _)| i)
            .find(|&i| self.items[i].content == content)
    }

    /// Add a copied text into memory cache.
    /// Handles continuous duplicate detection and LRU promotion.
    /// Returns true if items were changed/added.
    pub fn add_item(&mut self, content: String, db: Option<&mut Database>) -> bool {
        if content.is_empty() {
            return false;
        }

        let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let fingerprint = content_fingerprint(&content);

        // 1. Check if the most recent item is exactly identical (continuous duplicate)
        if let Some(first) = self.items.first_mut() {
            if self.hashes.first() == Some(&fingerprint) && first.content == content {
                first.last_used_at = now;
                self.dirty = true;
                if let Some(database) = db {
                    let _ = database.upsert_history(&content, Some(&first.last_used_at));
                }
                return true;
            }
        }

        // 2. Check if the content already exists elsewhere in the cache
        if let Some(pos) = self.find_by_fingerprint(&fingerprint, &content) {
            let mut item = self.items.remove(pos);
            self.hashes.remove(pos);
            item.last_used_at = now;
            self.items.insert(0, item);
            self.hashes.insert(0, fingerprint);
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
        self.hashes.insert(0, fingerprint);
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
                self.hashes.pop();
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
            self.hashes.remove(pos);
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
        self.hashes.clear();
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

    /// 指纹必须和条目一一对应：错位最坏会让「去重」认成别人，直接把用户的历史顶掉。
    #[test]
    fn fingerprints_stay_aligned_with_items() {
        let mut cache = MemoryCache::with_limits(3, 1024 * 1024);

        for s in ["a", "b", "c", "d", "e"] {
            cache.add_item(s.to_string(), None);
            assert_eq!(cache.hashes.len(), cache.items.len());
        }

        // 命中中段并提升到队首
        cache.add_item("c".to_string(), None);
        assert_eq!(cache.hashes.len(), cache.items.len());
        assert_eq!(cache.items[0].content, "c");

        // 删除
        let id = cache.items[1].id;
        cache.remove_item(id);
        assert_eq!(cache.hashes.len(), cache.items.len());

        // 清空
        cache.clear();
        assert!(cache.hashes.is_empty());
        assert!(cache.items.is_empty());

        // 清空后还能重新灌入
        cache.add_item("z".to_string(), None);
        assert_eq!(cache.hashes.len(), 1);
    }

    /// 大正文走指纹去重：内容不变时不重复入表，命中后提升到队首。
    #[test]
    fn large_payload_is_deduplicated_by_fingerprint() {
        let mut cache = MemoryCache::with_limits(10, 10 * 1024 * 1024);
        let big = "数据".repeat(50_000); // ~300 KB，字符数 100k

        cache.add_item(big.clone(), None);
        cache.add_item("另一条".to_string(), None);
        assert_eq!(cache.items.len(), 2);

        assert!(cache.add_item(big.clone(), None));
        assert_eq!(cache.items.len(), 2, "相同正文不应该产生第二条");
        assert_eq!(
            cache.items[0].content.len(),
            big.len(),
            "命中后应提升到队首"
        );
        assert_eq!(cache.items[1].content, "另一条");
    }

    /// 指纹相同但正文不同（构造一个假碰撞）时不能误判成同一条。
    #[test]
    fn fingerprint_collision_falls_back_to_content_comparison() {
        let mut cache = MemoryCache::with_limits(10, 1024 * 1024);
        cache.add_item("真实内容".to_string(), None);

        // 人为把指纹改成和候选一致，模拟 128 位碰撞
        let fake = content_fingerprint("另一段完全不同的内容");
        cache.hashes[0] = fake;

        // 指纹命中但正文不同 → 必须走「新增」分支，而不是把旧条目替换掉
        cache.add_item("另一段完全不同的内容".to_string(), None);
        assert_eq!(cache.items.len(), 2);
        assert_eq!(cache.items[1].content, "真实内容");
    }
}
