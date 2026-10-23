use crate::content::{ContentType, analyze_content};
use chrono::Local;
use rusqlite::{Connection, Result, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryItem {
    pub id: i64,
    pub content: String,
    pub created_at: String,
    pub last_used_at: String,
    #[serde(default)]
    pub content_type: ContentType,
    #[serde(default)]
    pub char_count: u64,
    #[serde(default)]
    pub line_count: u64,
    #[serde(default)]
    pub byte_count: u64,
    #[serde(default)]
    pub preview: String,
}

impl HistoryItem {
    pub fn new(id: i64, content: String, created_at: String, last_used_at: String) -> Self {
        let analysis = analyze_content(&content);
        Self {
            id,
            content,
            created_at,
            last_used_at,
            content_type: analysis.content_type,
            char_count: analysis.char_count,
            line_count: analysis.line_count,
            byte_count: analysis.byte_count,
            preview: analysis.preview,
        }
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhraseItem {
    pub id: i64,
    pub content: String,
    pub created_at: String,
    pub last_used_at: String,
    pub sort_order: i64,
    #[serde(default)]
    pub content_type: ContentType,
    #[serde(default)]
    pub char_count: u64,
    #[serde(default)]
    pub line_count: u64,
    #[serde(default)]
    pub byte_count: u64,
    #[serde(default)]
    pub preview: String,
}

impl PhraseItem {
    pub fn new(
        id: i64,
        content: String,
        created_at: String,
        last_used_at: String,
        sort_order: i64,
    ) -> Self {
        let analysis = analyze_content(&content);
        Self {
            id,
            content,
            created_at,
            last_used_at,
            sort_order,
            content_type: analysis.content_type,
            char_count: analysis.char_count,
            line_count: analysis.line_count,
            byte_count: analysis.byte_count,
            preview: analysis.preview,
        }
    }
}

fn default_is_enabled() -> i32 {
    1
}

fn default_position_mode() -> i32 {
    1
}

fn deserialize_is_enabled<'de, D>(deserializer: D) -> std::result::Result<i32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct IntOrBool;
    impl<'de> serde::de::Visitor<'de> for IntOrBool {
        type Value = i32;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a boolean or an integer (0 or 1)")
        }
        fn visit_bool<E>(self, v: bool) -> std::result::Result<i32, E> {
            Ok(if v { 1 } else { 0 })
        }
        fn visit_i64<E>(self, v: i64) -> std::result::Result<i32, E> {
            Ok(if v != 0 { 1 } else { 0 })
        }
        fn visit_u64<E>(self, v: u64) -> std::result::Result<i32, E> {
            Ok(if v != 0 { 1 } else { 0 })
        }
    }
    deserializer.deserialize_any(IntOrBool)
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhraseRule {
    #[serde(default)]
    pub id: String,
    pub phrase_id: i64,
    #[serde(
        default = "default_is_enabled",
        deserialize_with = "deserialize_is_enabled"
    )]
    pub is_enabled: i32,
    #[serde(default)]
    pub insert_position: i64,
    #[serde(default = "default_position_mode")]
    pub position_mode: i32,
    pub start_time: String,
    pub end_time: String,
    pub append_text: String,
    #[serde(default)]
    pub created_at: i64,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhraseRuleTemplate {
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub insert_position: i64,
    #[serde(default = "default_position_mode")]
    pub position_mode: i32,
    pub start_time: String,
    pub end_time: String,
    pub append_text: String,
    #[serde(default)]
    pub created_at: i64,
}

pub struct Database {
    conn: Connection,
    /// 数据库是否**确实**处于加密状态。
    ///
    /// 不能用「调用方传了 key」来推断：`PRAGMA key` 在未启用 SEE / SQLCipher 的
    /// 构建里是一个未知 pragma，SQLite 会静默忽略它——调用成功、数据照旧明文写盘。
    /// 所以这里只在运行期探测到 cipher 扩展存在时才为 `true`。
    encryption_active: bool,
}

/// 探测本次链接的 SQLite 是否带加密扩展（SEE / SQLCipher）。
///
/// 未启用时 `PRAGMA cipher_version` 是未知 pragma，会返回空结果集，
/// `query_row` 因此报 `QueryReturnedNoRows`；两种情况一并视为「不支持」。
fn sqlite_has_cipher(conn: &Connection) -> bool {
    conn.query_row("PRAGMA cipher_version", [], |row| row.get::<_, String>(0))
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// 用一个临时内存连接探测加密扩展是否存在。
///
/// 与 [`sqlite_has_cipher`] 的区别：这个不碰目标文件，因此可以在**决定怎么打开
/// 磁盘上那个文件之前**先问「当前构建到底能不能加密」。
fn probe_cipher_support() -> bool {
    Connection::open_in_memory()
        .map(|c| sqlite_has_cipher(&c))
        .unwrap_or(false)
}

/// 判断密钥是不是 64 位十六进制（256 bit）。
fn is_hex_key_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 把密钥交给 SQLCipher。
///
/// 64 位十六进制串走 **raw key** 形式 `PRAGMA key = "x'…'"`，跳过 SQLCipher 的
/// PBKDF2（默认 25 万轮），打开几乎零延迟；其他任意字符串按口令处理，由
/// SQLCipher 自己派生。
fn apply_key(conn: &Connection, key: &str) -> Result<()> {
    if is_hex_key_64(key) {
        // key 已校验为纯十六进制，拼接进 SQL 无注入风险
        conn.execute_batch(&format!("PRAGMA key = \"x'{key}'\";"))
    } else {
        conn.pragma_update(None, "key", key)
    }
}

#[allow(dead_code)]
impl Database {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_key(path, None)
    }

    /// 打开数据库，可选传入密钥。密钥为空 / `None` 即明文模式。
    ///
    /// **加密是可选能力**：只有构建时启用 `sqlcipher` 特性（`--features sqlcipher`），
    /// 且调用方确实传了密钥，库文件才会以密文落盘；两者缺一都退回明文，并打一条
    /// WARN 让宿主能把真实状态显示出来（[`Database::is_encrypted`]）。
    ///
    /// 密钥形状决定 SQLCipher 的处理方式：64 位十六进制按 raw key 用，跳过 PBKDF2；
    /// 其他字符串按口令处理。
    ///
    /// **打开一个"不合适"的库会直接失败**：加密模式下打开明文旧库、口令模式下打开密文库、
    /// 或者密钥不对，都会在首次读取时报 `file is not a database` / `decryption failed`。
    /// 本函数不做任何探测或事后迁移——新建库从第一页起就是密文，旧数据请走 `.mubc`
    /// 备份/还原。失败时会额外打一条说明性日志，避免宿主只看到「打不开」。
    pub fn open_with_key<P: AsRef<Path>>(path: P, key_hex: Option<&str>) -> Result<Self> {
        let path = path.as_ref();
        let key = key_hex.map(str::trim).filter(|k| !k.is_empty());
        let cipher_ready = probe_cipher_support();
        let mut encryption_active = false;

        let conn = Connection::open(path)?;
        if let Some(k) = key {
            if cipher_ready {
                apply_key(&conn, k)?;
                encryption_active = true;
            } else {
                // 这条必须足够显眼：安全承诺与实现不符是最容易误导用户的缺陷，
                // 而它此前是静默的——调用方以为加密了，磁盘上却是明文。
                crate::log_warn!(
                    "SQLite 加密不可用：本次构建未启用 sqlcipher 特性，密钥被忽略，\
                     数据库以**明文**存储。若此处参数来自用户的加密开关，请勿在界面上声称已加密。"
                );
            }
        }

        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let db = Self {
            conn,
            encryption_active,
        };
        if let Err(e) = db.init_tables() {
            // 首次读取才是校验密钥的时机，所以「密钥不对 / 库不是本密钥的」都报在这一步，
            // 原生错误信息只有一句 file is not a database，宿主看不出所以然。
            if encryption_active {
                crate::log_error!(
                    "无法用当前密钥打开数据库（密钥不匹配，或该库不是由它创建的）：{}",
                    e
                );
            }
            return Err(e);
        }
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let db = Self {
            conn,
            encryption_active: false,
        };
        db.init_tables()?;
        Ok(db)
    }

    /// 数据库文件是否真的加密了。
    ///
    /// 给宿主如实展示用。返回 `false` 时不应在任何 UI 上标注「已加密」。
    pub fn is_encrypted(&self) -> bool {
        self.encryption_active
    }

    fn init_tables(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS clipboard_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT NOT NULL,
                content_type TEXT,
                char_count INTEGER,
                line_count INTEGER,
                byte_count INTEGER,
                preview TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_history_last_used 
                ON clipboard_history(last_used_at DESC);

            CREATE INDEX IF NOT EXISTS idx_history_content 
                ON clipboard_history(content);

            CREATE TABLE IF NOT EXISTS phrases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT NOT NULL,
                sort_order INTEGER DEFAULT 0,
                content_type TEXT,
                char_count INTEGER,
                line_count INTEGER,
                byte_count INTEGER,
                preview TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_phrases_sort 
                ON phrases(sort_order ASC, last_used_at DESC);

            CREATE TABLE IF NOT EXISTS secure_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS phrase_rules (
                id TEXT PRIMARY KEY,
                phrase_id INTEGER NOT NULL,
                is_enabled INTEGER NOT NULL DEFAULT 1,
                insert_position INTEGER NOT NULL DEFAULT 0,
                position_mode INTEGER NOT NULL DEFAULT 1,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                append_text TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                FOREIGN KEY(phrase_id) REFERENCES phrases(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_phrase_rules_phrase_id 
                ON phrase_rules(phrase_id);

            CREATE TABLE IF NOT EXISTS phrase_rule_templates (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                insert_position INTEGER NOT NULL DEFAULT 0,
                position_mode INTEGER NOT NULL DEFAULT 1,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                append_text TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );
            ",
        )?;

        // Seamless migration for existing database files
        for table in ["clipboard_history", "phrases"] {
            for col_def in [
                "content_type TEXT",
                "char_count INTEGER",
                "line_count INTEGER",
                "byte_count INTEGER",
                "preview TEXT",
            ] {
                let _ = self
                    .conn
                    .execute(&format!("ALTER TABLE {} ADD COLUMN {}", table, col_def), []);
            }
        }

        Ok(())
    }

    fn row_to_history_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<HistoryItem> {
        let id: i64 = row.get(0)?;
        let content: String = row.get(1)?;
        let created_at: String = row.get(2)?;
        let last_used_at: String = row.get(3)?;
        let ctype_opt: Option<String> = row.get(4).ok().flatten();
        let char_opt: Option<i64> = row.get(5).ok().flatten();
        let line_opt: Option<i64> = row.get(6).ok().flatten();
        let byte_opt: Option<i64> = row.get(7).ok().flatten();
        let preview_opt: Option<String> = row.get(8).ok().flatten();

        if let (Some(ct), Some(cc), Some(lc), Some(bc), Some(pv)) =
            (ctype_opt, char_opt, line_opt, byte_opt, preview_opt)
        {
            Ok(HistoryItem {
                id,
                content,
                created_at,
                last_used_at,
                content_type: ContentType::from_db_str(&ct),
                char_count: cc.max(0) as u64,
                line_count: lc.max(1) as u64,
                byte_count: bc.max(0) as u64,
                preview: pv,
            })
        } else {
            Ok(HistoryItem::new(id, content, created_at, last_used_at))
        }
    }

    fn row_to_phrase_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<PhraseItem> {
        let id: i64 = row.get(0)?;
        let content: String = row.get(1)?;
        let created_at: String = row.get(2)?;
        let last_used_at: String = row.get(3)?;
        let sort_order: i64 = row.get(4)?;
        let ctype_opt: Option<String> = row.get(5).ok().flatten();
        let char_opt: Option<i64> = row.get(6).ok().flatten();
        let line_opt: Option<i64> = row.get(7).ok().flatten();
        let byte_opt: Option<i64> = row.get(8).ok().flatten();
        let preview_opt: Option<String> = row.get(9).ok().flatten();

        if let (Some(ct), Some(cc), Some(lc), Some(bc), Some(pv)) =
            (ctype_opt, char_opt, line_opt, byte_opt, preview_opt)
        {
            Ok(PhraseItem {
                id,
                content,
                created_at,
                last_used_at,
                sort_order,
                content_type: ContentType::from_db_str(&ct),
                char_count: cc.max(0) as u64,
                line_count: lc.max(1) as u64,
                byte_count: bc.max(0) as u64,
                preview: pv,
            })
        } else {
            Ok(PhraseItem::new(
                id,
                content,
                created_at,
                last_used_at,
                sort_order,
            ))
        }
    }

    fn row_to_phrase_rule(row: &rusqlite::Row<'_>) -> rusqlite::Result<PhraseRule> {
        let created_at: i64 = match row.get(8) {
            Ok(v) => v,
            Err(_) => {
                let s: String = row.get(8)?;
                s.parse::<i64>().unwrap_or(0)
            }
        };
        Ok(PhraseRule {
            id: row.get(0)?,
            phrase_id: row.get(1)?,
            is_enabled: row.get(2)?,
            insert_position: row.get(3)?,
            position_mode: row.get(4)?,
            start_time: row.get(5)?,
            end_time: row.get(6)?,
            append_text: row.get(7)?,
            created_at,
        })
    }

    fn row_to_phrase_rule_template(
        row: &rusqlite::Row<'_>,
    ) -> rusqlite::Result<PhraseRuleTemplate> {
        let created_at: i64 = match row.get(7) {
            Ok(v) => v,
            Err(_) => {
                let s: String = row.get(7)?;
                s.parse::<i64>().unwrap_or(0)
            }
        };
        Ok(PhraseRuleTemplate {
            id: row.get(0)?,
            name: row.get(1)?,
            insert_position: row.get(2)?,
            position_mode: row.get(3)?,
            start_time: row.get(4)?,
            end_time: row.get(5)?,
            append_text: row.get(6)?,
            created_at,
        })
    }

    /// Upsert a history item: if an identical content already exists, update its `last_used_at` timestamp.
    /// Otherwise, insert as a new record. Returns the record id.
    pub fn upsert_history(&mut self, content: &str, timestamp: Option<&str>) -> Result<i64> {
        let now = match timestamp {
            Some(ts) => ts.to_string(),
            None => Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        };

        let existing_id: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM clipboard_history WHERE content = ?1 LIMIT 1",
                params![content],
                |row| row.get(0),
            )
            .ok();

        let analysis = analyze_content(content);

        if let Some(id) = existing_id {
            self.conn.execute(
                "UPDATE clipboard_history 
                 SET last_used_at = ?1, content_type = ?2, char_count = ?3, line_count = ?4, byte_count = ?5, preview = ?6 
                 WHERE id = ?7",
                params![
                    now,
                    analysis.content_type.as_str(),
                    analysis.char_count as i64,
                    analysis.line_count as i64,
                    analysis.byte_count as i64,
                    analysis.preview,
                    id
                ],
            )?;
            Ok(id)
        } else {
            self.conn.execute(
                "INSERT INTO clipboard_history (content, created_at, last_used_at, content_type, char_count, line_count, byte_count, preview) 
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    content,
                    now,
                    now,
                    analysis.content_type.as_str(),
                    analysis.char_count as i64,
                    analysis.line_count as i64,
                    analysis.byte_count as i64,
                    analysis.preview
                ],
            )?;
            Ok(self.conn.last_insert_rowid())
        }
    }

    /// Batch upsert history items inside a transaction.
    /// Items are tuples of `(content, created_at, last_used_at)`.
    pub fn batch_upsert_history(&mut self, items: &[(String, String, String)]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut select_stmt =
                tx.prepare("SELECT id FROM clipboard_history WHERE content = ?1 LIMIT 1")?;
            let mut update_stmt = tx.prepare(
                "UPDATE clipboard_history 
                 SET last_used_at = ?1, content_type = ?2, char_count = ?3, line_count = ?4, byte_count = ?5, preview = ?6 
                 WHERE id = ?7",
            )?;
            let mut insert_stmt = tx.prepare(
                "INSERT INTO clipboard_history (content, created_at, last_used_at, content_type, char_count, line_count, byte_count, preview) 
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;

            for (content, created_at, last_used_at) in items {
                let existing_id: Option<i64> = select_stmt
                    .query_row(params![content], |row| row.get(0))
                    .ok();
                let analysis = analyze_content(content);

                if let Some(id) = existing_id {
                    update_stmt.execute(params![
                        last_used_at,
                        analysis.content_type.as_str(),
                        analysis.char_count as i64,
                        analysis.line_count as i64,
                        analysis.byte_count as i64,
                        analysis.preview,
                        id
                    ])?;
                } else {
                    insert_stmt.execute(params![
                        content,
                        created_at,
                        last_used_at,
                        analysis.content_type.as_str(),
                        analysis.char_count as i64,
                        analysis.line_count as i64,
                        analysis.byte_count as i64,
                        analysis.preview
                    ])?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Query recent history items ordered by last_used_at DESC.
    pub fn query_history(&self, limit: usize) -> Result<Vec<HistoryItem>> {
        self.query_history_page(0, limit)
    }

    /// Query history items with pagination ordered by last_used_at DESC, id DESC.
    pub fn query_history_page(&self, offset: usize, limit: usize) -> Result<Vec<HistoryItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, content, created_at, last_used_at, content_type, char_count, line_count, byte_count, preview 
             FROM clipboard_history 
             ORDER BY last_used_at DESC, id DESC 
             LIMIT ?1 OFFSET ?2",
        )?;

        let rows = stmt.query_map(
            params![limit as i64, offset as i64],
            Self::row_to_history_item,
        )?;

        let mut items = Vec::new();
        for item in rows {
            items.push(item?);
        }
        Ok(items)
    }

    /// Returns total count of persisted history records in SQLite.
    pub fn count_history(&self) -> Result<usize> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM clipboard_history", [], |row| {
                    row.get(0)
                })?;
        Ok(count.max(0) as usize)
    }

    /// Search history items matching the query text.
    pub fn search_history(&self, query: &str, limit: usize) -> Result<Vec<HistoryItem>> {
        let like_query = format!("%{}%", query);
        let mut stmt = self.conn.prepare(
            "SELECT id, content, created_at, last_used_at, content_type, char_count, line_count, byte_count, preview 
             FROM clipboard_history 
             WHERE content LIKE ?1 
             ORDER BY last_used_at DESC 
             LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![like_query, limit as i64], Self::row_to_history_item)?;

        let mut items = Vec::new();
        for item in rows {
            items.push(item?);
        }
        Ok(items)
    }

    /// Delete a single history item by id.
    pub fn delete_history(&mut self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM clipboard_history WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Clear all history records.
    pub fn clear_all_history(&mut self) -> Result<()> {
        self.conn.execute("DELETE FROM clipboard_history", [])?;
        Ok(())
    }

    /// Delete history items older than the specified retention days.
    pub fn cleanup_expired_history(&mut self, days: u32) -> Result<usize> {
        let modifier = format!("-{} days", days);
        let deleted = self.conn.execute(
            "DELETE FROM clipboard_history WHERE datetime(last_used_at) < datetime('now', 'localtime', ?1)",
            params![modifier],
        )?;
        Ok(deleted)
    }

    // --- Phrase operations ---

    /// Add a new phrase. Automatically assigns sort_order at the end.
    pub fn add_phrase(&mut self, content: &str) -> Result<i64> {
        let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let max_sort: Option<i64> = self
            .conn
            .query_row("SELECT MAX(sort_order) FROM phrases", [], |row| row.get(0))
            .unwrap_or(None);
        let next_sort = max_sort.unwrap_or(0) + 1;
        let analysis = analyze_content(content);

        self.conn.execute(
            "INSERT INTO phrases (content, created_at, last_used_at, sort_order, content_type, char_count, line_count, byte_count, preview) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                content,
                now,
                now,
                next_sort,
                analysis.content_type.as_str(),
                analysis.char_count as i64,
                analysis.line_count as i64,
                analysis.byte_count as i64,
                analysis.preview
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Edit the content of an existing phrase.
    pub fn edit_phrase(&mut self, id: i64, new_content: &str) -> Result<()> {
        let analysis = analyze_content(new_content);
        self.conn.execute(
            "UPDATE phrases 
             SET content = ?1, content_type = ?2, char_count = ?3, line_count = ?4, byte_count = ?5, preview = ?6 
             WHERE id = ?7",
            params![
                new_content,
                analysis.content_type.as_str(),
                analysis.char_count as i64,
                analysis.line_count as i64,
                analysis.byte_count as i64,
                analysis.preview,
                id
            ],
        )?;
        Ok(())
    }

    /// Delete a phrase by id.
    pub fn delete_phrase(&mut self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM phrases WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Clear all phrase records.
    pub fn clear_all_phrases(&mut self) -> Result<()> {
        self.conn.execute("DELETE FROM phrases", [])?;
        Ok(())
    }

    /// Mark a phrase as used, updating its `last_used_at` timestamp.
    pub fn update_phrase_used(&mut self, id: i64) -> Result<()> {
        let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.conn.execute(
            "UPDATE phrases SET last_used_at = ?1 WHERE id = ?2",
            params![now, id],
        )?;
        Ok(())
    }

    /// Query all phrases ordered by sort_order and last_used_at.
    pub fn query_phrases(&self) -> Result<Vec<PhraseItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, content, created_at, last_used_at, sort_order, content_type, char_count, line_count, byte_count, preview 
             FROM phrases 
             ORDER BY sort_order ASC, last_used_at DESC",
        )?;

        let rows = stmt.query_map([], Self::row_to_phrase_item)?;

        let mut items = Vec::new();
        for item in rows {
            items.push(item?);
        }
        Ok(items)
    }

    /// Search phrases matching the query text.
    pub fn search_phrases(&self, query: &str) -> Result<Vec<PhraseItem>> {
        let like_query = format!("%{}%", query);
        let mut stmt = self.conn.prepare(
            "SELECT id, content, created_at, last_used_at, sort_order, content_type, char_count, line_count, byte_count, preview 
             FROM phrases 
             WHERE content LIKE ?1 
             ORDER BY sort_order ASC, last_used_at DESC",
        )?;

        let rows = stmt.query_map(params![like_query], Self::row_to_phrase_item)?;

        let mut items = Vec::new();
        for item in rows {
            items.push(item?);
        }
        Ok(items)
    }

    /// Reorders phrases by updating their sort_order to match the sequence in `ordered_ids`.
    pub fn reorder_phrases(&mut self, ordered_ids: &[i64]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare("UPDATE phrases SET sort_order = ?1 WHERE id = ?2")?;
            for (order, &id) in ordered_ids.iter().enumerate() {
                let _ = stmt.execute(params![order as i64, id]);
            }
        }
        tx.commit()?;
        Ok(())
    }

    // --- Secure Config / Key-Value operations ---

    /// Sets a persistent configuration key-value pair in SQLite.
    pub fn set_config(&mut self, key: &str, value: &str) -> Result<()> {
        let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.conn.execute(
            "INSERT INTO secure_config (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key, value, now],
        )?;
        Ok(())
    }

    /// Gets a persistent configuration value by key.
    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM secure_config WHERE key = ?1 LIMIT 1")?;
        let mut rows = stmt.query(params![key])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    // --- Phrase Rules operations ---

    /// Adds or updates a phrase rule.
    pub fn add_or_update_phrase_rule(&mut self, rule: &PhraseRule) -> Result<String> {
        let id = if rule.id.trim().is_empty() {
            Uuid::now_v7().simple().to_string()
        } else {
            rule.id.trim().to_string()
        };
        let created_at = if rule.created_at <= 0 {
            Local::now().timestamp()
        } else {
            rule.created_at
        };

        self.conn.execute(
            "INSERT INTO phrase_rules (id, phrase_id, is_enabled, insert_position, position_mode, start_time, end_time, append_text, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
                phrase_id = excluded.phrase_id,
                is_enabled = excluded.is_enabled,
                insert_position = excluded.insert_position,
                position_mode = excluded.position_mode,
                start_time = excluded.start_time,
                end_time = excluded.end_time,
                append_text = excluded.append_text",
            params![
                id,
                rule.phrase_id,
                rule.is_enabled,
                rule.insert_position,
                rule.position_mode,
                rule.start_time,
                rule.end_time,
                rule.append_text,
                created_at,
            ],
        )?;
        Ok(id)
    }

    /// Deletes a phrase rule by its ID.
    pub fn delete_phrase_rule(&mut self, id: &str) -> Result<bool> {
        let rows = self
            .conn
            .execute("DELETE FROM phrase_rules WHERE id = ?1", params![id])?;
        Ok(rows > 0)
    }

    /// Queries all rules belonging to a specific phrase_id, ordered by created_at ASC.
    pub fn query_phrase_rules(&self, phrase_id: i64) -> Result<Vec<PhraseRule>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, phrase_id, is_enabled, insert_position, position_mode, start_time, end_time, append_text, created_at
             FROM phrase_rules
             WHERE phrase_id = ?1
             ORDER BY created_at ASC, id ASC",
        )?;
        let rows = stmt.query_map(params![phrase_id], Self::row_to_phrase_rule)?;
        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Queries all phrase rules across all phrases.
    pub fn query_all_phrase_rules(&self) -> Result<Vec<PhraseRule>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, phrase_id, is_enabled, insert_position, position_mode, start_time, end_time, append_text, created_at
             FROM phrase_rules
             ORDER BY phrase_id ASC, created_at ASC, id ASC",
        )?;
        let rows = stmt.query_map([], Self::row_to_phrase_rule)?;
        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    // --- Phrase Rule Templates operations ---

    /// Saves or updates a phrase rule template.
    pub fn save_phrase_rule_template(&mut self, template: &PhraseRuleTemplate) -> Result<String> {
        let id = if template.id.trim().is_empty() {
            Uuid::now_v7().simple().to_string()
        } else {
            template.id.trim().to_string()
        };
        let created_at = if template.created_at <= 0 {
            Local::now().timestamp()
        } else {
            template.created_at
        };

        self.conn.execute(
            "INSERT INTO phrase_rule_templates (id, name, insert_position, position_mode, start_time, end_time, append_text, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                insert_position = excluded.insert_position,
                position_mode = excluded.position_mode,
                start_time = excluded.start_time,
                end_time = excluded.end_time,
                append_text = excluded.append_text",
            params![
                id,
                template.name,
                template.insert_position,
                template.position_mode,
                template.start_time,
                template.end_time,
                template.append_text,
                created_at,
            ],
        )?;
        Ok(id)
    }

    /// Deletes a phrase rule template by ID.
    pub fn delete_phrase_rule_template(&mut self, id: &str) -> Result<bool> {
        let rows = self.conn.execute(
            "DELETE FROM phrase_rule_templates WHERE id = ?1",
            params![id],
        )?;
        Ok(rows > 0)
    }

    /// Queries all phrase rule templates.
    pub fn query_phrase_rule_templates(&self) -> Result<Vec<PhraseRuleTemplate>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, insert_position, position_mode, start_time, end_time, append_text, created_at
             FROM phrase_rule_templates
             ORDER BY created_at ASC, id ASC",
        )?;
        let rows = stmt.query_map([], Self::row_to_phrase_rule_template)?;
        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Exports the entire database to an encrypted backup file protected by `password`.
    /// Password is processed using PBKDF2-HMAC-SHA256 (100,000 rounds) and encrypted with XChaCha20-Poly1305.
    pub fn export_encrypted<P: AsRef<Path>>(
        &self,
        export_path: P,
        password: &str,
    ) -> std::result::Result<BackupSummary, BackupError> {
        let trimmed_pwd = password.trim();
        if trimmed_pwd.is_empty() {
            return Err(BackupError::EmptyPassword);
        }

        let mut history_stmt = self.conn.prepare(
            "SELECT id, content, created_at, last_used_at, content_type, char_count, line_count, byte_count, preview
             FROM clipboard_history ORDER BY id ASC",
        )?;
        let history = history_stmt
            .query_map([], Self::row_to_history_item)?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut phrases_stmt = self.conn.prepare(
            "SELECT id, content, created_at, last_used_at, sort_order, content_type, char_count, line_count, byte_count, preview
             FROM phrases ORDER BY sort_order ASC, id ASC",
        )?;
        let phrases = phrases_stmt
            .query_map([], Self::row_to_phrase_item)?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let phrase_rules = self.query_all_phrase_rules()?;
        let phrase_rule_templates = self.query_phrase_rule_templates()?;

        let mut config_stmt = self
            .conn
            .prepare("SELECT key, value FROM secure_config WHERE key != 'device_id'")?;
        let configs = config_stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let summary = BackupSummary {
            history_count: history.len() as u64,
            phrase_count: phrases.len() as u64,
            rule_count: phrase_rules.len() as u64,
            template_count: phrase_rule_templates.len() as u64,
            config_count: configs.len() as u64,
        };

        let backup_payload = EncryptedDatabaseBackup {
            format_version: 1,
            exported_at: chrono::Utc::now().to_rfc3339(),
            history,
            phrases,
            phrase_rules,
            phrase_rule_templates,
            configs,
        };

        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let mut header = [0u8; BACKUP_HEADER_SIZE];
        header[0..4].copy_from_slice(BACKUP_MAGIC);
        header[4] = BACKUP_VERSION;
        header[5..8].fill(0);
        header[8..12].copy_from_slice(&BACKUP_PBKDF2_ROUNDS.to_be_bytes());
        header[12..44].copy_from_slice(&salt);
        header[44..68].copy_from_slice(&nonce);

        let derived_key =
            crate::sync::crypto::derive_backup_key(trimmed_pwd, &salt, BACKUP_PBKDF2_ROUNDS);
        // 顺序不能反：先压缩再加密。反过来（先加密后压缩）既没压缩率，
        // 又会把密文长度泄露成压缩后的熵，属于教科书级错误。
        let json_bytes = deflate_bytes(&serde_json::to_vec(&backup_payload)?)?;

        let ciphertext = crate::sync::crypto::encrypt_payload_with_aad(
            &*derived_key,
            &nonce,
            &header,
            &json_bytes,
        )
        .map_err(BackupError::Crypto)?;

        let out_path = export_path.as_ref();
        if let Some(parent) = out_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp_path = out_path.with_extension("tmp_backup");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(&header)?;
            file.write_all(&ciphertext)?;
            file.flush()?;
        }

        std::fs::rename(&tmp_path, out_path)?;
        Ok(summary)
    }

    /// Imports an encrypted backup file protected by `password`.
    /// If `replace_all` is true, clears existing history, phrases, and rules before importing.
    /// If `replace_all` is false, merges and deduplicates records into current database.
    pub fn import_encrypted<P: AsRef<Path>>(
        &mut self,
        import_path: P,
        password: &str,
        replace_all: bool,
    ) -> std::result::Result<BackupSummary, BackupError> {
        let trimmed_pwd = password.trim();
        if trimmed_pwd.is_empty() {
            return Err(BackupError::EmptyPassword);
        }

        let in_path = import_path.as_ref();
        let file_bytes = std::fs::read(in_path)?;
        if file_bytes.len() < BACKUP_HEADER_SIZE + 16 {
            return Err(BackupError::InvalidFormat);
        }

        let header = &file_bytes[..BACKUP_HEADER_SIZE];
        if &header[0..4] != BACKUP_MAGIC {
            return Err(BackupError::InvalidFormat);
        }
        let version = header[4];
        if !(BACKUP_MIN_VERSION..=BACKUP_VERSION).contains(&version) {
            return Err(BackupError::UnsupportedVersion(version));
        }

        let rounds = u32::from_be_bytes(header[8..12].try_into().unwrap_or([0u8; 4]));
        if rounds < 1_000 || rounds > 2_000_000 {
            return Err(BackupError::InvalidFormat);
        }

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&header[12..44]);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&header[44..68]);

        let derived_key = crate::sync::crypto::derive_backup_key(trimmed_pwd, &salt, rounds);

        let ciphertext = &file_bytes[BACKUP_HEADER_SIZE..];
        let decrypted_bytes = crate::sync::crypto::decrypt_payload_with_aad(
            &*derived_key,
            &nonce,
            header,
            ciphertext,
        )
        .map_err(|_| BackupError::InvalidPasswordOrCorrupted)?;

        // v1 的载荷是裸 JSON；v2 起才压缩。老备份照样能读，不因为升级作废。
        let payload_bytes = if version >= 2 {
            inflate_bytes(&decrypted_bytes)?
        } else {
            decrypted_bytes
        };
        let backup: EncryptedDatabaseBackup = serde_json::from_slice(&payload_bytes)?;

        let tx = self.conn.transaction()?;

        if replace_all {
            tx.execute("DELETE FROM phrase_rules", [])?;
            tx.execute("DELETE FROM phrase_rule_templates", [])?;
            tx.execute("DELETE FROM phrases", [])?;
            tx.execute("DELETE FROM clipboard_history", [])?;
        }

        // Import clipboard history
        {
            let mut select_hist = tx.prepare(
                "SELECT id, last_used_at FROM clipboard_history WHERE content = ?1 LIMIT 1",
            )?;
            let mut update_hist = tx.prepare(
                "UPDATE clipboard_history 
                 SET last_used_at = ?1, content_type = ?2, char_count = ?3, line_count = ?4, byte_count = ?5, preview = ?6 
                 WHERE id = ?7",
            )?;
            let mut insert_hist = tx.prepare(
                "INSERT INTO clipboard_history (content, created_at, last_used_at, content_type, char_count, line_count, byte_count, preview)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;

            for item in &backup.history {
                let existing: Option<(i64, String)> = select_hist
                    .query_row(params![item.content], |row| Ok((row.get(0)?, row.get(1)?)))
                    .ok();

                if let Some((id, existing_last_used)) = existing {
                    let newer_last_used = if item.last_used_at > existing_last_used {
                        &item.last_used_at
                    } else {
                        &existing_last_used
                    };
                    update_hist.execute(params![
                        newer_last_used,
                        item.content_type.as_str(),
                        item.char_count as i64,
                        item.line_count as i64,
                        item.byte_count as i64,
                        item.preview,
                        id,
                    ])?;
                } else {
                    insert_hist.execute(params![
                        item.content,
                        item.created_at,
                        item.last_used_at,
                        item.content_type.as_str(),
                        item.char_count as i64,
                        item.line_count as i64,
                        item.byte_count as i64,
                        item.preview,
                    ])?;
                }
            }
        }

        // Import phrases
        for p in &backup.phrases {
            if replace_all {
                tx.execute(
                    "INSERT INTO phrases (id, content, created_at, last_used_at, sort_order, content_type, char_count, line_count, byte_count, preview)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        p.id,
                        p.content,
                        p.created_at,
                        p.last_used_at,
                        p.sort_order,
                        p.content_type.as_str(),
                        p.char_count as i64,
                        p.line_count as i64,
                        p.byte_count as i64,
                        p.preview,
                    ],
                )?;
            } else {
                let exists: bool = tx
                    .query_row(
                        "SELECT 1 FROM phrases WHERE content = ?1 LIMIT 1",
                        params![p.content],
                        |_| Ok(true),
                    )
                    .unwrap_or(false);

                if !exists {
                    let next_sort: i64 = tx
                        .query_row(
                            "SELECT COALESCE(MAX(sort_order), 0) + 1 FROM phrases",
                            [],
                            |row| row.get(0),
                        )
                        .unwrap_or(1);

                    tx.execute(
                        "INSERT INTO phrases (content, created_at, last_used_at, sort_order, content_type, char_count, line_count, byte_count, preview)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                        params![
                            p.content,
                            p.created_at,
                            p.last_used_at,
                            next_sort,
                            p.content_type.as_str(),
                            p.char_count as i64,
                            p.line_count as i64,
                            p.byte_count as i64,
                            p.preview,
                        ],
                    )?;
                }
            }
        }

        // Import phrase rules
        for r in &backup.phrase_rules {
            tx.execute(
                "INSERT INTO phrase_rules (id, phrase_id, is_enabled, insert_position, position_mode, start_time, end_time, append_text, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(id) DO UPDATE SET
                    phrase_id = excluded.phrase_id,
                    is_enabled = excluded.is_enabled,
                    insert_position = excluded.insert_position,
                    position_mode = excluded.position_mode,
                    start_time = excluded.start_time,
                    end_time = excluded.end_time,
                    append_text = excluded.append_text",
                params![
                    r.id,
                    r.phrase_id,
                    r.is_enabled,
                    r.insert_position,
                    r.position_mode,
                    r.start_time,
                    r.end_time,
                    r.append_text,
                    r.created_at,
                ],
            )?;
        }

        // Import phrase rule templates
        for t in &backup.phrase_rule_templates {
            tx.execute(
                "INSERT INTO phrase_rule_templates (id, name, insert_position, position_mode, start_time, end_time, append_text, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    insert_position = excluded.insert_position,
                    position_mode = excluded.position_mode,
                    start_time = excluded.start_time,
                    end_time = excluded.end_time,
                    append_text = excluded.append_text",
                params![
                    t.id,
                    t.name,
                    t.insert_position,
                    t.position_mode,
                    t.start_time,
                    t.end_time,
                    t.append_text,
                    t.created_at,
                ],
            )?;
        }

        // Import configs
        for (k, v) in &backup.configs {
            if k != "device_id" {
                tx.execute(
                    "INSERT INTO secure_config (key, value, updated_at)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        updated_at = excluded.updated_at",
                    params![k, v, chrono::Utc::now().to_rfc3339()],
                )?;
            }
        }

        tx.commit()?;

        Ok(BackupSummary {
            history_count: backup.history.len() as u64,
            phrase_count: backup.phrases.len() as u64,
            rule_count: backup.phrase_rules.len() as u64,
            template_count: backup.phrase_rule_templates.len() as u64,
            config_count: backup.configs.len() as u64,
        })
    }
}

pub const BACKUP_MAGIC: &[u8; 4] = b"MUBC";
/// 当前写出的格式版本。
///
/// - v1：载荷是裸 JSON
/// - v2：载荷是 **deflate 压缩后的** JSON（先压缩再加密，顺序不能反）
pub const BACKUP_VERSION: u8 = 2;
/// 仍然接受读入的最老版本。v1 的备份不因为升级而作废。
pub const BACKUP_MIN_VERSION: u8 = 1;
pub const BACKUP_HEADER_SIZE: usize = 68;
pub const BACKUP_PBKDF2_ROUNDS: u32 = 100_000;

/// 解压后的上限，防止构造的备份文件把内存打爆（解压炸弹）。
const BACKUP_MAX_INFLATED: u64 = 512 * 1024 * 1024;

/// 原始 deflate 压缩（不带 zlib / gzip 封装头，省 6~18 字节）。
fn deflate_bytes(data: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
    enc.write_all(data)?;
    enc.finish()
}

/// 解压 [`deflate_bytes`] 产物，输出规模受 [`BACKUP_MAX_INFLATED`] 约束。
fn inflate_bytes(data: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    let mut out = Vec::new();
    DeflateDecoder::new(data)
        .take(BACKUP_MAX_INFLATED)
        .read_to_end(&mut out)?;
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("Password cannot be empty")]
    EmptyPassword,
    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Invalid backup format or corrupt header")]
    InvalidFormat,
    #[error("Unsupported backup version: {0}")]
    UnsupportedVersion(u8),
    #[error("Incorrect password or backup corrupted")]
    InvalidPasswordOrCorrupted,
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Crypto error: {0:?}")]
    Crypto(crate::sync::crypto::CryptoError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedDatabaseBackup {
    pub format_version: u32,
    pub exported_at: String,
    pub history: Vec<HistoryItem>,
    pub phrases: Vec<PhraseItem>,
    pub phrase_rules: Vec<PhraseRule>,
    pub phrase_rule_templates: Vec<PhraseRuleTemplate>,
    pub configs: Vec<(String, String)>,
}

#[derive(uniffi::Record, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupSummary {
    pub history_count: u64,
    pub phrase_count: u64,
    pub rule_count: u64,
    pub template_count: u64,
    pub config_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_config_kv() {
        let mut db = Database::open_in_memory().unwrap();
        assert_eq!(db.get_config("pairing_pin").unwrap(), None);

        db.set_config("pairing_pin", "encrypted_pin_data_123456")
            .unwrap();
        assert_eq!(
            db.get_config("pairing_pin").unwrap(),
            Some("encrypted_pin_data_123456".to_string())
        );

        // Update existing key
        db.set_config("pairing_pin", "updated_pin_data_654321")
            .unwrap();
        assert_eq!(
            db.get_config("pairing_pin").unwrap(),
            Some("updated_pin_data_654321".to_string())
        );
    }

    #[test]
    fn test_history_crud_and_deduplication() {
        let mut db = Database::open_in_memory().unwrap();

        let id1 = db
            .upsert_history("Hello", Some("2026-09-01 10:00:00"))
            .unwrap();
        let id2 = db
            .upsert_history("World", Some("2026-09-01 10:01:00"))
            .unwrap();
        assert_ne!(id1, id2);

        // Deduplicate: same content updates existing id
        let id1_again = db
            .upsert_history("Hello", Some("2026-09-01 10:05:00"))
            .unwrap();
        assert_eq!(id1, id1_again);

        let items = db.query_history(10).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].content, "Hello");
        assert_eq!(items[0].char_count, 5);
        assert_eq!(items[0].line_count, 1);
        assert_eq!(items[0].byte_count, 5);
        assert_eq!(items[0].content_type, ContentType::PlainText);
        assert_eq!(items[0].preview, "Hello");
        assert_eq!(items[1].content, "World");

        // Search
        let search_res = db.search_history("ell", 10).unwrap();
        assert_eq!(search_res.len(), 1);
        assert_eq!(search_res[0].content, "Hello");
        assert_eq!(search_res[0].char_count, 5);

        // Delete
        db.delete_history(id1).unwrap();
        let items_after = db.query_history(10).unwrap();
        assert_eq!(items_after.len(), 1);
        assert_eq!(items_after[0].content, "World");
    }

    #[test]
    fn test_phrases_crud() {
        let mut db = Database::open_in_memory().unwrap();

        let p1 = db.add_phrase("Thank you for your inquiry").unwrap();
        let p2 = db.add_phrase("https://github.com/rust-lang").unwrap();

        let list = db.query_phrases().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, p1);
        assert_eq!(list[0].char_count, 26);
        assert_eq!(list[1].content_type, ContentType::Url);

        db.edit_phrase(p1, "Thank you very much!").unwrap();
        let list2 = db.query_phrases().unwrap();
        assert_eq!(list2[0].content, "Thank you very much!");
        assert_eq!(list2[0].char_count, 20);
        assert_eq!(list2[0].preview, "Thank you very much!");

        db.delete_phrase(p2).unwrap();
        let list3 = db.query_phrases().unwrap();
        assert_eq!(list3.len(), 1);
    }

    #[test]
    fn test_phrases_reorder() {
        let mut db = Database::open_in_memory().unwrap();
        let p1 = db.add_phrase("Item 1").unwrap();
        let p2 = db.add_phrase("Item 2").unwrap();
        let p3 = db.add_phrase("Item 3").unwrap();

        let list = db.query_phrases().unwrap();
        assert_eq!(list[0].id, p1);
        assert_eq!(list[1].id, p2);
        assert_eq!(list[2].id, p3);

        // Reorder to: p3, p1, p2
        db.reorder_phrases(&[p3, p1, p2]).unwrap();
        let reordered = db.query_phrases().unwrap();
        assert_eq!(reordered[0].id, p3);
        assert_eq!(reordered[1].id, p1);
        assert_eq!(reordered[2].id, p2);
        assert_eq!(reordered[0].sort_order, 0);
        assert_eq!(reordered[1].sort_order, 1);
        assert_eq!(reordered[2].sort_order, 2);
    }

    #[test]
    fn test_phrase_rules_crud_and_cascade() {
        let mut db = Database::open_in_memory().unwrap();
        let pid = db.add_phrase("Greeting phrase").unwrap();

        let mut rule = PhraseRule {
            id: String::new(),
            phrase_id: pid,
            is_enabled: 1,
            insert_position: 0,
            position_mode: 1,
            start_time: "08:00".to_string(),
            end_time: "18:00".to_string(),
            append_text: " [Working hours]".to_string(),
            created_at: 0,
        };

        // Add
        let rid = db.add_or_update_phrase_rule(&rule).unwrap();
        assert!(!rid.is_empty());

        // Query
        let rules = db.query_phrase_rules(pid).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, rid);
        assert_eq!(rules[0].append_text, " [Working hours]");

        // Update
        rule.id = rid.clone();
        rule.append_text = " [Updated text]".to_string();
        db.add_or_update_phrase_rule(&rule).unwrap();
        let rules2 = db.query_phrase_rules(pid).unwrap();
        assert_eq!(rules2.len(), 1);
        assert_eq!(rules2[0].append_text, " [Updated text]");

        // Foreign key cascade delete: deleting the phrase must delete its rules
        db.delete_phrase(pid).unwrap();
        let rules_after = db.query_phrase_rules(pid).unwrap();
        assert_eq!(rules_after.len(), 0);
    }

    #[test]
    fn test_phrase_rule_templates_crud() {
        let mut db = Database::open_in_memory().unwrap();

        let mut tpl = PhraseRuleTemplate {
            id: String::new(),
            name: "早间问候".to_string(),
            insert_position: 0,
            position_mode: 1,
            start_time: "06:00".to_string(),
            end_time: "10:00".to_string(),
            append_text: "（早上好）".to_string(),
            created_at: 0,
        };

        // Save
        let tid = db.save_phrase_rule_template(&tpl).unwrap();
        assert!(!tid.is_empty());

        let list = db.query_phrase_rule_templates().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, tid);
        assert_eq!(list[0].name, "早间问候");

        // Update
        tpl.id = tid.clone();
        tpl.name = "早间问候 (修改)".to_string();
        db.save_phrase_rule_template(&tpl).unwrap();

        let list2 = db.query_phrase_rule_templates().unwrap();
        assert_eq!(list2.len(), 1);
        assert_eq!(list2[0].name, "早间问候 (修改)");

        // Delete
        db.delete_phrase_rule_template(&tid).unwrap();
        let list3 = db.query_phrase_rule_templates().unwrap();
        assert_eq!(list3.len(), 0);
    }

    #[test]
    fn test_encrypted_backup_export_and_import() {
        let dir = tempfile::tempdir().unwrap();
        let db_path1 = dir.path().join("db1.sqlite");
        let db_path2 = dir.path().join("db2.sqlite");
        let backup_file = dir.path().join("backup.mubc");

        // Seed DB1
        let mut db1 = Database::open(db_path1.to_str().unwrap()).unwrap();
        let hid1 = db1.upsert_history("Clipboard item 1", None).unwrap();
        let hid2 = db1.upsert_history("Clipboard item 2", None).unwrap();
        assert!(hid1 > 0 && hid2 > 0);

        let pid1 = db1.add_phrase("Quick phrase 1").unwrap();
        db1.add_or_update_phrase_rule(&PhraseRule {
            id: String::new(),
            phrase_id: pid1,
            is_enabled: 1,
            insert_position: 0,
            position_mode: 0,
            start_time: "08:00".to_string(),
            end_time: "18:00".to_string(),
            append_text: " [Rule 1]".to_string(),
            created_at: 0,
        })
        .unwrap();

        db1.save_phrase_rule_template(&PhraseRuleTemplate {
            id: String::new(),
            name: "Test Template".to_string(),
            insert_position: 1,
            position_mode: 0,
            start_time: "09:00".to_string(),
            end_time: "17:00".to_string(),
            append_text: " [Tpl]".to_string(),
            created_at: 0,
        })
        .unwrap();

        db1.set_config("theme", "dark").unwrap();
        db1.set_config("device_id", "source-device-123").unwrap();

        // Export encrypted
        let password = "MySecretBackupPassword#2026";
        let summary_exp = db1
            .export_encrypted(backup_file.to_str().unwrap(), password)
            .unwrap();
        assert_eq!(summary_exp.history_count, 2);
        assert_eq!(summary_exp.phrase_count, 1);
        assert_eq!(summary_exp.rule_count, 1);
        assert_eq!(summary_exp.template_count, 1);
        assert_eq!(summary_exp.config_count, 1); // "device_id" is intentionally excluded from export

        // Verify wrong password fails
        let mut db2 = Database::open(db_path2.to_str().unwrap()).unwrap();
        let err = db2.import_encrypted(backup_file.to_str().unwrap(), "WrongPassword", false);
        assert!(err.is_err());

        // Import into DB2 with correct password (replace_all = true)
        let summary_imp = db2
            .import_encrypted(backup_file.to_str().unwrap(), password, true)
            .unwrap();
        assert_eq!(summary_imp.history_count, 2);
        assert_eq!(summary_imp.phrase_count, 1);
        assert_eq!(summary_imp.rule_count, 1);
        assert_eq!(summary_imp.template_count, 1);

        // Verify DB2 content
        let history = db2.query_history(10).unwrap();
        assert_eq!(history.len(), 2);
        let phrases = db2.query_phrases().unwrap();
        assert_eq!(phrases.len(), 1);
        assert_eq!(phrases[0].content, "Quick phrase 1");
        let rules = db2.query_all_phrase_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].append_text, " [Rule 1]");
        let templates = db2.query_phrase_rule_templates().unwrap();
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].name, "Test Template");

        // Verify config: "theme" restored, but "device_id" was skipped
        assert_eq!(db2.get_config("theme").unwrap().as_deref(), Some("dark"));
        assert_eq!(db2.get_config("device_id").unwrap(), None);

        // Test merge mode (replace_all = false)
        db2.upsert_history("Item only in DB2", None).unwrap();
        let summary_merge = db2
            .import_encrypted(backup_file.to_str().unwrap(), password, false)
            .unwrap();
        assert_eq!(summary_merge.history_count, 2);
        let history_merged = db2.query_history(10).unwrap();
        assert_eq!(history_merged.len(), 3);
    }

    /// 载荷压缩要真的省空间，不能只是"加了一层"。
    #[test]
    fn backup_payload_is_compressed() {
        let dir = tempfile::tempdir().unwrap();
        let backup_file = dir.path().join("compressed.mubc");
        let mut db = Database::open_in_memory().unwrap();

        // 造一批高度重复的内容，模拟真实剪贴板（大量相似文本）
        let mut raw_bytes = 0usize;
        for i in 0..200 {
            let content = format!(
                "第 {i} 条：这是一段用于测试压缩率的高度重复文本，包含中文与标点。\
                 https://example.com/path/to/resource?id={i}&token=abcdefghijklmnop "
            );
            raw_bytes += content.len();
            db.upsert_history(&content, None).unwrap();
        }

        db.export_encrypted(backup_file.to_str().unwrap(), "pass-123456")
            .unwrap();
        let on_disk = std::fs::metadata(&backup_file).unwrap().len() as usize;

        // 明文原始内容约 raw_bytes，压缩 + 加密后应当显著更小
        assert!(
            on_disk * 2 < raw_bytes,
            "压缩没生效：原始 {raw_bytes} 字节，落盘 {on_disk} 字节"
        );
    }

    /// v1（未压缩载荷）的旧备份必须还能读——升级不该让人手里的备份作废。
    #[test]
    fn v1_uncompressed_backup_still_imports() {
        use crate::sync::crypto::{derive_backup_key, encrypt_payload_with_aad};

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("legacy-v1.mubc");
        let password = "legacy-pass-888";

        // 手工按 v1 规范拼一个文件：版本字节 = 1 + 裸 JSON 载荷
        let payload = EncryptedDatabaseBackup {
            format_version: 1,
            exported_at: "2026-01-01T00:00:00Z".to_string(),
            history: Vec::new(),
            phrases: Vec::new(),
            phrase_rules: Vec::new(),
            phrase_rule_templates: Vec::new(),
            configs: vec![("theme".to_string(), "dark".to_string())],
        };
        let json = serde_json::to_vec(&payload).unwrap();

        let salt = [7u8; 32];
        let nonce = [9u8; 24];
        let mut header = [0u8; BACKUP_HEADER_SIZE];
        header[0..4].copy_from_slice(BACKUP_MAGIC);
        header[4] = 1; // v1
        header[8..12].copy_from_slice(&BACKUP_PBKDF2_ROUNDS.to_be_bytes());
        header[12..44].copy_from_slice(&salt);
        header[44..68].copy_from_slice(&nonce);

        let key = derive_backup_key(password, &salt, BACKUP_PBKDF2_ROUNDS);
        let ciphertext = encrypt_payload_with_aad(&key, &nonce, &header, &json).unwrap();

        let mut bytes = header.to_vec();
        bytes.extend_from_slice(&ciphertext);
        std::fs::write(&file, &bytes).unwrap();

        let mut db = Database::open_in_memory().unwrap();
        let summary = db
            .import_encrypted(file.to_str().unwrap(), password, true)
            .unwrap();
        assert_eq!(summary.config_count, 1);
        assert_eq!(db.get_config("theme").unwrap().as_deref(), Some("dark"));
    }

    // ---------------------------------------------------------------
    // 静态加密相关的辅助函数：不依赖 SQLCipher，任何构建都会跑
    // ---------------------------------------------------------------

    #[test]
    fn hex_key_detection_only_accepts_256_bit_hex() {
        assert!(is_hex_key_64(&"a".repeat(64)));
        assert!(is_hex_key_64(
            "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef"
        ));
        // 长度不足 / 超长
        assert!(!is_hex_key_64(&"a".repeat(63)));
        assert!(!is_hex_key_64(&"a".repeat(65)));
        // 含非十六进制字符
        assert!(!is_hex_key_64(&"z".repeat(64)));
        // 口令形态的密钥
        assert!(!is_hex_key_64("my passphrase"));
        assert!(!is_hex_key_64(""));
    }

    /// 默认构建（未启用 sqlcipher）下必须如实报告「没加密」，而不是假装成功。
    #[test]
    #[cfg(not(feature = "sqlcipher"))]
    fn plaintext_build_reports_not_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("plain.db");
        let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let db = Database::open_with_key(&p, Some(key)).unwrap();
        assert!(!db.is_encrypted());
        drop(db);
        // 落盘后仍是明文 SQLite：文件头是固定魔数
        let head = std::fs::read(&p).unwrap();
        assert_eq!(&head[..16], b"SQLite format 3\0");
    }

    // ---------------------------------------------------------------
    // 以下用例只在 `--features sqlcipher` 构建下有意义：
    //   cargo test --no-default-features --features sqlcipher
    // ---------------------------------------------------------------

    #[test]
    #[cfg(feature = "sqlcipher")]
    fn sqlcipher_writes_encrypted_file_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("enc.db");
        let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let mut db = Database::open_with_key(&p, Some(key)).unwrap();
        assert!(db.is_encrypted());
        db.upsert_history("secret clipboard content", None).unwrap();
        drop(db);

        // 文件头不再是明文魔数，且全文搜不到明文
        let raw = std::fs::read(&p).unwrap();
        assert_ne!(&raw[..16], b"SQLite format 3\0");
        assert!(
            !raw.windows(9).any(|w| w == b"secret cl"),
            "加密库里不应出现明文内容"
        );

        // 同一密钥可再次打开并读回数据
        let db2 = Database::open_with_key(&p, Some(key)).unwrap();
        assert!(db2.is_encrypted());
        assert_eq!(db2.query_history(10).unwrap().len(), 1);
    }

    #[test]
    #[cfg(feature = "sqlcipher")]
    fn sqlcipher_rejects_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("enc.db");
        let key_a = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key_b = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        {
            let mut db = Database::open_with_key(&p, Some(key_a)).unwrap();
            db.upsert_history("payload", None).unwrap();
        }
        // 错误密钥必然打不开（SQLCipher 在首次读取时才校验，故用 init_tables 触发）
        assert!(Database::open_with_key(&p, Some(key_b)).is_err());
    }

    /// 加密模式下打开一个明文旧库：不做探测也不改名，直接失败。
    /// 旧数据请走 `.mubc` 备份/还原，这一点是刻意的（不替用户猜）。
    #[test]
    #[cfg(feature = "sqlcipher")]
    fn plaintext_db_is_rejected_in_encrypted_mode() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("muclip.db");
        {
            let mut db = Database::open(&p).unwrap();
            db.upsert_history("old plaintext row", None).unwrap();
        }

        let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(Database::open_with_key(&p, Some(key)).is_err());

        // 原文件原封不动，没有被改名、也没有被覆盖
        let head = std::fs::read(&p).unwrap();
        assert_eq!(&head[..16], b"SQLite format 3\0");
        assert!(!p.with_file_name("muclip.db.plaintext.bak").exists());
    }
}
