pub mod cache;
pub mod content;
pub mod database;
pub mod diag;
pub mod ffi;
pub mod pool;
pub mod sync;
pub mod uniffi_api;

pub use cache::MemoryCache;
pub use content::{
    ContentAnalysis, ContentType, analyze_content, detect_content_type, format_preview,
};
pub use database::{Database, HistoryItem, PhraseItem};
pub use ffi::{MuClipCoreEngine, MuClipCoreHandle};
pub use pool::{NativeBufferPool, PooledBuffer, RawBuffer, global_buffer_pool};
pub use sync::{MuClipSyncEngine, PeerInfo, SyncConfig, SyncPayload};
pub use uniffi_api::{MuClipEngine, MuClipError};

uniffi::setup_scaffolding!();
