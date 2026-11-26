//! The crate's error type.

use std::path::Path;

/// Everything that can stop a bulk-import step. Messages never contain key
/// material: secrets are held in [`zeroize::Zeroizing`] buffers and are
/// never formatted.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// A file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: String,
        /// The cause.
        source: std::io::Error,
    },
    /// An input file breaks its format (intermediate archive, plan files).
    #[error("format: {0}")]
    Format(String),
    /// A plan or mapping is inconsistent.
    #[error("plan: {0}")]
    Plan(String),
    /// A safety rule refused the step; nothing was written.
    #[error("refused: {0}")]
    Refused(String),
    /// A database operation failed.
    #[error("database: {0}")]
    Db(String),
    /// A key could not be parsed or used.
    #[error("key: {0}")]
    Key(String),
    /// An external tool (ImageMagick, wrangler) failed.
    #[error("tool: {0}")]
    Tool(String),
}

impl ImportError {
    /// An I/O error on `path`.
    pub fn io(path: &Path, source: std::io::Error) -> Self {
        ImportError::Io {
            path: path.display().to_string(),
            source,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<rusqlite::Error> for ImportError {
    fn from(e: rusqlite::Error) -> Self {
        ImportError::Db(e.to_string())
    }
}
