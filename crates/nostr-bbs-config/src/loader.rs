//! TOML loader entry points.

use std::path::Path;

use thiserror::Error;

use crate::schema::ForumConfig;
use crate::validate::validate_config;

/// Errors raised while loading a `forum.toml`.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Filesystem read failed.
    #[error("read failed: {0}")]
    Io(#[from] std::io::Error),

    /// TOML parse failed.
    #[error("parse failed: {0}")]
    Parse(#[from] toml::de::Error),

    /// Semantic validation failed.
    #[error("validation failed: {0}")]
    Validation(String),
}

/// Load a [`ForumConfig`] from a TOML string and validate it.
pub fn load_from_str(s: &str) -> Result<ForumConfig, ConfigError> {
    let cfg: ForumConfig = toml::from_str(s)?;
    validate_config(&cfg).map_err(ConfigError::Validation)?;
    Ok(cfg)
}

/// Load a [`ForumConfig`] from a TOML file on disk and validate it.
pub fn load_from_path(path: impl AsRef<Path>) -> Result<ForumConfig, ConfigError> {
    let s = std::fs::read_to_string(path)?;
    load_from_str(&s)
}
