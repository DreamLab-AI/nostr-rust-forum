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
    // ADR-2037: serde ignores unknown keys, so a misspelt `channels` would
    // leave the channel it meant to pin in its old zone. Check the raw table.
    let raw: toml::Value = toml::from_str(s)?;
    if let Some(zones) = raw.get("zones") {
        let zones = serde_json::to_value(zones)
            .map_err(|e| ConfigError::Validation(format!("zones: {e}")))?;
        crate::validate::check_zone_pin_keys(&zones).map_err(ConfigError::Validation)?;
    }
    validate_config(&cfg).map_err(ConfigError::Validation)?;
    Ok(cfg)
}

/// Load a [`ForumConfig`] from a TOML file on disk and validate it.
pub fn load_from_path(path: impl AsRef<Path>) -> Result<ForumConfig, ConfigError> {
    let s = std::fs::read_to_string(path)?;
    load_from_str(&s)
}
