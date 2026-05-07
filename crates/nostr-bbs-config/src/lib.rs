//! Operator-supplied TOML configuration kit for nostr-bbs deployments.
//!
//! Implements [PRD-012 §5 X1] and [ADR-085]: a single `forum.toml` file is the
//! source of truth for every deployment-specific setting (branding, hostnames,
//! rate limits, custody tier, federation peers, ...). Worker crates in the
//! `nostr-bbs-*-worker` set load this at startup; the `forum-client` reads its
//! shape via `option_env!` slots populated at build time.
//!
//! # Example
//!
//! ```no_run
//! use nostr_bbs_config::ForumConfig;
//!
//! let toml = std::fs::read_to_string("forum.toml").unwrap();
//! let config: ForumConfig = nostr_bbs_config::load_from_str(&toml).unwrap();
//! assert!(!config.deployment.hostname.as_str().is_empty());
//! ```
//!
//! # Modules
//!
//! - [`schema`] — strongly-typed TOML schema (one struct per `[section]`).
//! - [`loader`] — `load_from_str` / `load_from_path` entry points.
//! - [`validate`] — semantic checks beyond serde (e.g. URL formats, port ranges).
//!
//! # Stability
//!
//! Schema additions are minor-version compatible (new optional fields behind
//! `#[serde(default)]`). Schema removals or type changes are breaking and bump
//! the major version of this crate.
//!
//! [PRD-012 §5 X1]: https://github.com/DreamLab-AI/nostr-rust-forum/blob/main/docs/PRD-012.md
//! [ADR-085]: https://github.com/DreamLab-AI/nostr-rust-forum/blob/main/docs/adr/ADR-085.md

#![warn(missing_docs)]

pub mod loader;
pub mod schema;
pub mod validate;

pub use loader::{load_from_path, load_from_str, ConfigError};
pub use schema::ForumConfig;
