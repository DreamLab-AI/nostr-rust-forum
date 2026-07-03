//! Operator-supplied TOML configuration kit for nostr-bbs deployments.
//!
//! Implements [PRD-012 §5 X1] and [ADR-085]: a single `forum.toml` file is the
//! source of truth for every deployment-specific setting (branding, hostnames,
//! rate limits, custody tier, federation peers, ...). This crate is a
//! **build-time / deploy-time validator**, not a runtime startup check: the
//! deploy pipeline loads and validates `forum.toml` through this crate before
//! deployment, then projects the individual values into each worker's wrangler
//! env bindings / secrets and into the `forum-client`'s `option_env!` slots.
//! The `nostr-bbs-*-worker` crates run as Cloudflare Workers (wasm, with no
//! runtime filesystem) and read those env bindings at runtime — they do not
//! call [`load_from_path`] or read `forum.toml` directly at startup.
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
//! [PRD-012 §5 X1]: ../../docs/PRD-012.md
//! [ADR-085]: ../../docs/adr/ADR-085.md

#![warn(missing_docs)]

pub mod loader;
pub mod schema;
pub mod validate;

pub use loader::{load_from_path, load_from_str, ConfigError};
pub use schema::ForumConfig;
