//! `nostr-bbs-bulk-import`: offline bulk import of external chat archives
//! into a nostr-bbs forum deployment.
//!
//! (Crate documentation is completed with the CLI.)

#![warn(missing_docs)]

pub mod adapter;
#[cfg(not(target_arch = "wasm32"))]
pub mod d1;
pub mod error;
pub mod events;
pub mod format;
pub mod fsutil;
pub mod identity;
pub mod keystore;
pub mod media;
pub mod plan;
pub mod structure;
pub mod target;

pub use error::ImportError;
