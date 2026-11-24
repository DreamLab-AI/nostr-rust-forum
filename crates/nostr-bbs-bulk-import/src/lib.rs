//! `nostr-bbs-bulk-import`: offline bulk import of external chat archives
//! into a nostr-bbs forum deployment.
//!
//! (Crate documentation is completed with the CLI.)

#![warn(missing_docs)]

pub mod adapter;
pub mod error;
pub mod format;
pub mod fsutil;
pub mod identity;
pub mod keystore;
pub mod plan;
pub mod structure;

pub use error::ImportError;
