//! Source adapters: turn a platform export into the intermediate format.
//!
//! The contract an adapter has to meet is the JSONL format in
//! [`crate::format`] (spec: `docs/bulk-import/FORMAT.md`). In Rust, implement
//! [`SourceAdapter`] and write records through [`ArchiveWriter`], which
//! deduplicates, sorts, copies attachments by content address and validates
//! the result. In any other language, write the files directly and run them
//! through the [`generic`] adapter, which validates and normalises them.
//!
//! What an adapter must do (and the writer cannot check):
//!
//! - apply edits (final text) and deletes (drop the message and reactions
//!   to it) before writing;
//! - give every message the ORIGINAL send time in unix seconds;
//! - make message ids unique across the whole archive (prefix with the
//!   channel id when the source numbers per channel);
//! - never copy raw source records through: they can hold secrets (Keybase
//!   lines carry per-attachment decryption keys);
//! - leave source-platform DMs out (the format carries only already-signed
//!   kind-1059 wraps, see [`crate::dm`]).
//!
//! Shipped adapters: [`generic`] and [`keybase`]. Discord, Slack and Matrix
//! adapters follow the same shape (see FORMAT.md, "Writing an adapter").

pub mod generic;
pub mod keybase;

use std::path::Path;

use serde::Serialize;

use crate::error::ImportError;
pub use crate::format::ArchiveWriter;

/// What an adapter did, for the operator.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AdapterReport {
    /// Channels written.
    pub channels: usize,
    /// Messages written (after edits and deletes).
    pub messages: usize,
    /// Edits applied.
    pub edits_applied: usize,
    /// Messages removed by an upstream delete.
    pub deleted: usize,
    /// Reactions written.
    pub reactions: usize,
    /// Attachments with bytes in the archive.
    pub attachments_ok: usize,
    /// Attachments recorded without bytes (unavailable or skipped upstream).
    pub attachments_missing: usize,
    /// Source records ignored (unknown types, undecodable lines).
    pub ignored: usize,
    /// Free-form warnings (one line each, no message text).
    pub warnings: Vec<String>,
}

/// A source platform export reader.
pub trait SourceAdapter {
    /// Short source name written into the manifest (`keybase`).
    fn name(&self) -> &'static str;

    /// Read the export at `input` and add every record to `out`.
    fn convert(&self, input: &Path, out: &mut ArchiveWriter) -> Result<AdapterReport, ImportError>;
}

/// Run `adapter` over `input` and write the archive to `output`.
pub fn run(
    adapter: &dyn SourceAdapter,
    input: &Path,
    source_id: &str,
    output: &Path,
) -> Result<(crate::format::Archive, AdapterReport), ImportError> {
    let mut w = ArchiveWriter::new(adapter.name(), source_id);
    let report = adapter.convert(input, &mut w)?;
    let archive = w.finish(output)?;
    Ok((archive, report))
}
