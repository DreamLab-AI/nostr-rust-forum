//! The intermediate format as a source: validate an archive another tool
//! wrote and re-write it normalised (sorted, deduplicated, attachments
//! re-digested and copied by content address).
//!
//! This is the extension point for exporters written outside Rust: emit the
//! files described in `docs/bulk-import/FORMAT.md` and run
//! `nostr-bbs-import adapt generic --in DIR --out DIR2`.

use std::path::Path;

use super::{AdapterReport, SourceAdapter};
use crate::error::ImportError;
use crate::format::{Archive, ArchiveWriter, AttachmentStatus};

/// See the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct GenericAdapter;

impl SourceAdapter for GenericAdapter {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn convert(&self, input: &Path, out: &mut ArchiveWriter) -> Result<AdapterReport, ImportError> {
        let a = Archive::open(input)?;
        // Keep the original platform as the source, so provenance tags still
        // name it after re-writing.
        out.set_source(&a.manifest.source, &a.manifest.source_id);
        let mut report = AdapterReport { channels: a.channels.len(), ..Default::default() };
        for au in &a.authors {
            out.author(au.clone());
        }
        for c in &a.channels {
            out.channel(c.clone());
        }
        for m in &a.messages {
            let mut m = m.clone();
            for att in &mut m.attachments {
                if att.status == AttachmentStatus::Ok {
                    // Re-digest: the copy's sha256 is computed from the bytes.
                    let file = a.attachment_file(att)?;
                    *att = out.attach_file(&file, &att.filename, &att.mime)?;
                    report.attachments_ok += 1;
                } else {
                    report.attachments_missing += 1;
                }
            }
            out.message(m);
            report.messages += 1;
        }
        for r in &a.reactions {
            out.reaction(r.clone());
            report.reactions += 1;
        }
        for d in &a.dms {
            out.dm(d.clone());
        }
        Ok(report)
    }
}
