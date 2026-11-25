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

/// See the module docs. DM migration is OFF by default: `dms.jsonl` is
/// left out of the re-written archive unless `include_dms` is set (the
/// operator's explicit `--include-dms`).
#[derive(Debug, Default, Clone, Copy)]
pub struct GenericAdapter {
    /// Carry the archive's `dms.jsonl` through (default `false`).
    pub include_dms: bool,
}

impl SourceAdapter for GenericAdapter {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn convert(&self, input: &Path, out: &mut ArchiveWriter) -> Result<AdapterReport, ImportError> {
        let a = Archive::open(input)?;
        // Keep the original platform as the source, so provenance tags still
        // name it after re-writing.
        out.set_source(&a.manifest.source, &a.manifest.source_id);
        let mut report = AdapterReport {
            channels: a.channels.len(),
            ..Default::default()
        };
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
        if self.include_dms {
            for d in &a.dms {
                out.dm(d.clone());
            }
            report.dms = a.dms.len();
        } else if !a.dms.is_empty() {
            report.dms_left_out = a.dms.len();
            report.warnings.push(format!(
                "{} DM wrap(s) left out: DM migration is off unless you pass --include-dms",
                a.dms.len()
            ));
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{Author, Channel, Message};

    #[test]
    fn dms_are_left_out_unless_included() {
        let base = std::env::temp_dir().join(format!("bi-generic-dms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let a = nostr_bbs_core::keys::generate_keypair().unwrap();
        let b = nostr_bbs_core::keys::generate_keypair().unwrap();
        let wrap = nostr_bbs_core::gift_wrap::gift_wrap(
            a.secret.as_bytes(),
            &a.public.to_hex(),
            &b.public.to_hex(),
            "hi",
        )
        .unwrap();
        let mut w = ArchiveWriter::new("test", "t");
        w.author(Author {
            id: "u".into(),
            handle: "u".into(),
            display_name: None,
            about: None,
            bot: false,
        });
        w.channel(Channel {
            id: "c".into(),
            name: "c".into(),
            topic: None,
            created_at: None,
        });
        w.message(Message {
            id: "m".into(),
            channel: "c".into(),
            author: "u".into(),
            created_at: 1,
            text: "x".into(),
            reply_to: None,
            edited_at: None,
            attachments: vec![],
        });
        w.dm(wrap);
        w.finish(&base.join("src")).unwrap();

        let (off, rep) = crate::adapter::run(
            &GenericAdapter::default(),
            &base.join("src"),
            "t",
            &base.join("off"),
        )
        .unwrap();
        assert!(off.dms.is_empty(), "DM migration is off by default");
        assert_eq!((rep.dms, rep.dms_left_out), (0, 1));
        let (on, rep) = crate::adapter::run(
            &GenericAdapter { include_dms: true },
            &base.join("src"),
            "t",
            &base.join("on"),
        )
        .unwrap();
        assert_eq!((on.dms.len(), rep.dms), (1, 1));
        std::fs::remove_dir_all(&base).unwrap();
    }
}
