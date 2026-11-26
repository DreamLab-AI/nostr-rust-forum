//! The intermediate archive format, version 1 (`docs/bulk-import/FORMAT.md`).
//!
//! An archive is a directory:
//!
//! ```text
//! manifest.json      Manifest
//! authors.jsonl      Author per line
//! channels.jsonl     Channel per line
//! messages.jsonl     Message per line
//! reactions.jsonl    Reaction per line
//! dms.jsonl          already-signed kind-1059 events, verbatim (optional)
//! attachments/…      files named by Attachment::path (relative, confined)
//! ```
//!
//! Every record type refuses unknown fields: a new field is a new format
//! version, so an exporter typo never passes silently. [`Archive::open`]
//! reads and validates a whole archive; [`ArchiveWriter`] is how adapters
//! produce one.
//!
//! ```
//! use nostr_bbs_bulk_import::format::{Archive, ArchiveWriter, Author, Channel, Message};
//!
//! let dir = std::env::temp_dir().join(format!("bi-doc-format-{}", std::process::id()));
//! let _ = std::fs::remove_dir_all(&dir);
//! let mut w = ArchiveWriter::new("example", "team-1");
//! w.author(Author { id: "u1".into(), handle: "alice".into(), display_name: None, about: None, bot: false });
//! w.channel(Channel { id: "c1".into(), name: "general".into(), topic: None, created_at: None });
//! w.message(Message {
//!     id: "m1".into(), channel: "c1".into(), author: "u1".into(), created_at: 1_600_000_000,
//!     text: "hello".into(), reply_to: None, edited_at: None, attachments: vec![],
//! });
//! w.finish(&dir).unwrap();
//! let a = Archive::open(&dir).unwrap();
//! assert_eq!(a.messages.len(), 1);
//! assert_eq!(a.manifest.version, 1);
//! # std::fs::remove_dir_all(&dir).unwrap();
//! ```

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::ImportError;
use crate::fsutil;

/// The `format` value every manifest carries.
pub const FORMAT_NAME: &str = "nostr-bbs-bulk-import";
/// The format version this crate reads and writes.
pub const FORMAT_VERSION: u32 = 1;

/// `manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Always [`FORMAT_NAME`].
    pub format: String,
    /// Always [`FORMAT_VERSION`] for archives this crate accepts.
    pub version: u32,
    /// Source platform (`keybase`, `discord`, …): lowercase, `[a-z0-9-]`.
    pub source: String,
    /// The source's own name for what was exported (team, guild, workspace).
    pub source_id: String,
    /// Unix seconds when the archive was written.
    pub exported_at: u64,
    /// Record counts per file, checked on open.
    pub counts: Counts,
}

/// Record counts in a [`Manifest`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    /// Lines in `authors.jsonl`.
    pub authors: usize,
    /// Lines in `channels.jsonl`.
    pub channels: usize,
    /// Lines in `messages.jsonl`.
    pub messages: usize,
    /// Lines in `reactions.jsonl`.
    pub reactions: usize,
    /// Lines in `dms.jsonl`.
    pub dms: usize,
}

/// One source account (`authors.jsonl`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Author {
    /// Source account id, unique in the file.
    pub id: String,
    /// Handle shown in the forum (the source username).
    pub handle: String,
    /// Display name, when the source has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Profile text, when the source has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    /// The source marks this account as a bot.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bot: bool,
}

/// One source channel (`channels.jsonl`). Each becomes one forum topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    /// Source channel id, unique in the file. Structure maps are keyed by it,
    /// never by name (names can be absent or repeated).
    pub id: String,
    /// Channel name (without a leading `#`).
    pub name: String,
    /// Channel topic / headline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Unix seconds the channel was created, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

/// Whether an attachment's bytes are in the archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttachmentStatus {
    /// `path` names the original bytes, `sha256` is their digest.
    Ok,
    /// The source could not deliver the bytes.
    Unavailable,
    /// The exporter chose not to fetch them (size, kind).
    Skipped,
}

/// One attachment of a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    /// Lowercase hex SHA-256 of the original bytes (required when `ok`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Path of the original bytes relative to the archive root (required when `ok`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Original file name.
    pub filename: String,
    /// Declared media type.
    pub mime: String,
    /// Size in bytes, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Whether the bytes are present.
    pub status: AttachmentStatus,
}

/// One message (`messages.jsonl`), edits and deletes already applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    /// Source message id, unique in the archive.
    pub id: String,
    /// [`Channel::id`].
    pub channel: String,
    /// [`Author::id`].
    pub author: String,
    /// Unix seconds of the ORIGINAL send.
    pub created_at: u64,
    /// Final text (may be empty when there are attachments).
    pub text: String,
    /// The message this replies to: any message id, possibly absent from the
    /// archive (deleted upstream). The planner decides what that becomes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// Unix seconds of the last edit (informational).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited_at: Option<u64>,
    /// Attachments, in source order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
}

/// One reaction (`reactions.jsonl`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reaction {
    /// [`Message::id`] reacted to.
    pub message: String,
    /// [`Author::id`] who reacted.
    pub author: String,
    /// The emoji (a Unicode emoji, or a `:shortcode:` the source used).
    pub emoji: String,
    /// Unix seconds.
    pub created_at: u64,
}

/// A whole archive, read and validated.
#[derive(Debug, Clone)]
pub struct Archive {
    /// Root directory (canonical).
    pub root: PathBuf,
    /// `manifest.json`.
    pub manifest: Manifest,
    /// `authors.jsonl`.
    pub authors: Vec<Author>,
    /// `channels.jsonl`.
    pub channels: Vec<Channel>,
    /// `messages.jsonl`, sorted by `(channel, created_at, id)` as written.
    pub messages: Vec<Message>,
    /// `reactions.jsonl`.
    pub reactions: Vec<Reaction>,
    /// `dms.jsonl`: raw signed events (checked by [`crate::dm`]).
    pub dms: Vec<nostr_bbs_core::NostrEvent>,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Resolve `rel` under `root`, refusing absolute paths, `..`, and anything
/// that canonicalises outside `root` (symlinks included). `root` must be
/// canonical. The file must exist.
pub fn confined_path(root: &Path, rel: &str) -> Result<PathBuf, ImportError> {
    let p = Path::new(rel);
    if rel.is_empty()
        || p.is_absolute()
        || p.components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err(ImportError::Format(format!(
            "attachment path {rel:?} must be relative without '..'"
        )));
    }
    let full = root
        .join(p)
        .canonicalize()
        .map_err(|e| ImportError::Format(format!("attachment path {rel:?}: {e}")))?;
    if !full.starts_with(root) {
        return Err(ImportError::Format(format!(
            "attachment path {rel:?} resolves outside the archive"
        )));
    }
    Ok(full)
}

fn has_nul(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::String(s) => s.contains('\0'),
        serde_json::Value::Array(a) => a.iter().any(has_nul),
        serde_json::Value::Object(o) => o.iter().any(|(k, v)| k.contains('\0') || has_nul(v)),
        _ => false,
    }
}

fn read_jsonl<T: DeserializeOwned>(path: &Path, required: bool) -> Result<Vec<T>, ImportError> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => return Ok(vec![]),
        Err(e) => return Err(ImportError::io(path, e)),
        Ok(m) if !m.is_file() => {
            return Err(ImportError::Format(format!(
                "{} must be a regular file (not a symlink)",
                path.display()
            )))
        }
        Ok(_) => {}
    }
    let mut out = Vec::new();
    fsutil::for_each_line(path, |n, line| {
        if line.trim().is_empty() {
            return Ok(());
        }
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| ImportError::Format(format!("{}:{n}: {e}", path.display())))?;
        if has_nul(&v) {
            return Err(ImportError::Format(format!(
                "{}:{n}: NUL characters are not accepted",
                path.display()
            )));
        }
        out.push(
            serde_json::from_value(v)
                .map_err(|e| ImportError::Format(format!("{}:{n}: {e}", path.display())))?,
        );
        Ok(())
    })?;
    Ok(out)
}

impl Archive {
    /// Read and validate the archive at `dir` (see [`Archive::validate`]).
    pub fn open(dir: &Path) -> Result<Self, ImportError> {
        let root = dir.canonicalize().map_err(|e| ImportError::io(dir, e))?;
        let mpath = root.join("manifest.json");
        let manifest: Manifest =
            serde_json::from_slice(&std::fs::read(&mpath).map_err(|e| ImportError::io(&mpath, e))?)
                .map_err(|e| ImportError::Format(format!("manifest.json: {e}")))?;
        let a = Archive {
            authors: read_jsonl(&root.join("authors.jsonl"), true)?,
            channels: read_jsonl(&root.join("channels.jsonl"), true)?,
            messages: read_jsonl(&root.join("messages.jsonl"), true)?,
            reactions: read_jsonl(&root.join("reactions.jsonl"), false)?,
            dms: read_jsonl(&root.join("dms.jsonl"), false)?,
            manifest,
            root,
        };
        a.validate()?;
        Ok(a)
    }

    /// Check the manifest, counts, unique ids, references and attachment
    /// paths. Every problem found is listed in the error.
    pub fn validate(&self) -> Result<(), ImportError> {
        let mut errs: Vec<String> = Vec::new();
        let m = &self.manifest;
        if m.format != FORMAT_NAME {
            errs.push(format!(
                "manifest format is {:?}, not {FORMAT_NAME:?}",
                m.format
            ));
        }
        if m.version != FORMAT_VERSION {
            errs.push(format!(
                "manifest version {} is not supported (this tool reads {FORMAT_VERSION})",
                m.version
            ));
        }
        if m.source.is_empty()
            || !m
                .source
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            errs.push(format!("manifest source {:?} must be [a-z0-9-]+", m.source));
        }
        let counts = Counts {
            authors: self.authors.len(),
            channels: self.channels.len(),
            messages: self.messages.len(),
            reactions: self.reactions.len(),
            dms: self.dms.len(),
        };
        if counts != m.counts {
            errs.push(format!(
                "manifest counts {:?} do not match the files {:?}",
                m.counts, counts
            ));
        }
        let mut dup = |what: &str, ids: Vec<&str>| {
            let mut seen = HashSet::new();
            for id in ids {
                if id.is_empty() {
                    errs.push(format!("{what}: empty id"));
                } else if !seen.insert(id) {
                    errs.push(format!("{what}: duplicate id {id:?}"));
                }
            }
        };
        dup(
            "authors",
            self.authors.iter().map(|a| a.id.as_str()).collect(),
        );
        dup(
            "channels",
            self.channels.iter().map(|c| c.id.as_str()).collect(),
        );
        dup(
            "messages",
            self.messages.iter().map(|x| x.id.as_str()).collect(),
        );
        let authors: HashSet<&str> = self.authors.iter().map(|a| a.id.as_str()).collect();
        let channels: HashSet<&str> = self.channels.iter().map(|c| c.id.as_str()).collect();
        let messages: HashSet<&str> = self.messages.iter().map(|x| x.id.as_str()).collect();
        for a in &self.authors {
            if a.handle.trim().is_empty() {
                errs.push(format!("author {:?}: empty handle", a.id));
            }
        }
        for msg in &self.messages {
            if !channels.contains(msg.channel.as_str()) {
                errs.push(format!(
                    "message {:?}: unknown channel {:?}",
                    msg.id, msg.channel
                ));
            }
            if !authors.contains(msg.author.as_str()) {
                errs.push(format!(
                    "message {:?}: unknown author {:?}",
                    msg.id, msg.author
                ));
            }
            if msg.created_at == 0 {
                errs.push(format!("message {:?}: created_at is 0", msg.id));
            }
            if msg.reply_to.as_deref() == Some(msg.id.as_str()) {
                errs.push(format!("message {:?}: replies to itself", msg.id));
            }
            for att in &msg.attachments {
                if att.status == AttachmentStatus::Ok {
                    match (&att.sha256, &att.path) {
                        (Some(sha), Some(path)) => {
                            if !is_hex64(sha) {
                                errs.push(format!(
                                    "message {:?}: attachment sha256 {sha:?} is not lowercase hex",
                                    msg.id
                                ));
                            }
                            if let Err(e) = confined_path(&self.root, path) {
                                errs.push(format!("message {:?}: {e}", msg.id));
                            }
                        }
                        _ => errs.push(format!(
                            "message {:?}: an ok attachment needs sha256 and path",
                            msg.id
                        )),
                    }
                }
            }
        }
        for r in &self.reactions {
            if !messages.contains(r.message.as_str()) {
                errs.push(format!("reaction: unknown message {:?}", r.message));
            }
            if !authors.contains(r.author.as_str()) {
                errs.push(format!("reaction: unknown author {:?}", r.author));
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            errs.truncate(200);
            Err(ImportError::Format(errs.join("\n")))
        }
    }

    /// Verify an `ok` attachment's bytes against its digest and return its
    /// confined path.
    pub fn attachment_file(&self, att: &Attachment) -> Result<PathBuf, ImportError> {
        let (Some(sha), Some(rel)) = (&att.sha256, &att.path) else {
            return Err(ImportError::Format(format!(
                "attachment {:?} has no bytes in the archive",
                att.filename
            )));
        };
        let p = confined_path(&self.root, rel)?;
        let got = fsutil::sha256_file(&p)?;
        if &got != sha {
            return Err(ImportError::Format(format!(
                "attachment {rel}: sha256 {got} does not match the recorded {sha}"
            )));
        }
        Ok(p)
    }

    /// Authors by id.
    pub fn authors_by_id(&self) -> HashMap<&str, &Author> {
        self.authors.iter().map(|a| (a.id.as_str(), a)).collect()
    }

    /// Channels by id.
    pub fn channels_by_id(&self) -> HashMap<&str, &Channel> {
        self.channels.iter().map(|c| (c.id.as_str(), c)).collect()
    }
}

/// Builds an archive in memory and writes it with [`ArchiveWriter::finish`].
///
/// Records are deduplicated by id (the last write wins, so an adapter can
/// apply edits by rewriting), sorted deterministically, and attachments are
/// copied into `attachments/<sha[0..2]>/<sha256>` so the archive is
/// self-contained and content-addressed.
#[derive(Debug)]
pub struct ArchiveWriter {
    source: String,
    source_id: String,
    exported_at: Option<u64>,
    authors: BTreeMap<String, Author>,
    channels: BTreeMap<String, Channel>,
    messages: BTreeMap<String, Message>,
    reactions: Vec<Reaction>,
    dms: Vec<nostr_bbs_core::NostrEvent>,
    files: BTreeMap<String, PathBuf>,
}

impl ArchiveWriter {
    /// A writer for `source` (e.g. `keybase`) and its export name.
    pub fn new(source: &str, source_id: &str) -> Self {
        ArchiveWriter {
            source: source.to_string(),
            source_id: source_id.to_string(),
            exported_at: None,
            authors: BTreeMap::new(),
            channels: BTreeMap::new(),
            messages: BTreeMap::new(),
            reactions: Vec::new(),
            dms: Vec::new(),
            files: BTreeMap::new(),
        }
    }

    /// Replace the source name and export name (an adapter that re-writes
    /// an existing archive keeps the original platform).
    pub fn set_source(&mut self, source: &str, source_id: &str) {
        self.source = source.to_string();
        self.source_id = source_id.to_string();
    }

    /// Fix `exported_at` (default: now). Tests use it for byte-stable output.
    pub fn exported_at(&mut self, t: u64) {
        self.exported_at = Some(t);
    }

    /// Add or replace an author.
    pub fn author(&mut self, a: Author) {
        self.authors.insert(a.id.clone(), a);
    }

    /// Add or replace a channel.
    pub fn channel(&mut self, c: Channel) {
        self.channels.insert(c.id.clone(), c);
    }

    /// Add or replace a message.
    pub fn message(&mut self, m: Message) {
        self.messages.insert(m.id.clone(), m);
    }

    /// Remove a message (an upstream delete).
    pub fn remove_message(&mut self, id: &str) {
        self.messages.remove(id);
    }

    /// Whether a message id is present.
    pub fn has_message(&self, id: &str) -> bool {
        self.messages.contains_key(id)
    }

    /// Add a reaction.
    pub fn reaction(&mut self, r: Reaction) {
        self.reactions.push(r);
    }

    /// Add an already-signed DM wrap (kind 1059).
    pub fn dm(&mut self, ev: nostr_bbs_core::NostrEvent) {
        self.dms.push(ev);
    }

    /// Register the original bytes of an attachment found at `file`
    /// (outside the archive). Returns the attachment entry pointing at the
    /// copy the writer will make. The digest is computed here, so the
    /// recorded `sha256` is always of the bytes copied.
    pub fn attach_file(
        &mut self,
        file: &Path,
        filename: &str,
        mime: &str,
    ) -> Result<Attachment, ImportError> {
        let sha = fsutil::sha256_file(file)?;
        let bytes = std::fs::metadata(file)
            .map_err(|e| ImportError::io(file, e))?
            .len();
        let rel = format!("attachments/{}/{}", &sha[..2], sha);
        self.files.insert(rel.clone(), file.to_path_buf());
        Ok(Attachment {
            sha256: Some(sha),
            path: Some(rel),
            filename: filename.to_string(),
            mime: mime.to_string(),
            bytes: Some(bytes),
            status: AttachmentStatus::Ok,
        })
    }

    /// Write the archive to `dir` (created 0700; must not hold a manifest
    /// yet), then re-open and validate it.
    pub fn finish(mut self, dir: &Path) -> Result<Archive, ImportError> {
        if dir.join("manifest.json").exists() {
            return Err(ImportError::Refused(format!(
                "{} already holds an archive; write to a new directory",
                dir.display()
            )));
        }
        fsutil::create_private_dir(dir)?;
        // Drop reactions to messages that were deleted after they were seen,
        // and keep the rest in a stable order.
        let ids: HashSet<String> = self.messages.keys().cloned().collect();
        self.reactions.retain(|r| ids.contains(&r.message));
        self.reactions.sort_by(|a, b| {
            (
                a.message.as_str(),
                a.created_at,
                a.author.as_str(),
                a.emoji.as_str(),
            )
                .cmp(&(
                    b.message.as_str(),
                    b.created_at,
                    b.author.as_str(),
                    b.emoji.as_str(),
                ))
        });
        self.reactions.dedup();
        let mut messages: Vec<Message> = self.messages.into_values().collect();
        messages.sort_by(|a, b| {
            (a.channel.as_str(), a.created_at, a.id.as_str()).cmp(&(
                b.channel.as_str(),
                b.created_at,
                b.id.as_str(),
            ))
        });
        for (rel, src) in &self.files {
            let dst = dir.join(rel);
            if let Some(parent) = dst.parent() {
                fsutil::create_private_dir(parent)?;
            }
            if !dst.exists() {
                fsutil::copy_private(src, &dst)?;
            }
            // The digest was taken when the file was registered; the copy
            // must still match it (no swap between hashing and copying).
            let want = rel.rsplit('/').next().unwrap_or("");
            if fsutil::sha256_file(&dst)? != want {
                let _ = std::fs::remove_file(&dst);
                return Err(ImportError::Refused(format!(
                    "{} changed after it was hashed",
                    src.display()
                )));
            }
        }
        let authors: Vec<Author> = self.authors.into_values().collect();
        let channels: Vec<Channel> = self.channels.into_values().collect();
        write_jsonl(&dir.join("authors.jsonl"), &authors)?;
        write_jsonl(&dir.join("channels.jsonl"), &channels)?;
        write_jsonl(&dir.join("messages.jsonl"), &messages)?;
        write_jsonl(&dir.join("reactions.jsonl"), &self.reactions)?;
        write_jsonl(&dir.join("dms.jsonl"), &self.dms)?;
        let manifest = Manifest {
            format: FORMAT_NAME.into(),
            version: FORMAT_VERSION,
            source: self.source,
            source_id: self.source_id,
            exported_at: self.exported_at.unwrap_or_else(fsutil::now),
            counts: Counts {
                authors: authors.len(),
                channels: channels.len(),
                messages: messages.len(),
                reactions: self.reactions.len(),
                dms: self.dms.len(),
            },
        };
        fsutil::write_private_atomic(
            &dir.join("manifest.json"),
            &serde_json::to_vec_pretty(&manifest).expect("manifest serialises"),
        )?;
        Archive::open(dir)
    }
}

fn write_jsonl<T: Serialize>(path: &Path, rows: &[T]) -> Result<(), ImportError> {
    let mut buf = Vec::new();
    for r in rows {
        serde_json::to_writer(&mut buf, r).expect("record serialises");
        buf.write_all(b"\n").expect("vec write");
    }
    fsutil::write_private_atomic(path, &buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bi-format-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn sample() -> ArchiveWriter {
        let mut w = ArchiveWriter::new("test", "t");
        w.exported_at(1);
        w.author(Author {
            id: "a".into(),
            handle: "alice".into(),
            display_name: None,
            about: None,
            bot: false,
        });
        w.channel(Channel {
            id: "c".into(),
            name: "gen".into(),
            topic: None,
            created_at: None,
        });
        w.message(Message {
            id: "m1".into(),
            channel: "c".into(),
            author: "a".into(),
            created_at: 10,
            text: "hi".into(),
            reply_to: None,
            edited_at: None,
            attachments: vec![],
        });
        w
    }

    #[test]
    fn round_trip_and_unknown_field_refused() {
        let d = tmp("rt");
        let a = sample().finish(&d).unwrap();
        assert_eq!(a.manifest.counts.messages, 1);
        let line = std::fs::read_to_string(d.join("messages.jsonl")).unwrap();
        std::fs::write(
            d.join("messages.jsonl"),
            line.replace("\"text\"", "\"txt\""),
        )
        .unwrap();
        assert!(Archive::open(&d).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn nul_refused_but_its_spelling_accepted() {
        let d = tmp("nul");
        sample().finish(&d).unwrap();
        let line = std::fs::read_to_string(d.join("messages.jsonl")).unwrap();
        std::fs::write(
            d.join("messages.jsonl"),
            line.replace("\"hi\"", "\"a\\\\u0000b\""),
        )
        .unwrap();
        assert!(
            Archive::open(&d).is_ok(),
            "the text backslash-u0000 is fine"
        );
        std::fs::write(
            d.join("messages.jsonl"),
            line.replace("\"hi\"", "\"a\\u0000b\""),
        )
        .unwrap();
        assert!(Archive::open(&d).unwrap_err().to_string().contains("NUL"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn dangling_references_listed() {
        let d = tmp("dangling");
        let mut w = sample();
        w.message(Message {
            id: "m2".into(),
            channel: "nope".into(),
            author: "ghost".into(),
            created_at: 11,
            text: "x".into(),
            reply_to: None,
            edited_at: None,
            attachments: vec![],
        });
        let err = w.finish(&d).unwrap_err().to_string();
        assert!(err.contains("unknown channel"), "{err}");
        assert!(err.contains("unknown author"), "{err}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn attachment_paths_are_confined() {
        let d = tmp("confine");
        sample().finish(&d).unwrap();
        let root = d.canonicalize().unwrap();
        assert!(confined_path(&root, "../etc/passwd").is_err());
        assert!(confined_path(&root, "/etc/passwd").is_err());
        assert!(confined_path(&root, "manifest.json").is_ok());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/hostname", root.join("link")).unwrap();
            assert!(confined_path(&root, "link").is_err());
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn attachments_are_copied_and_checked() {
        let d = tmp("att");
        let src = tmp("att-src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("f.txt"), b"bytes").unwrap();
        let mut w = sample();
        let att = w
            .attach_file(&src.join("f.txt"), "f.txt", "text/plain")
            .unwrap();
        w.message(Message {
            id: "m3".into(),
            channel: "c".into(),
            author: "a".into(),
            created_at: 12,
            text: String::new(),
            reply_to: None,
            edited_at: None,
            attachments: vec![att.clone()],
        });
        let a = w.finish(&d).unwrap();
        let p = a.attachment_file(&att).unwrap();
        assert_eq!(std::fs::read(p).unwrap(), b"bytes");
        std::fs::remove_dir_all(&d).unwrap();
        std::fs::remove_dir_all(&src).unwrap();
    }
}
