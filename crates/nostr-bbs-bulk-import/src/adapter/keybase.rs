//! Keybase team archive (the layout `keybase-port/archiver` writes).
//!
//! ```text
//! <team dir>/
//!   team.json                         {"name", "channels":[{"id","topic","dir","headline"?}], "members":[{"username","fullName"}]}
//!   users/<dir>/profile.json          {"username","fullName","bio",…}
//!   channels/<dir>/messages/YYYY/YYYY-MM.jsonl   RAW chat API `msg` objects (optionally wrapped as {"msg":…})
//!   assets/manifest.jsonl             per asset (key = sha256), last line per key wins: {"status","outputs":{"main":{"path","mime"}}}
//!   assets/refs.jsonl                 per attachment message "<topic>:<id>", last line wins: {"status":"done","sha256"}
//! ```
//!
//! Mapping:
//!
//! - message id `"<conversation id>:<keybase id>"` (Keybase numbers per
//!   conversation), author id = the Keybase username;
//! - `text` messages keep their body and `replyTo`; `attachment` messages
//!   carry the title as text when it differs from the file name, and the
//!   archived bytes (the archiver's already-optimised output) when the ref
//!   is `done`, otherwise an attachment entry without bytes;
//! - `edit` messages are applied in id order, `delete` messages remove
//!   their targets (and reactions to them), `reaction` messages become
//!   [`Reaction`] records with the raw body as the emoji (the planner maps
//!   `:shortcode:`s);
//! - everything else (joins, system messages, unfurls) is ignored and
//!   counted.
//!
//! Raw lines are parsed into a fixed set of fields and never copied: they
//! carry Keybase's per-attachment decryption keys.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

use super::{AdapterReport, SourceAdapter};
use crate::error::ImportError;
use crate::format::{
    confined_path, ArchiveWriter, Attachment, AttachmentStatus, Author, Channel, Message, Reaction,
};

/// See the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeybaseAdapter;

#[derive(Deserialize)]
struct TeamJson {
    #[serde(default)]
    channels: Vec<TeamChannel>,
    #[serde(default)]
    members: Vec<TeamMember>,
}

#[derive(Deserialize)]
struct TeamChannel {
    id: String,
    topic: String,
    #[serde(default)]
    dir: Option<String>,
    #[serde(default)]
    headline: Option<String>,
}

#[derive(Deserialize)]
struct TeamMember {
    username: String,
    #[serde(default, rename = "fullName")]
    full_name: Option<String>,
    /// `owner`, `admin`, `writer`, `reader`, `bot`, `restrictedBot`.
    #[serde(default)]
    role: Option<String>,
}

#[derive(Deserialize)]
struct Profile {
    username: String,
    #[serde(default, rename = "fullName")]
    full_name: Option<String>,
    #[serde(default)]
    bio: Option<String>,
}

/// A raw Keybase message reduced to the fields this adapter uses.
#[derive(Debug, Clone)]
enum Raw {
    Text {
        id: u64,
        at: u64,
        sender: String,
        body: String,
        reply_to: Option<u64>,
    },
    Attachment {
        id: u64,
        at: u64,
        sender: String,
        filename: String,
        title: String,
        size: Option<u64>,
        mime: Option<String>,
    },
    Edit {
        id: u64,
        at: u64,
        target: u64,
        body: String,
    },
    Delete {
        targets: Vec<u64>,
    },
    Reaction {
        id: u64,
        at: u64,
        sender: String,
        target: u64,
        body: String,
    },
}

fn num(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn s(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}

/// Parse one raw line. `None` = not a message type this adapter imports.
fn parse_raw(line: &Value) -> Option<Raw> {
    let m = line.get("msg").unwrap_or(line);
    let id = num(m.get("id")?)?;
    let at = m
        .get("sent_at")
        .and_then(num)
        .or_else(|| m.get("sent_at_ms").and_then(num).map(|ms| ms / 1000))?;
    let sender = m
        .get("sender")
        .and_then(|x| x.get("username"))
        .and_then(s)
        .unwrap_or_default();
    let c = m.get("content")?;
    match c.get("type")?.as_str()? {
        "text" => {
            let t = c.get("text")?;
            let reply_to = t.get("replyTo").or_else(|| t.get("reply_to")).and_then(num);
            Some(Raw::Text {
                id,
                at,
                sender,
                body: t.get("body").and_then(s).unwrap_or_default(),
                reply_to,
            })
        }
        "attachment" => {
            let o = c.get("attachment").and_then(|a| a.get("object"));
            let get = |k: &str| o.and_then(|o| o.get(k));
            Some(Raw::Attachment {
                id,
                at,
                sender,
                filename: get("filename")
                    .and_then(s)
                    .filter(|f| !f.is_empty())
                    .unwrap_or_else(|| "file".into()),
                title: get("title").and_then(s).unwrap_or_default(),
                size: get("size").and_then(num),
                mime: get("mimeType").and_then(s),
            })
        }
        "edit" => {
            let e = c.get("edit")?;
            let target = e
                .get("messageID")
                .or_else(|| e.get("message_id"))
                .and_then(num)?;
            Some(Raw::Edit {
                id,
                at,
                target,
                body: e.get("body").and_then(s).unwrap_or_default(),
            })
        }
        "delete" => {
            let d = c.get("delete")?;
            let ids = d.get("messageIDs").or_else(|| d.get("message_ids"))?;
            Some(Raw::Delete {
                targets: ids.as_array()?.iter().filter_map(num).collect(),
            })
        }
        "reaction" => {
            let r = c.get("reaction")?;
            Some(Raw::Reaction {
                id,
                at,
                sender,
                target: r.get("m").and_then(num)?,
                body: r.get("b").and_then(s).unwrap_or_default(),
            })
        }
        _ => None,
    }
}

fn read_lines(path: &Path, mut f: impl FnMut(Value)) -> Result<usize, ImportError> {
    require_plain_file(path)?;
    let mut bad = 0usize;
    crate::fsutil::for_each_line(path, |_, line| {
        if !line.trim().is_empty() {
            match serde_json::from_str::<Value>(line) {
                Ok(v) => f(v),
                Err(_) => bad += 1, // a torn final line of an interrupted archive run
            }
        }
        Ok(())
    })?;
    Ok(bad)
}

/// Refuse anything but a regular file (a symlink could pull outside data in).
fn require_plain_file(path: &Path) -> Result<(), ImportError> {
    let m = std::fs::symlink_metadata(path).map_err(|e| ImportError::io(path, e))?;
    if !m.file_type().is_file() {
        return Err(ImportError::Format(format!(
            "{} must be a regular file, not a symlink",
            path.display()
        )));
    }
    Ok(())
}

/// Resolve `rel` under `team_dir/<sub>/`, refusing symlinks at the final
/// component and anything that resolves outside that subdirectory.
fn confined_under(team_dir: &Path, sub: &str, rel: &str) -> Result<PathBuf, ImportError> {
    let full = confined_path(team_dir, rel)?;
    let base = team_dir.join(sub);
    if !full.starts_with(&base) {
        return Err(ImportError::Format(format!(
            "path {rel:?} is outside {sub}/"
        )));
    }
    let raw = team_dir.join(rel);
    let m = std::fs::symlink_metadata(&raw).map_err(|e| ImportError::io(&raw, e))?;
    if m.file_type().is_symlink() {
        return Err(ImportError::Format(format!("path {rel:?} is a symlink")));
    }
    Ok(full)
}

/// Last JSON object per `key` field in a JSONL file (missing file: empty).
fn last_by_key(path: &Path, key: &str) -> Result<HashMap<String, Value>, ImportError> {
    let mut out = HashMap::new();
    if !path.exists() {
        return Ok(out);
    }
    read_lines(path, |v| {
        if let Some(k) = v.get(key).and_then(Value::as_str) {
            out.insert(k.to_string(), v);
        }
    })?;
    Ok(out)
}

fn sorted_files(dir: &Path, ext: &str) -> Result<Vec<PathBuf>, ImportError> {
    let mut out = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(ImportError::io(dir, e)),
    };
    for e in rd {
        let e = e.map_err(|e| ImportError::io(dir, e))?;
        let p = e.path();
        let ft = e.file_type().map_err(|e| ImportError::io(&p, e))?;
        if ext.is_empty() {
            if ft.is_dir() {
                out.push(p);
            }
        } else if ft.is_file() && p.extension().and_then(|x| x.to_str()) == Some(ext) {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

impl KeybaseAdapter {
    fn channel_raw(
        &self,
        team_dir: &Path,
        dir: &str,
        report: &mut AdapterReport,
    ) -> Result<Vec<Raw>, ImportError> {
        if dir.contains('/') || dir.contains('\\') || dir == ".." || dir == "." || dir.is_empty() {
            return Err(ImportError::Format(format!(
                "team.json channel dir {dir:?} must be one path segment"
            )));
        }
        let rel = format!("channels/{dir}/messages");
        if !team_dir.join(&rel).exists() {
            return Ok(vec![]);
        }
        let base = confined_under(team_dir, "channels", &rel)
            .map_err(|e| ImportError::Format(format!("team.json channel dir {dir:?}: {e}")))?;
        let mut raws = Vec::new();
        for year in sorted_files(&base, "")? {
            for f in sorted_files(&year, "jsonl")? {
                let bad = read_lines(&f, |v| match parse_raw(&v) {
                    Some(r) => raws.push(r),
                    None => report.ignored += 1,
                })?;
                if bad > 0 {
                    report.ignored += bad;
                    report.warnings.push(format!(
                        "{}: {bad} undecodable line(s) ignored",
                        f.display()
                    ));
                }
            }
        }
        Ok(raws)
    }
}

impl SourceAdapter for KeybaseAdapter {
    fn name(&self) -> &'static str {
        "keybase"
    }

    fn convert(&self, input: &Path, out: &mut ArchiveWriter) -> Result<AdapterReport, ImportError> {
        let team_dir = input
            .canonicalize()
            .map_err(|e| ImportError::io(input, e))?;
        let tj = team_dir.join("team.json");
        require_plain_file(&tj)?;
        let team: TeamJson =
            serde_json::from_slice(&std::fs::read(&tj).map_err(|e| ImportError::io(&tj, e))?)
                .map_err(|e| ImportError::Format(format!("team.json: {e}")))?;
        let mut report = AdapterReport::default();

        // ── authors: profiles first, team members fill the gaps, posters last
        let mut authors: BTreeMap<String, Author> = BTreeMap::new();
        for d in sorted_files(&team_dir.join("users"), "")? {
            let p = d.join("profile.json");
            if require_plain_file(&p).is_err() {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&p) {
                match serde_json::from_slice::<Profile>(&bytes) {
                    Ok(pr) if !pr.username.is_empty() => {
                        authors.insert(
                            pr.username.clone(),
                            Author {
                                id: pr.username.clone(),
                                handle: pr.username,
                                display_name: pr.full_name.filter(|n| !n.trim().is_empty()),
                                about: pr.bio.filter(|b| !b.trim().is_empty()),
                                bot: false,
                            },
                        );
                    }
                    _ => report
                        .warnings
                        .push(format!("{}: unreadable profile ignored", p.display())),
                }
            }
        }
        let mut bots = HashSet::new();
        for m in &team.members {
            let bot = m.role.as_deref().is_some_and(|r| {
                r.eq_ignore_ascii_case("bot") || r.eq_ignore_ascii_case("restrictedbot")
            });
            if bot {
                bots.insert(m.username.clone());
            }
            authors.entry(m.username.clone()).or_insert_with(|| Author {
                id: m.username.clone(),
                handle: m.username.clone(),
                display_name: m.full_name.clone().filter(|n| !n.trim().is_empty()),
                about: None,
                bot,
            });
        }

        let manifest = last_by_key(&team_dir.join("assets/manifest.jsonl"), "key")?;
        let refs = last_by_key(&team_dir.join("assets/refs.jsonl"), "key")?;

        let mut seen_topics = HashSet::new();
        for ch in &team.channels {
            if !seen_topics.insert(ch.topic.clone()) {
                // Asset refs are keyed "<topic>:<id>", so two conversations
                // with one topic cannot be told apart.
                return Err(ImportError::Format(format!(
                    "two conversations share the topic {:?}: attachment refs would be ambiguous",
                    ch.topic
                )));
            }
            out.channel(Channel {
                id: ch.id.clone(),
                name: ch.topic.clone(),
                topic: ch.headline.clone().filter(|h| !h.trim().is_empty()),
                created_at: None,
            });
            report.channels += 1;
            let Some(dir) = ch.dir.as_deref() else {
                report
                    .warnings
                    .push(format!("#{}: no directory yet (not archived)", ch.topic));
                continue;
            };
            let mut raws = self.channel_raw(&team_dir, dir, &mut report)?;
            raws.sort_by_key(|r| match r {
                Raw::Text { id, .. }
                | Raw::Attachment { id, .. }
                | Raw::Edit { id, .. }
                | Raw::Reaction { id, .. } => *id,
                Raw::Delete { .. } => u64::MAX,
            });
            let mid = |n: u64| format!("{}:{n}", ch.id);
            let mut msgs: BTreeMap<u64, Message> = BTreeMap::new();
            let mut edits: Vec<(u64, u64, u64, String)> = Vec::new();
            let mut deletes: HashSet<u64> = HashSet::new();
            let mut reactions: Vec<(u64, u64, u64, String, String)> = Vec::new();
            for r in raws {
                match r {
                    Raw::Text {
                        id,
                        at,
                        sender,
                        body,
                        reply_to,
                    } => {
                        msgs.insert(
                            id,
                            Message {
                                id: mid(id),
                                channel: ch.id.clone(),
                                author: sender,
                                created_at: at,
                                text: body,
                                reply_to: reply_to.map(mid),
                                edited_at: None,
                                attachments: vec![],
                            },
                        );
                    }
                    Raw::Attachment {
                        id,
                        at,
                        sender,
                        filename,
                        title,
                        size,
                        mime,
                    } => {
                        let key = format!("{}:{id}", ch.topic);
                        let declared = mime
                            .clone()
                            .unwrap_or_else(|| "application/octet-stream".into());
                        let att = match refs.get(&key) {
                            Some(r) if r.get("status").and_then(Value::as_str) == Some("done") => {
                                let entry = r
                                    .get("sha256")
                                    .and_then(Value::as_str)
                                    .and_then(|sha| manifest.get(sha));
                                let main = entry
                                    .filter(|e| {
                                        e.get("status").and_then(Value::as_str) == Some("ok")
                                    })
                                    .and_then(|e| e.get("outputs")?.get("main"));
                                match main.and_then(|m| {
                                    Some((
                                        m.get("path")?.as_str()?,
                                        m.get("mime").and_then(Value::as_str),
                                    ))
                                }) {
                                    Some((rel, omime)) => {
                                        // Only the asset store: never a message file (raw lines
                                        // carry attachment decryption keys).
                                        let file = confined_under(&team_dir, "assets", rel)?;
                                        report.attachments_ok += 1;
                                        out.attach_file(
                                            &file,
                                            &filename,
                                            omime.unwrap_or(&declared),
                                        )?
                                    }
                                    None => {
                                        report.attachments_missing += 1;
                                        Attachment {
                                            sha256: None,
                                            path: None,
                                            filename: filename.clone(),
                                            mime: declared,
                                            bytes: size,
                                            status: AttachmentStatus::Unavailable,
                                        }
                                    }
                                }
                            }
                            Some(r) => {
                                report.attachments_missing += 1;
                                let status = if r.get("status").and_then(Value::as_str)
                                    == Some("deferred")
                                {
                                    AttachmentStatus::Skipped
                                } else {
                                    AttachmentStatus::Unavailable
                                };
                                Attachment {
                                    sha256: None,
                                    path: None,
                                    filename: filename.clone(),
                                    mime: declared,
                                    bytes: size,
                                    status,
                                }
                            }
                            None => {
                                report.attachments_missing += 1;
                                Attachment {
                                    sha256: None,
                                    path: None,
                                    filename: filename.clone(),
                                    mime: declared,
                                    bytes: size,
                                    status: AttachmentStatus::Skipped,
                                }
                            }
                        };
                        let text = if !title.trim().is_empty() && title != filename {
                            title
                        } else {
                            String::new()
                        };
                        msgs.insert(
                            id,
                            Message {
                                id: mid(id),
                                channel: ch.id.clone(),
                                author: sender,
                                created_at: at,
                                text,
                                reply_to: None,
                                edited_at: None,
                                attachments: vec![att],
                            },
                        );
                    }
                    Raw::Edit {
                        id,
                        at,
                        target,
                        body,
                    } => edits.push((id, at, target, body)),
                    Raw::Delete { targets } => deletes.extend(targets),
                    Raw::Reaction {
                        id,
                        at,
                        sender,
                        target,
                        body,
                    } => reactions.push((id, at, target, sender, body)),
                }
            }
            edits.sort_by_key(|e| e.0);
            for (_, at, target, body) in edits {
                if let Some(m) = msgs.get_mut(&target) {
                    m.text = body;
                    m.edited_at = Some(at);
                    report.edits_applied += 1;
                }
            }
            for d in &deletes {
                if msgs.remove(d).is_some() {
                    report.deleted += 1;
                }
            }
            for (id, at, target, sender, body) in reactions {
                if deletes.contains(&id) || !msgs.contains_key(&target) || sender.is_empty() {
                    continue;
                }
                authors.entry(sender.clone()).or_insert_with(|| Author {
                    id: sender.clone(),
                    handle: sender.clone(),
                    display_name: None,
                    about: None,
                    bot: false,
                });
                out.reaction(Reaction {
                    message: mid(target),
                    author: sender,
                    emoji: body,
                    created_at: at,
                });
                report.reactions += 1;
            }
            for m in msgs.into_values() {
                if m.author.is_empty() {
                    report.ignored += 1;
                    continue;
                }
                authors.entry(m.author.clone()).or_insert_with(|| Author {
                    id: m.author.clone(),
                    handle: m.author.clone(),
                    display_name: None,
                    about: None,
                    bot: false,
                });
                out.message(m);
                report.messages += 1;
            }
        }
        for mut a in authors.into_values() {
            a.bot |= bots.contains(&a.id);
            out.author(a);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_the_fields_it_needs_and_nothing_else() {
        let line = json!({"msg": {"id": 7, "sent_at": 100, "sender": {"username": "alice"},
            "content": {"type": "text", "text": {"body": "hi", "replyTo": 3}}}});
        match parse_raw(&line) {
            Some(Raw::Text {
                id: 7,
                at: 100,
                sender,
                body,
                reply_to: Some(3),
            }) => {
                assert_eq!(sender, "alice");
                assert_eq!(body, "hi");
            }
            other => panic!("{other:?}"),
        }
        let join = json!({"id": 1, "sent_at": 1, "content": {"type": "join"}});
        assert!(parse_raw(&join).is_none());
        let ms = json!({"id": 2, "sent_at_ms": 5000u64, "content": {"type": "delete", "delete": {"messageIDs": [1, 2]}}});
        assert!(matches!(parse_raw(&ms), Some(Raw::Delete { targets }) if targets == vec![1, 2]));
    }
}
