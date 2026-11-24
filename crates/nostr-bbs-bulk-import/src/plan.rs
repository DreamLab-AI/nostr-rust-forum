//! The import plan: pure, no keys, no I/O.
//!
//! From an [`Archive`], an [`IdentityPlan`] and a [`Structure`] it decides,
//! per source channel, the archivist-signed topic root and, per message,
//! the text, the reply links and the attachments, exactly as the forum
//! client would have published them (`pages/thread.rs` shapes):
//!
//! - each source channel is ONE topic: a root whose content is exactly the
//!   channel's title from [`crate::titles`], dated one second before the
//!   channel's first imported message (the sealer works in
//!   `(created_at, id)` order, so a root seals before its replies);
//! - every message replies to its topic root; a source reply to an imported
//!   message **in the same thread** adds a `quote` link; any other reply
//!   gets a first-line note instead (`↪ reply to <handle> (<date>)`, or
//!   `↪ reply to a message that was not migrated`);
//! - reactions are folded into the target's text, never kind-7 (the relay's
//!   retention sweep deletes kind 7 after 30 days);
//! - images reference the media manifest by content hash; every other
//!   attachment becomes a `[… not migrated: name, size, date]` line;
//! - messages of dropped authors are not imported, and an `operator` author
//!   with `defer` is planned but marked deferred.
//!
//! Ledger keys identify plan items, in separate namespaces so no source id
//! can collide with another kind of item: `<source>:<source_id>#m:<message
//! id>`, `…#root:<channel id>`, `…#thread:<thread key>`, `…#profile:<label>`,
//! `…#dm:<wrap id>`.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::format::{Archive, AttachmentStatus, Message};
use crate::identity::{IdentityPlan, Signer, ARCHIVIST};
use crate::structure::Structure;
use crate::titles::{default_title, Titles};

/// Longest text kept (the relay caps a whole event at 64 KiB).
pub const MAX_CONTENT: usize = 60_000;
/// Longest folded reaction line.
pub const MAX_REACTION_LINE: usize = 600;

/// A topic root (one per imported source channel).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RootPlan {
    /// Ledger key.
    pub key: String,
    /// Source channel id.
    pub channel: String,
    /// Thread key in the structure.
    pub thread: String,
    /// `created_at`: the first imported message − 1.
    pub created_at: u64,
    /// Root text.
    pub content: String,
}

/// An image the event links (resolved against the media manifest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageRef {
    /// SHA-256 of the archived bytes.
    pub sha256: String,
    /// Original file name (for the placeholder when media are missing).
    pub filename: String,
}

/// One part of a message body, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Part {
    /// Literal text.
    Text(String),
    /// An image URL line (resolved at signing time).
    Image(ImageRef),
}

/// A planned message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MessagePlan {
    /// Ledger key.
    pub key: String,
    /// Source message id.
    pub source_id: String,
    /// Source channel id.
    pub channel: String,
    /// Thread key.
    pub thread: String,
    /// Keystore label of the signer.
    pub signer: String,
    /// Original send time.
    pub created_at: u64,
    /// Body parts (note, text, attachments).
    pub parts: Vec<Part>,
    /// Folded reactions line (appended after a blank line), if any.
    pub reactions: Option<String>,
    /// Ledger key of the topic root.
    pub root: String,
    /// Ledger key of the quoted parent, when it is imported in the same thread.
    pub quote: Option<String>,
    /// Imported later (`build --deferred-only`).
    pub deferred: bool,
}

/// Counts for the operator.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PlanStats {
    /// Channels imported.
    pub channels: usize,
    /// Channels skipped by the structure.
    pub channels_skipped: usize,
    /// Topics (roots).
    pub topics: usize,
    /// Messages to import now.
    pub messages: usize,
    /// Operator messages deferred.
    pub deferred: usize,
    /// Messages of dropped authors.
    pub dropped_author: usize,
    /// Empty messages skipped.
    pub empty: usize,
    /// Replies linked by `quote`.
    pub quoted: usize,
    /// Replies turned into a note.
    pub noted: usize,
    /// Reactions folded into text.
    pub reactions_folded: usize,
    /// Messages truncated at [`MAX_CONTENT`].
    pub truncated: usize,
    /// Image attachments linked.
    pub images: usize,
    /// Attachments written as a "not migrated" line.
    pub not_migrated: usize,
}

/// The plan.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ImportPlan {
    /// `<source>:<source_id>`.
    pub provenance: String,
    /// Topic roots, in channel order.
    pub roots: Vec<RootPlan>,
    /// Messages, ordered `(created_at, channel order, source order)`.
    pub messages: Vec<MessagePlan>,
    /// Counts.
    pub stats: PlanStats,
}

/// `YYYY-MM-DD` (UTC) of unix seconds.
pub fn iso_date(t: u64) -> String {
    // Civil-from-days (Howard Hinnant), no time-zone tables needed.
    let days = (t / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, d)
}

/// `:shortcode:` (optionally with a skin tone) → emoji; anything else as is.
pub fn emoji_of(body: &str) -> String {
    const SHORTCODES: &[(&str, &str)] = &[
        ("+1", "👍"),
        ("-1", "👎"),
        ("thumbsup", "👍"),
        ("thumbsdown", "👎"),
        ("heart", "❤️"),
        ("joy", "😂"),
        ("laughing", "😆"),
        ("smile", "😄"),
        ("grinning", "😀"),
        ("tada", "🎉"),
        ("fire", "🔥"),
        ("clap", "👏"),
        ("eyes", "👀"),
        ("pray", "🙏"),
        ("cry", "😢"),
        ("sob", "😭"),
        ("thinking", "🤔"),
        ("100", "💯"),
        ("rocket", "🚀"),
        ("wave", "👋"),
        ("ok_hand", "👌"),
        ("raised_hands", "🙌"),
        ("facepalm", "🤦"),
        ("skull", "💀"),
    ];
    let b = body.trim();
    if b.is_empty() {
        return "❓".into();
    }
    if let Some(inner) = b.strip_prefix(':') {
        let name = inner.split(':').next().unwrap_or("");
        let rest = &inner[name.len()..];
        let tone_ok = rest == ":" || (rest.starts_with("::skin-tone-") && rest.ends_with(':'));
        if !name.is_empty() && !name.contains(char::is_whitespace) && tone_ok {
            if let Some((_, e)) = SHORTCODES.iter().find(|(k, _)| *k == name) {
                return (*e).into();
            }
        }
    }
    b.into()
}

/// `— reactions: 👍 ×3 (alice, bob, carol) · 😂 ×1 (dave)`: first-seen
/// order, one vote per person per emoji, capped at [`MAX_REACTION_LINE`].
pub fn reaction_line(rs: &[(String, String)]) -> Option<String> {
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for (who, emoji) in rs {
        match groups.iter_mut().find(|(e, _)| e == emoji) {
            Some((_, w)) => {
                if !w.contains(who) {
                    w.push(who.clone());
                }
            }
            None => groups.push((emoji.clone(), vec![who.clone()])),
        }
    }
    if groups.is_empty() {
        return None;
    }
    let mut out = groups
        .iter()
        .map(|(e, w)| format!("{e} ×{} ({})", w.len(), w.join(", ")))
        .collect::<Vec<_>>()
        .join(" · ");
    if out.chars().count() > MAX_REACTION_LINE {
        out = out.chars().take(MAX_REACTION_LINE - 1).collect::<String>() + "…";
    }
    Some(format!("— reactions: {out}"))
}

fn size_text(bytes: Option<u64>) -> String {
    match bytes {
        None => "size unknown".into(),
        Some(b) => {
            let mb = b as f64 / 1_048_576.0;
            if mb > 0.0 && mb < 0.05 {
                "<0.1 MB".into()
            } else {
                format!("{mb:.1} MB")
            }
        }
    }
}

fn kind_of(mime: &str) -> &'static str {
    let m = mime.to_ascii_lowercase();
    if m.starts_with("image/") {
        "image"
    } else if m.starts_with("video/") {
        "video"
    } else if m.starts_with("audio/") {
        "audio"
    } else if m == "application/pdf" {
        "pdf"
    } else {
        "file"
    }
}

/// Image types a zone media container accepts (pod zone ACL).
pub const ZONE_IMAGE_TYPES: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
    "image/avif",
    "image/heic",
    "image/heif",
    "image/tiff",
    "image/bmp",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum St {
    Imported,
    Deferred,
    Skipped,
}

/// Build the plan. The structure must already be validated against the
/// archive ([`Structure::validate`]).
pub fn build(
    archive: &Archive,
    ids: &IdentityPlan,
    structure: &Structure,
    titles: &Titles,
) -> ImportPlan {
    let prov = format!("{}:{}", archive.manifest.source, archive.manifest.source_id);
    let key_of = |id: &str| format!("{prov}#m:{id}");
    let mut plan = ImportPlan {
        provenance: prov.clone(),
        ..Default::default()
    };
    let handle_of = |author: &str| {
        ids.authors
            .get(author)
            .map(|r| r.handle.clone())
            .unwrap_or_else(|| author.to_string())
    };

    // message → (status, channel, thread, handle, created_at)
    let mut status: HashMap<&str, (St, &str, String, String, u64)> = HashMap::new();
    let mut by_channel: BTreeMap<usize, Vec<&Message>> = BTreeMap::new();
    let order: HashMap<&str, usize> = archive
        .channels
        .iter()
        .enumerate()
        .map(|(i, c)| (c.id.as_str(), i))
        .collect();
    for m in &archive.messages {
        by_channel
            .entry(order[m.channel.as_str()])
            .or_default()
            .push(m);
    }
    for c in &archive.channels {
        let map = structure.channels.get(&c.id);
        let thread = match map {
            Some(m) if !m.skip => m.thread.clone().unwrap_or_default(),
            _ => {
                plan.stats.channels_skipped += 1;
                continue;
            }
        };
        plan.stats.channels += 1;
        for m in by_channel
            .get(&order[c.id.as_str()])
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let has_body = !m.text.trim().is_empty() || !m.attachments.is_empty();
            let st = match ids.authors.get(&m.author).map(|r| &r.signer) {
                Some(Signer::Dropped) | None => {
                    plan.stats.dropped_author += 1;
                    St::Skipped
                }
                Some(_) if !has_body => {
                    plan.stats.empty += 1;
                    St::Skipped
                }
                Some(Signer::Key { deferred: true, .. }) => St::Deferred,
                Some(Signer::Key { .. }) => St::Imported,
            };
            status.insert(
                m.id.as_str(),
                (
                    st,
                    c.id.as_str(),
                    thread.clone(),
                    handle_of(&m.author),
                    m.created_at,
                ),
            );
        }
    }

    // reactions per target, reactor handles (dropped reactors left out)
    let mut reacts: HashMap<&str, Vec<(String, String)>> = HashMap::new();
    for r in &archive.reactions {
        if matches!(
            ids.authors.get(&r.author).map(|x| &x.signer),
            Some(Signer::Key { .. })
        ) {
            reacts
                .entry(r.message.as_str())
                .or_default()
                .push((handle_of(&r.author), emoji_of(&r.emoji)));
        }
    }

    for c in &archive.channels {
        let Some(thread) = structure
            .channels
            .get(&c.id)
            .filter(|m| !m.skip)
            .and_then(|m| m.thread.clone())
        else {
            continue;
        };
        let msgs = by_channel
            .get(&order[c.id.as_str()])
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let live: Vec<&&Message> = msgs
            .iter()
            .filter(|m| {
                status
                    .get(m.id.as_str())
                    .is_some_and(|s| s.0 != St::Skipped)
            })
            .collect();
        let Some(first) = live.iter().map(|m| m.created_at).min() else {
            continue;
        };
        // The root's content is exactly the title (the client's topic title
        // is the root's first line); provenance stays in the `import` tag.
        let title = titles
            .get(&c.id)
            .map(str::to_string)
            .unwrap_or_else(|| default_title(&c.name));
        let root_key = format!("{prov}#root:{}", c.id);
        plan.roots.push(RootPlan {
            key: root_key.clone(),
            channel: c.id.clone(),
            thread: thread.clone(),
            created_at: first.saturating_sub(1),
            content: title,
        });
        plan.stats.topics += 1;

        for m in msgs {
            let Some(&(st, _, _, _, _)) = status.get(m.id.as_str()) else {
                continue;
            };
            if st == St::Skipped {
                continue;
            }
            let signer = match &ids.authors[&m.author].signer {
                Signer::Key { label, .. } => label.clone(),
                Signer::Dropped => unreachable!("skipped above"),
            };
            let mut quote = None;
            let mut note = None;
            if let Some(parent) = &m.reply_to {
                match status.get(parent.as_str()) {
                    Some((pst, _, pthread, phandle, pat)) => {
                        let linkable = *pthread == thread
                            && (*pst == St::Imported
                                || (st == St::Deferred && *pst == St::Deferred));
                        if linkable {
                            quote = Some(key_of(parent));
                        } else if *pst != St::Skipped {
                            note = Some(format!("↪ reply to {phandle} ({})", iso_date(*pat)));
                        } else {
                            note = Some("↪ reply to a message that was not migrated".into());
                        }
                    }
                    None => note = Some("↪ reply to a message that was not migrated".into()),
                }
            }
            let mut parts = Vec::new();
            if let Some(n) = note {
                parts.push(Part::Text(n));
                plan.stats.noted += 1;
            } else if quote.is_some() && st == St::Imported {
                plan.stats.quoted += 1;
            }
            if !m.text.trim().is_empty() {
                let mut t = m.text.clone();
                if t.chars().count() > MAX_CONTENT {
                    t = t.chars().take(MAX_CONTENT).collect::<String>()
                        + "\n…[truncated during import]";
                    plan.stats.truncated += 1;
                }
                parts.push(Part::Text(t));
            }
            for att in &m.attachments {
                let kind = kind_of(&att.mime);
                if kind == "image"
                    && att.status == AttachmentStatus::Ok
                    && ZONE_IMAGE_TYPES.contains(&att.mime.to_ascii_lowercase().as_str())
                {
                    if let Some(sha) = &att.sha256 {
                        parts.push(Part::Image(ImageRef {
                            sha256: sha.clone(),
                            filename: att.filename.clone(),
                        }));
                        plan.stats.images += 1;
                        continue;
                    }
                }
                parts.push(Part::Text(format!(
                    "[{kind} not migrated: {}, {}, {}]",
                    att.filename,
                    size_text(att.bytes),
                    iso_date(m.created_at)
                )));
                plan.stats.not_migrated += 1;
            }
            let reactions = reacts.get(m.id.as_str()).and_then(|rs| {
                let line = reaction_line(rs);
                if line.is_some() {
                    plan.stats.reactions_folded += rs.len();
                }
                line
            });
            if st == St::Deferred {
                plan.stats.deferred += 1;
            } else {
                plan.stats.messages += 1;
            }
            plan.messages.push(MessagePlan {
                key: key_of(&m.id),
                source_id: m.id.clone(),
                channel: c.id.clone(),
                thread: thread.clone(),
                signer,
                created_at: m.created_at,
                parts,
                reactions,
                root: root_key.clone(),
                quote,
                deferred: st == St::Deferred,
            });
        }
    }
    let chan_order: HashMap<String, usize> = archive
        .channels
        .iter()
        .enumerate()
        .map(|(i, c)| (c.id.clone(), i))
        .collect();
    plan.messages.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then(chan_order[&a.channel].cmp(&chan_order[&b.channel]))
            .then(a.source_id.cmp(&b.source_id))
    });
    plan
}

impl ImportPlan {
    /// Keystore labels that sign something in this run (archivist included
    /// when any root exists).
    pub fn signers(&self, deferred_only: bool) -> Vec<String> {
        let mut v: Vec<String> = self
            .messages
            .iter()
            .filter(|m| m.deferred == deferred_only)
            .map(|m| m.signer.clone())
            .collect();
        if !self.roots.is_empty() {
            v.push(ARCHIVIST.into());
        }
        v.sort();
        v.dedup();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_emoji_and_reactions() {
        assert_eq!(iso_date(0), "1970-01-01");
        assert_eq!(iso_date(1_700_000_000), "2023-11-14");
        assert_eq!(iso_date(951_782_400), "2000-02-29");
        assert_eq!(emoji_of(":+1:"), "👍");
        assert_eq!(emoji_of(":+1::skin-tone-3:"), "👍");
        assert_eq!(emoji_of("🙂"), "🙂");
        assert_eq!(emoji_of(":unknown:"), ":unknown:");
        assert_eq!(emoji_of(""), "❓");
        let rs = vec![
            ("a".to_string(), "👍".to_string()),
            ("b".into(), "👍".into()),
            ("a".into(), "👍".into()),
            ("c".into(), "😂".into()),
        ];
        assert_eq!(
            reaction_line(&rs).unwrap(),
            "— reactions: 👍 ×2 (a, b) · 😂 ×1 (c)"
        );
        assert!(reaction_line(&[]).is_none());
    }
}
