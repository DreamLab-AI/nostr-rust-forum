//! Signing: plan → Nostr events.
//!
//! Shapes follow what the forum client publishes (`pages/thread.rs`), with an
//! empty relay hint so no deployment URL is signed into tags:
//!
//! | Event | Signer | Tags |
//! |---|---|---|
//! | new thread, kind 40 | archivist | `["section",s]`, `["zone",z]`, `["import",k]` |
//! | topic root, kind 42 | archivist | `["e",thread,"","root"]`, `["section",s]`, `["import",k]` |
//! | message, kind 42 | author's key | `["e",thread,"","root"]`, `["e",root,"","reply"]`, `["p",archivist]`, [`["e",parent,"","quote"]`, `["p",parent author]`], `["section",s]`, `["import",k]` |
//! | profile, kind 0 | each signer but the operator | `["import",k]` |
//!
//! No `zk` or `sealed` tag is ever written here: the sealer adds the outer
//! tags itself.
//!
//! **Ledger pinning.** An item whose key is in the ledger is never signed
//! again; its stored id is reused for every child, so a changed plan or a
//! growing archive cannot create a second copy or a dangling reference.
//!
//! **Sealing budget.** Every kind-42 is fitted so its serialised JSON is at
//! most [`MAX_EVENT_BYTES`]: the sealed envelope encrypts the whole signed
//! original with NIP-44 v2, and after padding and base64 the relay's 64 KiB
//! content cap leaves about 40 960 bytes.

use std::collections::{BTreeMap, HashMap};

use nostr_bbs_core::{sign_event, NostrEvent, UnsignedEvent};

use crate::error::ImportError;
use crate::identity::{IdentityPlan, Resolved, ARCHIVIST, OPERATOR};
use crate::keystore::Keystore;
use crate::media::MediaManifest;
use crate::plan::{ImportPlan, Part};
use crate::structure::{Structure, ThreadChannel};
use crate::target::Target;

/// Largest serialised kind-42 the sealer can wrap.
pub const MAX_EVENT_BYTES: usize = 40_000;
/// Marker appended to text cut to fit [`MAX_EVENT_BYTES`].
pub const TRUNCATED: &str = "\n…[truncated during import]";

/// A ledger row: what is already stored for a key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LedgerRow {
    /// Ledger key.
    pub k: String,
    /// Event id.
    pub id: String,
    /// Signer pubkey.
    pub pk: String,
    /// `created_at`.
    pub t: u64,
    /// Kind.
    pub kind: u64,
}

/// Which messages a run emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emit {
    /// Everything not deferred.
    Normal,
    /// Only the deferred operator messages (after the operator key is imported).
    DeferredOnly,
}

/// The signed output of one run, in insertion order.
#[derive(Debug, Clone, Default)]
pub struct Signed {
    /// `(ledger key, event)`, ordered `(created_at, id)`.
    pub events: Vec<(String, NostrEvent)>,
    /// Ledgered items reused instead of re-signed.
    pub reused: usize,
    /// Messages cut to fit the sealing budget.
    pub fitted: usize,
    /// Images whose media are missing (placeholder written).
    pub images_missing: usize,
}

fn tag(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

fn serialized_len(
    pubkey: &str,
    created_at: u64,
    kind: u64,
    tags: &[Vec<String>],
    content: &str,
) -> usize {
    let ev = NostrEvent {
        id: "0".repeat(64),
        pubkey: pubkey.to_string(),
        created_at,
        kind,
        tags: tags.to_vec(),
        content: content.to_string(),
        sig: "0".repeat(128),
    };
    serde_json::to_string(&ev)
        .map(|s| s.len())
        .unwrap_or(usize::MAX)
}

/// Assemble a message body from its parts, cutting the longest text part
/// (at a character boundary, JSON escaping counted) until the serialised
/// event fits [`MAX_EVENT_BYTES`]. Returns `(content, was_cut)`.
pub fn fit_content(
    parts: &[String],
    tail: Option<&str>,
    pubkey: &str,
    created_at: u64,
    tags: &[Vec<String>],
) -> Result<(String, bool), ImportError> {
    let join = |ps: &[String]| {
        let head = ps
            .iter()
            .filter(|p| !p.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        match tail {
            Some(t) if !t.is_empty() => format!("{head}\n\n{t}"),
            _ => head,
        }
    };
    let full = join(parts);
    if serialized_len(pubkey, created_at, 42, tags, &full) <= MAX_EVENT_BYTES {
        return Ok((full, false));
    }
    let Some((idx, _)) = parts.iter().enumerate().max_by_key(|(_, p)| p.len()) else {
        return Err(ImportError::Plan(
            "an event without text does not fit the sealing budget".into(),
        ));
    };
    let chars: Vec<char> = parts[idx].chars().collect();
    let (mut lo, mut hi) = (0usize, chars.len());
    let attempt = |n: usize| {
        let mut ps = parts.to_vec();
        ps[idx] = chars[..n].iter().collect::<String>() + TRUNCATED;
        join(&ps)
    };
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if serialized_len(pubkey, created_at, 42, tags, &attempt(mid)) <= MAX_EVENT_BYTES {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let c = attempt(lo);
    if serialized_len(pubkey, created_at, 42, tags, &c) > MAX_EVENT_BYTES {
        return Err(ImportError::Plan(
            "message does not fit the sealing budget even when cut".into(),
        ));
    }
    Ok((c, true))
}

/// Inputs to [`sign`].
pub struct SignInput<'a> {
    /// The plan.
    pub plan: &'a ImportPlan,
    /// The structure (threads, zones).
    pub structure: &'a Structure,
    /// The identity plan (profiles).
    pub ids: &'a IdentityPlan,
    /// Keys.
    pub keys: &'a Keystore,
    /// Processed media.
    pub media: &'a MediaManifest,
    /// URLs embedded in content.
    pub target: &'a Target,
    /// Already stored items by key.
    pub ledger: &'a HashMap<String, LedgerRow>,
    /// Which messages to emit.
    pub emit: Emit,
}

fn key_entry<'a>(
    keys: &'a Keystore,
    label: &str,
) -> Result<&'a crate::keystore::KeyEntry, ImportError> {
    keys.get(label).ok_or_else(|| {
        if label == OPERATOR {
            ImportError::Refused("the operator key is not in the keystore: import it first (keys import --label operator)".into())
        } else {
            ImportError::Refused(format!("keystore has no key {label:?}: run `keys` first"))
        }
    })
}

/// Sign everything this run needs (see the module docs).
pub fn sign(input: &SignInput<'_>) -> Result<Signed, ImportError> {
    let SignInput {
        plan,
        structure,
        ids,
        keys,
        media,
        target,
        ledger,
        emit,
    } = *input;
    let archivist = key_entry(keys, ARCHIVIST)?;
    // The archivist's secret is needed only when it signs something (a new
    // thread header, a topic root, its profile): a re-run, or a deferred
    // round under a retired archivist, must not require it.
    let mut out = Signed::default();
    let mut id_of: HashMap<String, (String, String)> = HashMap::new(); // key -> (id, pk)
    for (k, r) in ledger {
        id_of.insert(k.clone(), (r.id.clone(), r.pk.clone()));
    }
    let mut first_at: BTreeMap<String, u64> = BTreeMap::new();
    let mut note_signer = |label: &str, t: u64| {
        let e = first_at.entry(label.to_string()).or_insert(t);
        *e = (*e).min(t);
    };

    let emitted: Vec<&crate::plan::MessagePlan> = plan
        .messages
        .iter()
        .filter(|m| m.deferred == (emit == Emit::DeferredOnly))
        .filter(|m| !ledger.contains_key(&m.key))
        .collect();
    out.reused += plan
        .messages
        .iter()
        .filter(|m| m.deferred == (emit == Emit::DeferredOnly) && ledger.contains_key(&m.key))
        .count();
    let roots_needed: std::collections::BTreeSet<&str> =
        emitted.iter().map(|m| m.root.as_str()).collect();

    // ── thread headers (new threads used by this run)
    let mut thread_id: HashMap<String, String> = HashMap::new();
    for (tkey, t) in &structure.threads {
        match &t.channel {
            ThreadChannel::Existing(id) => {
                thread_id.insert(tkey.clone(), id.clone());
            }
            ThreadChannel::New { name, about } => {
                let k = format!("{}#thread:{tkey}", plan.provenance);
                if let Some((id, _)) = id_of.get(&k) {
                    thread_id.insert(tkey.clone(), id.clone());
                    continue;
                }
                let first_root = plan
                    .roots
                    .iter()
                    .filter(|r| &r.thread == tkey && roots_needed.contains(r.key.as_str()))
                    .map(|r| r.created_at)
                    .min();
                let Some(at) = first_root else { continue };
                let ev = sign_event(
                    UnsignedEvent {
                        pubkey: archivist.pk.clone(),
                        created_at: at.saturating_sub(1),
                        kind: 40,
                        tags: vec![
                            tag(&["section", &t.section]),
                            tag(&["zone", &t.zone]),
                            tag(&["import", &k]),
                        ],
                        content: serde_json::json!({"name": name, "about": about, "picture": ""})
                            .to_string(),
                    },
                    &signing_key(&archivist.secret()?)?,
                )
                .map_err(|e| ImportError::Key(e.to_string()))?;
                note_signer(ARCHIVIST, ev.created_at);
                thread_id.insert(tkey.clone(), ev.id.clone());
                id_of.insert(k.clone(), (ev.id.clone(), ev.pubkey.clone()));
                out.events.push((k, ev));
            }
        }
    }

    // ── topic roots needed by this run
    for r in &plan.roots {
        if !roots_needed.contains(r.key.as_str()) || id_of.contains_key(&r.key) {
            continue;
        }
        let thread = thread_id
            .get(&r.thread)
            .ok_or_else(|| ImportError::Plan(format!("thread {:?} has no channel id", r.thread)))?;
        let section = &structure.threads[&r.thread].section;
        let ev = sign_event(
            UnsignedEvent {
                pubkey: archivist.pk.clone(),
                created_at: r.created_at,
                kind: 42,
                tags: vec![
                    tag(&["e", thread, "", "root"]),
                    tag(&["section", section]),
                    tag(&["import", &r.key]),
                ],
                content: r.content.clone(),
            },
            &signing_key(&archivist.secret()?)?,
        )
        .map_err(|e| ImportError::Key(e.to_string()))?;
        note_signer(ARCHIVIST, ev.created_at);
        id_of.insert(r.key.clone(), (ev.id.clone(), ev.pubkey.clone()));
        out.events.push((r.key.clone(), ev));
    }

    // ── messages: resolve in dependency order (a quote needs its parent's id)
    let mut sks: HashMap<String, nostr_bbs_core::keys::SecretKey> = HashMap::new();
    let mut pending: Vec<&crate::plan::MessagePlan> = emitted;
    loop {
        let before = pending.len();
        let mut next = Vec::new();
        for m in pending {
            let root = id_of.get(&m.root).cloned();
            let quote = match &m.quote {
                // None: the parent is not resolved yet
                Some(q) => id_of.get(q).map(|x| Some(x.clone())),
                None => Some(None),
            };
            let (Some((root_id, root_pk)), Some(quote)) = (root, quote) else {
                next.push(m);
                continue;
            };
            let entry = key_entry(keys, &m.signer)?;
            if !sks.contains_key(&m.signer) {
                sks.insert(m.signer.clone(), entry.secret()?);
            }
            let thread = thread_id.get(&m.thread).ok_or_else(|| {
                ImportError::Plan(format!("thread {:?} has no channel id", m.thread))
            })?;
            let section = &structure.threads[&m.thread].section;
            let zone = &structure.threads[&m.thread].zone;
            let mut tags = vec![
                tag(&["e", thread, "", "root"]),
                tag(&["e", &root_id, "", "reply"]),
                tag(&["p", &root_pk]),
            ];
            if let Some((qid, qpk)) = &quote {
                tags.push(tag(&["e", qid, "", "quote"]));
                if qpk != &root_pk {
                    tags.push(tag(&["p", qpk]));
                }
            }
            tags.push(tag(&["section", section]));
            tags.push(tag(&["import", &m.key]));
            let parts: Vec<String> = m
                .parts
                .iter()
                .map(|p| match p {
                    Part::Text(t) => t.clone(),
                    Part::Image(img) => match media.main_of(&img.sha256) {
                        Some(obj) => target.zone_media_url(&archivist.pk, zone, &obj.name),
                        None => {
                            out.images_missing += 1;
                            format!("[image not migrated: {}]", img.filename)
                        }
                    },
                })
                .collect();
            let (content, cut) = fit_content(
                &parts,
                m.reactions.as_deref(),
                &entry.pk,
                m.created_at,
                &tags,
            )?;
            if cut {
                out.fitted += 1;
            }
            let ev = sign_event(
                UnsignedEvent {
                    pubkey: entry.pk.clone(),
                    created_at: m.created_at,
                    kind: 42,
                    tags,
                    content,
                },
                &signing_key(&sks[&m.signer])?,
            )
            .map_err(|e| ImportError::Key(e.to_string()))?;
            note_signer(&m.signer, ev.created_at);
            id_of.insert(m.key.clone(), (ev.id.clone(), ev.pubkey.clone()));
            out.events.push((m.key.clone(), ev));
        }
        if next.is_empty() {
            break;
        }
        if next.len() == before {
            let first = next[0];
            return Err(ImportError::Plan(format!(
                "{} message(s) reference a topic root or quoted parent that is neither planned in this run nor stored (first: {}){}",
                next.len(),
                first.key,
                if emit == Emit::DeferredOnly { "; run the normal build first" } else { "" }
            )));
        }
        pending = next;
    }

    // ── profiles for signers that signed something in this run (not the operator)
    let by_label: HashMap<String, &Resolved> = ids
        .authors
        .values()
        .filter_map(|r| match &r.signer {
            crate::identity::Signer::Key { label, .. } => Some((label.clone(), r)),
            _ => None,
        })
        .collect();
    for (label, at) in first_at {
        if label == OPERATOR {
            continue;
        }
        let k = format!("{}#profile:{label}", plan.provenance);
        if id_of.contains_key(&k) {
            continue;
        }
        let entry = key_entry(keys, &label)?;
        let content = if label == ARCHIVIST {
            serde_json::json!({"name": "archivist", "display_name": "Archivist", "about": format!("Signs the topics imported from {}", plan.provenance)})
        } else {
            let r = by_label.get(&label);
            let handle = r.map(|r| r.handle.clone()).unwrap_or_else(|| label.clone());
            let about = if label.starts_with("archive:") {
                format!(
                    "Archived history of {handle}, imported from {}",
                    plan.provenance
                )
            } else {
                r.and_then(|r| r.about.clone())
                    .unwrap_or_else(|| format!("Imported from {}", plan.provenance))
            };
            serde_json::json!({"name": handle, "display_name": r.and_then(|r| r.display_name.clone()).unwrap_or_else(|| handle.clone()), "about": about})
        };
        let ev = sign_event(
            UnsignedEvent {
                pubkey: entry.pk.clone(),
                created_at: at.saturating_sub(1),
                kind: 0,
                tags: vec![tag(&["import", &k])],
                content: content.to_string(),
            },
            &signing_key(&entry.secret()?)?,
        )
        .map_err(|e| ImportError::Key(e.to_string()))?;
        out.events.push((k, ev));
    }

    out.events.sort_by(|a, b| {
        a.1.created_at
            .cmp(&b.1.created_at)
            .then(a.1.id.cmp(&b.1.id))
    });
    Ok(out)
}

fn signing_key(
    sk: &nostr_bbs_core::keys::SecretKey,
) -> Result<k256::schnorr::SigningKey, ImportError> {
    nostr_bbs_core::keys::signing_key_from_bytes(sk.as_bytes())
        .map_err(|e| ImportError::Key(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fitting_respects_the_byte_budget_with_multibyte_text() {
        let pk = "a".repeat(64);
        let tags = vec![tag(&["e", &"b".repeat(64), "", "root"])];
        let big = "é\"\n".repeat(30_000); // multibyte and escaped characters
        let (c, cut) = fit_content(&[big], Some("— reactions: 👍 ×1 (a)"), &pk, 1, &tags).unwrap();
        assert!(cut);
        assert!(c.ends_with("— reactions: 👍 ×1 (a)"));
        assert!(c.contains(TRUNCATED));
        assert!(serialized_len(&pk, 1, 42, &tags, &c) <= MAX_EVENT_BYTES);
        let (small, cut) = fit_content(&["hi".into()], None, &pk, 1, &tags).unwrap();
        assert_eq!(small, "hi");
        assert!(!cut);
    }
}
