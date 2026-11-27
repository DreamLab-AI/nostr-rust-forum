//! A zone's posts from the relay, as index rows.
//!
//! What the relay holds for a post in an encrypted zone, and the id a
//! search hit resolves to (the client's `sealed_search::verified_hits`):
//!
//! - **A post written in the forum**: a kind-42 signed by its author, its
//!   content NIP-44 encrypted from the author to the zone epoch key, tagged
//!   `["zk", <zone>, <epoch>, <zone pk>]` (`zone_crypto::apply_write_plan`).
//!   The relay serves it by its own id, and the row's id is that id.
//! - **An imported or migrated post** (ADR-2017): only a sealed envelope, a
//!   kind-42 signed by the migrator, tagged `zk` and
//!   `["sealed", <original id>, "1"]`, whose content seals the whole original
//!   event to the zone key. The row's id is the ORIGINAL's id, which the
//!   client asks for by `#sealed`.
//!
//! Every event is verified (signature and id), its `zk` must name this zone
//! and a held key whose pubkey matches, and it must open. Rows are left out
//! when the post is:
//!
//! - **deleted**: named by a kind-5 the relay stored. The relay refuses a
//!   kind-5 below trust level 3 unless every target is the signer's own, so
//!   a stored kind-5 is an authorised deletion. A target may be a live post's
//!   id, an envelope's id, or an original's (inner) id; all three map to the
//!   row. (Moderator deletes physically remove the event as well; deletes
//!   through the admin HTTP API leave no kind-5 and are caught when a
//!   compaction finds the post gone.)
//! - **superseded**: the target of an edit, a kind-42 tagged
//!   `["e", <target>, "", "edit"]` by the target's own author (for an
//!   envelope, the original's author). Chains resolve edge by edge: each
//!   edit supersedes the post it names.
//! - **already indexed** (the overlap between runs).
//!
//! A post under an epoch whose key the indexer does not hold is not an
//! error to skip silently: it is counted, and [`Harvest::hold_back`] keeps
//! the high-water mark below it so it is read again once the key arrives.

use std::collections::{BTreeSet, HashMap, HashSet};

use nostr_bbs_core::event::verify_event_strict;
use nostr_bbs_core::sealed::{open_sealed_with_conversation_key, parse_sealed};
use nostr_bbs_core::NostrEvent;
use nostr_bbs_zone_migrate::keys::{KeyRing, ZoneKey};
use nostr_bbs_zone_migrate::relay::{
    fetch_all, fetch_by_ids, Filter, Relay, RelayError, MAX_IDS_PER_REQ,
};
use zeroize::Zeroizing;

/// Why a harvest stopped.
#[derive(Debug, thiserror::Error)]
pub enum HarvestError {
    /// The relay session is not NIP-42 authenticated: zone posts are
    /// members-only, so an unauthenticated read would look like an empty zone.
    #[error(
        "the relay session is not NIP-42 authenticated as the indexer; refusing to read the zone"
    )]
    Unauthenticated,
    /// The relay failed.
    #[error(transparent)]
    Relay(#[from] RelayError),
}

/// One post to index. `text` is plaintext: it lives only in memory and is
/// zeroised on drop.
pub struct ZoneRow {
    /// Hex id the client resolves the hit to (see the module docs).
    pub id: String,
    /// The post's text.
    pub text: Zeroizing<String>,
    /// Zone key epoch.
    pub epoch: u32,
    /// That epoch's hex zone pubkey.
    pub zone_pk: String,
    /// The post's `created_at`.
    pub created_at: u64,
}

impl std::fmt::Debug for ZoneRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneRow")
            .field("id", &self.id)
            .field("text", &"<redacted>")
            .field("epoch", &self.epoch)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// What a harvest found. Counts only: no text.
#[derive(Debug, Default)]
pub struct Harvest {
    /// Posts to index, oldest first.
    pub rows: Vec<ZoneRow>,
    /// Ids already in the index that are now deleted or superseded.
    pub exclude: BTreeSet<String>,
    /// Kind-42 events read.
    pub events: usize,
    /// Kind-5 events read.
    pub deletions: usize,
    /// Posts left out as deleted.
    pub deleted: usize,
    /// Posts left out as superseded by an edit.
    pub superseded: usize,
    /// Posts already in the index.
    pub already_indexed: usize,
    /// Posts with no text.
    pub empty: usize,
    /// Events whose signature or id does not verify.
    pub invalid: usize,
    /// Events whose `zk` names another zone or is malformed.
    pub foreign: usize,
    /// Events under a held key that do not open (counted, not retried).
    pub undecryptable: usize,
    /// Events under an epoch whose key is not held.
    pub missing_key: usize,
    /// Those epochs.
    pub missing_epochs: BTreeSet<u32>,
    /// Oldest `created_at` among events that could not be read for want of
    /// a key: the high-water mark must stay below it.
    pub hold_back: Option<u64>,
    /// Newest `created_at` read.
    pub newest: Option<u64>,
}

impl Harvest {
    /// The high-water mark this harvest supports: the newest event read, but
    /// below any event held back for want of a key, and never below `prior`.
    pub fn high_water(&self, prior: Option<u64>) -> Option<u64> {
        let hw = match (self.newest, self.hold_back) {
            (Some(n), Some(h)) => Some(n.min(h.saturating_sub(1))),
            (n, None) => n,
            (None, Some(_)) => None,
        };
        match (hw, prior) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }
}

struct Rec {
    author: String,
    created_at: u64,
    epoch: u32,
    zone_pk: String,
    text: Zeroizing<String>,
    edit_of: Option<String>,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// The first well-formed `zk` tag: `(zone, epoch >= 1, lowercase pubkey)`.
fn zk(ev: &NostrEvent) -> Option<(String, u32, String)> {
    ev.tags.iter().find_map(|t| {
        if t.len() < 4 || t[0] != "zk" || t[1].is_empty() || !is_hex64(&t[3]) {
            return None;
        }
        let epoch: u32 = t[2].parse().ok().filter(|e| *e >= 1)?;
        Some((t[1].clone(), epoch, t[3].to_ascii_lowercase()))
    })
}

/// The post a kind-42 edits (`["e", <id>, _, "edit"]`), lowercased.
fn edit_target(ev: &NostrEvent) -> Option<String> {
    if ev.kind != 42 {
        return None;
    }
    ev.tags
        .iter()
        .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "edit" && is_hex64(&t[1]))
        .map(|t| t[1].to_ascii_lowercase())
}

/// Opens zone events, caching one NIP-44 conversation key per
/// `(epoch, author)` (an import has one migrator; a forum has few authors).
struct Opener<'a> {
    zone: &'a str,
    ring: &'a KeyRing,
    conv: HashMap<(u32, String), Zeroizing<[u8; 32]>>,
}

enum Opened {
    /// `(row id, author, text, edit target)`.
    Post(String, String, Zeroizing<String>, Option<String>),
    MissingKey,
    Foreign,
    Undecryptable,
}

impl<'a> Opener<'a> {
    fn key(&self, epoch: u32, pk: &str) -> Option<&'a ZoneKey> {
        self.ring
            .get(self.zone, epoch)
            .filter(|k| k.pubkey().eq_ignore_ascii_case(pk))
    }

    fn conversation(&mut self, key: &ZoneKey, author: &str) -> Option<[u8; 32]> {
        let slot = (key.epoch(), author.to_ascii_lowercase());
        if let Some(c) = self.conv.get(&slot) {
            return Some(**c);
        }
        let ck = nostr_bbs_core::nip44::conversation_key(key.secret(), &hex32(author)?).ok()?;
        self.conv.insert(slot, Zeroizing::new(ck));
        Some(ck)
    }

    fn open(&mut self, ev: &NostrEvent) -> Opened {
        let Some((zone, epoch, pk)) = zk(ev) else {
            return Opened::Foreign;
        };
        if zone != self.zone {
            return Opened::Foreign;
        }
        let Some(key) = self.key(epoch, &pk) else {
            return Opened::MissingKey;
        };
        let Some(mut ck) = self.conversation(key, &ev.pubkey) else {
            return Opened::Undecryptable;
        };
        let out = if parse_sealed(&ev.tags).is_some() {
            match hex32(&ev.pubkey).map(|a| open_sealed_with_conversation_key(ev, &a, &ck)) {
                Some(Ok(inner)) => Opened::Post(
                    inner.id.to_ascii_lowercase(),
                    inner.pubkey.to_ascii_lowercase(),
                    Zeroizing::new(inner.content.clone()),
                    edit_target(&inner),
                ),
                _ => Opened::Undecryptable,
            }
        } else {
            match nostr_bbs_core::nip44::decrypt_with_conversation_key(&ck, &ev.content) {
                Ok(text) => Opened::Post(
                    ev.id.to_ascii_lowercase(),
                    ev.pubkey.to_ascii_lowercase(),
                    Zeroizing::new(text),
                    edit_target(ev),
                ),
                Err(_) => Opened::Undecryptable,
            }
        };
        zeroize::Zeroize::zeroize(&mut ck);
        out
    }
}

/// The author of an indexed post `id`, read back from the relay (by `ids`
/// for a live post, by `#sealed` for an original), or `None` when the relay
/// no longer serves it.
async fn author_of<R: Relay>(
    relay: &mut R,
    opener: &mut Opener<'_>,
    id: &str,
) -> Result<Option<String>, RelayError> {
    let found = fetch_by_ids(relay, &[id.to_string()]).await?;
    if let Some(ev) = found.get(id) {
        if verify_event_strict(ev).is_ok() && parse_sealed(&ev.tags).is_none() {
            return Ok(Some(ev.pubkey.to_ascii_lowercase()));
        }
    }
    let envs = relay
        .query(&Filter {
            kinds: Some(vec![42]),
            sealed_tags: Some(vec![id.to_string()]),
            limit: Some(4),
            ..Filter::default()
        })
        .await?;
    for env in envs {
        if verify_event_strict(&env).is_err() {
            continue;
        }
        if let Opened::Post(inner_id, author, _, _) = opener.open(&env) {
            if inner_id == id {
                return Ok(Some(author));
            }
        }
    }
    Ok(None)
}

/// Which of `ids` (row ids: live post ids or original ids) the relay still
/// serves. Live posts are asked for by `ids`, originals by `#sealed`, each
/// in batches the relay accepts.
///
/// # Errors
///
/// [`HarvestError::Unauthenticated`] when the session is not authenticated
/// (an anonymous read would report every zone post missing).
pub async fn present<R: Relay>(
    relay: &mut R,
    ids: &[String],
) -> Result<HashSet<String>, HarvestError> {
    if !relay.session_authenticated() {
        return Err(HarvestError::Unauthenticated);
    }
    let mut out = HashSet::new();
    for ev in fetch_by_ids(relay, ids).await?.into_values() {
        out.insert(ev.id.to_ascii_lowercase());
    }
    let rest: Vec<String> = ids.iter().filter(|i| !out.contains(*i)).cloned().collect();
    for chunk in rest.chunks(MAX_IDS_PER_REQ) {
        let envs = relay
            .query(&Filter {
                kinds: Some(vec![42]),
                sealed_tags: Some(chunk.to_vec()),
                limit: Some(chunk.len() as u32 * 2),
                ..Filter::default()
            })
            .await?;
        for env in envs {
            if let Some(r) = parse_sealed(&env.tags) {
                if chunk.contains(&r.inner_id) {
                    out.insert(r.inner_id);
                }
            }
        }
    }
    Ok(out)
}

/// Read `zone`'s posts created at or after `since` (all when `None`) and the
/// kind-5 deletions of that window, and turn them into rows. `indexed` holds
/// the row ids already in the index (deduplication, and the targets a
/// deletion or edit may exclude).
///
/// # Errors
///
/// [`HarvestError::Unauthenticated`] unless the relay session is NIP-42
/// authenticated; relay failures.
pub async fn harvest<R: Relay>(
    relay: &mut R,
    zone: &str,
    ring: &KeyRing,
    since: Option<u64>,
    indexed: &HashSet<String>,
) -> Result<Harvest, HarvestError> {
    if !relay.session_authenticated() {
        return Err(HarvestError::Unauthenticated);
    }
    let posts = fetch_all(
        relay,
        &Filter {
            kinds: Some(vec![42]),
            zk_tags: Some(vec![zone.to_string()]),
            since,
            ..Filter::default()
        },
    )
    .await?
    .events;
    let dels = fetch_all(
        relay,
        &Filter {
            kinds: Some(vec![5]),
            since,
            ..Filter::default()
        },
    )
    .await?
    .events;
    let mut h = Harvest {
        events: posts.len(),
        deletions: dels.len(),
        ..Harvest::default()
    };
    let mut opener = Opener {
        zone,
        ring,
        conv: HashMap::new(),
    };
    let mut recs: HashMap<String, Rec> = HashMap::new();
    let mut env_to_inner: HashMap<String, String> = HashMap::new();
    for ev in &posts {
        h.newest = Some(h.newest.unwrap_or(0).max(ev.created_at));
        if verify_event_strict(ev).is_err() {
            h.invalid += 1;
            continue;
        }
        match opener.open(ev) {
            Opened::Post(id, author, text, edit_of) => {
                if id != ev.id.to_ascii_lowercase() {
                    env_to_inner.insert(ev.id.to_ascii_lowercase(), id.clone());
                }
                let (_, epoch, zone_pk) = zk(ev).expect("opened events carry a zk tag");
                recs.entry(id).or_insert(Rec {
                    author,
                    created_at: ev.created_at,
                    epoch,
                    zone_pk,
                    text,
                    edit_of,
                });
            }
            Opened::MissingKey => {
                h.missing_key += 1;
                if let Some((_, e, _)) = zk(ev) {
                    h.missing_epochs.insert(e);
                }
                h.hold_back = Some(h.hold_back.unwrap_or(u64::MAX).min(ev.created_at));
            }
            Opened::Foreign => h.foreign += 1,
            Opened::Undecryptable => h.undecryptable += 1,
        }
    }

    // Deletions: every `e` target of a stored kind-5, mapped to a row id.
    let mut deleted: HashSet<String> = HashSet::new();
    let mut unknown: Vec<String> = Vec::new();
    for d in &dels {
        h.newest = Some(h.newest.unwrap_or(0).max(d.created_at));
        if verify_event_strict(d).is_err() {
            continue;
        }
        for t in d
            .tags
            .iter()
            .filter(|t| t.len() >= 2 && t[0] == "e" && is_hex64(&t[1]))
        {
            let t = t[1].to_ascii_lowercase();
            if let Some(inner) = env_to_inner.get(&t) {
                deleted.insert(inner.clone());
            } else if recs.contains_key(&t) || indexed.contains(&t) {
                deleted.insert(t);
            } else {
                unknown.push(t);
            }
        }
    }
    // A target may be the envelope of an indexed original read in an earlier
    // run: ask the relay what it is.
    unknown.sort();
    unknown.dedup();
    if !unknown.is_empty() {
        for ev in fetch_by_ids(relay, &unknown).await?.into_values() {
            if let Some(r) = parse_sealed(&ev.tags) {
                if indexed.contains(&r.inner_id) {
                    deleted.insert(r.inner_id);
                }
            }
        }
    }

    // Edits: the target is superseded when the edit's author wrote it.
    let mut superseded: HashSet<String> = HashSet::new();
    let edits: Vec<(String, String)> = recs
        .values()
        .filter_map(|r| r.edit_of.clone().map(|t| (t, r.author.clone())))
        .collect();
    for (target, editor) in edits {
        let author = if let Some(r) = recs.get(&target) {
            Some(r.author.clone())
        } else if indexed.contains(&target) {
            match author_of(relay, &mut opener, &target).await? {
                Some(a) => Some(a),
                // Gone from the relay: nothing left to show; exclude it.
                None => Some(editor.clone()),
            }
        } else {
            None
        };
        if author.as_deref() == Some(editor.as_str()) {
            superseded.insert(target);
        }
    }

    let mut rows: Vec<ZoneRow> = Vec::new();
    for (id, r) in recs {
        if deleted.contains(&id) {
            h.deleted += 1;
        } else if superseded.contains(&id) {
            h.superseded += 1;
        } else if indexed.contains(&id) {
            h.already_indexed += 1;
        } else if r.text.trim().is_empty() {
            h.empty += 1;
        } else {
            rows.push(ZoneRow {
                id,
                text: r.text,
                epoch: r.epoch,
                zone_pk: r.zone_pk,
                created_at: r.created_at,
            });
        }
    }
    rows.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    h.rows = rows;
    h.exclude = deleted
        .union(&superseded)
        .filter(|id| indexed.contains(*id))
        .cloned()
        .collect();
    Ok(h)
}
