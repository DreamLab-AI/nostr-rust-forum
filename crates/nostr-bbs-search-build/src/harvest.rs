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
//! - **deleted**: named by a verified kind-5 whose signer wrote the post (for
//!   an imported post, the original's author) or is a configured moderator
//!   ([`Rules::moderators`]). The relay is not trusted to have gated it. A
//!   target may be a live post's id, an envelope's id, or an original's
//!   (inner) id; all three map to the row. The author comes from the post
//!   itself when read this run, else from the job's [`AuthorBook`] (what it
//!   saw when it opened the post earlier), else from the relay; a target whose
//!   author none of them establishes is skipped. (Deletes through the admin HTTP
//!   API leave no kind-5: the relay stops serving the post, so no member sees
//!   it, but its row stays until positive evidence arrives.)
//! - **superseded**: the target of an edit, a kind-42 tagged
//!   `["e", <target>, "", "edit"]` by the target's own author (for an
//!   envelope, the original's author). Chains resolve edge by edge: each
//!   edit supersedes the post it names. A target the relay does not return
//!   this run is skipped.
//!
//! Only verified events of this zone move the high-water mark, never past
//! [`Rules::now`] (stricter than the relay's own bound of now +
//! `MAX_CREATED_AT_DRIFT_SECS`, so a post dated ahead is read again every run
//! until the clock passes it); a second the relay cannot page completely
//! ([`Harvest::ambiguous_seconds`]) holds the mark below it.
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
    fetch_all, fetch_by_ids, Filter, Relay, RelayError, MAX_IDS_PER_REQ, MAX_REQ_LIMIT,
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

/// What a harvest may trust beyond the events themselves.
#[derive(Debug, Clone, Copy)]
pub struct Rules<'a> {
    /// Current Unix time: no high-water mark is set beyond
    /// `now + MAX_CREATED_AT_DRIFT_SECS`.
    pub now: u64,
    /// Hex pubkeys whose kind-5 deletes any post (admins and moderators, from
    /// the job's configuration). Anyone else deletes only their own posts.
    pub moderators: &'a [String],
}

/// How long a second the relay cannot page completely may hold the
/// high-water mark (3 days); after that it is released with a warning.
pub const AMBIGUOUS_HOLD_SECS: u64 = 3 * 86_400;

/// What the job has seen of posts it opened: each row id's author and each
/// envelope id's original id. It holds no text: the relay already serves the
/// same facts (the event's `pubkey`, the envelope's `sealed` tag). It lets a
/// deletion's authority be checked after the relay has removed the post
/// (which it does at once for an author's own kind-5).
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorBook {
    /// Row id → author pubkey (an original's author for an imported post).
    pub authors: HashMap<String, String>,
    /// Envelope id → original (row) id.
    pub envelopes: HashMap<String, String>,
    /// Whether the book was built from the zone's events (`seed-book`, or a
    /// full build from the relay), so it covers an existing base.
    #[serde(default)]
    pub seeded: bool,
}

/// What [`seed_book`] read.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SeedReport {
    /// Kind-42 events of the zone read.
    pub events: usize,
    /// Posts whose author was recorded.
    pub recorded: usize,
    /// Events that did not verify or open.
    pub skipped: usize,
}

impl AuthorBook {
    /// Read `path`, or an empty book when it does not exist.
    ///
    /// # Errors
    ///
    /// When the file exists but cannot be read or parsed.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| format!("author book {} is malformed: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("author book {}: {e}", path.display())),
        }
    }

    /// Keep only entries for rows in `keep` (the index's row ids): the book
    /// stays the size of the index.
    pub fn retain_rows(&mut self, keep: &HashSet<String>) {
        self.authors.retain(|id, _| keep.contains(id));
        self.envelopes.retain(|_, row| keep.contains(row));
    }

    /// Forget `rows` (dropped from the index by a compaction).
    pub fn forget(&mut self, rows: &HashSet<String>) {
        self.authors.retain(|id, _| !rows.contains(id));
        self.envelopes.retain(|_, row| !rows.contains(row));
    }

    /// Write the book to `path` (mode 0600, through a fresh temporary file).
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        let json = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
        crate::secrets::write_owner_only(&tmp, &json)?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
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
    /// `created_at` seconds holding more events than one relay page, which
    /// the relay's `until` paging cannot read completely, and which hold a
    /// verified event that matters here and are younger than
    /// [`AMBIGUOUS_HOLD_SECS`]: the mark stays below them.
    pub ambiguous_seconds: Vec<u64>,
    /// Findings for the report (no text, no keys).
    pub warnings: Vec<String>,
}

impl Harvest {
    /// The high-water mark this harvest supports: the newest verified event
    /// of the zone read (capped at the job's clock, and never below `prior`),
    /// unless an event was held back for want of a key, or a second could not
    /// be paged completely: then just below the oldest such, even if that is
    /// below `prior`, so the next run reads it again however old it is.
    pub fn high_water(&self, prior: Option<u64>) -> Option<u64> {
        let hold = [self.hold_back, self.ambiguous_seconds.first().copied()]
            .into_iter()
            .flatten()
            .min();
        if let Some(h) = hold {
            return Some(h.saturating_sub(1));
        }
        match (self.newest, prior) {
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

/// Build `book` from every post of `zone` the relay serves (or an export of
/// the zone's events holds): each verified post that opens records its row
/// id's author, and each envelope its original's id. Marks the book seeded.
///
/// # Errors
///
/// [`HarvestError::Unauthenticated`] unless the session is authenticated;
/// relay failures.
pub async fn seed_book<R: Relay>(
    relay: &mut R,
    zone: &str,
    ring: &KeyRing,
    book: &mut AuthorBook,
) -> Result<SeedReport, HarvestError> {
    if !relay.session_authenticated() {
        return Err(HarvestError::Unauthenticated);
    }
    let posts = fetch_all(
        relay,
        &Filter {
            kinds: Some(vec![42]),
            zk_tags: Some(vec![zone.to_string()]),
            ..Filter::default()
        },
    )
    .await?
    .events;
    let mut opener = Opener {
        zone,
        ring,
        conv: HashMap::new(),
    };
    let mut r = SeedReport {
        events: posts.len(),
        ..SeedReport::default()
    };
    for ev in &posts {
        if verify_event_strict(ev).is_err() {
            r.skipped += 1;
            continue;
        }
        match opener.open(ev) {
            Opened::Post(id, author, _, _) => {
                if id != ev.id.to_ascii_lowercase() {
                    book.envelopes
                        .insert(ev.id.to_ascii_lowercase(), id.clone());
                }
                book.authors.insert(id, author);
                r.recorded += 1;
            }
            _ => r.skipped += 1,
        }
    }
    book.seeded = true;
    Ok(r)
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
    rules: &Rules<'_>,
    book: &mut AuthorBook,
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
    .await?;
    let dels = fetch_all(
        relay,
        &Filter {
            kinds: Some(vec![5]),
            since,
            ..Filter::default()
        },
    )
    .await?;
    // Seconds the relay could not page; only those holding a verified event
    // that matters here (a post of this zone, or a kind-5 naming one) will
    // hold the mark, so nobody can pin it with junk or unrelated deletions.
    // Each query's own unpaged seconds count only with a relevant event of
    // that query at that second.
    let post_ambiguous = posts.ambiguous_seconds.clone();
    let del_ambiguous = dels.ambiguous_seconds.clone();
    let mut relevant_secs: HashSet<u64> = HashSet::new();
    let mut relevant_del_secs: HashSet<u64> = HashSet::new();
    let (posts, dels) = (posts.events, dels.events);
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
    // Only a verified event of this zone moves the mark, and never past the
    // job's clock: a relay cannot push it beyond the posts it still owes.
    let seen = |h: &mut Harvest, at: u64| {
        h.newest = Some(h.newest.unwrap_or(0).max(at.min(rules.now)));
    };
    let mut recs: HashMap<String, Rec> = HashMap::new();
    let mut env_to_inner: HashMap<String, String> = HashMap::new();
    for ev in &posts {
        if verify_event_strict(ev).is_err() {
            h.invalid += 1;
            continue;
        }
        match opener.open(ev) {
            Opened::Post(id, author, text, edit_of) => {
                seen(&mut h, ev.created_at);
                relevant_secs.insert(ev.created_at);
                if id != ev.id.to_ascii_lowercase() {
                    env_to_inner.insert(ev.id.to_ascii_lowercase(), id.clone());
                }
                let (_, epoch, zone_pk) = zk(ev).expect("opened events carry a zk tag");
                book.authors.insert(id.clone(), author.clone());
                if id != ev.id.to_ascii_lowercase() {
                    book.envelopes
                        .insert(ev.id.to_ascii_lowercase(), id.clone());
                }
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
                seen(&mut h, ev.created_at);
                relevant_secs.insert(ev.created_at);
                h.missing_key += 1;
                if let Some((_, e, _)) = zk(ev) {
                    h.missing_epochs.insert(e);
                }
                h.hold_back = Some(h.hold_back.unwrap_or(u64::MAX).min(ev.created_at));
            }
            Opened::Foreign => h.foreign += 1,
            Opened::Undecryptable => {
                seen(&mut h, ev.created_at);
                relevant_secs.insert(ev.created_at);
                h.undecryptable += 1;
            }
        }
    }

    // Deletions: a verified kind-5 deletes a row when its signer wrote the
    // post (the original's author for an imported post) or is a configured
    // moderator. The relay's own write gate is not relied on. A target whose
    // author cannot be established this run is skipped, never assumed.
    let mut deleted: HashSet<String> = HashSet::new();
    let mut authors: HashMap<String, Option<(String, String)>> = HashMap::new();
    // Targets neither read this run nor indexed may be envelopes of indexed
    // originals: one batched lookup for all of them.
    let mut unknown: Vec<String> = dels
        .iter()
        .flat_map(|d| d.tags.iter())
        .filter(|t| t.len() >= 2 && t[0] == "e" && is_hex64(&t[1]))
        .map(|t| t[1].to_ascii_lowercase())
        .filter(|t| {
            !env_to_inner.contains_key(t)
                && !recs.contains_key(t)
                && !indexed.contains(t)
                && !book.envelopes.contains_key(t)
        })
        .collect();
    unknown.sort();
    unknown.dedup();
    let envelopes = if unknown.is_empty() {
        HashMap::new()
    } else {
        fetch_by_ids(relay, &unknown).await?
    };
    for t in &unknown {
        let found = envelopes.get(t).and_then(|env| {
            if verify_event_strict(env).is_err() || parse_sealed(&env.tags).is_none() {
                return None;
            }
            match opener.open(env) {
                Opened::Post(inner, author, _, _) if indexed.contains(&inner) => {
                    Some((inner, author))
                }
                _ => None,
            }
        });
        authors.insert(t.clone(), found);
    }
    for d in &dels {
        if verify_event_strict(d).is_err() {
            continue;
        }
        let signer = d.pubkey.to_ascii_lowercase();
        let moderator = rules
            .moderators
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&signer));
        for t in d
            .tags
            .iter()
            .filter(|t| t.len() >= 2 && t[0] == "e" && is_hex64(&t[1]))
        {
            let t = t[1].to_ascii_lowercase();
            // A moderator's deletion needs no author: only the row it names
            // (the relay removes the post at once, often before any run saw
            // its author).
            if moderator {
                let row = env_to_inner
                    .get(&t)
                    .cloned()
                    .or_else(|| recs.contains_key(&t).then(|| t.clone()))
                    .or_else(|| {
                        book.envelopes
                            .get(&t)
                            .filter(|r| indexed.contains(*r))
                            .cloned()
                    })
                    .or_else(|| indexed.contains(&t).then(|| t.clone()))
                    .or_else(|| authors.get(&t).cloned().flatten().map(|(r, _)| r));
                if let Some(row) = row {
                    relevant_del_secs.insert(d.created_at);
                    deleted.insert(row);
                }
                continue;
            }
            // (row id, author) the target stands for.
            let target = if let Some(inner) = env_to_inner.get(&t) {
                recs.get(inner).map(|r| (inner.clone(), r.author.clone()))
            } else if let Some(r) = recs.get(&t) {
                Some((t.clone(), r.author.clone()))
            } else if let Some(row) = book.envelopes.get(&t).filter(|r| indexed.contains(*r)) {
                book.authors.get(row).map(|a| (row.clone(), a.clone()))
            } else if let Some(a) = book.authors.get(&t).filter(|_| indexed.contains(&t)) {
                Some((t.clone(), a.clone()))
            } else {
                if !authors.contains_key(&t) {
                    // An indexed post named by its own id.
                    let found = author_of(relay, &mut opener, &t)
                        .await?
                        .map(|a| (t.clone(), a));
                    authors.insert(t.clone(), found);
                }
                authors.get(&t).cloned().flatten()
            };
            if let Some((row, author)) = target {
                relevant_del_secs.insert(d.created_at);
                if author == signer {
                    deleted.insert(row);
                }
            }
        }
    }

    // Edits: the target is superseded when the edit's author wrote it. A
    // target the relay does not return this run is skipped.
    let mut superseded: HashSet<String> = HashSet::new();
    let edits: Vec<(String, String)> = recs
        .values()
        .filter_map(|r| r.edit_of.clone().map(|t| (t, r.author.clone())))
        .collect();
    for (target, editor) in edits {
        let author = if let Some(r) = recs.get(&target) {
            Some(r.author.clone())
        } else if let Some(a) = book
            .authors
            .get(&target)
            .filter(|_| indexed.contains(&target))
        {
            Some(a.clone())
        } else if indexed.contains(&target) {
            author_of(relay, &mut opener, &target).await?
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
    // Ambiguous seconds that matter hold the mark, but not for ever: past
    // the hold period they are released with a warning (events at that
    // second may never be read: the relay pages only by whole seconds).
    let mut relevant_ambiguous: Vec<u64> = post_ambiguous
        .into_iter()
        .filter(|s| relevant_secs.contains(s))
        .chain(
            del_ambiguous
                .into_iter()
                .filter(|s| relevant_del_secs.contains(s)),
        )
        .collect();
    relevant_ambiguous.sort_unstable();
    relevant_ambiguous.dedup();
    for sec in relevant_ambiguous {
        if sec.saturating_add(AMBIGUOUS_HOLD_SECS) < rules.now {
            h.warnings.push(format!(
                "events at created_at {sec} could not be read completely (more than {MAX_REQ_LIMIT} at one second); released after {} days, some may never be indexed",
                AMBIGUOUS_HOLD_SECS / 86_400
            ));
        } else {
            h.ambiguous_seconds.push(sec);
        }
    }
    h.exclude = deleted
        .union(&superseded)
        .filter(|id| indexed.contains(*id))
        .cloned()
        .collect();
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_high_water_mark_stays_below_held_back_posts() {
        let h = Harvest {
            newest: Some(500),
            ..Harvest::default()
        };
        assert_eq!(h.high_water(None), Some(500));
        assert_eq!(
            h.high_water(Some(700)),
            Some(700),
            "never moves back otherwise"
        );
        let held = Harvest {
            newest: Some(500),
            hold_back: Some(300),
            ..Harvest::default()
        };
        assert_eq!(held.high_water(None), Some(299));
        assert_eq!(
            held.high_water(Some(700)),
            Some(299),
            "an old held post is read again"
        );
        assert_eq!(Harvest::default().high_water(Some(9)), Some(9));
    }
}
