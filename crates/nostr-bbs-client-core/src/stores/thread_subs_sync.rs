//! The cross-device copy of a member's thread subscriptions.
//!
//! One NIP-78 application-data event per member: kind 30078, addressable by
//! its `d` tag, whose **only** tag is `["d", "nostr-bbs/thread-subs/v1"]`.
//! There are no `e`, `a` or `p` tags, ever: they would publish which topics
//! the member follows. Everything else is compact JSON
//! (`{"subs":[{r,c,z,on,at,rd}]}`, the same shape as the local copy, read
//! marker inline, no titles) inside NIP-44 content encrypted by the member to
//! their own key through the auth store's [`Signer`] — the precedent is the
//! zone inbox-key backup (`zone_crypto::inbox_key::build_backup`). No other
//! envelope, no hand-rolled cryptography.
//!
//! ## Who can see what
//!
//! - **Anyone** who asks the relay (kind 30078 is not read-gated) can see the
//!   copy's author, its `d` tag, when it last changed and roughly how large it
//!   is — not which topics it lists.
//! - **The relay operator** can see more: the client's own reads name the
//!   followed topics. The unread backlog asks `#e:[root]` with `since` at the
//!   topic's read marker, and title fetches ask for roots by id, on the
//!   member's authenticated connection. So the operator can learn, from its
//!   logs, which topics a member follows and roughly how far they have read.
//!   Third parties cannot: those REQs travel over the member's TLS
//!   connection and are not stored as events.
//!
//! ## Rules
//!
//! The publish decision is one pure function (`plan`, unit-tested).
//!
//! - Fetch, then merge entry by entry
//!   ([`Subs::join`](crate::stores::thread_subs)), before every publish: a
//!   replaceable event is last-writer-wins for the whole list. A fetch older
//!   than [`FRESH_FETCH_MS`] when the copy is about to go out (a NIP-07
//!   prompt can take minutes) is repeated, and the copy re-merged and
//!   re-sealed if the relay's copy changed meanwhile.
//! - Never publish before this session's first fetch succeeded (a timeout is
//!   a failure, an empty answer is not), nor over a copy that cannot be
//!   decrypted or read: that would wipe what another device wrote.
//! - A subscribe or unsubscribe goes out within seconds
//!   ([`MEMBERSHIP_PUBLISH_INTERVAL_MS`]); read markers alone at most every
//!   [`MARKER_PUBLISH_INTERVAL_MS`], or when the page is hidden
//!   (`visibilitychange`) for a local-key signer — publishing each read
//!   would show anyone polling the copy when the member reads. Attempts are
//!   rate-limited on the last attempt (failures back off up to 30 minutes); sign-out
//!   gets one bounded publish (local-key and passkey sessions; it writes
//!   nothing to storage). A declined signature stops prompts for the session
//!   until the member subscribes or unsubscribes again. Signer calls are
//!   abandoned after two minutes. On `pagehide` the
//!   copy is published only if the last fetch is under
//!   [`PAGEHIDE_FRESH_MS`] old (normally the hide just before it), so it never
//!   overwrites a copy it has not seen.
//! - With a NIP-07 extension signer every publish costs prompts, so only
//!   subscribing and unsubscribing schedule one; read markers ride along with
//!   the next such publish, or go alone at most once per
//!   [`EXTENSION_MARKER_INTERVAL_MS`].
//! - The last relay copy seen (id, `created_at` and digests) is kept with the
//!   local copy, so an unchanged relay copy is never decrypted again, and
//!   other tabs see that nothing is pending. One tab publishes at a time: a
//!   lock in localStorage outlasting a signer call, taken again before the
//!   publish; another tab waits for its expiry or for the holder's write.
//! - Without NIP-44 (a NIP-07 extension lacking `nip44`), or on any error, the
//!   feature stays local-only ([`SyncStatus::LocalOnly`]); the local list
//!   keeps working.
//! - The plaintext is held to [`MAX_PLAINTEXT_BYTES`] so the encrypted content
//!   stays under the relay's 64 KiB content cap; the oldest tombstones are
//!   left out first, a followed topic never. The decision compares digests of
//!   that bounded encoding, so a list trimmed to fit does not look changed
//!   and is not republished every session.
//!
//! ## Device keys (ADR-099, `DEVICE_KEYS_ENABLED`)
//!
//! A device-key session holds only the device's derived key, and the client
//! cannot tell it from any other local key, so the copy is authored by, and
//! encrypted to, the device key. Reading it back always works (kind 30078 is
//! not read-gated). Whether the relay accepts the publish follows its write
//! gate, which checks the *effective* principal
//! (`relay_do/nip_handlers.rs`, `effective_principal`): with the gate on and
//! the device registered and not revoked, the owner is checked and the copy is
//! stored (under the device pubkey); with the gate off, or the device revoked,
//! the device pubkey itself is checked, so unless it is separately allowed the
//! relay refuses, and the feature stays local-only
//! ([`LocalOnlyReason::RelayError`], retried after the next change or
//! reconnect). Either way the copy is private to that device key and does not
//! follow the member's identity to their other devices. Nothing leaks.

use std::cell::RefCell;
use std::rc::Rc;

use nostr_bbs_core::signer::Signer;
use nostr_bbs_core::{verify_event_strict, NostrEvent, UnsignedEvent};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::relay::{Filter, OneShot, RelayConnection};
use crate::stores::thread_subs::{Subs, SubsDoc};

pub use crate::zone_crypto::inbox_key::KIND_APP_DATA;

/// The `d` tag of the subscriptions copy, and its only tag.
pub const THREAD_SUBS_D_TAG: &str = "nostr-bbs/thread-subs/v1";

/// The relay's content cap (`relay_do/nip_handlers.rs`, `MAX_CONTENT_SIZE`).
pub const RELAY_CONTENT_CAP: usize = 64 * 1024;

/// The largest plaintext sent: NIP-44 v2 pads it to 40,960 bytes, which
/// base64-encodes (with version, nonce, length prefix and MAC) to 54,704
/// bytes, under [`RELAY_CONTENT_CAP`]. The next padding step (49,152) would
/// not fit.
pub const MAX_PLAINTEXT_BYTES: usize = 40_960;

/// How long a fetch or a publish waits for the relay, milliseconds.
const RELAY_WAIT_MS: u32 = 10_000;

/// State of the cross-device copy, for a view to show if it wishes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SyncStatus {
    /// Not started: signed out, or waiting for the relay session.
    #[default]
    Idle,
    /// Fetching, merging or publishing.
    Syncing,
    /// The relay copy holds everything this device has, as of the last
    /// exchange.
    Synced,
    /// Kept on this device only, for the reason given. The local list works
    /// as before.
    LocalOnly(LocalOnlyReason),
}

/// Why the cross-device copy is not in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalOnlyReason {
    /// No signer for the signed-in account (yet).
    NoSigner,
    /// The signer cannot encrypt to itself: a NIP-07 extension without
    /// `nip44`. Lasts the session.
    NoNip44,
    /// A relay copy exists that this signer cannot decrypt or read; it is
    /// left alone rather than overwritten. Lasts the session.
    Unreadable,
    /// The list is too large to publish (only when more than
    /// [`MAX_ACTIVE_SUBSCRIPTIONS`](crate::stores::thread_subs::MAX_ACTIVE_SUBSCRIPTIONS)
    /// topics were merged from several devices). Retried after the next
    /// change.
    TooLarge,
    /// The relay did not answer, refused, or the connection dropped (or a
    /// signer call took longer than two minutes). Retried with backoff.
    RelayError,
    /// The signer refused to encrypt or sign (a declined NIP-07 prompt).
    /// No more prompts this session until the member subscribes or
    /// unsubscribes again, or reloads.
    SignerRefused,
}

impl LocalOnlyReason {
    /// Whether this ends syncing for the rest of the session.
    pub(crate) fn ends_session(self) -> bool {
        matches!(
            self,
            LocalOnlyReason::NoNip44 | LocalOnlyReason::Unreadable | LocalOnlyReason::SignerRefused
        )
    }
}

/// Pause after `failures` failed attempts in a row before the next one,
/// milliseconds: one minute, doubling, at most 30 minutes.
pub(crate) fn failure_backoff_ms(failures: u32) -> u64 {
    if failures == 0 {
        return 0;
    }
    (PUBLISH_INTERVAL_MS << (failures - 1).min(16)).min(EXTENSION_MARKER_INTERVAL_MS)
}

/// At most one scheduled publish per this many milliseconds.
pub const PUBLISH_INTERVAL_MS: u64 = 60_000;
// (Now the first step of the failure backoff; see `failure_backoff_ms`.)

/// A copy whose only change is read markers is published at most once per
/// this many milliseconds (30 minutes) by a scheduled publish, for every
/// signer; a local-key signer also publishes them when the page is hidden.
pub const MARKER_PUBLISH_INTERVAL_MS: u64 = 30 * 60_000;

/// The same interval under its earlier name (extension signers had it
/// first).
pub const EXTENSION_MARKER_INTERVAL_MS: u64 = MARKER_PUBLISH_INTERVAL_MS;

/// A subscribe or unsubscribe is published at most once per this many
/// milliseconds (after a short settle), so it is rarely still pending at
/// sign-out.
pub const MEMBERSHIP_PUBLISH_INTERVAL_MS: u64 = 5_000;

/// A fetch older than this when the copy is about to be published is
/// repeated first, milliseconds.
pub const FRESH_FETCH_MS: u64 = 5_000;

/// On `pagehide` (no time to fetch) the copy is published only if the last
/// fetch is younger than this, milliseconds.
pub const PAGEHIDE_FRESH_MS: u64 = 10_000;

/// The newest relay copy this browser has merged or published: its event id
/// and `created_at`, and the digests of its contents (as [`digests`]
/// computes them). Kept with the local copy, never published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RemoteSeen {
    pub id: String,
    pub created_at: u64,
    pub digest: String,
    pub entries_digest: String,
}

impl RemoteSeen {
    /// The newer of two records, for merging what two tabs stored: the later
    /// `created_at`, and in the same second the **lower** id (the copy the
    /// relay keeps, NIP-01).
    pub fn newer(a: Option<RemoteSeen>, b: Option<RemoteSeen>) -> Option<RemoteSeen> {
        match (a, b) {
            (Some(a), Some(b)) => {
                if b.created_at > a.created_at || (b.created_at == a.created_at && b.id < a.id) {
                    Some(b)
                } else {
                    Some(a)
                }
            }
            (a, b) => a.or(b),
        }
    }
}

/// SHA-256 digests (hex) of a list as it would be published: `full` over the
/// bounded encoding, `entries` over the same trimmed list without read
/// markers. Used only
/// to tell whether two lists differ; not a security measure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Digests {
    pub full: String,
    pub entries: String,
}

/// The [`Digests`] of `subs`; [`LocalOnlyReason::TooLarge`] when it cannot be
/// published at all.
pub(crate) fn digests(subs: &Subs) -> Result<Digests, LocalOnlyReason> {
    let hash = |s: &str| hex::encode(Sha256::digest(s.as_bytes()));
    let (trimmed, json) = bounded(subs)?;
    let membership = serde_json::to_string(&trimmed.membership().to_doc())
        .map_err(|_| LocalOnlyReason::TooLarge)?;
    Ok(Digests {
        full: hash(&json),
        entries: hash(&membership),
    })
}

/// Whether relay copy `latest` differs from the one last seen (`known`):
/// any other event id counts, whatever its `created_at` (in the same second
/// the relay keeps the lower id, so "newer" cannot be judged by time alone,
/// and merging an older copy is harmless).
pub(crate) fn remote_changed(known: Option<&RemoteSeen>, latest: &NostrEvent) -> bool {
    known.is_none_or(|k| k.id != latest.id)
}

/// What asked for a publish decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Trigger {
    /// A timer after a local change, or a sync after AUTH.
    Scheduled,
    /// The page was hidden (`visibilitychange`): it can still wait.
    Hidden,
    /// The page is going (`pagehide`): it cannot wait for anything.
    PageHide,
    /// The member is signing out: last chance, bounded by the caller.
    SignOut,
}

/// Inputs of [`plan`].
#[derive(Clone, Debug)]
pub(crate) struct PlanInput<'a> {
    /// This session's first fetch of the relay copy succeeded.
    pub fetched: bool,
    /// Local-only for the session (unreadable relay copy, no NIP-44).
    pub disabled: bool,
    /// The local list's digests; `None` when it is too large to publish.
    pub local: Option<&'a Digests>,
    /// The local list has no entries at all.
    pub local_empty: bool,
    /// The newest relay copy merged or published.
    pub remote: Option<&'a RemoteSeen>,
    /// The signer is a NIP-07 extension (every publish prompts).
    pub extension: bool,
    pub trigger: Trigger,
    pub now_ms: u64,
    /// When the relay copy was last fetched, if this session has.
    pub last_fetch_ms: Option<u64>,
    /// When this browser last published, 0 if never.
    pub published_ms: u64,
    /// After failed attempts: nothing before this time (milliseconds).
    pub not_before_ms: u64,
}

/// The publish decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Not allowed: no successful fetch yet this session, or local-only.
    Blocked,
    /// Nothing the relay copy lacks (or nothing worth a prompt now).
    Nothing,
    /// The list cannot be published at any size.
    TooLarge,
    /// Publish, but not before this time (milliseconds).
    Wait { until_ms: u64 },
    /// Publish after fetching again: the last fetch is too old.
    Refetch,
    /// Publish now: the last fetch is fresh.
    Publish,
}

/// Decide whether to publish the local list (see the module rules).
pub(crate) fn plan(p: &PlanInput<'_>) -> Plan {
    if p.disabled || !p.fetched {
        return Plan::Blocked;
    }
    let Some(local) = p.local else {
        return Plan::TooLarge;
    };
    let (full_differs, entries_differ) = match p.remote {
        None if p.local_empty => return Plan::Nothing,
        None => (true, true),
        Some(r) => (r.digest != local.full, r.entries_digest != local.entries),
    };
    if !full_differs {
        return Plan::Nothing;
    }
    let markers_only = !entries_differ;
    if p.trigger == Trigger::PageHide && p.extension {
        // An extension cannot answer while the page unloads.
        return Plan::Nothing;
    }
    // A subscribe or unsubscribe goes out within seconds, so little is ever
    // pending at sign-out (whose last publish often cannot finish before the
    // socket closes). Read markers alone are lazy for every signer: at most
    // every 30 minutes, or when the page is hidden (a local-key signer) —
    // publishing each read would let anyone polling the copy's author and
    // `d` tag see when the member reads.
    let interval = if markers_only {
        MARKER_PUBLISH_INTERVAL_MS
    } else {
        MEMBERSHIP_PUBLISH_INTERVAL_MS
    };
    let earliest = p.published_ms.saturating_add(interval).max(p.not_before_ms);
    match p.trigger {
        Trigger::Scheduled if p.now_ms < earliest => {
            return Plan::Wait { until_ms: earliest };
        }
        // After a failure, hiding the page does not retry early either.
        Trigger::Hidden | Trigger::PageHide if p.now_ms < p.not_before_ms => {
            return Plan::Nothing;
        }
        // Markers alone on hide: a local-key signer publishes them (no
        // prompt); an extension waits for their interval.
        Trigger::Hidden | Trigger::PageHide
            if markers_only && p.extension && p.now_ms < earliest =>
        {
            return Plan::Nothing;
        }
        _ => {}
    }
    let age = p.last_fetch_ms.map(|t| p.now_ms.saturating_sub(t));
    match p.trigger {
        Trigger::PageHide => match age {
            Some(a) if a <= PAGEHIDE_FRESH_MS => Plan::Publish,
            _ => Plan::Nothing,
        },
        _ => match age {
            Some(a) if a <= FRESH_FETCH_MS => Plan::Publish,
            _ => Plan::Refetch,
        },
    }
}

/// NIP-44 v2 padded plaintext length for an `n`-byte plaintext.
pub(crate) fn nip44_padded_len(n: usize) -> usize {
    if n <= 32 {
        return 32;
    }
    let next_power = 1usize << (usize::BITS - (n - 1).leading_zeros());
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * ((n - 1) / chunk + 1)
}

/// Length of the base64 NIP-44 v2 payload for an `n`-byte plaintext:
/// version (1) + nonce (32) + length prefix (2) + padded plaintext + MAC (32).
pub(crate) fn nip44_payload_len(n: usize) -> usize {
    let raw = 1 + 32 + 2 + nip44_padded_len(n) + 32;
    4 * raw.div_ceil(3)
}

/// The compact JSON published for `subs`, within [`MAX_PLAINTEXT_BYTES`].
///
/// Read markers of topics not followed are left out. When the whole list
/// does not fit, the oldest tombstones are left out until it does; if the
/// followed topics alone do not fit, nothing is published.
pub(crate) fn encode_bounded(subs: &Subs) -> Result<String, LocalOnlyReason> {
    bounded(subs).map(|(_, json)| json)
}

/// [`encode_bounded`], also returning the list as trimmed, so other
/// measures (the membership digest) can be taken over exactly what is
/// published.
pub(crate) fn bounded(subs: &Subs) -> Result<(Subs, String), LocalOnlyReason> {
    let mut out = subs.clone();
    let entries = &out.entries;
    out.read.retain(|r, _| entries.get(r).is_some_and(|e| e.on));
    let encode =
        |s: &Subs| serde_json::to_string(&s.to_doc()).map_err(|_| LocalOnlyReason::TooLarge);
    let json = encode(&out)?;
    if json.len() <= MAX_PLAINTEXT_BYTES {
        return Ok((out, json));
    }
    let mut tombs: Vec<(u64, String)> = out
        .entries
        .values()
        .filter(|e| !e.on)
        .map(|e| (e.at, e.r.clone()))
        .collect();
    tombs.sort();
    let mut tombs = tombs.into_iter();
    // Drop by estimate first (each entry's own JSON plus its comma), then
    // check the real length, one more at a time.
    let mut excess = json.len() - MAX_PLAINTEXT_BYTES;
    for (_, root) in tombs.by_ref() {
        if let Some(e) = out.entries.remove(&root) {
            let len = serde_json::to_string(&e).map_or(0, |s| s.len() + 1);
            excess = excess.saturating_sub(len);
        }
        if excess == 0 {
            break;
        }
    }
    loop {
        let json = encode(&out)?;
        if json.len() <= MAX_PLAINTEXT_BYTES {
            return Ok((out, json));
        }
        match tombs.next() {
            Some((_, root)) => {
                out.entries.remove(&root);
            }
            None => return Err(LocalOnlyReason::TooLarge),
        }
    }
}

/// Parse a decrypted copy, markers clamped to `now_secs`; `None` when it is
/// not the expected JSON.
pub(crate) fn decode(plain: &str, now_secs: u64) -> Option<Subs> {
    serde_json::from_str::<SubsDoc>(plain)
        .ok()
        .map(|d| Subs::from_doc(d, now_secs))
}

/// The unsigned event: kind 30078, the `d` tag and nothing else.
pub(crate) fn unsigned_event(owner: &str, content: String, created_at: u64) -> UnsignedEvent {
    UnsignedEvent {
        pubkey: owner.to_string(),
        created_at,
        kind: KIND_APP_DATA,
        tags: vec![vec!["d".to_string(), THREAD_SUBS_D_TAG.to_string()]],
        content,
    }
}

/// The current copy among `events`: kind 30078, authored by `owner`, exactly
/// the subscriptions `d` tag, id and signature verified; the newest, and at
/// equal `created_at` the lowest id (NIP-01's rule for replaceable events).
pub(crate) fn pick_latest<'a>(events: &'a [NostrEvent], owner: &str) -> Option<&'a NostrEvent> {
    events
        .iter()
        .filter(|e| {
            e.kind == KIND_APP_DATA
                && e.pubkey.eq_ignore_ascii_case(owner)
                && e.tags
                    .iter()
                    .any(|t| t.len() >= 2 && t[0] == "d" && t[1] == THREAD_SUBS_D_TAG)
                && verify_event_strict(e).is_ok()
        })
        .max_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| b.id.cmp(&a.id))
        })
}

/// Encrypt `subs` to the signer's own key and sign the copy.
pub(crate) async fn seal(
    signer: &dyn Signer,
    subs: &Subs,
    created_at: u64,
) -> Result<NostrEvent, LocalOnlyReason> {
    let owner = signer.public_key().to_string();
    let plain = encode_bounded(subs)?;
    // Known before encrypting (so a NIP-07 signer is not asked for a copy
    // the relay would refuse); `encode_bounded` already guarantees it.
    if nip44_payload_len(plain.len()) > RELAY_CONTENT_CAP {
        return Err(LocalOnlyReason::TooLarge);
    }
    let content = signer
        .nip44_encrypt(&owner, &plain)
        .await
        .map_err(|_| LocalOnlyReason::SignerRefused)?;
    if content.len() > RELAY_CONTENT_CAP {
        return Err(LocalOnlyReason::TooLarge);
    }
    signer
        .sign_event(unsigned_event(&owner, content, created_at))
        .await
        .map_err(|_| LocalOnlyReason::SignerRefused)
}

/// Decrypt and read a copy with the signer's own key (markers clamped to
/// `now_secs`).
pub(crate) async fn open(
    signer: &dyn Signer,
    ev: &NostrEvent,
    now_secs: u64,
) -> Result<Subs, LocalOnlyReason> {
    let owner = signer.public_key().to_string();
    let plain = signer
        .nip44_decrypt(&owner, &ev.content)
        .await
        .map_err(|_| LocalOnlyReason::Unreadable)?;
    decode(&plain, now_secs).ok_or(LocalOnlyReason::Unreadable)
}

/// Ask the relay for `owner`'s current copy. `Ok(None)` when it answered with
/// none; an error when it did not answer in time or refused the REQ.
pub(crate) async fn fetch_latest(
    relay: &RelayConnection,
    owner: &str,
) -> Result<Option<NostrEvent>, LocalOnlyReason> {
    let slot: Rc<OneShot<Result<(), ()>>> = OneShot::new();
    let events: Rc<RefCell<Vec<NostrEvent>>> = Rc::default();
    let sink = events.clone();
    let answered = slot.clone();
    let refused = slot.clone();
    let sub = relay.subscribe_with_receipt_or_closed(
        vec![Filter {
            authors: Some(vec![owner.to_string()]),
            kinds: Some(vec![KIND_APP_DATA]),
            d_tags: Some(vec![THREAD_SUBS_D_TAG.to_string()]),
            limit: Some(10),
            ..Default::default()
        }],
        Rc::new(move |ev| sink.borrow_mut().push(ev)),
        Rc::new(move |_authed| answered.fill(Ok(()))),
        Rc::new(move |_reason| refused.fill(Err(()))),
    );
    let late = slot.clone();
    let _timer = gloo::timers::callback::Timeout::new(RELAY_WAIT_MS, move || late.fill(Err(())));
    let outcome = slot.wait().await;
    relay.unsubscribe(&sub);
    outcome.map_err(|()| LocalOnlyReason::RelayError)?;
    let events = events.borrow();
    Ok(pick_latest(&events, owner).cloned())
}

/// Publish `ev` and wait for the relay's `OK`.
pub(crate) async fn publish(
    relay: &RelayConnection,
    ev: &NostrEvent,
) -> Result<(), LocalOnlyReason> {
    let slot: Rc<OneShot<bool>> = OneShot::new();
    let done = slot.clone();
    relay
        .publish_with_ack(ev, Some(Rc::new(move |ok, _msg| done.fill(ok))))
        .map_err(|_| LocalOnlyReason::RelayError)?;
    let late = slot.clone();
    let _timer = gloo::timers::callback::Timeout::new(RELAY_WAIT_MS, move || late.fill(false));
    if slot.wait().await {
        Ok(())
    } else {
        Err(LocalOnlyReason::RelayError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stores::thread_subs::{Entry, MAX_ACTIVE_SUBSCRIPTIONS};
    use nostr_bbs_core::keys::generate_keypair;
    use nostr_bbs_core::signer::PrfSigner;

    /// A clock past every marker the tests use, so clamping changes nothing.
    const LATER: u64 = u64::MAX;

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        futures::executor::block_on(f)
    }

    fn id(n: u32) -> String {
        format!("{n:064x}")
    }

    fn signer() -> PrfSigner {
        PrfSigner::new(generate_keypair().unwrap())
    }

    /// The largest list a member can hold: every followed topic with a full
    /// channel id, a long zone id and a marker, plus the most tombstones.
    fn worst_case(active: usize, zone_len: usize) -> Subs {
        let mut s = Subs::default();
        let now = 1_800_000_000_000u64;
        for n in 0..active as u32 {
            let r = id(n);
            s.entries.insert(
                r.clone(),
                Entry {
                    r: r.clone(),
                    c: id(1_000_000 + n),
                    z: "z".repeat(zone_len),
                    on: true,
                    at: now + n as u64,
                },
            );
            s.read.insert(r, now / 1000 + n as u64);
        }
        for n in 0..crate::stores::thread_subs::MAX_TOMBSTONES as u32 {
            let r = id(2_000_000 + n);
            s.entries.insert(
                r.clone(),
                Entry {
                    r,
                    c: String::new(),
                    z: String::new(),
                    on: false,
                    at: now - 1000 + n as u64,
                },
            );
        }
        s
    }

    #[test]
    fn padding_matches_nip44_v2() {
        assert_eq!(nip44_padded_len(1), 32);
        assert_eq!(nip44_padded_len(32), 32);
        assert_eq!(nip44_padded_len(33), 64);
        assert_eq!(nip44_padded_len(257), 320);
        assert_eq!(nip44_padded_len(40_960), 40_960);
        assert_eq!(nip44_padded_len(40_961), 49_152);
        assert_eq!(nip44_payload_len(MAX_PLAINTEXT_BYTES), 54_704);
        assert!(nip44_payload_len(MAX_PLAINTEXT_BYTES) <= RELAY_CONTENT_CAP);
        assert!(nip44_payload_len(MAX_PLAINTEXT_BYTES + 1) > RELAY_CONTENT_CAP);
    }

    #[test]
    fn computed_payload_length_matches_a_real_encryption() {
        let s = signer();
        for n in [1usize, 31, 32, 33, 300, 5_000, 33_000, MAX_PLAINTEXT_BYTES] {
            let plain = "x".repeat(n);
            let ct = block_on(s.nip44_encrypt(s.public_key(), &plain)).unwrap();
            assert_eq!(ct.len(), nip44_payload_len(n), "plaintext {n}");
        }
    }

    #[test]
    fn the_event_has_kind_30078_and_only_the_d_tag() {
        let s = signer();
        let mut subs = Subs::default();
        subs.subscribe(&id(1), &id(2), "zone1", 1, 1_000).unwrap();
        let ev = block_on(seal(&s, &subs, 1_700_000_000)).unwrap();
        assert_eq!(ev.kind, 30078);
        assert_eq!(ev.pubkey, s.public_key());
        assert_eq!(
            ev.tags,
            vec![vec![
                "d".to_string(),
                "nostr-bbs/thread-subs/v1".to_string()
            ]]
        );
        assert!(!ev.content.contains(&id(1)), "ids are not in the clear");
        assert!(verify_event_strict(&ev).is_ok());
    }

    #[test]
    fn seal_then_open_round_trips() {
        let s = signer();
        let mut subs = Subs::default();
        subs.subscribe(&id(1), &id(2), "zone1", 1, 1_000).unwrap();
        subs.subscribe(&id(3), &id(2), "", 1, 1_001).unwrap();
        subs.mark_read(&id(3), 50, LATER);
        subs.unsubscribe(&id(1), 2_000);
        let ev = block_on(seal(&s, &subs, 1_700_000_000)).unwrap();
        let back = block_on(open(&s, &ev, LATER)).unwrap();
        assert_eq!(back, subs);
    }

    #[test]
    fn another_key_cannot_open_the_copy() {
        let mine = signer();
        let theirs = signer();
        let mut subs = Subs::default();
        subs.subscribe(&id(1), &id(2), "", 1, 1_000).unwrap();
        let ev = block_on(seal(&mine, &subs, 1_700_000_000)).unwrap();
        assert_eq!(
            block_on(open(&theirs, &ev, LATER)),
            Err(LocalOnlyReason::Unreadable)
        );
    }

    #[test]
    fn the_worst_case_list_fits_the_relay_cap_keeping_every_followed_topic() {
        let s = signer();
        // Longest accepted ids: 64-hex root and channel, longest zone id.
        let subs = worst_case(
            MAX_ACTIVE_SUBSCRIPTIONS,
            crate::stores::thread_subs::MAX_ZONE_LEN,
        );
        let plain = encode_bounded(&subs).unwrap();
        assert!(plain.len() <= MAX_PLAINTEXT_BYTES);
        let back = decode(&plain, LATER).unwrap();
        assert_eq!(back.active_count(), MAX_ACTIVE_SUBSCRIPTIONS);
        let ev = block_on(seal(&s, &subs, 1_700_000_000)).unwrap();
        assert!(
            ev.content.len() <= RELAY_CONTENT_CAP,
            "{}",
            ev.content.len()
        );
        // Tombstones were shed oldest first.
        let kept: Vec<&Entry> = back.entries.values().filter(|e| !e.on).collect();
        assert!(kept.len() < crate::stores::thread_subs::MAX_TOMBSTONES);
        if let Some(oldest_kept) = kept.iter().map(|e| e.at).min() {
            let dropped_newer = subs
                .entries
                .values()
                .filter(|e| !e.on && !back.entries.contains_key(&e.r))
                .any(|e| e.at > oldest_kept);
            assert!(
                !dropped_newer,
                "never a newer tombstone before an older one"
            );
        }
    }

    #[test]
    fn a_list_that_cannot_fit_is_refused_rather_than_cut() {
        // Followed topics alone over the budget (only reachable by merging
        // lists that several devices each filled to the cap): nothing is published.
        let subs = worst_case(2 * MAX_ACTIVE_SUBSCRIPTIONS, 16);
        assert_eq!(encode_bounded(&subs), Err(LocalOnlyReason::TooLarge));
    }

    #[test]
    fn markers_of_topics_not_followed_are_not_published() {
        let mut subs = Subs::default();
        subs.subscribe(&id(1), &id(2), "", 1, 1_000).unwrap();
        subs.read.insert(id(9), 5);
        let back = decode(&encode_bounded(&subs).unwrap(), LATER).unwrap();
        assert!(!back.read.contains_key(&id(9)));
        assert!(back.read.contains_key(&id(1)));
    }

    #[test]
    fn pick_latest_takes_only_valid_copies_of_the_owner() {
        let me = signer();
        let other = signer();
        let mut subs = Subs::default();
        subs.subscribe(&id(1), &id(2), "", 1, 1_000).unwrap();
        let old = block_on(seal(&me, &subs, 100)).unwrap();
        let new = block_on(seal(&me, &subs, 200)).unwrap();
        let theirs = block_on(seal(&other, &subs, 300)).unwrap();
        let mut forged = new.clone();
        forged.created_at = 400;
        let wrong_d = block_on(me.sign_event(UnsignedEvent {
            pubkey: me.public_key().to_string(),
            created_at: 500,
            kind: KIND_APP_DATA,
            tags: vec![vec!["d".into(), "nostr-bbs/zone-inbox/v1".into()]],
            content: old.content.clone(),
        }))
        .unwrap();
        let all = vec![old.clone(), new.clone(), theirs, forged, wrong_d];
        assert_eq!(
            pick_latest(&all, me.public_key()).map(|e| &e.id),
            Some(&new.id)
        );
        assert!(pick_latest(&[], me.public_key()).is_none());
    }

    #[test]
    fn decode_rejects_what_is_not_the_copy() {
        assert!(decode("not json", LATER).is_none());
        assert!(decode("[1,2]", LATER).is_none());
        assert_eq!(decode("{}", LATER), Some(Subs::default()));
    }

    #[test]
    fn only_lasting_reasons_end_the_session() {
        assert!(LocalOnlyReason::NoNip44.ends_session());
        assert!(LocalOnlyReason::Unreadable.ends_session());
        assert!(!LocalOnlyReason::RelayError.ends_session());
        assert!(!LocalOnlyReason::TooLarge.ends_session());
        assert!(!LocalOnlyReason::NoSigner.ends_session());
    }

    // -- publish decision --

    fn dig(full: &str, entries: &str) -> Digests {
        Digests {
            full: full.into(),
            entries: entries.into(),
        }
    }

    fn seen(full: &str, entries: &str) -> RemoteSeen {
        RemoteSeen {
            id: "1".repeat(64),
            created_at: 100,
            digest: full.into(),
            entries_digest: entries.into(),
        }
    }

    const T: u64 = 10_000_000;

    fn input<'a>(local: &'a Digests, remote: Option<&'a RemoteSeen>) -> PlanInput<'a> {
        PlanInput {
            fetched: true,
            disabled: false,
            local: Some(local),
            local_empty: false,
            remote,
            extension: false,
            trigger: Trigger::Scheduled,
            now_ms: T,
            last_fetch_ms: Some(T),
            published_ms: 0,
            not_before_ms: 0,
        }
    }

    #[test]
    fn never_publishes_before_a_successful_fetch_or_over_an_unreadable_copy() {
        let local = dig("a", "x");
        let p = PlanInput {
            fetched: false,
            ..input(&local, None)
        };
        assert_eq!(plan(&p), Plan::Blocked);
        for trigger in [Trigger::Hidden, Trigger::PageHide, Trigger::SignOut] {
            assert_eq!(
                plan(&PlanInput {
                    trigger,
                    ..p.clone()
                }),
                Plan::Blocked
            );
        }
        // An unreadable relay copy disables the session: left alone.
        let p = PlanInput {
            disabled: true,
            ..input(&local, None)
        };
        assert_eq!(plan(&p), Plan::Blocked);
    }

    #[test]
    fn nothing_to_publish_when_the_relay_copy_matches_or_both_are_empty() {
        let local = dig("a", "x");
        let same = seen("a", "x");
        assert_eq!(plan(&input(&local, Some(&same))), Plan::Nothing);
        let p = PlanInput {
            local_empty: true,
            ..input(&local, None)
        };
        assert_eq!(plan(&p), Plan::Nothing);
        assert_eq!(plan(&input(&local, None)), Plan::Publish);
        let p = PlanInput {
            local: None,
            ..input(&local, None)
        };
        assert_eq!(plan(&p), Plan::TooLarge);
    }

    #[test]
    fn a_stale_fetch_is_repeated_before_publishing() {
        let local = dig("a", "x");
        let old = seen("b", "y");
        let p = PlanInput {
            last_fetch_ms: Some(T - FRESH_FETCH_MS - 1),
            ..input(&local, Some(&old))
        };
        assert_eq!(plan(&p), Plan::Refetch);
        let p = PlanInput {
            last_fetch_ms: Some(T - FRESH_FETCH_MS),
            ..input(&local, Some(&old))
        };
        assert_eq!(plan(&p), Plan::Publish);
        // A subscribe or unsubscribe waits only seconds after a publish.
        let p = PlanInput {
            published_ms: T - 1_000,
            ..input(&local, Some(&old))
        };
        assert_eq!(
            plan(&p),
            Plan::Wait {
                until_ms: T - 1_000 + MEMBERSHIP_PUBLISH_INTERVAL_MS
            }
        );
    }

    #[test]
    fn an_extension_signer_publishes_markers_alone_rarely() {
        let local = dig("a", "x");
        let markers_only = seen("b", "x");
        let ext = |trigger, published_ms| PlanInput {
            extension: true,
            trigger,
            published_ms,
            ..input(&local, Some(&markers_only))
        };
        // Read markers alone: not before the long interval, hidden or not.
        assert_eq!(
            plan(&ext(Trigger::Scheduled, T - 120_000)),
            Plan::Wait {
                until_ms: T - 120_000 + EXTENSION_MARKER_INTERVAL_MS
            }
        );
        assert_eq!(plan(&ext(Trigger::Hidden, T - 120_000)), Plan::Nothing);
        assert_eq!(
            plan(&ext(Trigger::Scheduled, T - EXTENSION_MARKER_INTERVAL_MS)),
            Plan::Publish
        );
        // At sign-out the markers go too (the local copy is about to go).
        assert_eq!(plan(&ext(Trigger::SignOut, T - 120_000)), Plan::Publish);
        // A subscribe or unsubscribe goes at the normal pace.
        let membership = seen("b", "y");
        let p = PlanInput {
            extension: true,
            published_ms: T - 120_000,
            ..input(&local, Some(&membership))
        };
        assert_eq!(plan(&p), Plan::Publish);
        // A local-key signer's scheduled publish of markers alone is just as
        // lazy (privacy: each read must not show on the relay)...
        let p = PlanInput {
            published_ms: T - 120_000,
            ..input(&local, Some(&markers_only))
        };
        assert_eq!(
            plan(&p),
            Plan::Wait {
                until_ms: T - 120_000 + MARKER_PUBLISH_INTERVAL_MS
            }
        );
        // ...but they go when the page is hidden (no prompt to cost).
        let hidden = PlanInput {
            trigger: Trigger::Hidden,
            ..p
        };
        assert_eq!(plan(&hidden), Plan::Publish);
        // An extension can never publish on pagehide.
        assert_eq!(plan(&ext(Trigger::PageHide, 0)), Plan::Nothing);
    }

    #[test]
    fn hide_and_sign_out_skip_the_interval_and_pagehide_needs_a_recent_fetch() {
        let local = dig("a", "x");
        let old = seen("b", "y");
        let base = PlanInput {
            published_ms: T - 1_000,
            ..input(&local, Some(&old))
        };
        assert_eq!(
            plan(&PlanInput {
                trigger: Trigger::Hidden,
                ..base.clone()
            }),
            Plan::Publish
        );
        assert_eq!(
            plan(&PlanInput {
                trigger: Trigger::SignOut,
                ..base.clone()
            }),
            Plan::Publish
        );
        let stale = PlanInput {
            trigger: Trigger::Hidden,
            last_fetch_ms: Some(T - 60_000),
            ..base.clone()
        };
        assert_eq!(plan(&stale), Plan::Refetch);
        let pagehide = PlanInput {
            trigger: Trigger::PageHide,
            last_fetch_ms: Some(T - PAGEHIDE_FRESH_MS),
            ..base.clone()
        };
        assert_eq!(plan(&pagehide), Plan::Publish);
        let pagehide_stale = PlanInput {
            last_fetch_ms: Some(T - PAGEHIDE_FRESH_MS - 1),
            ..pagehide
        };
        assert_eq!(plan(&pagehide_stale), Plan::Nothing, "never blind");
    }

    #[test]
    fn any_other_relay_copy_counts_as_changed_including_the_same_second() {
        let s = signer();
        let mut subs = Subs::default();
        subs.subscribe(&id(1), &id(2), "", 1, 1_000).unwrap();
        let ev = block_on(seal(&s, &subs, 200)).unwrap();
        assert!(remote_changed(None, &ev));
        let same = RemoteSeen {
            id: ev.id.clone(),
            created_at: 200,
            digest: String::new(),
            entries_digest: String::new(),
        };
        assert!(
            !remote_changed(Some(&same), &ev),
            "same copy: not decrypted again"
        );
        // Equal created_at, either id order: a change (the relay keeps the
        // lower id, so time cannot decide).
        for other in ["0".repeat(64), "f".repeat(64)] {
            let k = RemoteSeen {
                id: other,
                created_at: 200,
                ..same.clone()
            };
            assert!(remote_changed(Some(&k), &ev));
        }
        let later_known = RemoteSeen {
            id: "f".repeat(64),
            created_at: 300,
            ..same
        };
        assert!(
            remote_changed(Some(&later_known), &ev),
            "merging is harmless"
        );
    }

    #[test]
    fn of_two_records_in_the_same_second_the_lower_id_is_newer() {
        let r = |id: &str, at: u64| RemoteSeen {
            id: id.into(),
            created_at: at,
            digest: String::new(),
            entries_digest: String::new(),
        };
        let a = r("aaa", 100);
        let b = r("bbb", 100);
        assert_eq!(
            RemoteSeen::newer(Some(a.clone()), Some(b.clone())),
            Some(a.clone())
        );
        assert_eq!(
            RemoteSeen::newer(Some(b.clone()), Some(a.clone())),
            Some(a.clone())
        );
        let c = r("zzz", 101);
        assert_eq!(RemoteSeen::newer(Some(a.clone()), Some(c.clone())), Some(c));
        assert_eq!(RemoteSeen::newer(None, Some(a.clone())), Some(a));
    }

    #[test]
    fn failed_attempts_back_off_and_hide_does_not_retry_early() {
        assert_eq!(failure_backoff_ms(0), 0);
        assert_eq!(failure_backoff_ms(1), 60_000);
        assert_eq!(failure_backoff_ms(2), 120_000);
        assert_eq!(failure_backoff_ms(20), EXTENSION_MARKER_INTERVAL_MS);
        let local = dig("a", "x");
        let old = seen("b", "y");
        let p = PlanInput {
            not_before_ms: T + 5_000,
            ..input(&local, Some(&old))
        };
        assert_eq!(
            plan(&p),
            Plan::Wait {
                until_ms: T + 5_000
            }
        );
        let hidden = PlanInput {
            trigger: Trigger::Hidden,
            ..p.clone()
        };
        assert_eq!(plan(&hidden), Plan::Nothing);
        // Sign-out is the last chance: it still tries.
        let out = PlanInput {
            trigger: Trigger::SignOut,
            ..p
        };
        assert_eq!(plan(&out), Plan::Publish);
    }

    #[test]
    fn hiding_publishes_markers_only_for_a_local_signer() {
        let local = dig("a", "x");
        // Markers alone, inside the interval: an extension waits on hide, a
        // local-key signer publishes.
        let markers = seen("b", "x");
        let p = PlanInput {
            trigger: Trigger::Hidden,
            published_ms: T - 1_000,
            extension: true,
            ..input(&local, Some(&markers))
        };
        assert_eq!(plan(&p), Plan::Nothing);
        let local_signer = PlanInput {
            extension: false,
            ..p
        };
        assert_eq!(plan(&local_signer), Plan::Publish);
        // A subscribe or unsubscribe goes on hide at once.
        let membership = seen("b", "y");
        let p = PlanInput {
            trigger: Trigger::Hidden,
            published_ms: T - 1_000,
            ..input(&local, Some(&membership))
        };
        assert_eq!(plan(&p), Plan::Publish);
    }

    #[test]
    fn a_declined_signature_ends_the_session() {
        assert!(LocalOnlyReason::SignerRefused.ends_session());
    }

    #[test]
    fn a_list_trimmed_to_fit_does_not_look_changed_after_it_is_published() {
        // The worst case sheds tombstones to fit. The digest is over the
        // bounded encoding, so the published copy (decoded) and the local
        // list agree, and the plan says nothing is pending.
        let subs = worst_case(
            MAX_ACTIVE_SUBSCRIPTIONS,
            crate::stores::thread_subs::MAX_ZONE_LEN,
        );
        let local = digests(&subs).unwrap();
        let published = decode(&encode_bounded(&subs).unwrap(), LATER).unwrap();
        assert!(
            published.entries.len() < subs.entries.len(),
            "tombstones were shed"
        );
        let remote = digests(&published).unwrap();
        assert_eq!(local, remote);
        let r = RemoteSeen {
            id: "1".repeat(64),
            created_at: 1,
            digest: remote.full,
            entries_digest: remote.entries,
        };
        assert_eq!(plan(&input(&local, Some(&r))), Plan::Nothing);
    }

    #[test]
    fn digests_separate_membership_from_markers() {
        let mut a = Subs::default();
        a.subscribe(&id(1), &id(2), "", 1, 1_000).unwrap();
        let mut b = a.clone();
        b.mark_read(&id(1), 99, LATER);
        let (da, db) = (digests(&a).unwrap(), digests(&b).unwrap());
        assert_ne!(da.full, db.full);
        assert_eq!(da.entries, db.entries);
        b.unsubscribe(&id(1), 2_000);
        assert_ne!(da.entries, digests(&b).unwrap().entries);
    }
}
