//! The migration steps — `plan`, `seal`, `verify`, `purge` — generic over
//! [`Relay`].
//!
//! Relay transport errors abort a step and leave the state file as last
//! persisted; only definite outcomes (a relay rejection, an envelope that does
//! not open or does not match) mark an entry `failed`. Every step persists
//! through [`Hooks::persist`] after each change that matters, so a run can be
//! interrupted at any point and resumed.

use std::collections::{BTreeSet, HashMap};

use nostr_bbs_core::keys::SecretKey;
use nostr_bbs_core::sealed::{channel_of, open_sealed, seal_original};
use nostr_bbs_core::{verify_event, NostrEvent};
use serde::Serialize;
use thiserror::Error;

use crate::channels::ChannelSpec;
use crate::keys::KeyRing;
use crate::plan::{scan_channel, ChannelPlan, ChannelScan};
use crate::relay::{fetch_all, fetch_by_ids, Filter, Relay, RelayError, MAX_DELETE_IDS};
use crate::state::{sha256_hex, Counts, Entry, State, StateError, Status, Step};

/// `reason` sent with every `POST /api/admin/events/delete`; recorded in the
/// relay's admin audit log (`events.delete`).
pub const PURGE_REASON: &str = "sealed-original history migration (ADR-2017)";

/// Why a step stopped.
#[derive(Debug, Error)]
pub enum EngineError {
    /// Talking to the relay failed; the state file is as last saved.
    #[error(transparent)]
    Relay(#[from] RelayError),
    /// Saving the state file failed.
    #[error(transparent)]
    State(#[from] StateError),
    /// Zone keys needed for this step are not held. Nothing was changed.
    #[error("no zone key held for: {}", .0.join(", "))]
    MissingKeys(Vec<String>),
    /// The step refused to run; the message says why and what to do.
    #[error("{0}")]
    Refused(String),
}

/// Side effects the engine needs from its caller.
pub struct Hooks<'a> {
    /// Save the state (the CLI writes it atomically to `--state`).
    pub persist: &'a mut dyn FnMut(&State) -> Result<(), StateError>,
    /// Report one line of human-readable progress (the CLI writes to stderr).
    pub progress: &'a mut dyn FnMut(&str),
}

/// Result of [`scan`]: the plan for every listed channel.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Plan {
    /// One plan per listed channel, in channels-file order.
    pub channels: Vec<ChannelPlan>,
    /// Zones listed in the channels file for which no key is held.
    pub zones_without_key: Vec<String>,
    /// `(channel, created_at)` seconds where paging could not guarantee
    /// completeness (more than one page of events in one second).
    pub incomplete_seconds: Vec<(String, u64)>,
}

impl Plan {
    /// Total plaintext originals, already-sealed originals and ids to seal.
    pub fn totals(&self) -> (usize, usize, usize) {
        self.channels.iter().fold((0, 0, 0), |(p, a, w), c| {
            (
                p + c.plaintext,
                a + c.already_sealed,
                w + c.would_seal.len(),
            )
        })
    }
}

/// Fetch every listed channel's kind-42 events and classify them. Read-only.
pub async fn scan<R: Relay>(
    relay: &mut R,
    channels: &[ChannelSpec],
    keys: &KeyRing,
) -> Result<(Plan, Vec<ChannelScan>), RelayError> {
    let mut plan = Plan::default();
    let mut scans = Vec::with_capacity(channels.len());
    for spec in channels {
        let fetched = fetch_all(
            relay,
            &Filter {
                kinds: Some(vec![42]),
                e_tags: Some(vec![spec.id.clone()]),
                ..Filter::default()
            },
        )
        .await?;
        for s in fetched.ambiguous_seconds {
            plan.incomplete_seconds.push((spec.id.clone(), s));
        }
        let scan = scan_channel(spec, &fetched.events, keys);
        plan.channels.push(scan.plan.clone());
        scans.push(scan);
    }
    let zones: BTreeSet<&str> = channels.iter().map(|c| c.zone.as_str()).collect();
    plan.zones_without_key = zones
        .into_iter()
        .filter(|z| keys.current(z).is_none())
        .map(str::to_string)
        .collect();
    Ok((plan, scans))
}

/// Summary of a `seal` run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SealReport {
    /// The plan the run started from.
    pub plan: Plan,
    /// Envelopes published, read back and matched in this run.
    pub sealed: usize,
    /// Originals whose envelope was already on the relay and matched, so no
    /// new envelope was published.
    pub adopted: usize,
    /// Entries marked `failed` in this run: `(original id, reason)`.
    pub failed: Vec<(String, String)>,
    /// Entries still waiting to be sealed after this run.
    pub remaining: usize,
    /// Whether `--limit` stopped the run early.
    pub limit_reached: bool,
    /// State counts after the run.
    pub counts: Counts,
}

/// Seal every planned original (resumable). See the crate docs for the flow.
///
/// Newly found plaintext originals are added to `state` as `planned`. Then
/// each `planned` entry, and each entry that failed at `seal` or `verify`, is
/// processed oldest first, up to `limit`:
///
/// 1. if an envelope for it is already on the relay and opens to exactly the
///    original, it is adopted;
/// 2. otherwise an envelope is built with the zone's highest-epoch key and
///    published; after `OK true` it is fetched back by id, opened with the
///    zone key, and its inner event must equal the original byte for byte.
///
/// The entry becomes `sealed`, or `failed` with the reason.
pub async fn seal<R: Relay>(
    relay: &mut R,
    migrator: &SecretKey,
    channels: &[ChannelSpec],
    keys: &KeyRing,
    state: &mut State,
    limit: Option<usize>,
    hooks: &mut Hooks<'_>,
) -> Result<SealReport, EngineError> {
    let (plan, scans) = scan(relay, channels, keys).await?;
    let mut report = SealReport {
        plan,
        ..SealReport::default()
    };

    // Index what the relay holds right now.
    let mut originals: HashMap<String, &NostrEvent> = HashMap::new();
    let mut envelopes: HashMap<String, &Vec<NostrEvent>> = HashMap::new();
    for scan in &scans {
        for c in &scan.candidates {
            originals.insert(c.original.id.clone(), &c.original);
        }
        for (inner, evs) in &scan.envelopes_by_inner {
            envelopes.insert(inner.clone(), evs);
        }
    }

    // Record newly found originals.
    let mut added = 0usize;
    for scan in &scans {
        for c in &scan.candidates {
            if !state.entries.contains_key(&c.original.id) {
                state.entries.insert(
                    c.original.id.clone(),
                    Entry::planned(&scan.plan.channel, &scan.plan.zone, c.original.created_at),
                );
                added += 1;
            }
        }
    }
    if added > 0 {
        (hooks.progress)(&format!(
            "recorded {added} new plaintext originals as planned"
        ));
        (hooks.persist)(state)?;
    }

    let listed: HashMap<&str, &str> = channels
        .iter()
        .map(|c| (c.id.as_str(), c.zone.as_str()))
        .collect();
    let mut work: Vec<(String, u64)> = state
        .entries
        .iter()
        .filter(|(_, e)| listed.contains_key(e.channel.as_str()) && needs_seal(&e.status))
        .map(|(id, e)| (id.clone(), e.created_at))
        .collect();
    work.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));

    let missing: BTreeSet<String> = work
        .iter()
        .map(|(id, _)| state.entries[id].zone.clone())
        .filter(|z| keys.current(z).is_none())
        .collect();
    if !missing.is_empty() {
        return Err(EngineError::MissingKeys(missing.into_iter().collect()));
    }

    let total = work.len();
    for (n, (id, _)) in work.iter().enumerate() {
        if limit.is_some_and(|l| n >= l) {
            report.limit_reached = true;
            break;
        }
        let (channel, zone) = {
            let e = &state.entries[id];
            (e.channel.clone(), e.zone.clone())
        };
        let original = originals.get(id).copied();
        let existing = envelopes.get(id).map(|v| v.as_slice()).unwrap_or(&[]);

        // 1. Adopt an envelope already on the relay.
        if let Some((outer, epoch, digest)) = adopt(existing, id, &channel, original, keys) {
            set_sealed(state, id, epoch, &outer, digest);
            report.adopted += 1;
            (hooks.progress)(&format!(
                "[{}/{total}] {id}: adopted envelope {outer}",
                n + 1
            ));
            (hooks.persist)(state)?;
            continue;
        }

        // 2. Seal and publish a new envelope.
        let Some(original) = original else {
            fail(
                state,
                &mut report.failed,
                id,
                Step::Seal,
                "original not found on the relay",
                None,
            );
            (hooks.progress)(&format!("[{}/{total}] {id}: original not found", n + 1));
            (hooks.persist)(state)?;
            continue;
        };
        let key = keys.current(&zone).expect("checked above");
        let envelope = match seal_original(original, &zone, key.epoch(), key.pubkey(), migrator) {
            Ok(env) => env,
            Err(e) => {
                fail(
                    state,
                    &mut report.failed,
                    id,
                    Step::Seal,
                    &e.to_string(),
                    None,
                );
                (hooks.progress)(&format!("[{}/{total}] {id}: {e}", n + 1));
                (hooks.persist)(state)?;
                continue;
            }
        };
        let ok = relay.publish(&envelope).await?;
        if !ok.accepted {
            let reason = if ok.message.is_empty() {
                "relay rejected the envelope".to_string()
            } else {
                ok.message
            };
            fail(state, &mut report.failed, id, Step::Seal, &reason, None);
            (hooks.progress)(&format!("[{}/{total}] {id}: rejected: {reason}", n + 1));
            (hooks.persist)(state)?;
            continue;
        }

        // Read back and compare byte for byte.
        let expected = serde_json::to_string(original).expect("event serialises");
        let fetched = fetch_by_ids(relay, std::slice::from_ref(&envelope.id)).await?;
        let checked = match fetched.get(&envelope.id) {
            None => Err("envelope accepted but not returned when fetched by id".to_string()),
            Some(outer) => open_and_check(outer, id, &channel, key.secret()).and_then(|inner| {
                if inner == expected {
                    Ok(())
                } else {
                    Err("read-back inner event differs from the original".to_string())
                }
            }),
        };
        match checked {
            Ok(()) => {
                set_sealed(
                    state,
                    id,
                    key.epoch(),
                    &envelope.id,
                    sha256_hex(expected.as_bytes()),
                );
                report.sealed += 1;
                (hooks.progress)(&format!(
                    "[{}/{total}] {id}: sealed as {} ({zone} epoch {})",
                    n + 1,
                    envelope.id,
                    key.epoch()
                ));
            }
            Err(reason) => {
                fail(
                    state,
                    &mut report.failed,
                    id,
                    Step::Seal,
                    &reason,
                    Some((key.epoch(), &envelope.id)),
                );
                (hooks.progress)(&format!("[{}/{total}] {id}: {reason}", n + 1));
            }
        }
        (hooks.persist)(state)?;
    }

    report.remaining = state
        .entries
        .values()
        .filter(|e| needs_seal(&e.status))
        .count();
    report.counts = state.counts();
    Ok(report)
}

/// Summary of a `verify` run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct VerifyReport {
    /// Envelopes checked.
    pub checked: usize,
    /// Entries now `verified`.
    pub verified: usize,
    /// Entries marked `failed` at `verify`: `(original id, reason)`.
    pub failed: Vec<(String, String)>,
    /// State counts after the run.
    pub counts: Counts,
}

/// Re-fetch every recorded envelope (`sealed`, `verified`, or `failed` at
/// `verify`), open it with the recorded zone epoch key, and check the inner
/// event is the original: same id and the same canonical-JSON SHA-256 as when
/// it was sealed. Each becomes `verified` or `failed`.
pub async fn verify<R: Relay>(
    relay: &mut R,
    keys: &KeyRing,
    state: &mut State,
    hooks: &mut Hooks<'_>,
) -> Result<VerifyReport, EngineError> {
    let targets: Vec<String> = state
        .entries
        .iter()
        .filter(|(_, e)| {
            e.outer_id.is_some()
                && matches!(
                    e.status,
                    Status::Sealed
                        | Status::Verified
                        | Status::Failed {
                            step: Step::Verify,
                            ..
                        }
                )
        })
        .map(|(id, _)| id.clone())
        .collect();
    let mut report = VerifyReport::default();
    check_entries(relay, keys, state, &targets, &mut report.failed).await?;
    report.checked = targets.len();
    report.verified = targets
        .iter()
        .filter(|id| state.entries[*id].status == Status::Verified)
        .count();
    (hooks.progress)(&format!(
        "verified {} of {} envelopes; {} failed",
        report.verified,
        report.checked,
        report.failed.len()
    ));
    (hooks.persist)(state)?;
    report.counts = state.counts();
    Ok(report)
}

/// Summary of a `purge` run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PurgeReport {
    /// `POST /api/admin/events/delete` calls made.
    pub requests: usize,
    /// Rows the relay reported deleted.
    pub deleted: u64,
    /// Ids the relay did not hold (already gone); marked `purged`.
    pub not_found: Vec<String>,
    /// Ids the relay kept because they are not kind 42; marked `failed`.
    pub skipped: Vec<String>,
    /// State counts after the run.
    pub counts: Counts,
}

/// Delete the plaintext originals of every `verified` entry, silently
/// (no kind-5, no broadcast), in chunks of at most [`MAX_DELETE_IDS`].
///
/// Refuses unless `confirmed`, unless the state has entries, and unless every
/// entry is `verified` (or already `purged`, so an interrupted purge can
/// resume). Just before each chunk is deleted its envelopes are fetched and
/// opened once more; if any fails, that chunk is not deleted.
pub async fn purge<R: Relay>(
    relay: &mut R,
    keys: &KeyRing,
    state: &mut State,
    confirmed: bool,
    hooks: &mut Hooks<'_>,
) -> Result<PurgeReport, EngineError> {
    if !confirmed {
        return Err(EngineError::Refused(
            "purge deletes the plaintext originals irreversibly; re-run with --yes".into(),
        ));
    }
    if state.entries.is_empty() {
        return Err(EngineError::Refused(
            "the state file has no entries; run seal and verify first".into(),
        ));
    }
    let blocking: Vec<(&String, &Entry)> = state
        .entries
        .iter()
        .filter(|(_, e)| !matches!(e.status, Status::Verified | Status::Purged))
        .collect();
    if !blocking.is_empty() {
        let c = state.counts();
        let first: Vec<String> = blocking
            .iter()
            .take(5)
            .map(|(id, e)| format!("{id} ({})", e.status.label()))
            .collect();
        return Err(EngineError::Refused(format!(
            "{} of {} entries are not verified (planned {}, sealed {}, failed {}), e.g. {}; \
             run seal and verify until every entry is verified",
            blocking.len(),
            c.total,
            c.planned,
            c.sealed,
            c.failed,
            first.join(", ")
        )));
    }
    let todo: Vec<String> = state
        .entries
        .iter()
        .filter(|(_, e)| e.status == Status::Verified)
        .map(|(id, _)| id.clone())
        .collect();
    require_keys(state, keys, &todo)?;

    let mut report = PurgeReport::default();
    let chunks = todo.len().div_ceil(MAX_DELETE_IDS);
    for (n, chunk) in todo.chunks(MAX_DELETE_IDS).enumerate() {
        let mut failures = Vec::new();
        check_entries(relay, keys, state, chunk, &mut failures).await?;
        if !failures.is_empty() {
            (hooks.persist)(state)?;
            return Err(EngineError::Refused(format!(
                "{} envelopes in chunk {}/{chunks} no longer open and match (first: {} — {}); \
                 nothing in that chunk was deleted. Run seal, then verify, then purge again",
                failures.len(),
                n + 1,
                failures[0].0,
                failures[0].1
            )));
        }

        let outcome = relay.delete_events(chunk, PURGE_REASON).await?;
        report.requests += 1;
        report.deleted += outcome.deleted;
        for id in chunk {
            let entry = state
                .entries
                .get_mut(id)
                .expect("chunk ids come from state");
            if outcome.skipped.contains(id) {
                entry.status = Status::Failed {
                    step: Step::Purge,
                    reason: "relay kept the event: it is not kind 42".into(),
                };
                report.skipped.push(id.clone());
            } else {
                if outcome.not_found.contains(id) {
                    report.not_found.push(id.clone());
                }
                entry.status = Status::Purged;
            }
        }
        let expected = chunk.len() - chunk_hits(chunk, &outcome.not_found, &outcome.skipped);
        if outcome.deleted as usize != expected {
            (hooks.progress)(&format!(
                "warning: relay reported {} deleted for a chunk where {expected} were expected",
                outcome.deleted
            ));
        }
        (hooks.progress)(&format!(
            "purge chunk {}/{chunks}: {} deleted, {} not found, {} skipped",
            n + 1,
            outcome.deleted,
            outcome.not_found.len(),
            outcome.skipped.len()
        ));
        (hooks.persist)(state)?;
    }
    report.counts = state.counts();
    Ok(report)
}

// ── Internals ────────────────────────────────────────────────────────────────

fn needs_seal(status: &Status) -> bool {
    matches!(
        status,
        Status::Planned
            | Status::Failed {
                step: Step::Seal | Step::Verify,
                ..
            }
    )
}

fn chunk_hits(chunk: &[String], not_found: &[String], skipped: &[String]) -> usize {
    chunk
        .iter()
        .filter(|id| not_found.contains(id) || skipped.contains(id))
        .count()
}

/// Verify the outer signature and channel, open with `zone_sk`, and require
/// the inner id to be `original_id`. Returns the inner event's canonical JSON.
fn open_and_check(
    outer: &NostrEvent,
    original_id: &str,
    channel: &str,
    zone_sk: &[u8; 32],
) -> Result<String, String> {
    if !verify_event(outer) {
        return Err("envelope id or signature does not verify".into());
    }
    if channel_of(outer) != Some(channel) {
        return Err("envelope is in a different channel".into());
    }
    let inner = open_sealed(outer, zone_sk).map_err(|e| e.to_string())?;
    if inner.id != original_id {
        return Err("envelope wraps a different event".into());
    }
    Ok(serde_json::to_string(&inner).expect("event serialises"))
}

/// Find an existing envelope for `original_id` that opens with a held key and
/// wraps exactly the original (byte for byte when the original is still on the
/// relay). Returns `(outer id, epoch, inner sha256)`.
fn adopt(
    envelopes: &[NostrEvent],
    original_id: &str,
    channel: &str,
    original: Option<&NostrEvent>,
    keys: &KeyRing,
) -> Option<(String, u32, String)> {
    let expected = original.map(|o| serde_json::to_string(o).expect("event serialises"));
    envelopes.iter().find_map(|outer| {
        let zk = zk_of(outer)?;
        let key = keys.get(&zk.0, zk.1)?;
        let inner = open_and_check(outer, original_id, channel, key.secret()).ok()?;
        if expected.as_ref().is_some_and(|e| *e != inner) {
            return None;
        }
        Some((outer.id.clone(), zk.1, sha256_hex(inner.as_bytes())))
    })
}

/// `(zone, epoch)` from an envelope's `zk` tag.
fn zk_of(ev: &NostrEvent) -> Option<(String, u32)> {
    ev.tags.iter().find_map(|t| {
        if t.len() >= 4 && t[0] == "zk" && !t[1].is_empty() {
            Some((t[1].clone(), t[2].parse().ok()?))
        } else {
            None
        }
    })
}

fn set_sealed(state: &mut State, id: &str, epoch: u32, outer_id: &str, digest: String) {
    let e = state.entries.get_mut(id).expect("entry exists");
    e.status = Status::Sealed;
    e.epoch = Some(epoch);
    e.outer_id = Some(outer_id.to_string());
    e.inner_sha256 = Some(digest);
}

fn fail(
    state: &mut State,
    log: &mut Vec<(String, String)>,
    id: &str,
    step: Step,
    reason: &str,
    envelope: Option<(u32, &str)>,
) {
    let e = state.entries.get_mut(id).expect("entry exists");
    e.status = Status::Failed {
        step,
        reason: reason.to_string(),
    };
    if let Some((epoch, outer)) = envelope {
        e.epoch = Some(epoch);
        e.outer_id = Some(outer.to_string());
        e.inner_sha256 = None;
    }
    log.push((id.to_string(), reason.to_string()));
}

fn require_keys(state: &State, keys: &KeyRing, ids: &[String]) -> Result<(), EngineError> {
    let missing: BTreeSet<String> = ids
        .iter()
        .filter_map(|id| {
            let e = &state.entries[id];
            let epoch = e.epoch?;
            keys.get(&e.zone, epoch)
                .is_none()
                .then(|| format!("{}:{epoch}", e.zone))
        })
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(EngineError::MissingKeys(missing.into_iter().collect()))
    }
}

/// Fetch and check the envelopes of `ids`; set each to `verified` or
/// `failed` at `verify`, appending failures to `failed`.
async fn check_entries<R: Relay>(
    relay: &mut R,
    keys: &KeyRing,
    state: &mut State,
    ids: &[String],
    failed: &mut Vec<(String, String)>,
) -> Result<(), EngineError> {
    require_keys(state, keys, ids)?;
    let outer_ids: Vec<String> = ids
        .iter()
        .filter_map(|id| state.entries[id].outer_id.clone())
        .collect();
    let fetched = fetch_by_ids(relay, &outer_ids).await?;
    for id in ids {
        let e = state.entries.get_mut(id).expect("entry exists");
        let verdict = match (&e.outer_id, e.epoch, &e.inner_sha256) {
            (Some(outer_id), Some(epoch), Some(digest)) => match fetched.get(outer_id) {
                None => Err("envelope not found on the relay".to_string()),
                Some(outer) => {
                    let key = keys.get(&e.zone, epoch).expect("checked by require_keys");
                    open_and_check(outer, id, &e.channel, key.secret()).and_then(|inner| {
                        if sha256_hex(inner.as_bytes()) == *digest {
                            Ok(())
                        } else {
                            Err("inner event differs from the one sealed".to_string())
                        }
                    })
                }
            },
            _ => Err("no complete envelope record; run seal again".to_string()),
        };
        match verdict {
            Ok(()) => e.status = Status::Verified,
            Err(reason) => {
                e.status = Status::Failed {
                    step: Step::Verify,
                    reason: reason.clone(),
                };
                failed.push((id.clone(), reason));
            }
        }
    }
    Ok(())
}
