//! The planner: classify one channel's kind-42 events into what can be
//! sealed, what already is, and what must be left alone.
//!
//! A **plaintext original** is a kind-42 whose channel ([`channel_of`]) is the
//! listed channel and which carries neither a `zk` tag (a live encrypted post)
//! nor a `sealed` tag (an envelope). Originals whose own id or signature does
//! not verify are reported and never sealed: an envelope would vouch for a
//! message its author never signed, and the relay's copy stays untouched.

use std::collections::HashMap;

use nostr_bbs_core::sealed::{channel_of, has_sealed_tag, parse_sealed};
use nostr_bbs_core::{verify_event, NostrEvent};
use serde::Serialize;

use crate::channels::ChannelSpec;
use crate::keys::KeyRing;

/// A plaintext original to be sealed, with any envelopes already on the relay
/// that claim to wrap it.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The original, signature-verified.
    pub original: NostrEvent,
    /// Envelopes in the same channel whose `sealed` tag names this original.
    pub envelopes: Vec<NostrEvent>,
}

/// Per-channel plan, as printed by `plan` and embedded in every summary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ChannelPlan {
    /// Channel id.
    pub channel: String,
    /// Zone from the channels file.
    pub zone: String,
    /// Epoch of the key that would seal this channel, if one is held.
    pub seal_epoch: Option<u32>,
    /// Plaintext originals (signature-verified) still on the relay.
    pub plaintext: usize,
    /// Of those, originals that already have an envelope on the relay.
    pub already_sealed: usize,
    /// Ids that `seal` would publish an envelope for, oldest first.
    pub would_seal: Vec<String>,
    /// Plaintext kind-42s whose id or signature does not verify. Never sealed,
    /// never purged.
    pub invalid_signature: Vec<String>,
    /// Live zone-encrypted posts (`zk` tag, no `sealed` tag). Left alone.
    pub encrypted_posts: usize,
    /// Sealed-original envelopes in the channel.
    pub envelopes: usize,
}

/// The planner's full result for one channel.
#[derive(Debug, Clone, Default)]
pub struct ChannelScan {
    /// Printable plan.
    pub plan: ChannelPlan,
    /// Every sealable original, oldest first (ties broken by id).
    pub candidates: Vec<Candidate>,
    /// Envelopes keyed by the original id in their `sealed` tag, including
    /// those whose original is no longer on the relay.
    pub envelopes_by_inner: HashMap<String, Vec<NostrEvent>>,
}

/// Classify `events` (as returned by a `#e` REQ for the channel) for `spec`.
/// Events of other kinds or other channels are ignored.
pub fn scan_channel(spec: &ChannelSpec, events: &[NostrEvent], keys: &KeyRing) -> ChannelScan {
    let mut plan = ChannelPlan {
        channel: spec.id.clone(),
        zone: spec.zone.clone(),
        seal_epoch: keys.current(&spec.zone).map(|k| k.epoch()),
        ..ChannelPlan::default()
    };
    let mut envelopes_by_inner: HashMap<String, Vec<NostrEvent>> = HashMap::new();
    let mut originals = Vec::new();

    for ev in events {
        if ev.kind != 42 || channel_of(ev) != Some(spec.id.as_str()) {
            continue;
        }
        if has_sealed_tag(&ev.tags) {
            plan.envelopes += 1;
            if let Some(r) = parse_sealed(&ev.tags) {
                envelopes_by_inner
                    .entry(r.inner_id)
                    .or_default()
                    .push(ev.clone());
            }
        } else if ev
            .tags
            .iter()
            .any(|t| t.first().map(String::as_str) == Some("zk"))
        {
            plan.encrypted_posts += 1;
        } else if verify_event(ev) {
            originals.push(ev.clone());
        } else {
            plan.invalid_signature.push(ev.id.clone());
        }
    }

    originals.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    plan.invalid_signature.sort();
    let candidates: Vec<Candidate> = originals
        .into_iter()
        .map(|original| Candidate {
            envelopes: envelopes_by_inner
                .get(&original.id)
                .cloned()
                .unwrap_or_default(),
            original,
        })
        .collect();
    plan.plaintext = candidates.len();
    plan.already_sealed = candidates
        .iter()
        .filter(|c| !c.envelopes.is_empty())
        .count();
    plan.would_seal = candidates
        .iter()
        .filter(|c| c.envelopes.is_empty())
        .map(|c| c.original.id.clone())
        .collect();

    ChannelScan {
        plan,
        candidates,
        envelopes_by_inner,
    }
}
