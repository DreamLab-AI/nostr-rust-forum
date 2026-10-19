//! Web Push fan-out for a freshly stored event (ADR-2023).
//!
//! Runs after `save_event` and after the sender has its `OK`. Recipient
//! resolution happens here, on the Durable Object, because it needs the same
//! `resolve_viewer_context` + `authorize_event` read gate that live delivery
//! uses: a push must never reveal that a post exists to someone who could not
//! read it. The pushes themselves are sent under `State::wait_until`.

use std::collections::{HashMap, HashSet};

use nostr_bbs_core::event::NostrEvent;

use super::nip_handlers::ReadDecision;
use super::NostrRelayDO;
use crate::push::{self, Category, PushJob, PushPrefs};
use crate::zone_config::ZoneConfig;

impl NostrRelayDO {
    /// Whether `event` is already stored, i.e. this submission is a repeat
    /// (clients republish after a reconnect). Only asked for push-eligible
    /// kinds and only when push is on, so the common path pays nothing. A
    /// failed lookup answers `false`: better one extra alert than a lost one.
    pub(crate) async fn push_event_known(&self, event: &NostrEvent) -> bool {
        if !push::enabled(&self.env) || !matches!(event.kind, 40 | 42 | 1059) {
            return false;
        }
        let Ok(db) = self.env.d1("DB") else {
            return false;
        };
        let Ok(stmt) = db
            .prepare("SELECT 1 AS known FROM events WHERE id = ?1")
            .bind(&[nostr_bbs_core::d1_helpers::js_str(&event.id)])
        else {
            return false;
        };
        stmt.first::<serde_json::Value>(None)
            .await
            .ok()
            .flatten()
            .is_some()
    }

    /// Queue Web Push wake-ups for the members `event` concerns.
    ///
    /// `submitter` is the pubkey the submitting session authenticated as; it
    /// lets the NIP-17 sender copy of a DM be recognised and skipped.
    pub(crate) async fn push_fanout(&self, event: &NostrEvent, submitter: Option<String>) {
        if !push::enabled(&self.env) || !matches!(event.kind, 40 | 42 | 1059) {
            return;
        }
        let now = crate::auth::js_now_secs();
        let author = event.pubkey.to_ascii_lowercase();
        let channel = push::channel_of(event);

        // Candidates: (pubkey, category). Named recipients win over opt-in
        // broadcast, so a member tagged in a post gets one Reply, not two alerts.
        let mut candidates = push::explicit_recipients(event, submitter.as_deref());
        if let Some(category) = push::broadcast_category(event) {
            let named: HashSet<String> = candidates.iter().map(|(p, _)| p.clone()).collect();
            for pk in push::broadcast_candidates(&self.env, category).await {
                let pk = pk.to_ascii_lowercase();
                if pk != author && !named.contains(&pk) {
                    candidates.push((pk, category));
                }
            }
        }
        if candidates.is_empty() {
            return;
        }

        // Preferences (absent row = defaults).
        let pubkeys: Vec<String> = candidates.iter().map(|(p, _)| p.clone()).collect();
        let mut prefs: HashMap<String, PushPrefs> = push::load_prefs(&self.env, &pubkeys).await;
        candidates.retain(|(pk, cat)| {
            prefs
                .entry(pk.clone())
                .or_default()
                .wants(*cat, channel.as_deref(), now)
        });

        // Bound the per-candidate work BEFORE it starts. Each candidate costs a
        // cohort lookup and a zone check (D1 on a cache miss), awaited serially on
        // the single Durable Object, and the device cap below only trims jobs
        // afterwards. Named recipients come first, so they are never crowded out.
        candidates.truncate(push::max_fanout(&self.env));

        // Read gate for zone-scoped content. DMs are addressed by the wrap's
        // `p` tag and gated at ingress (ADR-2005), so they skip it.
        if matches!(event.kind, 40 | 42) {
            let zones = ZoneConfig::load(&self.env);
            let mut allowed = Vec::with_capacity(candidates.len());
            for (pk, cat) in candidates {
                let ctx = self.resolve_viewer_context(Some(pk.clone())).await;
                match self.authorize_event(event, &ctx, &zones).await {
                    ReadDecision::Withhold => {}
                    ReadDecision::Deliver | ReadDecision::DeliverAs(_) => allowed.push((pk, cat)),
                }
            }
            candidates = allowed;
        }
        if candidates.is_empty() {
            return;
        }

        // Devices, capped per event.
        let pubkeys: Vec<String> = candidates.iter().map(|(p, _)| p.clone()).collect();
        let category_of: HashMap<&str, Category> =
            candidates.iter().map(|(p, c)| (p.as_str(), *c)).collect();
        // A new topic opens its own channel; replies and posts resolve through
        // the message-jump route, which finds the right thread.
        let topic_link = format!("/chat/{}", event.id);
        let message_link = format!("/go/{}", event.id);
        let cap = push::max_fanout(&self.env);
        let mut jobs: Vec<PushJob> = Vec::new();
        for sub in push::load_subscriptions(&self.env, &pubkeys).await {
            if jobs.len() >= cap {
                worker::console_log!(
                    "push: fan-out capped at {cap} devices for event {}",
                    event.id
                );
                break;
            }
            let Some(category) = category_of.get(sub.pubkey()).copied() else {
                continue;
            };
            let link = category.has_link().then(|| {
                if category == Category::Topic {
                    topic_link.clone()
                } else {
                    message_link.clone()
                }
            });
            jobs.push(sub.into_job(category, link));
        }
        if jobs.is_empty() {
            return;
        }
        self.state
            .wait_until(push::deliver(self.env.clone(), jobs, true));
    }
}
