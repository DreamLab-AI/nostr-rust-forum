//! Reactive zone-key store (ADR-2016).
//!
//! Holds the zone keys this device knows, persists them in IndexedDB, pulls
//! key grants out of the member's gift wraps, and is the single place a
//! zone-encrypted kind-42 is turned into readable text on its way into the
//! [`ChannelStore`](crate::stores::channels::ChannelStore).

use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;

use leptos::prelude::*;
use nostr_bbs_core::signer::Signer;
use nostr_bbs_core::NostrEvent;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};

use super::grant_ledger::{GrantKv, GrantLedger};
use super::inbox_key::{
    deletion_for_wrap, ensure_inbox_key, grant_sweep_enabled, recipient_keys_enabled,
    subscription_targets, sweep_targets, unwrap_inbox_then_identity, LivePort, SweepCandidate,
};
use super::keyset::{self, SendKeyError};
use super::read_cache::ReadCache;
use super::{is_zone_message, read_outcome, resolve_event, validate_grant, ZoneKey};
use crate::relay::{Filter, RelayConnection};
use crate::stores::indexed_db::ForumDb;

/// `zone_kv` id holding the ids of gift wraps already unwrapped here.
const KV_PROCESSED: &str = "processed_wraps";
/// `(zone, epoch)` ids whose grant has arrived addressed to the inbox key.
const KV_INBOX_GRANTED: &str = "inbox_granted";

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Zone keys and the per-message decryption state.
#[derive(Clone, Copy)]
pub struct ZoneKeyStore {
    /// Keys by [`ZoneKey::store_id`] (zone, group, epoch, pubkey), so two
    /// keys claiming one epoch both stay visible (ADR-2028 decision 6).
    pub keys: RwSignal<HashMap<String, ZoneKey>>,
    /// Bumped whenever keys change or messages are re-decrypted.
    pub revision: RwSignal<u64>,
    /// Ids of zone-encrypted kind-42s (decrypted or not), as shown: a
    /// restored sealed original is listed under its own id. Views use this to
    /// keep link previews off: a preview would send the URL to the preview
    /// worker, outside the zone.
    pub encrypted_ids: RwSignal<HashSet<String>>,
    /// Set once the keys stored on this device have been loaded (or the
    /// load has failed), so nothing judges "no key held" too early.
    pub hydrated: RwSignal<bool>,
    /// Ciphertexts and sealed-original envelopes seen, so a key that arrives
    /// later can decrypt what is already on screen, swapping an envelope's
    /// placeholder for the original event in place (ADR-2017).
    cache: StoredValue<ReadCache>,
    processed: StoredValue<HashSet<String>>,
    /// `key_id`s that have been received through the inbox key on this device.
    /// A copy addressed to the identity is only ever swept once its id is here.
    inbox_granted: StoredValue<HashSet<String>>,
    admin_cache: StoredValue<HashMap<String, bool>>,
    /// "Granted from this device", shared by every Encryption-tab card.
    grants: StoredValue<Arc<GrantLedger>>,
    sync_started: StoredValue<bool>,
    /// Secret of the active inbox key (hex), once registered. Always `None`
    /// with `RECIPIENT_KEYS_ENABLED` off.
    inbox_sk: StoredValue<Option<String>>,
    /// Captured at construction: relay callbacks and spawned tasks run
    /// without a reactive owner, so `use_context` is not available there.
    channels: crate::stores::channels::ChannelStore,
}

impl ZoneKeyStore {
    fn new(channels: crate::stores::channels::ChannelStore) -> Self {
        Self {
            channels,
            keys: RwSignal::new(HashMap::new()),
            revision: RwSignal::new(0),
            encrypted_ids: RwSignal::new(HashSet::new()),
            hydrated: RwSignal::new(false),
            cache: StoredValue::new(ReadCache::default()),
            processed: StoredValue::new(HashSet::new()),
            inbox_granted: StoredValue::new(HashSet::new()),
            admin_cache: StoredValue::new(HashMap::new()),
            grants: StoredValue::new(Arc::new(GrantLedger::default())),
            sync_started: StoredValue::new(false),
            inbox_sk: StoredValue::new(None),
        }
    }

    /// Key for `(zone, epoch)`, untracked. Deterministic when an epoch is
    /// inconsistent (see [`keyset::read_key`]); the read path still checks
    /// the result against the message's `zk` pubkey.
    pub fn lookup(&self, zone: &str, epoch: u32) -> Option<ZoneKey> {
        self.keys
            .with_untracked(|m| keyset::read_key(m.values(), zone, epoch))
    }

    /// The key to send under for `zone`: `Err` while any epoch of the zone is
    /// claimed by two different pubkeys, `Ok(None)` when no key is eligible
    /// (including a derived genesis epoch 0 with no live epoch yet). See
    /// [`keyset::send_key`].
    pub fn current_send_key(&self, zone: &str) -> Result<Option<ZoneKey>, SendKeyError> {
        self.keys
            .with_untracked(|m| keyset::send_key(m.values(), zone))
    }

    /// Every key held for `zone`, oldest epoch first, untracked.
    pub fn all_for_zone(&self, zone: &str) -> Vec<ZoneKey> {
        let mut v: Vec<ZoneKey> = self
            .keys
            .with_untracked(|m| m.values().filter(|k| k.zone == zone).cloned().collect());
        v.sort_by_key(|k| k.epoch);
        v
    }

    /// Highest-epoch key held for `zone`, tracked.
    pub fn latest_tracked(&self, zone: &str) -> Option<ZoneKey> {
        self.keys.with(|m| latest_in(m, zone))
    }

    /// Add a key (persisted), then re-decrypt anything waiting for it.
    /// Returns `false` when the key was already held.
    pub fn insert(&self, key: ZoneKey) -> bool {
        let id = key.store_id();
        if self.keys.with_untracked(|m| m.get(&id) == Some(&key)) {
            return false;
        }
        self.keys.update(|m| {
            m.insert(id, key.clone());
        });
        spawn_local(async move {
            if let Ok(db) = ForumDb::open().await {
                if db.put_zone_key(&key).await.is_err() {
                    web_sys::console::warn_1(&"[zone-key] persist failed (IndexedDB write)".into());
                }
            }
        });
        self.redecrypt();
        true
    }

    /// Turn an incoming kind-42 into what the reader should see. Events
    /// without a `zk` or `sealed` tag pass through untouched; zone-encrypted
    /// ones get their decrypted text or a placeholder, with the original event
    /// id, tags and signature kept. A sealed original that opens is replaced
    /// by the whole original event (its own id), so call this before any
    /// id-based dedupe or tombstone check that must see that id.
    pub fn prepare_incoming(&self, ev: NostrEvent) -> NostrEvent {
        if !is_zone_message(&ev) {
            return ev;
        }
        let ev = self
            .cache
            .try_update_value(|c| c.prepare(&ev, |z, e| self.lookup(z, e)))
            .unwrap_or_else(|| without_keys(&ev));
        let id = ev.id.clone();
        if !self.encrypted_ids.with_untracked(|s| s.contains(&id)) {
            self.encrypted_ids.update(|s| {
                s.insert(id);
            });
        }
        ev
    }

    /// Re-run decryption over every zone-encrypted message already in the
    /// channel store (a key just arrived). Sealed-original placeholders that
    /// now open become the original event in place; see
    /// [`ReadCache::redecrypt`].
    pub fn redecrypt(&self) {
        let channels = self.channels;
        if self.cache.with_value(ReadCache::is_empty) {
            self.revision.update(|r| *r += 1);
            return;
        }
        let store = *self;
        let mut restored_ids: Vec<String> = Vec::new();
        channels.channel_messages.update(|m| {
            store.cache.update_value(|c| {
                c.redecrypt(
                    m,
                    |z, e| store.lookup(z, e),
                    |id| !channels.is_message_deleted(id),
                );
                restored_ids = m
                    .values()
                    .flatten()
                    .filter(|ev| c.envelope_of(&ev.id).is_some())
                    .map(|ev| ev.id.clone())
                    .collect();
            });
        });
        let missing: Vec<String> = self.encrypted_ids.with_untracked(|s| {
            restored_ids
                .into_iter()
                .filter(|id| !s.contains(id))
                .collect()
        });
        if !missing.is_empty() {
            self.encrypted_ids.update(|s| s.extend(missing));
        }
        self.revision.update(|r| *r += 1);
    }

    /// Load keys and the processed-wrap set from IndexedDB.
    pub async fn hydrate(&self) {
        self.load_stored().await;
        let _ = self.hydrated.try_set(true);
    }

    async fn load_stored(&self) {
        let Ok(db) = ForumDb::open().await else {
            return;
        };
        // One-way: rewrite entries stored under the old "<zone>:<epoch>" id.
        if db.migrate_zone_keys().await.is_err() {
            web_sys::console::warn_1(&"[zone-key] store migration failed".into());
        }
        if let Ok(keys) = db.get_all_zone_keys().await {
            if !keys.is_empty() {
                self.keys.update(|m| {
                    for k in keys {
                        m.insert(k.store_id(), k);
                    }
                });
                self.redecrypt();
            }
        }
        if let Ok(Some(json)) = db.get_zone_kv(KV_PROCESSED).await {
            if let Ok(ids) = serde_json::from_str::<Vec<String>>(&json) {
                self.processed.update_value(|s| s.extend(ids));
            }
        }
        if let Ok(Some(json)) = db.get_zone_kv(KV_INBOX_GRANTED).await {
            if let Ok(ids) = serde_json::from_str::<Vec<String>>(&json) {
                self.inbox_granted.update_value(|s| s.extend(ids));
            }
        }
    }

    /// Subscribe to the member's gift wraps once the relay session is
    /// authenticated and pull zone-key grants out of them. Each wrap is
    /// unwrapped at most once per device (ids remembered in IndexedDB), so
    /// ordinary DMs are not re-decrypted on every visit.
    pub fn start_grant_sync(&self, relay: &RelayConnection, signer: Rc<dyn Signer>, me: String) {
        if self.sync_started.get_value() || me.len() != 64 {
            return;
        }
        self.sync_started.set_value(true);
        let store = *self;
        let on_event = {
            let (relay, signer, me) = (relay.clone(), signer.clone(), me.clone());
            Rc::new(move |ev: NostrEvent| {
                if ev.kind != nostr_bbs_core::gift_wrap::KIND_GIFT_WRAP {
                    return;
                }
                // With the sweep on, wraps already handled are looked at again
                // when addressed to the identity: an old grant is deleted once
                // its key is safe here.
                let revisit = grant_sweep_enabled() && p_tags(&ev).any(|p| p == me);
                if !revisit && store.processed.with_value(|s| s.contains(&ev.id)) {
                    return;
                }
                let (relay, signer, me) = (relay.clone(), signer.clone(), me.clone());
                super::public_inbox::sweep_wrap_started();
                spawn_local(async move {
                    store.process_wrap(&ev, &*signer, &me, &relay).await;
                    super::public_inbox::sweep_wrap_done(&me);
                });
            })
        };
        // The end of stored events on the identity subscription settles the
        // old-grant cleanup flag the public-inbox opt-in waits for.
        let eose_me = me.clone();
        relay.subscribe(
            vec![wrap_filter(subscription_targets(&me, None))],
            on_event.clone(),
            Some(Rc::new(move || super::public_inbox::sweep_eose(&eose_me))),
        );
        if !recipient_keys_enabled() {
            return;
        }
        // Inbox key: create, restore or confirm it, then listen on it too.
        // Grants may still arrive at the identity key during the transition,
        // which the subscription above keeps covering.
        let relay = relay.clone();
        spawn_local(async move {
            let port = LivePort {
                relay: relay.clone(),
                identity: signer.clone(),
            };
            match ensure_inbox_key(&port, &*signer, now_secs()).await {
                Ok(key) => {
                    store.inbox_sk.set_value(Some(key.sk_hex));
                    relay.subscribe(vec![wrap_filter(vec![key.pubkey])], on_event, None);
                }
                Err(e) => {
                    web_sys::console::warn_1(&format!("[zone-key] inbox key: {e}").into());
                }
            }
        });
    }

    async fn process_wrap(
        &self,
        wrap: &NostrEvent,
        signer: &dyn Signer,
        me: &str,
        relay: &RelayConnection,
    ) {
        let inbox = self
            .inbox_sk
            .get_value()
            .and_then(|sk| super::inbox_key::inbox_signer(&sk).ok());
        let inbox_ref = inbox.as_ref().map(|s| s as &dyn Signer);
        let inbox_pk = inbox.as_ref().map(|s| s.public_key().to_string());
        let via_inbox = inbox_pk
            .as_deref()
            .is_some_and(|ipk| p_tags(wrap).any(|p| p == ipk));
        let (sealer, rumor) = match unwrap_inbox_then_identity(wrap, inbox_ref, signer).await {
            Ok(v) => v,
            // Not for us to read (or the signer cannot NIP-44): leave it
            // unmarked so a later session with a capable signer retries.
            Err(_) => return,
        };
        match super::tickets::route(rumor.kind, super::tickets::zone_groups_enabled()) {
            super::tickets::Route::Grant => {}
            super::tickets::Route::Ignore => {
                self.mark_processed(&wrap.id).await;
                return;
            }
            super::tickets::Route::Ticket => {
                self.process_ticket(wrap, inbox_ref, signer, me, via_inbox)
                    .await;
                return;
            }
        }
        // A grant is marked processed only once its outcome is final. An
        // unreachable admin check or a key that did not reach IndexedDB leaves
        // the wrap unmarked, so the next session retries instead of losing the
        // key for good.
        let admin = self.sealer_is_admin(&sealer).await;
        let (valid, persisted, grant_id) = match admin {
            None => (false, false, None),
            Some(is_admin) => match validate_grant(&rumor, &sealer, is_admin, now_secs()) {
                Ok(key) => {
                    let id = super::key_id(&key.zone, key.epoch);
                    let persisted = self.insert_persisted(key).await;
                    if via_inbox && persisted {
                        self.mark_inbox_granted(&id).await;
                    }
                    (true, persisted, Some(id))
                }
                Err(e) => {
                    web_sys::console::warn_1(&format!("[zone-key] grant refused: {e}").into());
                    (false, false, None)
                }
            },
        };
        if super::grant_settled(admin, valid, persisted) {
            self.mark_processed(&wrap.id).await;
        }
        // Deleting the identity copy is safe only once the SAME (zone, epoch)
        // key has also arrived addressed to the inbox key on this device, so a
        // replacement provably exists on the relay. Local persistence alone is
        // not enough: a wiped IndexedDB would then have no copy left anywhere.
        let replacement_exists = grant_id
            .as_deref()
            .is_some_and(|id| self.inbox_granted.with_value(|s| s.contains(id)));
        let candidate = SweepCandidate {
            wrap_id: wrap.id.clone(),
            to_identity: p_tags(wrap).any(|p| p == me),
            is_grant: true,
            key_safe: valid && persisted && replacement_exists,
        };
        let doomed = sweep_targets(grant_sweep_enabled(), std::slice::from_ref(&candidate));
        if candidate.to_identity
            && candidate.is_grant
            && super::public_inbox::grant_blocks_cleanup(admin.is_some(), valid, !doomed.is_empty())
        {
            // Still waiting on its replacement key: cleanup is not finished.
            super::public_inbox::sweep_grant_left(me);
        }
        for id in doomed {
            let unsigned = deletion_for_wrap(me, &id, now_secs());
            if let Ok(del) = signer.sign_event(unsigned).await {
                relay.publish(&del);
            }
        }
    }

    /// Add a key and wait for it to reach IndexedDB. The key is usable this
    /// session either way; returns whether it was persisted.
    /// An NIP-171 epoch ticket (ADR-2028 decision 2): opened with its
    /// signature intact, accepted only from the zone's bound group identity,
    /// and stored as the same [`ZoneKey`] a 21453 grant yields. No admin
    /// check: the group identity is not an admin. Unloaded bindings leave the
    /// wrap unmarked so the next session retries; any other refusal is final.
    async fn process_ticket(
        &self,
        wrap: &NostrEvent,
        inbox: Option<&dyn Signer>,
        identity: &dyn Signer,
        me: &str,
        via_inbox: bool,
    ) {
        use super::tickets::{
            ensure_bindings_loaded, loaded_bindings, ticket_verdict, TicketVerdict,
        };
        if let Err(e) = ensure_bindings_loaded().await {
            web_sys::console::warn_1(&format!("[zone-key] bindings: {e}").into());
        }
        let opened = super::tickets::open_ticket(wrap, inbox, identity).await;
        match ticket_verdict(opened, me, loaded_bindings().as_ref(), now_secs()) {
            TicketVerdict::Retry => {}
            TicketVerdict::Refuse(why) => {
                web_sys::console::warn_1(&format!("[zone-key] ticket refused: {why}").into());
                self.mark_processed(&wrap.id).await;
            }
            TicketVerdict::Accept(key) => {
                let key = *key;
                let id = super::key_id(&key.zone, key.epoch);
                let persisted = self.insert_persisted(key).await;
                if via_inbox && persisted {
                    self.mark_inbox_granted(&id).await;
                }
                if persisted {
                    self.mark_processed(&wrap.id).await;
                }
            }
        }
    }

    async fn insert_persisted(&self, key: ZoneKey) -> bool {
        let persisted = match ForumDb::open().await {
            Ok(db) => match db.put_zone_key(&key).await {
                Ok(()) => true,
                Err(_) => {
                    web_sys::console::warn_1(&"[zone-key] persist failed (IndexedDB write)".into());
                    false
                }
            },
            Err(_) => false,
        };
        let id = key.store_id();
        if self.keys.with_untracked(|m| m.get(&id) != Some(&key)) {
            self.keys.update(|m| {
                m.insert(id, key);
            });
            self.redecrypt();
        }
        persisted
    }

    async fn mark_processed(&self, wrap_id: &str) {
        self.processed.update_value(|s| {
            s.insert(wrap_id.to_string());
        });
        let ids: Vec<String> = self.processed.with_value(|s| s.iter().cloned().collect());
        if let (Ok(db), Ok(json)) = (ForumDb::open().await, serde_json::to_string(&ids)) {
            let _ = db.put_zone_kv(KV_PROCESSED, &json).await;
        }
    }

    async fn mark_inbox_granted(&self, id: &str) {
        self.inbox_granted.update_value(|s| {
            s.insert(id.to_string());
        });
        let ids: Vec<String> = self
            .inbox_granted
            .with_value(|s| s.iter().cloned().collect());
        if let (Ok(db), Ok(json)) = (ForumDb::open().await, serde_json::to_string(&ids)) {
            let _ = db.put_zone_kv(KV_INBOX_GRANTED, &json).await;
        }
    }

    /// Whether `pubkey` is a relay admin, or `None` when the relay could not
    /// be asked. Only definite answers are cached (per session).
    pub async fn sealer_is_admin(&self, pubkey: &str) -> Option<bool> {
        if let Some(v) = self.admin_cache.with_value(|m| m.get(pubkey).copied()) {
            return Some(v);
        }
        let v = fetch_is_admin(pubkey).await?;
        self.admin_cache.update_value(|m| {
            m.insert(pubkey.to_string(), v);
        });
        Some(v)
    }

    /// Pubkeys this admin has granted `(zone, epoch)` to, on this device.
    pub async fn grants_sent(&self, zone: &str, epoch: u32) -> HashSet<String> {
        let ledger = self.grants.get_value();
        ledger.sent(&IdbGrantKv, zone, epoch).await
    }

    /// Members already granted `(zone, epoch)` at the key they would be
    /// granted at now (`targets`: member to recipient key; absent means the
    /// member's identity).
    pub async fn grants_sent_to(
        &self,
        zone: &str,
        epoch: u32,
        targets: &HashMap<String, String>,
    ) -> HashSet<String> {
        let ledger = self.grants.get_value();
        ledger.sent_to(&IdbGrantKv, zone, epoch, targets).await
    }

    /// Record that `(zone, epoch)` was granted to each `(member, recipient
    /// key)`. Safe to call
    /// concurrently: acks for one batch arrive together (see [`GrantLedger`]).
    pub async fn record_grants(&self, zone: &str, epoch: u32, recipients: &[(String, String)]) {
        let ledger = self.grants.get_value();
        ledger.record(&IdbGrantKv, zone, epoch, recipients).await;
    }
}

/// The grant ledger's storage: the `zone_kv` IndexedDB store.
struct IdbGrantKv;

impl GrantKv for IdbGrantKv {
    async fn get(&self, id: &str) -> Option<String> {
        ForumDb::open()
            .await
            .ok()?
            .get_zone_kv(id)
            .await
            .ok()
            .flatten()
    }

    async fn put(&self, id: &str, json: &str) -> bool {
        match ForumDb::open().await {
            Ok(db) => db.put_zone_kv(id, json).await.is_ok(),
            Err(_) => false,
        }
    }
}

fn wrap_filter(p: Vec<String>) -> Filter {
    Filter {
        kinds: Some(vec![nostr_bbs_core::gift_wrap::KIND_GIFT_WRAP]),
        p_tags: Some(p),
        ..Default::default()
    }
}

fn p_tags(ev: &NostrEvent) -> impl Iterator<Item = &str> {
    ev.tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == "p")
        .map(|t| t[1].as_str())
}

fn latest_in(m: &HashMap<String, ZoneKey>, zone: &str) -> Option<ZoneKey> {
    m.values()
        .filter(|k| k.zone == zone)
        .max_by_key(|k| k.epoch)
        .cloned()
}

async fn fetch_is_admin(pubkey: &str) -> Option<bool> {
    let url = format!(
        "{}/api/check-whitelist?pubkey={}",
        crate::utils::relay_url::relay_api_base(),
        pubkey
    );
    let win = web_sys::window()?;
    let resp: web_sys::Response = JsFuture::from(win.fetch_with_str(&url))
        .await
        .ok()?
        .dyn_into()
        .ok()?;
    if !resp.ok() {
        return None;
    }
    let text = JsFuture::from(resp.text().ok()?).await.ok()?.as_string()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("isAdmin").and_then(|b| b.as_bool())
}

// -- Context -----------------------------------------------------------------

/// Provide the zone-key store and load held keys. Call once at app root,
/// after the channel store and before channel sync starts.
pub fn provide_zone_key_store(channels: crate::stores::channels::ChannelStore) {
    let store = ZoneKeyStore::new(channels);
    provide_context(store);
    spawn_local(async move {
        store.hydrate().await;
    });
}

/// The zone-key store, if provided.
pub fn try_use_zone_key_store() -> Option<ZoneKeyStore> {
    use_context::<ZoneKeyStore>()
}

/// [`ZoneKeyStore::prepare_incoming`] for a store captured at subscription
/// time (relay callbacks have no reactive owner, so capture with
/// [`try_use_zone_key_store`] while setting the subscription up). Without a
/// store a zone-encrypted message still never renders as ciphertext: it
/// shows the missing-key placeholder.
pub fn prepare_incoming(store: Option<ZoneKeyStore>, ev: NostrEvent) -> NostrEvent {
    match store {
        Some(store) => store.prepare_incoming(ev),
        None if is_zone_message(&ev) => without_keys(&ev),
        None => ev,
    }
}

/// The read path with no keys at all: a zone-encrypted message or sealed
/// envelope shows the missing-key placeholder under its own id.
fn without_keys(ev: &NostrEvent) -> NostrEvent {
    resolve_event(ev, read_outcome(ev, |_, _| None))
}

/// Encrypted-zone lookup for a channel: `(zone id, display name, encrypted)`,
/// resolved through the channel's section tag and `ZONE_CONFIG`.
pub fn channel_zone(
    channels: crate::stores::channels::ChannelStore,
    channel_id: &str,
) -> Option<(String, String, bool)> {
    let section = channels.channels.with_untracked(|list| {
        list.iter()
            .find(|c| c.id == channel_id)
            .map(|c| c.section.clone())
    })?;
    let zones = crate::stores::zones::load_zones();
    let zone_id = crate::stores::zones::section_to_zone(&section, &zones)?;
    let zone = zones.iter().find(|z| z.id == zone_id)?;
    Some((
        zone.id.clone(),
        zone.display_name.clone(),
        super::zone_is_encrypted(super::encryption_enabled(), zone.encrypted),
    ))
}

/// Apply the zone write rules to an outgoing kind-42 for `channel_id`:
/// encrypt when the channel's zone is encrypted, refuse when the member has
/// no key, pass through otherwise. Every kind-42 publish path calls this
/// immediately before signing.
///
/// `keys` and `channels` are captured by the caller while it is still inside
/// a reactive owner (component setup), because publish paths run in spawned
/// tasks where `use_context` is unavailable.
pub async fn prepare_outgoing(
    keys: Option<ZoneKeyStore>,
    channels: crate::stores::channels::ChannelStore,
    channel_id: &str,
    signer: Option<Rc<dyn Signer>>,
    unsigned: nostr_bbs_core::UnsignedEvent,
) -> Result<nostr_bbs_core::UnsignedEvent, String> {
    let Some((zone_id, display, encrypted)) = channel_zone(channels, channel_id) else {
        return Ok(unsigned);
    };
    let latest = match keys {
        Some(s) => s.current_send_key(&zone_id).map_err(|e| e.to_string())?,
        None => None,
    };
    let plan = super::write_plan(encrypted, &display, latest)?;
    if plan == super::WritePlan::Plain {
        return Ok(unsigned);
    }
    let signer = signer.ok_or("Sign in to post in an encrypted zone.")?;
    super::apply_write_plan(&plan, &*signer, unsigned).await
}

/// The two stores a kind-42 publish path needs, captured together while the
/// caller is still inside a reactive owner (component setup). `Copy`, so it
/// moves freely into the spawned publish task.
#[derive(Clone, Copy)]
pub struct ZoneWriter {
    keys: Option<ZoneKeyStore>,
    channels: Option<crate::stores::channels::ChannelStore>,
}

impl ZoneWriter {
    /// Capture from context. Call during component setup, not in a task.
    pub fn capture() -> Self {
        Self {
            keys: try_use_zone_key_store(),
            channels: use_context::<crate::stores::channels::ChannelStore>(),
        }
    }

    /// [`prepare_outgoing`] for `channel_id`. Without a channel store the
    /// event passes through; the relay still refuses plaintext in an
    /// encrypted zone.
    pub async fn prepare(
        &self,
        channel_id: &str,
        signer: Option<Rc<dyn Signer>>,
        unsigned: nostr_bbs_core::UnsignedEvent,
    ) -> Result<nostr_bbs_core::UnsignedEvent, String> {
        match self.channels {
            Some(channels) => {
                prepare_outgoing(self.keys, channels, channel_id, signer, unsigned).await
            }
            None => Ok(unsigned),
        }
    }
}
