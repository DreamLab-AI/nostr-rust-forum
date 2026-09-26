//! Reactive zone-key store (ADR-2016).
//!
//! Holds the zone keys this device knows, persists them in IndexedDB, pulls
//! key grants out of the member's gift wraps, and is the single place a
//! zone-encrypted kind-42 is turned into readable text on its way into the
//! [`ChannelStore`](crate::stores::channels::ChannelStore).

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use leptos::prelude::*;
use nostr_bbs_core::signer::Signer;
use nostr_bbs_core::NostrEvent;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};

use super::{display_text, has_zk_tag, read_outcome, validate_grant, ZoneKey, KIND_ZONE_KEY_GRANT};
use crate::relay::{Filter, RelayConnection};
use crate::stores::indexed_db::ForumDb;

/// `zone_kv` id holding the ids of gift wraps already unwrapped here.
const KV_PROCESSED: &str = "processed_wraps";
/// `zone_kv` id prefix for "grants this admin sent": `grants_sent:<zone>:<epoch>`.
const KV_GRANTS_SENT: &str = "grants_sent";

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Zone keys and the per-message decryption state.
#[derive(Clone, Copy)]
pub struct ZoneKeyStore {
    /// Keys by `"<zone>:<epoch>"`.
    pub keys: RwSignal<HashMap<String, ZoneKey>>,
    /// Bumped whenever keys change or messages are re-decrypted.
    pub revision: RwSignal<u64>,
    /// Ids of zone-encrypted kind-42s (decrypted or not). Views use this to
    /// keep link previews off: a preview would send the URL to the preview
    /// worker, outside the zone.
    pub encrypted_ids: RwSignal<HashSet<String>>,
    /// Original ciphertext of each zone-encrypted kind-42 seen, by event id,
    /// so a key that arrives later can decrypt what is already on screen.
    ciphertexts: StoredValue<HashMap<String, String>>,
    processed: StoredValue<HashSet<String>>,
    admin_cache: StoredValue<HashMap<String, bool>>,
    sync_started: StoredValue<bool>,
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
            ciphertexts: StoredValue::new(HashMap::new()),
            processed: StoredValue::new(HashSet::new()),
            admin_cache: StoredValue::new(HashMap::new()),
            sync_started: StoredValue::new(false),
        }
    }

    /// Key for `(zone, epoch)`, untracked.
    pub fn lookup(&self, zone: &str, epoch: u32) -> Option<ZoneKey> {
        self.keys
            .with_untracked(|m| m.get(&super::key_id(zone, epoch)).cloned())
    }

    /// Highest-epoch key held for `zone`, untracked.
    pub fn latest(&self, zone: &str) -> Option<ZoneKey> {
        self.keys.with_untracked(|m| latest_in(m, zone))
    }

    /// Highest-epoch key held for `zone`, tracked.
    pub fn latest_tracked(&self, zone: &str) -> Option<ZoneKey> {
        self.keys.with(|m| latest_in(m, zone))
    }

    /// Add a key (persisted), then re-decrypt anything waiting for it.
    /// Returns `false` when the key was already held.
    pub fn insert(&self, key: ZoneKey) -> bool {
        let id = key.id();
        if self.keys.with_untracked(|m| m.get(&id) == Some(&key)) {
            return false;
        }
        self.keys.update(|m| {
            m.insert(id, key.clone());
        });
        spawn_local(async move {
            if let Ok(db) = ForumDb::open().await {
                if let Err(e) = db.put_zone_key(&key).await {
                    web_sys::console::warn_1(&format!("[zone-key] persist failed: {e:?}").into());
                }
            }
        });
        self.redecrypt();
        true
    }

    /// Turn an incoming kind-42 into what the reader should see. Events
    /// without a `zk` tag pass through untouched; zone-encrypted ones get
    /// their decrypted text or a placeholder, with the original event id,
    /// tags and signature kept.
    pub fn prepare_incoming(&self, mut ev: NostrEvent) -> NostrEvent {
        if ev.kind != 42 || !has_zk_tag(&ev.tags) {
            return ev;
        }
        let id = ev.id.clone();
        self.ciphertexts.update_value(|m| {
            m.entry(id.clone()).or_insert_with(|| ev.content.clone());
        });
        let outcome = read_outcome(&ev, |z, e| self.lookup(z, e));
        ev.content = display_text(&outcome, &ev.content);
        if !self.encrypted_ids.with_untracked(|s| s.contains(&id)) {
            self.encrypted_ids.update(|s| {
                s.insert(id);
            });
        }
        ev
    }

    /// Re-run decryption over every zone-encrypted message already in the
    /// channel store (a key just arrived).
    pub fn redecrypt(&self) {
        let channels = self.channels;
        let cts = self.ciphertexts.get_value();
        if cts.is_empty() {
            self.revision.update(|r| *r += 1);
            return;
        }
        let store = *self;
        channels.channel_messages.update(|m| {
            for events in m.values_mut() {
                for ev in events.iter_mut() {
                    if let Some(ct) = cts.get(&ev.id) {
                        let mut original = ev.clone();
                        original.content = ct.clone();
                        let outcome = read_outcome(&original, |z, e| store.lookup(z, e));
                        ev.content = display_text(&outcome, ct);
                    }
                }
            }
        });
        self.revision.update(|r| *r += 1);
    }

    /// Load keys and the processed-wrap set from IndexedDB.
    pub async fn hydrate(&self) {
        let Ok(db) = ForumDb::open().await else {
            return;
        };
        if let Ok(keys) = db.get_all_zone_keys().await {
            if !keys.is_empty() {
                self.keys.update(|m| {
                    for k in keys {
                        m.insert(k.id(), k);
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
        let on_event = Rc::new(move |ev: NostrEvent| {
            if ev.kind != nostr_bbs_core::gift_wrap::KIND_GIFT_WRAP {
                return;
            }
            if store.processed.with_value(|s| s.contains(&ev.id)) {
                return;
            }
            let signer = signer.clone();
            spawn_local(async move {
                store.process_wrap(&ev, &*signer).await;
            });
        });
        relay.subscribe(
            vec![Filter {
                kinds: Some(vec![nostr_bbs_core::gift_wrap::KIND_GIFT_WRAP]),
                p_tags: Some(vec![me]),
                ..Default::default()
            }],
            on_event,
            None,
        );
    }

    async fn process_wrap(&self, wrap: &NostrEvent, signer: &dyn Signer) {
        let (sealer, rumor) = match super::unwrap_any(wrap, signer).await {
            Ok(v) => v,
            // Not for us to read (or the signer cannot NIP-44): leave it
            // unmarked so a later session with a capable signer retries.
            Err(_) => return,
        };
        self.mark_processed(&wrap.id).await;
        if rumor.kind != KIND_ZONE_KEY_GRANT {
            return;
        }
        let is_admin = self.sealer_is_admin(&sealer).await;
        match validate_grant(&rumor, &sealer, is_admin, now_secs()) {
            Ok(key) => {
                self.insert(key);
            }
            Err(e) => {
                web_sys::console::warn_1(&format!("[zone-key] grant refused: {e}").into());
            }
        }
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

    /// Whether `pubkey` is a relay admin (cached per session).
    pub async fn sealer_is_admin(&self, pubkey: &str) -> bool {
        if let Some(v) = self.admin_cache.with_value(|m| m.get(pubkey).copied()) {
            return v;
        }
        let v = fetch_is_admin(pubkey).await.unwrap_or(false);
        self.admin_cache.update_value(|m| {
            m.insert(pubkey.to_string(), v);
        });
        v
    }

    /// Pubkeys this admin has granted `(zone, epoch)` to, on this device.
    pub async fn grants_sent(&self, zone: &str, epoch: u32) -> HashSet<String> {
        let id = format!("{KV_GRANTS_SENT}:{zone}:{epoch}");
        match ForumDb::open().await {
            Ok(db) => db
                .get_zone_kv(&id)
                .await
                .ok()
                .flatten()
                .and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok())
                .map(|v| v.into_iter().collect())
                .unwrap_or_default(),
            Err(_) => HashSet::new(),
        }
    }

    /// Record that `(zone, epoch)` was granted to `recipients`.
    pub async fn record_grants(&self, zone: &str, epoch: u32, recipients: &[String]) {
        let mut all = self.grants_sent(zone, epoch).await;
        all.extend(recipients.iter().cloned());
        let mut v: Vec<String> = all.into_iter().collect();
        v.sort();
        let id = format!("{KV_GRANTS_SENT}:{zone}:{epoch}");
        if let (Ok(db), Ok(json)) = (ForumDb::open().await, serde_json::to_string(&v)) {
            let _ = db.put_zone_kv(&id, &json).await;
        }
    }
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
        None => {
            if ev.kind == 42 && has_zk_tag(&ev.tags) {
                let mut ev = ev;
                let outcome = read_outcome(&ev, |_, _| None);
                ev.content = display_text(&outcome, &ev.content);
                ev
            } else {
                ev
            }
        }
    }
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
    let latest = keys.and_then(|s| s.latest(&zone_id));
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
