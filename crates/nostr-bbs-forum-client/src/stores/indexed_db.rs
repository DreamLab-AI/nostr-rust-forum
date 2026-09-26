//! IndexedDB persistence layer for offline-first forum data.
//!
//! Wraps the `web_sys` IDB API with async Rust methods for storing messages,
//! profiles, deletions, and an outgoing event queue (outbox). Schema defined
//! in ADR-021.
//!
//! Object stores:
//! - `messages`  — key `event_id`, compound index `channel_created` on `[channel_id, created_at]`
//! - `channels`  — key `channel_id`, index `section` on `section_id`
//! - `profiles`  — key `pubkey`, index `updated` on `updated_at`
//! - `deletions` — key `event_id`, index `target` on `target_id`
//! - `outbox`    — autoIncrement key, index `created` on `created_at`
//! - `zone_keys` — key `id` (`"<zone>:<epoch>"`), zone end-to-end encryption keys (ADR-2016)
//! - `zone_kv`   — key `id`, small JSON values for zone encryption bookkeeping
//!   (processed gift-wrap ids, grants this admin has sent)

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{
    IdbDatabase, IdbKeyRange, IdbObjectStoreParameters, IdbOpenDbRequest, IdbRequest,
    IdbTransactionMode,
};

const DB_NAME: &str = "members-forum";
/// v2 adds `zone_keys` and `zone_kv` (ADR-2016). Upgrades only ADD stores.
const DB_VERSION: u32 = 2;

const STORE_MESSAGES: &str = "messages";
const STORE_CHANNELS: &str = "channels";
const STORE_PROFILES: &str = "profiles";
const STORE_DELETIONS: &str = "deletions";
const STORE_OUTBOX: &str = "outbox";
const STORE_ZONE_KEYS: &str = "zone_keys";
const STORE_ZONE_KV: &str = "zone_kv";

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedMessage {
    pub event_id: String,
    pub channel_id: String,
    pub pubkey: String,
    pub content: String,
    pub created_at: u64,
    pub tags: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedProfile {
    pub pubkey: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub about: Option<String>,
    pub updated_at: u64,
}

/// A zone key at rest: the key's fields plus its storage id
/// (`"<zone>:<epoch>"`), the store's key path.
///
/// The fields are spelled out rather than `#[serde(flatten)]`ed from
/// [`ZoneKey`](crate::zone_crypto::ZoneKey): `serde_wasm_bindgen` serialises a
/// flattened struct as a JS `Map`, which has no `id` property, so IndexedDB
/// rejects the `put` ("key path did not yield a value") and the key is lost.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoredZoneKey {
    pub id: String,
    pub zone: String,
    pub epoch: u32,
    pub secret: String,
    pub pubkey: String,
    pub granted_by: String,
    pub received_at: u64,
}

impl From<&crate::zone_crypto::ZoneKey> for StoredZoneKey {
    fn from(k: &crate::zone_crypto::ZoneKey) -> Self {
        Self {
            id: k.id(),
            zone: k.zone.clone(),
            epoch: k.epoch,
            secret: k.secret.clone(),
            pubkey: k.pubkey.clone(),
            granted_by: k.granted_by.clone(),
            received_at: k.received_at,
        }
    }
}

impl From<StoredZoneKey> for crate::zone_crypto::ZoneKey {
    fn from(r: StoredZoneKey) -> Self {
        Self {
            zone: r.zone,
            epoch: r.epoch,
            secret: r.secret,
            pubkey: r.pubkey,
            granted_by: r.granted_by,
            received_at: r.received_at,
        }
    }
}

/// A small JSON value in `zone_kv`.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ZoneKvRecord {
    id: String,
    value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedDeletion {
    event_id: String,
    target_id: String,
}

// ---------------------------------------------------------------------------
// IDB helpers
// ---------------------------------------------------------------------------

/// Convert an `IdbRequest` into a `Future` that resolves when `onsuccess` fires.
async fn idb_request_result(request: &IdbRequest) -> Result<JsValue, JsValue> {
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let req_ref = request.clone();
        let rej_clone = reject.clone();

        let on_success = Closure::once(move |_: web_sys::Event| {
            let result = req_ref.result().unwrap_or(JsValue::UNDEFINED);
            let _ = resolve.call1(&JsValue::NULL, &result);
        });
        let req_ref2 = request.clone();
        let on_error = Closure::once(move |_: web_sys::Event| {
            let err = req_ref2
                .error()
                .ok()
                .flatten()
                .map(JsValue::from)
                .unwrap_or_else(|| JsValue::from_str("IDB request failed"));
            let _ = rej_clone.call1(&JsValue::NULL, &err);
        });

        request.set_onsuccess(Some(on_success.as_ref().unchecked_ref()));
        request.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        on_success.forget();
        on_error.forget();
    });

    wasm_bindgen_futures::JsFuture::from(promise).await
}

/// Convert an `IdbOpenDbRequest` into a `Future`, running `on_upgrade` during
/// the `onupgradeneeded` event.
async fn open_db_request(
    request: &IdbOpenDbRequest,
    on_upgrade: impl FnOnce(&IdbDatabase) + 'static,
) -> Result<IdbDatabase, JsValue> {
    let upgrade_closure = Closure::once(move |event: web_sys::Event| {
        let Some(target) = event.target() else {
            web_sys::console::warn_1(&"IndexedDB upgrade: missing event target".into());
            return;
        };
        let Ok(open_req) = target.dyn_into::<web_sys::IdbOpenDbRequest>() else {
            web_sys::console::warn_1(&"IndexedDB upgrade: target is not IdbOpenDbRequest".into());
            return;
        };
        let Ok(result) = open_req.result() else {
            web_sys::console::warn_1(
                &"IndexedDB upgrade: could not get result from request".into(),
            );
            return;
        };
        let Ok(db) = result.dyn_into::<IdbDatabase>() else {
            web_sys::console::warn_1(&"IndexedDB upgrade: result is not IdbDatabase".into());
            return;
        };
        on_upgrade(&db);
    });
    request.set_onupgradeneeded(Some(upgrade_closure.as_ref().unchecked_ref()));
    upgrade_closure.forget();

    let result = idb_request_result(request.as_ref()).await?;
    result
        .dyn_into::<IdbDatabase>()
        .map_err(|_| JsValue::from_str("open() did not return IdbDatabase"))
}

fn to_js<T: Serialize>(val: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(val).map_err(|e| JsValue::from_str(&e.to_string()))
}

fn from_js<T: for<'de> Deserialize<'de>>(val: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(val).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ---------------------------------------------------------------------------
// ForumDb
// ---------------------------------------------------------------------------

/// IndexedDB abstraction for offline forum data.
#[derive(Clone)]
pub struct ForumDb {
    db: IdbDatabase,
}

impl ForumDb {
    /// Open (or create) the `members-forum` IndexedDB database.
    pub async fn open() -> Result<Self, JsValue> {
        let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
        let idb_factory = window
            .indexed_db()?
            .ok_or_else(|| JsValue::from_str("IndexedDB not available"))?;

        let request = idb_factory.open_with_u32(DB_NAME, DB_VERSION)?;

        let db = open_db_request(&request, |db| {
            // Helper: log a warning and continue if store/index creation fails.
            // The `onupgradeneeded` callback cannot propagate errors, so we log
            // and degrade gracefully — missing stores will surface as errors on
            // later read/write attempts, which all return `Result`.
            macro_rules! try_idb {
                ($expr:expr, $msg:literal) => {
                    match $expr {
                        Ok(v) => v,
                        Err(e) => {
                            web_sys::console::warn_1(
                                &format!(concat!("IndexedDB schema: ", $msg, ": {:?}"), e).into(),
                            );
                            return;
                        }
                    }
                };
            }

            // --- messages ---
            if !db.object_store_names().contains(STORE_MESSAGES) {
                let params = IdbObjectStoreParameters::new();
                params.set_key_path(&JsValue::from_str("event_id"));
                let store = try_idb!(
                    db.create_object_store_with_optional_parameters(STORE_MESSAGES, &params),
                    "failed to create messages store"
                );
                let key_path = js_sys::Array::new();
                key_path.push(&JsValue::from_str("channel_id"));
                key_path.push(&JsValue::from_str("created_at"));
                if let Err(e) = store.create_index_with_str_sequence("channel_created", &key_path) {
                    web_sys::console::warn_1(
                        &format!("IndexedDB schema: messages index failed: {:?}", e).into(),
                    );
                }
            }

            // --- channels ---
            if !db.object_store_names().contains(STORE_CHANNELS) {
                let params = IdbObjectStoreParameters::new();
                params.set_key_path(&JsValue::from_str("channel_id"));
                let store = try_idb!(
                    db.create_object_store_with_optional_parameters(STORE_CHANNELS, &params),
                    "failed to create channels store"
                );
                if let Err(e) = store.create_index_with_str("section", "section_id") {
                    web_sys::console::warn_1(
                        &format!("IndexedDB schema: channels index failed: {:?}", e).into(),
                    );
                }
            }

            // --- profiles ---
            if !db.object_store_names().contains(STORE_PROFILES) {
                let params = IdbObjectStoreParameters::new();
                params.set_key_path(&JsValue::from_str("pubkey"));
                let store = try_idb!(
                    db.create_object_store_with_optional_parameters(STORE_PROFILES, &params),
                    "failed to create profiles store"
                );
                if let Err(e) = store.create_index_with_str("updated", "updated_at") {
                    web_sys::console::warn_1(
                        &format!("IndexedDB schema: profiles index failed: {:?}", e).into(),
                    );
                }
            }

            // --- deletions ---
            if !db.object_store_names().contains(STORE_DELETIONS) {
                let params = IdbObjectStoreParameters::new();
                params.set_key_path(&JsValue::from_str("event_id"));
                let store = try_idb!(
                    db.create_object_store_with_optional_parameters(STORE_DELETIONS, &params),
                    "failed to create deletions store"
                );
                if let Err(e) = store.create_index_with_str("target", "target_id") {
                    web_sys::console::warn_1(
                        &format!("IndexedDB schema: deletions index failed: {:?}", e).into(),
                    );
                }
            }

            // --- outbox ---
            if !db.object_store_names().contains(STORE_OUTBOX) {
                let params = IdbObjectStoreParameters::new();
                params.set_auto_increment(true);
                let store = try_idb!(
                    db.create_object_store_with_optional_parameters(STORE_OUTBOX, &params),
                    "failed to create outbox store"
                );
                if let Err(e) = store.create_index_with_str("created", "created_at") {
                    web_sys::console::warn_1(
                        &format!("IndexedDB schema: outbox index failed: {:?}", e).into(),
                    );
                }
            }

            // --- zone_keys / zone_kv (v2, ADR-2016) ---
            for name in [STORE_ZONE_KEYS, STORE_ZONE_KV] {
                if !db.object_store_names().contains(name) {
                    let params = IdbObjectStoreParameters::new();
                    params.set_key_path(&JsValue::from_str("id"));
                    try_idb!(
                        db.create_object_store_with_optional_parameters(name, &params),
                        "failed to create zone store"
                    );
                }
            }
        })
        .await?;

        Ok(Self { db })
    }

    // -- Zone keys (ADR-2016) ------------------------------------------------

    /// Store (or replace) a zone key.
    pub async fn put_zone_key(&self, key: &crate::zone_crypto::ZoneKey) -> Result<(), JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_ZONE_KEYS, IdbTransactionMode::Readwrite)?;
        let store = tx.object_store(STORE_ZONE_KEYS)?;
        let rec = StoredZoneKey::from(key);
        let req = store.put(&to_js(&rec)?)?;
        idb_request_result(&req).await?;
        Ok(())
    }

    /// Every zone key held on this device.
    pub async fn get_all_zone_keys(&self) -> Result<Vec<crate::zone_crypto::ZoneKey>, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_ZONE_KEYS, IdbTransactionMode::Readonly)?;
        let store = tx.object_store(STORE_ZONE_KEYS)?;
        let req = store.get_all()?;
        let result = idb_request_result(&req).await?;
        let arr: js_sys::Array = result.dyn_into().unwrap_or_else(|_| js_sys::Array::new());
        Ok((0..arr.length())
            .filter_map(|i| from_js::<StoredZoneKey>(arr.get(i)).ok())
            .map(crate::zone_crypto::ZoneKey::from)
            .collect())
    }

    /// Write a small JSON value to `zone_kv`.
    pub async fn put_zone_kv(&self, id: &str, value: &str) -> Result<(), JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_ZONE_KV, IdbTransactionMode::Readwrite)?;
        let store = tx.object_store(STORE_ZONE_KV)?;
        let rec = ZoneKvRecord {
            id: id.to_string(),
            value: value.to_string(),
        };
        let req = store.put(&to_js(&rec)?)?;
        idb_request_result(&req).await?;
        Ok(())
    }

    /// Read a `zone_kv` value.
    pub async fn get_zone_kv(&self, id: &str) -> Result<Option<String>, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_ZONE_KV, IdbTransactionMode::Readonly)?;
        let store = tx.object_store(STORE_ZONE_KV)?;
        let req = store.get(&JsValue::from_str(id))?;
        let result = idb_request_result(&req).await?;
        if result.is_undefined() || result.is_null() {
            return Ok(None);
        }
        Ok(Some(from_js::<ZoneKvRecord>(result)?.value))
    }

    // -- Messages -----------------------------------------------------------

    /// Insert or update a cached message.
    pub async fn put_message(&self, msg: &CachedMessage) -> Result<(), JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_MESSAGES, IdbTransactionMode::Readwrite)?;
        let store = tx.object_store(STORE_MESSAGES)?;
        let js_val = to_js(msg)?;
        let req = store.put(&js_val)?;
        idb_request_result(&req).await?;
        Ok(())
    }

    /// Retrieve messages for a channel ordered by `created_at`, limited to
    /// `limit` most recent entries.
    pub async fn get_channel_messages(
        &self,
        channel_id: &str,
        limit: u32,
    ) -> Result<Vec<CachedMessage>, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_MESSAGES, IdbTransactionMode::Readonly)?;
        let store = tx.object_store(STORE_MESSAGES)?;
        let index = store.index("channel_created")?;

        // IDBKeyRange.bound([channel_id, 0], [channel_id, Infinity])
        let lower = js_sys::Array::new();
        lower.push(&JsValue::from_str(channel_id));
        lower.push(&JsValue::from_f64(0.0));
        let upper = js_sys::Array::new();
        upper.push(&JsValue::from_str(channel_id));
        upper.push(&JsValue::from_f64(f64::MAX));
        let range = IdbKeyRange::bound(&lower, &upper)?;

        let req = index.get_all_with_key_and_limit(&range, limit)?;
        let result = idb_request_result(&req).await?;

        let arr: js_sys::Array = result.dyn_into().unwrap_or_else(|_| js_sys::Array::new());
        let mut messages: Vec<CachedMessage> = Vec::with_capacity(arr.length() as usize);
        for i in 0..arr.length() {
            if let Ok(msg) = from_js::<CachedMessage>(arr.get(i)) {
                messages.push(msg);
            }
        }
        Ok(messages)
    }

    // -- Profiles -----------------------------------------------------------

    /// Insert or update a cached profile.
    pub async fn put_profile(&self, profile: &CachedProfile) -> Result<(), JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_PROFILES, IdbTransactionMode::Readwrite)?;
        let store = tx.object_store(STORE_PROFILES)?;
        let js_val = to_js(profile)?;
        let req = store.put(&js_val)?;
        idb_request_result(&req).await?;
        Ok(())
    }

    /// Retrieve a cached profile by pubkey.
    pub async fn get_profile(&self, pubkey: &str) -> Result<Option<CachedProfile>, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_PROFILES, IdbTransactionMode::Readonly)?;
        let store = tx.object_store(STORE_PROFILES)?;
        let req = store.get(&JsValue::from_str(pubkey))?;
        let result = idb_request_result(&req).await?;
        if result.is_undefined() || result.is_null() {
            return Ok(None);
        }
        Ok(Some(from_js::<CachedProfile>(result)?))
    }

    /// Retrieve all cached profiles. Used to warm-start the in-memory profile
    /// cache on app boot so nicknames render synchronously without waiting
    /// for the network.
    pub async fn get_all_profiles(&self) -> Result<Vec<CachedProfile>, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_PROFILES, IdbTransactionMode::Readonly)?;
        let store = tx.object_store(STORE_PROFILES)?;
        let req = store.get_all()?;
        let result = idb_request_result(&req).await?;
        let arr: js_sys::Array = result.dyn_into().unwrap_or_else(|_| js_sys::Array::new());
        let mut profiles: Vec<CachedProfile> = Vec::with_capacity(arr.length() as usize);
        for i in 0..arr.length() {
            if let Ok(p) = from_js::<CachedProfile>(arr.get(i)) {
                profiles.push(p);
            }
        }
        Ok(profiles)
    }

    /// Bulk-insert cached profiles in a single transaction. Used when
    /// hydrating the profile cache from a batch fetch response.
    pub async fn put_profiles(&self, profiles: &[CachedProfile]) -> Result<(), JsValue> {
        if profiles.is_empty() {
            return Ok(());
        }
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_PROFILES, IdbTransactionMode::Readwrite)?;
        let store = tx.object_store(STORE_PROFILES)?;
        for profile in profiles {
            let js_val = to_js(profile)?;
            let req = store.put(&js_val)?;
            idb_request_result(&req).await?;
        }
        Ok(())
    }

    // -- Outbox (offline queue) ---------------------------------------------

    /// Queue an outgoing event for later publishing when connectivity returns.
    pub async fn queue_outgoing(&self, event: &serde_json::Value) -> Result<(), JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_OUTBOX, IdbTransactionMode::Readwrite)?;
        let store = tx.object_store(STORE_OUTBOX)?;

        // Wrap with a created_at for indexing
        let wrapper = serde_json::json!({
            "created_at": js_sys::Date::now() / 1000.0,
            "event": event,
        });
        let js_val = to_js(&wrapper)?;
        let req = store.add(&js_val)?;
        idb_request_result(&req).await?;
        Ok(())
    }

    /// Drain all queued outgoing events, removing them from the store.
    /// Returns the events in insertion order.
    pub async fn drain_outbox(&self) -> Result<Vec<serde_json::Value>, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_OUTBOX, IdbTransactionMode::Readwrite)?;
        let store = tx.object_store(STORE_OUTBOX)?;

        // Read all
        let req = store.get_all()?;
        let result = idb_request_result(&req).await?;
        let arr: js_sys::Array = result.dyn_into().unwrap_or_else(|_| js_sys::Array::new());

        let mut events: Vec<serde_json::Value> = Vec::with_capacity(arr.length() as usize);
        for i in 0..arr.length() {
            if let Ok(wrapper) = from_js::<serde_json::Value>(arr.get(i)) {
                if let Some(event) = wrapper.get("event") {
                    events.push(event.clone());
                }
            }
        }

        // Clear the store
        let clear_req = store.clear()?;
        idb_request_result(&clear_req).await?;

        Ok(events)
    }

    // -- Deletions ----------------------------------------------------------

    /// Record a deletion event (event_id that was deleted, target_id it deletes).
    pub async fn put_deletion(&self, event_id: &str, target_id: &str) -> Result<(), JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_DELETIONS, IdbTransactionMode::Readwrite)?;
        let store = tx.object_store(STORE_DELETIONS)?;
        let val = to_js(&CachedDeletion {
            event_id: event_id.to_string(),
            target_id: target_id.to_string(),
        })?;
        let req = store.put(&val)?;
        idb_request_result(&req).await?;
        Ok(())
    }

    /// Check if an event has been deleted.
    pub async fn is_deleted(&self, event_id: &str) -> Result<bool, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_DELETIONS, IdbTransactionMode::Readonly)?;
        let store = tx.object_store(STORE_DELETIONS)?;
        let index = store.index("target")?;
        let req = index.get(&JsValue::from_str(event_id))?;
        let result = idb_request_result(&req).await?;
        Ok(!result.is_undefined() && !result.is_null())
    }

    // -- Eviction -----------------------------------------------------------

    /// Remove messages older than `max_age_secs` from the messages store.
    /// Returns the number of evicted entries.
    pub async fn evict_old(&self, max_age_secs: u64) -> Result<u32, JsValue> {
        let cutoff = (js_sys::Date::now() / 1000.0) as u64 - max_age_secs;

        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_MESSAGES, IdbTransactionMode::Readwrite)?;
        let store = tx.object_store(STORE_MESSAGES)?;

        // Get all messages, filter old ones, delete them
        let req = store.get_all()?;
        let result = idb_request_result(&req).await?;
        let arr: js_sys::Array = result.dyn_into().unwrap_or_else(|_| js_sys::Array::new());

        let mut evicted = 0u32;
        for i in 0..arr.length() {
            if let Ok(msg) = from_js::<CachedMessage>(arr.get(i)) {
                if msg.created_at < cutoff {
                    let del_req = store.delete(&JsValue::from_str(&msg.event_id))?;
                    idb_request_result(&del_req).await?;
                    evicted += 1;
                }
            }
        }

        Ok(evicted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone_crypto::ZoneKey;
    use serde::ser::{self, Impossible, Serializer};

    /// Reports how a value serialises at the top level: `serde_wasm_bindgen`
    /// turns a struct into a plain JS object but a map (which is what
    /// `#[serde(flatten)]` produces) into a JS `Map`, and IndexedDB's key path
    /// only sees object properties.
    struct TopLevelShape;

    #[derive(Debug)]
    struct Shape(&'static str);
    impl std::fmt::Display for Shape {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for Shape {}
    impl ser::Error for Shape {
        fn custom<T: std::fmt::Display>(_: T) -> Self {
            Shape("other")
        }
    }

    struct Fields;
    impl ser::SerializeStruct for Fields {
        type Ok = &'static str;
        type Error = Shape;
        fn serialize_field<T: ?Sized + Serialize>(
            &mut self,
            _: &'static str,
            _: &T,
        ) -> Result<(), Shape> {
            Ok(())
        }
        fn end(self) -> Result<&'static str, Shape> {
            Ok("struct")
        }
    }

    macro_rules! not_struct {
        ($($m:ident($($t:ty),*)),*) => {$(
            fn $m(self, $(_: $t),*) -> Result<&'static str, Shape> { Err(Shape("not a struct")) }
        )*};
    }

    impl Serializer for TopLevelShape {
        type Ok = &'static str;
        type Error = Shape;
        type SerializeSeq = Impossible<&'static str, Shape>;
        type SerializeTuple = Impossible<&'static str, Shape>;
        type SerializeTupleStruct = Impossible<&'static str, Shape>;
        type SerializeTupleVariant = Impossible<&'static str, Shape>;
        type SerializeMap = Impossible<&'static str, Shape>;
        type SerializeStruct = Fields;
        type SerializeStructVariant = Impossible<&'static str, Shape>;

        fn serialize_struct(self, _: &'static str, _: usize) -> Result<Fields, Shape> {
            Ok(Fields)
        }
        fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Shape> {
            Err(Shape("map"))
        }
        not_struct!(
            serialize_bool(bool),
            serialize_i8(i8),
            serialize_i16(i16),
            serialize_i32(i32),
            serialize_i64(i64),
            serialize_u8(u8),
            serialize_u16(u16),
            serialize_u32(u32),
            serialize_u64(u64),
            serialize_f32(f32),
            serialize_f64(f64),
            serialize_char(char),
            serialize_str(&str),
            serialize_bytes(&[u8]),
            serialize_none(),
            serialize_unit(),
            serialize_unit_struct(&'static str),
            serialize_unit_variant(&'static str, u32, &'static str)
        );
        fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<&'static str, Shape> {
            Err(Shape("not a struct"))
        }
        fn serialize_newtype_struct<T: ?Sized + Serialize>(
            self,
            _: &'static str,
            _: &T,
        ) -> Result<&'static str, Shape> {
            Err(Shape("not a struct"))
        }
        fn serialize_newtype_variant<T: ?Sized + Serialize>(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: &T,
        ) -> Result<&'static str, Shape> {
            Err(Shape("not a struct"))
        }
        fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Shape> {
            Err(Shape("not a struct"))
        }
        fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Shape> {
            Err(Shape("not a struct"))
        }
        fn serialize_tuple_struct(
            self,
            _: &'static str,
            _: usize,
        ) -> Result<Self::SerializeTupleStruct, Shape> {
            Err(Shape("not a struct"))
        }
        fn serialize_tuple_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Self::SerializeTupleVariant, Shape> {
            Err(Shape("not a struct"))
        }
        fn serialize_struct_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Self::SerializeStructVariant, Shape> {
            Err(Shape("not a struct"))
        }
    }

    fn key() -> ZoneKey {
        ZoneKey {
            zone: "zone3".into(),
            epoch: 2,
            secret: "11".repeat(32),
            pubkey: "22".repeat(32),
            granted_by: "33".repeat(32),
            received_at: 1_790_000_000,
        }
    }

    /// Regression: a flattened record serialised as a JS `Map`, so the
    /// `zone_keys` put failed and every zone key was lost on reload.
    #[test]
    fn stored_zone_key_serialises_as_a_plain_struct() {
        let rec = StoredZoneKey::from(&key());
        assert_eq!(rec.serialize(TopLevelShape).map_err(|e| e.0), Ok("struct"));
    }

    #[test]
    fn stored_zone_key_has_its_id_at_the_top_level_and_round_trips() {
        let k = key();
        let rec = StoredZoneKey::from(&k);
        let v = serde_json::to_value(&rec).unwrap();
        assert_eq!(v["id"], "zone3:2");
        assert_eq!(v["secret"], k.secret);
        let back: StoredZoneKey = serde_json::from_value(v).unwrap();
        assert_eq!(ZoneKey::from(back), k);
    }
}
