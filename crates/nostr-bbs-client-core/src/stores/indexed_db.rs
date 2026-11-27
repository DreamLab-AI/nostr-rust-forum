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
//! - `zone_keys` — key `id`, zone end-to-end encryption keys (ADR-2016): rows
//!   written now are `"<owner pubkey>/<store id>"` with an `owner` field;
//!   older rows have no owner and are the bare store id (see
//!   [`crate::zone_crypto::key_owner`]). The store id is
//!   `"<zone>:<epoch>"`, or `"<zone>:<group|->:<epoch>:<pubkey>"` with
//!   `ZONE_GROUPS_ENABLED`; rows are moved to the current form on load.
//! - `zone_kv`   — key `id`, small JSON values for zone encryption bookkeeping
//!   (processed gift-wrap ids, grants this admin has sent)

use serde::{Deserialize, Serialize};

use crate::zone_crypto::key_owner::{self, MintDecision, Owner, PutDecision};
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

/// A zone key at rest: the key's fields plus its row id (the store's key
/// path) and the identity that owns it.
///
/// Built for writing only by [`StoredZoneKey::owned`], so a written row always
/// carries an owner; rows without one were written before keys had owners and
/// are only ever read, or moved verbatim by [`ForumDb::migrate_zone_keys`].
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
    /// Group identity pubkey for a NIP-171 derived key; absent on entries
    /// written before ADR-2028, which read back as a legacy key.
    #[serde(default)]
    pub group: Option<String>,
    /// See [`ZoneKey::pending_delivery`](crate::zone_crypto::ZoneKey::pending_delivery).
    #[serde(default)]
    pub pending_delivery: bool,
    /// Pubkey (hex) of the identity this row belongs to, or `None` for a row
    /// written before rows had owners (visible to every signed-in identity).
    #[serde(default)]
    pub owner: Option<String>,
}

impl StoredZoneKey {
    /// `key` as `owner`'s row, under [`owned_row_id`].
    ///
    /// [`owned_row_id`]: crate::zone_crypto::key_owner::owned_row_id
    pub fn owned(owner: &Owner, key: &crate::zone_crypto::ZoneKey) -> Self {
        Self {
            id: crate::zone_crypto::key_owner::owned_row_id(owner, &key.store_id()),
            zone: key.zone.clone(),
            epoch: key.epoch,
            secret: key.secret.clone(),
            pubkey: key.pubkey.clone(),
            granted_by: key.granted_by.clone(),
            received_at: key.received_at,
            group: key.group.clone(),
            pending_delivery: key.pending_delivery,
            owner: Some(owner.as_str().to_string()),
        }
    }

    /// The key this row holds.
    pub fn to_zone_key(&self) -> crate::zone_crypto::ZoneKey {
        crate::zone_crypto::ZoneKey::from(self.clone())
    }
}

/// Outcome of [`ForumDb::put_zone_key_unless_conflicting`].
#[derive(Debug)]
pub enum ZoneKeyPut {
    /// Written (new, or the same secret again).
    Stored,
    /// Refused: this device holds a different secret for the same id.
    Conflict(crate::zone_crypto::ZoneKey),
}

/// Outcome of [`ForumDb::put_minted_zone_key`].
#[derive(Debug)]
pub enum MintPut {
    /// Written.
    Stored,
    /// Refused: the slot holds a different key.
    Conflict(crate::zone_crypto::ZoneKey),
    /// Refused: a row on this device (any owner) holds a different key for
    /// the zone at this epoch or the one named, which is above it.
    Superseded(u32),
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
            group: r.group,
            pending_delivery: r.pending_delivery,
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

/// Every row of the `zone_keys` store, within the caller's transaction.
async fn rows_in(store: &web_sys::IdbObjectStore) -> Result<Vec<StoredZoneKey>, JsValue> {
    let result = idb_request_result(&store.get_all()?).await?;
    let arr: js_sys::Array = result.dyn_into().unwrap_or_else(|_| js_sys::Array::new());
    Ok((0..arr.length())
        .filter_map(|i| from_js::<StoredZoneKey>(arr.get(i)).ok())
        .collect())
}

/// The row at `id`, within the caller's transaction.
async fn row_in(
    store: &web_sys::IdbObjectStore,
    id: &str,
) -> Result<Option<StoredZoneKey>, JsValue> {
    let v = idb_request_result(&store.get(&JsValue::from_str(id))?).await?;
    if v.is_undefined() || v.is_null() {
        return Ok(None);
    }
    Ok(Some(from_js::<StoredZoneKey>(v)?))
}

/// The key `owner` sees for `store_id`, within the caller's transaction:
/// [`key_owner::slot_view`] over their row and the legacy row. A row at the
/// legacy id that carries an owner is not a legacy row and is ignored.
/// The refused list stored under `id` in `kv` (empty when absent or
/// unreadable as the current format).
async fn refused_in(
    kv: &web_sys::IdbObjectStore,
    id: &str,
) -> Result<Vec<key_owner::RefusedKey>, JsValue> {
    let result = idb_request_result(&kv.get(&JsValue::from_str(id))?).await?;
    if result.is_undefined() || result.is_null() {
        return Ok(Vec::new());
    }
    let rec: ZoneKvRecord = from_js(result)?;
    Ok(serde_json::from_str(&rec.value).unwrap_or_default())
}

async fn put_refused_in(
    kv: &web_sys::IdbObjectStore,
    id: &str,
    list: &[key_owner::RefusedKey],
) -> Result<(), JsValue> {
    let rec = ZoneKvRecord {
        id: id.to_string(),
        value: serde_json::to_string(list).map_err(|e| JsValue::from_str(&e.to_string()))?,
    };
    idb_request_result(&kv.put(&to_js(&rec)?)?).await?;
    Ok(())
}

async fn slot_view_in(
    store: &web_sys::IdbObjectStore,
    owner: &Owner,
    store_id: &str,
) -> Result<Option<crate::zone_crypto::ZoneKey>, JsValue> {
    let owned = row_in(store, &key_owner::owned_row_id(owner, store_id))
        .await?
        .filter(|r| r.owner.as_deref() == Some(owner.as_str()))
        .map(|r| r.to_zone_key());
    let legacy = row_in(store, store_id)
        .await?
        .filter(|r| r.owner.is_none())
        .map(|r| r.to_zone_key());
    Ok(key_owner::slot_view(owned, legacy))
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
    //
    // Every write goes through a guard that reads and writes in one
    // transaction. Should a browser commit the transaction between the read
    // and the write, the write fails and the error reaches the caller, which
    // leaves the key to be retried: nothing is overwritten.

    /// Store `key` as `owner`'s row unless the slot, as `owner` sees it (their
    /// row, else the legacy row), holds a different key. An epoch's key never
    /// changes: a second, different key for a held `(zone, epoch)` is a
    /// conflicting mint (an admin rotating from a device that lacked the
    /// newest epoch), and replacing the held one would make every post under
    /// it unreadable here. Returns the held key on conflict.
    ///
    /// Another identity's rows are never read or written: they live under
    /// other ids.
    pub async fn put_zone_key_unless_conflicting(
        &self,
        owner: &Owner,
        key: &crate::zone_crypto::ZoneKey,
    ) -> Result<ZoneKeyPut, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_ZONE_KEYS, IdbTransactionMode::Readwrite)?;
        let store = tx.object_store(STORE_ZONE_KEYS)?;
        let view = slot_view_in(&store, owner, &key.store_id()).await?;
        if let PutDecision::Conflict(held) = key_owner::put_decision(view.as_ref(), key) {
            return Ok(ZoneKeyPut::Conflict(held));
        }
        let rec = StoredZoneKey::owned(owner, key);
        idb_request_result(&store.put(&to_js(&rec)?)?).await?;
        Ok(ZoneKeyPut::Stored)
    }

    /// Replace the key `owner` sees for `new`'s slot with `new`, but only
    /// while that slot still holds `expected` (see
    /// [`key_owner::swap_allowed`]), and record `expected` as displaced in
    /// `owner`'s refused list ([`key_owner::after_swap`]), in ONE transaction
    /// over `zone_keys` and `zone_kv`: the displaced key (possibly its only
    /// copy) is never lost between the two. Returns the stored refused list
    /// after the swap, or `None` when the slot changed meanwhile (nothing
    /// written). The owner's own row is written, which `visible_keys`
    /// prefers over a legacy row.
    pub async fn swap_zone_key(
        &self,
        owner: &Owner,
        expected: &crate::zone_crypto::ZoneKey,
        new: &crate::zone_crypto::ZoneKey,
    ) -> Result<Option<Vec<key_owner::RefusedKey>>, JsValue> {
        if expected.store_id() != new.store_id() {
            return Ok(None);
        }
        let names = js_sys::Array::of2(
            &JsValue::from_str(STORE_ZONE_KEYS),
            &JsValue::from_str(STORE_ZONE_KV),
        );
        let tx = self
            .db
            .transaction_with_str_sequence_and_mode(&names, IdbTransactionMode::Readwrite)?;
        let keys = tx.object_store(STORE_ZONE_KEYS)?;
        let kv = tx.object_store(STORE_ZONE_KV)?;
        let view = slot_view_in(&keys, owner, &new.store_id()).await?;
        if !key_owner::swap_allowed(view.as_ref(), expected) {
            return Ok(None);
        }
        let kv_id = key_owner::refused_keys_id(owner);
        let list = key_owner::after_swap(refused_in(&kv, &kv_id).await?, new, expected);
        let rec = StoredZoneKey::owned(owner, new);
        idb_request_result(&keys.put(&to_js(&rec)?)?).await?;
        put_refused_in(&kv, &kv_id, &list).await?;
        Ok(Some(list))
    }

    /// Add `entry` to `owner`'s stored refused list: read, merge
    /// ([`key_owner::note_refused`]) and write in one transaction, so two
    /// tabs never overwrite each other's entries. Returns the stored list.
    pub async fn add_refused_key(
        &self,
        owner: &Owner,
        entry: key_owner::RefusedKey,
    ) -> Result<Vec<key_owner::RefusedKey>, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_ZONE_KV, IdbTransactionMode::Readwrite)?;
        let kv = tx.object_store(STORE_ZONE_KV)?;
        let kv_id = key_owner::refused_keys_id(owner);
        let mut list = refused_in(&kv, &kv_id).await?;
        if key_owner::note_refused(&mut list, entry) {
            put_refused_in(&kv, &kv_id, &list).await?;
        }
        Ok(list)
    }

    /// `owner`'s stored refused list.
    pub async fn refused_keys(&self, owner: &Owner) -> Result<Vec<key_owner::RefusedKey>, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_ZONE_KV, IdbTransactionMode::Readonly)?;
        refused_in(
            &tx.object_store(STORE_ZONE_KV)?,
            &key_owner::refused_keys_id(owner),
        )
        .await
    }

    /// Store a key this device just created as `owner`'s row: the slot guard
    /// of [`put_zone_key_unless_conflicting`](Self::put_zone_key_unless_conflicting),
    /// plus a check over every row on the device, of every owner, so two
    /// accounts on one browser never mint different keys for one epoch (see
    /// [`key_owner::mint_decision`]). One transaction.
    pub async fn put_minted_zone_key(
        &self,
        owner: &Owner,
        key: &crate::zone_crypto::ZoneKey,
    ) -> Result<MintPut, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_ZONE_KEYS, IdbTransactionMode::Readwrite)?;
        let store = tx.object_store(STORE_ZONE_KEYS)?;
        let rows = rows_in(&store).await?;
        let flag = crate::zone_crypto::tickets::zone_groups_enabled();
        match key_owner::mint_decision(&rows, owner, key, flag) {
            MintDecision::Conflict(held) => return Ok(MintPut::Conflict(held)),
            MintDecision::Superseded(e) => return Ok(MintPut::Superseded(e)),
            MintDecision::Write => {}
        }
        let rec = StoredZoneKey::owned(owner, key);
        idb_request_result(&store.put(&to_js(&rec)?)?).await?;
        Ok(MintPut::Stored)
    }

    /// The key `owner` sees for `store_id`: their row, else the legacy row.
    pub async fn get_zone_key(
        &self,
        owner: &Owner,
        store_id: &str,
    ) -> Result<Option<crate::zone_crypto::ZoneKey>, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_ZONE_KEYS, IdbTransactionMode::Readonly)?;
        let store = tx.object_store(STORE_ZONE_KEYS)?;
        slot_view_in(&store, owner, store_id).await
    }

    /// Every zone-key row on this device, of every owner. Callers narrow it
    /// with [`key_owner::visible_keys`]; the whole set is needed only for the
    /// device-wide epoch floor.
    pub async fn zone_key_rows(&self) -> Result<Vec<StoredZoneKey>, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_ZONE_KEYS, IdbTransactionMode::Readonly)?;
        let store = tx.object_store(STORE_ZONE_KEYS)?;
        rows_in(&store).await
    }

    /// Move each row not stored under its expected id (the
    /// `ZONE_GROUPS_ENABLED` flag changed since it was written) to that id,
    /// owner kept, record copied verbatim. The new row is written first and
    /// the old one deleted only once the new id holds the same key, so an
    /// interruption never loses a key; when the new id holds a different key
    /// the old row stays where it is.
    pub async fn migrate_zone_keys(&self) -> Result<(), JsValue> {
        let rows = self.zone_key_rows().await?;
        let flag = crate::zone_crypto::tickets::zone_groups_enabled();
        for rename in key_owner::migration_plan(&rows, flag) {
            if self.move_zone_key_row(&rename.row).await? {
                let tx = self.db.transaction_with_str_and_mode(
                    STORE_ZONE_KEYS,
                    IdbTransactionMode::Readwrite,
                )?;
                let store = tx.object_store(STORE_ZONE_KEYS)?;
                idb_request_result(&store.delete(&JsValue::from_str(&rename.old_id))?).await?;
            }
        }
        Ok(())
    }

    /// Write `row` (already under its new id) unless that id holds a
    /// different key. Returns whether the id now holds this key. The only
    /// write that can produce a row without an owner, and only by copying one.
    async fn move_zone_key_row(&self, row: &StoredZoneKey) -> Result<bool, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_ZONE_KEYS, IdbTransactionMode::Readwrite)?;
        let store = tx.object_store(STORE_ZONE_KEYS)?;
        let held = idb_request_result(&store.get(&JsValue::from_str(&row.id))?).await?;
        if !held.is_undefined() && !held.is_null() {
            let held = from_js::<StoredZoneKey>(held)?;
            if held.owner != row.owner
                || crate::zone_crypto::conflicts(&held.to_zone_key(), &row.to_zone_key())
            {
                return Ok(false);
            }
        }
        idb_request_result(&store.put(&to_js(row)?)?).await?;
        Ok(true)
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

    // -- Relay scope ------------------------------------------------------------

    /// Drop everything here that came from, or was decided against, a
    /// particular relay (see [`crate::stores::relay_scope`]): the message,
    /// channel, profile and deletion caches, the outbox (events signed for
    /// that relay are not sent to another), and the `zone_kv` bookkeeping in
    /// [`relay_scoped_kv`]. Zone keys, the inbox key and member choices stay.
    ///
    /// `go_on` is asked before each step; once it says no, nothing more is
    /// cleared and `Ok(false)` is returned.
    pub async fn clear_relay_scoped(&self, go_on: &dyn Fn() -> bool) -> Result<bool, JsValue> {
        for name in [
            STORE_MESSAGES,
            STORE_CHANNELS,
            STORE_PROFILES,
            STORE_DELETIONS,
            STORE_OUTBOX,
        ] {
            if !go_on() {
                return Ok(false);
            }
            let tx = self
                .db
                .transaction_with_str_and_mode(name, IdbTransactionMode::Readwrite)?;
            idb_request_result(&tx.object_store(name)?.clear()?).await?;
        }
        if !go_on() {
            return Ok(false);
        }
        let tx = self
            .db
            .transaction_with_str_and_mode(STORE_ZONE_KV, IdbTransactionMode::Readwrite)?;
        let store = tx.object_store(STORE_ZONE_KV)?;
        let keys = idb_request_result(&store.get_all_keys()?).await?;
        let keys: js_sys::Array = keys.dyn_into().unwrap_or_else(|_| js_sys::Array::new());
        for k in keys.iter() {
            if k.as_string().is_some_and(|id| relay_scoped_kv(&id)) {
                idb_request_result(&store.delete(&k)?).await?;
            }
        }
        Ok(true)
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

/// Whether `zone_kv` entry `id` records relay state, cleared when the relay
/// changes: wraps unwrapped there, keys received through the inbox there,
/// grants sent there (`grants_sent:…`; re-sending one repeats the same key),
/// and the old-grant cleanup flag. Never anything holding a secret (the
/// inbox key, refused and displaced keys), member choices (DM consents, the
/// public-inbox choice), or the approved-targets sets: emptying those would
/// re-open the first-grant confirmation gate to the new relay's whole roster.
pub fn relay_scoped_kv(id: &str) -> bool {
    id.starts_with("processed_wraps")
        || id.starts_with("inbox_granted:")
        || id.starts_with("grant_cleanup_finished:")
        || id.starts_with(&format!(
            "{}:",
            crate::zone_crypto::grant_ledger::KV_GRANTS_SENT
        ))
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
            group: None,
            pending_delivery: false,
        }
    }

    /// Regression: a flattened record serialised as a JS `Map`, so the
    /// `zone_keys` put failed and every zone key was lost on reload.
    fn me() -> Owner {
        Owner::parse(&"44".repeat(32)).expect("hex")
    }

    #[test]
    fn stored_zone_key_serialises_as_a_plain_struct() {
        let rec = StoredZoneKey::owned(&me(), &key());
        assert_eq!(rec.serialize(TopLevelShape).map_err(|e| e.0), Ok("struct"));
    }

    #[test]
    fn stored_zone_key_has_its_id_at_the_top_level_and_round_trips() {
        let k = key();
        let rec = StoredZoneKey::owned(&me(), &k);
        let v = serde_json::to_value(&rec).unwrap();
        // The id is the owner plus the store id, which is flag-aware (legacy
        // `<zone>:<epoch>` with ZONE_GROUPS_ENABLED off, the native test
        // default; `<zone>:<group>:<epoch>:<pubkey>` with it on). Assert
        // against store_id so the test is correct in either mode.
        assert_eq!(v["id"], format!("{}/{}", me(), k.store_id()));
        assert_eq!(v["owner"], me().as_str());
        assert_eq!(v["secret"], k.secret);
        let back: StoredZoneKey = serde_json::from_value(v).unwrap();
        assert_eq!(ZoneKey::from(back), k);
    }

    /// A row written before rows had owners reads back as legacy: no owner,
    /// its key intact.
    #[test]
    fn a_pre_owner_row_reads_back_as_legacy() {
        let k = key();
        let json = serde_json::json!({
            "id": k.store_id(),
            "zone": k.zone,
            "epoch": k.epoch,
            "secret": k.secret,
            "pubkey": k.pubkey,
            "granted_by": k.granted_by,
            "received_at": k.received_at,
        });
        let row: StoredZoneKey = serde_json::from_value(json).unwrap();
        assert_eq!(row.owner, None);
        assert_eq!(row.to_zone_key(), k);
        assert_eq!(
            crate::zone_crypto::key_owner::expected_row_id(&row, false),
            Some(row.id.clone()),
            "a flag-off legacy row is already where it belongs: never moved"
        );
    }
}
