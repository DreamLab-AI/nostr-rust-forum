//! Recipient-key registry: private inbox and epoch keys (Phase 2, ADR-2027 decision 2).
//!
//! A member's zone grants (kind 21453) and session-mirror wraps must not be
//! addressed to the identity key that their other NIP-17 clients can open. The
//! member therefore holds a separate random **inbox key** and registers it here,
//! privately. A public event would link identity and inbox key for every observer;
//! a D1 row does not.
//!
//! | Method | Path                          | Caller              | Purpose                          |
//! |--------|-------------------------------|---------------------|----------------------------------|
//! | POST   | /api/recipient-keys/register  | the owner           | Register an inbox key (idempotent) |
//! | POST   | /api/recipient-keys/revoke    | the owner or admin  | Revoke a key                     |
//! | GET    | /api/recipient-keys/lookup    | admin               | Unrevoked inbox keys of an owner |
//! | POST   | /api/recipient-keys/epoch     | admin               | Register an epoch key for a zone |
//!
//! Everything is NIP-98 authenticated and sits behind `RECIPIENT_KEYS_ENABLED`
//! (exact string `"true"`, default off). When off, every route returns
//! `404 {error:"recipient keys disabled"}` and never touches the database.
//!
//! ## Data location
//!
//! The `recipient_keys` table lives in the **relay's** D1 (`RELAY_DB`) and is
//! created by the relay worker, which reads it at admission. This module only
//! reads and writes rows; it does not create the table.
//!
//! ## Proof of possession
//!
//! A registration carries a kind-[`RECIPIENT_KEY_PROOF_KIND`] event signed by the
//! new inbox key, committing to `(owner, exp)`, so a member cannot register a key
//! they do not hold. The kind is distinct from the device-link proof so a proof
//! made for one purpose cannot be replayed for the other.
//!
//! Keys are never logged and never echoed in error messages.

use async_trait::async_trait;
use nostr_bbs_core::event::{verify_event_strict, NostrEvent};
use serde::Deserialize;
use serde_json::{json, Value};
use wasm_bindgen::JsValue;
use worker::{Env, Response, Result};

use crate::admin::{canonical_url, is_admin, now_secs, require_authed};
use crate::http::{error_json, json_response};

/// Worker var that gates the feature. Enabled only by the exact string `"true"`.
pub const RECIPIENT_KEYS_ENABLED_VAR: &str = "RECIPIENT_KEYS_ENABLED";

/// Event kind of the inbox-key proof-of-possession event.
const RECIPIENT_KEY_PROOF_KIND: u64 = 27237;

/// Longest permitted proof lifetime in seconds: `now < exp <= now + window`.
const PROOF_MAX_WINDOW_SECS: u64 = 300;

/// Longest permitted zone identifier, in bytes.
const MAX_ZONE_LEN: usize = 64;

/// Role of a registered key.
const ROLE_INBOX: &str = "inbox";
/// Role of an admin-maintained epoch key.
const ROLE_EPOCH: &str = "epoch";

/// Is the feature enabled for this raw var value? Exact `"true"` only.
fn enabled_raw(raw: Option<&str>) -> bool {
    raw == Some("true")
}

fn enabled(env: &Env) -> bool {
    enabled_raw(
        env.var(RECIPIENT_KEYS_ENABLED_VAR)
            .ok()
            .map(|v| v.to_string())
            .as_deref(),
    )
}

/// 64 ASCII hex characters (BIP-340 x-only public key).
fn is_valid_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// A zone identifier: 1..=64 bytes of `[a-z0-9_-]`.
fn is_valid_zone(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ZONE_LEN
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

// ── Storage seam ────────────────────────────────────────────────────────────

/// One `recipient_keys` row (the columns this module needs).
#[derive(Clone, Debug, PartialEq, Eq)]
struct KeyRow {
    key: String,
    owner_pubkey: String,
    zone: Option<String>,
    role: String,
    created_at: u64,
    revoked: bool,
}

/// Storage failure. Carries no key material, so it is safe to surface or log.
#[derive(Debug)]
struct StoreError;

/// The storage operations the handlers need, so the decision logic runs
/// natively against an in-memory store in tests and against D1 in the worker.
#[async_trait(?Send)]
trait KeyStore {
    /// Fetch a row by key.
    async fn get(&self, key: &str) -> std::result::Result<Option<KeyRow>, StoreError>;
    /// Insert `row` unless the key already exists.
    async fn insert_if_absent(&self, row: &KeyRow) -> std::result::Result<(), StoreError>;
    /// Set `revoked = 1`; restricted to `owner` when given. Returns whether a row matched.
    async fn revoke(&self, key: &str, owner: Option<&str>)
        -> std::result::Result<bool, StoreError>;
    /// Unrevoked inbox rows owned by `owner`, newest first.
    async fn list_inbox(&self, owner: &str) -> std::result::Result<Vec<KeyRow>, StoreError>;
}

/// An HTTP status and JSON body.
#[derive(Debug, PartialEq)]
struct Reply {
    status: u16,
    body: Value,
}

fn err(status: u16, msg: &str) -> Reply {
    Reply {
        status,
        body: json!({ "error": msg }),
    }
}

fn store_err(_: StoreError) -> Reply {
    err(500, "storage error")
}

// ── Request bodies ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterBody {
    key: String,
    role: String,
    #[serde(default)]
    proof: Option<NostrEvent>,
}

#[derive(Deserialize)]
struct RevokeBody {
    key: String,
}

#[derive(Deserialize)]
struct EpochBody {
    key: String,
    zone: String,
}

// ── Proof of possession ─────────────────────────────────────────────────────

fn proof_tag<'a>(proof: &'a NostrEvent, name: &str) -> Option<&'a str> {
    proof
        .tags
        .iter()
        .find(|t| t.first().map(String::as_str) == Some(name))
        .and_then(|t| t.get(1))
        .map(String::as_str)
}

/// Verify an inbox-key proof: authored and signed by `key`, of the right kind,
/// committing to `owner` and to a short forward-only `exp`.
///
/// `key` and `owner` must already be lowercase.
fn verify_key_proof(
    proof: &NostrEvent,
    key: &str,
    owner: &str,
    now: u64,
) -> std::result::Result<(), &'static str> {
    if proof.pubkey.to_ascii_lowercase() != key {
        return Err("proof not signed by the registered key");
    }
    if proof.kind != RECIPIENT_KEY_PROOF_KIND {
        return Err("proof has wrong kind");
    }
    let owner_tag = proof_tag(proof, "owner").ok_or("proof missing owner tag")?;
    if owner_tag.to_ascii_lowercase() != owner {
        return Err("proof owner does not match authenticated owner");
    }
    let exp: u64 = proof_tag(proof, "exp")
        .and_then(|v| v.parse().ok())
        .ok_or("proof missing or invalid exp tag")?;
    if exp <= now {
        return Err("proof expired");
    }
    if exp > now + PROOF_MAX_WINDOW_SECS {
        return Err("proof exp too far in the future");
    }
    verify_event_strict(proof).map_err(|_| "proof signature invalid")?;
    Ok(())
}

// ── Decision logic (pure over KeyStore) ─────────────────────────────────────

/// Insert a new row, or accept an existing identical registration.
///
/// An existing row is accepted only if the same owner holds it and it is not
/// revoked: a member cannot un-revoke a key an admin revoked, and cannot claim a
/// key already registered to someone else.
async fn upsert_row(store: &dyn KeyStore, row: KeyRow) -> Reply {
    if let Err(e) = store.insert_if_absent(&row).await {
        return store_err(e);
    }
    match store.get(&row.key).await {
        Ok(Some(existing)) if existing.owner_pubkey != row.owner_pubkey => {
            err(409, "key already registered")
        }
        Ok(Some(existing)) if existing.role != row.role => err(409, "key already registered"),
        Ok(Some(existing)) if existing.revoked => err(409, "key revoked"),
        Ok(Some(existing)) => Reply {
            status: 200,
            body: json!({
                "key": existing.key,
                "owner_pubkey": existing.owner_pubkey,
                "zone": existing.zone,
                "role": existing.role,
                "revoked": 0,
            }),
        },
        Ok(None) => err(500, "storage error"),
        Err(e) => store_err(e),
    }
}

/// `POST /api/recipient-keys/register`. `caller` is the NIP-98 author.
async fn do_register(store: &dyn KeyStore, caller: &str, body: &[u8], now: u64) -> Reply {
    let body: RegisterBody = match serde_json::from_slice(body) {
        Ok(b) => b,
        Err(_) => return err(400, "bad body"),
    };
    if body.role != ROLE_INBOX {
        return err(400, "only role 'inbox' can be registered here");
    }
    if !is_valid_pubkey(&body.key) {
        return err(400, "invalid key: must be 64 hex chars");
    }
    let key = body.key.to_ascii_lowercase();
    let owner = caller.to_ascii_lowercase();
    if key == owner {
        return err(400, "inbox key must differ from the identity key");
    }
    let Some(proof) = body.proof.as_ref() else {
        return err(400, "proof required");
    };
    if let Err(msg) = verify_key_proof(proof, &key, &owner, now) {
        return err(400, msg);
    }
    upsert_row(
        store,
        KeyRow {
            key,
            owner_pubkey: owner,
            zone: None,
            role: ROLE_INBOX.into(),
            created_at: now,
            revoked: false,
        },
    )
    .await
}

/// `POST /api/recipient-keys/revoke`. The owner may revoke their own key; an
/// admin may revoke any. A stranger's attempt matches nothing and yields 404,
/// the same as a missing key, so it cannot probe for existence.
async fn do_revoke(
    store: &dyn KeyStore,
    caller: &str,
    caller_is_admin: bool,
    body: &[u8],
) -> Reply {
    let body: RevokeBody = match serde_json::from_slice(body) {
        Ok(b) => b,
        Err(_) => return err(400, "bad body"),
    };
    if !is_valid_pubkey(&body.key) {
        return err(400, "invalid key: must be 64 hex chars");
    }
    let key = body.key.to_ascii_lowercase();
    let owner = caller.to_ascii_lowercase();
    let scope = if caller_is_admin {
        None
    } else {
        Some(owner.as_str())
    };
    match store.revoke(&key, scope).await {
        Ok(true) => Reply {
            status: 200,
            body: json!({ "key": key, "revoked": 1 }),
        },
        Ok(false) => err(404, "key not found"),
        Err(e) => store_err(e),
    }
}

/// `GET /api/recipient-keys/lookup?owner=<hex>`. Admin only.
async fn do_lookup(store: &dyn KeyStore, caller_is_admin: bool, owner: Option<&str>) -> Reply {
    if !caller_is_admin {
        return err(403, "admin required");
    }
    let Some(owner) = owner.filter(|o| is_valid_pubkey(o)) else {
        return err(400, "invalid owner: must be 64 hex chars");
    };
    let owner = owner.to_ascii_lowercase();
    match store.list_inbox(&owner).await {
        Ok(rows) => {
            let keys: Vec<Value> = rows
                .iter()
                .map(|r| {
                    json!({
                        "key": r.key,
                        "role": r.role,
                        "revoked": u8::from(r.revoked),
                        "created_at": r.created_at,
                    })
                })
                .collect();
            Reply {
                status: 200,
                body: json!({ "owner": owner, "keys": keys }),
            }
        }
        Err(e) => store_err(e),
    }
}

/// `POST /api/recipient-keys/epoch`. Admin only; role `epoch`, bound to a zone.
/// No proof: epoch keys are maintained by an admin and never log in.
async fn do_epoch(
    store: &dyn KeyStore,
    caller: &str,
    caller_is_admin: bool,
    body: &[u8],
    now: u64,
) -> Reply {
    if !caller_is_admin {
        return err(403, "admin required");
    }
    let body: EpochBody = match serde_json::from_slice(body) {
        Ok(b) => b,
        Err(_) => return err(400, "bad body"),
    };
    if !is_valid_pubkey(&body.key) {
        return err(400, "invalid key: must be 64 hex chars");
    }
    if !is_valid_zone(&body.zone) {
        return err(400, "invalid zone");
    }
    upsert_row(
        store,
        KeyRow {
            key: body.key.to_ascii_lowercase(),
            owner_pubkey: caller.to_ascii_lowercase(),
            zone: Some(body.zone),
            role: ROLE_EPOCH.into(),
            created_at: now,
            revoked: false,
        },
    )
    .await
}

// ── D1 store ────────────────────────────────────────────────────────────────

const SQL_INSERT: &str =
    "INSERT INTO recipient_keys (key, owner_pubkey, zone, role, created_at, revoked) \
     VALUES (?1, ?2, ?3, ?4, ?5, 0) ON CONFLICT (key) DO NOTHING";
const SQL_GET: &str =
    "SELECT key, owner_pubkey, zone, role, created_at, revoked FROM recipient_keys WHERE key = ?1";
const SQL_REVOKE_ANY: &str = "UPDATE recipient_keys SET revoked = 1 WHERE key = ?1";
const SQL_REVOKE_OWNED: &str =
    "UPDATE recipient_keys SET revoked = 1 WHERE key = ?1 AND owner_pubkey = ?2";
const SQL_LIST_INBOX: &str =
    "SELECT key, owner_pubkey, zone, role, created_at, revoked FROM recipient_keys \
     WHERE owner_pubkey = ?1 AND role = 'inbox' AND revoked = 0 ORDER BY created_at DESC, key";

#[derive(Deserialize)]
struct D1Row {
    key: String,
    owner_pubkey: String,
    zone: Option<String>,
    role: String,
    created_at: f64,
    revoked: f64,
}

impl From<D1Row> for KeyRow {
    fn from(r: D1Row) -> Self {
        KeyRow {
            key: r.key,
            owner_pubkey: r.owner_pubkey,
            zone: r.zone,
            role: r.role,
            created_at: r.created_at as u64,
            revoked: r.revoked != 0.0,
        }
    }
}

struct D1Store(worker::D1Database);

#[async_trait(?Send)]
impl KeyStore for D1Store {
    async fn get(&self, key: &str) -> std::result::Result<Option<KeyRow>, StoreError> {
        let row = self
            .0
            .prepare(SQL_GET)
            .bind(&[JsValue::from_str(key)])
            .map_err(|_| StoreError)?
            .first::<D1Row>(None)
            .await
            .map_err(|_| StoreError)?;
        Ok(row.map(KeyRow::from))
    }

    async fn insert_if_absent(&self, row: &KeyRow) -> std::result::Result<(), StoreError> {
        let zone = row.zone.as_deref().map_or(JsValue::NULL, JsValue::from_str);
        self.0
            .prepare(SQL_INSERT)
            .bind(&[
                JsValue::from_str(&row.key),
                JsValue::from_str(&row.owner_pubkey),
                zone,
                JsValue::from_str(&row.role),
                JsValue::from_f64(row.created_at as f64),
            ])
            .map_err(|_| StoreError)?
            .run()
            .await
            .map_err(|_| StoreError)?;
        Ok(())
    }

    async fn revoke(
        &self,
        key: &str,
        owner: Option<&str>,
    ) -> std::result::Result<bool, StoreError> {
        let stmt = match owner {
            Some(o) => self
                .0
                .prepare(SQL_REVOKE_OWNED)
                .bind(&[JsValue::from_str(key), JsValue::from_str(o)]),
            None => self
                .0
                .prepare(SQL_REVOKE_ANY)
                .bind(&[JsValue::from_str(key)]),
        }
        .map_err(|_| StoreError)?;
        let meta = stmt
            .run()
            .await
            .map_err(|_| StoreError)?
            .meta()
            .map_err(|_| StoreError)?;
        Ok(meta.and_then(|m| m.changes.or(m.rows_written)).unwrap_or(0) > 0)
    }

    async fn list_inbox(&self, owner: &str) -> std::result::Result<Vec<KeyRow>, StoreError> {
        let res = self
            .0
            .prepare(SQL_LIST_INBOX)
            .bind(&[JsValue::from_str(owner)])
            .map_err(|_| StoreError)?
            .all()
            .await
            .map_err(|_| StoreError)?;
        let rows = res.results::<D1Row>().map_err(|_| StoreError)?;
        Ok(rows.into_iter().map(KeyRow::from).collect())
    }
}

// ── Handlers ────────────────────────────────────────────────────────────────

fn disabled(env: &Env) -> Result<Response> {
    error_json(env, "recipient keys disabled", 404)
}

fn reply(env: &Env, r: Reply) -> Result<Response> {
    json_response(env, &r.body, r.status)
}

fn store(env: &Env) -> Result<D1Store> {
    Ok(D1Store(env.d1("RELAY_DB")?))
}

/// Authenticate the caller via NIP-98, returning the author's pubkey or a ready reply.
async fn authed(
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
    path: &str,
    method: &str,
    body: Option<&[u8]>,
) -> std::result::Result<String, Value> {
    let url = canonical_url(origin, path);
    require_authed(auth_header, &url, method, body, env)
        .await
        .map_err(|(b, _)| b)
}

/// `POST /api/recipient-keys/register` (NIP-98, owner = author).
pub async fn handle_register(
    body: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    if !enabled(env) {
        return disabled(env);
    }
    let path = "/api/recipient-keys/register";
    let caller = match authed(auth_header, env, origin, path, "POST", Some(body)).await {
        Ok(pk) => pk,
        Err(b) => return json_response(env, &b, 401),
    };
    let r = do_register(&store(env)?, &caller, body, now_secs()).await;
    reply(env, r)
}

/// `POST /api/recipient-keys/revoke` (NIP-98; owner or admin).
pub async fn handle_revoke(
    body: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    if !enabled(env) {
        return disabled(env);
    }
    let path = "/api/recipient-keys/revoke";
    let caller = match authed(auth_header, env, origin, path, "POST", Some(body)).await {
        Ok(pk) => pk,
        Err(b) => return json_response(env, &b, 401),
    };
    let admin = is_admin(&caller, env).await;
    let r = do_revoke(&store(env)?, &caller, admin, body).await;
    reply(env, r)
}

/// `GET /api/recipient-keys/lookup?owner=<hex>` (NIP-98; admin).
pub async fn handle_lookup(
    query: &[(String, String)],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    if !enabled(env) {
        return disabled(env);
    }
    let caller = match authed(
        auth_header,
        env,
        origin,
        "/api/recipient-keys/lookup",
        "GET",
        None,
    )
    .await
    {
        Ok(pk) => pk,
        Err(b) => return json_response(env, &b, 401),
    };
    let admin = is_admin(&caller, env).await;
    let owner = query
        .iter()
        .find(|(k, _)| k == "owner")
        .map(|(_, v)| v.as_str());
    let r = do_lookup(&store(env)?, admin, owner).await;
    reply(env, r)
}

/// `POST /api/recipient-keys/epoch` (NIP-98; admin).
pub async fn handle_epoch(
    body: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    if !enabled(env) {
        return disabled(env);
    }
    let path = "/api/recipient-keys/epoch";
    let caller = match authed(auth_header, env, origin, path, "POST", Some(body)).await {
        Ok(pk) => pk,
        Err(b) => return json_response(env, &b, 401),
    };
    let admin = is_admin(&caller, env).await;
    let r = do_epoch(&store(env)?, &caller, admin, body, now_secs()).await;
    reply(env, r)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::SigningKey;
    use nostr_bbs_core::event::{sign_event_deterministic, UnsignedEvent};
    use std::cell::RefCell;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    const NOW: u64 = 1_700_000_000;

    /// Drive a future that never actually suspends (the in-memory store).
    fn block_on<F: Future>(f: F) -> F::Output {
        let mut f = std::pin::pin!(f);
        let mut cx = Context::from_waker(Waker::noop());
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("in-memory future suspended"),
        }
    }

    /// In-memory store mirroring the SQL semantics above.
    #[derive(Default)]
    struct Mem(RefCell<Vec<KeyRow>>);

    #[async_trait(?Send)]
    impl KeyStore for Mem {
        async fn get(&self, key: &str) -> std::result::Result<Option<KeyRow>, StoreError> {
            Ok(self.0.borrow().iter().find(|r| r.key == key).cloned())
        }
        async fn insert_if_absent(&self, row: &KeyRow) -> std::result::Result<(), StoreError> {
            let mut rows = self.0.borrow_mut();
            if !rows.iter().any(|r| r.key == row.key) {
                rows.push(row.clone());
            }
            Ok(())
        }
        async fn revoke(
            &self,
            key: &str,
            owner: Option<&str>,
        ) -> std::result::Result<bool, StoreError> {
            let mut rows = self.0.borrow_mut();
            let mut hit = false;
            for r in rows
                .iter_mut()
                .filter(|r| r.key == key && owner.is_none_or(|o| r.owner_pubkey == o))
            {
                r.revoked = true;
                hit = true;
            }
            Ok(hit)
        }
        async fn list_inbox(&self, owner: &str) -> std::result::Result<Vec<KeyRow>, StoreError> {
            let mut rows: Vec<KeyRow> = self
                .0
                .borrow()
                .iter()
                .filter(|r| r.owner_pubkey == owner && r.role == ROLE_INBOX && !r.revoked)
                .cloned()
                .collect();
            rows.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.key.cmp(&b.key)));
            Ok(rows)
        }
    }

    fn sk(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32]).unwrap()
    }
    fn pk(b: u8) -> String {
        hex::encode(sk(b).verifying_key().to_bytes())
    }

    const OWNER: u8 = 0x22;
    const INBOX: u8 = 0x11;
    const STRANGER: u8 = 0x33;
    const ADMIN: u8 = 0x44;

    fn proof(signer: u8, kind: u64, owner: &str, exp: u64) -> NostrEvent {
        sign_event_deterministic(
            UnsignedEvent {
                pubkey: pk(signer),
                created_at: NOW,
                kind,
                tags: vec![
                    vec!["owner".into(), owner.into()],
                    vec!["exp".into(), exp.to_string()],
                ],
                content: String::new(),
            },
            &sk(signer),
        )
        .unwrap()
    }

    fn reg_body(key: &str, role: &str, p: &NostrEvent) -> Vec<u8> {
        serde_json::to_vec(&json!({ "key": key, "role": role, "proof": p })).unwrap()
    }

    fn register_inbox(store: &Mem, owner: u8, inbox: u8) -> Reply {
        let p = proof(inbox, RECIPIENT_KEY_PROOF_KIND, &pk(owner), NOW + 60);
        block_on(do_register(
            store,
            &pk(owner),
            &reg_body(&pk(inbox), "inbox", &p),
            NOW,
        ))
    }

    fn revoke_body(key: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({ "key": key })).unwrap()
    }

    #[test]
    fn register_ok_and_idempotent() {
        let s = Mem::default();
        let first = register_inbox(&s, OWNER, INBOX);
        assert_eq!(first.status, 200);
        assert_eq!(first.body["owner_pubkey"], pk(OWNER));
        assert_eq!(first.body["role"], "inbox");
        let second = register_inbox(&s, OWNER, INBOX);
        assert_eq!(second, first);
        assert_eq!(s.0.borrow().len(), 1);
    }

    #[test]
    fn register_refused_when_proof_signed_by_different_key() {
        let s = Mem::default();
        // The caller names INBOX but the proof is signed by STRANGER's key.
        let p = proof(STRANGER, RECIPIENT_KEY_PROOF_KIND, &pk(OWNER), NOW + 60);
        let r = block_on(do_register(
            &s,
            &pk(OWNER),
            &reg_body(&pk(INBOX), "inbox", &p),
            NOW,
        ));
        assert_eq!(r.status, 400);
        assert!(s.0.borrow().is_empty());
    }

    #[test]
    fn register_refused_when_caller_is_not_the_proof_owner() {
        let s = Mem::default();
        // Proof commits to OWNER; STRANGER replays it under their own NIP-98 identity.
        let p = proof(INBOX, RECIPIENT_KEY_PROOF_KIND, &pk(OWNER), NOW + 60);
        let r = block_on(do_register(
            &s,
            &pk(STRANGER),
            &reg_body(&pk(INBOX), "inbox", &p),
            NOW,
        ));
        assert_eq!(r.status, 400);
        assert!(s.0.borrow().is_empty());
    }

    #[test]
    fn register_refuses_epoch_role_missing_proof_and_identity_key() {
        let s = Mem::default();
        let p = proof(INBOX, RECIPIENT_KEY_PROOF_KIND, &pk(OWNER), NOW + 60);
        let r = block_on(do_register(
            &s,
            &pk(OWNER),
            &reg_body(&pk(INBOX), "epoch", &p),
            NOW,
        ));
        assert_eq!(r.status, 400);
        let no_proof = serde_json::to_vec(&json!({ "key": pk(INBOX), "role": "inbox" })).unwrap();
        assert_eq!(
            block_on(do_register(&s, &pk(OWNER), &no_proof, NOW)).status,
            400
        );
        let own = proof(OWNER, RECIPIENT_KEY_PROOF_KIND, &pk(OWNER), NOW + 60);
        let r = block_on(do_register(
            &s,
            &pk(OWNER),
            &reg_body(&pk(OWNER), "inbox", &own),
            NOW,
        ));
        assert_eq!(r.status, 400);
        assert!(s.0.borrow().is_empty());
    }

    #[test]
    fn register_refuses_wrong_kind_and_expired_proof() {
        let s = Mem::default();
        let wrong_kind = proof(INBOX, 27236, &pk(OWNER), NOW + 60);
        let r = block_on(do_register(
            &s,
            &pk(OWNER),
            &reg_body(&pk(INBOX), "inbox", &wrong_kind),
            NOW,
        ));
        assert_eq!(r.status, 400);
        let expired = proof(INBOX, RECIPIENT_KEY_PROOF_KIND, &pk(OWNER), NOW);
        let r = block_on(do_register(
            &s,
            &pk(OWNER),
            &reg_body(&pk(INBOX), "inbox", &expired),
            NOW,
        ));
        assert_eq!(r.status, 400);
    }

    #[test]
    fn register_cannot_take_over_or_unrevoke() {
        let s = Mem::default();
        assert_eq!(register_inbox(&s, OWNER, INBOX).status, 200);
        // Another member who also holds the inbox key cannot claim the row.
        assert_eq!(register_inbox(&s, STRANGER, INBOX).status, 409);
        // After revocation the owner cannot quietly revive it.
        block_on(do_revoke(&s, &pk(OWNER), false, &revoke_body(&pk(INBOX))));
        assert_eq!(register_inbox(&s, OWNER, INBOX).status, 409);
    }

    #[test]
    fn revoke_by_owner_ok() {
        let s = Mem::default();
        register_inbox(&s, OWNER, INBOX);
        let r = block_on(do_revoke(&s, &pk(OWNER), false, &revoke_body(&pk(INBOX))));
        assert_eq!(r.status, 200);
        assert!(s.0.borrow()[0].revoked);
    }

    #[test]
    fn revoke_by_stranger_refused() {
        let s = Mem::default();
        register_inbox(&s, OWNER, INBOX);
        let r = block_on(do_revoke(
            &s,
            &pk(STRANGER),
            false,
            &revoke_body(&pk(INBOX)),
        ));
        assert_eq!(r.status, 404);
        assert!(!s.0.borrow()[0].revoked);
    }

    #[test]
    fn revoke_by_admin_ok() {
        let s = Mem::default();
        register_inbox(&s, OWNER, INBOX);
        let r = block_on(do_revoke(&s, &pk(ADMIN), true, &revoke_body(&pk(INBOX))));
        assert_eq!(r.status, 200);
        assert!(s.0.borrow()[0].revoked);
    }

    #[test]
    fn lookup_by_admin_returns_only_unrevoked_inbox_keys() {
        let s = Mem::default();
        register_inbox(&s, OWNER, INBOX);
        register_inbox(&s, OWNER, 0x55);
        register_inbox(&s, STRANGER, 0x66);
        // An epoch key owned by the same pubkey must not appear.
        let ep = serde_json::to_vec(&json!({ "key": pk(0x77), "zone": "general" })).unwrap();
        block_on(do_epoch(&s, &pk(OWNER), true, &ep, NOW));
        block_on(do_revoke(&s, &pk(OWNER), false, &revoke_body(&pk(0x55))));
        let r = block_on(do_lookup(&s, true, Some(&pk(OWNER))));
        assert_eq!(r.status, 200);
        assert_eq!(
            r.body["keys"],
            json!([{ "key": pk(INBOX), "role": "inbox", "revoked": 0, "created_at": NOW }])
        );
    }

    #[test]
    fn lookup_orders_newest_first() {
        let s = Mem::default();
        for (b, t) in [(0x51u8, NOW), (0x52, NOW + 20), (0x53, NOW + 10)] {
            let p = proof(b, RECIPIENT_KEY_PROOF_KIND, &pk(OWNER), t + 60);
            let body = reg_body(&pk(b), "inbox", &p);
            assert_eq!(block_on(do_register(&s, &pk(OWNER), &body, t)).status, 200);
        }
        let r = block_on(do_lookup(&s, true, Some(&pk(OWNER))));
        let order: Vec<&str> = r.body["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["key"].as_str().unwrap())
            .collect();
        assert_eq!(order, [pk(0x52), pk(0x53), pk(0x51)]);
    }

    #[test]
    fn lookup_by_member_is_403_and_bad_owner_is_400() {
        let s = Mem::default();
        register_inbox(&s, OWNER, INBOX);
        assert_eq!(block_on(do_lookup(&s, false, Some(&pk(OWNER)))).status, 403);
        assert_eq!(block_on(do_lookup(&s, true, Some("zz"))).status, 400);
        assert_eq!(block_on(do_lookup(&s, true, None)).status, 400);
    }

    #[test]
    fn epoch_is_admin_only_and_records_role_and_zone() {
        let s = Mem::default();
        let body = serde_json::to_vec(&json!({ "key": pk(0x77), "zone": "general" })).unwrap();
        assert_eq!(
            block_on(do_epoch(&s, &pk(OWNER), false, &body, NOW)).status,
            403
        );
        let r = block_on(do_epoch(&s, &pk(ADMIN), true, &body, NOW));
        assert_eq!(r.status, 200);
        assert_eq!(r.body["role"], "epoch");
        assert_eq!(r.body["zone"], "general");
        assert_eq!(block_on(do_epoch(&s, &pk(ADMIN), true, &body, NOW)), r);
        let bad = serde_json::to_vec(&json!({ "key": pk(0x78), "zone": "Bad Zone" })).unwrap();
        assert_eq!(
            block_on(do_epoch(&s, &pk(ADMIN), true, &bad, NOW)).status,
            400
        );
    }

    #[test]
    fn flag_is_off_unless_exactly_true() {
        // Every handler's first statement is `if !enabled(env) { return 404 }`.
        assert!(enabled_raw(Some("true")));
        for off in [
            None,
            Some(""),
            Some("false"),
            Some("TRUE"),
            Some("1"),
            Some(" true "),
        ] {
            assert!(!enabled_raw(off), "{off:?} must be off");
        }
    }

    #[test]
    fn sql_scopes_revoke_to_owner_and_lookup_to_live_inbox_keys() {
        assert!(SQL_REVOKE_OWNED.contains("owner_pubkey = ?2"));
        assert!(!SQL_REVOKE_ANY.contains("owner_pubkey"));
        assert!(SQL_LIST_INBOX.contains("role = 'inbox'"));
        assert!(SQL_LIST_INBOX.contains("revoked = 0"));
        assert!(SQL_LIST_INBOX.contains("ORDER BY created_at DESC"));
    }
}
