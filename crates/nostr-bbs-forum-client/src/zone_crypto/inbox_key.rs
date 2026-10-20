//! Inbox key for zone-key grants (Phase 2, ADR-2027 decision 2).
//!
//! A zone-key grant must not be addressed to the member's identity pubkey: a
//! second NIP-17 client holding the same identity would open it. Instead the
//! member keeps a random *inbox key*, registered with the auth-worker, and
//! admins wrap grants to that key.
//!
//! The inbox key is random (never derived: a NIP-07 signer offers no repeatable
//! secret) and backed up as a kind-30078 event, `d = nostr-bbs/zone-inbox/v1`,
//! whose content is a NIP-44 self-encryption of `{sk_hex, created_at}`. A fresh
//! browser restores it from that event.
//!
//! Lifecycle, in order, with every step idempotent so a retry resumes:
//!
//! 1. local state in IndexedDB → else the relay backup → else generate;
//! 2. persist locally as *pending*;
//! 3. publish the backup (only for a newly generated key);
//! 4. register with the auth-worker (proof signed by the inbox key);
//! 5. mark *active*.
//!
//! A key is active only after step 5, so a failed registration never leaves a
//! usable-looking key. If the relay cannot be asked whether a backup exists,
//! nothing is generated: a second key would overwrite the real backup.
//!
//! Everything is behind `window.__ENV__.RECIPIENT_KEYS_ENABLED == "true"`;
//! with the flag absent none of this runs.

use std::cell::RefCell;
use std::rc::Rc;
use std::task::{Poll, Waker};

use nostr_bbs_core::keys::{generate_keypair, pubkey_hex};
use nostr_bbs_core::signer::{PrfSigner, Signer};
use nostr_bbs_core::{verify_event_strict, NostrEvent, UnsignedEvent};
use serde::{Deserialize, Serialize};

use super::grant_ledger::GrantKv;

/// `window.__ENV__` key of the inbox-key switch.
pub const RECIPIENT_KEYS_ENV: &str = "RECIPIENT_KEYS_ENABLED";
/// `window.__ENV__` key of the old-grant sweep switch.
pub const GRANT_SWEEP_ENV: &str = "GRANT_SWEEP_ENABLED";
/// Kind of the encrypted backup (NIP-78 application data, replaceable).
pub const KIND_APP_DATA: u64 = 30078;
/// `d` tag of the backup event.
pub const BACKUP_D_TAG: &str = "nostr-bbs/zone-inbox/v1";
/// Kind of the proof event signed by the inbox key (NIP-98 style).
pub const KIND_PROOF: u64 = 27237;
/// Seconds a registration proof stays valid.
pub const PROOF_TTL_SECS: u64 = 300;

fn env_flag(key: &str) -> bool {
    let raw = web_sys::window()
        .and_then(|w| js_sys::Reflect::get(&w, &"__ENV__".into()).ok())
        .filter(|env| !env.is_undefined() && !env.is_null())
        .and_then(|env| js_sys::Reflect::get(&env, &key.into()).ok())
        .and_then(|v| v.as_string());
    super::gate_value_enabled(raw.as_deref())
}

/// Whether inbox keys are switched on. Absent means off.
pub fn recipient_keys_enabled() -> bool {
    env_flag(RECIPIENT_KEYS_ENV)
}

/// Whether the old-grant sweep is switched on. Absent means off.
pub fn grant_sweep_enabled() -> bool {
    env_flag(GRANT_SWEEP_ENV)
}

/// The decrypted backup payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxBackup {
    /// Inbox secret key, lower-case hex.
    pub sk_hex: String,
    /// Unix seconds when the key was generated.
    pub created_at: u64,
}

/// What this device keeps for the inbox key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalInbox {
    /// Inbox secret key, lower-case hex.
    pub sk_hex: String,
    /// Unix seconds when the key was generated.
    pub created_at: u64,
    /// True once the relay acknowledged the backup (or the key came from it).
    /// Registration waits for this, so no registered key lacks a backup.
    #[serde(default)]
    pub backed_up: bool,
    /// True only once the auth-worker accepted the registration.
    pub registered: bool,
}

/// A usable (registered) inbox key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxKey {
    /// Inbox secret key, hex.
    pub sk_hex: String,
    /// Inbox public key, hex.
    pub pubkey: String,
}

/// A local signer for an inbox secret given as hex.
pub fn inbox_signer(sk_hex: &str) -> Result<PrfSigner, String> {
    signer_from_hex(sk_hex)
}

/// `zone_kv` id for `owner`'s inbox state.
pub fn local_id(owner: &str) -> String {
    format!("inbox_key:v1:{owner}")
}

fn decode_sk(sk_hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(sk_hex).map_err(|_| "inbox key is not hex".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "inbox key is not 32 bytes".to_string())
}

fn signer_from_hex(sk_hex: &str) -> Result<PrfSigner, String> {
    let sk = decode_sk(sk_hex)?;
    let secret = nostr_bbs_core::keys::SecretKey::from_bytes(sk).map_err(|e| e.to_string())?;
    let public = secret.public_key();
    Ok(PrfSigner::new(nostr_bbs_core::keys::Keypair {
        secret,
        public,
    }))
}

fn pubkey_of(sk_hex: &str) -> Result<String, String> {
    pubkey_hex(&decode_sk(sk_hex)?).map_err(|e| e.to_string())
}

/// Everything the lifecycle needs from the outside world. The live
/// implementation is [`LivePort`]; tests use an in-memory one.
#[allow(async_fn_in_trait)]
pub trait InboxPort {
    /// Stored local state, or `None` when absent or unreadable.
    async fn load_local(&self) -> Option<LocalInbox>;
    /// Persist local state; false on failure.
    async fn save_local(&self, state: &LocalInbox) -> bool;
    /// Kind-30078 events authored by the owner. `Err` means "could not find
    /// out" (timeout, disconnect), which is not the same as an empty list.
    async fn fetch_backups(&self) -> Result<Vec<NostrEvent>, String>;
    /// Publish the backup; `Ok` only when the relay answered OK true.
    async fn publish_backup(&self, event: &NostrEvent) -> Result<(), String>;
    /// Register `key` with the auth-worker, `proof` signed by that key.
    async fn register(&self, key: &str, proof: &NostrEvent) -> Result<(), String>;
}

fn d_tag(ev: &NostrEvent) -> Option<&str> {
    ev.tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "d")
        .map(|t| t[1].as_str())
}

/// The newest valid backup among `events`: kind 30078, authored by `owner`,
/// the right `d` tag, id and signature verified.
pub fn pick_backup<'a>(events: &'a [NostrEvent], owner: &str) -> Option<&'a NostrEvent> {
    events
        .iter()
        .filter(|e| {
            e.kind == KIND_APP_DATA
                && e.pubkey == owner
                && d_tag(e) == Some(BACKUP_D_TAG)
                && verify_event_strict(e).is_ok()
        })
        .max_by_key(|e| e.created_at)
}

/// Build and sign the backup event with the identity signer.
pub async fn build_backup(
    identity: &dyn Signer,
    sk_hex: &str,
    created_at: u64,
) -> Result<NostrEvent, String> {
    let owner = identity.public_key().to_string();
    let payload = serde_json::to_string(&InboxBackup {
        sk_hex: sk_hex.to_string(),
        created_at,
    })
    .map_err(|e| e.to_string())?;
    let content = identity
        .nip44_encrypt(&owner, &payload)
        .await
        .map_err(|e| e.to_string())?;
    identity
        .sign_event(UnsignedEvent {
            pubkey: owner,
            created_at,
            kind: KIND_APP_DATA,
            tags: vec![vec!["d".to_string(), BACKUP_D_TAG.to_string()]],
            content,
        })
        .await
        .map_err(|e| e.to_string())
}

/// Decrypt a backup event and check the secret is a valid key.
pub async fn open_backup(identity: &dyn Signer, ev: &NostrEvent) -> Result<InboxBackup, String> {
    let owner = identity.public_key().to_string();
    let plain = identity
        .nip44_decrypt(&owner, &ev.content)
        .await
        .map_err(|_| "inbox backup does not decrypt".to_string())?;
    let b: InboxBackup =
        serde_json::from_str(&plain).map_err(|_| "inbox backup malformed".to_string())?;
    pubkey_of(&b.sk_hex).map_err(|_| "inbox backup holds an invalid key".to_string())?;
    Ok(b)
}

/// The registration proof, signed by the inbox key: kind 27237 (distinct from the
/// NIP-98 kind 27235 and the device-link proof 27236, so neither can be replayed
/// here), tags `owner`
/// (identity pubkey) and `exp` (unix seconds). One function so a change to the
/// auth-worker's contract is a one-line edit.
pub async fn build_proof(inbox: &dyn Signer, owner: &str, now: u64) -> Result<NostrEvent, String> {
    inbox
        .sign_event(UnsignedEvent {
            pubkey: inbox.public_key().to_string(),
            created_at: now,
            kind: KIND_PROOF,
            tags: vec![
                vec!["owner".to_string(), owner.to_string()],
                vec!["exp".to_string(), (now + PROOF_TTL_SECS).to_string()],
            ],
            content: String::new(),
        })
        .await
        .map_err(|e| e.to_string())
}

async fn register<P: InboxPort>(
    port: &P,
    st: &mut LocalInbox,
    owner: &str,
    now: u64,
) -> Result<InboxKey, String> {
    let inbox = signer_from_hex(&st.sk_hex)?;
    let proof = build_proof(&inbox, owner, now).await?;
    port.register(inbox.public_key(), &proof)
        .await
        .map_err(|e| format!("inbox key registration failed: {e}"))?;
    st.registered = true;
    if !port.save_local(st).await {
        return Err("inbox key registered but not saved locally".into());
    }
    Ok(InboxKey {
        sk_hex: st.sk_hex.clone(),
        pubkey: inbox.public_key().to_string(),
    })
}

/// Bring the inbox key to the active state, creating or restoring it as
/// needed. Returns the active key; any error leaves no key active.
pub async fn ensure_inbox_key<P: InboxPort>(
    port: &P,
    identity: &dyn Signer,
    now: u64,
) -> Result<InboxKey, String> {
    let owner = identity.public_key().to_string();
    if let Some(st) = port.load_local().await {
        let pubkey = pubkey_of(&st.sk_hex)?;
        if st.registered {
            return Ok(InboxKey {
                sk_hex: st.sk_hex,
                pubkey,
            });
        }
        // Pending from an earlier run. Registration waits for the backup: a
        // registered key with no backup would be lost with this browser, and a
        // second browser would generate another.
        let mut st = st;
        backup_then_register(port, identity, &mut st, &owner, now).await?;
        return Ok(InboxKey {
            sk_hex: st.sk_hex,
            pubkey,
        });
    }
    let events = port
        .fetch_backups()
        .await
        .map_err(|e| format!("could not check for an inbox backup: {e}"))?;
    let mut st = match pick_backup(&events, &owner) {
        Some(ev) => {
            // A backup we cannot open is an error, never a reason to generate:
            // a new key would replace the one backup that holds the real one.
            let b = open_backup(identity, ev).await?;
            LocalInbox {
                sk_hex: b.sk_hex,
                created_at: b.created_at,
                backed_up: true,
                registered: false,
            }
        }
        None => {
            let kp = generate_keypair().map_err(|e| e.to_string())?;
            LocalInbox {
                sk_hex: hex::encode(kp.secret.as_bytes()),
                created_at: now,
                backed_up: false,
                registered: false,
            }
        }
    };
    if !port.save_local(&st).await {
        return Err("inbox key could not be saved locally".into());
    }
    backup_then_register(port, identity, &mut st, &owner, now).await?;
    Ok(InboxKey {
        pubkey: pubkey_of(&st.sk_hex)?,
        sk_hex: st.sk_hex,
    })
}

async fn backup_then_register<P: InboxPort>(
    port: &P,
    identity: &dyn Signer,
    st: &mut LocalInbox,
    owner: &str,
    now: u64,
) -> Result<(), String> {
    if !st.backed_up {
        let ev = build_backup(identity, &st.sk_hex, st.created_at).await?;
        port.publish_backup(&ev)
            .await
            .map_err(|e| format!("inbox backup not published: {e}"))?;
        st.backed_up = true;
        if !port.save_local(st).await {
            return Err("inbox key could not be saved locally".into());
        }
    }
    register(port, st, owner, now).await.map(|_| ())
}

// -- Issuer side: lookup ------------------------------------------------------

/// Outcome of asking the auth-worker for a member's inbox key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// The member has an active inbox key.
    Found(String),
    /// Definitely none: wrap to the identity key.
    None,
    /// Could not find out: do not grant (it would leak to the identity key).
    Unknown(String),
}

/// Read a lookup reply: `{"keys":[{"key","role","revoked","created_at"}]}`.
/// The newest unrevoked `inbox` entry wins; an empty list is a definite none.
pub fn parse_lookup(body: &str) -> Lookup {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return Lookup::Unknown("lookup reply is not JSON".into());
    };
    let Some(list) = v.get("keys").and_then(|k| k.as_array()) else {
        return Lookup::Unknown("lookup reply has no keys list".into());
    };
    let best = list
        .iter()
        .filter(|e| e.get("role").and_then(|r| r.as_str()).unwrap_or("inbox") == "inbox")
        .filter(|e| !matches!(e.get("revoked"), Some(r) if r.as_bool() == Some(true) || r.as_i64().is_some_and(|n| n != 0)))
        .filter_map(|e| {
            let key = e.get("key")?.as_str()?;
            (key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()))
                .then(|| (e.get("created_at").and_then(|c| c.as_u64()).unwrap_or(0), key))
        })
        .max_by_key(|(c, _)| *c);
    match best {
        Some((_, k)) => Lookup::Found(k.to_ascii_lowercase()),
        None => Lookup::None,
    }
}

/// Turn a fetch result into a [`Lookup`]. A 404 is a definite "none"; every
/// other failure is unknown.
pub fn classify_lookup(result: Result<String, String>) -> Lookup {
    match result {
        Ok(body) => parse_lookup(&body),
        Err(e) if e.contains("HTTP 404") => Lookup::None,
        Err(e) => Lookup::Unknown(e),
    }
}

/// The key a grant to `member` should be wrapped to: `Ok(key)` (inbox or the
/// identity itself), or `Err` when it must be skipped as failed.
pub fn grant_target(member: &str, lookup: Lookup) -> Result<String, String> {
    match lookup {
        Lookup::Found(k) => Ok(k),
        Lookup::None => Ok(member.to_string()),
        Lookup::Unknown(e) => Err(e),
    }
}

// -- Subscription helpers (pure) ------------------------------------------------

/// `#p` values for the gift-wrap subscription: identity, plus the inbox key
/// when one is active (grants may still arrive at the identity meanwhile).
pub fn subscription_targets(me: &str, inbox_pk: Option<&str>) -> Vec<String> {
    let mut v = vec![me.to_string()];
    if let Some(pk) = inbox_pk.filter(|pk| *pk != me) {
        v.push(pk.to_string());
    }
    v
}

/// Unwrap a gift wrap: with the inbox key first (when present), then the
/// identity signer.
pub async fn unwrap_inbox_then_identity(
    wrap: &NostrEvent,
    inbox: Option<&dyn Signer>,
    identity: &dyn Signer,
) -> Result<(String, UnsignedEvent), String> {
    if let Some(inbox) = inbox {
        if let Ok(v) = super::unwrap_any(wrap, inbox).await {
            return Ok(v);
        }
    }
    super::unwrap_any(wrap, identity).await
}

// -- Old-grant sweep (decision 5) -------------------------------------------------

/// A gift wrap examined by the sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepCandidate {
    /// The wrap's event id.
    pub wrap_id: String,
    /// Addressed to the identity pubkey (not the inbox key).
    pub to_identity: bool,
    /// Its rumor is a zone-key grant.
    pub is_grant: bool,
    /// The key it carried is persisted here AND the same `(zone, epoch)` grant
    /// has also arrived addressed to the inbox key, so a replacement provably
    /// exists on the relay. Local persistence alone is not enough: a wiped
    /// IndexedDB would otherwise leave no copy anywhere.
    pub key_safe: bool,
}

/// Wrap ids to delete. Empty unless `enabled`; only grants addressed to the
/// identity whose key is safe locally. DMs are never selected.
pub fn sweep_targets(enabled: bool, candidates: &[SweepCandidate]) -> Vec<String> {
    if !enabled {
        return Vec::new();
    }
    candidates
        .iter()
        .filter(|c| c.to_identity && c.is_grant && c.key_safe)
        .map(|c| c.wrap_id.clone())
        .collect()
}

/// The unsigned kind-5 deleting one wrap.
pub fn deletion_for_wrap(pubkey: &str, wrap_id: &str, now: u64) -> UnsignedEvent {
    UnsignedEvent {
        pubkey: pubkey.to_string(),
        created_at: now,
        kind: 5,
        tags: vec![vec!["e".to_string(), wrap_id.to_string()]],
        content: String::new(),
    }
}

// -- Live port ------------------------------------------------------------------

struct Slot<T> {
    value: RefCell<Option<T>>,
    waker: RefCell<Option<Waker>>,
}

impl<T> Slot<T> {
    fn new() -> Rc<Self> {
        Rc::new(Self {
            value: RefCell::new(None),
            waker: RefCell::new(None),
        })
    }
    /// First writer wins.
    fn fill(&self, v: T) {
        if self.value.borrow().is_none() {
            *self.value.borrow_mut() = Some(v);
            if let Some(w) = self.waker.borrow_mut().take() {
                w.wake();
            }
        }
    }
    async fn wait(self: &Rc<Self>) -> T {
        std::future::poll_fn(|cx| {
            if let Some(v) = self.value.borrow_mut().take() {
                return Poll::Ready(v);
            }
            *self.waker.borrow_mut() = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

const RELAY_WAIT_MS: u32 = 8_000;

/// Browser implementation of [`InboxPort`]: IndexedDB, the relay connection
/// and the auth-worker.
pub struct LivePort {
    /// Relay connection used for the backup.
    pub relay: crate::relay::RelayConnection,
    /// The member's identity signer (NIP-98 for registration).
    pub identity: Rc<dyn Signer>,
}

struct Idb;
impl GrantKv for Idb {
    async fn get(&self, id: &str) -> Option<String> {
        crate::stores::indexed_db::ForumDb::open()
            .await
            .ok()?
            .get_zone_kv(id)
            .await
            .ok()
            .flatten()
    }
    async fn put(&self, id: &str, json: &str) -> bool {
        match crate::stores::indexed_db::ForumDb::open().await {
            Ok(db) => db.put_zone_kv(id, json).await.is_ok(),
            Err(_) => false,
        }
    }
}

impl InboxPort for LivePort {
    async fn load_local(&self) -> Option<LocalInbox> {
        let json = Idb.get(&local_id(self.identity.public_key())).await?;
        serde_json::from_str(&json).ok()
    }

    async fn save_local(&self, state: &LocalInbox) -> bool {
        match serde_json::to_string(state) {
            Ok(json) => Idb.put(&local_id(self.identity.public_key()), &json).await,
            Err(_) => false,
        }
    }

    async fn fetch_backups(&self) -> Result<Vec<NostrEvent>, String> {
        let slot: Rc<Slot<Result<(), String>>> = Slot::new();
        let events: Rc<RefCell<Vec<NostrEvent>>> = Rc::default();
        let sink = events.clone();
        let done = slot.clone();
        let sub = self.relay.subscribe(
            vec![crate::relay::Filter {
                authors: Some(vec![self.identity.public_key().to_string()]),
                kinds: Some(vec![KIND_APP_DATA]),
                d_tags: Some(vec![BACKUP_D_TAG.to_string()]),
                ..Default::default()
            }],
            Rc::new(move |ev| sink.borrow_mut().push(ev)),
            Some(Rc::new(move || done.fill(Ok(())))),
        );
        let late = slot.clone();
        let _timer = gloo::timers::callback::Timeout::new(RELAY_WAIT_MS, move || {
            late.fill(Err("timed out waiting for the relay".into()))
        });
        let outcome = slot.wait().await;
        self.relay.unsubscribe(&sub);
        outcome?;
        let out = events.borrow().clone();
        Ok(out)
    }

    async fn publish_backup(&self, event: &NostrEvent) -> Result<(), String> {
        let slot: Rc<Slot<Result<(), String>>> = Slot::new();
        let done = slot.clone();
        self.relay.publish_with_ack(
            event,
            Some(Rc::new(move |ok, msg| {
                done.fill(if ok { Ok(()) } else { Err(msg) })
            })),
        )?;
        let late = slot.clone();
        let _timer = gloo::timers::callback::Timeout::new(RELAY_WAIT_MS, move || {
            late.fill(Err("timed out waiting for the relay".into()))
        });
        slot.wait().await
    }

    async fn register(&self, key: &str, proof: &NostrEvent) -> Result<(), String> {
        let url = format!(
            "{}/api/recipient-keys/register",
            crate::utils::relay_url::relay_api_base()
        );
        let body = serde_json::json!({ "key": key, "role": "inbox", "proof": proof }).to_string();
        crate::auth::nip98::fetch_with_nip98_post_signer(&url, &body, &*self.identity)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// Ask the auth-worker for `owner`'s inbox key (admin, NIP-98).
pub async fn lookup_inbox_key(admin: &dyn Signer, owner: &str) -> Lookup {
    let url = format!(
        "{}/api/recipient-keys/lookup?owner={owner}",
        crate::utils::relay_url::relay_api_base()
    );
    classify_lookup(
        crate::auth::nip98::fetch_with_nip98_get_signer(&url, admin)
            .await
            .map_err(|e| e.to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use nostr_bbs_core::signer::SignerError;
    use std::cell::Cell;

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        futures::executor::block_on(f)
    }

    fn local_signer() -> PrfSigner {
        PrfSigner::new(generate_keypair().unwrap())
    }

    /// Behaves like a NIP-07 extension: signs and does NIP-44, but never
    /// exposes raw key bytes.
    struct Ext(PrfSigner);
    #[async_trait(?Send)]
    impl Signer for Ext {
        fn public_key(&self) -> &str {
            self.0.public_key()
        }
        async fn sign_event(&self, u: UnsignedEvent) -> Result<NostrEvent, SignerError> {
            self.0.sign_event(u).await
        }
        async fn nip44_encrypt(&self, p: &str, t: &str) -> Result<String, SignerError> {
            self.0.nip44_encrypt(p, t).await
        }
        async fn nip44_decrypt(&self, p: &str, t: &str) -> Result<String, SignerError> {
            self.0.nip44_decrypt(p, t).await
        }
        async fn nip04_encrypt(&self, p: &str, t: &str) -> Result<String, SignerError> {
            self.0.nip04_encrypt(p, t).await
        }
        async fn nip04_decrypt(&self, p: &str, t: &str) -> Result<String, SignerError> {
            self.0.nip04_decrypt(p, t).await
        }
        fn raw_key_bytes(&self) -> Option<[u8; 32]> {
            None
        }
    }

    #[derive(Default)]
    struct MemPort {
        local: RefCell<Option<LocalInbox>>,
        relay: RefCell<Vec<NostrEvent>>,
        fetch_fails: Cell<bool>,
        register_fails: Cell<bool>,
        publish_fails: Cell<bool>,
        registered: RefCell<Vec<(String, NostrEvent)>>,
        fetches: Cell<u32>,
        publishes: Cell<u32>,
    }
    impl InboxPort for MemPort {
        async fn load_local(&self) -> Option<LocalInbox> {
            self.local.borrow().clone()
        }
        async fn save_local(&self, s: &LocalInbox) -> bool {
            *self.local.borrow_mut() = Some(s.clone());
            true
        }
        async fn fetch_backups(&self) -> Result<Vec<NostrEvent>, String> {
            self.fetches.set(self.fetches.get() + 1);
            if self.fetch_fails.get() {
                return Err("timeout".into());
            }
            Ok(self.relay.borrow().clone())
        }
        async fn publish_backup(&self, e: &NostrEvent) -> Result<(), String> {
            self.publishes.set(self.publishes.get() + 1);
            if self.publish_fails.get() {
                return Err("timeout".into());
            }
            self.relay.borrow_mut().push(e.clone());
            Ok(())
        }
        async fn register(&self, key: &str, proof: &NostrEvent) -> Result<(), String> {
            if self.register_fails.get() {
                return Err("HTTP 500".into());
            }
            self.registered
                .borrow_mut()
                .push((key.to_string(), proof.clone()));
            Ok(())
        }
    }

    fn roundtrip(identity: &dyn Signer) {
        let port = MemPort::default();
        let key = block_on(ensure_inbox_key(&port, identity, 1_000)).unwrap();
        assert_ne!(key.pubkey, identity.public_key());
        // The backup decrypts to the same key.
        let ev = port.relay.borrow()[0].clone();
        assert_eq!(ev.kind, KIND_APP_DATA);
        assert_eq!(d_tag(&ev), Some(BACKUP_D_TAG));
        let b = block_on(open_backup(identity, &ev)).unwrap();
        assert_eq!(b.sk_hex, key.sk_hex);
        // Registered with a proof signed by the inbox key naming the owner.
        let (reg_key, proof) = port.registered.borrow()[0].clone();
        assert_eq!(reg_key, key.pubkey);
        assert_eq!(proof.pubkey, key.pubkey);
        assert_eq!(proof.kind, KIND_PROOF);
        assert!(verify_event_strict(&proof).is_ok());
        assert!(proof
            .tags
            .contains(&vec!["owner".into(), identity.public_key().into()]));
        assert!(proof.tags.contains(&vec!["exp".into(), "1300".into()]));
        assert!(port.local.borrow().as_ref().unwrap().registered);
    }

    #[test]
    fn backup_round_trips_for_a_local_key_signer() {
        roundtrip(&local_signer());
    }

    #[test]
    fn backup_round_trips_for_a_nip07_style_signer() {
        roundtrip(&Ext(local_signer()));
    }

    #[test]
    fn restores_from_the_relay_backup_when_local_state_is_empty() {
        let id = Ext(local_signer());
        let first = MemPort::default();
        let original = block_on(ensure_inbox_key(&first, &id, 1_000)).unwrap();
        // A fresh browser: empty IndexedDB, same relay.
        let fresh = MemPort::default();
        *fresh.relay.borrow_mut() = first.relay.borrow().clone();
        let restored = block_on(ensure_inbox_key(&fresh, &id, 2_000)).unwrap();
        assert_eq!(restored, original);
        assert_eq!(fresh.publishes.get(), 0, "must not re-publish or replace");
        assert_eq!(fresh.registered.borrow().len(), 1);
    }

    #[test]
    fn an_unreachable_relay_generates_nothing() {
        let id = local_signer();
        let port = MemPort::default();
        port.fetch_fails.set(true);
        assert!(block_on(ensure_inbox_key(&port, &id, 1)).is_err());
        assert!(port.local.borrow().is_none());
        assert_eq!(port.publishes.get(), 0);
    }

    #[test]
    fn a_backup_from_someone_else_is_ignored() {
        let id = local_signer();
        let other = local_signer();
        let theirs = block_on(build_backup(&other, &"11".repeat(32), 5)).unwrap();
        assert!(pick_backup(std::slice::from_ref(&theirs), id.public_key()).is_none());
    }

    #[test]
    fn registration_failure_leaves_no_active_key_and_a_retry_reuses_it() {
        let id = local_signer();
        let port = MemPort::default();
        port.register_fails.set(true);
        assert!(block_on(ensure_inbox_key(&port, &id, 1)).is_err());
        let pending = port.local.borrow().clone().unwrap();
        assert!(
            !pending.registered,
            "failed registration must not be active"
        );
        // Retry: same key, no second backup, now active.
        port.register_fails.set(false);
        let key = block_on(ensure_inbox_key(&port, &id, 2)).unwrap();
        assert_eq!(key.sk_hex, pending.sk_hex);
        assert_eq!(port.publishes.get(), 1);
        assert!(port.local.borrow().as_ref().unwrap().registered);
    }

    #[test]
    fn an_active_key_makes_no_network_calls() {
        let id = local_signer();
        let port = MemPort::default();
        block_on(ensure_inbox_key(&port, &id, 1)).unwrap();
        let (f, p, r) = (
            port.fetches.get(),
            port.publishes.get(),
            port.registered.borrow().len(),
        );
        block_on(ensure_inbox_key(&port, &id, 2)).unwrap();
        assert_eq!(
            (f, p, r),
            (
                port.fetches.get(),
                port.publishes.get(),
                port.registered.borrow().len()
            )
        );
    }

    #[test]
    fn the_flag_is_off_unless_exactly_true() {
        assert!(!super::super::gate_value_enabled(None));
        assert!(!super::super::gate_value_enabled(Some("1")));
        assert!(super::super::gate_value_enabled(Some("true")));
    }

    #[test]
    fn subscription_adds_the_inbox_key_after_the_identity() {
        let me = "aa".repeat(32);
        let ib = "bb".repeat(32);
        assert_eq!(subscription_targets(&me, None), vec![me.clone()]);
        assert_eq!(subscription_targets(&me, Some(&ib)), vec![me.clone(), ib]);
        assert_eq!(subscription_targets(&me, Some(&me)), vec![me]);
    }

    fn grant_to(admin: &PrfSigner, recipient: &str) -> NostrEvent {
        let key = super::super::generate_zone_key("zone3", 1, admin.public_key(), 0).unwrap();
        block_on(super::super::build_grant_wrap(admin, recipient, &key, 10)).unwrap()
    }

    #[test]
    fn a_grant_to_the_inbox_key_and_one_to_the_identity_both_open() {
        let admin = local_signer();
        let member = local_signer();
        let inbox = local_signer();
        let to_inbox = grant_to(&admin, inbox.public_key());
        let to_identity = grant_to(&admin, member.public_key());
        for wrap in [&to_inbox, &to_identity] {
            let (sealer, rumor) =
                block_on(unwrap_inbox_then_identity(wrap, Some(&inbox), &member)).unwrap();
            assert_eq!(sealer, admin.public_key());
            assert_eq!(rumor.kind, super::super::KIND_ZONE_KEY_GRANT);
        }
        // Without an inbox key (flag off) identity grants still open, and an
        // inbox grant does not.
        assert!(block_on(unwrap_inbox_then_identity(&to_identity, None, &member)).is_ok());
        assert!(block_on(unwrap_inbox_then_identity(&to_inbox, None, &member)).is_err());
    }

    #[test]
    fn lookup_parsing_distinguishes_none_from_unknown() {
        let k = "ab".repeat(32);
        let body = format!(
            r#"{{"keys":[{{"key":"{}","role":"inbox","revoked":0,"created_at":9}},
                {{"key":"{}","role":"inbox","revoked":1,"created_at":99}}]}}"#,
            k,
            "cd".repeat(32)
        );
        assert_eq!(parse_lookup(&body), Lookup::Found(k));
        assert_eq!(parse_lookup(r#"{"keys":[]}"#), Lookup::None);
        assert!(matches!(parse_lookup("nonsense"), Lookup::Unknown(_)));
        assert_eq!(classify_lookup(Err("HTTP 404".into())), Lookup::None);
        assert!(matches!(
            classify_lookup(Err("HTTP 500".into())),
            Lookup::Unknown(_)
        ));
        let m = "11".repeat(32);
        assert_eq!(grant_target(&m, Lookup::None).unwrap(), m);
        assert!(grant_target(&m, Lookup::Unknown("x".into())).is_err());
    }

    fn cand(id: &str, to_identity: bool, is_grant: bool, key_safe: bool) -> SweepCandidate {
        SweepCandidate {
            wrap_id: id.into(),
            to_identity,
            is_grant,
            key_safe,
        }
    }

    #[test]
    fn sweep_publishes_nothing_when_its_flag_is_off() {
        let all = [cand("a", true, true, true)];
        assert!(sweep_targets(false, &all).is_empty());
    }

    #[test]
    fn sweep_selects_only_safe_identity_grants() {
        let all = [
            cand("grant", true, true, true),
            cand("dm", true, false, true),
            cand("inbox", false, true, true),
            cand("unsaved", true, true, false),
        ];
        assert_eq!(sweep_targets(true, &all), vec!["grant".to_string()]);
        let d = deletion_for_wrap("pk", "grant", 7);
        assert_eq!(d.kind, 5);
        assert_eq!(d.tags, vec![vec!["e".to_string(), "grant".to_string()]]);
    }

    #[test]
    fn sweep_never_deletes_an_identity_grant_without_an_inbox_replacement() {
        // key_safe is computed by the store as persisted && replacement_exists;
        // a persisted-but-unreplaced grant arrives here with key_safe == false
        // and must never be selected, whatever the other fields say.
        let unreplaced = SweepCandidate {
            wrap_id: "w1".into(),
            to_identity: true,
            is_grant: true,
            key_safe: false,
        };
        let replaced = SweepCandidate {
            wrap_id: "w2".into(),
            to_identity: true,
            is_grant: true,
            key_safe: true,
        };
        assert_eq!(
            sweep_targets(true, &[unreplaced.clone(), replaced]),
            vec!["w2".to_string()]
        );
        assert!(sweep_targets(true, &[unreplaced]).is_empty());
    }

    #[test]
    fn a_failed_backup_publish_is_retried_before_registering_and_no_second_key_appears() {
        let id = local_signer();
        let port = MemPort::default();
        port.publish_fails.set(true);
        assert!(block_on(ensure_inbox_key(&port, &id, 1)).is_err());
        assert!(
            port.registered.borrow().is_empty(),
            "no registration without a backup"
        );
        let first = port.local.borrow().clone().unwrap();
        assert!(!first.backed_up);
        port.publish_fails.set(false);
        let key = block_on(ensure_inbox_key(&port, &id, 2)).unwrap();
        assert_eq!(key.sk_hex, first.sk_hex);
        assert_eq!(
            port.fetches.get(),
            1,
            "the retry must not look for or make a new key"
        );
        let backup = port.relay.borrow()[0].clone();
        assert_eq!(
            block_on(open_backup(&id, &backup)).unwrap().sk_hex,
            key.sk_hex
        );
        assert_eq!(port.registered.borrow().len(), 1);
        let st = port.local.borrow().clone().unwrap();
        assert!(st.backed_up && st.registered);
    }

    struct Refuser {
        inner: PrfSigner,
        refuse: Cell<bool>,
    }
    #[async_trait(?Send)]
    impl Signer for Refuser {
        fn public_key(&self) -> &str {
            self.inner.public_key()
        }
        async fn sign_event(&self, u: UnsignedEvent) -> Result<NostrEvent, SignerError> {
            self.inner.sign_event(u).await
        }
        async fn nip44_encrypt(&self, p: &str, t: &str) -> Result<String, SignerError> {
            self.inner.nip44_encrypt(p, t).await
        }
        async fn nip44_decrypt(&self, p: &str, t: &str) -> Result<String, SignerError> {
            if self.refuse.get() {
                return Err(SignerError::SigningFailed("user refused".into()));
            }
            self.inner.nip44_decrypt(p, t).await
        }
        async fn nip04_encrypt(&self, p: &str, t: &str) -> Result<String, SignerError> {
            self.inner.nip04_encrypt(p, t).await
        }
        async fn nip04_decrypt(&self, p: &str, t: &str) -> Result<String, SignerError> {
            self.inner.nip04_decrypt(p, t).await
        }
    }

    #[test]
    fn a_backup_that_will_not_decrypt_is_an_error_and_generates_nothing() {
        let id = Refuser {
            inner: local_signer(),
            refuse: Cell::new(false),
        };
        let first = MemPort::default();
        block_on(ensure_inbox_key(&first, &id, 1)).unwrap();
        let fresh = MemPort::default();
        *fresh.relay.borrow_mut() = first.relay.borrow().clone();
        id.refuse.set(true);
        assert!(block_on(ensure_inbox_key(&fresh, &id, 2)).is_err());
        assert!(fresh.local.borrow().is_none());
        assert_eq!(fresh.publishes.get(), 0);
        assert!(fresh.registered.borrow().is_empty());
    }

    #[test]
    fn the_backup_fetch_filter_names_the_d_tag() {
        let f = crate::relay::Filter {
            d_tags: Some(vec![BACKUP_D_TAG.to_string()]),
            ..Default::default()
        };
        assert!(serde_json::to_string(&f)
            .unwrap()
            .contains("\"#d\":[\"nostr-bbs/zone-inbox/v1\"]"));
    }
}
