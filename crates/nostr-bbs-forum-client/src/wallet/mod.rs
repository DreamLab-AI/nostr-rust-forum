//! Member wallets on `sidestr:dreamlab` (testnet4) and DREAM tips (ADR-2015).
//!
//! Every member already has a wallet: on a sidestr chain a Nostr key's coins
//! pay `OP_1 <x-only key>`, so a member's npub *is* their address and anyone
//! can pay them without the member doing anything first. This module is the
//! browser half: it downloads the chain from a mirror, validates every block
//! against the pinned document ([`chain`]), reads DREAM under the SPEC 12
//! assets rule, and signs spends with the member's key in memory, never
//! sending it anywhere — or, for a member signed in with an extension that
//! offers `window.nostr.sidestr`, has the extension sign ([`extension`]).
//! Transactions travel as kind-23500 events, signed by a throwaway key (a
//! transaction authorises itself, SPEC 11), to the public relays the
//! producer follows ([`relays`]).
//!
//! Off unless the deployment sets `window.__ENV__.SIDESTR_WALLET = "on"`, so
//! an instance that has not opted in renders exactly as before.

pub mod chain;
pub mod extension;
pub mod relays;

use std::rc::Rc;

use bitcoin::{OutPoint, ScriptBuf};
use leptos::prelude::*;
use send_wrapper::SendWrapper;
use serde::{Deserialize, Serialize};
use sidestr_agent::AgentKey;
use sidestr_nostr::event::SecretKeySigner;
use sidestr_nostr::tx::{sign_faucet_request, sign_transaction_event};
use sidestr_wallet::asset::{build_transfer, sort_coins, TransferRequest};
use sidestr_wallet::coins::Coin;
use sidestr_wallet::external::{accept_signed, unsigned_hex, ExternalSigner};
use sidestr_wallet::spend::{build_spend, Spend, SpendRequest};
use sidestr_wallet::{Permissive, SpendSigner};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};

use crate::auth::AuthStore;
use crate::utils::relay_url::env_override;
use chain::{Snapshot, TipTotal};

/// Whether the deployment switched the wallet on.
pub fn enabled() -> bool {
    matches!(
        env_override("SIDESTR_WALLET").as_deref().map(str::trim),
        Some("on" | "true" | "1")
    )
}

/// The mirror base URL (no trailing slash).
pub fn mirror() -> String {
    env_override("SIDESTR_MIRROR")
        .filter(|m| m.starts_with("https://"))
        .unwrap_or_else(|| chain::DEFAULT_MIRROR.to_string())
        .trim_end_matches('/')
        .to_string()
}

/// The relays transactions and faucet requests go to.
pub fn relay_urls() -> Vec<String> {
    let from_env: Vec<String> = env_override("SIDESTR_RELAYS")
        .map(|s| {
            s.split(',')
                .map(|r| r.trim().to_string())
                .filter(|r| r.starts_with("wss://"))
                .collect()
        })
        .unwrap_or_default();
    if from_env.is_empty() {
        chain::DEFAULT_RELAYS
            .iter()
            .map(|r| r.to_string())
            .collect()
    } else {
        from_env
    }
}

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Where the chain stands for this session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadStatus {
    /// Not asked for yet.
    Idle,
    /// Downloading and validating.
    Loading,
    /// A snapshot is held.
    Ready,
    /// The last load failed (a snapshot from an earlier load may still be held).
    Failed(String),
}

/// What a sent transaction was for, for the activity list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PendingKind {
    /// DREAM to someone.
    Dream,
    /// DREAM on a post.
    Tip,
    /// Sats to someone.
    Sats,
    /// DREAM and sats together: a starter pack for a member or an agent.
    Provision,
}

/// A transaction this browser sent that the mirror has not shown yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// Its id.
    pub txid: String,
    /// What it was for.
    pub kind: PendingKind,
    /// The recipient's script, hex.
    pub to: String,
    /// DREAM sent.
    pub dream: u64,
    /// Sats sent (not counting the fee).
    pub sats: u64,
    /// The fee.
    pub fee: u64,
    /// Coins it spends, `txid:vout`: held back from the next build.
    pub spent: Vec<String>,
    /// The post, for a tip.
    #[serde(default)]
    pub tip_event: Option<String>,
    /// When it was sent, unix seconds.
    pub at: u64,
}

/// How this session can spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendPath {
    /// With a key in this tab: the forum session's own, or a session unlock.
    Key,
    /// Through the browser extension, which asks the member every time.
    Extension,
    /// Not at all yet: signed in with an extension that cannot sign spends,
    /// and not unlocked.
    None,
}

/// Who signs a spend being built.
enum Spender {
    Key(AgentKey),
    Extension(ExternalSigner),
}

impl Spender {
    fn script(&self) -> ScriptBuf {
        match self {
            Spender::Key(k) => k.script(),
            Spender::Extension(e) => e.script(),
        }
    }
    /// Run a builder with this spender's [`SpendSigner`].
    fn build<R>(&self, f: impl FnOnce(&dyn SpendSigner) -> R) -> R {
        match self {
            Spender::Key(k) => f(&k.spend_signer()),
            Spender::Extension(e) => f(e),
        }
    }
}

/// A pending transaction older than this whose coins are still unspent is
/// taken to have been dropped, and its coins are released.
const PENDING_TTL: u64 = 30 * 60;

/// The wallet's reactive state, provided once at the app root.
#[derive(Clone, Copy)]
pub struct WalletStore {
    /// Load state.
    pub status: RwSignal<LoadStatus>,
    /// Bumped on each successful load, so views that read the snapshot re-run.
    pub version: RwSignal<u64>,
    /// This browser's transactions not yet on the mirror.
    pub pending: RwSignal<Vec<Pending>>,
    /// Whether a key unlocked for this session only is held.
    pub unlocked: RwSignal<bool>,
    /// Unix ms of the last successful load.
    pub loaded_at: RwSignal<f64>,
    snapshot: StoredValue<Option<SendWrapper<Rc<Snapshot>>>>,
    session_key: StoredValue<Option<SendWrapper<zeroize::Zeroizing<[u8; 32]>>>>,
    pending_owner: StoredValue<String>,
    refresh_armed: StoredValue<bool>,
}

/// Provide the wallet store; call once, at the app root.
pub fn provide_wallet() {
    let store = WalletStore {
        status: RwSignal::new(LoadStatus::Idle),
        version: RwSignal::new(0),
        pending: RwSignal::new(Vec::new()),
        unlocked: RwSignal::new(false),
        loaded_at: RwSignal::new(0.0),
        snapshot: StoredValue::new(None),
        session_key: StoredValue::new(None),
        pending_owner: StoredValue::new(String::new()),
        refresh_armed: StoredValue::new(false),
    };
    provide_context(store);
    // The pending list and any session unlock belong to the signed-in member:
    // rebind on every sign-in, and forget both on sign-out.
    if let Some(auth) = use_context::<AuthStore>() {
        Effect::new(move |_| {
            let pk = auth.pubkey().get().unwrap_or_default();
            store.bind_owner(&pk);
        });
    }
}

/// The wallet store, when the wallet is switched on and provided.
pub fn use_wallet() -> Option<WalletStore> {
    if !enabled() {
        return None;
    }
    use_context::<WalletStore>()
}

/// Fetch `url` as bytes.
async fn fetch_bytes(url: &str) -> Result<Vec<u8>, String> {
    let win = web_sys::window().ok_or("no window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("GET");
    init.set_cache(web_sys::RequestCache::NoStore);
    let req = web_sys::Request::new_with_str_and_init(url, &init)
        .map_err(|_| "could not build the request".to_string())?;
    let resp: web_sys::Response = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|_| "the mirror could not be reached".to_string())?
        .dyn_into()
        .map_err(|_| "bad response".to_string())?;
    if !resp.ok() {
        return Err(format!("the mirror answered {}", resp.status()));
    }
    let buf = JsFuture::from(resp.array_buffer().map_err(|_| "no body".to_string())?)
        .await
        .map_err(|_| "the download was cut short".to_string())?;
    Ok(js_sys::Uint8Array::new(&buf).to_vec())
}

fn random_32() -> Option<[u8; 32]> {
    let mut b = [0u8; 32];
    web_sys::window()?
        .crypto()
        .ok()?
        .get_random_values_with_u8_array(&mut b)
        .ok()?;
    Some(b)
}

fn pending_key(owner: &str) -> String {
    format!("sidestr.pending.{owner}")
}

impl WalletStore {
    /// The snapshot, reactively (re-read when a load lands).
    pub fn snapshot(&self) -> Option<Rc<Snapshot>> {
        self.version.track();
        self.snapshot_untracked()
    }

    fn snapshot_untracked(&self) -> Option<Rc<Snapshot>> {
        self.snapshot
            .with_value(|s| s.as_ref().map(|w| Rc::clone(&**w)))
    }

    /// Load once for this session if nothing is held or loading.
    pub fn ensure_loaded(&self) {
        if matches!(self.status.get_untracked(), LoadStatus::Idle) {
            self.reload();
        }
    }

    /// Download and validate the chain now.
    pub fn reload(&self) {
        if matches!(self.status.get_untracked(), LoadStatus::Loading) {
            return;
        }
        self.status.set(LoadStatus::Loading);
        let store = *self;
        spawn_local(async move {
            // a query string defeats the CDN's ten-minute cache; the mirror
            // serves the same bytes for any query
            let url = format!("{}/blocks.dat?t={}", mirror(), now_secs() / 15);
            let result = match fetch_bytes(&url).await {
                Ok(dat) => chain::replay(&dat, Some(now_secs() as u32)),
                Err(e) => Err(e),
            };
            match result {
                Ok(snap) => {
                    store
                        .snapshot
                        .set_value(Some(SendWrapper::new(Rc::new(snap))));
                    store.loaded_at.set(js_sys::Date::now());
                    store.status.set(LoadStatus::Ready);
                    store.reconcile();
                    store.version.update(|v| *v += 1);
                }
                Err(e) => store.status.set(LoadStatus::Failed(e)),
            }
            store.arm_refresh();
        });
    }

    /// While something is pending, look again every 20 s.
    fn arm_refresh(&self) {
        if self.pending.get_untracked().is_empty() || self.refresh_armed.get_value() {
            return;
        }
        self.refresh_armed.set_value(true);
        let store = *self;
        gloo::timers::callback::Timeout::new(20_000, move || {
            store.refresh_armed.set_value(false);
            store.reload();
        })
        .forget();
    }

    /// Drop pending transactions the chain now shows, and ones that were
    /// evidently dropped.
    fn reconcile(&self) {
        let Some(snap) = self.snapshot_untracked() else {
            return;
        };
        let now = now_secs();
        self.pending.update(|list| {
            list.retain(|p| {
                if snap.contains(&p.txid) {
                    return false;
                }
                let still_unspent = p
                    .spent
                    .iter()
                    .filter_map(|s| s.parse::<OutPoint>().ok())
                    .all(|op| snap.unspent(&op));
                !(still_unspent && now.saturating_sub(p.at) > PENDING_TTL)
            });
        });
        self.save_pending();
    }

    /// Bind the pending list to the signed-in member (restored from
    /// localStorage); called when the member is known.
    pub fn bind_owner(&self, pubkey: &str) {
        if self.pending_owner.get_value() == pubkey {
            return;
        }
        self.pending_owner.set_value(pubkey.to_string());
        let restored: Vec<Pending> = web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .and_then(|s| s.get_item(&pending_key(pubkey)).ok().flatten())
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        self.pending.set(restored);
        self.session_key.set_value(None);
        self.unlocked.set(false);
    }

    fn save_pending(&self) {
        let owner = self.pending_owner.get_value();
        if owner.is_empty() {
            return;
        }
        if let (Some(s), Ok(t)) = (
            web_sys::window().and_then(|w| w.local_storage().ok().flatten()),
            serde_json::to_string(&self.pending.get_untracked()),
        ) {
            let _ = s.set_item(&pending_key(&owner), &t);
        }
    }

    /// Coins a pending transaction spends.
    fn held(&self) -> Vec<OutPoint> {
        self.pending
            .get_untracked()
            .iter()
            .flat_map(|p| p.spent.iter().filter_map(|s| s.parse().ok()))
            .collect()
    }

    /// DREAM tipped on a post, the mirror's count plus this browser's
    /// pending tips.
    pub fn tip_total(&self, event_id: &str) -> TipTotal {
        let mut t = self
            .snapshot()
            .and_then(|s| s.tips.get(event_id).copied())
            .unwrap_or_default();
        for p in self.pending.get().iter() {
            if p.tip_event.as_deref() == Some(event_id) {
                t.dream += p.dream;
                t.count += 1;
            }
        }
        t
    }

    /// Unlock spending for this session with a pasted nsec (or hex): the
    /// fallback for a member signed in through an extension that cannot sign
    /// spends, whose key the forum never holds. The key must be the
    /// signed-in member's; it stays in memory for this tab only.
    pub fn unlock(&self, text: &str, expected_pubkey: &str) -> Result<(), String> {
        let k = AgentKey::parse(text)
            .map_err(|_| "That is not an nsec or a 64-hex key.".to_string())?;
        if !k.pubkey().to_string().eq_ignore_ascii_case(expected_pubkey) {
            return Err("That key is not the one you are signed in with.".into());
        }
        let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
        let hex_secret = zeroize::Zeroizing::new(
            // AgentKey keeps its secret private; re-derive the bytes from the text
            match text.trim() {
                t if t.to_ascii_lowercase().starts_with("nsec1") => {
                    let (_, data) = bech32::decode(t).map_err(|_| "Not an nsec.".to_string())?;
                    hex::encode(data)
                }
                t => t.to_string(),
            },
        );
        hex::decode_to_slice(hex_secret.as_str(), &mut bytes[..])
            .map_err(|_| "That is not an nsec or a 64-hex key.".to_string())?;
        self.session_key.set_value(Some(SendWrapper::new(bytes)));
        self.unlocked.set(true);
        Ok(())
    }

    /// Forget a session unlock.
    pub fn lock(&self) {
        self.session_key.set_value(None);
        self.unlocked.set(false);
    }

    /// The member's signing key: the forum session's own (passkey or local
    /// key), else a session unlock.
    pub fn signing_key(&self, auth: &AuthStore) -> Option<AgentKey> {
        if let Some(b) = auth.get_privkey_bytes() {
            return AgentKey::from_secret_bytes(&b).ok();
        }
        self.session_key
            .with_value(|k| k.as_ref().and_then(|b| AgentKey::from_secret_bytes(b).ok()))
    }

    /// How this session can spend: a key in the tab first, then the
    /// extension, when it offers `window.nostr.sidestr`.
    pub fn spend_path(&self, auth: &AuthStore) -> SpendPath {
        self.unlocked.get();
        let signed_in = auth.get().pubkey;
        if auth.get_privkey_bytes().is_some() || self.session_key.with_value(|k| k.is_some()) {
            SpendPath::Key
        } else if signed_in.is_some() && extension::available() {
            SpendPath::Extension
        } else {
            SpendPath::None
        }
    }

    /// Whether this session can spend.
    pub fn can_spend(&self, auth: &AuthStore) -> bool {
        self.spend_path(auth) != SpendPath::None
    }

    fn spender(&self, auth: &AuthStore) -> Option<Spender> {
        if let Some(k) = self.signing_key(auth) {
            return Some(Spender::Key(k));
        }
        let pk = auth.get().pubkey?;
        if !extension::available() {
            return None;
        }
        let key = sidestr_agent::parse_pubkey(&pk).ok()?;
        Some(Spender::Extension(ExternalSigner::new(key)))
    }

    /// A spend built for the extension goes to it now; one built with a key
    /// is already signed. The extension's answer is taken only if it is the
    /// same transaction with every input validly signed against the coins
    /// this tab built from.
    async fn signed(
        &self,
        spender: &Spender,
        spend: Spend,
        coins: &[Coin],
        me: &ScriptBuf,
    ) -> Result<Spend, String> {
        let Spender::Extension(_) = spender else {
            return Ok(spend);
        };
        let prevouts = chain::prevouts_for(&spend.tx, coins, me)?;
        let answer = extension::sign(chain::CHAIN_ID, &unsigned_hex(&spend.tx))
            .await
            .map_err(|r| extension::explain(&r))?;
        accept_signed(&spend, &answer, &prevouts, &chain::document()?).map_err(|e| {
            format!("Your extension's answer was not a valid signature for this transfer, so nothing was sent ({e}).")
        })
    }

    async fn deliver(&self, spend: Spend, mut pending: Pending) -> Result<String, String> {
        let doc = chain::document()?;
        // the transaction authorises itself (SPEC 11): the event that carries
        // it comes from a throwaway key, so the member is asked once, for the spend
        let secret = random_32().ok_or("This browser has no secure random source.")?;
        let carrier = SecretKeySigner::from_bytes(&secret).map_err(|e| e.to_string())?;
        let event = sign_transaction_event(&carrier, &doc.id, &spend.hex, now_secs())
            .map_err(|e| format!("could not sign the event: {e}"))?;
        let json = serde_json::to_string(&event).map_err(|e| e.to_string())?;
        let (ok, _) = relays::publish_all(&relay_urls(), &json, &event.id).await;
        if ok == 0 {
            return Err("No relay took the transaction. Nothing was sent; try again.".into());
        }
        pending.txid = spend.txid.to_string();
        pending.fee = spend.fee;
        pending.spent = spend
            .tx
            .input
            .iter()
            .map(|i| i.previous_output.to_string())
            .collect();
        pending.at = now_secs();
        let txid = pending.txid.clone();
        self.pending.update(|l| l.insert(0, pending));
        self.save_pending();
        self.arm_refresh();
        Ok(txid)
    }

    fn ready(&self, auth: &AuthStore) -> Result<(Rc<Snapshot>, Spender, ScriptBuf), String> {
        let snap = self
            .snapshot_untracked()
            .ok_or("The chain has not loaded yet.")?;
        let spender = self.spender(auth).ok_or("Unlock your wallet to send.")?;
        let me = spender.script();
        Ok((snap, spender, me))
    }

    /// Send DREAM, optionally as a tip on a post.
    pub async fn send_dream(
        &self,
        auth: &AuthStore,
        to: ScriptBuf,
        amount: u64,
        tip_event: Option<String>,
    ) -> Result<String, String> {
        let (snap, spender, me) = self.ready(auth)?;
        if to == me {
            return Err("That is your own wallet.".into());
        }
        let coins = snap.coins(&me, &self.held());
        let memos: Vec<String> = tip_event
            .iter()
            .map(|e| format!("{}{e}", chain::TIP_PREFIX))
            .collect();
        let t = spender
            .build(|signer| {
                build_transfer(
                    &TransferRequest {
                        chain: snap.view.state.document(),
                        coins: &coins,
                        view: &snap.view.assets,
                        tip_height: snap.height(),
                        asset: chain::dream_id(),
                        to: &to.to_hex_string(),
                        amount,
                        memos: &memos,
                        fee: None,
                    },
                    signer,
                    &Permissive,
                )
            })
            .map_err(explain)?;
        let spend = self.signed(&spender, t.spend, &coins, &me).await?;
        let kind = if tip_event.is_some() {
            PendingKind::Tip
        } else {
            PendingKind::Dream
        };
        self.deliver(
            spend,
            Pending {
                txid: String::new(),
                kind,
                to: to.to_hex_string(),
                dream: amount,
                sats: 0,
                fee: 0,
                spent: vec![],
                tip_event,
                at: 0,
            },
        )
        .await
    }

    /// Send plain sats (never from a DREAM carrier).
    pub async fn send_sats(
        &self,
        auth: &AuthStore,
        to: ScriptBuf,
        sats: u64,
    ) -> Result<String, String> {
        let (snap, spender, me) = self.ready(auth)?;
        if to == me {
            return Err("That is your own wallet.".into());
        }
        let coins = snap.coins(&me, &self.held());
        let plain = sort_coins(&coins, &snap.view.assets, None).plain;
        let spend = spender
            .build(|signer| {
                build_spend(
                    &SpendRequest {
                        chain: snap.view.state.document(),
                        coins: &plain,
                        tip_height: snap.height(),
                        to: &to.to_hex_string(),
                        amount: sats,
                        fee: None,
                    },
                    signer,
                    &Permissive,
                )
            })
            .map_err(explain)?;
        let spend = self.signed(&spender, spend, &coins, &me).await?;
        self.deliver(
            spend,
            Pending {
                txid: String::new(),
                kind: PendingKind::Sats,
                to: to.to_hex_string(),
                dream: 0,
                sats,
                fee: 0,
                spent: vec![],
                tip_event: None,
                at: 0,
            },
        )
        .await
    }

    /// Provision a member or an agent: DREAM on a carrier and sats for their
    /// fees, in one transaction.
    pub async fn provision(
        &self,
        auth: &AuthStore,
        to: ScriptBuf,
        dream: u64,
        sats: u64,
    ) -> Result<String, String> {
        let (snap, spender, me) = self.ready(auth)?;
        if to == me {
            return Err("That is your own wallet.".into());
        }
        let coins = snap.coins(&me, &self.held());
        let spend = spender
            .build(|signer| chain::build_provision(&snap, &coins, signer, &to, dream, sats))
            .map_err(|e| match e {
                chain::ProvisionError::Wallet(w) => explain(w),
                chain::ProvisionError::Plain(m) => m,
            })?;
        let spend = self.signed(&spender, spend, &coins, &me).await?;
        self.deliver(
            spend,
            Pending {
                txid: String::new(),
                kind: PendingKind::Provision,
                to: to.to_hex_string(),
                dream,
                sats,
                fee: 0,
                spent: vec![],
                tip_event: None,
                at: 0,
            },
        )
        .await
    }

    /// Ask the DreamLab faucet for a starter pack (kind 23501). Signed with a
    /// throwaway key: the request names only the address to pay.
    pub async fn request_faucet(&self, pubkey_hex: &str) -> Result<usize, String> {
        let address = chain::address_of(pubkey_hex).ok_or("No wallet address for this key.")?;
        let secret = random_32().ok_or("This browser has no secure random source.")?;
        let signer = SecretKeySigner::from_bytes(&secret).map_err(|e| e.to_string())?;
        let ev = sign_faucet_request(&signer, chain::CHAIN_ID, &address, now_secs())
            .map_err(|e| e.to_string())?;
        let json = serde_json::to_string(&ev).map_err(|e| e.to_string())?;
        let (ok, _) = relays::publish_all(&relay_urls(), &json, &ev.id).await;
        if ok == 0 {
            return Err("No relay took the request. Try again in a moment.".into());
        }
        self.arm_refresh_for_faucet();
        Ok(ok)
    }

    fn arm_refresh_for_faucet(&self) {
        let store = *self;
        for delay in [30_000, 90_000] {
            gloo::timers::callback::Timeout::new(delay, move || store.reload()).forget();
        }
    }
}

/// Wallet errors in words a member can act on.
pub fn explain(e: sidestr_wallet::Error) -> String {
    use sidestr_wallet::Error as E;
    match e {
        E::Insufficient { have, need } => format!(
            "Not enough sats for this and its fee: you have {have}, it needs {need}. Transfers cost a small fee in sats."
        ),
        E::InsufficientForFee { fee, .. } => {
            format!("Not enough sats left for the fee ({fee} sats).")
        }
        E::Asset(m) if m.starts_with("holds ") => {
            format!("Not enough DREAM: you {}.", m.replace("of the asset,", "DREAM,"))
        }
        E::Dust { min, .. } => format!("The smallest payment is {min} sats."),
        E::BadDestination(_) => "That is not a wallet address.".into(),
        E::BadAmount => "Enter an amount above zero.".into(),
        other => other.to_string(),
    }
}
