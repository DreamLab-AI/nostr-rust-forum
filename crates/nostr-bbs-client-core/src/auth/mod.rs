//! Auth state management for the nostr-bbs community forum.
//!
//! Ports the SvelteKit auth store (`stores/auth.ts`) to Leptos reactive signals.
//! Private key bytes are held in memory only and zeroized on drop/pagehide.

mod http;
pub mod nip07;
pub mod nip98;
pub mod passkey;
mod session;
mod webauthn;

#[cfg(feature = "dev-auth")]
pub mod dev;

use gloo::storage::{LocalStorage, Storage};
use leptos::prelude::*;
use send_wrapper::SendWrapper;
use serde::{Deserialize, Serialize};
use std::rc::Rc;
use zeroize::Zeroize;

use self::passkey::{PasskeyAuthResult, PasskeyRegistrationResult};
use self::session::{
    clear_privkey_session, read_privkey_session, save_privkey_session, StoredSession,
};
use crate::base::base_href;
use nostr_bbs_core::signer::Signer;
use nostr_bbs_core::{NostrEvent, UnsignedEvent};

/// Thread-local signer: SendWrapper makes `Rc<dyn Signer>` passable across Send boundaries
/// in WASM's single-threaded environment.
type SignerHandle = SendWrapper<Rc<dyn Signer>>;

// -- Constants ----------------------------------------------------------------

const STORAGE_KEY: &str = "nostr_bbs_keys";

// -- Auth state ---------------------------------------------------------------

/// Reactive auth state mirroring the SvelteKit `AuthState` interface.
///
/// **Security**: Private key bytes are stored separately in `AuthStore::privkey`
/// (a non-reactive `StoredValue`). They never enter the reactive signal graph,
/// preventing accidental leaks through Memo clones or debug output.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthState {
    pub state: AuthPhase,
    pub pubkey: Option<String>,
    pub is_authenticated: bool,
    pub public_key: Option<String>,
    pub nickname: Option<String>,
    pub avatar: Option<String>,
    pub error: Option<String>,
    pub account_status: AccountStatus,
    pub nsec_backed_up: bool,
    pub is_ready: bool,
    pub is_nip07: bool,
    pub is_passkey: bool,
    pub is_local_key: bool,
    pub extension_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthPhase {
    Unauthenticated,
    Authenticating,
    Authenticated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Incomplete,
    Complete,
}

impl Default for AuthState {
    fn default() -> Self {
        Self {
            state: AuthPhase::Unauthenticated,
            pubkey: None,
            is_authenticated: false,
            public_key: None,
            nickname: None,
            avatar: None,
            error: None,
            account_status: AccountStatus::Incomplete,
            nsec_backed_up: false,
            is_ready: false,
            is_nip07: false,
            is_passkey: false,
            is_local_key: false,
            extension_name: None,
        }
    }
}

// -- AuthStore ----------------------------------------------------------------

/// How a local-key sign-in stores the raw private key.
///
/// Passkey and NIP-07 sign-ins never store a raw key, whatever this says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyPersistence {
    /// Follow the site-wide "stay signed in on this device" flag (see
    /// [`AuthStore::set_remember_me`]): durable localStorage when it is set,
    /// otherwise sessionStorage, cleared when the tab closes. The forum's
    /// behaviour.
    RememberFlag,
    /// Hold the key in memory only: a reload signs the member out. A stored
    /// copy of a *different* key is removed, since session restore would
    /// otherwise install it under this session's pubkey; a stored copy of the
    /// same key (the member's own earlier choice) is kept. The BBS uses this
    /// unless the member ticked "Stay signed in" (ADR-2008).
    MemoryOnly,
}

/// Reactive auth store providing the auth context for the entire app.
///
/// Holds an `RwSignal<AuthState>` for the reactive UI state and a
/// `StoredValue<Option<Vec<u8>>>` for the in-memory private key.
/// Also holds reactive signals for pod_url and web_id from passkey auth.
#[derive(Clone, Copy)]
pub struct AuthStore {
    /// Reactive auth state; read it from other crates through [`Self::state`].
    pub(crate) state: RwSignal<AuthState>,
    /// Private key bytes held in a StoredValue so they stay on the WASM thread.
    /// Never serialized; persisted only as [`KeyPersistence`] allows.
    pub(crate) privkey: StoredValue<Option<Vec<u8>>>,
    /// Signer trait object — additive alongside privkey for trait-based signing.
    pub(crate) signer: StoredValue<Option<SignerHandle>>,
    /// Pod URL from passkey auth server response (Solid pod endpoint).
    pub pod_url: RwSignal<Option<String>>,
    /// Web ID from passkey auth server response (Solid WebID URI).
    pub web_id: RwSignal<Option<String>>,
    /// Set from sign-out until its navigation, while a last subscriptions
    /// publish may still be running; see [`Self::signing_out`].
    signing_out: RwSignal<bool>,
}

impl AuthStore {
    fn new() -> Self {
        Self {
            state: RwSignal::new(AuthState::default()),
            privkey: StoredValue::new(None),
            signer: StoredValue::new(None),
            pod_url: RwSignal::new(None),
            web_id: RwSignal::new(None),
            signing_out: RwSignal::new(false),
        }
    }

    /// Whether a sign-out is finishing: the account is already signed out
    /// (nothing of it is left in storage), and a last publish of its topic
    /// subscriptions may run for up to 3 s before the page navigates. Views
    /// can show "Signing out…" while this is true.
    pub fn signing_out(&self) -> ReadSignal<bool> {
        self.signing_out.read_only()
    }

    // -- Getters --------------------------------------------------------------

    /// The reactive auth state, read-only. Only this crate changes it.
    pub fn state(&self) -> ReadSignal<AuthState> {
        self.state.read_only()
    }

    /// Read the current auth state (reactive).
    #[allow(dead_code)]
    pub fn get(&self) -> AuthState {
        self.state.get()
    }

    /// Derived signal: is the user authenticated?
    pub fn is_authenticated(&self) -> Memo<bool> {
        let state = self.state;
        Memo::new(move |_| state.get().is_authenticated)
    }

    /// Derived signal: is the auth store ready (initial restore complete)?
    pub fn is_ready(&self) -> Memo<bool> {
        let state = self.state;
        Memo::new(move |_| state.get().is_ready)
    }

    /// Derived signal: current error message.
    pub fn error(&self) -> Memo<Option<String>> {
        let state = self.state;
        Memo::new(move |_| state.get().error)
    }

    /// Derived signal: hex pubkey.
    pub fn pubkey(&self) -> Memo<Option<String>> {
        let state = self.state;
        Memo::new(move |_| state.get().pubkey)
    }

    /// Derived signal: display nickname.
    pub fn nickname(&self) -> Memo<Option<String>> {
        let state = self.state;
        Memo::new(move |_| state.get().nickname)
    }

    /// Get the active Signer, if one has been set.
    ///
    /// Lazy NIP-07 fallback: a browser extension (Podkey) injects `window.nostr`
    /// AFTER the WASM boot, so when an extension session is authenticated on load
    /// the `Nip07Signer` is often not installed into `self.signer` (restore ran
    /// before injection; the relay-side auth path only sets the async relay
    /// signer, not this store). Posting still works because it routes through
    /// `sign_event_async()` / `window.nostr` directly — but every authed NIP-98
    /// fetch (admin user list + registrations, pod, search) calls `get_signer()`
    /// and was silently no-op'ing for extension users. So when no signer is
    /// stored but the session is NIP-07 and `window.nostr` is now present,
    /// construct a `Nip07Signer` on demand (it signs lazily via the extension).
    pub fn get_signer(&self) -> Option<Rc<dyn Signer>> {
        if let Some(s) = self
            .signer
            .with_value(|s| s.as_ref().map(|sw| (**sw).clone()))
        {
            return Some(s);
        }
        let st = self.state.get_untracked();
        if st.is_nip07 && nip07::has_nip07_extension() {
            if let Some(pk) = st.pubkey {
                let signer: Rc<dyn Signer> = Rc::new(nip07::Nip07Signer::from_pubkey(pk));
                return Some(signer);
            }
        }
        None
    }

    /// Sign an unsigned event using the in-memory private key.
    ///
    /// The raw key bytes never leave this module — the `SigningKey` is
    /// constructed inside the closure and dropped (+ zeroized) before
    /// returning. This prevents the 32-byte secret from being copied
    /// onto arbitrary WASM stack frames in calling code.
    pub fn sign_event(&self, mut event: UnsignedEvent) -> Result<NostrEvent, String> {
        self.privkey.with_value(|opt| {
            let v = opt.as_ref().ok_or("No signing key available")?;
            if v.len() != 32 {
                return Err("Invalid key length".to_string());
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(v);
            let signing_key = k256::schnorr::SigningKey::from_bytes((&key_bytes).into())
                .map_err(|e| format!("Invalid signing key: {e}"))?;
            key_bytes.zeroize();
            // Auto-populate pubkey when caller left it blank. The relay's
            // NIP-42 AUTH builder constructs the unsigned event without a
            // pubkey because it has no access to the auth store — fill it
            // in here from the verifying key so core's `sign_event` doesn't
            // bounce on PubkeyMismatch.
            if event.pubkey.is_empty() {
                event.pubkey = hex::encode(signing_key.verifying_key().to_bytes());
            }
            nostr_bbs_core::sign_event(event, &signing_key)
                .map_err(|e| format!("Signing failed: {e}"))
        })
    }

    /// Get the raw privkey bytes for NIP-44 encryption/decryption.
    ///
    /// **WARNING**: Prefer `sign_event()` for signing. This method exists
    /// only for NIP-44 symmetric key derivation where the raw bytes are
    /// required by the encryption API. The returned `Zeroizing<[u8; 32]>`
    /// auto-zeroizes on drop — callers do not need to manually clear it.
    pub fn get_privkey_bytes(&self) -> Option<zeroize::Zeroizing<[u8; 32]>> {
        self.privkey.with_value(|opt| {
            opt.as_ref().and_then(|v| {
                if v.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(v);
                    Some(zeroize::Zeroizing::new(arr))
                } else {
                    None
                }
            })
        })
    }

    // -- Setters --------------------------------------------------------------

    pub fn clear_error(&self) {
        self.state.update(|s| s.error = None);
    }

    pub fn set_error(&self, msg: &str) {
        self.state.update(|s| s.error = Some(msg.to_string()));
    }

    #[allow(dead_code)]
    pub fn set_profile(&self, nickname: Option<String>, avatar: Option<String>) {
        self.state.update(|s| {
            s.nickname = nickname.clone();
            s.avatar = avatar.clone();
        });
        if let Ok(json_str) = LocalStorage::get::<String>(STORAGE_KEY) {
            if let Ok(mut stored) = serde_json::from_str::<StoredSession>(&json_str) {
                stored.nickname = nickname;
                stored.avatar = avatar;
                if let Ok(new_json) = serde_json::to_string(&stored) {
                    let _ = LocalStorage::set(STORAGE_KEY, new_json);
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn complete_signup(&self) {
        self.state
            .update(|s| s.account_status = AccountStatus::Complete);
        self.update_storage_field(|stored| {
            stored.account_status = AccountStatus::Complete;
        });
    }

    #[allow(dead_code)]
    pub fn confirm_nsec_backup(&self) {
        self.state.update(|s| s.nsec_backed_up = true);
        self.update_storage_field(|stored| {
            stored.nsec_backed_up = true;
        });
    }

    // -- Auth flows -----------------------------------------------------------

    /// Register a new passkey and derive Nostr keypair from PRF.
    pub async fn register_with_passkey(&self, display_name: &str) -> Result<(), String> {
        self.refuse_while_signing_out()?;
        self.state.update(|s| {
            s.error = None;
            s.state = AuthPhase::Authenticating;
        });

        match passkey::register_passkey(display_name).await {
            Ok(result) => {
                web_sys::console::log_1(&"[register_with_passkey] success".into());
                self.apply_passkey_result(&result, Some(display_name));
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                // Log both Display and Debug formats to trace error origin
                web_sys::console::error_1(
                    &format!("[register_with_passkey] Display: {msg}").into(),
                );
                web_sys::console::error_1(&format!("[register_with_passkey] Debug: {e:?}").into());
                self.state.update(|s| {
                    s.error = Some(msg.clone());
                    s.state = AuthPhase::Unauthenticated;
                });
                Err(msg)
            }
        }
    }

    /// Authenticate with an existing passkey, re-deriving the Nostr privkey.
    pub async fn login_with_passkey(&self, pubkey: Option<&str>) -> Result<(), String> {
        self.refuse_while_signing_out()?;
        self.state.update(|s| {
            s.error = None;
            s.state = AuthPhase::Authenticating;
        });

        match passkey::authenticate_passkey(pubkey).await {
            Ok(result) => {
                self.apply_passkey_auth_result(&result);
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                self.state.update(|s| {
                    s.error = Some(msg.clone());
                    s.state = AuthPhase::Unauthenticated;
                });
                Err(msg)
            }
        }
    }

    /// Generate a new random keypair and register as a local-key user.
    ///
    /// Returns the hex-encoded private key so the signup UI can show it for
    /// backup. The privkey is held in memory and stored under
    /// [`KeyPersistence::RememberFlag`]: sessionStorage (cleared on tab close)
    /// unless the user has opted into "remember me" (localStorage). It is
    /// never written to durable storage by default.
    pub fn register_with_generated_key(&self, display_name: &str) -> Result<String, String> {
        self.register_with_generated_key_scoped(display_name, KeyPersistence::RememberFlag)
    }

    /// [`Self::register_with_generated_key`], storing the new key as
    /// `persistence` says.
    pub fn register_with_generated_key_scoped(
        &self,
        display_name: &str,
        persistence: KeyPersistence,
    ) -> Result<String, String> {
        self.refuse_while_signing_out()?;
        let keypair = nostr_bbs_core::generate_keypair()
            .map_err(|e| format!("Key generation failed: {e}"))?;

        let pubkey = keypair.public.to_hex();
        let privkey_hex = hex::encode(keypair.secret.as_bytes());
        self.privkey
            .set_value(Some(keypair.secret.as_bytes().to_vec()));
        save_privkey_session(&privkey_hex, &pubkey, persistence);

        // Mirror login_with_local_key's signer registration so downstream
        // NIP-98 features (pod browser, search, relay AUTH) work the moment
        // signup completes. Without this, the just-registered user can't
        // sign anything until they re-login.
        {
            let mut sk_copy = [0u8; 32];
            sk_copy.copy_from_slice(keypair.secret.as_bytes());
            if let Ok(secret_for_signer) = nostr_bbs_core::keys::SecretKey::from_bytes(sk_copy) {
                let public = secret_for_signer.public_key();
                let signer_keypair = nostr_bbs_core::keys::Keypair {
                    secret: secret_for_signer,
                    public,
                };
                let signer: Rc<dyn Signer> =
                    Rc::new(nostr_bbs_core::signer::PrfSigner::new(signer_keypair));
                self.signer.set_value(Some(SendWrapper::new(signer)));
            }
        }

        let nickname = Some(display_name.to_string());

        let stored = StoredSession {
            version: 2,
            public_key: Some(pubkey.clone()),
            is_passkey: false,
            is_nip07: false,
            is_local_key: true,
            extension_name: None,
            nickname: nickname.clone(),
            avatar: None,
            account_status: AccountStatus::Incomplete,
            nsec_backed_up: false,
        };
        self.save_session(&stored);

        self.state.set(AuthState {
            state: AuthPhase::Authenticated,
            pubkey: Some(pubkey.clone()),
            is_authenticated: true,
            public_key: Some(pubkey),
            nickname,
            avatar: None,
            error: None,
            account_status: AccountStatus::Incomplete,
            nsec_backed_up: false,
            is_ready: true,
            is_nip07: false,
            is_passkey: false,
            is_local_key: true,
            extension_name: None,
        });

        Ok(privkey_hex)
    }

    /// Set the "stay signed in on this device" preference for nsec/local-key
    /// logins. `true` persists the key to durable localStorage (survives a
    /// browser restart); `false` (the default) keeps it session-scoped (cleared
    /// on tab close). No effect on passkey / NIP-07 logins, which never persist a
    /// raw key.
    ///
    /// Re-persists the current in-memory key into the newly-chosen scope, so an
    /// opt-in made mid-session — e.g. at the end of signup, after the generated
    /// key was already saved session-scoped — actually moves it to durable
    /// localStorage (or back to sessionStorage when opting out). A no-op re-save
    /// when logged out: the login page sets the flag before
    /// [`Self::login_with_local_key`] persists the key.
    pub fn set_remember_me(&self, enabled: bool) {
        session::set_remember_me(enabled);
        if let Some(bytes) = self.privkey.get_value().map(zeroize::Zeroizing::new) {
            // Only a local-key session's key may be stored: a passkey key is
            // re-derived on every sign-in and must never reach web storage.
            let local_key_owner = self
                .state
                .with_untracked(|s| s.pubkey.clone().filter(|_| s.is_local_key));
            if let Some(pubkey) = local_key_owner {
                save_privkey_session(
                    &hex::encode(bytes.as_slice()),
                    &pubkey,
                    KeyPersistence::RememberFlag,
                );
            }
        }
    }

    /// What identity, if any, this device already holds, compared with the
    /// account `new_pubkey` that a scanned or tapped sign-in code would
    /// import. Looks at the persisted session (local key, passkey or NIP-07),
    /// a stored private key and an installed-app bake, not only a live
    /// session: a scan usually opens a fresh tab whose sessionStorage is empty.
    pub async fn prior_identity(&self, new_pubkey: &str) -> PriorIdentity {
        let mut known: Vec<String> = Vec::new();
        let mut unknown = false;
        if let Some(pk) = self.state.get_untracked().pubkey {
            known.push(pk);
        }
        if let Some(pk) = self.stored_session_pubkey() {
            known.push(pk);
        }
        if let Some(hex_sk) = read_privkey_session().map(zeroize::Zeroizing::new) {
            match hex::decode(hex_sk.as_str())
                .ok()
                .map(zeroize::Zeroizing::new)
                .and_then(|b| {
                    let arr: [u8; 32] = b.as_slice().try_into().ok()?;
                    let arr = zeroize::Zeroizing::new(arr);
                    nostr_bbs_core::keys::pubkey_hex(&arr).ok()
                }) {
                Some(pk) => known.push(pk),
                None => unknown = true,
            }
        }
        if crate::utils::bake::is_baked().await {
            match crate::utils::bake::baked_pubkey() {
                Some(pk) => known.push(pk),
                None => unknown = true,
            }
        }
        classify_prior(&known, unknown, new_pubkey)
    }

    /// Login with a local nsec/hex private key.
    ///
    /// Accepts either a 64-character hex string or an nsec1... bech32 key.
    /// The key is stored under [`KeyPersistence::RememberFlag`].
    pub fn login_with_local_key(&self, key_input: &str) -> Result<(), String> {
        self.login_with_local_key_scoped(key_input, KeyPersistence::RememberFlag)
    }

    /// [`Self::login_with_local_key`], storing the key as `persistence` says.
    pub fn login_with_local_key_scoped(
        &self,
        key_input: &str,
        persistence: KeyPersistence,
    ) -> Result<(), String> {
        self.refuse_while_signing_out()?;
        // Tolerate a key typed from a sheet in groups ("nsec1 abcd efgh …"):
        // no valid key contains whitespace.
        let compact = zeroize::Zeroizing::new(key_input.split_whitespace().collect::<String>());
        let key_input = compact.as_str();
        let bytes = if key_input.starts_with("nsec1") {
            decode_nsec(key_input)?
        } else {
            hex::decode(key_input).map_err(|_| {
                "Invalid key. Paste a 64-char hex key or nsec1... bech32 key.".to_string()
            })?
        };
        if bytes.len() != 32 {
            return Err("Key must be 32 bytes (64 hex characters or nsec1 bech32)".to_string());
        }
        let privkey_hex = &hex::encode(&bytes);
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);

        let sk = nostr_bbs_core::SecretKey::from_bytes(key_bytes)
            .map_err(|e| format!("Invalid secp256k1 key: {e}"))?;
        let pubkey = sk.public_key().to_hex();
        self.privkey.set_value(Some(key_bytes.to_vec()));
        save_privkey_session(privkey_hex, &pubkey, persistence);

        // Register a Signer so anything that calls `auth.get_signer()` works
        // (pod browser, search, anything that needs NIP-98). Without this, the
        // signer field was None for local-key users and downstream features
        // silently no-op'd (pod page never fetched, relay AUTH sync warning
        // every connection).
        let public = sk.public_key();
        let keypair = nostr_bbs_core::keys::Keypair { secret: sk, public };
        let signer: Rc<dyn Signer> = Rc::new(nostr_bbs_core::signer::PrfSigner::new(keypair));
        self.signer.set_value(Some(SendWrapper::new(signer)));

        // Reuse cached profile fields only for the SAME account (never bleed
        // another identity's name into this one).
        let (nickname, avatar, account_status, _nsec_backed_up) = self.read_metadata_for(&pubkey);

        let stored = StoredSession {
            version: 2,
            public_key: Some(pubkey.clone()),
            is_passkey: false,
            is_nip07: false,
            is_local_key: true,
            extension_name: None,
            nickname: nickname.clone(),
            avatar: avatar.clone(),
            account_status: account_status.clone(),
            nsec_backed_up: true,
        };
        self.save_session(&stored);

        self.state.set(AuthState {
            state: AuthPhase::Authenticated,
            pubkey: Some(pubkey.clone()),
            is_authenticated: true,
            public_key: Some(pubkey.clone()),
            nickname,
            avatar,
            error: None,
            account_status,
            nsec_backed_up: true,
            is_ready: true,
            is_nip07: false,
            is_passkey: false,
            is_local_key: true,
            extension_name: None,
        });

        key_bytes.zeroize();

        // Fire-and-forget: an nsec recovery login restores the pubkey but not
        // the user's kind-0 display name/avatar, so the header shows only a
        // truncated pubkey until they manually re-save their profile (QA #11).
        // Fetch the user's own kind-0 metadata off the relay projection and
        // hydrate the display fields + persisted session. Non-blocking, silent
        // on failure (keeps the pubkey fallback).
        self.hydrate_profile_from_relay(pubkey);

        Ok(())
    }

    /// Fetch the authenticated user's own kind-0 profile and hydrate the
    /// reactive nickname/avatar plus the persisted `StoredSession`.
    ///
    /// Runs fire-and-forget (spawned) so it never blocks the login flow, and
    /// degrades silently when the relay projection is unreachable — the
    /// truncated-pubkey fallback simply persists. A profile field is only
    /// applied when it has NOT changed since the fetch was spawned, so a
    /// nickname/avatar the user edited locally during this session (e.g. a
    /// profile save that lands first) is never clobbered.
    pub(super) fn hydrate_profile_from_relay(&self, pubkey: String) {
        if pubkey.is_empty() {
            return;
        }
        let store = *self;
        // Snapshot the values present right after login. If either differs
        // when the fetch returns, the user touched it in-session — leave it.
        let (pre_nickname, pre_avatar) = {
            let st = store.state.get_untracked();
            (st.nickname, st.avatar)
        };
        wasm_bindgen_futures::spawn_local(async move {
            let Some(entry) = crate::stores::profile_cache::fetch_profile(&pubkey).await else {
                return;
            };

            // The nickname is the kind-0 DISPLAY name: prefer `display_name`,
            // fall back to `name` (mirrors the settings page). NIP-05 is a
            // claimed handle, not a display name, so it is deliberately excluded.
            let fetched_nickname = entry
                .display_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    entry
                        .name
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                })
                .map(String::from);
            let fetched_avatar = entry
                .picture
                .as_deref()
                .map(str::trim)
                .filter(|p| p.starts_with("http://") || p.starts_with("https://"))
                .map(String::from);

            // Nothing usable came back — keep the pubkey fallback intact.
            if fetched_nickname.is_none() && fetched_avatar.is_none() {
                return;
            }

            let mut changed = false;
            let mut new_nickname = None;
            let mut new_avatar = None;
            store.state.update(|s| {
                if let Some(nick) = fetched_nickname {
                    // Only apply if untouched since login and actually new.
                    if s.nickname == pre_nickname && s.nickname.as_deref() != Some(nick.as_str()) {
                        s.nickname = Some(nick);
                        changed = true;
                    }
                }
                if let Some(av) = fetched_avatar {
                    if s.avatar == pre_avatar && s.avatar.as_deref() != Some(av.as_str()) {
                        s.avatar = Some(av);
                        changed = true;
                    }
                }
                new_nickname = s.nickname.clone();
                new_avatar = s.avatar.clone();
            });

            // Persist so the restored identity survives the next reload.
            if changed {
                store.update_storage_field(|stored| {
                    stored.nickname = new_nickname;
                    stored.avatar = new_avatar;
                });
            }
        });
    }

    /// Login with a NIP-07 browser extension (nos2x, Alby, etc.).
    ///
    /// Calls `window.nostr.getPublicKey()` to get the pubkey. No private key
    /// is stored — all signing is delegated to the extension via `signEvent()`.
    pub async fn login_with_nip07(&self) -> Result<(), String> {
        self.refuse_while_signing_out()?;
        self.state.update(|s| {
            s.error = None;
            s.state = AuthPhase::Authenticating;
        });

        let ext_name = nip07::get_extension_name();

        match nip07::nip07_get_pubkey().await {
            Ok(pubkey) => {
                // Build a Nip07Signer and store it as the active signer
                let ext_signer = nip07::Nip07Signer::from_pubkey(pubkey.clone());
                let s: Rc<dyn Signer> = Rc::new(ext_signer);
                self.signer.set_value(Some(SendWrapper::new(s)));

                let (nickname, avatar, account_status, nsec_backed_up) =
                    self.read_existing_metadata();

                let stored = StoredSession {
                    version: 2,
                    public_key: Some(pubkey.clone()),
                    is_passkey: false,
                    is_nip07: true,
                    is_local_key: false,
                    extension_name: ext_name.clone(),
                    nickname: nickname.clone(),
                    avatar: avatar.clone(),
                    account_status: account_status.clone(),
                    nsec_backed_up,
                };
                self.save_session(&stored);

                self.state.set(AuthState {
                    state: AuthPhase::Authenticated,
                    pubkey: Some(pubkey.clone()),
                    is_authenticated: true,
                    public_key: Some(pubkey),
                    nickname,
                    avatar,
                    error: None,
                    account_status,
                    nsec_backed_up,
                    is_ready: true,
                    is_nip07: true,
                    is_passkey: false,
                    is_local_key: false,
                    extension_name: ext_name,
                });
                Ok(())
            }
            Err(e) => {
                self.state.update(|s| {
                    s.error = Some(e.clone());
                    s.state = AuthPhase::Unauthenticated;
                });
                Err(e)
            }
        }
    }

    /// Async event signing that works for all auth paths.
    ///
    /// - **Local key / passkey**: Uses the in-memory privkey (sync, wrapped in async).
    /// - **NIP-07**: Delegates to `window.nostr.signEvent()` (truly async).
    pub async fn sign_event_async(&self, event: UnsignedEvent) -> Result<NostrEvent, String> {
        if self.state.get_untracked().is_nip07 {
            nip07::nip07_sign_event(&event).await
        } else {
            self.sign_event(event)
        }
    }

    /// Log out: zero privkey, clear state and storage, then load the home
    /// page. See [`Self::logout_to`].
    pub fn logout(&self) -> LogoutOutcome {
        self.logout_to(&base_href("/"))
    }

    /// Log out and finish with a **full page load** of `dest` (a reload when
    /// the page is already there), so nothing of the account stays in memory
    /// either: zone keys, decrypted lists, the relay socket authenticated as
    /// it. A sign-out always ends in that load.
    ///
    /// Everything persistent is cleared **at once**, before this returns: the
    /// stored keys and remembered session, the installed-app boot profile, the
    /// push registration, the per-account lists and the topic subscriptions.
    /// The installed-app key in IndexedDB is deleted asynchronously; the load
    /// waits for that delete (at most [`UNBAKE_WAIT_MS`]), and neither client
    /// adopts a baked key without the boot profile, so a tab closed or
    /// reloaded before the delete finishes still boots signed out.
    ///
    /// When topic subscriptions have changes the member's relay copy lacks
    /// (and the signer is a local key or passkey, never a NIP-07 extension,
    /// which would prompt), the in-memory signer alone is kept for one last
    /// publish, waited for at most `thread_subs::SIGN_OUT_FLUSH_MS` (3 s),
    /// before the load; it writes nothing to storage. Meanwhile
    /// [`Self::signing_out`] is set, sign-in is refused ("Signing out…"),
    /// and a further sign-out call returns
    /// [`LogoutOutcome::AlreadyFinishing`] and does nothing.
    pub fn logout_to(&self, dest: &str) -> LogoutOutcome {
        if self.signing_out.get_untracked() || signed_out_here() {
            return LogoutOutcome::AlreadyFinishing;
        }
        debug_assert!(
            !dest.contains('#'),
            "a sign-out destination has no fragment"
        );
        // Captured before anything is cleared: the signer, the list and the
        // last relay copy seen, held only by the job.
        let job = crate::stores::thread_subs::sign_out_flush();
        // Terminal for this document, on every path and before any await: a
        // cancelled load (Esc, Stop) leaves a page that refuses sign-in.
        SIGNED_OUT.with(|f| f.set(true));
        self.signing_out.set(true);
        let unbaked = self.clear_session();
        let outcome = if job.is_some() {
            LogoutOutcome::Finishing
        } else {
            LogoutOutcome::Done
        };
        let dest = dest.to_string();
        leptos::task::spawn_local(async move {
            if let Some(job) = job {
                crate::stores::thread_subs::within(
                    job,
                    crate::stores::thread_subs::SIGN_OUT_FLUSH_MS,
                )
                .await;
            }
            // The installed-app key must be gone before the page goes (the
            // BBS one-shot boot would adopt it); bounded, then load anyway.
            crate::stores::thread_subs::within(
                Box::pin(async move { unbaked.wait().await }),
                UNBAKE_WAIT_MS,
            )
            .await;
            // Always a full load: in-app navigation during the wait must not
            // carry this account's memory into the next session.
            full_load(&dest);
        });
        outcome
    }

    /// Refuse a sign-in while a sign-out is finishing, or after one in this
    /// document (see [`Self::logout_to`]).
    fn refuse_while_signing_out(&self) -> Result<(), String> {
        if self.signing_out.get_untracked() || signed_out_here() {
            return Err("Signing out\u{2026} please wait a moment.".to_string());
        }
        Ok(())
    }

    /// Clear everything of the signed-in account, persistent and in memory.
    /// Returns a slot filled once the installed-app key's async delete ends.
    fn clear_session(&self) -> Rc<crate::relay::OneShot<()>> {
        // ADR-2023: this device must stop waking for the account that signs out.
        crate::utils::push::teardown_on_logout();
        // Zone images fetched for this account must not outlive it.
        crate::utils::restricted_media::clear_media_cache();
        // The visible notification list is per-account; drop it so the next
        // account on this browser does not inherit it.
        crate::stores::notifications::clear_persisted_for_logout(
            self.state.get_untracked().pubkey.as_deref(),
        );
        // "Continue where you left off" is per identity too.
        crate::utils::resume::clear_for_logout(self.state.get_untracked().pubkey.as_deref());
        // So are topic subscriptions (the synced relay copy restores them).
        crate::stores::thread_subs::clear_persisted_for_logout(
            self.state.get_untracked().pubkey.as_deref(),
        );
        self.privkey.update_value(|opt| {
            if let Some(ref mut v) = opt {
                v.iter_mut().for_each(|b| *b = 0);
            }
            *opt = None;
        });
        self.signer.set_value(None);
        self.pod_url.set(None);
        self.web_id.set(None);

        self.state.set(AuthState::default());
        LocalStorage::delete(STORAGE_KEY);
        clear_privkey_session();
        // The installed-app boot trigger goes now (the async unbake below
        // deletes it too, then the key): a tab closed before that finishes
        // must not boot into this account.
        LocalStorage::delete(nostr_bbs_core::BOOTPROFILE_KEY);
        // Signing out also forgets the installed-app bake: otherwise the next
        // `?pwa=1` launch would silently adopt this account again (a shared
        // phone would open someone else's account).
        let done: Rc<crate::relay::OneShot<()>> = crate::relay::OneShot::new();
        let fill = done.clone();
        leptos::task::spawn_local(async move {
            if let Err(e) = crate::utils::bake::unbake().await {
                web_sys::console::warn_1(&format!("[logout] unbake failed: {e}").into());
            }
            fill.fill(());
        });
        done
    }

    // -- Internal helpers (passkey result application) -------------------------

    fn apply_passkey_result(&self, result: &PasskeyRegistrationResult, display_name: Option<&str>) {
        self.privkey.set_value(Some(result.privkey_bytes.to_vec()));

        // Build a PrfSigner from the derived privkey bytes (direct construction, not re-derivation)
        if let Ok(secret) = nostr_bbs_core::keys::SecretKey::from_bytes(result.privkey_bytes) {
            let public = secret.public_key();
            let keypair = nostr_bbs_core::keys::Keypair { secret, public };
            let s: Rc<dyn Signer> = Rc::new(nostr_bbs_core::signer::PrfSigner::new(keypair));
            self.signer.set_value(Some(SendWrapper::new(s)));
        }

        // Wire pod_url and web_id signals
        self.pod_url.set(result.pod_url.clone());
        self.web_id.set(result.web_id.clone());

        let (existing_nickname, existing_avatar, _existing_status, _existing_nsec) =
            self.read_existing_metadata();

        let nickname = display_name.map(|s| s.to_string()).or(existing_nickname);
        let avatar = existing_avatar;

        let stored = StoredSession {
            version: 2,
            public_key: Some(result.pubkey.clone()),
            is_passkey: true,
            is_nip07: false,
            is_local_key: false,
            extension_name: None,
            nickname: nickname.clone(),
            avatar: avatar.clone(),
            account_status: AccountStatus::Incomplete,
            nsec_backed_up: false,
        };
        self.save_session(&stored);

        self.state.set(AuthState {
            state: AuthPhase::Authenticated,
            pubkey: Some(result.pubkey.clone()),
            is_authenticated: true,
            public_key: Some(result.pubkey.clone()),
            nickname,
            avatar,
            error: None,
            account_status: AccountStatus::Incomplete,
            nsec_backed_up: false,
            is_ready: true,
            is_nip07: false,
            is_passkey: true,
            is_local_key: false,
            extension_name: None,
        });
    }

    fn apply_passkey_auth_result(&self, result: &PasskeyAuthResult) {
        self.privkey.set_value(Some(result.privkey_bytes.to_vec()));

        // Build a PrfSigner from the derived privkey bytes (direct construction, not re-derivation)
        if let Ok(secret) = nostr_bbs_core::keys::SecretKey::from_bytes(result.privkey_bytes) {
            let public = secret.public_key();
            let keypair = nostr_bbs_core::keys::Keypair { secret, public };
            let s: Rc<dyn Signer> = Rc::new(nostr_bbs_core::signer::PrfSigner::new(keypair));
            self.signer.set_value(Some(SendWrapper::new(s)));
        }

        // Wire web_id signal (passkey auth returns web_id but not pod_url)
        self.web_id.set(result.web_id.clone());

        let (nickname, avatar, account_status, nsec_backed_up) = self.read_existing_metadata();

        let stored = StoredSession {
            version: 2,
            public_key: Some(result.pubkey.clone()),
            is_passkey: true,
            is_nip07: false,
            is_local_key: false,
            extension_name: None,
            nickname: nickname.clone(),
            avatar: avatar.clone(),
            account_status: account_status.clone(),
            nsec_backed_up,
        };
        self.save_session(&stored);

        self.state.set(AuthState {
            state: AuthPhase::Authenticated,
            pubkey: Some(result.pubkey.clone()),
            is_authenticated: true,
            public_key: Some(result.pubkey.clone()),
            nickname,
            avatar,
            error: None,
            account_status,
            nsec_backed_up,
            is_ready: true,
            is_nip07: false,
            is_passkey: true,
            is_local_key: false,
            extension_name: None,
        });
    }
}

// -- Bech32 nsec decoder ------------------------------------------------------

/// Decode an nsec1... bech32 string to raw 32-byte secret key.
fn decode_nsec(nsec: &str) -> Result<Vec<u8>, String> {
    let (hrp, data) = bech32::decode(nsec).map_err(|e| format!("Invalid bech32 encoding: {e}"))?;
    if hrp.as_str() != "nsec" {
        return Err(format!("Expected nsec prefix, got {}", hrp.as_str()));
    }
    if data.len() != 32 {
        return Err(format!("nsec data must be 32 bytes, got {}", data.len()));
    }
    Ok(data)
}

// -- Context providers --------------------------------------------------------

/// Create and provide the auth context. Call once at the app root.
/// Result of [`AuthStore::prior_identity`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PriorIdentity {
    /// Nothing on this device: import without asking.
    None,
    /// Only the same account: import without asking.
    Same,
    /// Another account (pubkey when known): ask before replacing it.
    Other(Option<String>),
}

/// Pure decision behind [`AuthStore::prior_identity`].
pub fn classify_prior(known: &[String], unknown: bool, new_pubkey: &str) -> PriorIdentity {
    if let Some(other) = known.iter().find(|k| !k.eq_ignore_ascii_case(new_pubkey)) {
        return PriorIdentity::Other(Some(other.clone()));
    }
    if unknown {
        return PriorIdentity::Other(None);
    }
    if known.is_empty() {
        PriorIdentity::None
    } else {
        PriorIdentity::Same
    }
}

pub fn provide_auth() {
    let store = AuthStore::new();
    store.restore_session();
    session::register_pagehide_listener(store);
    provide_context(store);
}

/// The pubkey of the session persisted on this browser (written by every
/// sign-in, removed by sign-out), if any. Public data only.
pub(crate) fn persisted_session_pubkey() -> Option<String> {
    let json: String = LocalStorage::get(STORAGE_KEY).ok()?;
    serde_json::from_str::<session::StoredSession>(&json)
        .ok()?
        .public_key
}

/// What [`AuthStore::logout_to`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogoutOutcome {
    /// Signed out; the page is loading `dest`.
    Done,
    /// Signed out; a last publish runs (at most 3 s) before the page loads
    /// `dest`. Show "Signing out…".
    Finishing,
    /// A sign-out was already finishing; this call did nothing.
    AlreadyFinishing,
}

/// How to end a sign-out on `dest` from `current`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoadAction {
    Reload,
    Replace,
}

fn load_action(current: &str, dest: &str) -> LoadAction {
    if current == dest {
        LoadAction::Reload
    } else {
        LoadAction::Replace
    }
}

/// A full document load of `dest`: a reload when the page is already there,
/// else a replace (so Back does not return to the signed-in page). If that
/// throws, falls back to assigning the address; the sign-in guard stays set
/// either way (fail safe).
fn full_load(dest: &str) {
    let Some(window) = web_sys::window() else {
        return;
    };
    let location = window.location();
    let current = location.pathname().unwrap_or_default();
    let result = match load_action(&current, dest) {
        LoadAction::Reload => location.reload(),
        LoadAction::Replace => location.replace(dest),
    };
    if result.is_err() {
        let _ = location.set_href(dest);
    }
}

/// How long a sign-out waits for the installed-app key's delete before the
/// page loads, milliseconds.
pub const UNBAKE_WAIT_MS: u32 = 500;

thread_local! {
    /// Set by a sign-out and never cleared: this document has signed an
    /// account out, so it refuses sign-in until a fresh load.
    static SIGNED_OUT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether this document has signed an account out (see [`SIGNED_OUT`]).
pub(crate) fn signed_out_here() -> bool {
    SIGNED_OUT.with(std::cell::Cell::get)
}

/// After a back/forward-cache restore: whether the page must reload because
/// what it holds in memory is not the stored session any more (a sign-out
/// happened here, or elsewhere, or another account signed in).
pub(crate) fn stale_after_restore(
    signed_out_here: bool,
    stored: Option<&str>,
    in_memory: Option<&str>,
) -> bool {
    if signed_out_here {
        return true;
    }
    match (stored, in_memory) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(s), Some(m)) => !s.eq_ignore_ascii_case(m),
    }
}

#[cfg(test)]
mod logout_load_tests {
    use super::{load_action, LoadAction};

    #[test]
    fn a_restored_page_reloads_when_its_memory_is_not_the_stored_session() {
        use super::stale_after_restore as stale;
        let (a, b) = ("aa", "bb");
        assert!(stale(true, None, None), "signed out in this document");
        assert!(stale(false, None, Some(a)), "signed out elsewhere");
        assert!(stale(false, Some(b), Some(a)), "another account signed in");
        assert!(!stale(false, Some(a), Some(a)));
        assert!(!stale(false, Some("AA"), Some(a)));
        assert!(!stale(false, Some(a), None), "nothing in memory to leak");
        assert!(!stale(false, None, None));
    }

    #[test]
    fn sign_out_destinations_have_no_fragment() {
        // A fragment-only difference would be a same-document navigation,
        // not a load.
        for dest in [
            crate::base::base_href("/"),
            crate::base::base_href("/login"),
        ] {
            assert!(!dest.contains('#'), "{dest}");
        }
    }

    #[test]
    fn a_sign_out_always_ends_in_a_full_load() {
        assert_eq!(load_action("/", "/"), LoadAction::Reload, "already home");
        assert_eq!(load_action("/forums", "/"), LoadAction::Replace);
        assert_eq!(load_action("/login", "/login"), LoadAction::Reload);
    }
}

/// Get the auth store from context. Panics if `provide_auth()` was not called.
pub fn use_auth() -> AuthStore {
    expect_context::<AuthStore>()
}

// -- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── classify_prior (account-switch confirmation) ─────────────────────

    #[test]
    fn prior_identity_matrix() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        assert_eq!(classify_prior(&[], false, &a), PriorIdentity::None);
        assert_eq!(
            classify_prior(std::slice::from_ref(&a), false, &a),
            PriorIdentity::Same
        );
        assert_eq!(
            classify_prior(&[a.to_uppercase()], false, &a),
            PriorIdentity::Same
        );
        assert_eq!(
            classify_prior(std::slice::from_ref(&b), false, &a),
            PriorIdentity::Other(Some(b.clone()))
        );
        assert_eq!(
            classify_prior(&[a.clone(), b.clone()], false, &a),
            PriorIdentity::Other(Some(b))
        );
        // A bake or stored key whose owner can't be read counts as another account.
        assert_eq!(classify_prior(&[], true, &a), PriorIdentity::Other(None));
        assert_eq!(
            classify_prior(std::slice::from_ref(&a), true, &a),
            PriorIdentity::Other(None)
        );
    }

    // ── decode_nsec ─────────────────────────────────────────────────────

    #[test]
    fn decode_nsec_valid() {
        // Generate a valid nsec from known bytes
        let secret = [0x42u8; 32];
        let nsec =
            bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("nsec").unwrap(), &secret).unwrap();
        let decoded = decode_nsec(&nsec).unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded, secret.to_vec());
    }

    #[test]
    fn decode_nsec_wrong_prefix() {
        let data = [0x01u8; 32];
        let npub =
            bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("npub").unwrap(), &data).unwrap();
        let result = decode_nsec(&npub);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Expected nsec prefix"));
    }

    #[test]
    fn decode_nsec_invalid_bech32() {
        let result = decode_nsec("nsec1notvalidbech32");
        assert!(result.is_err());
    }

    #[test]
    fn decode_nsec_completely_invalid() {
        let result = decode_nsec("not a bech32 string at all");
        assert!(result.is_err());
    }

    #[test]
    fn decode_nsec_empty_string() {
        let result = decode_nsec("");
        assert!(result.is_err());
    }

    // ── StoredSession serialization ─────────────────────────────────────

    #[test]
    fn stored_session_roundtrip() {
        let session = session::StoredSession {
            version: 2,
            public_key: Some("aabb".repeat(16)),
            is_nip07: false,
            is_passkey: true,
            is_local_key: false,
            extension_name: None,
            nickname: Some("Alice".into()),
            avatar: Some("https://example.com/avatar.jpg".into()),
            account_status: AccountStatus::Complete,
            nsec_backed_up: true,
        };
        let json = serde_json::to_string(&session).unwrap();
        let restored: session::StoredSession = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.version, 2);
        assert_eq!(restored.public_key, session.public_key);
        assert!(restored.is_passkey);
        assert!(!restored.is_nip07);
        assert!(!restored.is_local_key);
        assert_eq!(restored.nickname, Some("Alice".into()));
        assert!(restored.nsec_backed_up);
    }

    #[test]
    fn stored_session_default() {
        let session = session::StoredSession::default();
        assert_eq!(session.version, 2);
        assert!(session.public_key.is_none());
        assert!(!session.is_nip07);
        assert!(!session.is_passkey);
        assert!(!session.is_local_key);
        assert!(!session.nsec_backed_up);
    }

    #[test]
    fn stored_session_deserialize_minimal() {
        // Minimal JSON that should deserialize with defaults for missing fields
        let json = r#"{"_v":2,"publicKey":null,"isNip07":false,"isPasskey":false,"extensionName":null,"nickname":null,"avatar":null,"accountStatus":"incomplete","nsecBackedUp":false}"#;
        let session: session::StoredSession = serde_json::from_str(json).unwrap();
        assert_eq!(session.version, 2);
        assert!(!session.is_local_key); // default
    }

    // ── AccountStatus serialization ─────────────────────────────────────

    #[test]
    fn account_status_serialize_incomplete() {
        let status = AccountStatus::Incomplete;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"incomplete\"");
    }

    #[test]
    fn account_status_serialize_complete() {
        let status = AccountStatus::Complete;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"complete\"");
    }

    #[test]
    fn account_status_roundtrip() {
        let status = AccountStatus::Complete;
        let json = serde_json::to_string(&status).unwrap();
        let restored: AccountStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, AccountStatus::Complete);
    }

    // ── AuthState default ───────────────────────────────────────────────

    #[test]
    fn auth_state_default() {
        let state = AuthState::default();
        assert_eq!(state.state, AuthPhase::Unauthenticated);
        assert!(!state.is_authenticated);
        assert!(state.pubkey.is_none());
        assert!(state.public_key.is_none());
        assert!(!state.is_ready);
        assert!(!state.is_nip07);
        assert!(!state.is_passkey);
        assert!(!state.is_local_key);
    }

    // ── PrivkeyMem ──────────────────────────────────────────────────────

    #[test]
    fn privkey_mem_to_hex() {
        let bytes = [0xABu8; 32];
        let mem = session::PrivkeyMem::new(bytes);
        assert_eq!(mem.to_hex(), "ab".repeat(32));
    }

    #[test]
    fn privkey_mem_zeros_on_drop() {
        let bytes = [0xFFu8; 32];
        let mem = session::PrivkeyMem::new(bytes);
        let hex = mem.to_hex();
        assert_eq!(hex, "ff".repeat(32));
        drop(mem);
        // After drop, the internal bytes should be zeroed by Zeroize trait.
        // We can't access them after drop, but the drop impl is guaranteed
        // by the #[zeroize(drop)] attribute.
    }
}
