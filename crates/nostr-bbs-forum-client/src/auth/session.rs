//! Session persistence and private key lifecycle management.
//!
//! Handles localStorage read/write for `StoredSession`, pagehide/pageshow
//! listeners for zeroizing the in-memory private key, and session restoration.

use gloo::storage::{LocalStorage, Storage};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use zeroize::Zeroize;

use std::rc::Rc;

use send_wrapper::SendWrapper;

use super::{AccountStatus, AuthPhase, AuthState, AuthStore, STORAGE_KEY};
use nostr_bbs_core::signer::Signer;

/// Storage key for the local-key privkey.
///
/// Lives in **localStorage** by default so an explicit login survives page
/// reloads (QA: "session lost on every reload"). When the user opts out of
/// persistence via the remember-me flag (`nostr_bbs_remember` == "false"),
/// the key is written to sessionStorage instead (cleared on tab close).
///
/// **TRANSITIONAL PATH** (audit C2/B8): persisting a Schnorr private key in
/// web storage is acceptable only as a bridge for the "local-key" import
/// flow (NIP-19 `nsec` paste). Passkey users never hit this code path —
/// their key is re-derived from the authenticator on every authenticate.
const SESSION_PRIVKEY_KEY: &str = "nostr_bbs_sk";

/// localStorage flag controlling privkey persistence scope. Anything other
/// than the literal string "false" means "remember me" (the default).
const REMEMBER_ME_KEY: &str = "nostr_bbs_remember";

// -- Persisted session data ---------------------------------------------------

/// Schema for the data stored in localStorage. Never contains private keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct StoredSession {
    #[serde(rename = "_v")]
    pub version: u32,
    #[serde(rename = "publicKey")]
    pub public_key: Option<String>,
    #[serde(rename = "isNip07")]
    pub is_nip07: bool,
    #[serde(rename = "isPasskey")]
    pub is_passkey: bool,
    #[serde(rename = "isLocalKey", default)]
    pub is_local_key: bool,
    #[serde(rename = "extensionName")]
    pub extension_name: Option<String>,
    pub nickname: Option<String>,
    pub avatar: Option<String>,
    #[serde(rename = "accountStatus")]
    pub account_status: AccountStatus,
    #[serde(rename = "nsecBackedUp")]
    pub nsec_backed_up: bool,
}

impl Default for StoredSession {
    fn default() -> Self {
        Self {
            version: 2,
            public_key: None,
            is_nip07: false,
            is_passkey: false,
            is_local_key: false,
            extension_name: None,
            nickname: None,
            avatar: None,
            account_status: AccountStatus::Incomplete,
            nsec_backed_up: false,
        }
    }
}

// -- Private key holder with zeroize ------------------------------------------

/// Wrapper that zeroizes private key bytes on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
#[allow(dead_code)]
pub(super) struct PrivkeyMem {
    pub bytes: [u8; 32],
}

#[allow(dead_code)]
impl PrivkeyMem {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }
}

// -- privkey storage helpers ----------------------------------------------------

fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
}

fn session_storage() -> Option<web_sys::Storage> {
    web_sys::window()
        .and_then(|w| w.session_storage().ok())
        .flatten()
}

/// "Remember me" is the default. Only an explicit `"false"` flag in
/// localStorage downgrades privkey persistence to sessionStorage scope.
fn remember_me() -> bool {
    local_storage()
        .and_then(|s| s.get_item(REMEMBER_ME_KEY).ok())
        .flatten()
        .map(|v| v != "false")
        .unwrap_or(true)
}

/// Store privkey hex so an explicit login survives page reloads.
///
/// Writes to localStorage by default ("remember me" on), or sessionStorage
/// when the user opted out. The other storage area is cleared so a stale
/// copy can never linger. See `SESSION_PRIVKEY_KEY` for the audit note —
/// passkey-derived keys MUST NOT be persisted via this path; they
/// re-derive from PRF on every login.
pub(super) fn save_privkey_session(hex: &str) {
    if remember_me() {
        if let Some(storage) = local_storage() {
            let _ = storage.set_item(SESSION_PRIVKEY_KEY, hex);
        }
        if let Some(storage) = session_storage() {
            let _ = storage.remove_item(SESSION_PRIVKEY_KEY);
        }
    } else {
        if let Some(storage) = session_storage() {
            let _ = storage.set_item(SESSION_PRIVKEY_KEY, hex);
        }
        if let Some(storage) = local_storage() {
            let _ = storage.remove_item(SESSION_PRIVKEY_KEY);
        }
    }
}

/// Read privkey hex from storage. Checks localStorage first (the default
/// persistence scope), then sessionStorage (remember-me=false sessions and
/// sessions created before the localStorage migration).
pub(super) fn read_privkey_session() -> Option<String> {
    if let Some(hex) = local_storage()
        .and_then(|s| s.get_item(SESSION_PRIVKEY_KEY).ok())
        .flatten()
    {
        return Some(hex);
    }
    session_storage()
        .and_then(|s| s.get_item(SESSION_PRIVKEY_KEY).ok())
        .flatten()
}

/// Clear privkey from both storage areas. Called on explicit logout.
pub(super) fn clear_privkey_session() {
    if let Some(storage) = local_storage() {
        let _ = storage.remove_item(SESSION_PRIVKEY_KEY);
    }
    if let Some(storage) = session_storage() {
        let _ = storage.remove_item(SESSION_PRIVKEY_KEY);
    }
}

// -- Session persistence helpers ----------------------------------------------

impl AuthStore {
    /// Read existing metadata from localStorage without modifying state.
    pub(super) fn read_existing_metadata(
        &self,
    ) -> (Option<String>, Option<String>, AccountStatus, bool) {
        let json_str: Result<String, _> = LocalStorage::get(STORAGE_KEY);
        if let Ok(ref s) = json_str {
            if let Ok(stored) = serde_json::from_str::<StoredSession>(s) {
                return (
                    stored.nickname,
                    stored.avatar,
                    stored.account_status,
                    stored.nsec_backed_up,
                );
            }
        }
        (None, None, AccountStatus::Incomplete, false)
    }

    /// Persist session data to localStorage (never includes private keys).
    pub(super) fn save_session(&self, stored: &StoredSession) {
        if let Ok(json) = serde_json::to_string(stored) {
            let _ = LocalStorage::set(STORAGE_KEY, json);
        }
    }

    /// Update a single field in the stored session.
    #[allow(dead_code)]
    pub(super) fn update_storage_field<F: FnOnce(&mut StoredSession)>(&self, f: F) {
        let json_str: Result<String, _> = LocalStorage::get(STORAGE_KEY);
        if let Ok(ref s) = json_str {
            if let Ok(mut stored) = serde_json::from_str::<StoredSession>(s) {
                f(&mut stored);
                if let Ok(new_json) = serde_json::to_string(&stored) {
                    let _ = LocalStorage::set(STORAGE_KEY, new_json);
                }
            }
        }
    }

    /// Restore session from localStorage on page load.
    ///
    /// Only pubkey and profile metadata are restored. Passkey users must
    /// re-authenticate to re-derive the privkey.
    pub(super) fn restore_session(&self) {
        let json_str: Result<String, _> = LocalStorage::get(STORAGE_KEY);
        let json_str = match json_str {
            Ok(s) => s,
            Err(_) => {
                self.state.update(|s| s.is_ready = true);
                return;
            }
        };

        let parsed: Result<StoredSession, _> = serde_json::from_str(&json_str);
        let stored = match parsed {
            Ok(s) => s,
            Err(_) => {
                LocalStorage::delete(STORAGE_KEY);
                self.state.update(|s| s.is_ready = true);
                return;
            }
        };

        if stored.is_passkey {
            if let Some(ref pubkey) = stored.public_key {
                self.state.set(AuthState {
                    state: AuthPhase::Unauthenticated,
                    pubkey: Some(pubkey.clone()),
                    is_authenticated: false,
                    public_key: Some(pubkey.clone()),
                    nickname: stored.nickname,
                    avatar: stored.avatar,
                    is_pending: false,
                    error: None,
                    account_status: stored.account_status,
                    nsec_backed_up: stored.nsec_backed_up,
                    is_ready: true,
                    is_nip07: false,
                    is_passkey: false,
                    is_local_key: false,
                    extension_name: None,
                });
                return;
            }
        }

        if stored.is_nip07 {
            if let Some(ref pubkey) = stored.public_key {
                let has_ext = super::nip07::has_nip07_extension();
                self.state.set(AuthState {
                    state: if has_ext {
                        AuthPhase::Authenticated
                    } else {
                        AuthPhase::Unauthenticated
                    },
                    pubkey: Some(pubkey.clone()),
                    is_authenticated: has_ext,
                    public_key: Some(pubkey.clone()),
                    nickname: stored.nickname,
                    avatar: stored.avatar,
                    is_pending: false,
                    error: None,
                    account_status: stored.account_status,
                    nsec_backed_up: stored.nsec_backed_up,
                    is_ready: true,
                    is_nip07: has_ext,
                    is_passkey: false,
                    is_local_key: false,
                    extension_name: stored.extension_name,
                });
                return;
            }
        }

        if stored.is_local_key {
            if let Some(ref pubkey) = stored.public_key {
                // Try to restore the persisted privkey (localStorage by
                // default, sessionStorage for remember-me=false sessions).
                // The hex string is zeroized in-place after decoding so it
                // does not linger on the JS heap longer than necessary
                // (audit B8 hardening).
                if let Some(mut hex) = read_privkey_session() {
                    let decoded = hex::decode(&hex);
                    // Overwrite the hex string buffer; Rust's String does
                    // not expose direct zeroize but writing ASCII zeros
                    // before drop reduces residual exposure.
                    unsafe {
                        for b in hex.as_bytes_mut() {
                            *b = 0;
                        }
                    }
                    if let Ok(bytes) = decoded {
                        if bytes.len() == 32 {
                            // Register a Signer for downstream features
                            // (pod, search, NIP-98). Without this, the signer
                            // was None after restore for local-key users and
                            // every authed request silently no-op'd.
                            let mut sk_bytes = [0u8; 32];
                            sk_bytes.copy_from_slice(&bytes);
                            if let Ok(secret) =
                                nostr_bbs_core::keys::SecretKey::from_bytes(sk_bytes)
                            {
                                let public = secret.public_key();
                                let keypair = nostr_bbs_core::keys::Keypair { secret, public };
                                let signer: Rc<dyn Signer> =
                                    Rc::new(nostr_bbs_core::signer::PrfSigner::new(keypair));
                                self.signer.set_value(Some(SendWrapper::new(signer)));
                            }
                            self.privkey.set_value(Some(bytes));
                            self.state.set(AuthState {
                                state: AuthPhase::Authenticated,
                                pubkey: Some(pubkey.clone()),
                                is_authenticated: true,
                                public_key: Some(pubkey.clone()),
                                nickname: stored.nickname,
                                avatar: stored.avatar,
                                is_pending: false,
                                error: None,
                                account_status: stored.account_status,
                                nsec_backed_up: stored.nsec_backed_up,
                                is_ready: true,
                                is_nip07: false,
                                is_passkey: false,
                                is_local_key: true,
                                extension_name: None,
                            });
                            return;
                        }
                    }
                }

                // No persisted privkey — need re-login.
                self.state.set(AuthState {
                    state: AuthPhase::Unauthenticated,
                    pubkey: Some(pubkey.clone()),
                    is_authenticated: false,
                    public_key: Some(pubkey.clone()),
                    nickname: stored.nickname,
                    avatar: stored.avatar,
                    is_pending: false,
                    error: None,
                    account_status: stored.account_status,
                    nsec_backed_up: stored.nsec_backed_up,
                    is_ready: true,
                    is_nip07: false,
                    is_passkey: false,
                    is_local_key: true,
                    extension_name: None,
                });
                return;
            }
        }

        // Unknown state
        self.state.update(|s| s.is_ready = true);
    }
}

// -- Pagehide listener --------------------------------------------------------

/// Registers a `pagehide` event listener that zeros the in-memory private key
/// when the page is truly discarded (not bfcache).
pub(super) fn register_pagehide_listener(store: AuthStore) {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return,
    };

    let store_clone = store;
    let pagehide_cb = Closure::<dyn Fn(web_sys::PageTransitionEvent)>::new(
        move |event: web_sys::PageTransitionEvent| {
            // persisted=true means entering bfcache (app-switch, back/forward) -- keep key
            if event.persisted() {
                return;
            }
            // Page actually unloading -- zero the in-memory key
            store_clone.privkey.update_value(|opt| {
                if let Some(ref mut v) = opt {
                    v.iter_mut().for_each(|b| *b = 0);
                }
                *opt = None;
            });
            // Do NOT clear the persisted privkey here. `pagehide` with
            // persisted=false fires on every plain reload as well as on tab
            // close — clearing storage here wiped the key before the new
            // document could restore it, logging the user out on every
            // reload (QA HIGH bug #1). Storage is cleared on explicit
            // logout only; tab-close cleanup of the non-remember-me copy is
            // handled by the browser (sessionStorage scope).
            // AuthState no longer carries private_key — privkey bytes
            // are already zeroed in the StoredValue above.
        },
    );

    let _ =
        window.add_event_listener_with_callback("pagehide", pagehide_cb.as_ref().unchecked_ref());
    // Leak the closure so it stays alive for the page lifetime
    pagehide_cb.forget();

    // pageshow handler: if restored from bfcache and key is gone, force re-auth
    let store_clone2 = store;
    let pageshow_cb = Closure::<dyn Fn(web_sys::PageTransitionEvent)>::new(
        move |event: web_sys::PageTransitionEvent| {
            if !event.persisted() {
                return;
            }
            let has_key = store_clone2.privkey.with_value(|opt| opt.is_some());
            if !has_key {
                store_clone2.state.update(|s| {
                    if s.is_passkey {
                        s.is_authenticated = false;
                        s.state = AuthPhase::Unauthenticated;
                    }
                });
            }
        },
    );

    let _ =
        window.add_event_listener_with_callback("pageshow", pageshow_cb.as_ref().unchecked_ref());
    pageshow_cb.forget();
}
