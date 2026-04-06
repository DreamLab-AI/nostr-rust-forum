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

use super::{AccountStatus, AuthPhase, AuthState, AuthStore, STORAGE_KEY};

/// sessionStorage key for local-key privkey (survives same-tab nav, cleared on tab close).
const SESSION_PRIVKEY_KEY: &str = "nostr_bbs_sk";

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

// -- sessionStorage privkey helpers -------------------------------------------

/// Store privkey hex in sessionStorage (survives SPA navigation + refresh, cleared on tab close).
pub(super) fn save_privkey_session(hex: &str) {
    if let Some(storage) = web_sys::window().and_then(|w| w.session_storage().ok()).flatten() {
        let _ = storage.set_item(SESSION_PRIVKEY_KEY, hex);
    }
}

/// Read privkey hex from sessionStorage.
pub(super) fn read_privkey_session() -> Option<String> {
    web_sys::window()
        .and_then(|w| w.session_storage().ok())
        .flatten()
        .and_then(|s| s.get_item(SESSION_PRIVKEY_KEY).ok())
        .flatten()
}

/// Clear privkey from sessionStorage.
pub(super) fn clear_privkey_session() {
    if let Some(storage) = web_sys::window().and_then(|w| w.session_storage().ok()).flatten() {
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
                    state: if has_ext { AuthPhase::Authenticated } else { AuthPhase::Unauthenticated },
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
                // Try to restore privkey from sessionStorage (survives refresh).
                if let Some(hex) = read_privkey_session() {
                    if let Ok(bytes) = hex::decode(&hex) {
                        if bytes.len() == 32 {
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

                // sessionStorage empty — privkey lost, need re-login.
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
            // Page actually unloading -- zero the key
            store_clone.privkey.update_value(|opt| {
                if let Some(ref mut v) = opt {
                    v.iter_mut().for_each(|b| *b = 0);
                }
                *opt = None;
            });
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
