//! BBS write-path signer — the crypto-owning module.
//!
//! The receive-only BBS gains a write path by obtaining a [`Signer`] the SAME way
//! the forum client does, without hand-rolling any cryptography: it reuses the
//! kit's audited [`nostr_bbs_core::signer::PrfSigner`] (BIP-340 Schnorr +
//! NIP-44/04) and key parsing ([`nostr_bbs_core::SecretKey`],
//! [`nostr_bbs_core::Keypair`], [`nostr_bbs_core::decode_nsec`]). No BIP-340,
//! NIP-44, or bech32 is re-implemented here.
//!
//! A signer is obtained two ways, in priority order:
//!
//! 1. **Adopt the forum session, same-origin.** For local-key / imported-nsec
//!    logins the forum client persists the raw 32-byte secret as hex under the
//!    localStorage/sessionStorage key `nostr_bbs_sk` (see the forum's
//!    `auth::session`). The BBS is served same-origin (`/community/bbs/` vs
//!    `/community/`), so it reads the SAME key material the forum already holds.
//!    This adds no new exposure boundary: any same-origin script can already read
//!    that entry. The transient hex is scrubbed after decoding (audit B8
//!    hardening, mirrored from the forum's `read_privkey_session`).
//!
//! 2. **Minimal in-memory BBS login.** Paste an `nsec1…` / 64-char hex key, or
//!    generate a fresh one. The resulting [`Keypair`] lives only in memory and is
//!    zeroized on drop (via [`nostr_bbs_core::SecretKey`]); the BBS never persists
//!    it. Passkey and NIP-07 sessions have no readable `nostr_bbs_sk`, so those
//!    users take this path (or sign in at `/community/` with a local key).
//!
//! Fail closed: with no signer the write actions are disabled and the UI directs
//! the user to sign in. The signer is registered with the relay module
//! ([`crate::relay::set_signer`]) so NIP-42 AUTH challenges can be answered.

use std::rc::Rc;

use leptos::prelude::*;
use send_wrapper::SendWrapper;
use zeroize::Zeroize;

use nostr_bbs_core::signer::{PrfSigner, Signer};
use nostr_bbs_core::Keypair;

/// A `Rc<dyn Signer>` carried through Leptos context. `SendWrapper` asserts the
/// single-threaded wasm invariant at runtime so the non-`Send` `Rc` can satisfy
/// the `Send + Sync` bound `provide_context` requires.
type SignerHandle = SendWrapper<Rc<dyn Signer>>;

/// Forum-client localStorage/sessionStorage key holding the raw secret key hex
/// for local-key / imported-nsec sessions. Read same-origin; never written here.
#[cfg(target_arch = "wasm32")]
const FORUM_PRIVKEY_KEY: &str = "nostr_bbs_sk";

/// Reactive write-path signer state. `Copy` — every field is a reactive handle,
/// so it is cheap to pass by value and store in Leptos context.
#[derive(Clone, Copy)]
pub struct BbsSigner {
    /// The active signer, if signed in. Held in a non-reactive `StoredValue` so
    /// the `Rc<dyn Signer>` never enters the reactive signal graph.
    signer: StoredValue<Option<SignerHandle>>,
    /// The signed-in viewer's hex pubkey (reactive — the UI gates on it).
    pubkey: RwSignal<Option<String>>,
    /// Latest sign-in error, surfaced by the login UI.
    error: RwSignal<Option<String>>,
}

impl Default for BbsSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl BbsSigner {
    /// Create an empty (signed-out) signer store.
    pub fn new() -> Self {
        Self {
            signer: StoredValue::new(None),
            pubkey: RwSignal::new(None),
            error: RwSignal::new(None),
        }
    }

    /// Reactive signal of the signed-in pubkey (hex), or `None` when signed out.
    pub fn pubkey(&self) -> RwSignal<Option<String>> {
        self.pubkey
    }

    /// Reactive signal of the latest sign-in error.
    pub fn error(&self) -> RwSignal<Option<String>> {
        self.error
    }

    /// The signed-in pubkey (untracked) — for use inside event handlers.
    pub fn pubkey_hex(&self) -> Option<String> {
        self.pubkey.get_untracked()
    }

    /// Clone out the active signer, if any.
    pub fn get_signer(&self) -> Option<Rc<dyn Signer>> {
        self.signer
            .with_value(|s| s.as_ref().map(|sw| (**sw).clone()))
    }

    /// Install a keypair as the active signer (in-memory) and register it with
    /// the relay so NIP-42 AUTH challenges can be answered.
    fn install(&self, keypair: Keypair) {
        let pubkey_hex = keypair.public.to_hex();
        let signer: Rc<dyn Signer> = Rc::new(PrfSigner::new(keypair));
        self.signer
            .set_value(Some(SendWrapper::new(signer.clone())));
        self.pubkey.set(Some(pubkey_hex));
        self.error.set(None);
        crate::relay::set_signer(signer);
    }

    /// Sign in with a pasted `nsec1…` / 64-char hex private key.
    pub fn login_with_key(&self, input: &str) -> Result<(), String> {
        match parse_secret_key(input) {
            Ok(kp) => {
                self.install(kp);
                Ok(())
            }
            Err(e) => {
                self.error.set(Some(e.clone()));
                Err(e)
            }
        }
    }

    /// Generate a fresh keypair, install it, and return the hex secret so the UI
    /// can show it once for backup. The secret is not persisted by the BBS.
    pub fn generate(&self) -> Result<String, String> {
        let keypair = nostr_bbs_core::generate_keypair()
            .map_err(|e| format!("Key generation failed: {e}"))?;
        let privkey_hex = hex::encode(keypair.secret.as_bytes());
        self.install(keypair);
        Ok(privkey_hex)
    }

    /// Sign out: drop the in-memory signer and de-register it from the relay.
    pub fn logout(&self) {
        self.signer.set_value(None);
        self.pubkey.set(None);
        self.error.set(None);
        crate::relay::clear_signer();
    }

    /// Adopt the forum client's persisted session key, same-origin (wasm only).
    /// Returns `true` if a usable key was found and installed.
    #[cfg(target_arch = "wasm32")]
    pub fn adopt_forum_session(&self) -> bool {
        match read_forum_privkey_hex() {
            Some(hex_key) => match parse_secret_key(&hex_key) {
                Ok(kp) => {
                    self.install(kp);
                    true
                }
                Err(_) => false,
            },
            None => false,
        }
    }

    /// Native fallback: no browser storage to adopt.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn adopt_forum_session(&self) -> bool {
        false
    }
}

/// Parse a user-supplied secret key (64-char hex or `nsec1…` bech32) into a
/// validated [`Keypair`]. Rejects anything that is not a valid secp256k1 scalar.
/// The intermediate hex buffer is scrubbed before returning.
pub fn parse_secret_key(input: &str) -> Result<Keypair, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Enter a private key (nsec1… or 64-char hex).".to_string());
    }

    // Normalise to a lowercase hex string, delegating nsec decoding to the kit.
    let mut hex_key = if trimmed.starts_with("nsec1") {
        nostr_bbs_core::decode_nsec(trimmed).map_err(|e| format!("Invalid nsec: {e}"))?
    } else {
        trimmed.to_ascii_lowercase()
    };

    let decoded = hex::decode(&hex_key);
    // Scrub the transient hex before it drops (String has no Zeroize impl).
    unsafe {
        for b in hex_key.as_bytes_mut() {
            *b = 0;
        }
    }

    let bytes =
        decoded.map_err(|_| "Invalid key: expected 64-char hex or nsec1… bech32.".to_string())?;
    if bytes.len() != 32 {
        return Err(format!(
            "Key must be 32 bytes (got {}). Paste a 64-char hex key or nsec1… bech32.",
            bytes.len()
        ));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let secret = nostr_bbs_core::SecretKey::from_bytes(arr)
        .map_err(|e| format!("Invalid secp256k1 key: {e}"))?;
    arr.zeroize();
    let public = secret.public_key();
    Ok(Keypair { secret, public })
}

/// Read the forum client's persisted secret key hex from browser storage,
/// checking localStorage first (the forum's default persistence scope) then
/// sessionStorage (remember-me=false sessions). Returns `None` when absent.
#[cfg(target_arch = "wasm32")]
fn read_forum_privkey_hex() -> Option<String> {
    let window = web_sys::window()?;
    if let Some(storage) = window.local_storage().ok().flatten() {
        if let Ok(Some(hex_key)) = storage.get_item(FORUM_PRIVKEY_KEY) {
            if !hex_key.trim().is_empty() {
                return Some(hex_key);
            }
        }
    }
    if let Some(storage) = window.session_storage().ok().flatten() {
        if let Ok(Some(hex_key)) = storage.get_item(FORUM_PRIVKEY_KEY) {
            if !hex_key.trim().is_empty() {
                return Some(hex_key);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_key_roundtrips_to_pubkey() {
        // A known-valid secret (all 0x01 is a valid secp256k1 scalar).
        let sk_hex = "01".repeat(32);
        let kp = parse_secret_key(&sk_hex).expect("valid hex key");
        let expected_pubkey = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hex::decode(&sk_hex).unwrap());
            nostr_bbs_core::SecretKey::from_bytes(arr)
                .unwrap()
                .public_key()
                .to_hex()
        };
        assert_eq!(kp.public.to_hex(), expected_pubkey);
    }

    #[test]
    fn parse_uppercase_hex_is_accepted() {
        let sk_hex_upper = "01".repeat(32).to_ascii_uppercase();
        assert!(parse_secret_key(&sk_hex_upper).is_ok());
    }

    #[test]
    fn parse_nsec_matches_hex_path() {
        let sk_hex = "01".repeat(32);
        let nsec = nostr_bbs_core::encode_nsec(&sk_hex).expect("encode nsec");
        let from_nsec = parse_secret_key(&nsec).expect("valid nsec");
        let from_hex = parse_secret_key(&sk_hex).expect("valid hex");
        assert_eq!(from_nsec.public.to_hex(), from_hex.public.to_hex());
    }

    #[test]
    fn parse_rejects_empty_and_garbage() {
        assert!(parse_secret_key("").is_err());
        assert!(parse_secret_key("   ").is_err());
        assert!(parse_secret_key("not a key").is_err());
        assert!(parse_secret_key("nsec1notvalidbech32").is_err());
    }

    #[test]
    fn parse_rejects_wrong_length_hex() {
        assert!(parse_secret_key("abcd").is_err());
        assert!(parse_secret_key(&"ab".repeat(31)).is_err());
    }

    #[test]
    fn parse_rejects_zero_scalar() {
        // All-zero bytes are a syntactically valid hex string but not a valid
        // secp256k1 secret key — must fail closed, not produce a bogus signer.
        assert!(parse_secret_key(&"00".repeat(32)).is_err());
    }
}
