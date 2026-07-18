//! BBS write-path signer — the crypto-owning module.
//!
//! The receive-only BBS gains a write path by obtaining a [`Signer`] the SAME way
//! the forum client does, without hand-rolling any cryptography: it reuses the
//! kit's audited [`nostr_bbs_core::signer::PrfSigner`] (BIP-340 Schnorr +
//! NIP-44/04) and key parsing ([`nostr_bbs_core::SecretKey`],
//! [`nostr_bbs_core::Keypair`], [`nostr_bbs_core::decode_nsec`]). No BIP-340,
//! NIP-44, or bech32 is re-implemented here.
//!
//! A signer is obtained three ways, in priority order:
//!
//! 1. **Adopt the forum session, same-origin — local key.** For local-key /
//!    imported-nsec logins the forum client persists the raw 32-byte secret as
//!    hex under the localStorage/sessionStorage key `nostr_bbs_sk` (see the
//!    forum's `auth::session`). The BBS is served same-origin (`/community/bbs/`
//!    vs `/community/`), so it reads the SAME key material the forum already
//!    holds into an in-memory [`PrfSigner`]. This adds no new exposure boundary:
//!    any same-origin script can already read that entry. The transient hex is
//!    scrubbed after decoding (audit B8 hardening, mirrored from the forum's
//!    `read_privkey_session`).
//!
//! 2. **Adopt the forum session, same-origin — NIP-07 extension.** PodKey /
//!    passkey / nos2x / Alby sessions expose no readable `nostr_bbs_sk` — the key
//!    lives in the extension. When the forum's stored session records
//!    `isNip07:true` and that extension (`window.nostr`) is present same-origin,
//!    the BBS re-attaches a [`crate::nip07::Nip07Signer`] to it, so signing in at
//!    `/community/` carries here with NO key exposure. Signatures (posts,
//!    governance, the relay's NIP-42 AUTH) round-trip through the extension's
//!    approval prompt; the BBS never sees private key material.
//!
//! 3. **Minimal in-memory BBS login.** Paste an `nsec1…` / 64-char hex key, or
//!    generate a fresh one, or click "sign in with extension" when a NIP-07
//!    provider is present. A pasted/generated [`Keypair`] lives only in memory
//!    and is zeroized on drop (via [`nostr_bbs_core::SecretKey`]); the BBS never
//!    persists it.
//!
//! Fail closed: with no signer the write actions are disabled and the UI directs
//! the user to sign in. Every path routes through `BbsSigner::install_signer`,
//! which registers the signer with the relay module ([`crate::relay::set_signer`])
//! so NIP-42 AUTH challenges can be answered.

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

    /// Install an already-built signer as the active signer and register it with
    /// the relay so NIP-42 AUTH challenges can be answered. Every sign-in path —
    /// the in-memory keypair ([`PrfSigner`]) and the NIP-07 browser extension
    /// ([`crate::nip07::Nip07Signer`]) — funnels through here, so the AUTH / relay
    /// wiring lives in exactly one place regardless of signer backend.
    fn install_signer(&self, signer: Rc<dyn Signer>, pubkey_hex: String) {
        self.signer
            .set_value(Some(SendWrapper::new(signer.clone())));
        self.pubkey.set(Some(pubkey_hex));
        self.error.set(None);
        crate::relay::set_signer(signer);
    }

    /// Install a local keypair as the active in-memory signer ([`PrfSigner`]).
    fn install(&self, keypair: Keypair) {
        let pubkey_hex = keypair.public.to_hex();
        let signer: Rc<dyn Signer> = Rc::new(PrfSigner::new(keypair));
        self.install_signer(signer, pubkey_hex);
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

    /// Adopt a passkey-derived keypair (F9). The WebAuthn PRF ceremony
    /// ([`crate::passkey`]) hands us a [`Keypair`]; install it through the SAME
    /// in-memory path as the generate/paste/adopt logins ([`Self::install`]).
    /// The passkey itself is the recovery factor, so — unlike `generate()` — no
    /// one-time backup sheet follows; the key lives in memory only and is never
    /// persisted by the BBS.
    pub fn login_with_passkey(&self, keypair: Keypair) {
        self.install(keypair);
    }

    /// Sign in with a NIP-07 browser extension (`window.nostr` — PodKey, nos2x,
    /// Alby, or a passkey provider that exposes NIP-07).
    ///
    /// Reads the extension's pubkey ([`crate::nip07::nip07_get_pubkey`]) and
    /// installs a [`crate::nip07::Nip07Signer`] that routes every signature —
    /// board posts, governance decisions, and the relay's NIP-42 AUTH challenge —
    /// back through the extension's approval prompt. The private key never enters
    /// the BBS. Async because the extension may prompt the user; errors surface on
    /// the [`error`](Self::error) signal and are also returned. Fails closed when
    /// no provider is present.
    pub async fn login_with_extension(&self) -> Result<(), String> {
        if !crate::nip07::has_nip07_extension() {
            let e = "No NIP-07 browser extension detected.".to_string();
            self.error.set(Some(e.clone()));
            return Err(e);
        }
        match crate::nip07::nip07_get_pubkey().await {
            Ok(pubkey) => {
                let signer: Rc<dyn Signer> =
                    Rc::new(crate::nip07::Nip07Signer::from_pubkey(pubkey.clone()));
                self.install_signer(signer, pubkey);
                Ok(())
            }
            Err(e) => {
                let msg = format!("Extension sign-in failed: {e}");
                self.error.set(Some(msg.clone()));
                Err(msg)
            }
        }
    }

    /// Adopt a baked (ADR-109) 32-byte secret as the active in-memory signer.
    ///
    /// The durable copy is the AES-GCM-wrapped record in IndexedDB (written by the
    /// forum bake, or by the BBS local re-bake after an iOS rebind); this installs
    /// a live [`PrfSigner`] from the unwrapped secret through the SAME
    /// `install()`/`install_signer()` seam as every other path — so the relay is
    /// registered and NIP-42 AUTH is answered identically. The BBS never
    /// re-persists the secret here (the durable copy stays in IndexedDB). The
    /// caller-owned buffer is left to the caller to zeroize (it holds it in a
    /// [`zeroize::Zeroizing`]); the local copy taken here is scrubbed. Returns
    /// `false` when the bytes are not a valid secp256k1 scalar (fail closed).
    pub fn adopt_baked_key(&self, secret: &[u8; 32]) -> bool {
        let mut arr = *secret;
        let parsed = nostr_bbs_core::SecretKey::from_bytes(arr);
        arr.zeroize();
        match parsed {
            Ok(sk) => {
                let public = sk.public_key();
                self.install(Keypair { secret: sk, public });
                true
            }
            Err(_) => false,
        }
    }

    /// Whether a signer is installed (a pubkey is present). The `app.rs` boot gate
    /// uses this to decide whether the PWA one-shot boot still needs to unwrap the
    /// baked key or route to rebind — an already-adopted forum session skips both.
    pub fn has_key(&self) -> bool {
        self.pubkey.get_untracked().is_some()
    }

    /// Sign out: drop the in-memory signer and de-register it from the relay.
    pub fn logout(&self) {
        self.signer.set_value(None);
        self.pubkey.set(None);
        self.error.set(None);
        crate::relay::clear_signer();
    }

    /// Adopt the forum client's same-origin session, wasm only. Returns `true`
    /// if a usable signer was found and installed.
    ///
    /// Two adoption paths, in priority order:
    ///
    /// 1. **Local key** — the forum persisted the raw secret hex under
    ///    `nostr_bbs_sk`; parse it into an in-memory [`PrfSigner`].
    /// 2. **NIP-07 extension** — the forum's stored session records
    ///    `isNip07:true` and the extension (`window.nostr`) is present
    ///    same-origin; re-attach a [`crate::nip07::Nip07Signer`] to it. No key is
    ///    read or exposed; the extension answers the relay's AUTH challenge (via
    ///    its approval popup, or replayed from `PendingAuth` if the challenge
    ///    arrives before this signer is installed).
    #[cfg(target_arch = "wasm32")]
    pub fn adopt_forum_session(&self) -> bool {
        // A present-but-unparseable raw key must fall through to the NIP-07 path,
        // not dead-end, so gate the local-key choice on a successful parse.
        let local_kp = read_forum_privkey_hex()
            .as_deref()
            .and_then(|hex| parse_secret_key(hex).ok());
        let session_json = crate::config::read_forum_session_json();
        match choose_adoption(
            local_kp.is_some(),
            session_json.as_deref(),
            crate::nip07::has_nip07_extension(),
        ) {
            AdoptChoice::LocalKey => match local_kp {
                Some(kp) => {
                    self.install(kp);
                    true
                }
                None => false,
            },
            AdoptChoice::Nip07(pubkey) => {
                let signer: Rc<dyn Signer> =
                    Rc::new(crate::nip07::Nip07Signer::from_pubkey(pubkey.clone()));
                self.install_signer(signer, pubkey);
                true
            }
            AdoptChoice::None => false,
        }
    }

    /// Native fallback: no browser storage to adopt.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn adopt_forum_session(&self) -> bool {
        false
    }

    /// The readable raw secret hex for a signed-in LOCAL key — the same-origin
    /// forum `nostr_bbs_sk` entry — so the Settings backup sheet (F14) can show
    /// it once. Returns `None` when signed out or when the session is a NIP-07
    /// extension (which exposes no readable key — nothing to back up here). Never
    /// exposes new material: any same-origin script can already read that entry.
    #[cfg(target_arch = "wasm32")]
    pub fn local_secret_hex(&self) -> Option<String> {
        if self.pubkey.get_untracked().is_none() {
            return None;
        }
        read_forum_privkey_hex().filter(|h| !h.trim().is_empty())
    }

    /// Native fallback: no browser storage to read.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn local_secret_hex(&self) -> Option<String> {
        None
    }
}

/// Which backend a forum-session adoption should install. Pure decision split
/// out of [`BbsSigner::adopt_forum_session`] so the priority/selection logic is
/// unit-testable on the native target without browser storage or `window.nostr`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AdoptChoice {
    /// A valid raw `nostr_bbs_sk` secret is present → in-memory [`PrfSigner`].
    LocalKey,
    /// The forum session is NIP-07 and the extension is present → a
    /// [`crate::nip07::Nip07Signer`] for this hex pubkey.
    Nip07(String),
    /// Nothing adoptable — stay signed out.
    None,
}

/// Decide how to adopt the forum's same-origin session.
///
/// A readable local key wins over NIP-07 (it is the prompt-free path and needs no
/// extension round-trip). NIP-07 is chosen only when there is no usable local key
/// AND the session was extension-backed (`isNip07:true`) AND the provider is
/// present same-origin AND a pubkey is recorded — otherwise there is nothing to
/// re-attach to, so we stay signed out (fail closed).
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub(crate) fn choose_adoption(
    local_key_valid: bool,
    session_json: Option<&str>,
    extension_present: bool,
) -> AdoptChoice {
    if local_key_valid {
        return AdoptChoice::LocalKey;
    }
    if extension_present {
        if let Some(json) = session_json {
            if crate::config::session_is_nip07(json) {
                if let Some(pubkey) = crate::config::pubkey_from_session(json) {
                    return AdoptChoice::Nip07(pubkey);
                }
            }
        }
    }
    AdoptChoice::None
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

    // ── adoption selection ──────────────────────────────────────────────────

    fn nip07_session(pk: &str) -> String {
        format!(r#"{{"_v":2,"publicKey":"{pk}","isNip07":true,"nickname":"x"}}"#)
    }

    #[test]
    fn local_key_wins_even_with_nip07_session_and_extension() {
        // A readable local key is the prompt-free path; it takes priority over an
        // extension re-attach regardless of the stored session flags.
        let pk = "ab".repeat(32);
        let choice = choose_adoption(true, Some(&nip07_session(&pk)), true);
        assert_eq!(choice, AdoptChoice::LocalKey);
    }

    #[test]
    fn nip07_chosen_when_no_local_key_and_extension_present() {
        let pk = "cd".repeat(32);
        let choice = choose_adoption(false, Some(&nip07_session(&pk)), true);
        assert_eq!(choice, AdoptChoice::Nip07(pk));
    }

    #[test]
    fn nip07_session_without_extension_is_not_adopted() {
        // isNip07 session but no provider present → cannot sign, so stay signed
        // out (the PendingAuth/AUTH path never gets a usable signer). Fail closed.
        let pk = "ef".repeat(32);
        assert_eq!(
            choose_adoption(false, Some(&nip07_session(&pk)), false),
            AdoptChoice::None
        );
    }

    #[test]
    fn non_nip07_session_with_extension_is_not_adopted() {
        // A local-key/passkey forum session (isNip07 absent/false) must not be
        // silently re-attached to whatever extension happens to be installed —
        // that could sign as the wrong identity.
        let pk = "11".repeat(32);
        let local_key_session =
            format!(r#"{{"_v":2,"publicKey":"{pk}","isNip07":false,"isLocalKey":true}}"#);
        assert_eq!(
            choose_adoption(false, Some(&local_key_session), true),
            AdoptChoice::None
        );
    }

    #[test]
    fn nip07_session_missing_pubkey_is_not_adopted() {
        // isNip07 but no recorded pubkey → nothing to re-attach to.
        let choice = choose_adoption(false, Some(r#"{"_v":2,"isNip07":true}"#), true);
        assert_eq!(choice, AdoptChoice::None);
    }

    #[test]
    fn no_session_and_no_key_stays_signed_out() {
        assert_eq!(choose_adoption(false, None, true), AdoptChoice::None);
        assert_eq!(choose_adoption(false, None, false), AdoptChoice::None);
    }
}
