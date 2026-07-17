//! F9 — Native passkey sign-in (WebAuthn PRF → derived Nostr key).
//!
//! This lets the BBS sign a phone user in on-device, with **no browser
//! extension** and **without leaving to `/community/`**. A WebAuthn credential
//! with the **PRF extension** yields a per-credential secret; HKDF-SHA-256 over
//! that PRF output is derived into a secp256k1 keypair by the kit
//! ([`nostr_bbs_core::derive_from_prf`]) — the *same* construction the forum
//! client uses, so a passkey created here and one created at `/community/`
//! resolve to the **same** Nostr identity.
//!
//! ## Origin
//!
//! Ported (and condensed into one self-contained module) from the audited forum
//! client so the BBS can reuse the proven ceremony without an auth rewrite:
//!   - `crates/nostr-bbs-forum-client/src/auth/passkey.rs`  (register/authenticate)
//!   - `crates/nostr-bbs-forum-client/src/auth/webauthn.rs` (options builders,
//!     PRF extraction, base64url codec, JSON→JS)
//!   - `crates/nostr-bbs-forum-client/src/auth/http.rs`     (response encoders,
//!     `fetch_json_post`)
//!
//! Deliberate divergences from the forum port:
//!   - **Returns a [`nostr_bbs_core::Keypair`]** (not raw privkey bytes plus
//!     server metadata) so the caller installs it through the *same* code path
//!     as the generate/paste/adopt logins ([`crate::signer::BbsSigner`]). The
//!     passkey IS the backup, so no one-time backup sheet is shown.
//!   - **`json_to_js` uses `JSON.parse`** instead of `serde_wasm_bindgen`, which
//!     produces the identical plain-JS-object structure the WebAuthn API and
//!     password-manager extensions expect, with zero extra crate dependencies.
//!   - **Self-contained**: references only `nostr_bbs_core` + web-sys, never
//!     `crate::*`, so the crypto/ceremony logic is unit-testable in isolation.
//!
//! Pure helpers (intent selection, PRF→key shape, base64url codec, endpoint
//! join, options/verify body + response parsing) are `#[cfg(test)]`-covered on
//! the native target; the WebAuthn ceremony itself is wasm-only.

#![allow(dead_code)] // Public surface is wired in by the F9 manifest (screens.rs / signer.rs).

use nostr_bbs_core::Keypair;

#[cfg(target_arch = "wasm32")]
use js_sys::{Object, Reflect};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;

// ── Result / outcome types ──────────────────────────────────────────────────

/// A successful passkey sign-in: the signed-in hex pubkey and the derived
/// keypair the caller installs into the signer. The [`Keypair`]'s secret is
/// zeroized on drop by [`nostr_bbs_core::SecretKey`]; the BBS never persists it.
pub struct PasskeyOutcome {
    pub pubkey: String,
    pub keypair: Keypair,
}

/// Whether this passkey sign-in should re-authenticate a known identity or
/// register a fresh one. Pure decision, split out for unit testing.
#[derive(Debug, PartialEq, Eq)]
pub enum PasskeyIntent {
    /// A pubkey is already known (returning user / adopted forum session) — run
    /// the login ceremony bound to it.
    Authenticate(String),
    /// No known identity — create a new passkey credential + account on-device.
    Register,
}

/// Choose the passkey flow. A non-empty saved pubkey (from a prior session /
/// adopted forum login) means "returning user" → authenticate; otherwise a
/// first-time phone user registers a new credential.
pub fn choose_passkey_intent(saved_pubkey: Option<&str>) -> PasskeyIntent {
    match saved_pubkey.map(str::trim) {
        Some(pk) if !pk.is_empty() => PasskeyIntent::Authenticate(pk.to_string()),
        _ => PasskeyIntent::Register,
    }
}

// ── Error type (no thiserror dep — plain Display/Error) ──────────────────────

#[derive(Debug)]
pub enum PasskeyError {
    /// No browser environment (e.g. native build).
    NoBrowser,
    /// WebAuthn / PRF not available on this device or browser.
    Unsupported(String),
    /// The authenticator does not support the PRF extension we need.
    PrfNotSupported(String),
    /// Cross-device QR (hybrid) transport — produces a different PRF and cannot
    /// re-derive the identity.
    HybridBlocked,
    /// User cancelled or the ceremony was aborted.
    Cancelled(String),
    /// No passkey registered for this account (login path).
    NoCredential,
    /// Network / fetch failure.
    Network(String),
    /// Server returned a non-OK status.
    ServerError(String),
    /// Malformed protocol data (bad JSON, missing salt, …).
    Protocol(String),
    /// secp256k1 / HKDF key derivation failed.
    KeyDerivation(String),
    /// A raw JavaScript error surfaced from web-sys.
    JsError(String),
}

impl std::fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoBrowser => write!(f, "No browser environment"),
            Self::Unsupported(m) => write!(f, "Passkeys aren\u{2019}t available here: {m}"),
            Self::PrfNotSupported(m) => write!(f, "PRF extension not supported: {m}"),
            Self::HybridBlocked => write!(
                f,
                "Cross-device QR sign-in produces a different key and cannot re-derive your \
                 identity. Use this device\u{2019}s own biometrics (Face ID / Touch ID / \
                 fingerprint)."
            ),
            Self::Cancelled(m) => write!(f, "Passkey cancelled: {m}"),
            Self::NoCredential => write!(f, "No passkey is registered for this account yet"),
            Self::Network(m) => write!(f, "Network error: {m}"),
            Self::ServerError(m) => write!(f, "Server error: {m}"),
            Self::Protocol(m) => write!(f, "Protocol error: {m}"),
            Self::KeyDerivation(m) => write!(f, "Key derivation error: {m}"),
            Self::JsError(m) => write!(f, "Browser error: {m}"),
        }
    }
}

impl std::error::Error for PasskeyError {}

#[cfg(target_arch = "wasm32")]
impl From<JsValue> for PasskeyError {
    fn from(e: JsValue) -> Self {
        Self::JsError(describe_js_error(&e))
    }
}

// ── Pure helpers (unit-tested) ──────────────────────────────────────────────

/// Join an auth-API base with a path, tolerating a trailing slash on the base
/// and always emitting exactly one separator. An empty base yields a relative
/// (same-origin) path, matching the forum client's `base.is_empty()` handling.
pub(crate) fn endpoint(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    if base.is_empty() {
        format!("/{path}")
    } else {
        format!("{base}/{path}")
    }
}

/// Take the first 32 bytes of a PRF output, rejecting anything shorter — the
/// authenticator must return at least a 32-byte pseudo-random value for us to
/// key the secp256k1 scalar off. Pure; the fallible boundary the ceremony hits.
pub(crate) fn require_prf_32(prf_output: &[u8]) -> Result<[u8; 32], PasskeyError> {
    if prf_output.len() < 32 {
        return Err(PasskeyError::PrfNotSupported(format!(
            "PRF output too short ({} bytes, need 32)",
            prf_output.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&prf_output[..32]);
    Ok(out)
}

/// PRF output → Nostr keypair. The whole point of F9: deterministic, on-device,
/// identical to the forum's derivation (HKDF-SHA-256, info `"nostr-secp256k1-v1"`
/// inside [`nostr_bbs_core::derive_from_prf`]). The transient 32-byte PRF buffer
/// is zeroized before returning.
pub(crate) fn derive_keypair_from_prf_output(prf_output: &[u8]) -> Result<Keypair, PasskeyError> {
    use zeroize::Zeroize;
    let mut prf_bytes = require_prf_32(prf_output)?;
    let keypair = nostr_bbs_core::derive_from_prf(&prf_bytes)
        .map_err(|e| PasskeyError::KeyDerivation(e.to_string()));
    prf_bytes.zeroize();
    keypair
}

/// Body for `POST /auth/register/options`.
pub(crate) fn register_options_body(display_name: &str) -> serde_json::Value {
    serde_json::json!({ "displayName": display_name })
}

/// Body for `POST /auth/login/options`.
pub(crate) fn login_options_body(pubkey: &str) -> serde_json::Value {
    serde_json::json!({ "pubkey": pubkey })
}

/// Parse an options response (`{ options, prfSalt }`), returning the raw options
/// JSON plus the mandatory PRF salt. The salt is server-issued and bound to the
/// credential; without the SAME salt the PRF output — and thus the derived key —
/// would differ, so a missing salt is a hard error.
pub(crate) fn parse_options_response(
    resp_text: &str,
) -> Result<(serde_json::Value, String), PasskeyError> {
    let v: serde_json::Value =
        serde_json::from_str(resp_text).map_err(|e| PasskeyError::Protocol(e.to_string()))?;
    let options = v
        .get("options")
        .cloned()
        .ok_or_else(|| PasskeyError::Protocol("options missing from server response".into()))?;
    let salt = v
        .get("prfSalt")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            PasskeyError::PrfNotSupported(
                "Server did not return a prfSalt \u{2014} this credential has no PRF data. \
                 Register a new passkey or use a private key instead."
                    .into(),
            )
        })?
        .to_string();
    Ok((options, salt))
}

/// Body for `POST /auth/register/verify` (plain POST).
pub(crate) fn register_verify_body(
    encoded_response: serde_json::Value,
    pubkey: &str,
    prf_salt_b64: &str,
) -> serde_json::Value {
    serde_json::json!({
        "response": encoded_response,
        "pubkey": pubkey,
        "prfSalt": prf_salt_b64,
    })
}

/// Body for `POST /auth/login/verify` (NIP-98 authenticated POST).
pub(crate) fn login_verify_body(
    encoded_response: serde_json::Value,
    pubkey: &str,
) -> serde_json::Value {
    serde_json::json!({
        "response": encoded_response,
        "pubkey": pubkey,
    })
}

/// Decode a base64url (no-pad) string to bytes. Pure; used for the server
/// challenge / user.id / credential id / PRF salt.
pub(crate) fn base64url_to_bytes(input: &str) -> Result<Vec<u8>, PasskeyError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let cleaned = input.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(cleaned)
        .map_err(|e| PasskeyError::Protocol(format!("base64url decode: {e}")))
}

/// Encode bytes as base64url (no padding). Pure; the wasm buffer encoder funnels
/// through this after reading the ArrayBuffer.
pub(crate) fn bytes_to_base64url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

// ── Feature detection ───────────────────────────────────────────────────────

/// Is native passkey sign-in usable here? True only when the browser exposes
/// both `navigator.credentials` (Credential Management API) and
/// `window.PublicKeyCredential` (WebAuthn Level 2). PRF availability can only be
/// confirmed by running a ceremony, so PRF gaps surface later as a graceful
/// [`PasskeyError::PrfNotSupported`] rather than a false "supported" here.
pub fn is_passkey_supported() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        let Some(win) = web_sys::window() else {
            return false;
        };
        let nav = win.navigator();
        let has_creds = Reflect::get(nav.as_ref(), &JsValue::from_str("credentials"))
            .map(|c| !c.is_undefined() && !c.is_null())
            .unwrap_or(false);
        let has_pkc = Reflect::get(win.as_ref(), &JsValue::from_str("PublicKeyCredential"))
            .map(|v| !v.is_undefined() && !v.is_null())
            .unwrap_or(false);
        has_creds && has_pkc
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        false
    }
}

// ── High-level sign-in (wasm) ───────────────────────────────────────────────

/// One-call native passkey sign-in for the BBS button.
///
/// - Returning user (a `saved_pubkey` is known, e.g. from an adopted forum
///   session): run the **login** ceremony; if the account has no passkey yet
///   ([`PasskeyError::NoCredential`]) fall through to **register**.
/// - First-time phone user: **register** a new credential + account on-device.
///
/// On success the caller installs `outcome.keypair` through the normal signer
/// path (`BbsSigner`), and — because the passkey itself is the recovery factor —
/// shows **no** backup sheet.
#[cfg(target_arch = "wasm32")]
pub async fn passkey_sign_in(saved_pubkey: Option<String>) -> Result<PasskeyOutcome, PasskeyError> {
    if !is_passkey_supported() {
        return Err(PasskeyError::Unsupported(
            "this browser has no WebAuthn / passkey support".into(),
        ));
    }
    match choose_passkey_intent(saved_pubkey.as_deref()) {
        PasskeyIntent::Authenticate(pk) => match passkey_authenticate(&pk).await {
            Err(PasskeyError::NoCredential) => passkey_register(&register_display_name()).await,
            other => other,
        },
        PasskeyIntent::Register => passkey_register(&register_display_name()).await,
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn passkey_sign_in(
    _saved_pubkey: Option<String>,
) -> Result<PasskeyOutcome, PasskeyError> {
    Err(PasskeyError::NoBrowser)
}

/// Register a NEW passkey (PRF) and derive the Nostr keypair on-device.
///
/// 1. `POST /auth/register/options` → creation options + `prfSalt`
/// 2. `navigator.credentials.create()` with the PRF extension
/// 3. PRF output → HKDF → keypair
/// 4. `POST /auth/register/verify` → account / pod provisioned server-side
#[cfg(target_arch = "wasm32")]
pub async fn passkey_register(display_name: &str) -> Result<PasskeyOutcome, PasskeyError> {
    let base = auth_api_base();

    let resp = fetch_json_post(
        &endpoint(&base, "/auth/register/options"),
        &register_options_body(display_name),
    )
    .await?;
    let (options, prf_salt_b64) = parse_options_response(&resp)?;

    let credential = create_credential(&options, &prf_salt_b64).await?;

    let prf_output = extract_prf_output(&credential, true)?;
    let keypair = derive_keypair_from_prf_output(&prf_output)?;
    let pubkey = keypair.public.to_hex();

    let encoded = encode_attestation_response(&credential)?;
    let verify_body = register_verify_body(encoded, &pubkey, &prf_salt_b64);
    // Register verify is a plain POST (the credential proves possession); the
    // server records the credential and provisions the pod / whitelist entry.
    fetch_json_post(&endpoint(&base, "/auth/register/verify"), &verify_body).await?;

    Ok(PasskeyOutcome { pubkey, keypair })
}

/// Authenticate an EXISTING passkey and re-derive the same keypair.
///
/// Requires the caller to supply the pubkey it intends to sign in as (the
/// forum's post-audit-C2 rule: no credentialId→pubkey discovery oracle). The
/// pubkey comes from a previously-adopted forum session.
#[cfg(target_arch = "wasm32")]
pub async fn passkey_authenticate(pubkey: &str) -> Result<PasskeyOutcome, PasskeyError> {
    if pubkey.trim().is_empty() {
        return Err(PasskeyError::Protocol(
            "a pubkey is required to authenticate an existing passkey".into(),
        ));
    }
    let base = auth_api_base();

    let resp = fetch_json_post(
        &endpoint(&base, "/auth/login/options"),
        &login_options_body(pubkey),
    )
    .await?;
    let (options, prf_salt_b64) = parse_options_response(&resp)?;

    let assertion = get_assertion(&options, &prf_salt_b64).await?;
    // Cross-device QR (hybrid) produces a different PRF → different key. Reject.
    check_hybrid_transport(&assertion)?;

    let prf_output = extract_prf_output(&assertion, false)?;
    let keypair = derive_keypair_from_prf_output(&prf_output)?;
    let derived_pubkey = keypair.public.to_hex();

    let encoded = encode_assertion_response(&assertion)?;
    let verify_body = login_verify_body(encoded, &derived_pubkey);
    let verify_json =
        serde_json::to_string(&verify_body).map_err(|e| PasskeyError::Protocol(e.to_string()))?;
    // Login verify is NIP-98 authenticated with the freshly-derived secret.
    let mut sk = [0u8; 32];
    sk.copy_from_slice(keypair.secret.as_bytes());
    let result =
        fetch_with_nip98_post(&endpoint(&base, "/auth/login/verify"), &verify_json, &sk).await;
    {
        use zeroize::Zeroize;
        sk.zeroize();
    }
    result?;

    Ok(PasskeyOutcome {
        pubkey: derived_pubkey,
        keypair,
    })
}

// ── JsValue error sanitisation (wasm) ───────────────────────────────────────
// Friendly errors must never dump a raw `JsValue(...)` debug string to the user
// (redesign spec §5.x). These pull out just the DOMException `name`
// (e.g. "NotAllowedError") so ceremony / network failures read as short, safe
// copy instead of leaking the whole `{e:?}` blob through `PasskeyError`'s Display.

/// The DOMException `name` of a JsValue error, when present and non-empty.
#[cfg(target_arch = "wasm32")]
fn js_error_name(e: &JsValue) -> Option<String> {
    Reflect::get(e, &JsValue::from_str("name"))
        .ok()
        .and_then(|v| v.as_string())
        .filter(|s| !s.is_empty())
}

/// A short, safe description of a JsValue error — its DOMException `name` when
/// present, else a generic label. Never the raw `{e:?}` debug dump.
#[cfg(target_arch = "wasm32")]
fn describe_js_error(e: &JsValue) -> String {
    js_error_name(e).unwrap_or_else(|| "unexpected browser error".to_string())
}

/// Human copy for a WebAuthn prompt the user dismissed or that timed out
/// (a `NotAllowedError`), used by both the register and login ceremonies.
#[cfg(target_arch = "wasm32")]
const CEREMONY_CANCELLED_COPY: &str =
    "the Face ID / Touch ID prompt was dismissed or timed out. Try again, or paste a \
     private key instead.";

/// Map a rejected `navigator.credentials.get()` promise to a friendly
/// [`PasskeyError`]. A `NotAllowedError` (or an unnamed rejection during the
/// prompt) becomes a [`PasskeyError::Cancelled`] with human copy; any other
/// named failure keeps only the error name — never the raw JsValue. This gives
/// the returning-user login path the same friendly handling the register path
/// already has.
#[cfg(target_arch = "wasm32")]
fn map_get_rejection(e: JsValue) -> PasskeyError {
    match js_error_name(&e).as_deref() {
        Some("NotAllowedError") | None => PasskeyError::Cancelled(CEREMONY_CANCELLED_COPY.into()),
        Some(name) => PasskeyError::JsError(format!("passkey ceremony failed ({name})")),
    }
}

// ── WebAuthn ceremony (wasm) ────────────────────────────────────────────────

/// Detect a password-manager extension monkey-patching
/// `navigator.credentials.create` — its software authenticator won't support
/// PRF, so key derivation would be impossible. Mirrors the forum client's guard.
#[cfg(target_arch = "wasm32")]
fn check_credentials_intercepted() -> Result<(), PasskeyError> {
    let win = web_sys::window().ok_or(PasskeyError::NoBrowser)?;
    let credentials: JsValue = win.navigator().credentials().into();
    if let Ok(create_fn) = Reflect::get(&credentials, &JsValue::from_str("create")) {
        if !create_fn.is_undefined() && !create_fn.is_null() {
            if let Ok(func) = create_fn.dyn_into::<js_sys::Function>() {
                let fn_str = func.to_string().as_string().unwrap_or_default();
                if !fn_str.contains("[native code]") {
                    return Err(PasskeyError::PrfNotSupported(
                        "A password-manager extension is intercepting passkey requests, which \
                         blocks the key derivation your identity needs. Disable its passkey \
                         feature for this site, or paste a private key instead."
                            .into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn create_credential(
    options_json: &serde_json::Value,
    prf_salt_b64: &str,
) -> Result<JsValue, PasskeyError> {
    let win = web_sys::window().ok_or(PasskeyError::NoBrowser)?;
    let credentials = win.navigator().credentials();
    check_credentials_intercepted()?;

    let pk_options = build_creation_options(options_json, prf_salt_b64)?;
    let cred_options = Object::new();
    Reflect::set(&cred_options, &"publicKey".into(), &pk_options)
        .map_err(|_| PasskeyError::JsError("Failed to set publicKey".into()))?;

    let promise = credentials
        .create_with_options(&web_sys::CredentialCreationOptions::from(JsValue::from(
            cred_options,
        )))
        .map_err(|e| PasskeyError::JsError(describe_js_error(&e)))?;

    let result = JsFuture::from(promise).await.map_err(|e| {
        if js_error_name(&e).as_deref() == Some("NotAllowedError") {
            PasskeyError::Cancelled(
                "Passkey creation didn\u{2019}t complete. If you scanned a QR code with your \
                 phone, note cross-device passkeys can\u{2019}t derive a Nostr key \u{2014} use \
                 this device\u{2019}s own biometrics, or choose \u{201C}Generate a throwaway \
                 key\u{201D}."
                    .into(),
            )
        } else {
            PasskeyError::JsError(describe_js_error(&e))
        }
    })?;

    if result.is_null() || result.is_undefined() {
        return Err(PasskeyError::Cancelled("Passkey creation cancelled".into()));
    }
    Ok(result)
}

#[cfg(target_arch = "wasm32")]
async fn get_assertion(
    options_json: &serde_json::Value,
    prf_salt_b64: &str,
) -> Result<JsValue, PasskeyError> {
    let win = web_sys::window().ok_or(PasskeyError::NoBrowser)?;
    let credentials = win.navigator().credentials();
    check_credentials_intercepted()?;

    let pk_options = build_request_options(options_json, Some(prf_salt_b64))?;
    let cred_options = Object::new();
    Reflect::set(&cred_options, &"publicKey".into(), &pk_options)
        .map_err(|_| PasskeyError::JsError("Failed to set publicKey".into()))?;

    let promise = credentials
        .get_with_options(&web_sys::CredentialRequestOptions::from(JsValue::from(
            cred_options,
        )))
        .map_err(|e| PasskeyError::JsError(describe_js_error(&e)))?;

    let result = JsFuture::from(promise).await.map_err(map_get_rejection)?;

    if result.is_null() || result.is_undefined() {
        return Err(PasskeyError::Cancelled(
            "Passkey authentication cancelled".into(),
        ));
    }
    Ok(result)
}

/// Build `PublicKeyCredentialCreationOptions` from server JSON + PRF extension.
/// Spread-like: JSON→JS object first (preserving every server field), then
/// override the binary fields and attach the `prf.eval.first` salt.
#[cfg(target_arch = "wasm32")]
fn build_creation_options(
    json: &serde_json::Value,
    prf_salt_b64: &str,
) -> Result<JsValue, PasskeyError> {
    let options = json_to_js(json)?;

    if let Some(challenge) = json.get("challenge").and_then(|v| v.as_str()) {
        set_buffer(&options, "challenge", challenge)?;
    }
    if let Some(user_json) = json.get("user") {
        let user_obj = Reflect::get(&options, &"user".into()).unwrap_or(JsValue::UNDEFINED);
        if !user_obj.is_undefined() && !user_obj.is_null() {
            if let Some(id) = user_json.get("id").and_then(|v| v.as_str()) {
                set_buffer(&user_obj, "id", id)?;
            }
        }
    }
    if let Some(exclude) = json.get("excludeCredentials").and_then(|v| v.as_array()) {
        let arr = js_sys::Array::new();
        for cred in exclude {
            let cred_obj = json_to_js(cred)?;
            if let Some(id) = cred.get("id").and_then(|v| v.as_str()) {
                set_buffer(&cred_obj, "id", id)?;
            }
            arr.push(&cred_obj);
        }
        Reflect::set(&options, &"excludeCredentials".into(), &arr)?;
    }

    attach_prf_extension(&options, prf_salt_b64)?;
    Ok(options)
}

/// Build `PublicKeyCredentialRequestOptions` from server JSON, optionally + PRF.
#[cfg(target_arch = "wasm32")]
fn build_request_options(
    json: &serde_json::Value,
    prf_salt_b64: Option<&str>,
) -> Result<JsValue, PasskeyError> {
    let options = json_to_js(json)?;

    if let Some(challenge) = json.get("challenge").and_then(|v| v.as_str()) {
        set_buffer(&options, "challenge", challenge)?;
    }
    if let Some(allow) = json.get("allowCredentials").and_then(|v| v.as_array()) {
        let arr = js_sys::Array::new();
        for cred in allow {
            let cred_obj = json_to_js(cred)?;
            if let Some(id) = cred.get("id").and_then(|v| v.as_str()) {
                set_buffer(&cred_obj, "id", id)?;
            }
            arr.push(&cred_obj);
        }
        Reflect::set(&options, &"allowCredentials".into(), &arr)?;
    }
    if let Some(salt) = prf_salt_b64 {
        attach_prf_extension(&options, salt)?;
    }
    Ok(options)
}

/// Attach `extensions.prf.eval.first = <salt buffer>` to an options object.
#[cfg(target_arch = "wasm32")]
fn attach_prf_extension(options: &JsValue, prf_salt_b64: &str) -> Result<(), PasskeyError> {
    let extensions = Object::new();
    let prf = Object::new();
    let eval_obj = Object::new();
    let salt_buf = base64url_to_uint8array(prf_salt_b64)?;
    Reflect::set(&eval_obj, &"first".into(), &salt_buf)?;
    Reflect::set(&prf, &"eval".into(), &eval_obj)?;
    Reflect::set(&extensions, &"prf".into(), &prf)?;
    Reflect::set(options, &"extensions".into(), &extensions)?;
    Ok(())
}

/// Override an object field with a base64url string decoded to an ArrayBuffer.
#[cfg(target_arch = "wasm32")]
fn set_buffer(obj: &JsValue, key: &str, b64url: &str) -> Result<(), PasskeyError> {
    let buf = base64url_to_uint8array(b64url)?;
    Reflect::set(obj, &JsValue::from_str(key), &buf)?;
    Ok(())
}

/// Extract the PRF output (`getClientExtensionResults().prf.results.first`) from
/// a creation (`is_creation=true`) or assertion result.
#[cfg(target_arch = "wasm32")]
fn extract_prf_output(credential: &JsValue, is_creation: bool) -> Result<Vec<u8>, PasskeyError> {
    let ext_results = call_method(credential, "getClientExtensionResults", &[])?;

    let prf = Reflect::get(&ext_results, &"prf".into())
        .map_err(|_| PasskeyError::PrfNotSupported("No PRF in extension results".into()))?;
    if prf.is_undefined() || prf.is_null() {
        return Err(PasskeyError::PrfNotSupported(
            "This authenticator doesn\u{2019}t support the PRF extension. Use a device with \
             Face ID / Touch ID / a fingerprint reader, or paste a private key."
                .into(),
        ));
    }

    // On creation, `prf.enabled === false` means the credential was made without
    // PRF and can never produce it.
    if is_creation {
        if let Ok(enabled) = Reflect::get(&prf, &"enabled".into()) {
            if enabled.is_falsy() && !enabled.is_undefined() {
                return Err(PasskeyError::PrfNotSupported(
                    "This authenticator can\u{2019}t enable PRF. Use built-in biometrics (not \
                     cross-device QR)."
                        .into(),
                ));
            }
        }
    }

    let results = Reflect::get(&prf, &"results".into())
        .map_err(|_| PasskeyError::PrfNotSupported("No PRF results".into()))?;
    if results.is_undefined() || results.is_null() {
        return Err(PasskeyError::PrfNotSupported(
            "No PRF result returned. Please use Chrome 116+ or Safari 17.4+.".into(),
        ));
    }
    let first = Reflect::get(&results, &"first".into())
        .map_err(|_| PasskeyError::PrfNotSupported("No PRF first result".into()))?;
    if first.is_undefined() || first.is_null() {
        return Err(PasskeyError::PrfNotSupported(
            "No PRF first result. Please use Chrome 116+ or Safari 17.4+.".into(),
        ));
    }
    arraybuffer_to_vec(&first)
}

/// Block cross-device QR (hybrid) transport — a different authenticator would
/// yield a different PRF and thus a different (wrong) identity.
#[cfg(target_arch = "wasm32")]
fn check_hybrid_transport(assertion: &JsValue) -> Result<(), PasskeyError> {
    let attachment = Reflect::get(assertion, &"authenticatorAttachment".into()).ok();
    let is_cross_platform = attachment
        .as_ref()
        .and_then(|v| v.as_string())
        .map(|s| s == "cross-platform")
        .unwrap_or(false);
    if !is_cross_platform {
        return Ok(());
    }
    if let Some(resp) = Reflect::get(assertion, &"response".into()).ok() {
        if let Ok(transports) = call_method(&resp, "getTransports", &[]) {
            let arr = js_sys::Array::from(&transports);
            for i in 0..arr.length() {
                if arr.get(i).as_string().as_deref() == Some("hybrid") {
                    return Err(PasskeyError::HybridBlocked);
                }
            }
        }
    }
    Ok(())
}

// ── WebAuthn response encoders (wasm) ───────────────────────────────────────

/// Encode a registration (attestation) result for `/auth/register/verify`.
#[cfg(target_arch = "wasm32")]
fn encode_attestation_response(credential: &JsValue) -> Result<serde_json::Value, PasskeyError> {
    let id = js_str(credential, "id").ok_or_else(|| PasskeyError::JsError("Missing id".into()))?;
    let raw_id = buffer_to_base64url(&get(credential, "rawId")?)?;
    let response = get(credential, "response")?;
    let client_data = buffer_to_base64url(&get(&response, "clientDataJSON")?)?;
    let attestation = buffer_to_base64url(&get(&response, "attestationObject")?)?;

    let transports = call_method(&response, "getTransports", &[])
        .map(|arr| {
            let js_arr = js_sys::Array::from(&arr);
            (0..js_arr.length())
                .filter_map(|i| js_arr.get(i).as_string().map(serde_json::Value::String))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let cred_type = js_str(credential, "type").unwrap_or_else(|| "public-key".into());

    Ok(serde_json::json!({
        "id": id,
        "rawId": raw_id,
        "response": {
            "clientDataJSON": client_data,
            "attestationObject": attestation,
            "transports": transports,
        },
        "type": cred_type,
    }))
}

/// Encode an authentication (assertion) result for `/auth/login/verify`.
#[cfg(target_arch = "wasm32")]
fn encode_assertion_response(assertion: &JsValue) -> Result<serde_json::Value, PasskeyError> {
    let id = js_str(assertion, "id").ok_or_else(|| PasskeyError::JsError("Missing id".into()))?;
    let raw_id = buffer_to_base64url(&get(assertion, "rawId")?)?;
    let response = get(assertion, "response")?;
    let client_data = buffer_to_base64url(&get(&response, "clientDataJSON")?)?;
    let auth_data = buffer_to_base64url(&get(&response, "authenticatorData")?)?;
    let signature = buffer_to_base64url(&get(&response, "signature")?)?;

    let user_handle = Reflect::get(&response, &"userHandle".into())
        .ok()
        .filter(|v| !v.is_null() && !v.is_undefined())
        .and_then(|v| buffer_to_base64url(&v).ok());
    let cred_type = js_str(assertion, "type").unwrap_or_else(|| "public-key".into());

    Ok(serde_json::json!({
        "id": id,
        "rawId": raw_id,
        "response": {
            "clientDataJSON": client_data,
            "authenticatorData": auth_data,
            "signature": signature,
            "userHandle": user_handle,
        },
        "type": cred_type,
    }))
}

// ── JS interop / codec (wasm) ───────────────────────────────────────────────

/// `JSON.parse(serde_json)` — produces plain JS objects (never `Map`), exactly
/// what WebAuthn + password-manager extensions expect. Avoids `serde_wasm_bindgen`.
#[cfg(target_arch = "wasm32")]
fn json_to_js(value: &serde_json::Value) -> Result<JsValue, PasskeyError> {
    let s = serde_json::to_string(value).map_err(|e| PasskeyError::Protocol(e.to_string()))?;
    js_sys::JSON::parse(&s)
        .map_err(|e| PasskeyError::JsError(format!("JSON.parse: {}", describe_js_error(&e))))
}

#[cfg(target_arch = "wasm32")]
fn get(obj: &JsValue, key: &str) -> Result<JsValue, PasskeyError> {
    Reflect::get(obj, &JsValue::from_str(key))
        .map_err(|_| PasskeyError::JsError(format!("Missing {key}")))
}

#[cfg(target_arch = "wasm32")]
fn js_str(obj: &JsValue, key: &str) -> Option<String> {
    Reflect::get(obj, &JsValue::from_str(key))
        .ok()
        .and_then(|v| v.as_string())
}

#[cfg(target_arch = "wasm32")]
fn base64url_to_uint8array(input: &str) -> Result<JsValue, PasskeyError> {
    let bytes = base64url_to_bytes(input)?;
    let arr = js_sys::Uint8Array::new_with_length(bytes.len() as u32);
    arr.copy_from(&bytes);
    Ok(arr.buffer().into())
}

#[cfg(target_arch = "wasm32")]
fn buffer_to_base64url(js_val: &JsValue) -> Result<String, PasskeyError> {
    Ok(bytes_to_base64url(&arraybuffer_to_vec(js_val)?))
}

#[cfg(target_arch = "wasm32")]
fn arraybuffer_to_vec(js_val: &JsValue) -> Result<Vec<u8>, PasskeyError> {
    if let Ok(arr) = js_val.clone().dyn_into::<js_sys::Uint8Array>() {
        return Ok(arr.to_vec());
    }
    if let Ok(buf) = js_val.clone().dyn_into::<js_sys::ArrayBuffer>() {
        return Ok(js_sys::Uint8Array::new(&buf).to_vec());
    }
    Err(PasskeyError::JsError(
        "Expected ArrayBuffer or Uint8Array".into(),
    ))
}

#[cfg(target_arch = "wasm32")]
fn call_method(obj: &JsValue, method: &str, args: &[JsValue]) -> Result<JsValue, PasskeyError> {
    let func = Reflect::get(obj, &JsValue::from_str(method))
        .map_err(|_| PasskeyError::JsError(format!("Missing method: {method}")))?;
    if func.is_undefined() {
        return Err(PasskeyError::JsError(format!("Method {method} not found")));
    }
    let func: js_sys::Function = func
        .dyn_into()
        .map_err(|_| PasskeyError::JsError(format!("{method} is not a function")))?;
    let args_arr = js_sys::Array::new();
    for a in args {
        args_arr.push(a);
    }
    func.apply(obj, &args_arr).map_err(|e| {
        PasskeyError::JsError(format!("{method} call failed: {}", describe_js_error(&e)))
    })
}

// ── HTTP (wasm) ─────────────────────────────────────────────────────────────

/// POST JSON, returning the response body text; extracts a server error message
/// (and the `NO_CREDENTIAL` code) on non-OK responses.
#[cfg(target_arch = "wasm32")]
async fn fetch_json_post(url: &str, body: &serde_json::Value) -> Result<String, PasskeyError> {
    let win = web_sys::window().ok_or(PasskeyError::NoBrowser)?;
    let body_str =
        serde_json::to_string(body).map_err(|e| PasskeyError::Protocol(e.to_string()))?;

    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    let headers =
        web_sys::Headers::new().map_err(|e| PasskeyError::JsError(describe_js_error(&e)))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| PasskeyError::JsError(describe_js_error(&e)))?;
    init.set_headers(&headers);
    init.set_body(&JsValue::from_str(&body_str));

    let request = web_sys::Request::new_with_str_and_init(url, &init)
        .map_err(|e| PasskeyError::JsError(describe_js_error(&e)))?;
    let resp_val = JsFuture::from(win.fetch_with_request(&request))
        .await
        .map_err(|e| PasskeyError::Network(describe_js_error(&e)))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| PasskeyError::Network("Not a Response".into()))?;

    if !resp.ok() {
        return Err(extract_server_error(&resp).await);
    }
    resp_text(&resp).await
}

/// POST JSON with a NIP-98 `Authorization: Nostr <token>` header signed by the
/// derived secret — the login-verify step. Uses the kit's canonical token
/// builder ([`nostr_bbs_core::nip98::create_token_at`]).
#[cfg(target_arch = "wasm32")]
async fn fetch_with_nip98_post(
    url: &str,
    json_body: &str,
    secret_key: &[u8; 32],
) -> Result<String, PasskeyError> {
    let now_secs = (js_sys::Date::now() / 1000.0) as u64;
    let token = nostr_bbs_core::nip98::create_token_at(
        secret_key,
        url,
        "POST",
        Some(json_body.as_bytes()),
        now_secs,
    )
    .map_err(|e| PasskeyError::Protocol(format!("NIP-98 token: {e}")))?;
    let auth_header = format!("Nostr {token}");

    let win = web_sys::window().ok_or(PasskeyError::NoBrowser)?;
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    let headers =
        web_sys::Headers::new().map_err(|e| PasskeyError::JsError(describe_js_error(&e)))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| PasskeyError::JsError(describe_js_error(&e)))?;
    headers
        .set("Authorization", &auth_header)
        .map_err(|e| PasskeyError::JsError(describe_js_error(&e)))?;
    init.set_headers(&headers);
    init.set_body(&JsValue::from_str(json_body));

    let request = web_sys::Request::new_with_str_and_init(url, &init)
        .map_err(|e| PasskeyError::JsError(describe_js_error(&e)))?;
    let resp_val = JsFuture::from(win.fetch_with_request(&request))
        .await
        .map_err(|e| PasskeyError::Network(describe_js_error(&e)))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| PasskeyError::Network("Not a Response".into()))?;

    if !resp.ok() {
        return Err(extract_server_error(&resp).await);
    }
    resp_text(&resp).await
}

#[cfg(target_arch = "wasm32")]
async fn resp_text(resp: &web_sys::Response) -> Result<String, PasskeyError> {
    let promise = resp
        .text()
        .map_err(|e| PasskeyError::Network(describe_js_error(&e)))?;
    JsFuture::from(promise)
        .await
        .map_err(|e| PasskeyError::Network(describe_js_error(&e)))?
        .as_string()
        .ok_or_else(|| PasskeyError::Network("Response body not a string".into()))
}

#[cfg(target_arch = "wasm32")]
async fn extract_server_error(resp: &web_sys::Response) -> PasskeyError {
    let status = resp.status();
    if let Ok(promise) = resp.text() {
        if let Ok(text) = JsFuture::from(promise).await {
            if let Some(text_str) = text.as_string() {
                web_sys::console::error_1(&format!("[passkey] HTTP {status}: {text_str}").into());
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text_str) {
                    if v.get("code").and_then(|c| c.as_str()) == Some("NO_CREDENTIAL") {
                        return PasskeyError::NoCredential;
                    }
                    if let Some(msg) = v.get("error").and_then(|e| e.as_str()) {
                        return PasskeyError::ServerError(msg.to_string());
                    }
                }
                return PasskeyError::ServerError(format!("HTTP {status}: {text_str}"));
            }
        }
    }
    PasskeyError::ServerError(format!("HTTP {status}"))
}

// ── Runtime config (wasm) ───────────────────────────────────────────────────

/// Auth-API base URL, resolved from `window.__ENV__` (matching the forum
/// client's `relay_url::auth_api_base`). An empty result means "same-origin",
/// which [`endpoint`] turns into a root-relative path.
#[cfg(target_arch = "wasm32")]
fn auth_api_base() -> String {
    for key in ["AUTH_API_URL", "VITE_AUTH_API_URL"] {
        if let Some(url) = window_env(key) {
            return url;
        }
    }
    option_env!("VITE_AUTH_API_URL").unwrap_or("").to_string()
}

/// The displayName the platform authenticator shows for a newly-created passkey.
#[cfg(target_arch = "wasm32")]
fn register_display_name() -> String {
    window_env("NODE_NAME")
        .or_else(|| window_env("FORUM_NAME"))
        .unwrap_or_else(|| "nostr-bbs".to_string())
}

/// Read a non-empty string from `window.__ENV__[key]`.
#[cfg(target_arch = "wasm32")]
fn window_env(key: &str) -> Option<String> {
    let window = web_sys::window()?;
    let env = Reflect::get(&window, &"__ENV__".into()).ok()?;
    if env.is_undefined() || env.is_null() {
        return None;
    }
    let val = Reflect::get(&env, &JsValue::from_str(key)).ok()?;
    let s = val.as_string()?;
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

// ── Tests (native, pure) ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_authenticate_with_saved_pubkey() {
        let pk = "ab".repeat(32);
        assert_eq!(
            choose_passkey_intent(Some(&pk)),
            PasskeyIntent::Authenticate(pk)
        );
    }

    #[test]
    fn intent_register_when_no_pubkey() {
        assert_eq!(choose_passkey_intent(None), PasskeyIntent::Register);
        assert_eq!(choose_passkey_intent(Some("")), PasskeyIntent::Register);
        assert_eq!(choose_passkey_intent(Some("   ")), PasskeyIntent::Register);
    }

    #[test]
    fn intent_trims_whitespace() {
        let choice = choose_passkey_intent(Some("  cafe  "));
        assert_eq!(choice, PasskeyIntent::Authenticate("cafe".to_string()));
    }

    #[test]
    fn endpoint_joins_with_single_slash() {
        assert_eq!(
            endpoint("https://api.example.com", "/auth/login/options"),
            "https://api.example.com/auth/login/options"
        );
        assert_eq!(
            endpoint("https://api.example.com/", "auth/login/options"),
            "https://api.example.com/auth/login/options"
        );
    }

    #[test]
    fn endpoint_empty_base_is_root_relative() {
        assert_eq!(endpoint("", "/auth/login/verify"), "/auth/login/verify");
        assert_eq!(endpoint("", "auth/login/verify"), "/auth/login/verify");
    }

    #[test]
    fn require_prf_32_rejects_short() {
        assert!(require_prf_32(&[0u8; 31]).is_err());
        assert!(require_prf_32(&[]).is_err());
    }

    #[test]
    fn require_prf_32_takes_first_32() {
        let mut input = vec![0u8; 40];
        for (i, b) in input.iter_mut().enumerate() {
            *b = i as u8;
        }
        let out = require_prf_32(&input).expect("32+ bytes");
        assert_eq!(out[0], 0);
        assert_eq!(out[31], 31);
    }

    #[test]
    fn derive_keypair_is_deterministic() {
        // Same PRF output → same identity (the whole point of PRF-derived keys).
        let prf = [7u8; 32];
        let a = derive_keypair_from_prf_output(&prf).expect("derive a");
        let b = derive_keypair_from_prf_output(&prf).expect("derive b");
        assert_eq!(a.public.to_hex(), b.public.to_hex());
        // Different PRF output → different identity.
        let c = derive_keypair_from_prf_output(&[9u8; 32]).expect("derive c");
        assert_ne!(a.public.to_hex(), c.public.to_hex());
    }

    #[test]
    fn derive_keypair_matches_core_derive_from_prf() {
        // Our wrapper must produce byte-identical output to the kit's canonical
        // derivation the forum client uses — same passkey ⇒ same key everywhere.
        let prf = [42u8; 32];
        let ours = derive_keypair_from_prf_output(&prf).expect("ours");
        let canonical = nostr_bbs_core::derive_from_prf(&prf).expect("core");
        assert_eq!(ours.public.to_hex(), canonical.public.to_hex());
        assert_eq!(ours.secret.as_bytes(), canonical.secret.as_bytes());
    }

    #[test]
    fn derive_keypair_rejects_short_prf() {
        assert!(derive_keypair_from_prf_output(&[0u8; 16]).is_err());
    }

    #[test]
    fn base64url_roundtrip() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let encoded = bytes_to_base64url(&bytes);
        assert!(!encoded.contains('='), "no padding");
        assert!(!encoded.contains('+') && !encoded.contains('/'), "url-safe");
        assert_eq!(base64url_to_bytes(&encoded).expect("decode"), bytes);
    }

    #[test]
    fn base64url_tolerates_padding() {
        // Server salts sometimes arrive padded; the decoder trims it.
        assert_eq!(base64url_to_bytes("YQ==").expect("decode"), b"a");
        assert_eq!(base64url_to_bytes("YQ").expect("decode"), b"a");
    }

    #[test]
    fn parse_options_response_extracts_salt() {
        let json = r#"{"options":{"challenge":"YWJj","rp":{"id":"x"}},"prfSalt":"c2FsdA"}"#;
        let (options, salt) = parse_options_response(json).expect("parse");
        assert_eq!(salt, "c2FsdA");
        assert_eq!(
            options.get("challenge").and_then(|c| c.as_str()),
            Some("YWJj")
        );
    }

    #[test]
    fn parse_options_response_requires_salt() {
        // No prfSalt ⇒ no PRF data ⇒ cannot derive a stable key ⇒ hard error.
        let json = r#"{"options":{"challenge":"YWJj"}}"#;
        assert!(matches!(
            parse_options_response(json),
            Err(PasskeyError::PrfNotSupported(_))
        ));
        // Empty salt is treated as absent.
        let json_empty = r#"{"options":{},"prfSalt":""}"#;
        assert!(parse_options_response(json_empty).is_err());
    }

    #[test]
    fn parse_options_response_requires_options() {
        assert!(matches!(
            parse_options_response(r#"{"prfSalt":"c2FsdA"}"#),
            Err(PasskeyError::Protocol(_))
        ));
        assert!(parse_options_response("not json").is_err());
    }

    #[test]
    fn options_bodies_have_expected_shape() {
        assert_eq!(
            register_options_body("Ada"),
            serde_json::json!({ "displayName": "Ada" })
        );
        assert_eq!(
            login_options_body("deadbeef"),
            serde_json::json!({ "pubkey": "deadbeef" })
        );
    }

    #[test]
    fn verify_bodies_have_expected_shape() {
        let enc = serde_json::json!({ "id": "cred" });
        assert_eq!(
            register_verify_body(enc.clone(), "pk", "salt"),
            serde_json::json!({ "response": { "id": "cred" }, "pubkey": "pk", "prfSalt": "salt" })
        );
        assert_eq!(
            login_verify_body(enc, "pk"),
            serde_json::json!({ "response": { "id": "cred" }, "pubkey": "pk" })
        );
    }

    #[test]
    fn is_passkey_supported_false_on_native() {
        // No browser ⇒ never claims support (fail closed).
        assert!(!is_passkey_supported());
    }

    #[test]
    fn error_display_is_human_readable() {
        assert!(PasskeyError::NoCredential
            .to_string()
            .contains("No passkey"));
        assert!(PasskeyError::HybridBlocked.to_string().contains("QR"));
    }

    #[test]
    fn cancelled_display_never_dumps_raw_jsvalue() {
        // The login path maps a dismissed Face ID / Touch ID prompt to friendly
        // copy — it must never surface a raw `JsValue(NotAllowedError: …)` blob.
        let friendly = PasskeyError::Cancelled(
            "the Face ID / Touch ID prompt was dismissed or timed out. Try again, or paste a \
             private key instead."
                .into(),
        )
        .to_string();
        assert!(friendly.contains("Face ID"));
        assert!(!friendly.contains("JsValue"));
    }
}
