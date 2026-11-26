//! Spending through a browser signer: `window.nostr.sidestr.signTransaction`
//! (sidestr spec `proposals/browser-signer.md`; reference signer Podkey).
//!
//! A member signed in with an extension has no key in this tab. When the
//! extension offers the method, the wallet builds the spend unsigned
//! ([`sidestr_wallet::external::ExternalSigner`]), hands the extension the
//! bare transaction, and takes back only the same transaction with every
//! input validly signed ([`sidestr_wallet::external::accept_signed`]). The
//! extension resolves the chain itself, shows the member what the spend
//! does and asks every time; this tab never sees the key.

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

/// The version of the method this client speaks.
pub const VERSION: f64 = 1.0;

/// Why the extension did not sign, as it said: its `code` (spec: `rejected`,
/// `unsupported`, `not-yours`, `invalid`, `unavailable`) and its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The error's `code`, when it gave one.
    pub code: Option<String>,
    /// The error's message.
    pub message: String,
}

fn provider() -> Option<wasm_bindgen::JsValue> {
    let window = web_sys::window()?;
    let nostr = js_sys::Reflect::get(&window, &"nostr".into()).ok()?;
    if nostr.is_undefined() || nostr.is_null() {
        return None;
    }
    let sidestr = js_sys::Reflect::get(&nostr, &"sidestr".into()).ok()?;
    if sidestr.is_undefined() || sidestr.is_null() {
        return None;
    }
    let version = js_sys::Reflect::get(&sidestr, &"version".into())
        .ok()?
        .as_f64()?;
    let sign = js_sys::Reflect::get(&sidestr, &"signTransaction".into()).ok()?;
    (version >= VERSION && sign.is_function()).then_some(sidestr)
}

/// Whether the browser has a signer that can sign sidestr spends.
pub fn available() -> bool {
    provider().is_some()
}

/// Whether the signer says sidechain spends are turned on
/// (`window.nostr.sidestr.enabled`). A signer that predates the field is
/// taken as on. When off, a spend still works: the signer's first request
/// asks the member to turn spends on, in its own window.
pub fn enabled() -> bool {
    provider()
        .and_then(|s| js_sys::Reflect::get(&s, &"enabled".into()).ok())
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

/// What to call the signer in a sentence: the name it gives itself
/// (`window.nostr.sidestr.name`, e.g. "Podkey"; `window.nostr.name` for
/// others), else "Your extension".
pub fn name() -> String {
    let nostr = web_sys::window().and_then(|w| js_sys::Reflect::get(&w, &"nostr".into()).ok());
    let text = |v: wasm_bindgen::JsValue| v.as_string();
    provider()
        .and_then(|s| js_sys::Reflect::get(&s, &"name".into()).ok())
        .and_then(text)
        .or_else(|| {
            nostr
                .and_then(|n| js_sys::Reflect::get(&n, &"name".into()).ok())
                .and_then(text)
        })
        .map(|s| s.trim().chars().take(32).collect::<String>())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Your extension".into())
}

/// Ask the extension to sign `unsigned_hex` on `chain`; its answer, the
/// signed transaction as hex, unchecked (the caller checks it).
pub async fn sign(chain: &str, unsigned_hex: &str) -> Result<String, Refusal> {
    let plain = |m: &str| Refusal {
        code: Some("unavailable".into()),
        message: m.into(),
    };
    let sidestr = provider().ok_or_else(|| plain("no browser signer"))?;
    let f: js_sys::Function = js_sys::Reflect::get(&sidestr, &"signTransaction".into())
        .map_err(|_| plain("no signTransaction"))?
        .dyn_into()
        .map_err(|_| plain("signTransaction is not a function"))?;
    let req = js_sys::Object::new();
    js_sys::Reflect::set(&req, &"chain".into(), &chain.into()).map_err(|_| plain("request"))?;
    js_sys::Reflect::set(&req, &"tx".into(), &unsigned_hex.into()).map_err(|_| plain("request"))?;
    let promise: js_sys::Promise = f
        .call1(&sidestr, &req)
        .map_err(refusal_of)?
        .dyn_into()
        .map_err(|_| plain("signTransaction did not return a promise"))?;
    let answer = JsFuture::from(promise).await.map_err(refusal_of)?;
    js_sys::Reflect::get(&answer, &"tx".into())
        .ok()
        .and_then(|v| v.as_string())
        .ok_or_else(|| Refusal {
            code: Some("invalid".into()),
            message: "the signer's answer carries no tx".into(),
        })
}

fn refusal_of(e: wasm_bindgen::JsValue) -> Refusal {
    let get = |k: &str| {
        js_sys::Reflect::get(&e, &k.into())
            .ok()
            .and_then(|v| v.as_string())
    };
    Refusal {
        code: get("code"),
        message: get("message").or_else(|| e.as_string()).unwrap_or_default(),
    }
}

/// What the member will see next, before they continue in the extension:
/// with spends off, the extension first asks to turn them on.
pub fn review_hint(signer: &str, what: &str) -> String {
    hint_for(signer, what, enabled())
}

fn hint_for(signer: &str, what: &str, enabled: bool) -> String {
    if enabled {
        format!("{signer} will show you {what} and ask you to confirm.")
    } else {
        format!(
            "{signer} will ask you to turn on sidechain spends, then show you {what} to confirm."
        )
    }
}

/// The extension's refusal in words a member can act on. `rejected` is the
/// member saying no, so it reads as that rather than as a failure.
pub fn explain(r: &Refusal) -> String {
    match r.code.as_deref() {
        Some("rejected") => "You declined the spend in your extension. Nothing was sent.".into(),
        Some("not-yours") => "Your extension will only spend coins it can see are its own, and it could not find these under its key. Check that the extension holds the key you signed in with here, and wait for recent transfers to confirm.".into(),
        Some("unsupported") => "Your extension did not take this spend: sidechain spends may be turned off there. In Podkey, turn them on when it asks, or in its settings. Nothing was sent.".into(),
        Some("invalid") => "Your extension could not read this transfer. Nothing was sent; try again.".into(),
        Some("unavailable") => {
            "Your extension is locked or could not read the chain. Unlock it and try again.".into()
        }
        _ if r.message.is_empty() => "Your extension did not sign. Nothing was sent.".into(),
        _ => format!("Your extension did not sign: {}. Nothing was sent.", r.message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(code: Option<&str>, message: &str) -> Refusal {
        Refusal {
            code: code.map(str::to_string),
            message: message.into(),
        }
    }

    #[test]
    fn every_spec_code_reads_as_something_to_do() {
        for code in [
            "rejected",
            "not-yours",
            "unsupported",
            "invalid",
            "unavailable",
        ] {
            let text = explain(&r(Some(code), "internal detail"));
            assert!(!text.contains("internal detail"), "{code}: {text}");
            assert!(text.ends_with('.'), "{code}: {text}");
        }
        assert!(explain(&r(Some("rejected"), "")).starts_with("You declined"));
    }

    #[test]
    fn the_hint_says_when_spends_must_be_turned_on_first() {
        assert_eq!(
            hint_for("Podkey", "this spend", true),
            "Podkey will show you this spend and ask you to confirm."
        );
        assert!(hint_for("Podkey", "each tip", false)
            .starts_with("Podkey will ask you to turn on sidechain spends"));
        assert!(explain(&r(Some("unsupported"), "")).contains("turn them on"));
    }

    #[test]
    fn an_unknown_refusal_says_what_the_extension_said() {
        assert!(explain(&r(None, "boom")).contains("boom"));
        assert!(explain(&r(Some("other"), "")).contains("did not sign"));
    }
}
