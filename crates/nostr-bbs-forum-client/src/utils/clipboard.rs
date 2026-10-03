//! The forum's one clipboard writer.
//!
//! Every copy affordance in the client goes through [`write_text`] (awaitable,
//! reports success) or [`copy_text`] (fire-and-forget). Before this module the
//! client carried half a dozen inline copies of the same logic, most of them
//! calling `navigator.clipboard.writeText` through web-sys directly. That
//! binding is not `catch`-annotated: where `navigator.clipboard` is absent (an
//! insecure `http://` origin, an embedded webview, an older browser) the call
//! throws through WASM and aborts the click handler. Here the API is reached
//! through `Reflect` so a missing capability is an ordinary `false`, and a
//! hidden-textarea `execCommand("copy")` covers the gap.

use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

/// Write `text` to the system clipboard. Resolves to `true` when one of the
/// two strategies reported success:
///
/// 1. the async Clipboard API (`navigator.clipboard.writeText`), awaited so a
///    permission rejection is seen as a failure rather than assumed a success;
/// 2. a hidden `<textarea>` plus `document.execCommand("copy")`, for contexts
///    without the async API (or where it rejected).
pub async fn write_text(text: &str) -> bool {
    if write_via_async_api(text).await {
        return true;
    }
    write_via_exec_command(text)
}

/// Fire-and-forget [`write_text`], for affordances that confirm the copy some
/// other way (a toast, a button label) and do not need the outcome.
pub fn copy_text(text: &str) {
    copy_text_then(text, |_| {});
}

/// [`write_text`] in a spawned task, handing the outcome to `then`.
pub fn copy_text_then<F: FnOnce(bool) + 'static>(text: &str, then: F) {
    let text = text.to_string();
    wasm_bindgen_futures::spawn_local(async move {
        then(write_text(&text).await);
    });
}

async fn write_via_async_api(text: &str) -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    let nav = window.navigator();
    let Ok(clipboard) = js_sys::Reflect::get(&nav, &"clipboard".into()) else {
        return false;
    };
    if clipboard.is_undefined() || clipboard.is_null() {
        return false;
    }
    let Ok(write_fn) = js_sys::Reflect::get(&clipboard, &"writeText".into()) else {
        return false;
    };
    let Ok(func) = write_fn.dyn_into::<js_sys::Function>() else {
        return false;
    };
    let Ok(ret) = func.call1(&clipboard, &JsValue::from_str(text)) else {
        return false;
    };
    match ret.dyn_into::<js_sys::Promise>() {
        Ok(promise) => JsFuture::from(promise).await.is_ok(),
        // A non-promise return is a non-standard shim that completed
        // synchronously without throwing.
        Err(_) => true,
    }
}

fn write_via_exec_command(text: &str) -> bool {
    let Some(document) = web_sys::window().and_then(|w| w.document()) else {
        return false;
    };
    let Some(body) = document.body() else {
        return false;
    };
    let Ok(textarea) = document
        .create_element("textarea")
        .map(|el| el.unchecked_into::<web_sys::HtmlTextAreaElement>())
    else {
        return false;
    };
    textarea.set_value(text);
    let _ = textarea.set_attribute("readonly", "");
    let _ = textarea.set_attribute("aria-hidden", "true");
    let _ = textarea.set_attribute(
        "style",
        "position:fixed;top:-1000px;left:-1000px;opacity:0;pointer-events:none",
    );
    if body.append_child(&textarea).is_err() {
        return false;
    }
    textarea.select();
    let copied = document
        .dyn_ref::<web_sys::HtmlDocument>()
        .and_then(|d| d.exec_command("copy").ok())
        .unwrap_or(false);
    textarea.remove();
    copied
}

/// Message shown when a toast-confirmed copy fails.
pub const COPY_FAILED_TOAST: &str = "Copy failed — your browser blocked clipboard access";

/// Copy `text` and confirm with a toast: `ok_message` (as `ok_variant`) when
/// the write succeeded, [`COPY_FAILED_TOAST`] as an error when it did not.
pub fn copy_with_toast(
    text: &str,
    ok_message: impl Into<String>,
    ok_variant: crate::components::toast::ToastVariant,
    toasts: crate::components::toast::ToastStore,
) {
    let ok_message = ok_message.into();
    copy_text_then(text, move |ok| {
        if ok {
            toasts.show(ok_message, ok_variant);
        } else {
            toasts.show(
                COPY_FAILED_TOAST,
                crate::components::toast::ToastVariant::Error,
            );
        }
    });
}
