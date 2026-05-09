//! Cloudflare D1 helpers shared by worker crates.
//!
//! Both `nostr-bbs-auth-worker` and `nostr-bbs-relay-worker` frequently need
//! to convert Rust values into `JsValue` for D1 bind parameters. These tiny
//! helpers were duplicated 8+ times across the two crates. Centralising them
//! here eliminates that duplication without adding any new dependencies (core
//! already depends on `wasm-bindgen` for the wasm32 target).

use wasm_bindgen::JsValue;

/// Convert a `&str` to a `JsValue::from_str`.
#[inline]
pub fn js_str(s: &str) -> JsValue {
    JsValue::from_str(s)
}

/// Convert an `Option<&str>` to a `JsValue`, mapping `None` to `JsValue::NULL`.
#[inline]
pub fn js_opt_str(s: Option<&str>) -> JsValue {
    match s {
        Some(v) => JsValue::from_str(v),
        None => JsValue::NULL,
    }
}

/// Convert an `f64` to a `JsValue::from_f64`.
#[inline]
pub fn js_f64(v: f64) -> JsValue {
    JsValue::from_f64(v)
}

/// Convert an `i64` to a `JsValue::from_f64` (JS numbers are always f64).
#[inline]
pub fn js_i64(v: i64) -> JsValue {
    JsValue::from_f64(v as f64)
}

/// Convert an `Option<i64>` to a `JsValue`, mapping `None` to `JsValue::NULL`.
#[inline]
pub fn js_opt_i64(v: Option<i64>) -> JsValue {
    match v {
        Some(x) => JsValue::from_f64(x as f64),
        None => JsValue::NULL,
    }
}
