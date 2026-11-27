//! Delivery to the public relays the chain's producer follows (SPEC 11): a
//! kind-23500 transaction or a kind-23501 faucet request, one short-lived
//! WebSocket per relay, `["EVENT", …]`, and the relay's `OK` for that id
//! within a timeout. The forum's own `RelayConnection` is bound to the
//! forum relay and its NIP-42 session; these relays are someone else's, so
//! the wallet opens its own sockets and closes them when answered.

use std::cell::RefCell;
use std::rc::Rc;

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{MessageEvent, WebSocket};

/// How long one relay has to answer.
const TIMEOUT_MS: i32 = 8_000;

/// What one relay said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `OK` true.
    Accepted,
    /// `OK` false, with the relay's reason.
    Refused(String),
    /// No answer in time, or the socket failed.
    NoAnswer,
}

/// Open the socket to one relay and send the event now; the promise
/// settles with the relay's verdict. Synchronous, so several relays are
/// asked at once before any answer is awaited.
fn start(url: &str, event_json: &str, event_id: &str) -> Promise {
    let frame = format!("[\"EVENT\",{event_json}]");
    let id = event_id.to_string();
    let url = url.to_string();
    Promise::new(&mut |resolve, _reject| {
        let resolve = Rc::new(resolve);
        let done = Rc::new(RefCell::new(false));
        let settle = {
            let resolve = resolve.clone();
            let done = done.clone();
            move |v: JsValue| {
                if !*done.borrow() {
                    *done.borrow_mut() = true;
                    let _ = resolve.call1(&JsValue::NULL, &v);
                }
            }
        };
        let ws = match WebSocket::new(&url) {
            Ok(ws) => ws,
            Err(_) => {
                settle(JsValue::from_str("noanswer"));
                return;
            }
        };
        let ws_open = ws.clone();
        let frame_c = frame.clone();
        let on_open = Closure::<dyn FnMut()>::new(move || {
            let _ = ws_open.send_with_str(&frame_c);
        });
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        on_open.forget();

        let settle_msg = settle.clone();
        let ws_msg = ws.clone();
        let id_c = id.clone();
        let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
            let Some(text) = e.data().as_string() else {
                return;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
                return;
            };
            let a = v.as_array();
            if a.and_then(|a| a.first()).and_then(|x| x.as_str()) == Some("OK")
                && a.and_then(|a| a.get(1)).and_then(|x| x.as_str()) == Some(id_c.as_str())
            {
                let ok = a.and_then(|a| a.get(2)).and_then(|x| x.as_bool()) == Some(true);
                let why = a
                    .and_then(|a| a.get(3))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                settle_msg(JsValue::from_str(&if ok {
                    "ok".to_string()
                } else {
                    format!("no:{why}")
                }));
                let _ = ws_msg.close();
            }
        });
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        on_message.forget();

        let settle_err = settle.clone();
        let on_error =
            Closure::<dyn FnMut()>::new(move || settle_err(JsValue::from_str("noanswer")));
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));
        on_error.forget();

        let settle_time = settle.clone();
        let ws_time = ws.clone();
        let on_timeout = Closure::<dyn FnMut()>::new(move || {
            settle_time(JsValue::from_str("noanswer"));
            let _ = ws_time.close();
        });
        if let Some(w) = web_sys::window() {
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(
                on_timeout.as_ref().unchecked_ref(),
                TIMEOUT_MS,
            );
        }
        on_timeout.forget();
    })
}

async fn verdict(promise: Promise) -> Outcome {
    match JsFuture::from(promise)
        .await
        .ok()
        .and_then(|v| v.as_string())
    {
        Some(s) if s == "ok" => Outcome::Accepted,
        Some(s) if s.starts_with("no:") => Outcome::Refused(s[3..].to_string()),
        _ => Outcome::NoAnswer,
    }
}

/// Publish to every relay at once; how many accepted, and each verdict.
pub async fn publish_all(
    relays: &[String],
    event_json: &str,
    event_id: &str,
) -> (usize, Vec<(String, Outcome)>) {
    let started: Vec<(String, Promise)> = relays
        .iter()
        .map(|r| (r.clone(), start(r, event_json, event_id)))
        .collect();
    let mut results = Vec::with_capacity(started.len());
    for (r, p) in started {
        results.push((r, verdict(p).await));
    }
    let ok = results
        .iter()
        .filter(|(_, o)| *o == Outcome::Accepted)
        .count();
    (ok, results)
}
