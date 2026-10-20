//! The one-time confirmation before a member's browser first connects to
//! relays a stranger chose (ADR-2027 decision 1).
//!
//! Replying to a non-member opens sockets from the member's browser straight to
//! relays that person named, so those operators see the member's IP address and
//! connection time. The member is asked once per recipient; the acceptance is
//! remembered in IndexedDB. Nothing foreign opens before it: the publish path
//! asks first ([`super::delivery::release_steps`] withholds the foreign steps).
//!
//! The prompt is state ([`ConsentRequest`] on the store) plus the
//! [`ConsentPrompt`] component, which a page mounts once. With no prompt mounted
//! nobody answers, and the request times out as a refusal: it fails closed.

use std::cell::RefCell;
use std::rc::Rc;

use leptos::prelude::*;

use super::delivery::CONSENT_TEXT;
use super::DMStore;
use crate::relay::OneShot;

/// How long the member has to answer before it counts as "Cancel".
pub const ANSWER_TIMEOUT_MS: i32 = 120_000;

/// A pending question: may we connect to these relays for this recipient?
///
/// Plain data, so it can live in the reactive store; the channel that carries
/// the answer is kept apart ([`begin`], [`answer`]) because it is not `Send`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentRequest {
    /// Lowercase hex of the person being replied to.
    pub recipient: String,
    /// Host names of the relays they chose, shown under the text.
    pub hosts: Vec<String>,
}

thread_local! {
    /// Where the answer to the open question goes.
    static ANSWER: RefCell<Option<Rc<OneShot<bool>>>> = const { RefCell::new(None) };
}

/// Open a question and return the slot its answer will arrive in.
pub(super) fn begin() -> Rc<OneShot<bool>> {
    let slot = OneShot::new();
    ANSWER.with(|a| *a.borrow_mut() = Some(slot.clone()));
    slot
}

/// Deliver the member's answer to the open question, if there is one.
pub(super) fn answer(accept: bool) {
    if let Some(slot) = ANSWER.with(|a| a.borrow_mut().take()) {
        slot.fill(accept);
    }
}

/// IndexedDB key for "`me` accepted foreign relays for `recipient`".
pub fn accepted_id(me: &str, recipient: &str) -> String {
    format!("dm-foreign-consent/v1/{me}/{recipient}")
}

/// Whether `me` has already accepted for `recipient`.
pub async fn is_accepted(me: &str, recipient: &str) -> bool {
    let id = accepted_id(me, recipient);
    match crate::stores::indexed_db::ForumDb::open().await {
        Ok(db) => db.get_zone_kv(&id).await.ok().flatten().is_some(),
        Err(_) => false,
    }
}

/// Remember the acceptance. A storage failure only means being asked again.
pub async fn remember(me: &str, recipient: &str) {
    let id = accepted_id(me, recipient);
    if let Ok(db) = crate::stores::indexed_db::ForumDb::open().await {
        let _ = db.put_zone_kv(&id, "1").await;
    }
}

/// The confirmation dialog. Mount once on the DM screen; it shows itself when
/// a send needs the member's agreement.
// Mounted by the DM page (not yet wired; pages/dm_chat.rs is outside this phase).
#[allow(dead_code)]
#[component]
pub fn ConsentPrompt(store: DMStore) -> impl IntoView {
    let pending = store.pending_consent();
    view! {
        <Show when=move || pending.get().is_some()>
            {move || pending.get().map(|req| {
                let hosts = req.hosts.clone();
                view! {
                    <div role="alertdialog" aria-modal="true"
                         class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
                        <div class="max-w-md rounded-lg bg-gray-900 p-5 text-sm text-gray-100 shadow-xl">
                            <p>{CONSENT_TEXT}</p>
                            <ul class="mt-3 list-disc pl-5 font-mono text-xs text-amber-300">
                                {hosts.into_iter().map(|h| view! { <li>{h}</li> }).collect_view()}
                            </ul>
                            <div class="mt-4 flex justify-end gap-2">
                                <button class="rounded px-3 py-1.5 hover:bg-gray-800"
                                        on:click=move |_| store.answer_consent(false)>"Cancel"</button>
                                <button class="rounded bg-amber-500 px-3 py-1.5 text-black"
                                        on:click=move |_| store.answer_consent(true)>"Send anyway"</button>
                            </div>
                        </div>
                    </div>
                }
            })}
        </Show>
    }
}
