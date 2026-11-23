//! Loads a channel's older history on demand, for list views whose oldest
//! entries sit at the END (the section topic list) or wherever a page wants
//! a "load older" control.
//!
//! Renders the paging state (`data-history-state` = `more` / `loading` /
//! `start`), a "Load older" button, and an invisible sentinel. While the
//! sentinel is in the viewport, pages keep loading one after another
//! ([`ChannelStore::load_older`]) until the relay reports the start of
//! history, so scrolling to the end of the list is enough.
//!
//! It also records the channel's first page from its `ensure_subscribed`
//! REQ ([`ChannelStore::settle_first_page`]) once that answer counts, which
//! is what starts the cursor.

use leptos::prelude::*;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::relay::RelayConnection;
use crate::stores::channels::ChannelStore;

/// See the module docs. `channel_id` is the id `ensure_subscribed` was
/// called with; `gated` is whether its zone withholds history before AUTH.
#[component]
pub fn HistoryLoader(
    channel_id: Signal<Option<String>>,
    gated: Signal<bool>,
    #[prop(into)] older_label: String,
) -> impl IntoView {
    let store = expect_context::<ChannelStore>();
    let relay = expect_context::<RelayConnection>();
    let sentinel = NodeRef::<leptos::html::Div>::new();
    let visible = RwSignal::new(false);

    // Start the cursor once the first page's answer counts.
    Effect::new(move |_| {
        let Some(cid) = channel_id.get() else {
            return;
        };
        let g = gated.get();
        if store.history_receipt(&cid).settles(g) {
            store.settle_first_page(&cid, g);
        }
    });

    let request = {
        let relay = relay.clone();
        move || {
            if let Some(cid) = channel_id.get_untracked() {
                store.load_older(
                    &relay,
                    &cid,
                    vec![cid.clone()],
                    gated.get_untracked(),
                    Rc::new(|| {}),
                );
            }
        }
    };
    let request = StoredValue::new_local(Rc::new(request) as Rc<dyn Fn()>);

    // Keep paging while the sentinel is on screen: re-runs on every cursor
    // change (a page landed) and on visibility changes.
    Effect::new(move |_| {
        let Some(cid) = channel_id.get() else {
            return;
        };
        let cursor = store.history_cursor(&cid);
        if visible.get() && cursor.next_request().is_some() {
            request.with_value(|f| f());
        }
    });

    // Observe the sentinel.
    Effect::new(move |_| {
        let Some(el) = sentinel.get() else {
            return;
        };
        let callback = Closure::wrap(Box::new(
            move |entries: js_sys::Array, _observer: web_sys::IntersectionObserver| {
                if let Some(entry) = entries
                    .get(entries.length().saturating_sub(1))
                    .dyn_ref::<web_sys::IntersectionObserverEntry>()
                {
                    let _ = visible.try_set(entry.is_intersecting());
                }
            },
        )
            as Box<dyn FnMut(js_sys::Array, web_sys::IntersectionObserver)>);
        let opts = web_sys::IntersectionObserverInit::new();
        opts.set_root_margin("600px 0px");
        if let Ok(observer) = web_sys::IntersectionObserver::new_with_options(
            callback.as_ref().unchecked_ref(),
            &opts,
        ) {
            let target: &web_sys::Element = &el;
            observer.observe(target);
            let observer = send_wrapper::SendWrapper::new(observer);
            let callback = send_wrapper::SendWrapper::new(callback);
            on_cleanup(move || {
                observer.disconnect();
                drop(callback);
            });
        }
    });

    let state = Signal::derive(move || channel_id.get().map(|cid| store.history_cursor(&cid)));
    let older_label = StoredValue::new(older_label);

    view! {
        <div
            class="flex justify-center py-3 text-xs text-gray-500"
            data-history-state=move || match state.get() {
                Some(c) if c.exhausted => "start",
                Some(c) if c.loading => "loading",
                Some(c) if c.started => "more",
                _ => "pending",
            }
        >
            {move || match state.get() {
                Some(c) if c.exhausted => view! { <span>"Start of history"</span> }.into_any(),
                Some(c) if c.loading => view! { <span>"Loading older\u{2026}"</span> }.into_any(),
                Some(c) if c.started => view! {
                    <button
                        class="text-xs text-gray-400 hover:text-gray-200 underline"
                        on:click=move |_| request.with_value(|f| f())
                    >
                        {older_label.get_value()}
                    </button>
                }.into_any(),
                _ => ().into_any(),
            }}
            <div node_ref=sentinel class="h-px w-px"></div>
        </div>
    }
}
