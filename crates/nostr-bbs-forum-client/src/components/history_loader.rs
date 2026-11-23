//! Loads a channel's history on demand at one end of a list view: older
//! pages, or (once the window has evicted them) newer ones.
//!
//! Renders the paging state (`data-history-state` = `more` / `loading` /
//! `start` for older history, `newer` / `loading` for newer), a control, and
//! an invisible sentinel. While the sentinel is in the viewport, pages keep
//! loading one after another ([`ChannelStore::load_older`] /
//! [`ChannelStore::load_newer`]) until the relay reports the start of
//! history, or until the window holds the newest messages again. Each page
//! keeps the reader's place through [`scroll_anchor`] (rows carry
//! `data-anchor-id`; the list scrolls with the window).
//!
//! The older loader also records the channel's first page from its
//! `ensure_subscribed` REQ ([`ChannelStore::settle_first_page`]) once that
//! answer counts, which is what starts the cursor.

use leptos::prelude::*;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::relay::RelayConnection;
use crate::stores::channels::ChannelStore;
use crate::utils::scroll_anchor;

/// Which history a [`HistoryLoader`] fetches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum HistoryDirection {
    /// Older pages, back to the start of the channel.
    #[default]
    Older,
    /// Evicted newer pages, back to the newest message. Renders nothing
    /// while the window already holds the newest messages.
    Newer,
}

/// See the module docs. `channel_id` is the id `ensure_subscribed` was
/// called with; `gated` is whether its zone withholds history before AUTH.
#[component]
pub fn HistoryLoader(
    channel_id: Signal<Option<String>>,
    gated: Signal<bool>,
    #[prop(into)] label: String,
    #[prop(optional)] direction: HistoryDirection,
) -> impl IntoView {
    let store = expect_context::<ChannelStore>();
    let relay = expect_context::<RelayConnection>();
    let sentinel = NodeRef::<leptos::html::Div>::new();
    let visible = RwSignal::new(false);
    let anchor = StoredValue::new_local(None::<scroll_anchor::Anchor>);

    // Start the cursor once the first page's answer counts.
    if direction == HistoryDirection::Older {
        Effect::new(move |_| {
            let Some(cid) = channel_id.get() else {
                return;
            };
            let g = gated.get();
            if store.history_receipt(&cid).settles(g) {
                store.settle_first_page(&cid, g);
            }
        });
    }

    let request = {
        let relay = relay.clone();
        move || {
            let Some(cid) = channel_id.get_untracked() else {
                return;
            };
            let before: Rc<dyn Fn()> = Rc::new(move || {
                anchor.set_value(scroll_anchor::capture(None));
            });
            let after: Rc<dyn Fn()> = Rc::new(move || {
                if let Some(a) = anchor.try_update_value(Option::take).flatten() {
                    scroll_anchor::restore(a, None);
                }
            });
            let needles = vec![cid.clone()];
            let g = gated.get_untracked();
            match direction {
                HistoryDirection::Older => {
                    store.load_older(&relay, &cid, needles, g, before, after)
                }
                HistoryDirection::Newer => {
                    store.load_newer(&relay, &cid, needles, g, before, after)
                }
            };
        }
    };
    let request = StoredValue::new_local(Rc::new(request) as Rc<dyn Fn()>);

    let state = Signal::derive(move || channel_id.get().map(|cid| store.history_cursor(&cid)));
    let can_request = move || {
        state.with(|c| {
            c.as_ref().is_some_and(|c| match direction {
                HistoryDirection::Older => c.next_request().is_some(),
                HistoryDirection::Newer => c.next_newer().is_some(),
            })
        })
    };

    // Keep paging while the sentinel is on screen: re-runs on every cursor
    // change (a page landed) and on visibility changes.
    Effect::new(move |_| {
        if visible.get() && can_request() {
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

    let label = StoredValue::new(label);
    let shown = move || match direction {
        HistoryDirection::Older => true,
        HistoryDirection::Newer => {
            state.with(|c| c.as_ref().is_some_and(|c| c.newer_from.is_some()))
        }
    };
    let state_attr = move || match (direction, state.get()) {
        (_, Some(c)) if c.loading => "loading",
        (HistoryDirection::Older, Some(c)) if c.exhausted => "start",
        (HistoryDirection::Older, Some(c)) if c.started => "more",
        (HistoryDirection::Newer, Some(c)) if c.newer_from.is_some() => "newer",
        _ => "pending",
    };

    view! {
        <div
            class="flex justify-center py-3 text-xs text-gray-500"
            class:hidden=move || !shown()
            data-history-direction=match direction {
                HistoryDirection::Older => "older",
                HistoryDirection::Newer => "newer",
            }
            data-history-state=state_attr
        >
            {move || match (direction, state.get()) {
                (_, Some(c)) if c.loading => view! { <span>"Loading\u{2026}"</span> }.into_any(),
                (HistoryDirection::Older, Some(c)) if c.exhausted => {
                    view! { <span>"Start of history"</span> }.into_any()
                }
                (_, Some(c)) if c.started => view! {
                    <button
                        class="text-xs text-gray-400 hover:text-gray-200 underline"
                        on:click=move |_| request.with_value(|f| f())
                    >
                        {label.get_value()}
                    </button>
                }.into_any(),
                _ => ().into_any(),
            }}
            <div node_ref=sentinel class="h-px w-px"></div>
        </div>
    }
}
