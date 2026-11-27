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
use crate::stores::channels::{ChannelStore, HistoryCursor};
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
    /// The `#e` values pages are requested for; `[channel_id]` when absent.
    /// A topic list is keyed `topic:<root>` but paged by `#e:[root]`.
    #[prop(optional, into)]
    needles: Option<Signal<Vec<String>>>,
    /// When true, this direction has nothing more the view would show (a
    /// section whose complete root list already lists every topic): the
    /// loader is hidden and pages nothing, by scroll or otherwise.
    #[prop(optional, into)]
    exhausted: Option<Signal<bool>>,
) -> impl IntoView {
    // Reads in this component's reactive closures use `try_*`: see
    // [`read_cursor`] for why they can run after the page is gone.
    let exhausted = move || exhausted.is_some_and(|e| e.try_get().unwrap_or(true));
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
            let needles = needles
                .map(|n| n.get_untracked())
                .unwrap_or_else(|| vec![cid.clone()]);
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

    let state = Signal::derive(move || {
        channel_id
            .try_get()
            .flatten()
            .map(|cid| store.history_cursor(&cid))
    });
    let can_request = move || {
        read_cursor(state).is_some_and(|c| match direction {
            HistoryDirection::Older => c.next_request().is_some(),
            HistoryDirection::Newer => c.next_newer().is_some(),
        })
    };

    // Keep paging while the sentinel is on screen: re-runs on every cursor
    // change (a page landed) and on visibility changes.
    Effect::new(move |_| {
        if visible.get() && !exhausted() && can_request() {
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
    let shown = move || {
        !exhausted()
            && match direction {
                HistoryDirection::Older => true,
                HistoryDirection::Newer => {
                    read_cursor(state).is_some_and(|c| c.newer_from.is_some())
                }
            }
    };
    let state_attr = move || history_state_attr(direction, read_cursor(state).as_ref());

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
            {move || match (direction, read_cursor(state)) {
                (_, Some(c)) if c.loading => view! { <span>"Loading\u{2026}"</span> }.into_any(),
                (HistoryDirection::Older, Some(c)) if c.exhausted => {
                    view! { <span>"Start of history"</span> }.into_any()
                }
                (_, Some(c)) if c.started => view! {
                    <button
                        class="text-xs text-gray-400 hover:text-gray-200 underline"
                        on:click=move |_| request.with_value(|f| f())
                    >
                        {label.try_get_value().unwrap_or_default()}
                    </button>
                }.into_any(),
                _ => ().into_any(),
            }}
            <div node_ref=sentinel class="h-px w-px"></div>
        </div>
    }
}

/// The channel's cursor, or `None` before the channel resolves or once the
/// page that owns `state` is gone.
///
/// Leptos 0.7 drops a page's nested render effects one task hop per level
/// after the router has already disposed the page's owner. A store write in
/// that window (the next page's first effects request history for the same
/// channel) re-runs this loader's attribute and children closures against a
/// disposed `state`: `get` panicked ("a reactive value that has already been
/// disposed"), and the aborted task leaked the rest of the old page.
fn read_cursor(state: Signal<Option<HistoryCursor>>) -> Option<HistoryCursor> {
    state.try_get().flatten()
}

/// `data-history-state` for a loader in `direction` at `cursor`.
fn history_state_attr(direction: HistoryDirection, cursor: Option<&HistoryCursor>) -> &'static str {
    match (direction, cursor) {
        (_, Some(c)) if c.loading => "loading",
        (HistoryDirection::Older, Some(c)) if c.exhausted => "start",
        (HistoryDirection::Older, Some(c)) if c.started => "more",
        (HistoryDirection::Newer, Some(c)) if c.newer_from.is_some() => "newer",
        _ => "pending",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor(started: bool, loading: bool, exhausted: bool) -> HistoryCursor {
        HistoryCursor {
            started,
            loading,
            exhausted,
            ..HistoryCursor::default()
        }
    }

    #[test]
    fn a_live_cursor_is_read() {
        let owner = Owner::new();
        owner.with(|| {
            let state = Signal::derive(|| Some(cursor(true, false, false)));
            assert_eq!(read_cursor(state), Some(cursor(true, false, false)));
            assert_eq!(
                history_state_attr(HistoryDirection::Older, read_cursor(state).as_ref()),
                "more"
            );
        });
    }

    #[test]
    fn the_cursor_of_a_disposed_page_is_none_not_a_panic() {
        // Section -> topic: the section's two loaders re-ran their attribute
        // and children closures after the router had disposed the section,
        // eight panics per click. Reading through `read_cursor` renders the
        // pending state instead.
        let owner = Owner::new();
        let (state, channel) = owner.with(|| {
            let channel = Signal::derive(|| Some("c".to_string()));
            (
                Signal::derive(move || channel.get().map(|_| cursor(true, true, false))),
                channel,
            )
        });
        owner.cleanup();
        assert!(channel.try_get().is_none(), "the owner disposed its values");
        assert_eq!(read_cursor(state), None);
        assert_eq!(
            history_state_attr(HistoryDirection::Older, read_cursor(state).as_ref()),
            "pending"
        );
        assert_eq!(history_state_attr(HistoryDirection::Newer, None), "pending");
    }

    #[test]
    fn history_state_attr_names_each_phase() {
        let older = HistoryDirection::Older;
        assert_eq!(
            history_state_attr(older, Some(&cursor(true, true, false))),
            "loading"
        );
        assert_eq!(
            history_state_attr(older, Some(&cursor(true, false, true))),
            "start"
        );
        assert_eq!(
            history_state_attr(older, Some(&cursor(false, false, false))),
            "pending"
        );
        let newer = HistoryCursor {
            newer_from: Some(5),
            ..HistoryCursor::default()
        };
        assert_eq!(
            history_state_attr(HistoryDirection::Newer, Some(&newer)),
            "newer"
        );
        assert_eq!(
            history_state_attr(HistoryDirection::Newer, Some(&cursor(true, false, false))),
            "pending"
        );
    }
}
