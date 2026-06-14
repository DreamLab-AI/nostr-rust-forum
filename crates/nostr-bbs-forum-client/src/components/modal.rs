//! Glass modal component with backdrop-close and Escape-key support.
//!
//! Uses the `.modal-backdrop` / `.modal-panel` classes from `style.css` for
//! glass blur, scale-in animation, and dark overlay.

use leptos::prelude::*;
use std::sync::atomic::{AtomicU32, Ordering};
use wasm_bindgen::JsCast;

/// Reusable glass modal overlay.
///
/// - Renders children inside a centered `.modal-panel`.
/// - Clicking the backdrop or pressing Escape closes the modal.
/// - Body scroll is locked while open.
#[component]
pub(crate) fn Modal(
    /// Controls visibility. The modal sets this to `false` on close.
    is_open: RwSignal<bool>,
    /// Header title text.
    title: String,
    /// Optional icon rendered before the title in the header (e.g. a bookmark
    /// glyph). Lets callers decorate the title without forking the shell.
    #[prop(optional)]
    title_icon: Option<AnyView>,
    /// Optional CSS `max-width` override (e.g. `"640px"`).
    #[prop(optional)]
    max_width: Option<String>,
    /// Optional callback fired on close.
    #[prop(optional)]
    on_close: Option<Callback<()>>,
    /// Modal body content.
    children: Children,
) -> impl IntoView {
    // Always-on escape listener — only acts when modal is open.
    let esc_closure = wasm_bindgen::closure::Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(
        move |ev: web_sys::KeyboardEvent| {
            if is_open.get_untracked() && ev.key() == "Escape" {
                is_open.set(false);
                if let Some(cb) = on_close {
                    cb.run(());
                }
            }
        },
    );
    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
        let _ =
            doc.add_event_listener_with_callback("keydown", esc_closure.as_ref().unchecked_ref());
    }
    let esc_ref = send_wrapper::SendWrapper::new(esc_closure);
    on_cleanup(move || drop(esc_ref));

    // Body scroll lock
    Effect::new(move |_| {
        toggle_body_scroll(is_open.get());
    });

    let panel_style = max_width
        .map(|mw| format!("width: min(90vw, {}); max-width: {};", mw, mw))
        .unwrap_or_default();

    let on_backdrop = move |_| {
        is_open.set(false);
        if let Some(cb) = on_close {
            cb.run(());
        }
    };

    // Render children once (outside any conditional)
    let body = children();

    // Generate unique ID for aria-labelledby
    static MODAL_COUNTER: AtomicU32 = AtomicU32::new(0);
    let title_id = format!(
        "modal-title-{}",
        MODAL_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let title_id_attr = title_id.clone();

    view! {
        <div
            class=move || if is_open.get() { "modal-backdrop" } else { "hidden" }
            on:click=on_backdrop
        >
            <div
                class="modal-panel p-6"
                style=panel_style
                on:click=|e| e.stop_propagation()
                role="dialog"
                aria-modal="true"
                aria-labelledby=title_id_attr
            >
                // Header
                <div class="flex items-center justify-between mb-4">
                    <div class="flex items-center gap-2">
                        {title_icon}
                        <h2 id=title_id class="text-lg font-bold text-white">{title.clone()}</h2>
                    </div>
                    <button
                        class="text-gray-400 hover:text-white transition-colors p-1 rounded-lg hover:bg-gray-800"
                        aria-label="Close dialog"
                        on:click=move |_| {
                            is_open.set(false);
                            if let Some(cb) = on_close {
                                cb.run(());
                            }
                        }
                    >
                        <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round"/>
                            <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round"/>
                        </svg>
                    </button>
                </div>
                {body}
            </div>
        </div>
    }
}

/// Toggle `overflow: hidden` on `<body>` to prevent background scroll.
fn toggle_body_scroll(lock: bool) {
    if let Some(body) = gloo::utils::document().body() {
        let style = body.style();
        let _ = style.set_property("overflow", if lock { "hidden" } else { "" });
    }
}
