//! Global toast notification system.
//!
//! Uses `provide_context` / `expect_context` so any component can push a toast
//! via `use_toasts().show(message, variant)`.
//!
//! CSS classes `toast-container`, `toast-item`, `toast-success`, `toast-error`,
//! `toast-warning`, and `toast-exit` are defined in `style.css`.

use leptos::prelude::*;

pub use nostr_bbs_client_core::toast::{provide_toasts, use_toasts, ToastStore, ToastVariant};

fn variant_css_class(v: ToastVariant) -> &'static str {
    match v {
        ToastVariant::Success => "toast-success",
        ToastVariant::Error => "toast-error",
        ToastVariant::Warning => "toast-warning",
        ToastVariant::Info => "",
    }
}

fn variant_icon_path(v: ToastVariant) -> &'static str {
    match v {
        ToastVariant::Success => "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z",
        ToastVariant::Error => {
            "M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"
        }
        ToastVariant::Warning => "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
        ToastVariant::Info => "M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
    }
}

fn variant_icon_color(v: ToastVariant) -> &'static str {
    match v {
        ToastVariant::Success => "text-green-400",
        ToastVariant::Error => "text-red-400",
        ToastVariant::Warning => "text-amber-400",
        ToastVariant::Info => "text-blue-400",
    }
}

// ---------------------------------------------------------------------------
// Renderer
// ---------------------------------------------------------------------------

/// Renders the fixed toast container. Mount once in your layout.
#[component]
pub(crate) fn ToastContainer() -> impl IntoView {
    let store = use_toasts();
    let toasts = store.toasts();

    view! {
        <div class="toast-container" role="alert" aria-live="polite" aria-atomic="false">
            <For
                each=move || toasts.get()
                key=|t| t.id
                let:toast
            >
                {
                    let variant_cls = variant_css_class(toast.variant);
                    let icon_path = variant_icon_path(toast.variant);
                    let icon_color = variant_icon_color(toast.variant);
                    let exiting = toast.exiting;
                    let id = toast.id;

                    let item_class = move || {
                        let base = format!("toast-item flex items-start gap-3 {}", variant_cls);
                        if exiting.get() {
                            format!("{} toast-exit", base)
                        } else {
                            base
                        }
                    };

                    view! {
                        <div class=item_class>
                            <svg class=format!("w-5 h-5 flex-shrink-0 mt-0.5 {}", icon_color)
                                viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d=icon_path stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            <span class="text-sm text-gray-200 flex-1">{toast.message.clone()}</span>
                            <button
                                class="text-gray-500 hover:text-gray-300 transition-colors flex-shrink-0"
                                on:click=move |_| store.dismiss(id)
                                aria-label="Dismiss notification"
                            >
                                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round"/>
                                    <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round"/>
                                </svg>
                            </button>
                        </div>
                    }
                }
            </For>
        </div>
    }
}
