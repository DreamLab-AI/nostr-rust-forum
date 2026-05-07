//! Global toast notification system.
//!
//! Uses `provide_context` / `expect_context` so any component can push a toast
//! via `use_toasts().show(message, variant)`.
//!
//! CSS classes `toast-container`, `toast-item`, `toast-success`, `toast-error`,
//! `toast-warning`, and `toast-exit` are defined in `style.css`.

use leptos::prelude::*;

use crate::utils::set_timeout_once;

/// Maximum number of visible toasts. Oldest are dismissed first.
const MAX_VISIBLE: usize = 5;

/// Auto-dismiss delay in milliseconds.
const AUTO_DISMISS_MS: i32 = 4_000;

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

/// Visual variant for a toast notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToastVariant {
    Success,
    Error,
    Warning,
    Info,
}

impl ToastVariant {
    fn css_class(self) -> &'static str {
        match self {
            Self::Success => "toast-success",
            Self::Error => "toast-error",
            Self::Warning => "toast-warning",
            Self::Info => "",
        }
    }

    fn icon_path(self) -> &'static str {
        match self {
            Self::Success => "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z",
            Self::Error => "M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z",
            Self::Warning => "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
            Self::Info => "M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
        }
    }

    fn icon_color(self) -> &'static str {
        match self {
            Self::Success => "text-green-400",
            Self::Error => "text-red-400",
            Self::Warning => "text-amber-400",
            Self::Info => "text-blue-400",
        }
    }
}

/// A single toast notification.
#[derive(Clone, Debug)]
struct Toast {
    id: u64,
    message: String,
    variant: ToastVariant,
    exiting: RwSignal<bool>,
}

// ---------------------------------------------------------------------------
// Context store
// ---------------------------------------------------------------------------

/// Shared toast store that lives in Leptos context.
#[derive(Clone)]
pub struct ToastStore {
    toasts: RwSignal<Vec<Toast>>,
    next_id: RwSignal<u64>,
}

impl ToastStore {
    fn new() -> Self {
        Self {
            toasts: RwSignal::new(Vec::new()),
            next_id: RwSignal::new(1),
        }
    }

    /// Push a new toast. Trims oldest if over `MAX_VISIBLE`.
    pub fn show(&self, message: impl Into<String>, variant: ToastVariant) {
        let id = self.next_id.get_untracked();
        self.next_id.set(id + 1);

        let toast = Toast {
            id,
            message: message.into(),
            variant,
            exiting: RwSignal::new(false),
        };

        self.toasts.update(|list| {
            list.push(toast);
            // Enforce max visible — remove from front.
            while list.len() > MAX_VISIBLE {
                list.remove(0);
            }
        });

        // Auto-dismiss after delay.
        let store = self.clone();
        set_timeout_once(move || store.dismiss(id), AUTO_DISMISS_MS);
    }

    /// Start exit animation then remove.
    fn dismiss(&self, id: u64) {
        // Mark as exiting for CSS animation.
        let found = self
            .toasts
            .with_untracked(|list| list.iter().find(|t| t.id == id).map(|t| t.exiting));
        if let Some(exiting) = found {
            exiting.set(true);
            // Remove after exit animation completes (200 ms).
            let store = self.clone();
            set_timeout_once(
                move || {
                    store.toasts.update(|list| list.retain(|t| t.id != id));
                },
                220,
            );
        }
    }
}

/// Call once near the app root to install the toast store into context.
pub fn provide_toasts() {
    provide_context(ToastStore::new());
}

/// Retrieve the global toast store from context.
pub fn use_toasts() -> ToastStore {
    expect_context::<ToastStore>()
}

// ---------------------------------------------------------------------------
// Renderer
// ---------------------------------------------------------------------------

/// Renders the fixed toast container. Mount once in your layout.
#[component]
pub(crate) fn ToastContainer() -> impl IntoView {
    let store = use_toasts();
    let toasts = store.toasts;

    view! {
        <div class="toast-container" role="alert" aria-live="polite" aria-atomic="false">
            <For
                each=move || toasts.get()
                key=|t| t.id
                let:toast
            >
                {
                    let variant_cls = toast.variant.css_class();
                    let icon_path = toast.variant.icon_path();
                    let icon_color = toast.variant.icon_color();
                    let exiting = toast.exiting;
                    let id = toast.id;
                    let store = store.clone();

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
