//! Headless toast notification store shared across browser clients.
//!
//! Each client provides its own visual renderer (`ToastContainer` in
//! `forum-client`, terminal toast bar in `bbs-client`) while sharing one
//! reactive `ToastStore` in Leptos context.

use leptos::prelude::*;

use crate::utils::set_timeout_once;

/// Maximum number of visible toasts. Oldest are dismissed first.
const MAX_VISIBLE: usize = 5;

/// Auto-dismiss delay in milliseconds.
const AUTO_DISMISS_MS: i32 = 4_000;

/// Visual variant for a toast notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToastVariant {
    Success,
    Error,
    Warning,
    Info,
}

/// A single toast notification item.
#[derive(Clone, Debug)]
pub struct Toast {
    pub id: u64,
    pub message: String,
    pub variant: ToastVariant,
    pub exiting: RwSignal<bool>,
}

/// Shared reactive toast store held in Leptos context.
#[derive(Clone, Copy)]
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

    /// Reactive signal containing currently active toasts.
    pub fn toasts(&self) -> RwSignal<Vec<Toast>> {
        self.toasts
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
            while list.len() > MAX_VISIBLE {
                list.remove(0);
            }
        });

        let store = *self;
        set_timeout_once(move || store.dismiss(id), AUTO_DISMISS_MS);
    }

    /// Start exit animation then remove.
    pub fn dismiss(&self, id: u64) {
        let found = self
            .toasts
            .with_untracked(|list| list.iter().find(|t| t.id == id).map(|t| t.exiting));
        if let Some(exiting) = found {
            exiting.set(true);
            let store = *self;
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

/// Retrieve the global toast store if it has been provided.
pub fn try_use_toasts() -> Option<ToastStore> {
    use_context::<ToastStore>()
}
