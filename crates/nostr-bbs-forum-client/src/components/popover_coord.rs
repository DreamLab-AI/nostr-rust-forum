//! Popover coordinator — a single-slot context that makes header popovers
//! mutually exclusive.
//!
//! Multiple popovers (Notifications, Bookmarks, …) used to be openable at the
//! same time, with the most recently-opened one painting over (and
//! click-blocking) the others. Each popover registers a stable string key and
//! checks `is_active(key)` from its `is_open` derivation; opening one with
//! `open(key)` automatically closes every other.

use leptos::prelude::*;

/// A coordinator shared via Leptos context. Holds the key of the currently
/// open popover, or `None` when nothing is open.
#[derive(Clone, Copy)]
pub struct PopoverCoord {
    active: RwSignal<Option<&'static str>>,
}

impl PopoverCoord {
    pub fn new() -> Self {
        Self {
            active: RwSignal::new(None),
        }
    }

    /// Open the popover with this key, closing any other that was open.
    pub fn open(&self, key: &'static str) {
        self.active.set(Some(key));
    }

    /// Close the popover with this key if it is currently active.
    /// No-op if a different popover is active.
    pub fn close(&self, key: &'static str) {
        if self.active.with_untracked(|a| *a == Some(key)) {
            self.active.set(None);
        }
    }

    /// Close any open popover.
    pub fn close_all(&self) {
        self.active.set(None);
    }

    /// Reactively true while `key` is the currently active popover.
    pub fn is_active(&self, key: &'static str) -> bool {
        self.active.with(|a| *a == Some(key))
    }

    /// Toggle: open this popover if not active, else close.
    pub fn toggle(&self, key: &'static str) {
        if self.active.with_untracked(|a| *a == Some(key)) {
            self.active.set(None);
        } else {
            self.active.set(Some(key));
        }
    }
}

/// Retrieve the coordinator. Falls back to a no-op instance if context is
/// missing — caller checks should still compile and run.
pub fn use_popover_coord() -> PopoverCoord {
    use_context::<PopoverCoord>().unwrap_or_else(PopoverCoord::new)
}
