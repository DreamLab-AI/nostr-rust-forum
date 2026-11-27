//! Keep the address bar on a page's canonical URL.
//!
//! The derivation (which URL is canonical, and when an address is replaced)
//! is client-core's [`section_url`](crate::utils::section_url), shared with
//! the BBS; this is the forum's router-side half.

use leptos::prelude::*;
use leptos_router::hooks::{use_location, use_navigate};
use leptos_router::NavigateOptions;

use crate::app::current_app_path;
use crate::components::back_button::ScrollMemory;
use crate::utils::section_url::canonical_replacement;

/// Replace the address with `canonical()` whenever it yields a path that
/// differs from the current one: a history replace through the router (so
/// its location, and anything keyed on it, sees the canonical path), with no
/// new history entry, no reload and no scroll to the top. The query string
/// and hash are kept, and the scroll memory moves the page's offset to the
/// canonical path, so no entry is left under the old one. `canonical` returns `None` until the page has resolved
/// what it shows.
pub fn keep_address_canonical(canonical: impl Fn() -> Option<String> + 'static) {
    let location = use_location();
    let navigate = StoredValue::new(use_navigate());
    let memory = use_context::<ScrollMemory>();
    Effect::new(move |_| {
        let Some(target) = canonical() else {
            return;
        };
        // Untracked: this runs when what the page shows changes, never because
        // the router has moved on to another page.
        let current = current_app_path(&location.pathname.get_untracked());
        let (search, hash) = web_sys::window()
            .map(|w| {
                let l = w.location();
                (l.search().unwrap_or_default(), l.hash().unwrap_or_default())
            })
            .unwrap_or_default();
        if let Some(to) = canonical_replacement(&current, &target, &search, &hash) {
            if let Some(memory) = memory {
                memory.rename(&current, &target);
            }
            navigate.try_with_value(|nav| {
                nav(
                    &to,
                    NavigateOptions {
                        replace: true,
                        scroll: false,
                        ..Default::default()
                    },
                )
            });
        }
    });
}
