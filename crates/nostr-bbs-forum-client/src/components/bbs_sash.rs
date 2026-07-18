//! The "switch to the retro BBS" sash.
//!
//! A thin, glitchy amber terminal ribbon that switches the reader into the retro
//! ASCII/BBS rendering of the same community. Rendered under a page hero so it is
//! easy to see. Placed on BOTH the `/forums` index (multi-zone / admin users)
//! and the zone landing (`/forums/{zone}`, where single-locked-zone members are
//! sent by the zone-first nav, ADR-107) so every user meets it regardless of
//! which hero they land on.
//!
//! Rendered only when the deployment ships a BBS (`bbs_enabled()`, default on).
//! The BBS is a separate SPA at `<base>/bbs/` (not a router route). A bare `<a>`
//! is NOT enough to reach it: Leptos Router installs a delegated click listener
//! that hijacks every same-origin anchor into client-side routing, so the click
//! resolves to no route and renders the 404 page (while a manual refresh — a real
//! server GET — loads the BBS fine). Two things make the click escape the router:
//! `rel="external"` (which the router checks and skips) plus an explicit
//! hard-navigation `on:click` (belt-and-braces for router builds that ignore it).
//! The label carries `data-text` so the CSS RGB-split glitch pseudo-elements can
//! echo it (`.bbs-sash` in `style.css`).

use leptos::prelude::*;

use crate::app::base_href;
use crate::utils::relay_url::{bbs_enabled, bbs_url_override};

/// The glitchy amber sash inviting the reader into the retro BBS. Renders
/// nothing when the deployment has no BBS.
pub fn bbs_switch_sash() -> impl IntoView {
    if !bbs_enabled() {
        return ().into_any();
    }
    let href = bbs_url_override().unwrap_or_else(|| base_href("/bbs/"));
    let nav_href = href.clone();
    // Force a full document navigation to the BBS SPA, bypassing the Leptos
    // router that would otherwise treat this same-origin href as an internal
    // route and 404 on the miss.
    let on_click = move |ev: leptos::ev::MouseEvent| {
        ev.prevent_default();
        if let Some(w) = web_sys::window() {
            let _ = w.location().set_href(&nav_href);
        }
    };
    let label = "Enter the retro BBS terminal";
    view! {
        <a class="bbs-sash" href=href rel="external"
           on:click=on_click
           aria-label="Switch to the retro ASCII BBS interface">
            <span class="caret" aria-hidden="true">"\u{25B8}"</span>
            <span class="label" data-text=label>{label}</span>
            <span class="caret" aria-hidden="true">"\u{25C2}"</span>
        </a>
    }
    .into_any()
}
