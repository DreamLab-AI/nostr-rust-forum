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
//! The BBS is a separate SPA at `<base>/bbs/` (not a router route), so this is a
//! plain full-navigation `<a>`, not a Leptos `<A>`. The label carries `data-text`
//! so the CSS RGB-split glitch pseudo-elements can echo it (`.bbs-sash` in
//! `style.css`).

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
    let label = "Enter the retro BBS terminal";
    view! {
        <a class="bbs-sash" href=href
           aria-label="Switch to the retro ASCII BBS interface">
            <span class="caret" aria-hidden="true">"\u{25B8}"</span>
            <span class="label" data-text=label>{label}</span>
            <span class="caret" aria-hidden="true">"\u{25C2}"</span>
        </a>
    }
    .into_any()
}
