//! "Continue: Zone › Section" on the Forums index, back to the last place the
//! member was reading (see [`crate::utils::resume`]). Never redirects; hidden
//! when nothing is stored, when the stored place is the current page, or when
//! the member can no longer reach its zone.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_location;

use crate::app::{base_href, current_app_path};
use crate::auth::use_auth;
use crate::stores::channels::{roots_key, use_channel_store, ChannelStore};
use crate::stores::zone_access::use_zone_access;
use crate::stores::zones::{load_zones, resolve_zone_param, ZoneVisibility};
use crate::utils::back_nav::ForumRoute;
use crate::utils::resume::{self, ResumePoint};
use crate::utils::slug_hash::{matches_section_slug, matches_topic_slug};

/// The title of the topic at `point`, if the channel store holds its root
/// readable in memory (decrypted, for an encrypted zone). Never stored.
fn topic_title_in_memory(store: ChannelStore, point: &ResumePoint) -> Option<String> {
    let ForumRoute::Topic { section, topic, .. } = ForumRoute::parse(&point.path) else {
        return None;
    };
    let cid = store.channels.with(|chans| {
        chans
            .iter()
            .find(|c| matches_section_slug(&c.id, section))
            .map(|c| c.id.clone())
    })?;
    let find = |key: &str| {
        store
            .list_events(key)
            .into_iter()
            .find(|e| e.kind == 42 && matches_topic_slug(&e.id, topic))
    };
    let root = find(&roots_key(&cid)).or_else(|| find(&cid))?;
    if root.content == crate::zone_crypto::PLACEHOLDER_MISSING_KEY
        || root.content == crate::zone_crypto::PLACEHOLDER_UNDECRYPTABLE
    {
        return None;
    }
    let line = root
        .content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())?;
    Some(resume::clip_label(line))
}

/// One unobtrusive link to the member's last zone, section or topic.
#[component]
pub fn ContinueLink() -> impl IntoView {
    let auth = use_auth();
    let pubkey = auth.pubkey();
    let zone_access = use_zone_access();
    let location = use_location();
    let store = use_channel_store();

    // Read once per identity: the pages that write it are elsewhere, and the
    // Forums index is remounted on every visit.
    let point = Memo::new(move |_| pubkey.get().and_then(|pk| resume::load(&pk)));

    let shown = Memo::new(move |_| {
        let p = point.get()?;
        // Wait for the access fetch: an unloaded cohort list would hide a
        // reachable zone, then flash the link in.
        if !zone_access.loaded.get() {
            return None;
        }
        let zones = load_zones();
        let reachable = ForumRoute::parse(&p.path)
            .zone()
            .and_then(|z| resolve_zone_param(z, &zones))
            .is_some_and(|z| z.visibility == ZoneVisibility::Public || zone_access.is_member_of(z));
        let here = current_app_path(&location.pathname.get());
        resume::should_show(Some(&p), &here, reachable).then_some(p)
    });

    move || {
        shown.get().map(|p| {
            let label = p.label(topic_title_in_memory(store, &p).as_deref());
            let href = base_href(&p.path);
            view! {
                <div class="mb-4 flex">
                    <A
                        href=href
                        attr:class="inline-flex items-center gap-1.5 max-w-full min-h-[44px] px-3 py-2 rounded-lg text-sm text-gray-300 hover:text-amber-400 hover:bg-gray-800/60 transition-colors no-underline"
                    >
                        <svg class="w-4 h-4 shrink-0 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                            <polyline points="9 18 15 12 9 6" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                        <span class="shrink-0 text-gray-400">"Continue:"</span>
                        <span class="truncate">{label}</span>
                    </A>
                </div>
            }
        })
    }
}
