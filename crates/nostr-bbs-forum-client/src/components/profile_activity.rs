//! Activity section of the user card: how long someone has been posting, how
//! much, where they are most active, and which other keys are the same person.
//!
//! Backed by the relay's `GET /api/profile-stats`, which counts only what the
//! viewer could read anyway (see `profile_stats.rs` in the relay worker). The
//! request is NIP-98 signed when a signer is available so a member's card
//! includes the zones they belong to; otherwise it falls back to public scope.
//! Results are memoised per pubkey for the session, so reopening a card never
//! re-signs.

use std::cell::RefCell;
use std::collections::HashMap;

use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::user_display::use_display_name_tracked;
use crate::utils::{format_relative_time, relay_url::relay_api_base, shorten_pubkey};

/// One channel in the "most active in" list.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) struct TopChannel {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub count: u32,
}

/// `/api/profile-stats` response.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) struct ProfileStats {
    #[serde(default)]
    pub superseded_by: Option<String>,
    #[serde(default)]
    pub identities: Vec<String>,
    pub post_count: u32,
    #[serde(default)]
    pub first_post_at: Option<u64>,
    #[serde(default)]
    pub last_post_at: Option<u64>,
    #[serde(default)]
    pub top_channels: Vec<TopChannel>,
    #[serde(default)]
    pub truncated: bool,
}

impl ProfileStats {
    /// Keys in the identity other than `shown` (the key the card is about).
    pub fn other_identities(&self, shown: &str) -> Vec<String> {
        self.identities
            .iter()
            .filter(|k| k.as_str() != shown)
            .cloned()
            .collect()
    }
}

thread_local! {
    static STATS_MEMO: RefCell<HashMap<String, ProfileStats>> = RefCell::new(HashMap::new());
}

/// "Jul 2026" from Unix seconds.
fn month_year(ts: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(ts as f64 * 1000.0));
    let m = MONTHS[(d.get_month() as usize).min(11)];
    format!("{m} {}", d.get_full_year())
}

async fn fetch_stats(pubkey: &str) -> Option<ProfileStats> {
    let url = format!("{}/api/profile-stats?pubkey={}", relay_api_base(), pubkey);
    let signer = use_auth().get_signer();
    let text = match signer {
        Some(s) => crate::auth::nip98::fetch_with_nip98_get_signer(&url, &*s)
            .await
            .ok(),
        None => None,
    };
    let text = match text {
        Some(t) => t,
        // No signer, or the signed request failed: public scope.
        None => {
            let win = web_sys::window()?;
            let resp: web_sys::Response = JsFuture::from(win.fetch_with_str(&url))
                .await
                .ok()?
                .dyn_into()
                .ok()?;
            if !resp.ok() {
                return None;
            }
            JsFuture::from(resp.text().ok()?).await.ok()?.as_string()?
        }
    };
    serde_json::from_str(&text).ok()
}

/// Activity block for a user card. `compact` trims it for the popover.
#[component]
pub(crate) fn ProfileActivity(pubkey: String, #[prop(optional)] compact: bool) -> impl IntoView {
    let stats: RwSignal<Option<ProfileStats>> =
        RwSignal::new(STATS_MEMO.with(|m| m.borrow().get(&pubkey).cloned()));
    let failed = RwSignal::new(false);

    if stats.get_untracked().is_none() {
        let pk = pubkey.clone();
        spawn_local(async move {
            match fetch_stats(&pk).await {
                Some(s) => {
                    STATS_MEMO.with(|m| m.borrow_mut().insert(pk, s.clone()));
                    stats.set(Some(s));
                }
                None => failed.set(true),
            }
        });
    }

    let shown = StoredValue::new(pubkey);
    let max_channels = if compact { 3 } else { 5 };

    move || {
        if failed.get() {
            return None;
        }
        let Some(s) = stats.get() else {
            return Some(
                view! {
                    <div class="mt-3 h-10 rounded-lg bg-gray-900/40 animate-pulse" aria-hidden="true"></div>
                }
                .into_any(),
            );
        };
        let shown_pk = shown.get_value();
        let moved = s.superseded_by.clone();
        let others = s.other_identities(&shown_pk);
        let count_label = if s.truncated {
            format!("{}+ posts", s.post_count)
        } else if s.post_count == 1 {
            "1 post".to_string()
        } else {
            format!("{} posts", s.post_count)
        };
        let since = s.first_post_at.map(month_year);
        let last = s.last_post_at.map(format_relative_time);
        let channels: Vec<TopChannel> = s.top_channels.iter().take(max_channels).cloned().collect();

        Some(
            view! {
                <div class="mt-3 space-y-2 text-xs">
                    {moved.map(|next| {
                        let href = base_href(&format!("/profile/{next}"));
                        let next_name = next.clone();
                        view! {
                            <a href=href class="block rounded-lg border border-amber-500/40 bg-amber-500/10 \
                                              px-2.5 py-1.5 text-amber-300 hover:bg-amber-500/20">
                                "Now posts as " {move || use_display_name_tracked(&next_name)} " →"
                            </a>
                        }
                    })}
                    <div class="flex flex-wrap gap-x-3 gap-y-1 text-gray-400">
                        {since.map(|m| view! { <span>"Posting since " <span class="text-gray-200">{m}</span></span> })}
                        <span class="text-gray-200">{count_label}</span>
                        {last.map(|l| view! { <span>"Last active " {l}</span> })}
                    </div>
                    {(!channels.is_empty()).then(|| view! {
                        <div>
                            <div class="text-[10px] uppercase tracking-wide text-gray-500 mb-1">"Most active in"</div>
                            <ul class="space-y-0.5">
                                {channels.into_iter().map(|c| {
                                    let href = base_href(&format!("/chat/{}", c.id));
                                    let label = c.name.clone().unwrap_or_else(|| format!("#{}", &c.id[..8.min(c.id.len())]));
                                    view! {
                                        <li class="flex justify-between gap-2">
                                            <a href=href class="truncate text-amber-400/90 hover:text-amber-300">{label}</a>
                                            <span class="flex-shrink-0 text-gray-500">{c.count}</span>
                                        </li>
                                    }
                                }).collect_view()}
                            </ul>
                        </div>
                    })}
                    {(!others.is_empty()).then(|| view! {
                        <div class="text-gray-400">
                            "Also posted as "
                            {others.into_iter().map(|k| view! {
                                <span class="font-mono text-[11px] text-amber-400/80 mr-1" title=k.clone()>
                                    {shorten_pubkey(&k)}
                                </span>
                            }).collect_view()}
                        </div>
                    })}
                </div>
            }
            .into_any(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stats_and_lists_other_identities() {
        let new = "b4".repeat(32);
        let old = "cd".repeat(32);
        let json = format!(
            r#"{{"pubkey":"{new}","superseded_by":null,"identities":["{new}","{old}"],
               "post_count":123,"first_post_at":1784460000,"last_post_at":1790000000,
               "top_channels":[{{"id":"abc","name":"Games","zone":null,"count":12,"last_at":1}}],
               "truncated":false,"scope":"viewer"}}"#
        );
        let s: ProfileStats = serde_json::from_str(&json).unwrap();
        assert_eq!(s.post_count, 123);
        assert_eq!(s.top_channels[0].name.as_deref(), Some("Games"));
        assert_eq!(s.other_identities(&new), vec![old.clone()]);
        assert_eq!(s.other_identities(&old), vec![new]);
    }
}
