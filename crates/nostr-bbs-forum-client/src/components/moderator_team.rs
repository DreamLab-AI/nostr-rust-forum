//! Moderator team display component.
//!
//! Horizontal card showing forum moderators and admins with avatars,
//! role badges, and click-to-profile functionality.

use leptos::prelude::*;

use crate::components::avatar::{Avatar, AvatarSize};
use crate::components::message_bubble::ProfileModalTarget;

/// Data for a moderator/admin entry.
#[derive(Clone, Debug)]
pub struct ModeratorData {
    /// Hex pubkey.
    pub pubkey: String,
    /// Display name.
    pub name: String,
    /// Role label: "Admin" or "Moderator".
    pub role: String,
    /// Optional avatar image URL (falls back to identicon).
    #[allow(dead_code)]
    pub avatar_url: Option<String>,
}

/// Horizontal display card showing forum moderators and admins.
///
/// Each entry shows an avatar, name, and role badge. Clicking a moderator
/// opens the profile modal via `ProfileModalTarget` context.
#[allow(dead_code)]
#[component]
pub fn ModeratorTeam(
    /// List of moderator data entries.
    moderators: Signal<Vec<ModeratorData>>,
) -> impl IntoView {
    view! {
        <div class="bg-white/5 backdrop-blur-xl border border-white/10 rounded-2xl p-4 shadow-lg shadow-amber-500/10">
            <div class="flex items-center gap-2 mb-4">
                <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
                        stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <h3 class="text-sm font-semibold text-white">"Team"</h3>
            </div>

            {move || {
                let mods = moderators.get();
                if mods.is_empty() {
                    return view! {
                        <p class="text-sm text-gray-500 text-center py-2">"No team members"</p>
                    }.into_any();
                }

                view! {
                    <div class="flex flex-wrap gap-3">
                        {mods.into_iter().map(|m| {
                            let pk = m.pubkey.clone();
                            let pk_for_click = m.pubkey.clone();
                            let is_admin = m.role == "Admin";
                            let badge_class = if is_admin {
                                "text-[10px] px-1.5 py-0 rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30 font-medium"
                            } else {
                                "text-[10px] px-1.5 py-0 rounded-full bg-amber-500/10 text-amber-500/80 border border-amber-500/20 font-medium"
                            };

                            let on_click = move |_: web_sys::MouseEvent| {
                                if let Some(target) = use_context::<ProfileModalTarget>() {
                                    target.0.set(Some(pk_for_click.clone()));
                                }
                            };

                            view! {
                                <button
                                    class="flex items-center gap-2 bg-white/5 border border-white/5 rounded-xl px-3 py-2 hover:border-amber-500/20 hover:bg-white/10 transition-colors cursor-pointer"
                                    on:click=on_click
                                >
                                    <Avatar pubkey=pk size=AvatarSize::Sm />
                                    <div class="text-left">
                                        <div class="text-sm text-gray-200">{m.name.clone()}</div>
                                        <span class=badge_class>{m.role.clone()}</span>
                                    </div>
                                </button>
                            }
                        }).collect_view()}
                    </div>
                }.into_any()
            }}
        </div>
    }
}
