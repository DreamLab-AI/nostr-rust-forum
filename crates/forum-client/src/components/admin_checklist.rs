//! Admin onboarding checklist -- shown at the top of the admin page for new admins.

use leptos::prelude::*;

#[component]
pub fn AdminChecklist(
    has_channels: Signal<bool>,
    has_members: Signal<bool>,
    has_zones: Signal<bool>,
) -> impl IntoView {
    let all_done = Memo::new(move |_| has_channels.get() && has_members.get() && has_zones.get());

    view! {
        <Show when=move || !all_done.get()>
            <div class="bg-gradient-to-r from-amber-500/10 to-orange-500/5 border border-amber-500/20 rounded-2xl p-6 mb-6">
                <h3 class="text-lg font-bold text-white mb-3">"Getting Started"</h3>
                <p class="text-gray-400 text-sm mb-4">"Complete these steps to set up your community."</p>
                <div class="space-y-3">
                    <ChecklistItem done=has_channels label="Create your first channel" />
                    <ChecklistItem done=has_members label="Invite community members" />
                    <ChecklistItem done=has_zones label="Configure zone access" />
                </div>
            </div>
        </Show>
    }
}

#[component]
fn ChecklistItem(done: Signal<bool>, label: &'static str) -> impl IntoView {
    view! {
        <div class="flex items-center gap-3">
            <div class=move || if done.get() {
                "w-6 h-6 rounded-full bg-green-500/20 flex items-center justify-center flex-shrink-0"
            } else {
                "w-6 h-6 rounded-full bg-gray-700 flex items-center justify-center flex-shrink-0"
            }>
                <Show
                    when=move || done.get()
                    fallback=|| view! {
                        <div class="w-2 h-2 rounded-full bg-gray-500"></div>
                    }
                >
                    <svg class="w-3.5 h-3.5 text-green-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                        <polyline points="20 6 9 17 4 12" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </Show>
            </div>
            <span class=move || if done.get() {
                "text-sm text-gray-500 line-through"
            } else {
                "text-sm text-gray-300"
            }>{label}</span>
        </div>
    }
}
