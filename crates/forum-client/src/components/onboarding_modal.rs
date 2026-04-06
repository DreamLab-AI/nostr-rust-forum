//! 3-step onboarding modal shown on first login.
//!
//! Step 1: Community guidelines summary with accept button.
//! Step 2: Profile setup (display name + optional avatar URL).
//! Step 3: Channel exploration with links to main channels.
//!
//! Completion is tracked via `localStorage` key `bbs:onboarded`.
//! Only shown if this key is absent.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

use crate::app::base_href;
use crate::auth::use_auth;

/// localStorage key for onboarding completion.
const ONBOARDED_KEY: &str = "bbs:onboarded";

/// Check if the user has completed onboarding.
fn is_onboarded() -> bool {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item(ONBOARDED_KEY).ok().flatten())
        .is_some()
}

/// Mark onboarding as complete in localStorage.
fn mark_onboarded() {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item(ONBOARDED_KEY, "1");
    }
}

/// 3-step onboarding modal for new users.
///
/// Mount this component inside an authenticated page (e.g., ForumsPage).
/// It self-manages visibility based on the localStorage flag.
#[component]
pub fn OnboardingModal() -> impl IntoView {
    let is_open = RwSignal::new(false);
    let step = RwSignal::new(1u8);
    let display_name = RwSignal::new(String::new());
    let avatar_url = RwSignal::new(String::new());
    let guidelines_accepted = RwSignal::new(false);

    let auth = use_auth();

    // Check localStorage on mount
    Effect::new(move |_| {
        if !is_onboarded() && auth.is_authenticated().get() {
            is_open.set(true);
        }
    });

    // Escape key handler
    let esc_closure = wasm_bindgen::closure::Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(
        move |ev: web_sys::KeyboardEvent| {
            if is_open.get_untracked() && ev.key() == "Escape" {
                // Don't allow escape to skip onboarding — user must complete it
            }
        },
    );
    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
        let _ = doc.add_event_listener_with_callback(
            "keydown",
            esc_closure.as_ref().unchecked_ref(),
        );
    }
    let esc_ref = send_wrapper::SendWrapper::new(esc_closure);
    on_cleanup(move || drop(esc_ref));

    let on_accept_guidelines = move |_: web_sys::MouseEvent| {
        guidelines_accepted.set(true);
        step.set(2);
    };

    let on_save_profile = move |_: web_sys::MouseEvent| {
        // Publish kind-0 metadata update if display name was entered
        let name = display_name.get_untracked().trim().to_string();
        if !name.is_empty() {
            let auth = use_auth();
            let relay = expect_context::<crate::relay::RelayConnection>();
            if let Some(pubkey) = auth.pubkey().get_untracked() {
                let avatar = avatar_url.get_untracked().trim().to_string();
                let mut meta = serde_json::json!({
                    "name": name,
                    "display_name": name,
                });
                if !avatar.is_empty() {
                    meta["picture"] = serde_json::Value::String(avatar);
                }
                let now = (js_sys::Date::now() / 1000.0) as u64;
                let unsigned = nostr_core::UnsignedEvent {
                    pubkey,
                    created_at: now,
                    kind: 0,
                    tags: vec![],
                    content: meta.to_string(),
                };
                if let Ok(signed) = auth.sign_event(unsigned) {
                    relay.publish(&signed);
                }
            }
        }
        step.set(3);
    };

    let on_skip_profile = move |_: web_sys::MouseEvent| {
        step.set(3);
    };

    let on_finish = move |_: web_sys::MouseEvent| {
        mark_onboarded();
        is_open.set(false);
    };

    view! {
        <Show when=move || is_open.get()>
            <div
                class="fixed inset-0 z-[70] flex items-center justify-center p-4"
                style="animation: fadeIn 0.3s ease-out"
            >
                // Backdrop (no click-to-dismiss — user must complete onboarding)
                <div class="absolute inset-0 bg-black/70 backdrop-blur-sm" />

                // Panel
                <div
                    class="relative bg-gray-900/95 backdrop-blur-xl border border-white/10 rounded-2xl p-6 sm:p-8 max-w-lg w-full shadow-2xl shadow-amber-500/10"
                    style="animation: scaleIn 0.3s ease-out"
                    on:click=|e| e.stop_propagation()
                >
                    // Animated gradient border
                    <div class="absolute inset-0 rounded-2xl bg-gradient-to-r from-amber-500/20 via-orange-500/20 to-amber-500/20 -z-10 blur-sm" />

                    // Step indicator
                    <div class="flex items-center justify-center gap-2 mb-6">
                        <StepDot active=Signal::derive(move || step.get() >= 1) />
                        <div class="w-8 h-px bg-gray-700" />
                        <StepDot active=Signal::derive(move || step.get() >= 2) />
                        <div class="w-8 h-px bg-gray-700" />
                        <StepDot active=Signal::derive(move || step.get() >= 3) />
                    </div>

                    // Step 1: Community Guidelines
                    <Show when=move || step.get() == 1>
                        <div class="space-y-4">
                            <div class="text-center">
                                <div class="inline-flex items-center justify-center w-12 h-12 rounded-full bg-amber-500/10 border border-amber-500/20 mb-3">
                                    {welcome_icon()}
                                </div>
                                <h2 class="text-2xl font-bold bg-gradient-to-r from-amber-400 via-orange-400 to-rose-400 bg-clip-text text-transparent">
                                    "Welcome to the Nostr BBS Community"
                                </h2>
                            </div>

                            <div class="bg-gray-800/50 border border-gray-700/30 rounded-xl p-4 space-y-3 text-sm text-gray-300 leading-relaxed max-h-48 overflow-y-auto">
                                <p class="font-medium text-white">"Community Guidelines"</p>
                                <ul class="space-y-2 list-none">
                                    <li class="flex gap-2">
                                        <span class="text-amber-400 flex-shrink-0">"1."</span>
                                        <span>"Be respectful and constructive in all interactions. We are a professional learning community."</span>
                                    </li>
                                    <li class="flex gap-2">
                                        <span class="text-amber-400 flex-shrink-0">"2."</span>
                                        <span>"Keep discussions on topic within each channel. Use the appropriate zone for your content."</span>
                                    </li>
                                    <li class="flex gap-2">
                                        <span class="text-amber-400 flex-shrink-0">"3."</span>
                                        <span>"Do not share private keys, credentials, or sensitive information in public channels."</span>
                                    </li>
                                    <li class="flex gap-2">
                                        <span class="text-amber-400 flex-shrink-0">"4."</span>
                                        <span>"Report inappropriate content using the report button. Do not engage with trolls or spam."</span>
                                    </li>
                                    <li class="flex gap-2">
                                        <span class="text-amber-400 flex-shrink-0">"5."</span>
                                        <span>"Your identity is Nostr-native and sovereign. You own your data and can export it at any time."</span>
                                    </li>
                                </ul>
                            </div>

                            <button
                                on:click=on_accept_guidelines
                                class="w-full bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 text-gray-900 font-semibold py-3 rounded-xl transition-all duration-200 shadow-lg shadow-amber-500/25"
                            >
                                "I Agree \u{2014} Continue"
                            </button>
                        </div>
                    </Show>

                    // Step 2: Profile Setup
                    <Show when=move || step.get() == 2>
                        <div class="space-y-4">
                            <div class="text-center">
                                <div class="inline-flex items-center justify-center w-12 h-12 rounded-full bg-blue-500/10 border border-blue-500/20 mb-3">
                                    {profile_icon()}
                                </div>
                                <h2 class="text-2xl font-bold text-white">"Set Up Your Profile"</h2>
                                <p class="text-gray-400 text-sm mt-1">"Help others recognise you in the community"</p>
                            </div>

                            <div class="space-y-3">
                                <div class="space-y-2">
                                    <label for="onboard-name" class="block text-sm font-medium text-gray-300">
                                        "Display Name"
                                    </label>
                                    <input
                                        id="onboard-name"
                                        type="text"
                                        placeholder="How should we call you?"
                                        on:input=move |ev| display_name.set(event_target_value(&ev))
                                        prop:value=move || display_name.get()
                                        maxlength="50"
                                        class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-xl px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500 text-sm"
                                    />
                                </div>

                                <div class="space-y-2">
                                    <label for="onboard-avatar" class="block text-sm font-medium text-gray-300">
                                        "Avatar URL "
                                        <span class="text-gray-500 font-normal">"(optional)"</span>
                                    </label>
                                    <input
                                        id="onboard-avatar"
                                        type="url"
                                        placeholder="https://example.com/avatar.jpg"
                                        on:input=move |ev| avatar_url.set(event_target_value(&ev))
                                        prop:value=move || avatar_url.get()
                                        class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-xl px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500 text-sm"
                                    />
                                    <p class="text-xs text-gray-500">"You can change this later in settings."</p>
                                </div>
                            </div>

                            <div class="flex gap-3">
                                <button
                                    on:click=on_skip_profile
                                    class="flex-1 border border-gray-600 hover:border-gray-500 text-gray-300 py-3 rounded-xl transition-colors text-sm font-medium"
                                >
                                    "Skip for now"
                                </button>
                                <button
                                    on:click=on_save_profile
                                    class="flex-1 bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold py-3 rounded-xl transition-colors text-sm"
                                >
                                    "Save & Continue"
                                </button>
                            </div>
                        </div>
                    </Show>

                    // Step 3: Explore Channels
                    <Show when=move || step.get() == 3>
                        <div class="space-y-4">
                            <div class="text-center">
                                <div class="inline-flex items-center justify-center w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 mb-3">
                                    {explore_icon()}
                                </div>
                                <h2 class="text-2xl font-bold text-white">"Explore"</h2>
                                <p class="text-gray-400 text-sm mt-1">"Here are some places to get started"</p>
                            </div>

                            <div class="space-y-2">
                                <ChannelLink
                                    name="Lobby"
                                    description="General discussion and introductions. Say hello!"
                                    href=base_href("/chat")
                                    accent="amber"
                                />
                                <ChannelLink
                                    name="Forums"
                                    description="Browse all zones and categories"
                                    href=base_href("/forums")
                                    accent="blue"
                                />
                                <ChannelLink
                                    name="Events"
                                    description="Upcoming workshops, meetups, and community events"
                                    href=base_href("/events")
                                    accent="purple"
                                />
                                <ChannelLink
                                    name="Direct Messages"
                                    description="Private encrypted conversations"
                                    href=base_href("/dm")
                                    accent="green"
                                />
                            </div>

                            <button
                                on:click=on_finish
                                class="w-full bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 text-gray-900 font-semibold py-3 rounded-xl transition-all duration-200 shadow-lg shadow-amber-500/25"
                            >
                                "Get Started"
                            </button>
                        </div>
                    </Show>
                </div>
            </div>
        </Show>
    }
}

// -- Sub-components -----------------------------------------------------------

/// Step indicator dot.
#[component]
fn StepDot(active: Signal<bool>) -> impl IntoView {
    view! {
        <div class=move || if active.get() {
            "w-3 h-3 rounded-full bg-amber-400 transition-colors duration-300"
        } else {
            "w-3 h-3 rounded-full bg-gray-700 transition-colors duration-300"
        } />
    }
}

/// Channel exploration link card.
#[component]
fn ChannelLink(
    name: &'static str,
    description: &'static str,
    href: String,
    accent: &'static str,
) -> impl IntoView {
    let border_class = match accent {
        "amber" => "hover:border-amber-500/30",
        "blue" => "hover:border-blue-500/30",
        "purple" => "hover:border-purple-500/30",
        "green" => "hover:border-green-500/30",
        _ => "hover:border-gray-500/30",
    };
    let icon_class = match accent {
        "amber" => "text-amber-400",
        "blue" => "text-blue-400",
        "purple" => "text-purple-400",
        "green" => "text-green-400",
        _ => "text-gray-400",
    };
    let cls = format!(
        "block bg-gray-800/50 border border-gray-700/30 rounded-xl p-3 transition-all duration-200 {} hover:bg-gray-800/80",
        border_class
    );

    view! {
        <a href=href class=cls>
            <div class="flex items-center gap-3">
                <div class=format!("flex-shrink-0 {}", icon_class)>
                    {channel_icon()}
                </div>
                <div>
                    <div class="text-sm font-medium text-white">{name}</div>
                    <div class="text-xs text-gray-500">{description}</div>
                </div>
                <svg class="w-4 h-4 text-gray-600 ml-auto flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="9 18 15 12 9 6" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </div>
        </a>
    }
}

// -- SVG icons ----------------------------------------------------------------

fn welcome_icon() -> impl IntoView {
    view! {
        <svg class="w-6 h-6 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M12 3v2.25m6.364.386l-1.591 1.591M21 12h-2.25m-.386 6.364l-1.591-1.591M12 18.75V21m-4.773-4.227l-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0z"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn profile_icon() -> impl IntoView {
    view! {
        <svg class="w-6 h-6 text-blue-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn explore_icon() -> impl IntoView {
    view! {
        <svg class="w-6 h-6 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn channel_icon() -> impl IntoView {
    view! {
        <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M5.25 8.25h15m-16.5 7.5h15m-1.8-13.5l-3.9 19.5m-2.1-19.5l-3.9 19.5"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}
