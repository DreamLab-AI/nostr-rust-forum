//! First-visit welcome modal component.
//!
//! Displays a glass-panel overlay with feature highlights on the user's
//! first visit. The `bbs:welcomed` flag in localStorage prevents
//! re-display on subsequent visits.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

/// Welcome modal shown once on first visit.
///
/// Checks `localStorage` for the `bbs:welcomed` key. If absent, shows
/// the modal with a fade-in animation. Clicking "Get Started" or the X button
/// closes the modal and sets the flag.
#[component]
pub fn WelcomeModal() -> impl IntoView {
    let is_open = RwSignal::new(false);

    // Check localStorage on mount
    Effect::new(move |_| {
        let should_show = web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .map(|s| s.get_item("bbs:welcomed").ok().flatten().is_none())
            .unwrap_or(false);

        if should_show {
            is_open.set(true);
        }
    });

    let dismiss = move |_: web_sys::MouseEvent| {
        is_open.set(false);
        if let Some(storage) = web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
        {
            let _ = storage.set_item("bbs:welcomed", "1");
        }
    };

    // Escape key handler
    let esc_closure = wasm_bindgen::closure::Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(
        move |ev: web_sys::KeyboardEvent| {
            if is_open.get_untracked() && ev.key() == "Escape" {
                is_open.set(false);
                if let Some(storage) = web_sys::window()
                    .and_then(|w| w.local_storage().ok().flatten())
                {
                    let _ = storage.set_item("bbs:welcomed", "1");
                }
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

    view! {
        <Show when=move || is_open.get()>
            <div
                class="fixed inset-0 z-[60] flex items-center justify-center p-4"
                style="animation: fadeIn 0.3s ease-out"
            >
                // Backdrop
                <div
                    class="absolute inset-0 bg-black/60 backdrop-blur-sm"
                    on:click=dismiss
                />

                // Panel
                <div
                    class="relative bg-gray-900/90 backdrop-blur-xl border border-white/10 rounded-2xl p-6 sm:p-8 max-w-lg w-full shadow-2xl shadow-amber-500/10"
                    style="animation: scaleIn 0.3s ease-out"
                    on:click=|e| e.stop_propagation()
                >
                    // Animated gradient border effect
                    <div class="absolute inset-0 rounded-2xl bg-gradient-to-r from-amber-500/20 via-orange-500/20 to-amber-500/20 -z-10 blur-sm" />

                    // Close button
                    <button
                        class="absolute top-4 right-4 text-gray-400 hover:text-white transition-colors p-1 rounded-lg hover:bg-gray-800"
                        on:click=dismiss
                    >
                        <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round"/>
                            <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round"/>
                        </svg>
                    </button>

                    // Heading
                    <h2 class="text-2xl sm:text-3xl font-bold text-center mb-2 bg-gradient-to-r from-amber-400 via-orange-400 to-rose-400 bg-clip-text text-transparent">
                        "Welcome to Nostr BBS"
                    </h2>
                    <p class="text-gray-400 text-center text-sm mb-6">
                        "Your decentralized community awaits"
                    </p>

                    // Feature cards
                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-6">
                        <FeatureCard
                            icon="channels"
                            title="Channels"
                            description="Join public conversations"
                        />
                        <FeatureCard
                            icon="dms"
                            title="Direct Messages"
                            description="Encrypted end-to-end"
                        />
                        <FeatureCard
                            icon="events"
                            title="Events"
                            description="Workshops and meetups"
                        />
                    </div>

                    // CTA
                    <button
                        class="w-full bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 text-gray-900 font-semibold py-3 rounded-xl transition-all duration-200 shadow-lg shadow-amber-500/25"
                        on:click=dismiss
                    >
                        "Get Started"
                    </button>
                </div>
            </div>
        </Show>
    }
}

/// Feature highlight card for the welcome modal.
#[component]
fn FeatureCard(
    icon: &'static str,
    title: &'static str,
    description: &'static str,
) -> impl IntoView {
    let icon_view = match icon {
        "channels" => view! {
            <svg class="w-6 h-6 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M5.25 8.25h15m-16.5 7.5h15m-1.8-13.5l-3.9 19.5m-2.1-19.5l-3.9 19.5"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        "dms" => view! {
            <svg class="w-6 h-6 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M16.5 12a4.5 4.5 0 11-9 0 4.5 4.5 0 019 0zm0 0c0 1.657 1.007 3 2.25 3S21 13.657 21 12a9 9 0 10-2.636 6.364M16.5 12V8.25"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        "events" => view! {
            <svg class="w-6 h-6 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M6.75 3v2.25M17.25 3v2.25M3 18.75V7.5a2.25 2.25 0 012.25-2.25h13.5A2.25 2.25 0 0121 7.5v11.25m-18 0A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75m-18 0v-7.5A2.25 2.25 0 015.25 9h13.5A2.25 2.25 0 0121 11.25v7.5"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        _ => view! { <span></span> }.into_any(),
    };

    view! {
        <div class="bg-white/5 border border-white/5 rounded-xl p-3 text-center hover:border-amber-500/20 transition-colors">
            <div class="flex justify-center mb-2">{icon_view}</div>
            <div class="text-sm font-medium text-white mb-0.5">{title}</div>
            <div class="text-[11px] text-gray-500">{description}</div>
        </div>
    }
}
