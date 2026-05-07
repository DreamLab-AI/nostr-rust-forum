//! Typing indicator -- shows bouncing dots with user count.

use leptos::prelude::*;

use crate::components::user_display::use_display_name;

/// Show a "user is typing..." indicator with bouncing dots.
///
/// - Single user: shows shortened pubkey + "is typing..."
/// - Multiple users: shows "N people are typing..."
/// - Auto-hides when the pubkey list is empty
/// - Uses `typing-dot` CSS class for bounce animation
#[component]
pub(crate) fn TypingIndicator(
    /// Reactive list of pubkeys currently typing.
    typing_pubkeys: RwSignal<Vec<String>>,
) -> impl IntoView {
    let is_visible = move || !typing_pubkeys.get().is_empty();

    let label = move || {
        let pks = typing_pubkeys.get();
        match pks.len() {
            0 => String::new(),
            1 => format!("{} is typing", use_display_name(&pks[0])),
            n => format!("{} people are typing", n),
        }
    };

    view! {
        <Show when=is_visible>
            <div class="flex items-center gap-2 px-3 py-1.5 text-xs text-gray-400 animate-fadeIn">
                // Bouncing dots
                <div class="flex items-center gap-0.5">
                    <span class="typing-dot"></span>
                    <span class="typing-dot"></span>
                    <span class="typing-dot"></span>
                </div>

                <span class="italic">
                    {label}
                </span>
            </div>
        </Show>
    }
}
