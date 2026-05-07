//! Quoted/replied-to message component for reply threading.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

use crate::components::user_display::use_display_name;
use crate::utils::pubkey_color;

/// Display a quoted/replied-to message with a left amber border.
///
/// - Shows shortened pubkey with deterministic avatar color
/// - Truncates content to 100 characters
/// - Click scrolls to the original message element
#[component]
pub(crate) fn QuotedMessage(
    /// Event ID of the message being replied to.
    reply_to_id: String,
    /// Pubkey of the original message author.
    reply_to_pubkey: String,
    /// Content of the original message.
    reply_to_content: String,
) -> impl IntoView {
    let short_pk = use_display_name(&reply_to_pubkey);
    let avatar_bg = pubkey_color(&reply_to_pubkey);
    let avatar_letter = reply_to_pubkey
        .chars()
        .next()
        .unwrap_or('?')
        .to_uppercase()
        .to_string();

    // Truncate content
    let truncated = if reply_to_content.len() > 100 {
        let mut s = reply_to_content.chars().take(100).collect::<String>();
        s.push_str("...");
        s
    } else {
        reply_to_content
    };

    let scroll_target_id = reply_to_id.clone();
    let on_click = move |_: leptos::ev::MouseEvent| {
        // Attempt to scroll to the original message element
        if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
            // Messages use data-event-id attribute or id for targeting
            let selector = format!("[data-event-id=\"{}\"]", scroll_target_id);
            if let Ok(Some(el)) = doc.query_selector(&selector) {
                let opts = web_sys::ScrollIntoViewOptions::new();
                opts.set_behavior(web_sys::ScrollBehavior::Smooth);
                el.scroll_into_view_with_scroll_into_view_options(&opts);

                // Brief highlight flash
                let html_el: web_sys::HtmlElement = el.unchecked_into();
                html_el
                    .style()
                    .set_property("transition", "background-color 0.3s ease")
                    .ok();
                html_el
                    .style()
                    .set_property("background-color", "rgba(245, 158, 11, 0.15)")
                    .ok();
                let html_el_clone = html_el.clone();
                crate::utils::set_timeout_once(
                    move || {
                        html_el_clone
                            .style()
                            .remove_property("background-color")
                            .ok();
                    },
                    1500,
                );
            }
        }
    };

    view! {
        <div
            class="flex items-start gap-2 pl-3 py-1.5 mb-1 border-l-2 border-amber-500/60 bg-gray-800/30 rounded-r-lg cursor-pointer hover:bg-gray-800/50 transition-colors"
            on:click=on_click
        >
            // Mini avatar
            <div
                class="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold text-white flex-shrink-0 mt-0.5"
                style=format!("background-color: {}", avatar_bg)
            >
                {avatar_letter}
            </div>

            <div class="flex-1 min-w-0">
                <span class="text-xs font-medium text-amber-400/80 font-mono">
                    {short_pk}
                </span>
                <p class="text-xs text-gray-400 truncate leading-snug mt-0.5">
                    {truncated}
                </p>
            </div>

            // Reply indicator icon
            <svg class="w-3.5 h-3.5 text-gray-600 flex-shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="9 14 4 9 9 4" stroke-linecap="round" stroke-linejoin="round"/>
                <path d="M20 20v-7a4 4 0 00-4-4H4" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        </div>
    }
}
