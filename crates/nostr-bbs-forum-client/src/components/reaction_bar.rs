//! Emoji reaction bar for messages -- display, toggle, and publish NIP-25
//! kind-7 reactions (and NIP-09 kind-5 un-reacts).
//!
//! The bar is stateless: aggregated counts live in the shared
//! [`ReactionStore`](crate::stores::reactions::ReactionStore), which subscribes
//! to kind-7/kind-5 once at app root. Clicking publishes and optimistically
//! nudges the store, so the pill updates before the relay echo and converges
//! with everyone else's reactions on load.
//!
//! ## Picker affordance (user feedback, 2026-09)
//!
//! Two complaints landed here together:
//!
//! 1. *"Plus sign for emojis non standard, and non intuitive. Look at other
//!    examples such as slack"* -- the picker trigger was a bare `"+"` glyph,
//!    which reads as "add something" but never as "add a **reaction**". Every
//!    chat client the user has muscle memory for (Slack, Discord, GitHub,
//!    Messages) uses the same mark: a smiley face with a small plus at its
//!    corner. That is now an inline SVG below -- no icon library, no external
//!    asset, so it inherits `currentColor` and needs no CSS file change.
//! 2. *"Configurable / add your own emojis"* -- the picker now renders the
//!    viewer's own emoji from
//!    [`CustomEmojiStore`](crate::stores::custom_emoji) after the built-ins,
//!    with a compact add box and a per-emoji remove control. Custom emoji are
//!    ordinary NIP-25 kind-7 content strings, so they go through
//!    `toggle_reaction` unchanged.

use leptos::prelude::*;

use crate::auth::use_auth;
use crate::components::fx::reaction_burst::ReactionBurst;
use crate::relay::RelayConnection;
use crate::stores::custom_emoji::{use_custom_emoji_store, MAX_EMOJI_CHARS};
use crate::stores::reactions::use_reaction_store;

/// Common reaction emojis offered in the picker.
const REACTION_EMOJIS: &[&str] = &[
    "\u{1F44D}",
    "\u{2764}\u{FE0F}",
    "\u{1F602}",
    "\u{1F525}",
    "\u{1F389}",
    "\u{1F440}",
    "\u{1F4AF}",
    "\u{1F64C}",
];

/// A single emoji reaction on a message, aggregated across all reactors.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Reaction {
    pub emoji: String,
    pub count: u32,
    pub reacted_by_me: bool,
}

/// Display and toggle emoji reactions on a message.
///
/// Reads aggregated reactions from the [`ReactionStore`](crate::stores::reactions::ReactionStore)
/// and renders each emoji as a pill with a count. Clicking a pill toggles the
/// viewer's own reaction: adding publishes a kind-7 event; removing publishes a
/// kind-5 deletion of the viewer's earlier kind-7. An add-reaction button (the
/// conventional smiley-with-a-plus mark) opens a compact picker holding the
/// built-in emoji, the viewer's own custom emoji, and an add box.
#[component]
pub(crate) fn ReactionBar(
    /// The event ID of the message being reacted to.
    event_id: String,
    /// The pubkey of the message's author — the NIP-25 `p` tag on the kind-7
    /// reaction (notifies the author, per NIP-25). NOT the reactor's pubkey.
    #[prop(into)]
    author_pubkey: String,
) -> impl IntoView {
    let show_picker = RwSignal::new(false);

    // Store ids in StoredValue so the closures that capture them are Copy.
    let event_id_stored = StoredValue::new(event_id.clone());
    let author_pk_stored = StoredValue::new(author_pubkey);

    // Resolve contexts at component construction. Calling expect_context() /
    // use_auth() inside a click handler or spawn_local panics ("expected
    // context of type RelayConnection") because the reactive owner is gone by
    // event time, and that panic kills the whole WASM runtime. AuthStore and the
    // ReactionStore are Copy; RelayConnection is only Clone, so park it in a
    // StoredValue (Copy) and clone from there inside the handlers.
    let auth = use_auth();
    let relay_stored = StoredValue::new(expect_context::<RelayConnection>());
    let store = use_reaction_store();

    // The viewer's own emoji. `use_custom_emoji_store` self-provisions if the
    // app root never provided one, so a missing provider degrades to "no custom
    // emoji" instead of an `expect_context` panic that would kill the runtime
    // mid-message-list (see the note above about context at event time).
    let custom_store = use_custom_emoji_store();
    // Draft text for the add box. Held in a signal rather than read off a
    // NodeRef so both the button and the Enter key path see the same value.
    let emoji_draft = RwSignal::new(String::new());

    // Reactive, aggregated reactions for this event (all reactors, deduped).
    let reactions = store.reactions_for(&event_id);

    // Toggle the viewer's own `emoji` reaction on this message. Adding publishes
    // a kind-7; removing publishes a kind-5 deleting the viewer's prior kind-7.
    // Both paths update the store optimistically so the pill reacts instantly.
    let toggle_reaction = move |emoji: String| {
        let relay = relay_stored.get_value();
        let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
        if pubkey.is_empty() {
            return;
        }
        let target = event_id_stored.get_value();

        if store.has_my_reaction(&target, &emoji, &pubkey) {
            // Un-react: NIP-09 kind-5 deletion of the viewer's own kind-7.
            let Some(reaction_id) = store.my_reaction_id(&target, &emoji, &pubkey) else {
                return;
            };
            store.remove_local(&reaction_id);
            let now = (js_sys::Date::now() / 1000.0) as u64;
            let unsigned = nostr_bbs_core::UnsignedEvent {
                pubkey,
                created_at: now,
                kind: 5,
                tags: vec![vec!["e".to_string(), reaction_id]],
                content: String::new(),
            };
            wasm_bindgen_futures::spawn_local(async move {
                match auth.sign_event_async(unsigned).await {
                    Ok(signed) => relay.publish(&signed),
                    Err(e) => web_sys::console::error_1(
                        &format!("[ReactionBar] Un-react sign failed: {}", e).into(),
                    ),
                }
            });
        } else {
            // React: NIP-25 kind-7. The `p` tag is the reacted-to AUTHOR.
            let author = author_pk_stored.get_value();
            let now = (js_sys::Date::now() / 1000.0) as u64;
            let mut tags = vec![vec!["e".to_string(), target.clone()]];
            if !author.is_empty() {
                tags.push(vec!["p".to_string(), author]);
            }
            let unsigned = nostr_bbs_core::UnsignedEvent {
                pubkey: pubkey.clone(),
                created_at: now,
                kind: 7,
                tags,
                content: emoji.clone(),
            };
            wasm_bindgen_futures::spawn_local(async move {
                match auth.sign_event_async(unsigned).await {
                    Ok(signed) => {
                        // Record with the real signed id so a later un-react can
                        // address the kind-5; idempotent with the relay echo.
                        store.add_local(&signed.id, &target, &emoji, &pubkey);
                        relay.publish(&signed);
                    }
                    Err(e) => web_sys::console::error_1(
                        &format!("[ReactionBar] React sign failed: {}", e).into(),
                    ),
                }
            });
        }
    };

    // Commit whatever is in the add box. The store owns validation (trim,
    // reject empty/whitespace/over-long, dedupe, cap) -- we only clear the box
    // when it actually accepted something, so a rejected paste stays visible
    // and editable rather than silently vanishing.
    let add_custom_emoji = move || {
        let raw = emoji_draft.get_untracked();
        if custom_store.add(&raw) {
            emoji_draft.set(String::new());
        }
    };

    view! {
        <div class="flex items-center gap-1 flex-wrap mt-1">
            // Existing reaction pills
            <For
                each=move || reactions.get()
                key=|r| r.emoji.clone()
                let:reaction
            >
                {
                    let emoji = reaction.emoji.clone();
                    let emoji_for_click = emoji.clone();
                    let emoji_for_burst = emoji.clone();
                    let toggle = toggle_reaction;
                    let burst_trigger = RwSignal::new(false);
                    view! {
                        <div class="relative inline-flex">
                            <button
                                class=move || {
                                    let is_mine = reactions.get()
                                        .iter()
                                        .find(|r| r.emoji == emoji)
                                        .map(|r| r.reacted_by_me)
                                        .unwrap_or(false);
                                    if is_mine {
                                        "reaction-burst is-active inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-amber-500/15 border border-amber-500/30 hover:bg-amber-500/25 transition-colors cursor-pointer"
                                    } else {
                                        "reaction-burst inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-gray-700/50 border border-gray-600/50 hover:bg-gray-600/50 transition-colors cursor-pointer"
                                    }
                                }
                                on:click={
                                    let emoji_c = emoji_for_click.clone();
                                    let toggle_c = toggle;
                                    move |_| {
                                        // A burst plays only when ADDING a reaction.
                                        let adding = !reactions.get_untracked()
                                            .iter()
                                            .find(|r| r.emoji == emoji_c)
                                            .map(|r| r.reacted_by_me)
                                            .unwrap_or(false);
                                        toggle_c(emoji_c.clone());
                                        if adding {
                                            burst_trigger.set(false);
                                            burst_trigger.set(true);
                                        }
                                    }
                                }
                            >
                                <span>{reaction.emoji.clone()}</span>
                                <span class="text-gray-300 font-medium">{reaction.count}</span>
                            </button>
                            <ReactionBurst
                                trigger=Signal::from(burst_trigger)
                                particle_count=12
                                emoji=emoji_for_burst
                            />
                        </div>
                    }
                }
            </For>

            // Add-reaction affordance. The icon is the cross-app convention
            // (Slack/Discord/GitHub): a smiley with a small plus at its top-right
            // corner. Inline SVG rather than an icon font so it inherits
            // `currentColor` from the button's text colour and ships with zero
            // extra assets.
            //
            // REST STATE: Slack keeps this low-emphasis until you hover the
            // message. We deliberately DO NOT hide it (`opacity-0`) at rest:
            // there is no hover on a phone, and a `group-hover`-only affordance
            // is simply unreachable by touch. Tailwind has no way to express
            // "@media (hover: hover)" inline without a configured
            // `hover-hover:` variant, and this codebase has no such variant, so
            // the honest choice is: always visible, just dimmed
            // (`opacity-70`), brightening to full on hover AND on
            // `focus-visible` so keyboard users get the same signal. Opacity
            // alone means no reflow, so nothing shifts as it brightens.
            <div class="relative">
                <button
                    class="inline-flex items-center justify-center w-6 h-6 rounded-full text-gray-500 opacity-70 hover:opacity-100 hover:text-amber-400 hover:bg-gray-700/50 focus-visible:opacity-100 focus-visible:text-amber-400 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-amber-400/60 transition-all"
                    on:click=move |_| show_picker.update(|v| *v = !*v)
                    aria-label="Add reaction"
                    aria-haspopup="true"
                    aria-expanded=move || if show_picker.get() { "true" } else { "false" }
                    // Native tooltip: zero layout cost and it cannot overlap or
                    // shift anything, unlike a positioned tooltip span inside an
                    // already-dense message row.
                    title="Add reaction"
                >
                    <svg
                        xmlns="http://www.w3.org/2000/svg"
                        viewBox="0 0 20 20"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="1.6"
                        stroke-linecap="round"
                        class="w-4 h-4"
                        aria-hidden="true"
                        focusable="false"
                    >
                        // Face
                        <circle cx="9" cy="11" r="7.2"></circle>
                        // Eyes (filled dots -- stroke-none so the 1.6 stroke
                        // does not bloat them into blobs at 16px)
                        <circle cx="6.4" cy="9.2" r="0.95" fill="currentColor" stroke="none"></circle>
                        <circle cx="11.6" cy="9.2" r="0.95" fill="currentColor" stroke="none"></circle>
                        // Smile
                        <path d="M5.9 12.9a3.9 3.9 0 0 0 6.2 0"></path>
                        // The "add" plus, clear of the face at the top-right
                        <path d="M16.6 1.4v4.4M14.4 3.6h4.4"></path>
                    </svg>
                </button>

                <Show when=move || show_picker.get()>
                    // Popover, not a settings page: one wrapped row of built-ins,
                    // one wrapped row of the viewer's own, one add box. Width is
                    // bounded so a long custom list wraps instead of stretching
                    // the popover off-screen.
                    <div
                        class="absolute bottom-full left-0 mb-1 glass-card p-2 rounded-xl shadow-lg z-50 w-max max-w-[14rem]"
                        role="dialog"
                        aria-label="Add reaction"
                    >
                        <div class="flex gap-1 flex-wrap">
                            {REACTION_EMOJIS.iter().map(|&emoji| {
                                let emoji_static = emoji;
                                let toggle = toggle_reaction;
                                view! {
                                    <button
                                        class="emoji-btn text-base"
                                        on:click=move |_| {
                                            show_picker.set(false);
                                            toggle(emoji_static.to_string());
                                        }
                                    >
                                        {emoji_static}
                                    </button>
                                }
                            }).collect_view()}
                        </div>

                        // The viewer's own emoji, separated by a hairline so it
                        // is obvious which ones they own (and can remove).
                        <Show when=move || !custom_store.emojis().is_empty()>
                            <div class="flex gap-1 flex-wrap mt-1.5 pt-1.5 border-t border-gray-600/40">
                                <For
                                    each=move || custom_store.emojis()
                                    key=|e| e.clone()
                                    let:custom
                                >
                                    {
                                        let for_click = custom.clone();
                                        let for_remove = custom.clone();
                                        let for_label = custom.clone();
                                        let toggle = toggle_reaction;
                                        view! {
                                            <span class="relative inline-flex">
                                                <button
                                                    class="emoji-btn text-base"
                                                    on:click=move |_| {
                                                        show_picker.set(false);
                                                        toggle(for_click.clone());
                                                    }
                                                >
                                                    {custom.clone()}
                                                </button>
                                                // Remove control. Permanently
                                                // rendered (not hover-only) for the
                                                // same touch reason as the trigger
                                                // above; it is small and dimmed so
                                                // it stays out of the way, and it
                                                // sits on the corner so it never
                                                // reflows the emoji grid.
                                                <button
                                                    class="absolute -top-1 -right-1 w-3.5 h-3.5 inline-flex items-center justify-center rounded-full bg-gray-800 border border-gray-600/60 text-[9px] leading-none text-gray-400 opacity-80 hover:opacity-100 hover:text-red-400 focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-red-400/60 transition-opacity"
                                                    on:click=move |ev| {
                                                        // Do not let the click fall
                                                        // through to the emoji button
                                                        // behind it and publish a
                                                        // reaction we are deleting.
                                                        ev.stop_propagation();
                                                        custom_store.remove(&for_remove);
                                                    }
                                                    aria-label=move || format!("Remove {} from my emoji", for_label)
                                                    title="Remove"
                                                >
                                                    "\u{00D7}"
                                                </button>
                                            </span>
                                        }
                                    }
                                </For>
                            </div>
                        </Show>

                        // Add box: "Configurable / add your own emojis". A plain
                        // text input, because the OS emoji keyboard/picker is the
                        // right tool for choosing a glyph and we should not try to
                        // reimplement it inside a popover.
                        <div class="flex items-center gap-1 mt-1.5 pt-1.5 border-t border-gray-600/40">
                            <input
                                type="text"
                                class="w-20 px-1.5 py-0.5 rounded-md bg-gray-800/70 border border-gray-600/50 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-amber-500/60"
                                maxlength=MAX_EMOJI_CHARS.to_string()
                                placeholder="Add emoji"
                                aria-label="Add your own emoji"
                                prop:value=move || emoji_draft.get()
                                on:input=move |ev| emoji_draft.set(event_target_value(&ev))
                                on:keydown=move |ev| {
                                    if ev.key() == "Enter" {
                                        ev.prevent_default();
                                        add_custom_emoji();
                                    }
                                }
                            />
                            <button
                                class="px-1.5 py-0.5 rounded-md text-xs text-gray-300 bg-gray-700/60 hover:bg-amber-500/25 hover:text-amber-300 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-amber-400/60 transition-colors"
                                on:click=move |_| add_custom_emoji()
                                aria-label="Save emoji"
                                title="Save emoji"
                            >
                                "Add"
                            </button>
                        </div>
                    </div>
                </Show>
            </div>
        </div>
    }
}
