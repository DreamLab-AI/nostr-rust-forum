//! Emoji reaction bar for messages -- display, toggle, and publish NIP-25
//! kind-7 reactions (and NIP-09 kind-5 un-reacts).
//!
//! The bar is stateless: aggregated counts live in the shared
//! [`ReactionStore`](crate::stores::reactions::ReactionStore), which subscribes
//! to kind-7/kind-5 once at app root. Clicking publishes and optimistically
//! nudges the store, so the pill updates before the relay echo and converges
//! with everyone else's reactions on load.

use leptos::prelude::*;

use crate::auth::use_auth;
use crate::components::fx::reaction_burst::ReactionBurst;
use crate::relay::RelayConnection;
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
/// kind-5 deletion of the viewer's earlier kind-7. A "+" button opens a compact
/// picker for adding new reactions.
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

            // Add reaction button
            <div class="relative">
                <button
                    class="inline-flex items-center justify-center w-6 h-6 rounded-full text-gray-500 hover:text-amber-400 hover:bg-gray-700/50 transition-colors text-sm"
                    on:click=move |_| show_picker.update(|v| *v = !*v)
                    aria-label="Add reaction"
                >
                    "+"
                </button>

                <Show when=move || show_picker.get()>
                    <div class="absolute bottom-full left-0 mb-1 glass-card p-2 rounded-xl shadow-lg z-50">
                        <div class="flex gap-1">
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
                    </div>
                </Show>
            </div>
        </div>
    }
}
