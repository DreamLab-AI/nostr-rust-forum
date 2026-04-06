//! Emoji reaction bar for messages -- display, toggle, and publish kind 7 reactions.

use leptos::prelude::*;

use crate::auth::use_auth;
use crate::components::fx::reaction_burst::ReactionBurst;
use crate::relay::RelayConnection;

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

/// A single emoji reaction on a message.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Reaction {
    pub emoji: String,
    pub count: u32,
    pub reacted_by_me: bool,
}

/// Display and toggle emoji reactions on a message.
///
/// Shows existing reactions as pills with count. Clicking a pill toggles
/// the reaction (publishes a kind 7 event via the relay). A "+" button
/// opens a compact picker for adding new reactions.
#[component]
pub(crate) fn ReactionBar(
    /// The event ID of the message being reacted to.
    event_id: String,
    /// Reactive list of reactions on this message.
    reactions: RwSignal<Vec<Reaction>>,
) -> impl IntoView {
    let show_picker = RwSignal::new(false);

    // Store event_id in StoredValue so closures that capture it are Copy.
    let event_id_stored = StoredValue::new(event_id);

    let toggle_reaction = move |emoji: String| {
        let relay = expect_context::<RelayConnection>();
        let auth = use_auth();
        let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
        if pubkey.is_empty() {
            return;
        }

        // Toggle local state
        reactions.update(|list| {
            if let Some(r) = list.iter_mut().find(|r| r.emoji == emoji) {
                if r.reacted_by_me {
                    r.count = r.count.saturating_sub(1);
                    r.reacted_by_me = false;
                } else {
                    r.count += 1;
                    r.reacted_by_me = true;
                }
                if r.count == 0 {
                    list.retain(|r| r.count > 0);
                }
            } else {
                list.push(Reaction {
                    emoji: emoji.clone(),
                    count: 1,
                    reacted_by_me: true,
                });
            }
        });

        // Publish kind 7 reaction event
        let eid = event_id_stored.get_value();
        let now = (js_sys::Date::now() / 1000.0) as u64;
        let unsigned = nostr_core::UnsignedEvent {
            pubkey: pubkey.clone(),
            created_at: now,
            kind: 7,
            tags: vec![vec!["e".to_string(), eid], vec!["p".to_string(), pubkey]],
            content: emoji,
        };

        let relay = relay.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match auth.sign_event_async(unsigned).await {
                Ok(signed) => { let _ = relay.publish(&signed); }
                Err(e) => {
                    web_sys::console::error_1(&format!("[ReactionBar] Sign failed: {}", e).into());
                }
            }
        });
    };

    let add_from_picker = move |emoji: &'static str| {
        show_picker.set(false);
        let relay = expect_context::<RelayConnection>();
        let auth = use_auth();
        let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
        if pubkey.is_empty() {
            return;
        }

        // Update local state
        reactions.update(|list| {
            if let Some(r) = list.iter_mut().find(|r| r.emoji == emoji) {
                if !r.reacted_by_me {
                    r.count += 1;
                    r.reacted_by_me = true;
                }
            } else {
                list.push(Reaction {
                    emoji: emoji.to_string(),
                    count: 1,
                    reacted_by_me: true,
                });
            }
        });

        // Publish kind 7
        let eid = event_id_stored.get_value();
        let now = (js_sys::Date::now() / 1000.0) as u64;
        let unsigned = nostr_core::UnsignedEvent {
            pubkey: pubkey.clone(),
            created_at: now,
            kind: 7,
            tags: vec![vec!["e".to_string(), eid], vec!["p".to_string(), pubkey]],
            content: emoji.to_string(),
        };

        wasm_bindgen_futures::spawn_local(async move {
            match auth.sign_event_async(unsigned).await {
                Ok(signed) => { let _ = relay.publish(&signed); }
                Err(e) => {
                    web_sys::console::error_1(&format!("[ReactionBar] Sign failed: {}", e).into());
                }
            }
        });
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
                                    let r = reactions.get().iter().find(|r| r.emoji == emoji).cloned();
                                    let is_mine = r.as_ref().map(|r| r.reacted_by_me).unwrap_or(false);
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
                    title="Add reaction"
                >
                    "+"
                </button>

                <Show when=move || show_picker.get()>
                    <div class="absolute bottom-full left-0 mb-1 glass-card p-2 rounded-xl shadow-lg z-50">
                        <div class="flex gap-1">
                            {REACTION_EMOJIS.iter().map(|&emoji| {
                                let emoji_static = emoji;
                                view! {
                                    <button
                                        class="emoji-btn text-base"
                                        on:click=move |_| add_from_picker(emoji_static)
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
