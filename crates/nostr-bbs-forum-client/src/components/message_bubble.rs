//! Rich message bubble with mentions, media embeds, link previews, reactions,
//! bookmarks, report button, pin button, and threaded replies.

use leptos::prelude::*;

use crate::components::agent_badge::AgentBadge;
use crate::components::avatar::{Avatar, AvatarSize};
use crate::components::badge_display::BadgeBar;
use crate::components::bookmarks_modal::use_bookmarks;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::link_preview::LinkPreview;
use crate::components::media_embed::MediaEmbed;
use crate::components::mention_text::MentionText;
use crate::components::pinned_messages::PinButton;
use crate::components::quoted_message::QuotedMessage;
use crate::components::reaction_bar::{Reaction, ReactionBar};
use crate::components::report_button::ReportButton;
use crate::components::thread_view::{ThreadReply, ThreadView};
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::user_display::use_display_name_memo;
use crate::stores::badges::use_badges;
use crate::utils::format_relative_time;

/// Props for a single message in the channel view.
#[derive(Clone, Debug)]
pub struct MessageData {
    pub id: String,
    pub pubkey: String,
    pub content: String,
    pub created_at: u64,
    /// Reply-to event ID (from `e` tag with "reply" marker).
    pub reply_to_id: Option<String>,
    /// Reply-to author pubkey.
    pub reply_to_pubkey: Option<String>,
    /// Reply-to content (cached for display).
    pub reply_to_content: Option<String>,
    /// Reactive reactions list.
    pub reactions: RwSignal<Vec<Reaction>>,
    /// Whether this message has been hidden by moderation.
    pub is_hidden: bool,
    /// Channel ID this message belongs to (for pin/thread context).
    pub channel_id: String,
    /// Reactive list of threaded replies (kind-1111) to this message.
    pub thread_replies: RwSignal<Vec<ThreadReply>>,
}

/// Global context for opening a profile modal from any component.
#[derive(Clone, Copy)]
pub struct ProfileModalTarget(pub RwSignal<Option<String>>);

/// Provide the profile modal target context. Call once at app root.
pub fn provide_profile_modal_target() {
    provide_context(ProfileModalTarget(RwSignal::new(None)));
}

/// Display a rich message bubble with all interactive features.
///
/// Includes report button (TL1+), pin button (admin), and threaded
/// replies (kind-1111 NIP-22). Hidden messages show a placeholder instead.
#[component]
pub fn MessageBubble(message: MessageData) -> impl IntoView {
    // If hidden, render the placeholder instead
    if message.is_hidden {
        let eid = message.id.clone();
        return view! {
            <crate::components::hidden_message::HiddenMessage event_id=eid />
        }
        .into_any();
    }

    let time_display = format_relative_time(message.created_at);
    let bookmarks = use_bookmarks();
    let event_id = message.id.clone();
    let msg_pubkey = message.pubkey.clone();
    let content = message.content.clone();
    let pk_for_avatar = msg_pubkey.clone();
    let channel_id = message.channel_id.clone();
    let thread_replies = message.thread_replies;

    // Extract URLs from content for media embeds and link previews
    let urls = extract_urls(&content);
    let (media_urls, link_urls): (Vec<_>, Vec<_>) =
        urls.into_iter().partition(|url| is_media_url(url));
    let first_link_url = link_urls.into_iter().next();
    // Hide embedded media URLs from the visible text — the embed below carries
    // its own hover "open full" affordance, so the bare URL is just noise.
    let body_text = crate::components::mention_text::strip_media_urls(&content, &media_urls);

    // Bookmark toggle via StoredValue (Copy-friendly)
    let is_bookmarked = bookmarks.is_bookmarked_signal(event_id.clone());
    let eid_bm = StoredValue::new(event_id.clone());
    let content_bm = StoredValue::new(content.clone());
    let pk_bm = StoredValue::new(msg_pubkey.clone());
    let ts_bm = message.created_at;

    let toggle_bookmark = move |_: leptos::ev::MouseEvent| {
        let store = use_bookmarks();
        let eid = eid_bm.get_value();
        if store.is_bookmarked(&eid) {
            store.remove(&eid);
        } else {
            store.add(&eid, &content_bm.get_value(), &pk_bm.get_value(), ts_bm, "");
        }
    };

    // Profile modal trigger (avatar + name click)
    let pk_modal = StoredValue::new(msg_pubkey.clone());
    let on_avatar_click = move |_: leptos::ev::MouseEvent| {
        if let Some(ctx) = use_context::<ProfileModalTarget>() {
            ctx.0.set(Some(pk_modal.get_value()));
        }
    };
    let on_name_click = move |_: leptos::ev::MouseEvent| {
        if let Some(ctx) = use_context::<ProfileModalTarget>() {
            ctx.0.set(Some(pk_modal.get_value()));
        }
    };

    // Display name resolved through ProfileCache > NameCache > shortened pubkey.
    let display_name = use_display_name_memo(msg_pubkey.clone());

    // Disclosure badge (COM-13/F2): marks this author as an agent and names the
    // authorising principal when the pubkey is active in the agent registry.
    let pk_for_agent_badge = msg_pubkey.clone();
    // Badge IDs for this message's author (from the shared badge store)
    let pk_for_badges = msg_pubkey.clone();
    let author_badge_ids = Signal::derive(move || {
        let store = use_badges();
        // If we're viewing our own messages, use the pre-fetched badge store
        // For other users, return empty (badges shown on profile page instead)
        let auth_pk = crate::auth::use_auth().pubkey().get_untracked();
        if auth_pk.as_deref() == Some(&pk_for_badges) {
            store
                .badges
                .get()
                .iter()
                .map(|b| b.badge_id.clone())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    });

    // Reply info
    let has_reply = message.reply_to_id.is_some();
    let reply_id = message.reply_to_id.unwrap_or_default();
    let reply_pk = message.reply_to_pubkey.unwrap_or_default();
    let reply_content = message.reply_to_content.unwrap_or_default();

    let event_id_attr = event_id.clone();
    let event_id_react = event_id.clone();
    let event_id_report = event_id.clone();
    let event_id_pin = event_id.clone();
    let event_id_delete = event_id.clone();
    let event_id_thread = event_id.clone();
    let pk_report = msg_pubkey.clone();
    let pk_delete = msg_pubkey.clone();
    let pk_thread = msg_pubkey.clone();
    let channel_id_pin = channel_id.clone();
    let channel_id_thread = channel_id;

    view! {
        <div
            class="flex gap-3 py-2 px-2 hover:bg-gray-800/30 rounded-lg transition-colors group"
            data-event-id=event_id_attr
        >
            // Avatar (clickable)
            <div class="flex-shrink-0 mt-0.5 cursor-pointer" on:click=on_avatar_click>
                <Avatar pubkey=pk_for_avatar size=AvatarSize::Md />
            </div>

            // Content column
            <div class="flex-1 min-w-0">
                // Author + time + action buttons
                <div class="flex items-baseline gap-2">
                    <span
                        class="font-semibold text-sm text-amber-400 cursor-pointer hover:text-amber-300 transition-colors"
                        on:click=on_name_click
                    >
                        {move || display_name.get()}
                    </span>
                    <BadgeBar badge_ids=author_badge_ids max=3 />
                    <AgentBadge pubkey=pk_for_agent_badge compact=true />
                    <span class="text-xs text-gray-600 opacity-0 group-hover:opacity-100 transition-opacity">
                        {time_display}
                    </span>
                    // Action buttons (appear on hover)
                    <div class="flex items-center gap-0.5 ml-auto">
                        // Pin button (admin only)
                        <PinButton channel_id=channel_id_pin event_id=event_id_pin />
                        // Delete button (author or admin)
                        <DeleteMessageButton event_id=event_id_delete pubkey=pk_delete />
                        // Report button (TL1+)
                        <ReportButton event_id=event_id_report reported_pubkey=pk_report />
                        // Bookmark button
                        <button
                            class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 rounded hover:bg-gray-700/50"
                            title=move || if is_bookmarked.get() { "Remove bookmark" } else { "Bookmark" }
                            on:click=toggle_bookmark
                        >
                            <svg
                                class=move || if is_bookmarked.get() {
                                    "w-3.5 h-3.5 text-amber-400"
                                } else {
                                    "w-3.5 h-3.5 text-gray-600 hover:text-gray-400"
                                }
                                viewBox="0 0 24 24"
                                fill=move || if is_bookmarked.get() { "currentColor" } else { "none" }
                                stroke="currentColor"
                                stroke-width="2"
                            >
                                <path d="M5 2h14a1 1 0 011 1v19.143a.5.5 0 01-.766.424L12 18.03l-7.234 4.536A.5.5 0 014 22.143V3a1 1 0 011-1z"/>
                            </svg>
                        </button>
                    </div>
                </div>

                // Quoted/reply message
                {has_reply.then(|| view! {
                    <QuotedMessage
                        reply_to_id=reply_id.clone()
                        reply_to_pubkey=reply_pk.clone()
                        reply_to_content=reply_content.clone()
                    />
                })}

                // Message text with mentions + markdown (media URLs stripped)
                {(!body_text.is_empty()).then(|| view! {
                    <div class="mt-0.5 text-sm text-gray-200 leading-relaxed">
                        <MentionText content=body_text />
                    </div>
                })}

                // Media embeds (images, YouTube)
                {media_urls.into_iter().map(|url| {
                    view! { <MediaEmbed url=url /> }
                }).collect_view()}

                // Link preview (first non-media URL only)
                {first_link_url.map(|url| view! {
                    <LinkPreview url=url />
                })}

                // Reaction bar
                <ReactionBar
                    event_id=event_id_react
                    reactions=message.reactions
                />

                // Threaded replies (NIP-22 kind-1111). Threading is one level
                // deep: a message that is itself a reply (`has_reply`) shows its
                // thread but offers no reply affordance, so a second-level reply
                // (a reply to a reply) can never be started.
                <ThreadView
                    root_event_id=channel_id_thread
                    parent_event_id=event_id_thread
                    parent_pubkey=pk_thread
                    replies=thread_replies
                    allow_reply=!has_reply
                />
            </div>
        </div>
    }
    .into_any()
}

/// Author-or-admin delete affordance for a chat message.
///
/// Publishes a NIP-09 kind-5 deletion; the shared [`ChannelStore`] folds it out
/// on the relay echo (kind-5 fold) and we optimistically remove on OK so the
/// actor never waits. Visibility is gated to the message author or an admin;
/// the relay is the real boundary (own posts always; others' posts admin/TL3+).
#[component]
fn DeleteMessageButton(
    #[prop(into)] event_id: String,
    #[prop(into)] pubkey: String,
) -> impl IntoView {
    let can_delete = {
        let pubkey = pubkey.clone();
        Signal::derive(move || {
            let is_admin = use_context::<crate::stores::zone_access::ZoneAccess>()
                .map(|za| za.is_admin.get())
                .unwrap_or(false);
            let mine = crate::auth::use_auth().pubkey().get().unwrap_or_default();
            is_admin || (!mine.is_empty() && mine.eq_ignore_ascii_case(&pubkey))
        })
    };
    let show_confirm = RwSignal::new(false);
    let eid = StoredValue::new(event_id);

    // Context lookups happen inside the confirm handler (mirrors PinButton) so a
    // bubble rendered without a relay never panics at render time.
    let on_confirm = Callback::new(move |()| {
        let relay = expect_context::<crate::relay::RelayConnection>();
        let auth = crate::auth::use_auth();
        let toasts = use_toasts();
        let store = crate::stores::channels::use_channel_store();
        let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
        if pubkey.is_empty() {
            return;
        }
        let now = (js_sys::Date::now() / 1000.0) as u64;
        let target = eid.get_value();
        let unsigned = nostr_bbs_core::UnsignedEvent {
            pubkey,
            created_at: now,
            kind: 5,
            tags: vec![vec!["e".to_string(), target.clone()]],
            content: String::new(),
        };
        wasm_bindgen_futures::spawn_local(async move {
            match auth.sign_event_async(unsigned).await {
                Ok(signed) => {
                    let on_ok = std::rc::Rc::new(move |accepted: bool, message: String| {
                        if accepted {
                            store.remove_message(&target);
                            toasts.show("Message deleted", ToastVariant::Success);
                        } else {
                            let reason = if message.trim().is_empty() {
                                "Delete rejected by relay".to_string()
                            } else {
                                format!("Delete rejected: {message}")
                            };
                            toasts.show(reason, ToastVariant::Error);
                        }
                    });
                    if let Err(e) = relay.publish_with_ack(&signed, Some(on_ok)) {
                        toasts.show(format!("Delete failed: {e}"), ToastVariant::Error);
                    }
                }
                Err(e) => {
                    toasts.show(format!("Failed to sign deletion: {e}"), ToastVariant::Error);
                }
            }
        });
    });

    view! {
        <Show when=move || can_delete.get()>
            <button
                class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 rounded hover:bg-gray-700/50 text-gray-600 hover:text-red-400"
                aria-label="Delete message"
                on:click=move |_: leptos::ev::MouseEvent| show_confirm.set(true)
            >
                <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2m2 0v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6M10 11v6M14 11v6" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </button>
            <ConfirmDialog
                is_open=show_confirm
                title="Delete message".to_string()
                message="Delete this message? This is permanent and removes it for everyone.".to_string()
                confirm_label="Delete".to_string()
                on_confirm=on_confirm
            />
        </Show>
    }
}

/// Extract URLs from text content.
fn extract_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for word in text.split_whitespace() {
        let trimmed = word.trim_matches(|c: char| {
            c == '(' || c == ')' || c == '[' || c == ']' || c == '<' || c == '>' || c == ','
        });
        if (trimmed.starts_with("https://") || trimmed.starts_with("http://")) && trimmed.len() > 10
        {
            urls.push(trimmed.to_string());
        }
    }
    urls
}

/// Check if a URL points to a media resource (image or YouTube).
fn is_media_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    let path = lower.split('?').next().unwrap_or(&lower);
    let image_exts = [".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"];
    for ext in &image_exts {
        if path.ends_with(ext) {
            return true;
        }
    }
    lower.contains("youtube.com/watch") || lower.contains("youtu.be/")
}
