//! Admin modal for renaming a section (channel) and editing its description.
//!
//! Publishes a kind-41 channel-metadata event whose content is the NIP-28
//! metadata JSON (`{"name","about"[,"picture"]}`) and whose tags mirror the
//! kind-40 shape (`["e", <channel_id>, "", "root"]` + `["section", <section>]`)
//! so downstream filtering stays consistent. The relay gates who may write
//! kind-41 (TL2 for own channel, TL3/admin for any); on echo the shared
//! [`ChannelStore`](crate::stores::channels::ChannelStore) folds the edit into
//! its live channel list. Admin-only — the caller renders the trigger behind
//! [`ZoneAccess::is_admin`](crate::stores::zone_access::ZoneAccess).

use leptos::prelude::*;

use crate::auth::use_auth;
use crate::components::modal::Modal;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::relay::{ConnectionState, RelayConnection};

/// Name cap matches the New-Topic title cap; description cap is a sensible
/// two-line limit for a section blurb.
const MAX_NAME: usize = 80;
const MAX_ABOUT: usize = 280;

/// Modal that edits a section's name and description via a kind-41 event.
#[component]
pub fn ChannelEditModal(
    /// Controls visibility; the modal sets it to `false` on close/save.
    is_open: RwSignal<bool>,
    /// kind-40 channel event id being edited.
    #[prop(into)]
    channel_id: String,
    /// Section slug to mirror onto the kind-41 (keeps the metadata edit tagged
    /// like the kind-40 it amends). Empty when the channel has no section tag.
    #[prop(into)]
    section: String,
    /// Existing picture URL to preserve across the edit (empty when none).
    #[prop(into)]
    picture: String,
    /// Current name, used to prefill the field.
    #[prop(into)]
    initial_name: String,
    /// Current description, used to prefill the field.
    #[prop(into)]
    initial_description: String,
) -> impl IntoView {
    let name = RwSignal::new(initial_name);
    let description = RwSignal::new(initial_description);
    let saving = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);

    // Stable, cheaply-copyable captures for the async save closure.
    let cid = StoredValue::new(channel_id);
    let section = StoredValue::new(section);
    let picture = StoredValue::new(picture);

    let on_save = move |_: leptos::ev::MouseEvent| {
        let new_name = name.get_untracked().trim().to_string();
        let new_about = description.get_untracked().trim().to_string();
        if new_name.is_empty() {
            error.set(Some("Name can't be empty".into()));
            return;
        }
        if new_name.chars().count() > MAX_NAME {
            error.set(Some(format!("Name must be {MAX_NAME} characters or fewer")));
            return;
        }
        if new_about.chars().count() > MAX_ABOUT {
            error.set(Some(format!(
                "Description must be {MAX_ABOUT} characters or fewer"
            )));
            return;
        }

        let relay = expect_context::<RelayConnection>();
        if relay.connection_state().get_untracked() != ConnectionState::Connected {
            error.set(Some("Relay not connected — try again in a moment".into()));
            return;
        }
        let auth = use_auth();
        let Some(pubkey) = auth.pubkey().get_untracked() else {
            error.set(Some("Not signed in".into()));
            return;
        };

        saving.set(true);
        error.set(None);

        // NIP-28 metadata content; preserve the existing `picture` key so a
        // rename doesn't drop the channel's avatar.
        let mut content = serde_json::Map::new();
        content.insert("name".into(), serde_json::Value::String(new_name));
        content.insert("about".into(), serde_json::Value::String(new_about));
        let pic = picture.get_value();
        if !pic.is_empty() {
            content.insert("picture".into(), serde_json::Value::String(pic));
        }
        let content = serde_json::Value::Object(content).to_string();

        // Mirror the kind-40 tag shape: NIP-10 root marker + section tag.
        let now = (js_sys::Date::now() / 1000.0) as u64;
        let mut tags = vec![vec![
            "e".to_string(),
            cid.get_value(),
            String::new(),
            "root".to_string(),
        ]];
        let sec = section.get_value();
        if !sec.is_empty() {
            tags.push(vec!["section".to_string(), sec]);
        }

        let unsigned = nostr_bbs_core::UnsignedEvent {
            pubkey,
            created_at: now,
            kind: 41,
            tags,
            content,
        };

        // Capture reactive handles for the OK/err callbacks (all `Copy`).
        let toasts = use_toasts();
        let saving_sig = saving;
        let error_sig = error;
        let open_sig = is_open;

        wasm_bindgen_futures::spawn_local(async move {
            match auth.sign_event_async(unsigned).await {
                Ok(signed) => {
                    // The store folds the edit when the relay echoes the 41, so
                    // there's no optimistic local mutation here — the echo is the
                    // single source of truth.
                    let on_ok = std::rc::Rc::new(move |accepted: bool, msg: String| {
                        saving_sig.set(false);
                        if accepted {
                            open_sig.set(false);
                            toasts.show("Section updated".to_string(), ToastVariant::Success);
                        } else {
                            let display = if msg.contains("whitelist") {
                                "Your account isn't active yet — try refreshing the page."
                                    .to_string()
                            } else if msg.trim().is_empty() {
                                "Update rejected by relay".to_string()
                            } else {
                                format!("Update rejected: {msg}")
                            };
                            error_sig.set(Some(display));
                        }
                    });
                    if let Err(e) = relay.publish_with_ack(&signed, Some(on_ok)) {
                        saving_sig.set(false);
                        error_sig.set(Some(format!("Send failed: {e}")));
                    }
                }
                Err(e) => {
                    saving_sig.set(false);
                    error_sig.set(Some(format!("Signing failed: {e}")));
                }
            }
        });
    };

    view! {
        <Modal is_open=is_open title="Edit section".to_string() max_width="480px".to_string()>
            <div class="space-y-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Name"</label>
                    <input
                        type="text"
                        maxlength=MAX_NAME.to_string()
                        placeholder="Section name"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev))
                        class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Description"</label>
                    <textarea
                        maxlength=MAX_ABOUT.to_string()
                        rows="3"
                        placeholder="What this section is about"
                        prop:value=move || description.get()
                        on:input=move |ev| description.set(event_target_value(&ev))
                        class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 resize-none"
                    ></textarea>
                </div>
                {move || error.get().map(|e| view! {
                    <p class="text-red-400 text-sm">{e}</p>
                })}
                <div class="flex gap-2 justify-end">
                    <button
                        type="button"
                        on:click=move |_| is_open.set(false)
                        class="text-gray-400 hover:text-white px-3 py-2 text-sm transition-colors"
                    >
                        "Cancel"
                    </button>
                    <button
                        type="button"
                        disabled=move || saving.get()
                        on:click=on_save
                        class="bg-amber-500 hover:bg-amber-400 disabled:bg-gray-600 disabled:cursor-not-allowed text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors text-sm"
                    >
                        {move || if saving.get() { "Saving..." } else { "Save" }}
                    </button>
                </div>
            </div>
        </Modal>
    }
}
