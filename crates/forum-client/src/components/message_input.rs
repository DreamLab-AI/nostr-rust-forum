//! Rich message compose box with markdown preview, emoji picker, character counter,
//! and draft auto-save (debounced 2s to localStorage).

use leptos::prelude::*;
use wasm_bindgen::JsCast;

use crate::components::draft_indicator::{clear_draft, load_draft, save_draft, DraftIndicator};
use crate::utils::image_compress::{is_accepted_image, MAX_FILE_SIZE};

/// Pending image attachment for preview before sending.
#[derive(Clone, Debug)]
struct ImageAttachment {
    file: web_sys::File,
    data_url: String,
    name: String,
}

/// Maximum message length in characters.
const MAX_CHARS: usize = 4096;

/// Common emojis for the quick picker.
const EMOJIS: &[&str] = &[
    "\u{1F44D}",
    "\u{2764}\u{FE0F}",
    "\u{1F602}",
    "\u{1F525}",
    "\u{1F389}",
    "\u{1F440}",
    "\u{1F4AF}",
    "\u{1F64C}",
    "\u{1F60D}",
    "\u{1F914}",
    "\u{1F44F}",
    "\u{1F680}",
    "\u{2728}",
    "\u{1F60E}",
    "\u{1F64F}",
    "\u{1F631}",
    "\u{1F60A}",
    "\u{1F4A1}",
    "\u{1F3AF}",
    "\u{1F48E}",
    "\u{1F30E}",
    "\u{1F4AC}",
    "\u{1F4AA}",
    "\u{1F308}",
];

/// Rich message input with markdown preview, emoji picker, and character counter.
///
/// - Textarea auto-grows as content is typed
/// - Shift+Enter inserts a newline; Enter sends
/// - Character counter (max 4096)
/// - Markdown preview toggle (rendered via comrak)
/// - Emoji picker popup
/// - Send button with amber glow, disabled when empty
#[component]
pub(crate) fn MessageInput(
    /// Callback fired with the message text when the user sends.
    on_send: Callback<String>,
    /// Placeholder text shown in the empty textarea.
    #[prop(default = "Type a message...")]
    placeholder: &'static str,
    /// Optional callback fired on every keystroke (for typing indicators).
    #[prop(optional)]
    on_typing: Option<Callback<()>>,
    /// Optional channel ID for draft persistence. When set, content is auto-saved
    /// to localStorage every 2 seconds and restored on mount.
    #[prop(optional, into)]
    channel_id: Option<String>,
    /// Optional callback fired when an image file is attached for upload.
    /// The parent component handles compression + upload (channel or DM context).
    #[prop(optional)]
    on_image_attach: Option<Callback<web_sys::File>>,
) -> impl IntoView {
    let content = RwSignal::new(String::new());
    let file_input_ref = NodeRef::<leptos::html::Input>::new();
    let attachment = RwSignal::new(Option::<ImageAttachment>::None);
    let has_image_support = on_image_attach.is_some();

    // -- Draft persistence ------------------------------------------------
    let cid_for_draft = channel_id.clone();
    let has_draft = Memo::new({
        let cid = channel_id.clone();
        move |_| {
            if cid.is_none() {
                return false;
            }
            !content.get().trim().is_empty()
        }
    });

    // Restore draft on mount
    if let Some(ref cid) = channel_id {
        if let Some(draft) = load_draft(cid) {
            content.set(draft);
        }
    }

    // Debounced auto-save: save draft 2s after last edit
    let draft_timer: RwSignal<Option<i32>> = RwSignal::new(None);
    let schedule_draft_save = {
        let cid = channel_id.clone();
        move || {
            let Some(ref cid) = cid else { return };
            // Clear previous timer
            if let Some(tid) = draft_timer.get_untracked() {
                if let Some(w) = web_sys::window() {
                    w.clear_timeout_with_handle(tid);
                }
            }
            let cid_inner = cid.clone();
            let cb = wasm_bindgen::closure::Closure::wrap(Box::new(move || {
                let text = content.get_untracked();
                save_draft(&cid_inner, &text);
            }) as Box<dyn FnMut()>);
            if let Some(w) = web_sys::window() {
                if let Ok(tid) = w.set_timeout_with_callback_and_timeout_and_arguments_0(
                    cb.as_ref().unchecked_ref(),
                    2000,
                ) {
                    draft_timer.set(Some(tid));
                }
            }
            cb.forget();
        }
    };

    let show_preview = RwSignal::new(false);
    let show_emoji = RwSignal::new(false);
    let textarea_ref = NodeRef::<leptos::html::Textarea>::new();

    let char_count = move || content.get().len();
    let is_empty = move || content.get().trim().is_empty() && attachment.get().is_none();
    let is_over_limit = move || char_count() > MAX_CHARS;

    // Auto-resize textarea to fit content
    let resize_textarea = move || {
        if let Some(el) = textarea_ref.get() {
            let el: web_sys::HtmlElement = el.into();
            el.style().set_property("height", "auto").ok();
            let scroll_h = el.scroll_height();
            let clamped = scroll_h.clamp(44, 200);
            el.style()
                .set_property("height", &format!("{}px", clamped))
                .ok();
        }
    };

    let draft_saver = StoredValue::new(schedule_draft_save.clone());
    let on_input = Callback::new(move |ev: leptos::ev::Event| {
        let target = ev.target().unwrap();
        let textarea: web_sys::HtmlTextAreaElement = target.unchecked_into();
        content.set(textarea.value());
        resize_textarea();
        if let Some(cb) = on_typing {
            cb.run(());
        }
        draft_saver.with_value(|f| f());
    });

    let cid_for_clear = StoredValue::new(cid_for_draft.clone());
    let do_send = Callback::new(move |()| {
        // Fire image attachment callback if present
        if let Some(att) = attachment.get_untracked() {
            if let Some(cb) = on_image_attach {
                cb.run(att.file);
            }
            attachment.set(None);
        }
        let text = content.get_untracked();
        let text = text.trim().to_string();
        if !text.is_empty() && text.len() <= MAX_CHARS {
            on_send.run(text);
        }
        content.set(String::new());
        show_preview.set(false);
        // Clear draft on send
        cid_for_clear.with_value(|cid_opt| {
            if let Some(ref cid) = cid_opt {
                clear_draft(cid);
            }
        });
        // Reset textarea height
        if let Some(el) = textarea_ref.get() {
            let el: web_sys::HtmlElement = el.into();
            el.style().set_property("height", "auto").ok();
        }
    });

    let on_keydown = Callback::new(move |ev: leptos::ev::KeyboardEvent| {
        if ev.key() == "Enter" && !ev.shift_key() {
            ev.prevent_default();
            do_send.run(());
        }
    });

    let insert_emoji = move |emoji: &'static str| {
        content.update(|c| c.push_str(emoji));
        show_emoji.set(false);
        // Re-focus textarea
        if let Some(el) = textarea_ref.get() {
            let el: web_sys::HtmlElement = el.into();
            let _ = el.focus();
        }
    };

    // Handle image file selection for attachment
    let on_image_selected = move |ev: leptos::ev::Event| {
        let input: web_sys::HtmlInputElement = ev.target().unwrap().unchecked_into();
        if let Some(files) = input.files() {
            if let Some(file) = files.get(0) {
                if !is_accepted_image(&file) {
                    return;
                }
                if file.size() as u64 > MAX_FILE_SIZE {
                    return;
                }
                let fname = file.name();
                let file_clone = file.clone();
                if let Ok(reader) = web_sys::FileReader::new() {
                    let onload = wasm_bindgen::closure::Closure::wrap(Box::new(
                        move |ev: web_sys::Event| {
                            let r: web_sys::FileReader = ev.target().unwrap().unchecked_into();
                            if let Ok(res) = r.result() {
                                if let Some(url) = res.as_string() {
                                    attachment.set(Some(ImageAttachment {
                                        file: file_clone.clone(),
                                        data_url: url,
                                        name: fname.clone(),
                                    }));
                                }
                            }
                        },
                    )
                        as Box<dyn FnMut(web_sys::Event)>);
                    reader.set_onload(Some(onload.as_ref().unchecked_ref()));
                    let _ = reader.read_as_data_url(&file);
                    onload.forget();
                }
            }
        }
        input.set_value("");
    };

    let open_file_picker = move |_| {
        if let Some(el) = file_input_ref.get() {
            let el: web_sys::HtmlElement = el.into();
            el.click();
        }
    };

    let clear_attachment = move |_| {
        attachment.set(None);
    };

    // Render markdown preview via sanitized comrak
    let preview_html = move || {
        let raw = content.get();
        if raw.trim().is_empty() {
            return "<p class=\"text-gray-500 italic\">Nothing to preview</p>".to_string();
        }
        crate::utils::sanitize::sanitize_markdown(&raw)
    };

    let counter_class = move || {
        let count = char_count();
        if count > MAX_CHARS {
            "text-xs text-red-400 font-medium"
        } else if count > MAX_CHARS - 200 {
            "text-xs text-amber-400"
        } else {
            "text-xs text-gray-500"
        }
    };

    view! {
        <div class="glass-card p-3 rounded-2xl relative">
            // Hidden file input for image attachment
            {if has_image_support {
                Some(view! {
                    <input
                        node_ref=file_input_ref
                        type="file"
                        accept="image/jpeg,image/png,image/webp,image/gif"
                        class="hidden"
                        on:change=on_image_selected
                    />
                })
            } else {
                None
            }}

            // Image attachment preview
            {move || {
                attachment.get().map(|att| view! {
                    <div class="mb-2 flex items-start gap-2 p-2 bg-gray-800/60 rounded-xl border border-gray-700/50">
                        <img
                            src=att.data_url.clone()
                            alt="Attachment preview"
                            class="w-16 h-16 object-cover rounded-lg border border-gray-600/50"
                        />
                        <div class="flex-1 min-w-0">
                            <p class="text-xs text-gray-400 truncate">{att.name.clone()}</p>
                            <p class="text-[10px] text-gray-600">"Will be compressed & uploaded"</p>
                        </div>
                        <button
                            class="p-1 text-gray-500 hover:text-red-400 transition-colors flex-shrink-0"
                            on:click=clear_attachment
                            title="Remove attachment"
                        >
                            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round"/>
                                <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round"/>
                            </svg>
                        </button>
                    </div>
                })
            }}

            // Preview area
            <Show when=move || show_preview.get()>
                <div class="mb-2 p-3 bg-gray-800/60 rounded-xl border border-gray-700/50 max-h-48 overflow-y-auto">
                    <div
                        class="prose prose-invert prose-sm max-w-none text-gray-200"
                        inner_html=preview_html
                    />
                </div>
            </Show>

            // Textarea
            <Show when=move || !show_preview.get()>
                <textarea
                    node_ref=textarea_ref
                    class="w-full bg-transparent text-white placeholder-gray-500 resize-none focus:outline-none focus:ring-1 focus:ring-amber-400 rounded-xl p-3 text-sm leading-relaxed min-h-[44px] max-h-[200px]"
                    placeholder=placeholder
                    prop:value=move || content.get()
                    on:input=move |ev| on_input.run(ev)
                    on:keydown=move |ev| on_keydown.run(ev)
                    rows="1"
                    aria-label="Message input"
                    aria-multiline="true"
                />
            </Show>

            // Bottom toolbar
            <div class="flex items-center justify-between mt-1.5 px-1">
                <div class="flex items-center gap-1">
                    // Markdown preview toggle
                    <button
                        class=move || {
                            if show_preview.get() {
                                "p-1.5 rounded-lg text-amber-400 bg-amber-400/10 transition-colors"
                            } else {
                                "p-1.5 rounded-lg text-gray-500 hover:text-gray-300 hover:bg-gray-700/50 transition-colors"
                            }
                        }
                        on:click=move |_| show_preview.update(|v| *v = !*v)
                        title="Toggle markdown preview"
                    >
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M2 4h20v16H2z" stroke-linecap="round" stroke-linejoin="round"/>
                            <path d="M6 12l2-2v4m4-6l2 3 2-3m2 0v3l2 3" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </button>

                    // Emoji picker toggle
                    <div class="relative">
                        <button
                            class=move || {
                                if show_emoji.get() {
                                    "p-1.5 rounded-lg text-amber-400 bg-amber-400/10 transition-colors"
                                } else {
                                    "p-1.5 rounded-lg text-gray-500 hover:text-gray-300 hover:bg-gray-700/50 transition-colors"
                                }
                            }
                            on:click=move |_| show_emoji.update(|v| *v = !*v)
                            title="Emoji picker"
                        >
                            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"/>
                                <path d="M8 14s1.5 2 4 2 4-2 4-2" stroke-linecap="round"/>
                                <line x1="9" y1="9" x2="9.01" y2="9"/>
                                <line x1="15" y1="9" x2="15.01" y2="9"/>
                            </svg>
                        </button>

                        // Emoji popup
                        <Show when=move || show_emoji.get()>
                            <div class="absolute bottom-full left-0 mb-2 glass-card p-2 rounded-xl shadow-lg z-50 w-64">
                                <div class="emoji-grid">
                                    {EMOJIS.iter().map(|&emoji| {
                                        let emoji_static = emoji;
                                        view! {
                                            <button
                                                class="emoji-btn"
                                                on:click=move |_| insert_emoji(emoji_static)
                                            >
                                                {emoji_static}
                                            </button>
                                        }
                                    }).collect_view()}
                                </div>
                            </div>
                        </Show>
                    </div>

                    // Image attachment button (paperclip)
                    {if has_image_support {
                        Some(view! {
                            <button
                                class="p-1.5 rounded-lg text-gray-500 hover:text-gray-300 hover:bg-gray-700/50 transition-colors"
                                on:click=open_file_picker
                                title="Attach image"
                                aria-label="Attach image"
                            >
                                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </button>
                        })
                    } else {
                        None
                    }}
                </div>

                <div class="flex items-center gap-2">
                    // Draft indicator
                    {channel_id.clone().map(|cid| view! {
                        <DraftIndicator channel_id=cid has_draft=has_draft />
                    })}

                    // Character counter
                    <span class=counter_class>
                        {move || format!("{}/{}", char_count(), MAX_CHARS)}
                    </span>

                    // Send button
                    <button
                        class="w-8 h-8 flex items-center justify-center rounded-full bg-amber-500 hover:bg-amber-400 disabled:bg-gray-700 disabled:text-gray-500 text-gray-900 transition-all glow-hover flex-shrink-0"
                        on:click=move |_| do_send.run(())
                        disabled=move || is_empty() || is_over_limit()
                        aria-label="Send message"
                    >
                        <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M10 17a.75.75 0 01-.75-.75V5.612L5.29 9.77a.75.75 0 01-1.08-1.04l5.25-5.5a.75.75 0 011.08 0l5.25 5.5a.75.75 0 11-1.08 1.04l-3.96-4.158V16.25A.75.75 0 0110 17z" clip-rule="evenodd"/>
                        </svg>
                    </button>
                </div>
            </div>
        </div>
    }
}
