//! Rich message compose box with markdown preview, emoji picker, character counter,
//! draft auto-save (debounced 2s to localStorage), and `@`-mention autocomplete.

use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};

use crate::components::draft_indicator::{clear_draft, load_draft, save_draft, DraftIndicator};
use crate::utils::image_compress::{is_accepted_image, MAX_FILE_SIZE};
use crate::utils::relay_url::relay_api_base;

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

// -- Mention autocomplete ----------------------------------------------------

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct MentionCandidate {
    pubkey: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    nip05: Option<String>,
    #[serde(default)]
    picture: Option<String>,
}

/// Wrapper deserialiser tolerant of both `[..]` and `{"results":[..]}` shapes.
#[derive(Deserialize)]
#[serde(untagged)]
enum SearchResponse {
    Array(Vec<MentionCandidate>),
    Wrapped { results: Vec<MentionCandidate> },
}

impl SearchResponse {
    fn into_vec(self) -> Vec<MentionCandidate> {
        match self {
            Self::Array(v) => v,
            Self::Wrapped { results } => results,
        }
    }
}

impl MentionCandidate {
    fn handle(&self) -> String {
        self.display_name
            .clone()
            .or_else(|| self.name.clone())
            .or_else(|| self.nip05.clone())
            .unwrap_or_else(|| self.pubkey.chars().take(8).collect())
    }
}

/// Minimal URL-encode helper for query-string values.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

async fn search_profiles(query: &str) -> Result<Vec<MentionCandidate>, String> {
    if query.is_empty() {
        return Ok(Vec::new());
    }
    let url = format!(
        "{}/api/profiles/search?q={}&limit=10",
        relay_api_base(),
        url_encode(query)
    );
    let win = web_sys::window().ok_or_else(|| "no window".to_string())?;
    let init = web_sys::RequestInit::new();
    init.set_method("GET");
    let req = web_sys::Request::new_with_str_and_init(&url, &init)
        .map_err(|e| format!("request build failed: {:?}", e))?;
    let resp_val = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|e| format!("fetch failed: {:?}", e))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "bad response type".to_string())?;
    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let txt_promise = resp.text().map_err(|e| format!("text() failed: {:?}", e))?;
    let txt_val = JsFuture::from(txt_promise)
        .await
        .map_err(|e| format!("await text failed: {:?}", e))?;
    let txt = txt_val
        .as_string()
        .ok_or_else(|| "non-string body".to_string())?;
    let parsed: SearchResponse =
        serde_json::from_str(&txt).map_err(|e| format!("parse failed: {}", e))?;
    Ok(parsed.into_vec())
}

/// Round `idx` down to the nearest UTF-8 char boundary that is `<= idx`.
///
/// `caret_pos` arrives from the DOM's `selectionStart`, which counts UTF-16
/// code units, not bytes. When the textarea contains any multi-byte character
/// (e.g. the em-dash `—`, three bytes) before the caret, the raw value can land
/// *inside* a UTF-8 sequence. Slicing `&text[..caret_pos]` on a non-boundary
/// panics, and the panic aborts the WASM runtime — the whole app goes dead.
/// Flooring to a char boundary makes every downstream slice infallible.
fn floor_char_boundary(text: &str, idx: usize) -> usize {
    if idx >= text.len() {
        return text.len();
    }
    let mut i = idx;
    while i > 0 && !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Locate the `@<query>` token at or before `caret_pos` inside `text`.
///
/// Returns `Some((token_start, query))` where:
/// - `token_start` is the byte index of the `@`
/// - `query` is the text between `@` and `caret_pos` (must be ≥2 chars to trigger fetch)
///
/// Returns `None` if no active mention token is found.
fn detect_mention_token(text: &str, caret_pos: usize) -> Option<(usize, String)> {
    // `caret_pos` may be a UTF-16 offset that falls inside a multi-byte char;
    // floor it to a valid UTF-8 boundary before any byte slicing.
    let caret_pos = floor_char_boundary(text, caret_pos);
    let prefix = &text[..caret_pos];

    // Find the most recent `@` that is preceded by start-of-string or whitespace.
    let at_pos = prefix.rfind('@')?;
    if at_pos > 0 {
        let preceding = &prefix[..at_pos];
        let last_char = preceding.chars().last()?;
        if !last_char.is_whitespace() {
            return None;
        }
    }
    let query = &prefix[at_pos + 1..];
    // Only username-shaped queries; bail on whitespace or 64-hex (which is a
    // raw pubkey reference handled elsewhere).
    if query.contains(char::is_whitespace) {
        return None;
    }
    if !query
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return None;
    }
    Some((at_pos, query.to_string()))
}

/// Rich message input with markdown preview, emoji picker, character counter,
/// and `@`-mention autocomplete.
#[component]
pub(crate) fn MessageInput(
    /// Callback fired with the message text when the user sends.
    on_send: Callback<String>,
    /// Optional callback fired alongside `on_send` with the list of mentioned
    /// pubkeys collected from the autocomplete dropdown. Allows callers to
    /// emit `["p", pubkey]` event tags. Existing call sites that omit this
    /// prop receive only `on_send` and the autocomplete still works for the
    /// content-side replacement.
    #[prop(optional)]
    on_send_with_mentions: Option<Callback<(String, Vec<String>)>>,
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
    #[prop(optional)]
    on_image_attach: Option<Callback<web_sys::File>>,
    /// Optional restore channel for failed sends. The send path publishes with
    /// an ack callback; when the relay rejects the message (OK=false, e.g.
    /// "zone access denied"), the caller pushes the original text here. The
    /// input re-fills the textarea so the user does not lose what they wrote.
    /// Omitting this prop preserves the legacy fire-and-forget clear behaviour.
    #[prop(optional)]
    restore_failed: Option<RwSignal<Option<String>>>,
) -> impl IntoView {
    let content = RwSignal::new(String::new());
    let file_input_ref = NodeRef::<leptos::html::Input>::new();
    let attachment = RwSignal::new(Option::<ImageAttachment>::None);
    let has_image_support = on_image_attach.is_some();

    // Mention autocomplete state.
    let mention_open = RwSignal::new(false);
    let mention_query = RwSignal::new(String::new());
    let mention_token_start = RwSignal::new(0usize);
    let mention_candidates: RwSignal<Vec<MentionCandidate>> = RwSignal::new(Vec::new());
    let mention_active_idx = RwSignal::new(0usize);
    let mention_seq = RwSignal::new(0u32);
    let mention_debounce: RwSignal<Option<i32>> = RwSignal::new(None);
    // Pubkeys selected via the autocomplete dropdown — passed through to
    // `on_send_with_mentions` so callers can build `["p", pubkey]` tags.
    let selected_mentions: RwSignal<Vec<(String, String)>> = RwSignal::new(Vec::new());

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

    if let Some(ref cid) = channel_id {
        if let Some(draft) = load_draft(cid) {
            content.set(draft);
        }
    }

    let draft_timer: RwSignal<Option<i32>> = RwSignal::new(None);
    let schedule_draft_save = {
        let cid = channel_id.clone();
        move || {
            let Some(ref cid) = cid else { return };
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

    // Restore-on-failure: when the send path reports a rejected publish, it
    // pushes the failed text here. Re-fill the textarea (only if the user has
    // not already typed a replacement) so nothing is silently lost.
    if let Some(restore) = restore_failed {
        Effect::new(move |_| {
            if let Some(failed) = restore.get() {
                if content.get_untracked().trim().is_empty() {
                    content.set(failed);
                }
                restore.set(None);
            }
        });
    }

    let char_count = move || content.get().len();
    let is_empty = move || content.get().trim().is_empty() && attachment.get().is_none();
    let is_over_limit = move || char_count() > MAX_CHARS;

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

    // -- Mention autocomplete: token detection + debounced fetch ----------
    let trigger_mention_search = move |query: String| {
        // Cancel previous pending fetch.
        if let Some(h) = mention_debounce.get_untracked() {
            if let Some(w) = web_sys::window() {
                w.clear_timeout_with_handle(h);
            }
            mention_debounce.set(None);
        }

        if query.len() < 2 {
            // Show open with empty candidates so users see "Keep typing"
            mention_candidates.set(Vec::new());
            return;
        }

        let seq_now = mention_seq.get_untracked().wrapping_add(1);
        mention_seq.set(seq_now);

        let cb = wasm_bindgen::closure::Closure::wrap(Box::new(move || {
            let q = mention_query.get_untracked();
            if q.len() < 2 {
                return;
            }
            let q_for_fetch = q.clone();
            spawn_local(async move {
                match search_profiles(&q_for_fetch).await {
                    Ok(candidates) => {
                        if mention_seq.get_untracked() == seq_now {
                            mention_candidates.set(candidates);
                            mention_active_idx.set(0);
                        }
                    }
                    Err(e) => {
                        // Endpoint not yet deployed — fail silently with empty list.
                        web_sys::console::warn_1(
                            &format!("[mention] profile search failed: {}", e).into(),
                        );
                        if mention_seq.get_untracked() == seq_now {
                            mention_candidates.set(Vec::new());
                        }
                    }
                }
            });
        }) as Box<dyn FnMut()>);

        if let Some(w) = web_sys::window() {
            if let Ok(h) = w.set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                200,
            ) {
                mention_debounce.set(Some(h));
            }
        }
        cb.forget();
    };

    let update_mention_state = move || {
        let Some(el) = textarea_ref.get_untracked() else {
            return;
        };
        let el: web_sys::HtmlTextAreaElement = el;
        let caret = el.selection_start().ok().flatten().unwrap_or(0) as usize;
        let text = content.get_untracked();
        match detect_mention_token(&text, caret) {
            Some((start, query)) => {
                mention_token_start.set(start);
                mention_query.set(query.clone());
                mention_open.set(true);
                trigger_mention_search(query);
            }
            None => {
                mention_open.set(false);
                mention_candidates.set(Vec::new());
                mention_query.set(String::new());
            }
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
        update_mention_state();
    });

    // Selecting a candidate from the dropdown — replace the @<query> token
    // with @<candidate.handle> in the textarea and stash the pubkey for tag
    // emission.
    let select_candidate = Callback::new(move |idx: usize| {
        let candidates = mention_candidates.get_untracked();
        let Some(c) = candidates.get(idx).cloned() else {
            return;
        };
        let start = mention_token_start.get_untracked();
        let mut text = content.get_untracked();
        // `start` indexes the `@`; bail if it is stale (content shrank) or no
        // longer lands on a char boundary (defensive — it always should).
        if start >= text.len() || !text.is_char_boundary(start) {
            return;
        }
        // Replace from `start` through the current end of the token.
        let after_at = &text[start + 1..];
        let token_len = after_at
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_' || *c == '-')
            .count();
        let token_end = start + 1 + token_len;
        let handle = c.handle();
        let replacement = format!("@{} ", handle);
        text.replace_range(start..token_end, &replacement);
        content.set(text);
        // Track the pubkey so on_send_with_mentions can emit ["p", pubkey].
        selected_mentions.update(|v| {
            if !v.iter().any(|(_, pk)| pk == &c.pubkey) {
                v.push((handle.clone(), c.pubkey.clone()));
            }
        });
        // Place caret after the replacement.
        if let Some(el) = textarea_ref.get_untracked() {
            let el: web_sys::HtmlTextAreaElement = el;
            let new_pos = (start + replacement.len()) as u32;
            let _ = el.set_selection_range(new_pos, new_pos);
            let _ = el.focus();
        }
        mention_open.set(false);
        mention_candidates.set(Vec::new());
        mention_query.set(String::new());
    });

    let cid_for_clear = StoredValue::new(cid_for_draft.clone());
    let do_send = Callback::new(move |()| {
        // Fire image attachment callback if present.
        if let Some(att) = attachment.get_untracked() {
            if let Some(cb) = on_image_attach {
                cb.run(att.file);
            }
            attachment.set(None);
        }
        let text = content.get_untracked();
        let text = text.trim().to_string();
        if !text.is_empty() && text.len() <= MAX_CHARS {
            // Determine which selected mentions actually appear in the final text
            // (the user may have backspaced past one).
            let mentions = selected_mentions.get_untracked();
            let active_pubkeys: Vec<String> = mentions
                .iter()
                .filter(|(handle, _)| text.contains(&format!("@{}", handle)))
                .map(|(_, pk)| pk.clone())
                .collect();

            if let Some(cb) = on_send_with_mentions {
                cb.run((text.clone(), active_pubkeys));
            }
            on_send.run(text);
        }
        content.set(String::new());
        selected_mentions.set(Vec::new());
        mention_open.set(false);
        show_preview.set(false);
        cid_for_clear.with_value(|cid_opt| {
            if let Some(ref cid) = cid_opt {
                clear_draft(cid);
            }
        });
        if let Some(el) = textarea_ref.get() {
            let el: web_sys::HtmlElement = el.into();
            el.style().set_property("height", "auto").ok();
        }
    });

    let on_keydown = Callback::new(move |ev: leptos::ev::KeyboardEvent| {
        let key = ev.key();
        if mention_open.get_untracked() {
            let len = mention_candidates.get_untracked().len();
            if len > 0 {
                match key.as_str() {
                    "ArrowDown" => {
                        ev.prevent_default();
                        mention_active_idx.update(|i| *i = (*i + 1) % len);
                        return;
                    }
                    "ArrowUp" => {
                        ev.prevent_default();
                        mention_active_idx.update(|i| *i = if *i == 0 { len - 1 } else { *i - 1 });
                        return;
                    }
                    "Enter" | "Tab" => {
                        ev.prevent_default();
                        select_candidate.run(mention_active_idx.get_untracked());
                        return;
                    }
                    "Escape" => {
                        ev.prevent_default();
                        mention_open.set(false);
                        return;
                    }
                    _ => {}
                }
            } else if key == "Escape" {
                ev.prevent_default();
                mention_open.set(false);
                return;
            }
        }
        if key == "Enter" && !ev.shift_key() {
            ev.prevent_default();
            do_send.run(());
        }
    });

    let insert_emoji = move |emoji: &'static str| {
        content.update(|c| c.push_str(emoji));
        show_emoji.set(false);
        if let Some(el) = textarea_ref.get() {
            let el: web_sys::HtmlElement = el.into();
            let _ = el.focus();
        }
    };

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
                    let onload =
                        wasm_bindgen::closure::Closure::wrap(Box::new(move |ev: web_sys::Event| {
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
                        })
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
                <div class="relative">
                    <textarea
                        node_ref=textarea_ref
                        class="w-full bg-transparent text-white placeholder-gray-500 resize-none focus:outline-none focus:ring-1 focus:ring-amber-400 rounded-xl p-3 text-sm leading-relaxed min-h-[44px] max-h-[200px]"
                        placeholder=placeholder
                        prop:value=move || content.get()
                        on:input=move |ev| on_input.run(ev)
                        on:keydown=move |ev| on_keydown.run(ev)
                        on:click=move |_| update_mention_state()
                        on:keyup=move |ev: leptos::ev::KeyboardEvent| {
                            // Update token detection on caret-moving keys (left/right/home/end).
                            match ev.key().as_str() {
                                "ArrowLeft" | "ArrowRight" | "Home" | "End" => update_mention_state(),
                                _ => {}
                            }
                        }
                        rows="1"
                        aria-label="Message input"
                        aria-multiline="true"
                    />

                    // Mention autocomplete dropdown
                    <Show when=move || mention_open.get()>
                        <div class="absolute bottom-full left-0 mb-1 w-72 max-w-full glass-card rounded-xl shadow-lg z-50 overflow-hidden">
                            {move || {
                                let candidates = mention_candidates.get();
                                if candidates.is_empty() {
                                    let q = mention_query.get();
                                    if q.len() < 2 {
                                        view! {
                                            <div class="px-3 py-2 text-xs text-gray-500">
                                                "Keep typing to search\u{2026}"
                                            </div>
                                        }.into_any()
                                    } else {
                                        view! {
                                            <div class="px-3 py-2 text-xs text-gray-500">
                                                "No matches"
                                            </div>
                                        }.into_any()
                                    }
                                } else {
                                    let active = mention_active_idx.get();
                                    view! {
                                        <ul role="listbox" class="max-h-60 overflow-y-auto">
                                            {candidates.into_iter().enumerate().map(|(i, c)| {
                                                let handle = c.handle();
                                                let nip05 = c.nip05.clone().unwrap_or_default();
                                                let is_active = i == active;
                                                let class = if is_active {
                                                    "flex items-center gap-2 px-3 py-2 cursor-pointer bg-amber-500/15 text-amber-100"
                                                } else {
                                                    "flex items-center gap-2 px-3 py-2 cursor-pointer hover:bg-gray-800/60 text-gray-200"
                                                };
                                                let pic = c.picture.clone();
                                                view! {
                                                    <li
                                                        role="option"
                                                        aria-selected=is_active
                                                        class=class
                                                        on:mousedown=move |ev| {
                                                            // mousedown so the textarea's blur doesn't kill the click.
                                                            ev.prevent_default();
                                                            select_candidate.run(i);
                                                        }
                                                    >
                                                        {pic.map(|src| view! {
                                                            <img
                                                                src=src
                                                                alt=""
                                                                class="w-6 h-6 rounded-full bg-gray-700 object-cover flex-shrink-0"
                                                            />
                                                        })}
                                                        <div class="flex-1 min-w-0">
                                                            <div class="text-xs font-medium truncate">
                                                                {handle.clone()}
                                                            </div>
                                                            {(!nip05.is_empty()).then(|| view! {
                                                                <div class="text-[10px] text-gray-400 truncate">
                                                                    "@" {nip05}
                                                                </div>
                                                            })}
                                                        </div>
                                                    </li>
                                                }
                                            }).collect_view()}
                                        </ul>
                                    }.into_any()
                                }
                            }}
                        </div>
                    </Show>
                </div>
            </Show>

            // Bottom toolbar
            <div class="flex items-center justify-between mt-1.5 px-1">
                <div class="flex items-center gap-1">
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
                    {channel_id.clone().map(|cid| view! {
                        <DraftIndicator channel_id=cid has_draft=has_draft />
                    })}

                    <span class=counter_class>
                        {move || format!("{}/{}", char_count(), MAX_CHARS)}
                    </span>

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

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_token_at_end() {
        let r = detect_mention_token("hi @al", 6);
        assert_eq!(r, Some((3, "al".to_string())));
    }

    #[test]
    fn detect_token_at_start() {
        let r = detect_mention_token("@bob", 4);
        assert_eq!(r, Some((0, "bob".to_string())));
    }

    #[test]
    fn detect_token_requires_whitespace_before_at() {
        // `@` immediately after a non-space letter should NOT be a mention.
        let r = detect_mention_token("foo@bar", 7);
        assert_eq!(r, None);
    }

    #[test]
    fn detect_token_returns_none_for_no_at() {
        let r = detect_mention_token("hello world", 5);
        assert_eq!(r, None);
    }

    #[test]
    fn detect_token_aborts_on_whitespace_in_query() {
        // After typing a space, the token is closed.
        let r = detect_mention_token("@alice ", 7);
        assert_eq!(r, None);
    }

    #[test]
    fn detect_token_aborts_on_disallowed_char() {
        let r = detect_mention_token("@al!ce", 6);
        assert_eq!(r, None);
    }

    #[test]
    fn detect_token_caret_in_middle() {
        // Caret at index 6 in "hi @ali rest" — only "@al" is before caret
        // (positions 0..6 = "hi @al"), so query is "al".
        let r = detect_mention_token("hi @ali rest", 6);
        assert_eq!(r, Some((3, "al".to_string())));
    }

    #[test]
    fn detect_token_caret_after_full_query() {
        // Caret at index 7 = end of "ali".
        let r = detect_mention_token("hi @ali rest", 7);
        assert_eq!(r, Some((3, "ali".to_string())));
    }

    #[test]
    fn floor_char_boundary_clamps_into_multibyte() {
        // "ab—" is bytes: a(0) b(1) then em-dash occupies bytes 2..5.
        let s = "ab\u{2014}";
        assert_eq!(s.len(), 5);
        // Boundaries are 0, 1, 2, 5.
        assert_eq!(floor_char_boundary(s, 0), 0);
        assert_eq!(floor_char_boundary(s, 2), 2);
        // 3 and 4 land inside the em-dash → floored back to 2.
        assert_eq!(floor_char_boundary(s, 3), 2);
        assert_eq!(floor_char_boundary(s, 4), 2);
        // Past the end clamps to len.
        assert_eq!(floor_char_boundary(s, 5), 5);
        assert_eq!(floor_char_boundary(s, 99), 5);
    }

    #[test]
    fn detect_token_no_panic_with_multibyte_at_caret() {
        // Regression: caret_pos from selectionStart was a UTF-16 offset that
        // could fall inside a multi-byte char, panicking on `&text[..caret]`
        // ("end byte index N is not a char boundary; inside '—'"). The em-dash
        // here spans bytes 30..33; a caret of 31 must NOT panic.
        let text = "look at this thread for the —fix";
        let dash_byte = text.find('\u{2014}').unwrap();
        assert_eq!(dash_byte, 28);
        // Caret one byte into the em-dash — previously a hard panic.
        let _ = detect_mention_token(text, dash_byte + 1);
        // And exactly at the QA-reported shape: em-dash spanning 30..33.
        let text2 = "0123456789012345678901234567890\u{2014}x"; // dash at byte 31
        let dash2 = text2.find('\u{2014}').unwrap();
        assert_eq!(dash2, 31);
        let r = detect_mention_token(text2, 32);
        // No `@` present, so the result is None — the point is it returns
        // rather than panicking.
        assert_eq!(r, None);
    }

    #[test]
    fn detect_token_multibyte_before_at() {
        // A multi-byte char before the `@` must not corrupt the byte indices.
        // "— @al" : em-dash(0..3) space(3) @(4) a(5) l(6).
        let text = "\u{2014} @al";
        let r = detect_mention_token(text, text.len());
        assert_eq!(r, Some((4, "al".to_string())));
    }

    #[test]
    fn url_encode_basic() {
        assert_eq!(url_encode("alice"), "alice");
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("a&b"), "a%26b");
    }

    #[test]
    fn search_response_array_shape() {
        let json = r#"[{"pubkey":"abc","name":"alice"}]"#;
        let parsed: SearchResponse = serde_json::from_str(json).unwrap();
        let v = parsed.into_vec();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name.as_deref(), Some("alice"));
    }

    #[test]
    fn search_response_wrapped_shape() {
        let json = r#"{"results":[{"pubkey":"abc","display_name":"Alice"}]}"#;
        let parsed: SearchResponse = serde_json::from_str(json).unwrap();
        let v = parsed.into_vec();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn candidate_handle_precedence() {
        let c = MentionCandidate {
            pubkey: "abcdef0123456789".into(),
            name: Some("alice".into()),
            display_name: Some("Alice In Wonderland".into()),
            nip05: Some("alice@example.com".into()),
            picture: None,
        };
        assert_eq!(c.handle(), "Alice In Wonderland");

        let c2 = MentionCandidate {
            pubkey: "abcdef0123456789".into(),
            name: Some("alice".into()),
            display_name: None,
            nip05: Some("alice@example.com".into()),
            picture: None,
        };
        assert_eq!(c2.handle(), "alice");

        let c3 = MentionCandidate {
            pubkey: "abcdef0123456789".into(),
            name: None,
            display_name: None,
            nip05: Some("alice@example.com".into()),
            picture: None,
        };
        assert_eq!(c3.handle(), "alice@example.com");

        let c4 = MentionCandidate {
            pubkey: "abcdef0123456789".into(),
            name: None,
            display_name: None,
            nip05: None,
            picture: None,
        };
        assert_eq!(c4.handle(), "abcdef01");
    }
}
