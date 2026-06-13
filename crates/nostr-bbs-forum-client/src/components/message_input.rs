//! Rich message compose box with markdown preview, emoji picker, character counter,
//! draft auto-save (debounced 2s to localStorage), and `@`-mention autocomplete.

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use crate::auth::use_auth;
use crate::components::draft_indicator::{clear_draft, load_draft, save_draft, DraftIndicator};
use crate::components::mention_autocomplete::{
    local_candidates, merge_candidates, search_profiles, MentionAutocomplete, MentionCandidate,
    NETWORK_SEARCH_MIN_LEN,
};
use crate::utils::image_compress::{
    compress_image_default, generate_thumbnail, is_accepted_image, MAX_FILE_SIZE,
};
use crate::utils::pod_client::upload_image_with_thumbnail_signer;

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
//
// Candidate sourcing, ranking, and the dropdown view live in
// `components/mention_autocomplete.rs`. This module owns only the
// textarea-side concerns: detecting the active `@<query>` token at the caret,
// driving the candidate signal (local sources first, network merge after),
// keyboard navigation, and splicing the chosen handle back into the textarea
// while stashing the pubkey for `["p", pubkey]` tag emission.

/// Max candidates shown in the dropdown.
const MENTION_LIMIT: usize = 10;

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

/// Characters allowed inside a `@<query>` mention token.
///
/// Covers usernames (`a-z 0-9 _ -`), capitalised display-name typing
/// (`A-Z`), and NIP-05 handles (`. @`) so a user can begin typing any of the
/// labels the candidates expose. Whitespace always closes the token.
fn is_mention_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@')
}

/// Locate the `@<query>` token at or before `caret_pos` inside `text`.
///
/// Returns `Some((token_start, query))` where:
/// - `token_start` is the byte index of the leading `@`
/// - `query` is the text between that `@` and `caret_pos`
///
/// The query may be empty (the moment after `@` is typed) so the dropdown can
/// open immediately and offer the local roster. Returns `None` when there is
/// no active mention token (no `@`, `@` glued to a word, or whitespace in the
/// query).
fn detect_mention_token(text: &str, caret_pos: usize) -> Option<(usize, String)> {
    // `caret_pos` may be a UTF-16 offset that falls inside a multi-byte char;
    // floor it to a valid UTF-8 boundary before any byte slicing.
    let caret_pos = floor_char_boundary(text, caret_pos);
    let prefix = &text[..caret_pos];

    // Find the most recent `@` that begins a token (start-of-string or
    // whitespace before it). Scanning from the end lets a NIP-05-style query
    // ("alice@host") keep working: we anchor on the leading `@`.
    let mut at_pos = None;
    for (idx, _) in prefix.char_indices().rev() {
        if prefix.as_bytes()[idx] == b'@' {
            let starts_token = idx == 0
                || prefix[..idx]
                    .chars()
                    .last()
                    .map(|c| c.is_whitespace())
                    .unwrap_or(true);
            if starts_token {
                at_pos = Some(idx);
                break;
            }
        }
    }
    let at_pos = at_pos?;
    let query = &prefix[at_pos + 1..];
    // Whitespace closes the token; any non-mention char (e.g. punctuation that
    // is not part of a handle) also closes it.
    if query.contains(char::is_whitespace) {
        return None;
    }
    if !query.chars().all(is_mention_char) {
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
    /// When `true`, the composer handles photo upload end-to-end: an attached
    /// image is compressed and uploaded to the user's pod (NIP-98) on send, and
    /// the resulting public URL is appended to the message content so it renders
    /// inline via `MediaEmbed`. This enables the paperclip affordance without the
    /// caller wiring `on_image_attach`. The two are independent: a caller may use
    /// either or both.
    #[prop(optional)]
    enable_image_upload: bool,
    /// Optional initial textarea content. Used by the edit flow to pre-fill the
    /// composer with the post being edited. Existing call sites omit it and the
    /// composer opens empty (then restores any saved draft).
    #[prop(optional, into)]
    initial_content: Option<String>,
    /// When `true`, the send button renders as a "Save edit" action and the
    /// composer styling signals edit mode. Purely cosmetic — the publish path is
    /// the caller's responsibility via `on_send` / `on_send_with_mentions`.
    #[prop(optional)]
    is_editing: bool,
    /// Optional callback fired when the user cancels an in-progress edit
    /// (only rendered when `is_editing` is set).
    #[prop(optional)]
    on_cancel_edit: Option<Callback<()>>,
    /// Optional restore channel for failed sends. The send path publishes with
    /// an ack callback; when the relay rejects the message (OK=false, e.g.
    /// "zone access denied"), the caller pushes the original text here. The
    /// input re-fills the textarea so the user does not lose what they wrote.
    /// Omitting this prop preserves the legacy fire-and-forget clear behaviour.
    #[prop(optional)]
    restore_failed: Option<RwSignal<Option<String>>>,
) -> impl IntoView {
    let content = RwSignal::new(initial_content.clone().unwrap_or_default());
    let file_input_ref = NodeRef::<leptos::html::Input>::new();
    let attachment = RwSignal::new(Option::<ImageAttachment>::None);
    // The paperclip shows when EITHER the caller wants the raw file
    // (`on_image_attach`) OR the composer should upload it itself
    // (`enable_image_upload`).
    let has_image_support = on_image_attach.is_some() || enable_image_upload;
    // Tracks the self-contained pod upload triggered on send. `None` when idle,
    // `Some(true)` while uploading, `Some(false)` is unused (errors surface via
    // `upload_error`). Disables the send button while a photo is in flight.
    let uploading = RwSignal::new(false);
    let upload_error: RwSignal<Option<String>> = RwSignal::new(None);
    // Auth store captured in the component's reactive scope (Copy) so the send
    // callback can read pubkey/signer without re-entering context.
    let auth = use_auth();

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

    // When opened with pre-filled content (edit flow), size the textarea to fit
    // once it is mounted. Runs once: the guard returns early after the resize.
    if initial_content.is_some() {
        Effect::new(move |ran: Option<bool>| {
            if ran == Some(true) {
                return true;
            }
            if textarea_ref.get().is_some() {
                resize_textarea();
                true
            } else {
                false
            }
        });
    }

    // -- Mention autocomplete: token detection + debounced fetch ----------
    //
    // Two-stage resolution so `@mention` works even when the relay search
    // endpoint is empty or undeployed:
    //   1. Seed the dropdown synchronously from the LOCAL sources (read-only
    //      ProfileCache + known-users seed). This is what makes typing `@junk`
    //      surface `junkiejarvis` (pubkey 2de44d…) with no network at all.
    //   2. Debounce-fetch the relay search endpoint and merge richer results
    //      in, preferring network records but never dropping a local match.
    //
    // `local` is computed by the caller inside a reactive scope (so it
    // subscribes to the ProfileCache) and threaded through here.
    let trigger_mention_search = move |query: String, local: Vec<MentionCandidate>| {
        // Cancel any previous pending network fetch.
        if let Some(h) = mention_debounce.get_untracked() {
            if let Some(w) = web_sys::window() {
                w.clear_timeout_with_handle(h);
            }
            mention_debounce.set(None);
        }

        // Stage 1: show local candidates immediately.
        mention_candidates.set(local.clone());
        mention_active_idx.set(0);

        // Below the network-search threshold we rely on local sources only.
        if query.len() < NETWORK_SEARCH_MIN_LEN {
            return;
        }

        let seq_now = mention_seq.get_untracked().wrapping_add(1);
        mention_seq.set(seq_now);

        let cb = wasm_bindgen::closure::Closure::wrap(Box::new(move || {
            let q = mention_query.get_untracked();
            if q.len() < NETWORK_SEARCH_MIN_LEN {
                return;
            }
            let q_for_fetch = q.clone();
            let local_for_merge = local.clone();
            spawn_local(async move {
                // `search_profiles` degrades to an empty list on any failure,
                // so the local candidates remain in place if the relay is down.
                let network = search_profiles(&q_for_fetch, MENTION_LIMIT).await;
                if mention_seq.get_untracked() == seq_now {
                    let merged = merge_candidates(network, local_for_merge.clone(), MENTION_LIMIT);
                    mention_candidates.set(merged);
                    mention_active_idx.set(0);
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
                // Compute local candidates here (reactive scope -> subscribes
                // to ProfileCache) and thread them into the search trigger.
                let local = local_candidates(&query, MENTION_LIMIT);
                trigger_mention_search(query, local);
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
    // with @<candidate.handle> in the textarea and stash the pubkey so the
    // send path can emit a ["p", pubkey] tag on the kind-42 event.
    let select_candidate = Callback::new(move |c: MentionCandidate| {
        let start = mention_token_start.get_untracked();
        let mut text = content.get_untracked();
        // `start` indexes the `@`; bail if it is stale (content shrank) or no
        // longer lands on a char boundary (defensive — it always should).
        if start >= text.len() || !text.is_char_boundary(start) {
            return;
        }
        // Replace from `start` through the current end of the token. The token
        // ends at the first char that cannot belong to a mention.
        let after_at = &text[start + 1..];
        let token_len = after_at
            .chars()
            .take_while(|c| is_mention_char(*c))
            .map(char::len_utf8)
            .sum::<usize>();
        let token_end = start + 1 + token_len;
        // Splice the handle. Strip whitespace from the handle so the inserted
        // token stays a single mention (display names may contain spaces).
        let handle = c.handle();
        let safe_handle: String = handle.chars().filter(|c| !c.is_whitespace()).collect();
        let safe_handle = if safe_handle.is_empty() {
            c.pubkey.chars().take(8).collect::<String>()
        } else {
            safe_handle
        };
        let replacement = format!("@{} ", safe_handle);
        text.replace_range(start..token_end, &replacement);
        content.set(text);
        // Track the (handle, pubkey) pair. `do_send` filters this list against
        // the final text so a backspaced-away mention drops its p-tag.
        selected_mentions.update(|v| {
            if !v.iter().any(|(_, pk)| pk == &c.pubkey) {
                v.push((safe_handle.clone(), c.pubkey.clone()));
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

    // Keyboard path: resolve the highlighted row to its candidate, then select.
    let select_active = move || {
        let idx = mention_active_idx.get_untracked();
        if let Some(c) = mention_candidates.get_untracked().get(idx).cloned() {
            select_candidate.run(c);
        }
    };

    let cid_for_clear = StoredValue::new(cid_for_draft.clone());

    // Emit `text` through the send callbacks (filtering mentions to those still
    // present) and reset the composer. Shared by the synchronous send path and
    // the async upload-then-send path so both behave identically post-send.
    let finalize_send = Callback::new(move |text: String| {
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

    let do_send = Callback::new(move |()| {
        let att = attachment.get_untracked();

        // Legacy raw-file path: hand the caller the File for its own upload.
        if let Some(ref a) = att {
            if let Some(cb) = on_image_attach {
                cb.run(a.file.clone());
            }
        }

        let text = content.get_untracked();

        // Self-contained upload path: compress + upload the attachment to the
        // user's pod, append the public URL to the content, then send. The URL
        // is detected as media by `MediaEmbed`, so the photo renders inline.
        if enable_image_upload {
            if let Some(a) = att {
                let file = a.file.clone();
                let pk = match auth.pubkey().get_untracked() {
                    Some(p) if !p.is_empty() => p,
                    _ => {
                        upload_error.set(Some("Sign in to attach a photo".into()));
                        return;
                    }
                };
                let signer = match auth.get_signer() {
                    Some(s) => s,
                    None => {
                        upload_error.set(Some("No signing key available".into()));
                        return;
                    }
                };
                upload_error.set(None);
                uploading.set(true);
                let base_text = text.clone();
                spawn_local(async move {
                    let compressed = match compress_image_default(&file).await {
                        Ok(b) => b,
                        Err(e) => {
                            uploading.set(false);
                            upload_error.set(Some(format!("Compression failed: {e}")));
                            return;
                        }
                    };
                    let thumbnail = match generate_thumbnail(&file).await {
                        Ok(b) => b,
                        Err(e) => {
                            uploading.set(false);
                            upload_error.set(Some(format!("Thumbnail failed: {e}")));
                            return;
                        }
                    };
                    match upload_image_with_thumbnail_signer(
                        &compressed,
                        &thumbnail,
                        &file.name(),
                        &pk,
                        signer.as_ref(),
                    )
                    .await
                    {
                        Ok((image_url, _thumb_url)) => {
                            uploading.set(false);
                            attachment.set(None);
                            let combined = if base_text.trim().is_empty() {
                                image_url
                            } else {
                                format!("{}\n{}", base_text.trim_end(), image_url)
                            };
                            finalize_send.run(combined);
                        }
                        Err(e) => {
                            uploading.set(false);
                            upload_error.set(Some(format!("Upload failed: {e}")));
                        }
                    }
                });
                return;
            }
        }

        // No upload pending — clear any legacy attachment preview and send the
        // text immediately.
        attachment.set(None);
        finalize_send.run(text);
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
                        select_active();
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
            // Edit-mode banner with a cancel affordance.
            {is_editing.then(|| view! {
                <div class="mb-2 flex items-center justify-between gap-2 px-1">
                    <span class="text-xs text-amber-400 flex items-center gap-1.5">
                        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7" stroke-linecap="round" stroke-linejoin="round"/>
                            <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                        "Editing post"
                    </span>
                    {on_cancel_edit.map(|cb| view! {
                        <button
                            class="text-xs text-gray-400 hover:text-white underline"
                            on:click=move |_| cb.run(())
                        >
                            "Cancel"
                        </button>
                    })}
                </div>
            })}

            // Upload error (self-contained photo upload path).
            {move || upload_error.get().map(|e| view! {
                <div class="mb-2 px-3 py-2 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400">
                    {e}
                </div>
            })}

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

                    // Mention autocomplete dropdown (view + ranking live in
                    // components/mention_autocomplete.rs).
                    <MentionAutocomplete
                        open=mention_open
                        query=mention_query
                        candidates=mention_candidates
                        active_idx=mention_active_idx
                        on_select=select_candidate
                    />
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
                        disabled=move || is_empty() || is_over_limit() || uploading.get()
                        aria-label=move || {
                            if uploading.get() {
                                "Uploading photo"
                            } else if is_editing {
                                "Save edit"
                            } else {
                                "Send message"
                            }
                        }
                        title=move || if is_editing { "Save edit" } else { "Send" }
                    >
                        {move || {
                            if uploading.get() {
                                // Spinner while the photo uploads to the pod.
                                view! {
                                    <svg class="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                                        <path d="M12 2v4m0 12v4m-7.07-3.93l2.83-2.83m8.48-8.48l2.83-2.83M2 12h4m12 0h4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83" stroke-linecap="round"/>
                                    </svg>
                                }.into_any()
                            } else if is_editing {
                                // Checkmark for "save edit".
                                view! {
                                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                                        <polyline points="20 6 9 17 4 12" stroke-linecap="round" stroke-linejoin="round"/>
                                    </svg>
                                }.into_any()
                            } else {
                                view! {
                                    <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
                                        <path fill-rule="evenodd" d="M10 17a.75.75 0 01-.75-.75V5.612L5.29 9.77a.75.75 0 01-1.08-1.04l5.25-5.5a.75.75 0 011.08 0l5.25 5.5a.75.75 0 11-1.08 1.04l-3.96-4.158V16.25A.75.75 0 0110 17z" clip-rule="evenodd"/>
                                    </svg>
                                }.into_any()
                            }
                        }}
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
    fn detect_token_opens_on_bare_at() {
        // The instant after typing `@`, the empty-query token opens so the
        // dropdown can show the local roster.
        let r = detect_mention_token("hi @", 4);
        assert_eq!(r, Some((3, String::new())));
    }

    #[test]
    fn detect_token_allows_uppercase_and_nip05_chars() {
        // Capitalised display-name typing.
        let r = detect_mention_token("@Alice", 6);
        assert_eq!(r, Some((0, "Alice".to_string())));
        // NIP-05-style handle: anchors on the leading `@`, keeps the inner `@`.
        let r2 = detect_mention_token("@alice@host.tld", 15);
        assert_eq!(r2, Some((0, "alice@host.tld".to_string())));
    }

    #[test]
    fn is_mention_char_classes() {
        assert!(is_mention_char('a'));
        assert!(is_mention_char('Z'));
        assert!(is_mention_char('9'));
        assert!(is_mention_char('_'));
        assert!(is_mention_char('-'));
        assert!(is_mention_char('.'));
        assert!(is_mention_char('@'));
        assert!(!is_mention_char(' '));
        assert!(!is_mention_char('!'));
    }
}
