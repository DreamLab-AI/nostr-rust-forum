//! Message export modal -- JSON or CSV download of channel messages.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

use crate::components::message_bubble::MessageData;
use crate::components::modal::Modal;

/// Export format selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExportFormat {
    Json,
    Csv,
}

/// Modal for exporting channel messages as JSON or CSV.
#[component]
pub fn ExportModal(
    /// Channel ID (used in the exported filename).
    #[prop(into)]
    channel_id: String,
    /// Messages to export.
    messages: Vec<MessageData>,
    /// Callback to close the modal.
    on_close: Callback<()>,
) -> impl IntoView {
    let is_open = RwSignal::new(true);
    let format = RwSignal::new(ExportFormat::Json);

    let channel_id_dl = channel_id.clone();
    let msgs = messages.clone();

    let do_export = move |_| {
        let fmt = format.get();
        let (content, mime, ext) = match fmt {
            ExportFormat::Json => {
                let data: Vec<serde_json::Value> = msgs
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "id": m.id,
                            "pubkey": m.pubkey,
                            "content": m.content,
                            "created_at": m.created_at,
                        })
                    })
                    .collect();
                let json = serde_json::to_string_pretty(&data).unwrap_or_default();
                (json, "application/json", "json")
            }
            ExportFormat::Csv => {
                let mut csv = String::from("id,pubkey,content,created_at\n");
                for m in &msgs {
                    let escaped = m.content.replace('"', "\"\"");
                    csv.push_str(&format!(
                        "{},{},\"{}\",{}\n",
                        m.id, m.pubkey, escaped, m.created_at
                    ));
                }
                (csv, "text/csv", "csv")
            }
        };

        trigger_download(&content, mime, &format!("members-{}.{}", channel_id_dl, ext));
        is_open.set(false);
        on_close.run(());
    };

    let on_modal_close = Callback::new(move |()| {
        on_close.run(());
    });

    let msg_count = messages.len();

    view! {
        <Modal is_open=is_open title="Export Messages".to_string() max_width="480px".to_string() on_close=on_modal_close>
            <div class="space-y-4">
                <p class="text-sm text-gray-400">
                    {format!("Export {} message{} from this channel.", msg_count, if msg_count == 1 { "" } else { "s" })}
                </p>

                // Format selector
                <div class="flex gap-2">
                    <button
                        class=move || if format.get() == ExportFormat::Json {
                            "flex-1 px-4 py-2.5 rounded-lg text-sm font-medium bg-amber-500/20 text-amber-400 border border-amber-500/30"
                        } else {
                            "flex-1 px-4 py-2.5 rounded-lg text-sm font-medium bg-gray-800 text-gray-400 border border-gray-700 hover:bg-gray-750 transition-colors"
                        }
                        on:click=move |_| format.set(ExportFormat::Json)
                    >
                        "JSON"
                    </button>
                    <button
                        class=move || if format.get() == ExportFormat::Csv {
                            "flex-1 px-4 py-2.5 rounded-lg text-sm font-medium bg-amber-500/20 text-amber-400 border border-amber-500/30"
                        } else {
                            "flex-1 px-4 py-2.5 rounded-lg text-sm font-medium bg-gray-800 text-gray-400 border border-gray-700 hover:bg-gray-750 transition-colors"
                        }
                        on:click=move |_| format.set(ExportFormat::Csv)
                    >
                        "CSV"
                    </button>
                </div>

                // Download button
                <button
                    class="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-amber-500 to-amber-400 hover:from-amber-400 hover:to-amber-300 text-gray-900 font-semibold px-4 py-2.5 rounded-lg transition-all"
                    on:click=do_export
                >
                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" stroke-linecap="round" stroke-linejoin="round"/>
                        <polyline points="7 10 12 15 17 10" stroke-linecap="round" stroke-linejoin="round"/>
                        <line x1="12" y1="15" x2="12" y2="3" stroke-linecap="round"/>
                    </svg>
                    "Download"
                </button>
            </div>
        </Modal>
    }
}

/// Trigger a file download in the browser using Blob + Object URL.
fn trigger_download(content: &str, mime_type: &str, filename: &str) {
    use js_sys::{Array, Uint8Array};
    use web_sys::{Blob, BlobPropertyBag, Url};

    let bytes = content.as_bytes();
    let array = Uint8Array::new_with_length(bytes.len() as u32);
    array.copy_from(bytes);

    let parts = Array::new();
    parts.push(&array.into());

    let opts = BlobPropertyBag::new();
    opts.set_type(mime_type);

    if let Ok(blob) = Blob::new_with_u8_array_sequence_and_options(&parts, &opts) {
        if let Ok(url) = Url::create_object_url_with_blob(&blob) {
            if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
                if let Ok(a) = doc.create_element("a") {
                    let _ = a.set_attribute("href", &url);
                    let _ = a.set_attribute("download", filename);
                    a.set_attribute("style", "display:none").ok();
                    if let Some(body) = doc.body() {
                        let _ = body.append_child(&a);
                        let html_el: web_sys::HtmlElement = a.unchecked_into();
                        html_el.click();
                        if let Some(parent) = html_el.parent_node() {
                            let _ = parent.remove_child(&html_el);
                        }
                    }
                    let _ = Url::revoke_object_url(&url);
                }
            }
        }
    }
}
