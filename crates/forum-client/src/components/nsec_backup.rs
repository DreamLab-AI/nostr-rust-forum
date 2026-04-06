//! One-time nsec backup component displayed after first registration.
//!
//! Shows the bech32-encoded private key in a glass card with copy/download
//! actions and a confirmation dismissal that persists via localStorage.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

/// localStorage key to track whether the user has dismissed the backup prompt.
const BACKUP_DISMISSED_KEY: &str = "bbs:nsec_backup_dismissed";

/// Private key backup display.
///
/// Renders a card with the hex-encoded private key, copy and download
/// buttons, and a confirmation that dismisses the component.
#[component]
pub(crate) fn NsecBackup(
    /// The hex-encoded private key (64 characters).
    nsec: String,
    /// Fired when the user confirms backup and dismisses the card.
    on_dismiss: Callback<()>,
) -> impl IntoView {
    let copied = RwSignal::new(false);
    let nsec_for_copy = nsec.clone();
    let nsec_for_download = nsec.clone();

    let on_copy = move |_| {
        let nsec = nsec_for_copy.clone();
        if let Some(window) = web_sys::window() {
            let clipboard = window.navigator().clipboard();
            let _ = clipboard.write_text(&nsec);
            copied.set(true);
            // Reset after 2 seconds
            crate::utils::set_timeout_once(move || copied.set(false), 2000);
        }
    };

    let on_download = move |_| {
        let nsec = nsec_for_download.clone();
        if let Some(window) = web_sys::window() {
            if let Some(doc) = window.document() {
                let content = format!(
                    "Nostr BBS - Recovery Key Backup\n\
                     ==================================\n\n\
                     Key: {}\n\n\
                     IMPORTANT: Anyone with this key can access your account.\n\
                     Store this file securely and delete it from your downloads.\n",
                    nsec
                );

                // Create Blob and trigger download
                let arr = js_sys::Array::new();
                arr.push(&wasm_bindgen::JsValue::from_str(&content));
                let opts = web_sys::BlobPropertyBag::new();
                opts.set_type("text/plain");
                if let Ok(blob) = web_sys::Blob::new_with_str_sequence_and_options(&arr, &opts) {
                    if let Ok(url) = web_sys::Url::create_object_url_with_blob(&blob) {
                        if let Ok(a) = doc.create_element("a") {
                            let _ = a.set_attribute("href", &url);
                            let _ = a.set_attribute("download", "nostr-bbs-nsec-backup.txt");
                            let a_html: web_sys::HtmlElement = a.unchecked_into();
                            a_html.click();
                            let _ = web_sys::Url::revoke_object_url(&url);
                        }
                    }
                }
            }
        }
    };

    let on_confirm = move |_| {
        // Persist dismissal
        if let Some(storage) = web_sys::window()
            .and_then(|w| w.local_storage().ok())
            .flatten()
        {
            let _ = storage.set_item(BACKUP_DISMISSED_KEY, "true");
        }
        on_dismiss.run(());
    };

    view! {
        <div
            class="bg-gray-800/40 border-2 border-amber-500/60 rounded-2xl p-6 space-y-5"
            role="alertdialog"
            aria-labelledby="nsec-backup-title"
            aria-describedby="nsec-backup-desc"
        >
            // Header
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-full bg-amber-500/20 flex items-center justify-center flex-shrink-0">
                    <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"
                            stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </div>
                <div>
                    <h3 id="nsec-backup-title" class="text-lg font-bold text-white">"Save Your Recovery Key"</h3>
                    <p id="nsec-backup-desc" class="text-xs text-gray-400">"You need this to sign back in."</p>
                </div>
            </div>

            // Key display
            <div class="bg-gray-900/60 border border-gray-700 rounded-xl p-4">
                <label class="block text-xs text-gray-500 mb-2 font-medium uppercase tracking-wider">"Recovery Key"</label>
                <code class="block text-sm text-amber-300 font-mono break-all select-all leading-relaxed">
                    {nsec.clone()}
                </code>
            </div>

            // Action buttons
            <div class="flex flex-wrap gap-3">
                <button
                    on:click=on_copy
                    class="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg transition-colors text-sm"
                    aria-label="Copy private key to clipboard"
                >
                    <Show
                        when=move || copied.get()
                        fallback=|| view! {
                            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            <span>"Copy"</span>
                        }
                    >
                        <svg class="w-4 h-4 text-green-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="20 6 9 17 4 12" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                        <span class="text-green-400">"Copied!"</span>
                    </Show>
                </button>

                <button
                    on:click=on_download
                    class="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg transition-colors text-sm"
                    aria-label="Download private key as text file"
                >
                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" stroke-linecap="round" stroke-linejoin="round"/>
                        <polyline points="7 10 12 15 17 10" stroke-linecap="round" stroke-linejoin="round"/>
                        <line x1="12" y1="15" x2="12" y2="3" stroke-linecap="round"/>
                    </svg>
                    <span>"Download"</span>
                </button>
            </div>

            // Confirmation button
            <div class="border-t border-gray-700/50 pt-4">
                <button
                    on:click=on_confirm
                    class="w-full bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold py-3 px-4 rounded-xl transition-colors text-sm"
                >
                    "I've saved my backup"
                </button>
            </div>
        </div>
    }
}

/// Returns `true` if the user has previously dismissed the nsec backup.
#[allow(dead_code)]
pub fn is_backup_dismissed() -> bool {
    web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
        .and_then(|s| s.get_item(BACKUP_DISMISSED_KEY).ok())
        .flatten()
        .map(|v| v == "true")
        .unwrap_or(false)
}
