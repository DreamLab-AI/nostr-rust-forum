//! Image upload component with drag-and-drop, preview, and NIP-98 auth upload
//! to the pod-api. Glass card with dashed amber border.

use crate::auth::use_auth;
use crate::utils::image_compress::{compress_image_default, generate_thumbnail};
use crate::utils::pod_client::upload_image_with_thumbnail;
use leptos::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

const MAX_SIZE: u64 = 5 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq)]
enum State {
    Idle,
    Preview { data_url: String, name: String },
    Compressing,
    Uploading,
    Ok(String),
    Err(String),
}

/// Image upload with drag-and-drop, preview, and NIP-98 authenticated upload.
#[allow(dead_code)]
#[component]
pub(crate) fn ImageUpload(
    on_upload: Callback<String>,
    #[prop(default = "image/*")] accept: &'static str,
) -> impl IntoView {
    let state = RwSignal::new(State::Idle);
    let drag = RwSignal::new(false);
    let input_ref = NodeRef::<leptos::html::Input>::new();
    let auth = use_auth();
    let file_cell = StoredValue::new(send_wrapper::SendWrapper::new(std::cell::RefCell::new(
        Option::<web_sys::File>::None,
    )));

    let process = move |file: web_sys::File| {
        if !file.type_().starts_with("image/") {
            state.set(State::Err("Only image files are allowed".into()));
            return;
        }
        if file.size() as u64 > MAX_SIZE {
            state.set(State::Err(format!(
                "File too large ({:.1} MB). Max 5 MB.",
                file.size() / 1048576.0
            )));
            return;
        }
        let fname = file.name();
        file_cell.with_value(|c| *c.borrow_mut() = Some(file.clone()));
        let reader = match web_sys::FileReader::new() {
            Ok(r) => r,
            Err(_) => {
                state.set(State::Err("FileReader unavailable".into()));
                return;
            }
        };
        let s = state;
        let n = fname.clone();
        let onload = Closure::wrap(Box::new(move |ev: web_sys::Event| {
            let r: web_sys::FileReader = ev.target().unwrap().unchecked_into();
            if let Ok(res) = r.result() {
                if let Some(url) = res.as_string() {
                    s.set(State::Preview {
                        data_url: url,
                        name: n.clone(),
                    });
                }
            }
        }) as Box<dyn FnMut(web_sys::Event)>);
        reader.set_onload(Some(onload.as_ref().unchecked_ref()));
        let _ = reader.read_as_data_url(&file);
        onload.forget();
    };

    let on_zone_click = move |_| {
        if let Some(el) = input_ref.get() {
            let el: web_sys::HtmlElement = el.into();
            el.click();
        }
    };
    let on_file_change = move |ev: leptos::ev::Event| {
        let input: web_sys::HtmlInputElement = ev.target().unwrap().unchecked_into();
        if let Some(files) = input.files() {
            if let Some(f) = files.get(0) {
                process(f);
            }
        }
    };
    let on_dragover = move |ev: web_sys::DragEvent| {
        ev.prevent_default();
        drag.set(true);
    };
    let on_dragleave = move |ev: web_sys::DragEvent| {
        ev.prevent_default();
        drag.set(false);
    };
    let on_drop = move |ev: web_sys::DragEvent| {
        ev.prevent_default();
        drag.set(false);
        if let Some(dt) = ev.data_transfer() {
            if let Some(files) = dt.files() {
                if let Some(f) = files.get(0) {
                    process(f);
                }
            }
        }
    };

    let do_upload = move |_| {
        let file = file_cell.with_value(|c| c.borrow().clone());
        let file = match file {
            Some(f) => f,
            None => return,
        };
        let pk = match auth.get().pubkey {
            Some(p) => p,
            None => {
                state.set(State::Err("Not authenticated".into()));
                return;
            }
        };
        let privkey = match auth.get_privkey_bytes() {
            Some(k) => k,
            None => {
                state.set(State::Err("No signing key".into()));
                return;
            }
        };
        state.set(State::Compressing);
        let fname = file.name();
        let cb = on_upload;
        wasm_bindgen_futures::spawn_local(async move {
            // Compress image
            let compressed = match compress_image_default(&file).await {
                Ok(b) => b,
                Err(e) => {
                    state.set(State::Err(format!("Compression failed: {e}")));
                    return;
                }
            };
            // Generate thumbnail
            let thumbnail = match generate_thumbnail(&file).await {
                Ok(b) => b,
                Err(e) => {
                    state.set(State::Err(format!("Thumbnail failed: {e}")));
                    return;
                }
            };
            state.set(State::Uploading);
            // Upload both to pod
            match upload_image_with_thumbnail(&compressed, &thumbnail, &fname, &pk, &privkey).await
            {
                Ok((image_url, _thumb_url)) => {
                    state.set(State::Ok(image_url.clone()));
                    cb.run(image_url);
                }
                Err(e) => {
                    state.set(State::Err(e));
                }
            }
        });
    };

    let on_clear = move |_| {
        state.set(State::Idle);
        file_cell.with_value(|c| *c.borrow_mut() = None);
        if let Some(el) = input_ref.get() {
            let i: web_sys::HtmlInputElement = el;
            i.set_value("");
        }
    };

    let zone_cls = move || {
        let base = "relative flex flex-col items-center justify-center rounded-xl border-2 border-dashed transition-all cursor-pointer p-8 text-center";
        if drag.get() {
            format!("{} border-amber-400 bg-amber-400/10", base)
        } else {
            format!("{} border-amber-500/30 hover:border-amber-400/50 bg-gray-800/30 hover:bg-gray-800/50", base)
        }
    };

    view! {
        <div class="glass-card rounded-2xl p-4">
            <input node_ref=input_ref type="file" accept=accept class="hidden" on:change=on_file_change />
            {move || match state.get() {
                State::Idle => view! {
                    <div class=zone_cls on:click=on_zone_click on:dragover=on_dragover on:dragleave=on_dragleave on:drop=on_drop>
                        <svg class="w-10 h-10 text-amber-400/60 mb-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                            <path d="M4 14.899A7 7 0 1115.71 8h1.79a4.5 4.5 0 012.5 8.242" stroke-linecap="round" stroke-linejoin="round"/>
                            <path d="M12 12v9m0-9l-3 3m3-3l3 3" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                        <p class="text-sm text-gray-400 mb-1">"Drop an image here or click to browse"</p>
                        <p class="text-xs text-gray-600">"Max 5 MB - PNG, JPG, GIF, WebP"</p>
                    </div>
                }.into_any(),
                State::Preview { ref data_url, ref name } => { let u = data_url.clone(); let n = name.clone(); view! {
                    <div class="space-y-3">
                        <div class="rounded-xl overflow-hidden border border-gray-700/50">
                            <img src=u alt="Preview" class="w-full max-h-48 object-contain bg-gray-900" />
                        </div>
                        <p class="text-xs text-gray-400 truncate px-1">{n}</p>
                        <div class="flex items-center gap-2">
                            <button class="flex-1 bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors text-sm" on:click=do_upload>"Upload"</button>
                            <button class="px-4 py-2 text-gray-400 hover:text-white border border-gray-700 hover:border-gray-600 rounded-lg transition-colors text-sm" on:click=on_clear>"Cancel"</button>
                        </div>
                    </div>
                }.into_any() },
                State::Compressing => view! {
                    <div class="flex flex-col items-center justify-center py-8 gap-3">
                        <div class="w-full max-w-xs h-2 bg-gray-700/50 rounded-full overflow-hidden mx-auto">
                            <div class="h-full w-full bg-gradient-to-r from-amber-500 via-amber-400 to-amber-500 rounded-full animate-pulse"></div>
                        </div>
                        <p class="text-sm text-gray-400">"Compressing..."</p>
                    </div>
                }.into_any(),
                State::Uploading => view! {
                    <div class="flex flex-col items-center justify-center py-8 gap-3">
                        <div class="w-full max-w-xs h-2 bg-gray-700/50 rounded-full overflow-hidden mx-auto">
                            <div class="h-full w-full bg-gradient-to-r from-amber-500 via-amber-400 to-amber-500 rounded-full animate-pulse"></div>
                        </div>
                        <p class="text-sm text-gray-400">"Uploading..."</p>
                    </div>
                }.into_any(),
                State::Ok(ref url) => { let du = url.clone(); view! {
                    <div class="text-center py-6 space-y-3">
                        <div class="w-12 h-12 rounded-full bg-green-500/20 flex items-center justify-center mx-auto">
                            <svg class="w-6 h-6 text-green-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12" stroke-linecap="round" stroke-linejoin="round"/></svg>
                        </div>
                        <p class="text-sm text-green-400 font-medium">"Upload complete"</p>
                        <p class="text-xs text-gray-500 truncate px-4">{du}</p>
                        <button class="text-xs text-gray-400 hover:text-white underline" on:click=on_clear>"Upload another"</button>
                    </div>
                }.into_any() },
                State::Err(ref msg) => { let e = msg.clone(); view! {
                    <div class="text-center py-6 space-y-3">
                        <div class="w-12 h-12 rounded-full bg-red-500/20 flex items-center justify-center mx-auto">
                            <svg class="w-6 h-6 text-red-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15" stroke-linecap="round"/><line x1="9" y1="9" x2="15" y2="15" stroke-linecap="round"/></svg>
                        </div>
                        <p class="text-sm text-red-400">{e}</p>
                        <button class="text-xs text-gray-400 hover:text-white underline" on:click=on_clear>"Try again"</button>
                    </div>
                }.into_any() },
            }}
        </div>
    }
}

