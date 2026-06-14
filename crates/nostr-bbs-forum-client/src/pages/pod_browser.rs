//! Pod Browser — navigate and manage the user's Solid data pod.
//!
//! Provides an LDP-aware file browser with NIP-98 authenticated requests.
//! Displays containers as navigable folders and resources as viewable items,
//! with quick-access links to well-known pod endpoints (profile, inbox,
//! type indexes, media).

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::auth::use_auth;

// ── Media classification ──────────────────────────────────────────────────────

/// How a pod resource should be rendered. Media kinds need an authenticated
/// byte fetch + object URL (an `<img>`/`<video>`/`<audio>` element can't carry
/// the NIP-98 `Authorization` header, so a bare `src` to the pod URL 404s);
/// everything else falls back to the text/JSON-LD viewer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MediaKind {
    Image,
    Video,
    Audio,
    Other,
}

impl MediaKind {
    /// Classify by file extension (primary signal — the container listing only
    /// gives us names/paths, no content-type until we fetch).
    fn from_path(path: &str) -> Self {
        let ext = path
            .rsplit('/')
            .next()
            .unwrap_or(path)
            .rsplit_once('.')
            .map(|(_, e)| e.to_ascii_lowercase());
        match ext.as_deref() {
            Some("png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "avif" | "bmp" | "ico") => {
                MediaKind::Image
            }
            Some("mp4" | "webm" | "ogg" | "ogv" | "mov" | "m4v") => MediaKind::Video,
            Some("mp3" | "wav" | "oga" | "m4a" | "aac" | "flac" | "opus") => MediaKind::Audio,
            _ => MediaKind::Other,
        }
    }

    /// Refine/confirm using the response `Content-Type` (authoritative when the
    /// pod sets it; e.g. an extensionless file or a misnamed one). Only ever
    /// upgrades an `Other` classification or corrects the media family — it
    /// never demotes a known media extension to `Other` on a missing header.
    fn from_content_type(ct: &str) -> Self {
        let ct = ct.split(';').next().unwrap_or(ct).trim();
        // `image/svg+xml`, `image/png`, etc. all render as images.
        if ct.starts_with("image/") {
            MediaKind::Image
        } else if ct.starts_with("video/") {
            MediaKind::Video
        } else if ct.starts_with("audio/") {
            MediaKind::Audio
        } else {
            MediaKind::Other
        }
    }
}

/// Best-effort MIME type for the `Blob` we hand to the browser. Prefer the
/// server-provided content-type; fall back to a type derived from the
/// extension so `<img>`/`<video>` decode correctly even when the pod omits it.
fn mime_for(path: &str, content_type: Option<&str>) -> String {
    if let Some(ct) = content_type {
        let base = ct.split(';').next().unwrap_or(ct).trim();
        if !base.is_empty() && base != "application/octet-stream" {
            return base.to_string();
        }
    }
    let ext = path
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("avif") => "image/avif",
        Some("bmp") => "image/bmp",
        Some("ico") => "image/x-icon",
        Some("mp4" | "m4v") => "video/mp4",
        Some("webm") => "video/webm",
        Some("ogv") => "video/ogg",
        Some("mov") => "video/quicktime",
        Some("ogg") => "video/ogg",
        Some("mp3") => "audio/mpeg",
        Some("wav") => "audio/wav",
        Some("oga" | "opus") => "audio/ogg",
        Some("m4a" | "aac") => "audio/mp4",
        Some("flac") => "audio/flac",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Wrap raw bytes in a typed `Blob` and return a browser object URL that can be
/// used directly as an `<img>`/`<video>`/`<audio>` `src`. The caller owns the
/// URL and must revoke it (see `revoke_object_url`) once the element is gone.
fn bytes_to_object_url(bytes: &[u8], mime: &str) -> Result<String, String> {
    let arr = js_sys::Uint8Array::from(bytes);
    let parts = js_sys::Array::new();
    parts.push(&arr.buffer());

    let opts = web_sys::BlobPropertyBag::new();
    opts.set_type(mime);

    let blob = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &opts)
        .map_err(|e| format!("Blob: {e:?}"))?;
    web_sys::Url::create_object_url_with_blob(&blob).map_err(|e| format!("Object URL: {e:?}"))
}

const POD_API: &str = match option_env!("VITE_POD_API_URL") {
    Some(u) => u,
    None => "https://pod.example.com",
};

const NATIVE_POD_URL: &str = match option_env!("NATIVE_POD_URL") {
    Some(u) => u,
    None => "",
};

// ── Data types ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct PodEntry {
    id: String,
    name: String,
    is_container: bool,
    modified: String,
}

#[derive(Clone, Debug)]
enum FetchState {
    Idle,
    Loading,
    Loaded(Vec<PodEntry>),
    Error(String),
}

/// What the resource viewer is currently showing. Text resources carry their
/// decoded body; media resources carry a blob object URL (revoked on cleanup)
/// and the kind so the viewer picks the right element.
#[derive(Clone, Debug)]
enum ResourceView {
    Text {
        content: String,
        path: String,
    },
    Media {
        object_url: String,
        kind: MediaKind,
        mime: String,
        path: String,
    },
}

impl ResourceView {
    fn path(&self) -> &str {
        match self {
            ResourceView::Text { path, .. } => path,
            ResourceView::Media { path, .. } => path,
        }
    }
}

// ── Authenticated fetch ─────────────────────────────────────────────────────

async fn pod_fetch(
    url: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<String, String> {
    let token = crate::auth::nip98::create_nip98_token_with_signer(signer, url, "GET", None)
        .await
        .map_err(|e| format!("NIP-98: {e}"))?;

    let win = web_sys::window().ok_or("No window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("GET");

    let headers = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Authorization", &format!("Nostr {token}"))
        .map_err(|e| format!("{e:?}"))?;
    headers
        .set(
            "Accept",
            "application/ld+json, application/json, text/turtle, */*",
        )
        .map_err(|e| format!("{e:?}"))?;
    init.set_headers(&headers);

    let req = web_sys::Request::new_with_str_and_init(url, &init).map_err(|e| format!("{e:?}"))?;
    let resp_val = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|e| format!("Fetch: {e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "Not a Response".to_string())?;

    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let text_promise = resp.text().map_err(|e| format!("{e:?}"))?;
    let text_val = JsFuture::from(text_promise)
        .await
        .map_err(|e| format!("{e:?}"))?;
    text_val.as_string().ok_or_else(|| "Empty response".into())
}

/// Same NIP-98 authenticated GET as [`pod_fetch`], but returns the raw bytes
/// plus the server `Content-Type`. Used for media resources (image/video/audio)
/// which must be decoded by the browser rather than rendered as text — an
/// `<img>`/`<video>` `src` can't send the auth header, so we fetch the bytes
/// here and hand them to a `Blob`/object-URL instead.
async fn pod_fetch_bytes(
    url: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<(Vec<u8>, Option<String>), String> {
    let token = crate::auth::nip98::create_nip98_token_with_signer(signer, url, "GET", None)
        .await
        .map_err(|e| format!("NIP-98: {e}"))?;

    let win = web_sys::window().ok_or("No window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("GET");

    let headers = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Authorization", &format!("Nostr {token}"))
        .map_err(|e| format!("{e:?}"))?;
    headers.set("Accept", "*/*").map_err(|e| format!("{e:?}"))?;
    init.set_headers(&headers);

    let req = web_sys::Request::new_with_str_and_init(url, &init).map_err(|e| format!("{e:?}"))?;
    let resp_val = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|e| format!("Fetch: {e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "Not a Response".to_string())?;

    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let content_type = resp.headers().get("content-type").ok().flatten();

    let buf_promise = resp.array_buffer().map_err(|e| format!("{e:?}"))?;
    let buf_val = JsFuture::from(buf_promise)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let bytes = js_sys::Uint8Array::new(&buf_val).to_vec();
    Ok((bytes, content_type))
}

async fn pod_provision(
    base_url: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<(), String> {
    let url = format!("{base_url}/.provision");
    let token = crate::auth::nip98::create_nip98_token_with_signer(signer, &url, "POST", None)
        .await
        .map_err(|e| format!("NIP-98: {e}"))?;

    let win = web_sys::window().ok_or("No window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("POST");

    let headers = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Authorization", &format!("Nostr {token}"))
        .map_err(|e| format!("{e:?}"))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| format!("{e:?}"))?;
    init.set_headers(&headers);

    let req = web_sys::Request::new_with_str_and_init(&url, &init).map_err(|e| format!("{e:?}"))?;
    let resp_val = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|e| format!("Fetch: {e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "Not a Response".to_string())?;

    let status = resp.status();
    if status == 201 || status == 409 {
        Ok(())
    } else {
        Err(format!("Provision failed: HTTP {status}"))
    }
}

fn parse_container_listing(json_str: &str) -> Vec<PodEntry> {
    let val: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let members = match val.get("ldp:contains") {
        Some(serde_json::Value::Array(arr)) => arr.clone(),
        Some(single) => vec![single.clone()],
        None => return Vec::new(),
    };

    members
        .iter()
        .filter_map(|m| {
            let id = m.get("@id")?.as_str()?.to_string();
            let is_container = id.ends_with('/');
            let name = id
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or(&id)
                .to_string();
            let name = if is_container {
                format!("{name}/")
            } else {
                name
            };
            let modified = m
                .get("dcterms:modified")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Some(PodEntry {
                id,
                name,
                is_container,
                modified,
            })
        })
        .collect()
}

// ── Quick-access cards ──────────────────────────────────────────────────────

struct QuickLink {
    label: &'static str,
    path: &'static str,
    icon: &'static str,
    description: &'static str,
}

const QUICK_LINKS: &[QuickLink] = &[
    QuickLink {
        label: "Profile",
        path: "/profile/card",
        icon: "M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z",
        description: "WebID document",
    },
    QuickLink {
        label: "Inbox",
        path: "/inbox/",
        icon: "M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z",
        description: "Linked Data Notifications",
    },
    QuickLink {
        label: "Public Index",
        path: "/settings/publicTypeIndex.jsonld",
        icon: "M4 6h16M4 10h16M4 14h16M4 18h16",
        description: "Public type registrations",
    },
    QuickLink {
        label: "Media",
        path: "/media/public/",
        icon: "M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z",
        description: "Uploaded files",
    },
];

// ── Resource viewer ─────────────────────────────────────────────────────────

#[component]
fn ResourceViewer(content: String, path: String) -> impl IntoView {
    let is_json = content.trim_start().starts_with('{') || content.trim_start().starts_with('[');
    let display = if is_json {
        serde_json::from_str::<serde_json::Value>(&content)
            .ok()
            .and_then(|v| serde_json::to_string_pretty(&v).ok())
            .unwrap_or(content)
    } else {
        content
    };

    view! {
        <div class="bg-gray-900 rounded-lg border border-gray-700/50 overflow-hidden">
            <div class="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700/50">
                <span class="text-sm text-gray-400 font-mono truncate">{path}</span>
                <span class="text-xs px-2 py-0.5 rounded bg-gray-700 text-gray-300">
                    {if is_json { "JSON-LD" } else { "Text" }}
                </span>
            </div>
            <pre class="p-4 text-sm text-gray-300 overflow-x-auto whitespace-pre-wrap font-mono max-h-96 overflow-y-auto">
                {display}
            </pre>
        </div>
    }
}

/// Renders an authenticated media resource from a blob object URL. The bytes
/// were fetched with NIP-98 auth and wrapped in an object URL by the caller, so
/// the element can render without sending any header. The URL is revoked by the
/// page's navigation/cleanup logic when the viewer is dismissed.
#[component]
fn MediaViewer(object_url: String, kind: MediaKind, mime: String, path: String) -> impl IntoView {
    let label = match kind {
        MediaKind::Image => "Image",
        MediaKind::Video => "Video",
        MediaKind::Audio => "Audio",
        MediaKind::Other => "File",
    };

    let body = match kind {
        MediaKind::Image => view! {
            <div class="flex items-center justify-center p-4 bg-gray-950">
                <img
                    src=object_url.clone()
                    alt=path.clone()
                    class="max-w-full max-h-[32rem] object-contain rounded"
                />
            </div>
        }
        .into_any(),
        MediaKind::Video => {
            let src = object_url.clone();
            let ty = mime.clone();
            view! {
                <div class="flex items-center justify-center p-4 bg-gray-950">
                    <video
                        controls=true
                        class="max-w-full max-h-[32rem] rounded"
                    >
                        <source src=src type=ty />
                        "Your browser can\u{2019}t play this video."
                    </video>
                </div>
            }
            .into_any()
        }
        MediaKind::Audio => {
            let src = object_url.clone();
            let ty = mime.clone();
            view! {
                <div class="p-4 bg-gray-950">
                    <audio controls=true class="w-full">
                        <source src=src type=ty />
                        "Your browser can\u{2019}t play this audio."
                    </audio>
                </div>
            }
            .into_any()
        }
        MediaKind::Other => view! {
            <div class="p-4 text-sm text-gray-400">"Unsupported media type."</div>
        }
        .into_any(),
    };

    view! {
        <div class="bg-gray-900 rounded-lg border border-gray-700/50 overflow-hidden">
            <div class="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700/50">
                <span class="text-sm text-gray-400 font-mono truncate">{path}</span>
                <span class="text-xs px-2 py-0.5 rounded bg-gray-700 text-gray-300">{label}</span>
            </div>
            {body}
        </div>
    }
}

// ── Main page component ─────────────────────────────────────────────────────

/// Result of probing the pod for a `.git/HEAD` file. The CF Workers tier
/// returns 404 (no git-init); native/agentbox tiers serve the HEAD ref.
#[derive(Clone, Debug, PartialEq, Eq)]
enum GitProbeState {
    Idle,
    Probing,
    Available { branch: String },
    Unavailable, // 404 / no HEAD
    Error(String),
}

#[component]
pub fn PodBrowserPage() -> impl IntoView {
    let auth = use_auth();
    let pubkey = auth.pubkey();

    let current_path = RwSignal::new("/".to_string());
    let fetch_state = RwSignal::new(FetchState::Idle);
    let resource_content = RwSignal::new(None::<ResourceView>);
    let viewing_resource = RwSignal::new(false);
    let git_probe = RwSignal::new(GitProbeState::Idle);
    let native_probe = RwSignal::new(GitProbeState::Idle);
    let toasts = crate::components::toast::use_toasts();

    let pod_base_url = Memo::new(move |_| {
        pubkey
            .get()
            .map(|pk| format!("{}/pods/{}", POD_API.trim_end_matches('/'), pk))
    });

    // Per-user pod git clone command (ADR-089). URL builder lives in
    // `solid_pod_rs::webid::pod_git_clone_url` so the forum-client and the
    // pod-worker share one definition of the layout.
    let pod_clone_command = Memo::new(move |_| {
        pubkey
            .get()
            .map(|pk| {
                format!(
                    "git clone {}",
                    solid_pod_rs::webid::pod_git_clone_url(POD_API, &pk)
                )
            })
            .unwrap_or_default()
    });

    // Copy the raw pod storage endpoint to the clipboard (issue #28). The URL
    // is an authenticated Solid endpoint — pasting it into a browser 404s —
    // so we surface it as a labelled copy affordance rather than a bare link.
    let toasts_for_url_copy = toasts;
    let on_copy_pod_url = move |_| {
        let Some(url) = pod_base_url.get_untracked() else {
            toasts_for_url_copy.show(
                "Pod URL not available yet",
                crate::components::toast::ToastVariant::Warning,
            );
            return;
        };
        if let Some(window) = web_sys::window() {
            let nav = window.navigator().clipboard();
            let _ = nav.write_text(&url);
        }
        toasts_for_url_copy.show(
            "Pod URL copied",
            crate::components::toast::ToastVariant::Success,
        );
    };

    // Copy the clone command to clipboard.
    let toasts_for_copy = toasts;
    let on_copy_clone = move |_| {
        let cmd = pod_clone_command.get_untracked();
        if cmd.is_empty() {
            toasts_for_copy.show(
                "No clone URL available",
                crate::components::toast::ToastVariant::Warning,
            );
            return;
        }
        if let Some(window) = web_sys::window() {
            let nav = window.navigator().clipboard();
            let _ = nav.write_text(&cmd);
        }
        toasts_for_copy.show(
            "Clone command copied",
            crate::components::toast::ToastVariant::Success,
        );
    };

    // Probe `<pod_base>/HEAD` (NOT `.git/HEAD`; smart-HTTP-style serves the
    // refs at the root in solid-pod-rs-git's design). 200 means git-init
    // ran at provisioning; 404 / 501 means this operator's tier doesn't
    // support it. Idempotent; safe to call repeatedly.
    let run_git_probe = move || {
        let Some(base) = pod_base_url.get() else {
            return;
        };
        let Some(signer) = auth.get_signer() else {
            return;
        };
        git_probe.set(GitProbeState::Probing);
        let url = format!("{}/HEAD", base.trim_end_matches('/'));
        wasm_bindgen_futures::spawn_local(async move {
            match pod_fetch(&url, &*signer).await {
                Ok(body) => {
                    let branch = body
                        .trim()
                        .strip_prefix("ref: refs/heads/")
                        .unwrap_or(body.trim())
                        .to_string();
                    if branch.is_empty() {
                        git_probe.set(GitProbeState::Unavailable);
                    } else {
                        git_probe.set(GitProbeState::Available { branch });
                    }
                }
                // 404: no git-init ran at provisioning (native tier, feature
                //      flag off). 501: CF Workers tier (ADR-089 limitation).
                Err(e) if e.contains("404") || e.contains("501") => {
                    git_probe.set(GitProbeState::Unavailable)
                }
                Err(e) => git_probe.set(GitProbeState::Error(e)),
            }
        });
    };

    // Auto-probe once as soon as the pod URL is known.
    Effect::new(move |ran: Option<bool>| {
        if ran == Some(true) {
            return true; // already fired
        }
        if pod_base_url.get().is_some() && auth.get_signer().is_some() {
            run_git_probe();
            true
        } else {
            false
        }
    });

    // Native pod base URL derived from pubkey + NATIVE_POD_URL constant.
    let native_pod_base_url = Memo::new(move |_| {
        if NATIVE_POD_URL.is_empty() {
            return None;
        }
        pubkey
            .get()
            .map(|pk| format!("{}/{}", NATIVE_POD_URL.trim_end_matches('/'), pk))
    });

    // Auto-probe native pod once the URL and signer are ready.
    Effect::new(move |ran: Option<bool>| {
        if ran == Some(true) || NATIVE_POD_URL.is_empty() {
            return true;
        }
        let Some(base) = native_pod_base_url.get() else {
            return false;
        };
        let Some(signer) = auth.get_signer() else {
            return false;
        };
        native_probe.set(GitProbeState::Probing);
        let head_url = format!("{}/HEAD", base.trim_end_matches('/'));
        wasm_bindgen_futures::spawn_local(async move {
            match pod_fetch(&head_url, &*signer).await {
                Ok(body) => {
                    let branch = body
                        .trim()
                        .strip_prefix("ref: refs/heads/")
                        .unwrap_or(body.trim())
                        .to_string();
                    if branch.is_empty() {
                        native_probe.set(GitProbeState::Unavailable);
                    } else {
                        native_probe.set(GitProbeState::Available { branch });
                    }
                }
                Err(e) if e.contains("404") || e.contains("501") => {
                    native_probe.set(GitProbeState::Unavailable)
                }
                Err(e) => native_probe.set(GitProbeState::Error(e)),
            }
        });
        true
    });

    let on_probe_git = move |_| run_git_probe();

    // Revoke any live blob object URL the viewer is holding, then clear it.
    // Must run before replacing/clearing the resource so we don't leak the URL
    // (and the underlying decoded bytes the browser keeps alive for it).
    let revoke_current_object_url = move || {
        if let Some(ResourceView::Media { object_url, .. }) = resource_content.get_untracked() {
            let _ = web_sys::Url::revoke_object_url(&object_url);
        }
    };

    let navigate_to = move |path: String| {
        revoke_current_object_url();
        resource_content.set(None);
        viewing_resource.set(false);
        current_path.set(path);
    };

    // Final safety net: revoke the outstanding object URL when the page unmounts.
    on_cleanup(move || revoke_current_object_url());

    // Fetch container listing whenever current_path changes
    Effect::new(move |_| {
        let path = current_path.get();
        let signer = auth.get_signer();

        if let (Some(base), Some(signer)) = (pod_base_url.get(), signer) {
            fetch_state.set(FetchState::Loading);
            let url = format!("{}{}", base, path);
            let is_container = path.ends_with('/') || path == "/";

            // Media files are fetched as bytes and rendered via a blob object
            // URL (an <img>/<video>/<audio> src can't carry the NIP-98 header).
            // Classify by extension first; the content-type from the byte fetch
            // refines it. Non-media resources keep the text/JSON-LD viewer.
            let path_kind = MediaKind::from_path(&path);

            wasm_bindgen_futures::spawn_local(async move {
                if !is_container && path_kind != MediaKind::Other {
                    match pod_fetch_bytes(&url, &*signer).await {
                        Ok((bytes, content_type)) => {
                            // Prefer the server content-type when it disagrees
                            // with the extension (e.g. .ogg served as audio).
                            let kind = match content_type.as_deref() {
                                Some(ct) => {
                                    let ct_kind = MediaKind::from_content_type(ct);
                                    if ct_kind == MediaKind::Other {
                                        path_kind
                                    } else {
                                        ct_kind
                                    }
                                }
                                None => path_kind,
                            };
                            let mime = mime_for(&path, content_type.as_deref());
                            match bytes_to_object_url(&bytes, &mime) {
                                Ok(object_url) => {
                                    resource_content.set(Some(ResourceView::Media {
                                        object_url,
                                        kind,
                                        mime,
                                        path,
                                    }));
                                    viewing_resource.set(true);
                                    fetch_state.set(FetchState::Idle);
                                }
                                Err(e) => fetch_state.set(FetchState::Error(e)),
                            }
                        }
                        Err(e) => fetch_state.set(FetchState::Error(e)),
                    }
                    return;
                }

                let result = match pod_fetch(&url, &*signer).await {
                    Ok(body) => Ok(body),
                    Err(ref e) if path == "/" && (e.contains("403") || e.contains("404")) => {
                        // Pod likely not provisioned — try auto-provisioning
                        if pod_provision(&base, &*signer).await.is_ok() {
                            pod_fetch(&url, &*signer).await
                        } else {
                            Err(e.clone())
                        }
                    }
                    Err(e) => Err(e),
                };

                match result {
                    Ok(body) => {
                        if is_container {
                            let entries = parse_container_listing(&body);
                            fetch_state.set(FetchState::Loaded(entries));
                        } else {
                            resource_content.set(Some(ResourceView::Text {
                                content: body,
                                path,
                            }));
                            viewing_resource.set(true);
                            fetch_state.set(FetchState::Idle);
                        }
                    }
                    Err(e) => fetch_state.set(FetchState::Error(e)),
                }
            });
        }
    });

    let breadcrumbs = Memo::new(move |_| {
        let path = current_path.get();
        let mut crumbs: Vec<(String, String)> = vec![("Pod".into(), "/".into())];
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut accumulated = String::new();
        for part in parts {
            accumulated.push('/');
            accumulated.push_str(part);
            accumulated.push('/');
            crumbs.push((part.to_string(), accumulated.clone()));
        }
        crumbs
    });

    let on_quick_link = move |path: &'static str| {
        let path = path.to_string();
        move |_: web_sys::MouseEvent| {
            navigate_to(path.clone());
        }
    };

    view! {
        <div class="pod-browser max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            // Header
            <div class="mb-6">
                <h1 class="text-2xl font-bold text-white mb-1">"Pod Browser"</h1>

                // Pod storage endpoint (issue #28). This is an authenticated
                // Solid endpoint accessed by the app on your behalf — opening
                // it directly in a browser won't work. Present it as a clearly
                // labelled, copy-to-clipboard field, not a bare clickable link.
                <div class="mt-2 bg-gray-800/60 border border-gray-700/50 rounded-lg p-3">
                    <div class="flex items-center justify-between gap-2 mb-1">
                        <span class="text-xs text-gray-500 uppercase tracking-wide">
                            "Your pod storage endpoint"
                        </span>
                        <button
                            data-testid="pod-url-copy"
                            on:click=on_copy_pod_url
                            class="text-xs bg-gray-700 hover:bg-gray-600 text-gray-100 font-medium px-2.5 py-1 rounded-md transition-colors flex items-center gap-1.5 flex-shrink-0"
                            aria-label="Copy pod URL"
                        >
                            <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                            </svg>
                            "Copy"
                        </button>
                    </div>
                    <code
                        data-testid="pod-url"
                        class="block text-xs text-gray-300 font-mono break-all select-all"
                    >
                        {move || pod_base_url.get().unwrap_or_else(|| "Connecting\u{2026}".into())}
                    </code>
                    <p class="text-xs text-gray-500 mt-2 leading-relaxed">
                        "This is your private Solid pod storage endpoint — accessed by the app on your behalf. It requires authentication, so opening it directly in a browser won\u{2019}t work (you\u{2019}ll see an error). Use the folders below to browse your data."
                    </p>
                </div>
            </div>

            // Solid explainer — collapsible (what this Pod is and why it matters).
            <details class="group mb-8 bg-gray-800/40 border border-gray-700/50 rounded-xl p-5">
                <summary class="flex items-center gap-3 cursor-pointer list-none [&::-webkit-details-marker]:hidden">
                    <svg
                        class="w-6 h-6 text-amber-400 flex-shrink-0"
                        viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
                        aria-hidden="true"
                    >
                        <circle cx="12" cy="12" r="9.5" />
                        <path stroke-linecap="round" d="M2.5 12h19M12 2.5c2.6 2.7 3.9 6 3.9 9.5s-1.3 6.8-3.9 9.5c-2.6-2.7-3.9-6-3.9-9.5s1.3-6.8 3.9-9.5z" />
                    </svg>
                    <h2 class="text-base font-semibold text-white flex-1">"Your data, your Pod — built on Solid"</h2>
                    <svg
                        class="w-4 h-4 text-gray-400 flex-shrink-0 transition-transform group-open:rotate-180"
                        viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"
                    >
                        <path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" />
                    </svg>
                </summary>
                <div class="space-y-2 mt-3">
                        <p class="text-gray-300 text-sm leading-relaxed">
                            "This is your personal "<span class="text-amber-300">"Solid Pod"</span>" — an instance of the open web standard created by Sir Tim Berners-Lee, inventor of the World Wide Web. Solid (\"Social Linked Data\") decouples your data from the apps that use it: rather than each service hoarding your information, you keep it in a datastore you own and control."
                        </p>
                        <p class="text-gray-300 text-sm leading-relaxed">
                            "Everything here — your profile, messages, media, and your portable identity (your "<span class="text-amber-300">"WebID"</span>") — lives in storage that answers to you, not to someone else's servers. Apps ask permission to read or write, and you can revoke it at any time."
                        </p>
                        <p class="text-gray-400 text-sm leading-relaxed">
                            "Why it matters: it flips the usual model — data portability instead of lock-in, consent instead of surveillance, an open standard instead of a walled garden. Your identity and your data travel with you across any Solid-compatible app, and this forum is just one of them."
                        </p>
                        <a
                            href="https://solidproject.org"
                            target="_blank" rel="noopener noreferrer"
                            class="inline-flex items-center gap-1 text-amber-400 hover:text-amber-300 text-sm font-medium"
                        >
                            "Learn more about Solid"
                            <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
                            </svg>
                        </a>
                </div>
            </details>

            // Git pod card (ADR-089). Shown only when the probe confirms git
            // is available; CF Workers returns 501 → Unavailable → no card.
            {move || match git_probe.get() {
                GitProbeState::Idle => view! { <div></div> }.into_any(),

                GitProbeState::Probing => view! {
                    <div class="mb-6 flex items-center gap-2 text-sm text-gray-500 py-2">
                        <div class="animate-spin rounded-full h-4 w-4 border-b-2 border-amber-400/50"></div>
                        "Checking git status…"
                    </div>
                }.into_any(),

                GitProbeState::Available { branch } => {
                    let branch_signal = Signal::derive({
                        let branch = branch.clone();
                        move || branch.clone()
                    });
                    view! {
                        <div>
                            <section
                                data-section="git-pod"
                                aria-labelledby="git-pod-heading"
                                class="mb-4 bg-gradient-to-br from-amber-500/10 to-orange-500/5 border border-amber-400/20 rounded-lg p-4"
                            >
                                <div class="flex items-center gap-2 mb-2">
                                    <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                        <circle cx="12" cy="12" r="3"/>
                                        <path d="M12 1v6m0 6v6m11-7h-6m-6 0H1"/>
                                    </svg>
                                    <h2 id="git-pod-heading" class="text-base font-semibold text-white">
                                        {format!("Your pod is a git repository · branch: {branch}")}
                                    </h2>
                                </div>
                                <p class="text-sm text-gray-300 mb-3">
                                    "Clone, push, and pull your pod with standard git. "
                                    <code class="text-xs bg-gray-800 px-1.5 py-0.5 rounded text-amber-300">"receive.denyCurrentBranch=updateInstead"</code>
                                    " — push and the working tree updates server-side."
                                </p>
                                <div class="bg-gray-900/80 border border-gray-700/50 rounded px-3 py-2 mb-3">
                                    <code data-testid="pod-clone-command" class="text-xs text-amber-300 font-mono break-all">
                                        {move || pod_clone_command.get()}
                                    </code>
                                </div>
                                <div class="flex flex-wrap items-center gap-2">
                                    <button
                                        data-testid="pod-clone-copy"
                                        on:click=on_copy_clone
                                        class="text-sm bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-3 py-1.5 rounded-md transition-colors"
                                    >
                                        "Copy clone command"
                                    </button>
                                    <button
                                        data-testid="pod-git-probe"
                                        on:click=on_probe_git
                                        class="text-sm bg-gray-700 hover:bg-gray-600 text-gray-100 font-medium px-3 py-1.5 rounded-md transition-colors"
                                    >
                                        "Re-check"
                                    </button>
                                </div>
                                <p class="text-xs text-gray-500 mt-3">
                                    "Powered by solid-pod-rs · git feature enabled on this deployment."
                                </p>
                            </section>
                            <crate::components::git_panel::GitPanel
                                pod_base_url=pod_base_url
                                branch=branch_signal
                            />
                            <crate::components::git_panel::AppManifestPanel
                                pod_base_url=pod_base_url
                            />
                        </div>
                    }.into_any()
                },

                GitProbeState::Unavailable => view! {
                    <div
                        data-section="git-pod-unavailable"
                        class="mb-6 flex items-center justify-between gap-3 text-xs text-gray-600 bg-gray-800/30 border border-gray-700/30 rounded-lg px-4 py-2.5"
                    >
                        <span>
                            "Git HTTP not available on this deployment "
                            <span class="text-gray-700">"(CF Workers tier — see ADR-089)"</span>
                        </span>
                        <button
                            data-testid="pod-git-probe"
                            on:click=on_probe_git
                            class="text-gray-600 hover:text-gray-400 transition-colors underline underline-offset-2 flex-shrink-0"
                        >
                            "Re-check"
                        </button>
                    </div>
                }.into_any(),

                GitProbeState::Error(e) => {
                    web_sys::console::warn_1(
                        &format!("[PodBrowser] Git probe failed: {e}").into(),
                    );
                    let detail = e.clone();
                    view! {
                        <div class="mb-6 flex flex-col gap-2 text-xs text-gray-500 bg-gray-800/30 border border-gray-700/30 rounded-lg px-4 py-2.5">
                            <div class="flex items-center justify-between gap-3">
                                <span>"Version history isn\u{2019}t available for your pod just yet."</span>
                                <button
                                    data-testid="pod-git-probe"
                                    on:click=on_probe_git
                                    class="text-gray-600 hover:text-gray-400 transition-colors underline underline-offset-2 flex-shrink-0"
                                >
                                    "Re-check"
                                </button>
                            </div>
                            <details class="text-gray-700">
                                <summary class="cursor-pointer select-none hover:text-gray-500">"Details"</summary>
                                <span class="block mt-1 font-mono">{detail}</span>
                            </details>
                        </div>
                    }.into_any()
                },
            }}

            // Native pod section — only rendered when NATIVE_POD_URL is configured.
            {move || {
                if NATIVE_POD_URL.is_empty() { return view! {<div></div>}.into_any(); }
                match native_probe.get() {
                    GitProbeState::Idle | GitProbeState::Probing => view! {
                        <div class="mb-4 flex items-center gap-2 text-sm text-gray-500 py-2">
                            <div class="animate-spin rounded-full h-4 w-4 border-b-2 border-green-400/50"></div>
                            "Connecting to native pod\u{2026}"
                        </div>
                    }.into_any(),
                    GitProbeState::Available { branch } => {
                        let branch_for_header = branch.clone();
                        let branch_sig = Signal::derive({ let b = branch.clone(); move || b.clone() });
                        view! {
                            <section class="mb-4 bg-gradient-to-br from-green-500/10 to-emerald-500/5 border border-green-400/20 rounded-lg p-4">
                                <div class="flex items-center gap-2 mb-2">
                                    <span class="text-green-400 text-lg">"\u{2387}"</span>
                                    <h2 class="text-base font-semibold text-white">
                                        {format!("Native pod \u{00b7} branch: {branch_for_header}")}
                                    </h2>
                                    <span class="ml-auto text-xs bg-green-500/20 text-green-300 px-2 py-0.5 rounded-full">"Git enabled"</span>
                                </div>
                                <p class="text-xs text-gray-400 mb-3">
                                    "Full git version control \u{00b7} hosted on the agentbox native server"
                                </p>
                            </section>
                            <crate::components::git_panel::GitPanel
                                pod_base_url=native_pod_base_url
                                branch=branch_sig
                            />
                            <crate::components::git_panel::AppManifestPanel
                                pod_base_url=native_pod_base_url
                            />
                        }.into_any()
                    },
                    // Reachable native server with no git pod for this user yet
                    // (404/501). The git-backed mesh tier simply isn't available
                    // on this deployment — say so plainly rather than implying an
                    // in-progress setup that will never complete.
                    GitProbeState::Unavailable => view! {
                        <div class="mb-4 text-xs text-gray-500 bg-gray-800/20 border border-gray-700/20 rounded px-3 py-2">
                            "A git-backed pod (mesh tier) isn\u{2019}t available on this deployment yet. "
                            "Your files live on the standard pod above."
                        </div>
                    }.into_any(),
                    // Transport/DNS failure reaching the configured native host
                    // (e.g. the mesh pod server isn\u{2019}t wired up). Surface the
                    // real error instead of a misleading \u{201c}being set up\u{201d} message.
                    GitProbeState::Error(e) => {
                        web_sys::console::warn_1(
                            &format!("[PodBrowser] Native pod probe failed: {e}").into(),
                        );
                        let detail = e.clone();
                        view! {
                            <div class="mb-4 flex flex-col gap-1 text-xs text-gray-500 bg-gray-800/20 border border-gray-700/20 rounded px-3 py-2">
                                <span>
                                    "The git-backed mesh pod server isn\u{2019}t reachable right now. "
                                    "Your files live on the standard pod above."
                                </span>
                                <details class="text-gray-600">
                                    <summary class="cursor-pointer select-none hover:text-gray-400">"Details"</summary>
                                    <span class="block mt-1 font-mono">{detail}</span>
                                </details>
                            </div>
                        }.into_any()
                    },
                }
            }}

            // Quick-access cards
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
                {QUICK_LINKS.iter().map(|link| {
                    let path_svg = link.icon;
                    let label = link.label;
                    let desc = link.description;
                    let handler = on_quick_link(link.path);
                    view! {
                        <button
                            class="bg-gray-800 hover:bg-gray-750 border border-gray-700/50 hover:border-amber-400/30 rounded-lg p-3 text-left transition-colors group"
                            on:click=handler
                        >
                            <div class="flex items-center gap-2 mb-1">
                                <svg class="w-4 h-4 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d=path_svg />
                                </svg>
                                <span class="text-sm font-medium text-white">{label}</span>
                            </div>
                            <span class="text-xs text-gray-500">{desc}</span>
                        </button>
                    }
                }).collect_view()}
            </div>

            // Breadcrumb navigation
            <nav class="flex items-center gap-1 text-sm mb-4 overflow-x-auto pb-1" aria-label="Pod path">
                {move || {
                    let crumbs = breadcrumbs.get();
                    crumbs.into_iter().enumerate().map(|(i, (label, path))| {
                        let is_last = i == breadcrumbs.get().len() - 1;
                        let nav = navigate_to;
                        view! {
                            {if i > 0 {
                                Some(view! { <span class="text-gray-600">"/"</span> })
                            } else {
                                None
                            }}
                            {if is_last {
                                view! {
                                    <span class="text-amber-400 font-medium">{label}</span>
                                }.into_any()
                            } else {
                                let p = path.clone();
                                view! {
                                    <button
                                        class="text-gray-400 hover:text-white transition-colors"
                                        on:click=move |_| nav(p.clone())
                                    >
                                        {label}
                                    </button>
                                }.into_any()
                            }}
                        }
                    }).collect_view()
                }}
            </nav>

            // Resource viewer (when viewing a non-container resource)
            {move || {
                resource_content.get().map(|view_res| {
                    let nav = navigate_to;
                    let path = view_res.path().to_string();
                    let parent = {
                        let mut p = path.rsplit_once('/').map(|(a, _)| format!("{a}/")).unwrap_or_else(|| "/".into());
                        if p.is_empty() { p = "/".into(); }
                        p
                    };
                    let inner = match view_res {
                        ResourceView::Text { content, path } => {
                            view! { <ResourceViewer content=content path=path /> }.into_any()
                        }
                        ResourceView::Media { object_url, kind, mime, path } => {
                            view! { <MediaViewer object_url=object_url kind=kind mime=mime path=path /> }.into_any()
                        }
                    };
                    view! {
                        <div class="mb-4">
                            <button
                                class="text-sm text-gray-400 hover:text-amber-400 transition-colors flex items-center gap-1 mb-3"
                                on:click=move |_| nav(parent.clone())
                            >
                                <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M19 12H5M12 19l-7-7 7-7" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                                "Back to folder"
                            </button>
                            {inner}
                        </div>
                    }
                })
            }}

            // Container listing
            <Show when=move || !viewing_resource.get()>
                {move || match fetch_state.get() {
                    FetchState::Loading => view! {
                        <div class="flex items-center justify-center py-12">
                            <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-amber-400"></div>
                        </div>
                    }.into_any(),

                    FetchState::Error(e) => {
                        web_sys::console::warn_1(
                            &format!("[PodBrowser] Pod fetch failed: {e}").into(),
                        );
                        let detail = e.clone();
                        view! {
                            <div class="bg-gray-800/50 border border-gray-700/50 rounded-lg p-6 text-center">
                                <svg class="w-12 h-12 mx-auto text-gray-600 mb-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                    <path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                                <p class="text-gray-300 text-sm">"Your personal pod isn\u{2019}t set up yet."</p>
                                <p class="text-gray-500 text-xs mt-1">"Pod storage is being provisioned \u{2014} this can take a moment after you first sign in."</p>
                                <details class="text-gray-700 text-xs mt-3 inline-block text-left">
                                    <summary class="cursor-pointer select-none hover:text-gray-500">"Details"</summary>
                                    <span class="block mt-1 font-mono">{detail}</span>
                                </details>
                            </div>
                        }.into_any()
                    },

                    FetchState::Loaded(entries) if entries.is_empty() => view! {
                        <div class="bg-gray-800/50 rounded-lg p-8 text-center">
                            <svg class="w-12 h-12 mx-auto text-gray-600 mb-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                <path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            <p class="text-gray-500">"This container is empty."</p>
                        </div>
                    }.into_any(),

                    FetchState::Loaded(entries) => {
                        let nav = navigate_to;
                        view! {
                            <div class="bg-gray-800 rounded-lg border border-gray-700/50 divide-y divide-gray-700/30 overflow-hidden">
                                {entries.into_iter().map(|entry| {
                                    let id = entry.id.clone();
                                    let name = entry.name.clone();
                                    let is_container = entry.is_container;
                                    let modified = entry.modified.clone();
                                    view! {
                                        <button
                                            class="w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-750 transition-colors text-left group"
                                            on:click=move |_| nav(id.clone())
                                        >
                                            {if is_container {
                                                view! {
                                                    <svg class="w-5 h-5 text-amber-400 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                        <path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" stroke-linecap="round" stroke-linejoin="round"/>
                                                    </svg>
                                                }.into_any()
                                            } else {
                                                view! {
                                                    <svg class="w-5 h-5 text-gray-500 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" stroke-linecap="round" stroke-linejoin="round"/>
                                                        <polyline points="14 2 14 8 20 8" stroke-linecap="round" stroke-linejoin="round"/>
                                                    </svg>
                                                }.into_any()
                                            }}
                                            <div class="flex-1 min-w-0">
                                                <span class="text-sm text-white group-hover:text-amber-400 transition-colors block truncate">
                                                    {name}
                                                </span>
                                                {if !modified.is_empty() {
                                                    Some(view! {
                                                        <span class="text-xs text-gray-600 block truncate">{modified}</span>
                                                    })
                                                } else {
                                                    None
                                                }}
                                            </div>
                                            <svg class="w-4 h-4 text-gray-600 group-hover:text-gray-400 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                <path d="M9 18l6-6-6-6" stroke-linecap="round" stroke-linejoin="round"/>
                                            </svg>
                                        </button>
                                    }
                                }).collect_view()}
                            </div>
                        }.into_any()
                    },

                    FetchState::Idle => view! { <div></div> }.into_any(),
                }}
            </Show>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::{mime_for, MediaKind};

    #[test]
    fn classifies_images_by_extension() {
        for p in [
            "/media/public/photo.png",
            "cat.JPG",
            "a/b/c.jpeg",
            "x.gif",
            "y.webp",
            "logo.svg",
            "shot.avif",
        ] {
            assert_eq!(MediaKind::from_path(p), MediaKind::Image, "{p}");
        }
    }

    #[test]
    fn classifies_video_and_audio_by_extension() {
        assert_eq!(MediaKind::from_path("clip.mp4"), MediaKind::Video);
        assert_eq!(MediaKind::from_path("clip.WEBM"), MediaKind::Video);
        assert_eq!(MediaKind::from_path("a.mov"), MediaKind::Video);
        assert_eq!(MediaKind::from_path("song.mp3"), MediaKind::Audio);
        assert_eq!(MediaKind::from_path("v.wav"), MediaKind::Audio);
        assert_eq!(MediaKind::from_path("v.flac"), MediaKind::Audio);
    }

    #[test]
    fn non_media_extensions_stay_text() {
        for p in [
            "/profile/card",
            "settings/publicTypeIndex.jsonld",
            "notes.txt",
            "data.ttl",
            "noext",
        ] {
            assert_eq!(MediaKind::from_path(p), MediaKind::Other, "{p}");
        }
    }

    #[test]
    fn content_type_classification() {
        assert_eq!(MediaKind::from_content_type("image/png"), MediaKind::Image);
        assert_eq!(
            MediaKind::from_content_type("image/svg+xml; charset=utf-8"),
            MediaKind::Image
        );
        assert_eq!(MediaKind::from_content_type("video/mp4"), MediaKind::Video);
        assert_eq!(MediaKind::from_content_type("audio/mpeg"), MediaKind::Audio);
        assert_eq!(
            MediaKind::from_content_type("text/turtle"),
            MediaKind::Other
        );
    }

    #[test]
    fn mime_prefers_server_then_extension() {
        // Server content-type wins when meaningful.
        assert_eq!(mime_for("x.bin", Some("image/webp")), "image/webp");
        // Strips parameters.
        assert_eq!(
            mime_for("x.png", Some("image/png; charset=binary")),
            "image/png"
        );
        // octet-stream is ignored in favour of the extension-derived type.
        assert_eq!(
            mime_for("photo.jpg", Some("application/octet-stream")),
            "image/jpeg"
        );
        // No header → derive from extension.
        assert_eq!(mime_for("a/b/clip.webm", None), "video/webm");
        // Unknown extension and no header → octet-stream.
        assert_eq!(mime_for("mystery", None), "application/octet-stream");
    }
}
