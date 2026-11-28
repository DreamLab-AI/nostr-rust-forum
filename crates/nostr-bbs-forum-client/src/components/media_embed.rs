//! Inline media embeds for images, direct video files, and YouTube videos.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use leptos::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::stores::preferences::use_preferences;
use crate::utils::restricted_media::{
    cache_blob, cached_blob, fetch_restricted_blob, is_restricted_media_url, RestrictedFetchError,
};

/// How many zone-restricted images in one post load on sight; later ones wait
/// for a tap, so a single post cannot make every viewer sign many requests.
pub(crate) const RESTRICTED_AUTOLOAD_PER_POST: usize = 4;

/// Detected media type from a URL.
#[derive(Clone, Debug, PartialEq)]
enum MediaType {
    Image,
    /// A directly-hosted video file (mp4/webm/ogg/mov) -- rendered with a
    /// native `<video controls>` player.
    Video,
    YouTube(String), // video ID
    Unknown,
}

/// Detect what kind of media a URL points to.
fn detect_media(url: &str) -> MediaType {
    let lower = url.to_lowercase();
    // Strip any query string once for extension checks.
    let path = lower.split('?').next().unwrap_or(&lower);

    // Image extensions
    let image_exts = [".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"];
    for ext in &image_exts {
        if path.ends_with(ext) {
            return MediaType::Image;
        }
    }

    // Direct video file extensions (HTML5 <video>-playable containers).
    let video_exts = [".mp4", ".webm", ".ogg", ".ogv", ".mov", ".m4v"];
    for ext in &video_exts {
        if path.ends_with(ext) {
            return MediaType::Video;
        }
    }

    // YouTube: youtube.com/watch?v=ID or youtu.be/ID
    if lower.contains("youtube.com/watch") {
        // Search and slice the SAME string. `lower` and `url` can differ in
        // byte length (non-ASCII case folding), so a position found in `lower`
        // must never index `url` — that could split a char boundary and panic.
        // Search `url` directly ("v=" is already lowercase) so the extracted,
        // case-sensitive video ID is preserved.
        if let Some(pos) = url.find("v=") {
            let after_v = &url[pos + 2..];
            let video_id: String = after_v
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if !video_id.is_empty() {
                return MediaType::YouTube(video_id);
            }
        }
    } else if lower.contains("youtu.be/") {
        if let Some(pos) = url.find("youtu.be/") {
            let after = &url[pos + 9..];
            let video_id: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if !video_id.is_empty() {
                return MediaType::YouTube(video_id);
            }
        }
    }

    MediaType::Unknown
}

/// Embed images and YouTube videos inline in messages.
///
/// - Images: lazy-loaded `<img>` with max-height, rounded corners, click to open full
/// - YouTube: responsive 16:9 iframe embed
/// - Skeleton loading state before media loads
/// - Graceful fallback on error
#[component]
pub(crate) fn MediaEmbed(
    /// The media URL to embed.
    url: String,
    /// Position of this embed among the post's media (0-based). Zone-restricted
    /// images past [`RESTRICTED_AUTOLOAD_PER_POST`] are tap-to-load.
    #[prop(optional)]
    position: usize,
) -> impl IntoView {
    let media_type = detect_media(&url);

    // Honour the "Show link previews" preference (#wire-settings): when off,
    // inline media derived from a posted link is gated out of the render (and
    // so never loaded), matching link-preview suppression. `prefs` is a `Copy`
    // `RwSignal`, read inside the reactive block so toggling re-renders.
    let prefs = use_preferences();

    move || {
        if !prefs.get().show_link_previews {
            return ().into_any();
        }
        match media_type.clone() {
            MediaType::Image if is_restricted_media_url(&url) => view! {
                <RestrictedImage
                    url=url.clone()
                    auto_load=position < RESTRICTED_AUTOLOAD_PER_POST
                />
            }
            .into_any(),
            MediaType::Image => {
                let img_url = url.clone();
                let full_url = url.clone();
                let loaded = RwSignal::new(false);
                let errored = RwSignal::new(false);

                view! {
                <div class="mt-2 max-w-lg">
                    // Reserved box shown while loading: a 4:3 placeholder at the
                    // embed's width (`max-w-lg`, so at most 384px tall, inside the
                    // image's own 400px cap). It is released on load, so the image
                    // appears at its natural aspect with no letterboxing; an
                    // error swaps it for the one-line notice below, so a broken
                    // image never leaves an empty box behind.
                    <Show when=move || !loaded.get() && !errored.get()>
                        <div class="skeleton aspect-[4/3] max-h-[400px] w-full rounded-lg"></div>
                    </Show>

                    // Error state
                    <Show when=move || errored.get()>
                        <div class="flex items-center gap-2 text-gray-500 text-xs p-2 bg-gray-800/50 rounded-lg border border-gray-700/50">
                            <svg class="w-4 h-4 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                                <circle cx="8.5" cy="8.5" r="1.5"/>
                                <polyline points="21 15 16 10 5 21"/>
                            </svg>
                            <span>"Failed to load image"</span>
                        </div>
                    </Show>

                    // Image (hidden until loaded)
                    <a
                        href=full_url
                        target="_blank"
                        rel="noopener noreferrer"
                        title="Open full image"
                        class=move || {
                            if loaded.get() && !errored.get() {
                                "relative inline-block group"
                            } else {
                                "hidden"
                            }
                        }
                    >
                        // MUST load eagerly: this <img> sits inside the
                        // hidden-until-loaded <a> above, and a `loading="lazy"`
                        // image inside a display:none box never intersects the
                        // viewport, so the browser never fetches it — on:load
                        // never fires and the skeleton deadlocks forever (an
                        // already-cached image masks the bug, which is how it
                        // survived verification).
                        <img
                            src=img_url
                            alt="Embedded image"
                            class="max-h-[400px] w-auto rounded-lg border border-gray-700/50 hover:border-amber-500/30 transition-colors cursor-pointer"
                            decoding="async"
                            on:load=move |_| loaded.set(true)
                            on:error=move |_| errored.set(true)
                        />
                        // Hover-revealed "open full" affordance — hidden by default,
                        // so the raw URL never has to be shown as text.
                        <span
                            class="absolute top-2 right-2 p-1.5 rounded-md bg-black/60 text-gray-100 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none"
                            aria-hidden="true"
                        >
                            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="15 3 21 3 21 9" stroke-linecap="round" stroke-linejoin="round"/>
                                <polyline points="9 21 3 21 3 15" stroke-linecap="round" stroke-linejoin="round"/>
                                <line x1="21" y1="3" x2="14" y2="10" stroke-linecap="round"/>
                                <line x1="3" y1="21" x2="10" y2="14" stroke-linecap="round"/>
                            </svg>
                        </span>
                    </a>
                </div>
            }
            .into_any()
            }
            MediaType::Video => {
                // Native HTML5 player for directly-hosted video (e.g. an uploaded
                // .mp4 on the user's pod). Lazy metadata preload keeps the feed light.
                let video_url = url.clone();
                view! {
                <div class="mt-2 max-w-lg">
                    <video
                        src=video_url
                        class="max-h-[400px] w-auto rounded-lg border border-gray-700/50 bg-black"
                        controls=true
                        preload="metadata"
                        playsinline=true
                    >
                        "Your browser does not support embedded video."
                    </video>
                </div>
            }
            .into_any()
            }
            MediaType::YouTube(video_id) => {
                let embed_url = format!("https://www.youtube-nocookie.com/embed/{}", video_id);

                view! {
                <div class="mt-2 max-w-lg">
                    <div class="relative w-full overflow-hidden rounded-lg border border-gray-700/50" style="padding-top: 56.25%">
                        <iframe
                            src=embed_url
                            class="absolute inset-0 w-full h-full border-0"
                            allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                            allowfullscreen=true
                            // The page sends no Referer (ADR-2025); YouTube refuses an
                            // embed with none ("Error 153"), so this frame opts back in
                            // to the browser default.
                            referrerpolicy="strict-origin-when-cross-origin"
                            title="YouTube video"
                        />
                    </div>
                </div>
            }
            .into_any()
            }
            MediaType::Unknown => {
                // Not a recognized media URL -- render nothing
                view! { <span></span> }.into_any()
            }
        }
    }
}

/// Load state of a zone-restricted image.
#[derive(Clone, Debug, PartialEq)]
enum RestrictedState {
    /// Not yet in view.
    Idle,
    /// Waiting for a tap (NIP-07 signer, or past the per-post auto-load cap).
    NeedsTap,
    /// Signing and fetching.
    Loading,
    /// Rendered from this component's own object URL.
    Loaded(String),
    /// 401/403, or signed out: not readable by this viewer.
    Locked,
    /// Anything else.
    Failed,
}

/// A zone-restricted pod image (`…/media/zones/<zone>/<name>`).
///
/// `<img src>` cannot carry NIP-98, so the bytes are fetched with a signed GET
/// once the placeholder scrolls into view, kept as a Blob in a small per-user
/// LRU, and shown through an object URL this component creates and revokes on
/// unmount. A viewer whose zone membership does not cover the image sees a
/// locked placeholder; the pod decides, at request time, from live membership.
#[component]
fn RestrictedImage(
    /// The restricted URL (already checked to be on this deployment's pod).
    url: String,
    /// Fetch on sight (else wait for a tap).
    auto_load: bool,
) -> impl IntoView {
    let auth = crate::auth::use_auth();
    let state = RwSignal::new(RestrictedState::Idle);
    let placeholder = NodeRef::<leptos::html::Div>::new();

    // This component's object URL and liveness: an await that lands after
    // unmount must not mint a URL nobody will revoke.
    let alive = Rc::new(Cell::new(true));
    let object_url: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    {
        let guard = send_wrapper::SendWrapper::new((alive.clone(), object_url.clone()));
        on_cleanup(move || {
            let (alive, object_url) = guard.take();
            alive.set(false);
            let taken = object_url.borrow_mut().take();
            if let Some(u) = taken {
                let _ = web_sys::Url::revoke_object_url(&u);
            }
        });
    }

    // Show `blob` through a fresh object URL owned by this component.
    let show: Rc<dyn Fn(&web_sys::Blob)> = {
        let alive = alive.clone();
        let object_url = object_url.clone();
        Rc::new(move |blob: &web_sys::Blob| {
            if !alive.get() {
                return;
            }
            match web_sys::Url::create_object_url_with_blob(blob) {
                Ok(u) => {
                    if let Some(old) = object_url.borrow_mut().replace(u.clone()) {
                        let _ = web_sys::Url::revoke_object_url(&old);
                    }
                    state.try_set(RestrictedState::Loaded(u));
                }
                Err(_) => {
                    state.try_set(RestrictedState::Failed);
                }
            }
        })
    };

    // Sign + fetch (or reuse a cached blob).
    let start: Rc<dyn Fn()> = {
        let url = url.clone();
        let alive = alive.clone();
        let show = show.clone();
        Rc::new(move || {
            let Some(owner) = auth.pubkey().get_untracked() else {
                state.try_set(RestrictedState::Locked);
                return;
            };
            if let Some(blob) = cached_blob(&owner, &url) {
                show(&blob);
                return;
            }
            let Some(signer) = auth.get_signer() else {
                state.try_set(RestrictedState::Locked);
                return;
            };
            state.try_set(RestrictedState::Loading);
            let url = url.clone();
            let alive = alive.clone();
            let show = show.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let result = fetch_restricted_blob(&url, signer.as_ref()).await;
                if !alive.get() {
                    return;
                }
                match result {
                    Ok(blob) => {
                        cache_blob(&owner, &url, &blob);
                        show(&blob);
                    }
                    Err(RestrictedFetchError::Locked) => {
                        state.try_set(RestrictedState::Locked);
                    }
                    Err(RestrictedFetchError::Failed(e)) => {
                        web_sys::console::warn_1(&format!("[zone media] {e}").into());
                        state.try_set(RestrictedState::Failed);
                    }
                }
            });
        })
    };

    // A NIP-07 extension may prompt for every signature: never sign unasked.
    let manual = !auto_load || auth.state().with_untracked(|st| st.is_nip07);

    // Already cached for this viewer: show at once, no observer, no request.
    let cached_now = auth
        .pubkey()
        .get_untracked()
        .and_then(|owner| cached_blob(&owner, &url));
    if let Some(blob) = cached_now {
        show(&blob);
    }

    {
        let start = send_wrapper::SendWrapper::new(start.clone());
        Effect::new(move |_| {
            let Some(el) = placeholder.get() else {
                return;
            };
            if state.get_untracked() != RestrictedState::Idle {
                return;
            }
            let start = (*start).clone();
            let callback = Closure::wrap(Box::new(
                move |entries: js_sys::Array, observer: web_sys::IntersectionObserver| {
                    for i in 0..entries.length() {
                        let entry: web_sys::IntersectionObserverEntry =
                            entries.get(i).unchecked_into();
                        if entry.is_intersecting() {
                            observer.disconnect();
                            if manual {
                                state.try_set(RestrictedState::NeedsTap);
                            } else {
                                start();
                            }
                            break;
                        }
                    }
                },
            )
                as Box<dyn FnMut(js_sys::Array, web_sys::IntersectionObserver)>);
            let opts = web_sys::IntersectionObserverInit::new();
            opts.set_threshold(&JsValue::from_f64(0.01));
            if let Ok(observer) = web_sys::IntersectionObserver::new_with_options(
                callback.as_ref().unchecked_ref(),
                &opts,
            ) {
                let target: &web_sys::Element = &el;
                observer.observe(target);
                let guard = send_wrapper::SendWrapper::new((observer, callback));
                on_cleanup(move || {
                    let (observer, callback) = guard.take();
                    observer.disconnect();
                    drop(callback);
                });
            }
        });
    }

    let tap = send_wrapper::SendWrapper::new(start);

    view! {
        <div class="mt-2 max-w-lg">
            {move || match state.get() {
                RestrictedState::Loaded(src) => {
                    let href = src.clone();
                    view! {
                        <a
                            href=href
                            target="_blank"
                            rel="noopener noreferrer"
                            title="Open full image"
                            class="relative inline-block"
                        >
                            <img
                                src=src
                                alt="Embedded image"
                                class="max-h-[400px] w-auto rounded-lg border border-gray-700/50 hover:border-amber-500/30 transition-colors cursor-pointer"
                                decoding="async"
                            />
                        </a>
                    }
                    .into_any()
                }
                RestrictedState::Locked => view! {
                    <div
                        class="flex items-center gap-2 text-gray-400 text-xs p-3 bg-gray-800/60 rounded-lg border border-gray-700/50"
                        role="img"
                        aria-label="Image restricted to zone members"
                    >
                        <svg class="w-4 h-4 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                            <rect x="5" y="11" width="14" height="10" rx="2"/>
                            <path d="M8 11V7a4 4 0 018 0v4" stroke-linecap="round"/>
                        </svg>
                        <span>"Image restricted to members of this zone"</span>
                    </div>
                }
                .into_any(),
                RestrictedState::Failed => view! {
                    <div class="flex items-center gap-2 text-gray-500 text-xs p-2 bg-gray-800/50 rounded-lg border border-gray-700/50">
                        <svg class="w-4 h-4 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                            <circle cx="8.5" cy="8.5" r="1.5"/>
                            <polyline points="21 15 16 10 5 21"/>
                        </svg>
                        <span>"Failed to load image"</span>
                    </div>
                }
                .into_any(),
                RestrictedState::NeedsTap => {
                    let tap = tap.clone();
                    view! {
                        <button
                            type="button"
                            class="flex items-center justify-center gap-2 h-32 w-full rounded-lg border border-gray-700/50 bg-gray-800/60 text-gray-300 text-xs hover:border-amber-500/30"
                            on:click=move |_| (*tap)()
                        >
                            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                                <circle cx="8.5" cy="8.5" r="1.5"/>
                                <polyline points="21 15 16 10 5 21"/>
                            </svg>
                            "Tap to load image"
                        </button>
                    }
                    .into_any()
                }
                // Idle / Loading: a VISIBLE box (an element inside a hidden
                // box never intersects, so the observer would never fire).
                RestrictedState::Idle | RestrictedState::Loading => view! {
                    <div
                        node_ref=placeholder
                        class="skeleton h-48 w-full rounded-lg flex items-center justify-center text-gray-500 text-xs"
                        aria-busy="true"
                    >
                        "Loading image…"
                    </div>
                }
                .into_any(),
            }}
        </div>
    }
}
