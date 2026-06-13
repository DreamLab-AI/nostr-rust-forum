//! Inline media embeds for images, YouTube videos, and encrypted DM images.

use leptos::prelude::*;

use crate::dm::encrypted_media::{decrypt_dm_image, EncryptedImage};
use crate::stores::preferences::use_preferences;

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
        if let Some(pos) = lower.find("v=") {
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
            MediaType::Image => {
                let img_url = url.clone();
                let full_url = url.clone();
                let loaded = RwSignal::new(false);
                let errored = RwSignal::new(false);

                view! {
                <div class="mt-2 max-w-lg">
                    // Skeleton shown while loading
                    <Show when=move || !loaded.get() && !errored.get()>
                        <div class="skeleton h-48 w-full rounded-lg"></div>
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
                        class=move || {
                            if loaded.get() && !errored.get() {
                                "block"
                            } else {
                                "hidden"
                            }
                        }
                    >
                        <img
                            src=img_url
                            alt="Embedded image"
                            class="max-h-[400px] w-auto rounded-lg border border-gray-700/50 hover:border-amber-500/30 transition-colors cursor-pointer"
                            loading="lazy"
                            on:load=move |_| loaded.set(true)
                            on:error=move |_| errored.set(true)
                        />
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

/// Render an encrypted DM image with decryption, lock icon overlay, and loading skeleton.
///
/// Decrypts the image on mount using the recipient's private key, then renders
/// it as a blob URL. Shows a lock icon to indicate the content is encrypted.
#[allow(dead_code)]
#[component]
pub(crate) fn EncryptedMediaEmbed(
    /// JSON-serialized EncryptedImage from a DM event tag.
    encrypted_json: String,
    /// Hex pubkey of the message sender (needed for NIP-44 decryption).
    sender_pubkey: String,
    /// Recipient's 32-byte private key for decryption.
    recipient_privkey: [u8; 32],
) -> impl IntoView {
    let decrypted_url = RwSignal::new(Option::<String>::None);
    let error = RwSignal::new(Option::<String>::None);
    let loading = RwSignal::new(true);

    // Decrypt on mount
    wasm_bindgen_futures::spawn_local(async move {
        let encrypted = match EncryptedImage::from_tag_value(&encrypted_json) {
            Ok(e) => e,
            Err(e) => {
                error.set(Some(format!("Parse error: {e}")));
                loading.set(false);
                return;
            }
        };

        match decrypt_dm_image(&encrypted, &sender_pubkey, &recipient_privkey).await {
            Ok(blob) => match web_sys::Url::create_object_url_with_blob(&blob) {
                Ok(url) => {
                    decrypted_url.set(Some(url));
                }
                Err(e) => {
                    error.set(Some(format!("URL creation: {e:?}")));
                }
            },
            Err(e) => {
                error.set(Some(format!("Decryption failed: {e}")));
            }
        }
        loading.set(false);
    });

    view! {
        <div class="mt-2 max-w-lg relative">
            // Loading skeleton
            <Show when=move || loading.get()>
                <div class="skeleton h-48 w-full rounded-lg flex items-center justify-center">
                    <div class="flex items-center gap-2 text-gray-500 text-xs">
                        <svg class="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 2v4m0 12v4m-7.07-3.93l2.83-2.83m8.48-8.48l2.83-2.83M2 12h4m12 0h4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83"/>
                        </svg>
                        <span>"Decrypting..."</span>
                    </div>
                </div>
            </Show>

            // Error state
            {move || {
                error.get().map(|e| view! {
                    <div class="flex items-center gap-2 text-gray-500 text-xs p-2 bg-gray-800/50 rounded-lg border border-gray-700/50">
                        <svg class="w-4 h-4 flex-shrink-0 text-red-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="5" width="18" height="14" rx="2"/>
                            <path d="M7 5V3a5 5 0 0110 0v2"/>
                        </svg>
                        <span>{e}</span>
                    </div>
                })
            }}

            // Decrypted image with lock overlay
            {move || {
                decrypted_url.get().map(|url| view! {
                    <div class="relative group">
                        <img
                            src=url
                            alt="Encrypted image"
                            class="max-h-[400px] w-auto rounded-lg border border-gray-700/50"
                            loading="lazy"
                        />
                        // Lock icon overlay
                        <div class="absolute top-2 right-2 bg-gray-900/70 backdrop-blur-sm rounded-full p-1.5 flex items-center gap-1">
                            <svg class="w-3 h-3 text-amber-400" viewBox="0 0 24 24" fill="currentColor">
                                <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM9 8V6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9z"/>
                            </svg>
                            <span class="text-[10px] text-amber-400/80 font-medium pr-0.5">"E2E"</span>
                        </div>
                    </div>
                })
            }}
        </div>
    }
}
