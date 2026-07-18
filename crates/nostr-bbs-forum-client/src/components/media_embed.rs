//! Inline media embeds for images, direct video files, and YouTube videos.

use leptos::prelude::*;

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
                        title="Open full image"
                        class=move || {
                            if loaded.get() && !errored.get() {
                                "relative inline-block group"
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
