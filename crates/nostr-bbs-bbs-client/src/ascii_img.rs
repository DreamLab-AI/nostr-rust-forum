//! On-theme ASCII image rendering.
//!
//! The retro rule is "stay on theme at all times" — there is no raw `<img>` in
//! the BBS. Every image surface (banner, pod File Base, Message Base posts)
//! becomes ASCII art. The image→ASCII conversion happens **server-side**:
//!
//! * the preview-worker exposes
//!   `GET /ascii?url=<imgurl>&cols=<n>&ramp=<standard|blocks|dense>`, and
//! * the pod-worker serves any pod image resource as the same fragment when
//!   requested with `?format=ascii`.
//!
//! Both return an HTML fragment
//! `<pre class="ascii-img" aria-hidden="true"><span class="pN">…</span>…</pre>`
//! whose `pN` cells (p0..p7) are theme-agnostic phosphor levels; `assets/bbs.css`
//! recolours them per active theme via `color-mix` on the theme vars.
//!
//! This module is the CLIENT side: [`AsciiImg`] fetches the fragment for a given
//! image URL and injects it. Pod-hosted images are tried **directly** with
//! `?format=ascii` first (the DreamLab pod-worker renders them itself), then
//! **fall back** to the preview endpoint. That fallback is load-bearing: a pod
//! that does not implement `?format=ascii` (e.g. a local `solid-pod-rs` dev pod,
//! which ignores the param and returns the raw image as `application/octet-stream`)
//! makes the direct fetch fail the `text/html` gate; the client then routes the
//! public pod URL through the preview-worker, which converts it server-side. Only
//! when every route fails does it degrade to `[ image unavailable ]` — never a
//! raw `JsValue` and never a panic. The pure URL/parsing helpers are unit-tested
//! on the native target; the `fetch` itself is wasm-only.
//!
//! **Protected media is never sent anywhere.** A zone image
//! (`…/media/zones/…`) or any other non-public pod resource needs the
//! member's own credentials, which neither the preview worker nor an
//! unauthenticated pod request has: the preview worker answered such URLs
//! with 400 after the pod refused it. [`ascii_route`] classifies them first
//! ([`is_protected_media`]) and [`AsciiImg`] shows a placeholder with the
//! file name (and, where the caller passes one, a link to the post in the
//! forum, which can show it) without making a request. Each outcome is kept
//! for the session (`ascii_slot`), so a re-rendered post never repeats a
//! request, failed or not.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

use leptos::prelude::*;
use url::Url;

use crate::config::BbsConfig;

/// Default column width for the ASCII grid when a caller doesn't specify one.
pub const DEFAULT_COLS: u32 = 80;

/// Async load state for a single ASCII image fragment.
///
/// `Loaded` is only constructed on wasm (after a successful fetch); on the
/// native target the fetch is compiled out, so silence the dead-code lint there.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
enum AsciiState {
    /// Fetch in flight.
    Loading,
    /// Server-rendered HTML fragment ready to inject.
    Loaded(String),
    /// Media only the member's own credentials can read: never fetched.
    Protected,
    /// Fetch failed / no endpoint / wrong content-type.
    Error,
}

/// Most outcomes kept for the session (oldest dropped first).
const ASCII_CACHE_MAX: usize = 256;

/// Session outcomes of ASCII renders: each key's slot, and the keys oldest
/// first (for eviction past [`ASCII_CACHE_MAX`]).
#[derive(Default)]
struct AsciiCache {
    slots: HashMap<String, ArcRwSignal<AsciiState>>,
    order: VecDeque<String>,
}

thread_local! {
    /// Outcome of each ASCII render this session, keyed by
    /// [`ascii_cache_key`]: a remounted image (a post re-rendered by a store
    /// update, a revisited thread) reuses it instead of fetching again, and a
    /// request in flight is shared rather than repeated.
    static ASCII_CACHE: RefCell<AsciiCache> = RefCell::new(AsciiCache::default());
}

/// The session slot for `key`, and whether it is new (the caller then
/// fetches into it). A new slot starts as `initial`.
fn ascii_slot(key: &str, initial: AsciiState) -> (ArcRwSignal<AsciiState>, bool) {
    ASCII_CACHE.with(|cache| {
        let AsciiCache { slots: map, order } = &mut *cache.borrow_mut();
        if let Some(slot) = map.get(key) {
            return (slot.clone(), false);
        }
        if order.len() >= ASCII_CACHE_MAX {
            if let Some(oldest) = order.pop_front() {
                map.remove(&oldest);
            }
        }
        let slot = ArcRwSignal::new(initial);
        map.insert(key.to_string(), slot.clone());
        order.push_back(key.to_string());
        (slot, true)
    })
}

/// The session cache key of an image render.
fn ascii_cache_key(src: &str, cols: u32, ramp: &str) -> String {
    format!("{cols}|{ramp}|{src}")
}

/// How [`AsciiImg`] renders an image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsciiRoute {
    /// Protected media ([`is_protected_media`]): a placeholder, no request.
    Protected,
    /// Try these fragment URLs in order ([`ascii_fetch_urls`]).
    Fetch(Vec<String>),
    /// No endpoint can serve it (blank `src`, no preview API).
    Unavailable,
}

/// Decide how to render `src`: protected media first, so its URL never
/// reaches the preview worker or an unauthenticated pod request.
pub fn ascii_route(
    preview_api: &str,
    pod_api: &str,
    src: &str,
    cols: u32,
    ramp: &str,
) -> AsciiRoute {
    if is_protected_media(src) {
        return AsciiRoute::Protected;
    }
    let urls = ascii_fetch_urls(preview_api, pod_api, src, cols, ramp);
    if urls.is_empty() {
        AsciiRoute::Unavailable
    } else {
        AsciiRoute::Fetch(urls)
    }
}

/// Render an image as on-theme ASCII art.
///
/// On mount it fetches the server-rendered phosphor fragment for `src` and
/// injects it, once per session (see `ascii_slot`). While loading it shows
/// `[ loading ascii … ]`. Protected media is never fetched, and it and any
/// failure show a placeholder naming the file, with an "Open in forum" link
/// when `forum_href` is given. Endpoints come from [`BbsConfig`] in context
/// (`preview_api` for arbitrary URLs, `pod_api` for pod-hosted images).
#[component]
pub fn AsciiImg(
    /// Image URL to render.
    src: String,
    /// ASCII grid width in columns.
    #[prop(default = DEFAULT_COLS)]
    cols: u32,
    /// Phosphor ramp: `standard`, `blocks`, or `dense`.
    #[prop(default = String::from("standard"))]
    ramp: String,
    /// Where the forum shows the post this image belongs to, for media the
    /// BBS cannot render.
    #[prop(optional)]
    forum_href: Option<String>,
) -> impl IntoView {
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("config");
    let (preview_api, pod_api) = cfg.with_value(|c| (c.preview_api.clone(), c.pod_api.clone()));
    // Resolve a root-relative src (e.g. a zone banner "/images/heroes/x.webp")
    // to an absolute URL — the /ascii endpoint fetches server-side and cannot
    // resolve a client-relative path.
    #[cfg(target_arch = "wasm32")]
    let src = make_absolute(&current_origin(), &src);
    let name = media_file_name(&src);
    let protected_why = protected_reason(&src);
    let route = ascii_route(&preview_api, &pod_api, &src, cols, &ramp);
    let initial = match &route {
        AsciiRoute::Protected => AsciiState::Protected,
        AsciiRoute::Fetch(_) => AsciiState::Loading,
        AsciiRoute::Unavailable => AsciiState::Error,
    };
    let (state, fresh) = ascii_slot(&ascii_cache_key(&src, cols, &ramp), initial);

    if let (true, AsciiRoute::Fetch(fetch_urls)) = (fresh, route) {
        #[cfg(target_arch = "wasm32")]
        {
            let state = state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                // Try each candidate in priority order (pod-direct, then
                // preview fallback); the first `text/html` fragment wins. When
                // every candidate fails the slot records it, so no later mount
                // asks again. The slot is not owned by this component, so it
                // outlives an unmounted post.
                for url in &fetch_urls {
                    if let Ok(html) = fetch_ascii(url).await {
                        state.set(AsciiState::Loaded(html));
                        return;
                    }
                }
                state.set(AsciiState::Error);
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = fetch_urls;
    }

    move || match state.get() {
        AsciiState::Loading => view! {
            <pre class="ascii-img ascii-img-status">"[ loading ascii … ]"</pre>
        }
        .into_any(),
        AsciiState::Protected => view! {
            <MediaPlaceholder
                name=name.clone()
                reason=protected_why
                forum_href=forum_href.clone()
            />
        }
        .into_any(),
        AsciiState::Error => view! {
            <MediaPlaceholder
                name=name.clone()
                reason="image unavailable"
                forum_href=forum_href.clone()
            />
        }
        .into_any(),
        // The fragment is server-generated by our own workers and already
        // HTML-escaped (only <pre>/<span class="pN"> structure); inject it.
        AsciiState::Loaded(html) => view! {
            <div class="ascii-img-wrap" inner_html=html></div>
        }
        .into_any(),
    }
}

/// The inline stand-in for an image the BBS cannot render: its file name,
/// why, and a link to the post in the forum when there is one.
#[component]
pub fn MediaPlaceholder(
    /// The image's file name ([`media_file_name`]).
    name: String,
    /// Why it is not shown, e.g. "protected zone media".
    reason: &'static str,
    /// The post in the forum, which can show the image.
    forum_href: Option<String>,
) -> impl IntoView {
    view! {
        <div class="ascii-img ascii-img-status" role="note">
            <span>{format!("[ {name} · {reason} ]")}</span>
            {forum_href.map(|href| view! {
                " "
                <a href=href rel="noopener">"Open in forum ↗"</a>
            })}
        </div>
    }
}

/// Whether `src` is media only the member's own credentials can read, which
/// must never be sent to the preview worker (or fetched without credentials):
/// a zone image (a `media/zones/` path on any host), or any pod resource
/// (`/pods/<owner>/…` on any host) outside its `public/` and `media/public/`
/// containers. Decided on the path alone and failing closed: a lookalike host
/// is still treated as protected, since the cost is a placeholder rather than
/// a leaked URL. The path is percent-decoded first.
pub fn is_protected_media(src: &str) -> bool {
    let raw = src.trim();
    let path = match Url::parse(raw) {
        Ok(u) => u.path().to_string(),
        Err(_) => raw.split(['?', '#']).next().unwrap_or_default().to_string(),
    };
    let path = percent_decode(&path).to_ascii_lowercase();
    if path.contains("/media/zones/") || path.starts_with("media/zones/") {
        return true;
    }
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segs.iter().position(|s| *s == "pods") {
        Some(i) if segs.len() > i + 2 => {
            let rest = &segs[i + 2..];
            !(rest[0] == "public" || (rest[0] == "media" && rest.get(1) == Some(&"public")))
        }
        _ => false,
    }
}

/// How a placeholder names protected media: a zone image, or a member's own
/// non-public pod file (the File Base).
pub fn protected_reason(src: &str) -> &'static str {
    if percent_decode(src)
        .to_ascii_lowercase()
        .contains("/media/zones/")
    {
        "protected zone media"
    } else {
        "private pod file"
    }
}

/// The file name of an image URL for a placeholder: the last path segment,
/// percent-decoded, without query or fragment; "image" when there is none.
pub fn media_file_name(src: &str) -> String {
    let path = src.trim().split(['?', '#']).next().unwrap_or_default();
    let path = path.split_once("://").map_or(path, |(_, rest)| {
        rest.split_once('/').map_or("", |(_, p)| p)
    });
    let last = path.rsplit('/').find(|s| !s.is_empty()).unwrap_or_default();
    let name = percent_decode(last);
    let name = name.trim();
    if name.is_empty() {
        "image".to_string()
    } else {
        name.chars().take(80).collect()
    }
}

/// Decode `%XX` escapes (invalid escapes and non-UTF-8 results are kept as
/// they were).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(b) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// Is `src` a resource hosted under the configured pod API base?
///
/// Uses a parsed-URL **exact authority match** (scheme + host + port), not a
/// bare string prefix. A pod URL is treated as first-party and its ASCII
/// fragment is injected as trusted HTML (see [`AsciiImg`]), so a lookalike host
/// like `https://pods.example.com.evil.com/x.png` — which *prefix*-matches
/// `pods.example.com` — must NOT be classified as pod-hosted, or it becomes a
/// stored-XSS sink. Only a genuine same-origin pod host qualifies.
pub fn is_pod_url(pod_api: &str, src: &str) -> bool {
    if pod_api.is_empty() {
        return false;
    }
    let (Ok(base), Ok(target)) = (Url::parse(pod_api), Url::parse(src)) else {
        return false;
    };
    // host_str() is None for cannot-be-a-base / hostless URLs; require both
    // present and byte-equal (url normalises host case), same scheme, same
    // effective port (default port for the scheme when unspecified).
    base.host_str().is_some()
        && base.scheme() == target.scheme()
        && base.host_str() == target.host_str()
        && base.port_or_known_default() == target.port_or_known_default()
}

/// Resolve a possibly root-relative URL against `origin`. Absolute http(s) URLs
/// and empty strings pass through unchanged; `"/path"` and `"path"` are joined
/// onto the origin. The `/ascii` endpoint fetches server-side, so the URL it
/// receives must be absolute.
pub fn make_absolute(origin: &str, src: &str) -> String {
    let s = src.trim();
    if s.is_empty() || s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!(
            "{}/{}",
            origin.trim_end_matches('/'),
            s.trim_start_matches('/')
        )
    }
}

/// The current document origin (wasm), e.g. `https://dreamlab-ai.com`.
#[cfg(target_arch = "wasm32")]
fn current_origin() -> String {
    web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_default()
}

/// Build the ordered list of candidate URLs to fetch the ASCII fragment for
/// `src`. [`AsciiImg`] tries them in order and injects the first that returns a
/// `text/html` fragment, so position encodes priority:
///
/// 1. **Pod-hosted images** are fetched directly with `?format=ascii` (plus
///    `cols`/`ramp`) — the DreamLab pod-worker renders them itself, saving a hop.
/// 2. **Fallback for pod images**, and the sole route for everything else, is the
///    preview-worker's `/ascii` endpoint with the image URL percent-encoded. For
///    a pod image this fallback is what keeps the signature ASCII render working
///    when the pod does not implement `?format=ascii` (a local `solid-pod-rs` dev
///    pod returns the raw image, failing the direct fetch's `text/html` gate):
///    the preview-worker fetches the public pod URL server-side and converts it.
///
/// Returns an empty vec when no route can serve the image (blank `src`, or a
/// non-pod URL with no preview API configured), so the caller renders the
/// `[ image unavailable ]` placeholder.
pub fn ascii_fetch_urls(
    preview_api: &str,
    pod_api: &str,
    src: &str,
    cols: u32,
    ramp: &str,
) -> Vec<String> {
    if src.trim().is_empty() {
        return Vec::new();
    }
    // The preview-worker route: sole route for non-pod images, fallback for pods.
    let preview_route = {
        let base = preview_api.trim_end_matches('/');
        (!base.is_empty()).then(|| {
            format!(
                "{base}/ascii?url={}&cols={cols}&ramp={ramp}",
                encode_uri_component(src)
            )
        })
    };
    let mut urls = Vec::new();
    if is_pod_url(pod_api, src) {
        let sep = if src.contains('?') { '&' } else { '?' };
        urls.push(format!("{src}{sep}format=ascii&cols={cols}&ramp={ramp}"));
        urls.extend(preview_route);
    } else {
        urls.extend(preview_route);
    }
    urls
}

/// The primary (highest-priority) fetch URL for `src`, or `None` when no route
/// can serve it. This is the first element of [`ascii_fetch_urls`] — pod-direct
/// for pod-hosted images, the preview endpoint otherwise. Prefer
/// [`ascii_fetch_urls`] when the fallback chain matters (as [`AsciiImg`] does).
pub fn ascii_fetch_url(
    preview_api: &str,
    pod_api: &str,
    src: &str,
    cols: u32,
    ramp: &str,
) -> Option<String> {
    ascii_fetch_urls(preview_api, pod_api, src, cols, ramp)
        .into_iter()
        .next()
}

/// Whether a filename looks like a renderable raster image.
pub fn is_image_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let stem = lower.split(['?', '#']).next().unwrap_or(&lower);
    matches!(
        stem.rsplit('.').next(),
        Some("png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp")
    ) && stem.contains('.')
}

/// Whether `s` is an absolute http(s) image URL.
pub fn is_image_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return false;
    }
    is_image_name(&lower)
}

/// Extract image URLs from free-form post content.
///
/// Splits on whitespace, strips wrapping punctuation/markdown delimiters, and
/// keeps tokens that are absolute http(s) URLs ending in a known image
/// extension. De-duplicated, order-preserving.
pub fn extract_image_urls(content: &str) -> Vec<String> {
    const TRIM: &[char] = &[
        '(', ')', '[', ']', '<', '>', '{', '}', '"', '\'', '`', ',', '.', '!', '?', ';', ':', '|',
        '*', '~',
    ];
    let mut out: Vec<String> = Vec::new();
    for tok in content.split_whitespace() {
        let url = tok.trim_matches(TRIM);
        if is_image_url(url) && !out.iter().any(|u| u == url) {
            out.push(url.to_string());
        }
    }
    out
}

/// Percent-encode a string the way JavaScript's `encodeURIComponent` does:
/// every byte except the unreserved set `A-Z a-z 0-9 - _ . ! ~ * ' ( )`.
fn encode_uri_component(s: &str) -> String {
    fn hex(n: u8) -> char {
        match n {
            0..=9 => (b'0' + n) as char,
            _ => (b'A' + (n - 10)) as char,
        }
    }
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'~'
            | b'*'
            | b'\''
            | b'('
            | b')' => out.push(b as char),
            _ => {
                out.push('%');
                out.push(hex(b >> 4));
                out.push(hex(b & 0x0f));
            }
        }
    }
    out
}

/// Fetch a server-rendered ASCII fragment. Wasm-only (uses the Fetch API).
///
/// Only injects the body when the response is `text/html` from our own workers;
/// the fragment is server-generated and already HTML-escaped.
#[cfg(target_arch = "wasm32")]
async fn fetch_ascii(url: &str) -> Result<String, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    let init = web_sys::RequestInit::new();
    init.set_method("GET");
    init.set_mode(web_sys::RequestMode::Cors);
    if let Ok(headers) = web_sys::Headers::new() {
        let _ = headers.set("Accept", "text/html");
        init.set_headers(&headers);
    }
    let request = web_sys::Request::new_with_str_and_init(url, &init)
        .map_err(|e| format!("bad request: {e:?}"))?;
    let win = web_sys::window().ok_or("no window")?;
    let resp_val = JsFuture::from(win.fetch_with_request(&request))
        .await
        .map_err(|e| format!("fetch failed: {e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "not a Response".to_string())?;
    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let ctype = resp
        .headers()
        .get("content-type")
        .ok()
        .flatten()
        .unwrap_or_default();
    if !ctype.to_ascii_lowercase().contains("text/html") {
        return Err(format!("unexpected content-type: {ctype}"));
    }
    let text_val = JsFuture::from(resp.text().map_err(|e| format!("{e:?}"))?)
        .await
        .map_err(|e| format!("read failed: {e:?}"))?;
    Ok(text_val.as_string().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_url_detection() {
        assert!(is_pod_url(
            "https://pods.example.com",
            "https://pods.example.com/pods/ab/x.png"
        ));
        assert!(is_pod_url(
            "https://pods.example.com/",
            "https://pods.example.com/pods/ab/x.png"
        ));
        assert!(!is_pod_url("", "https://pods.example.com/pods/ab/x.png"));
        assert!(!is_pod_url(
            "https://pods.example.com",
            "https://cdn.other.com/x.png"
        ));
    }

    #[test]
    fn pod_url_rejects_authority_lookalikes() {
        // Stored-XSS regression: a bare-prefix check would classify these as
        // pod-hosted (and inject their fragment as trusted HTML). An authority
        // match must reject every one.
        let pod = "https://pods.example.com";
        // Suffix-appended lookalike domain (the classic `.evil.com` bypass).
        assert!(!is_pod_url(pod, "https://pods.example.com.evil.com/x.png"));
        // Userinfo trick: real host is evil.com, pod host is only in userinfo.
        assert!(!is_pod_url(pod, "https://pods.example.com@evil.com/x.png"));
        // Scheme downgrade must not match an https pod base.
        assert!(!is_pod_url(pod, "http://pods.example.com/x.png"));
        // Non-default port on the same host is a different authority.
        assert!(!is_pod_url(pod, "https://pods.example.com:8443/x.png"));
        // Sub-host prefix without a dot boundary.
        assert!(!is_pod_url(pod, "https://pods.example.computer/x.png"));
        // Relative / non-absolute src cannot be a pod URL.
        assert!(!is_pod_url(pod, "/pods/ab/x.png"));
        // Explicit default port on both sides still matches the genuine host.
        assert!(is_pod_url(
            "https://pods.example.com:443",
            "https://pods.example.com/pods/ab/x.png"
        ));
    }

    #[test]
    fn pod_image_fetches_with_format_ascii() {
        let url = ascii_fetch_url(
            "https://preview.example.com",
            "https://pods.example.com",
            "https://pods.example.com/pods/ab/cat.png",
            72,
            "standard",
        )
        .expect("url");
        assert_eq!(
            url,
            "https://pods.example.com/pods/ab/cat.png?format=ascii&cols=72&ramp=standard"
        );
    }

    #[test]
    fn pod_image_with_query_uses_ampersand() {
        let url = ascii_fetch_url(
            "https://preview.example.com",
            "https://pods.example.com",
            "https://pods.example.com/pods/ab/cat.png?v=2",
            64,
            "blocks",
        )
        .expect("url");
        assert_eq!(
            url,
            "https://pods.example.com/pods/ab/cat.png?v=2&format=ascii&cols=64&ramp=blocks"
        );
    }

    #[test]
    fn external_image_routes_through_preview_and_is_encoded() {
        let url = ascii_fetch_url(
            "https://preview.example.com/",
            "https://pods.example.com",
            "https://cdn.other.com/a b.png?x=1&y=2",
            80,
            "standard",
        )
        .expect("url");
        assert_eq!(
            url,
            "https://preview.example.com/ascii?url=https%3A%2F%2Fcdn.other.com%2Fa%20b.png%3Fx%3D1%26y%3D2&cols=80&ramp=standard"
        );
    }

    #[test]
    fn no_endpoint_for_external_image_is_none() {
        assert!(ascii_fetch_url(
            "",
            "https://pods.example.com",
            "https://cdn.other.com/x.png",
            80,
            "standard"
        )
        .is_none());
        assert!(ascii_fetch_url("", "", "  ", 80, "standard").is_none());
    }

    #[test]
    fn pod_image_falls_back_to_preview_route() {
        // A local `solid-pod-rs` pod ignores `?format=ascii` and returns the raw
        // image, so the direct fetch fails the `text/html` gate. The candidate
        // list must carry a preview-worker fallback (the public pod URL routed
        // server-side) so the ASCII still renders. Ordering is pod-direct first.
        let urls = ascii_fetch_urls(
            "https://preview.example.com",
            "https://pods.example.com",
            "https://pods.example.com/pods/ab/media/public/cat.jpg",
            64,
            "standard",
        );
        assert_eq!(
            urls,
            vec![
                "https://pods.example.com/pods/ab/media/public/cat.jpg?format=ascii&cols=64&ramp=standard".to_string(),
                "https://preview.example.com/ascii?url=https%3A%2F%2Fpods.example.com%2Fpods%2Fab%2Fmedia%2Fpublic%2Fcat.jpg&cols=64&ramp=standard".to_string(),
            ]
        );
    }

    #[test]
    fn pod_image_without_preview_has_only_direct_candidate() {
        // No preview API configured → the pod-direct route is the only candidate;
        // if it fails there is nothing to fall back to (graceful `[ image
        // unavailable ]`).
        let urls = ascii_fetch_urls(
            "",
            "https://pods.example.com",
            "https://pods.example.com/pods/ab/cat.png",
            72,
            "standard",
        );
        assert_eq!(
            urls,
            vec![
                "https://pods.example.com/pods/ab/cat.png?format=ascii&cols=72&ramp=standard"
                    .to_string()
            ]
        );
    }

    #[test]
    fn external_image_has_single_preview_candidate() {
        // Non-pod images have no direct route — only the preview endpoint, so
        // there is exactly one candidate and no spurious pod-direct fetch.
        let urls = ascii_fetch_urls(
            "https://preview.example.com",
            "https://pods.example.com",
            "https://cdn.other.com/x.png",
            80,
            "standard",
        );
        assert_eq!(
            urls,
            vec![
                "https://preview.example.com/ascii?url=https%3A%2F%2Fcdn.other.com%2Fx.png&cols=80&ramp=standard"
                    .to_string()
            ]
        );
    }

    #[test]
    fn no_route_yields_empty_candidate_list() {
        assert!(ascii_fetch_urls(
            "",
            "https://pods.example.com",
            "https://cdn.other.com/x.png",
            80,
            "standard"
        )
        .is_empty());
        assert!(ascii_fetch_urls("", "", "  ", 80, "standard").is_empty());
    }

    const OWNER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn zone_media_is_protected_on_any_host_and_never_routed() {
        let zone_img = format!("https://pods.example.com/pods/{OWNER}/media/zones/zone2/cat.png");
        assert!(is_protected_media(&zone_img));
        // Lookalike or unconfigured host: still protected (fail closed).
        assert!(is_protected_media(&format!(
            "https://pods.example.com.evil.com/pods/{OWNER}/media/zones/z/x.jpg"
        )));
        assert!(is_protected_media(&format!(
            "https://other.example/pods/{OWNER}/media/zones/z/x.jpg?v=1"
        )));
        // An escaped path is decoded before it is judged.
        assert!(is_protected_media(&format!(
            "https://p.example/pods/{OWNER}/media%2Fzones%2Fz/x.png"
        )));
        // With and without a configured pod API, no URL is built for it.
        for pod in ["", "https://pods.example.com"] {
            assert_eq!(
                ascii_route(
                    "https://preview.example.com",
                    pod,
                    &zone_img,
                    64,
                    "standard"
                ),
                AsciiRoute::Protected,
                "pod api {pod:?}"
            );
        }
    }

    #[test]
    fn private_pod_resources_are_protected_and_public_ones_are_not() {
        let pod = |path: &str| format!("https://pods.example.com/pods/{OWNER}/{path}");
        assert!(is_protected_media(&pod("private/me.png")));
        assert!(is_protected_media(&pod("media/other/x.png")));
        assert!(is_protected_media(&pod("inbox/x.png")));
        assert!(!is_protected_media(&pod("public/x.png")));
        assert!(!is_protected_media(&pod("media/public/x.png")));
        assert!(!is_protected_media("https://cdn.other.com/media/x.png"));
        assert!(!is_protected_media("/images/heroes/lake.webp"));
        assert_eq!(
            ascii_route(
                "https://preview.example.com",
                "",
                &pod("media/public/cat.jpg"),
                64,
                "standard"
            ),
            AsciiRoute::Fetch(vec![format!(
                "https://preview.example.com/ascii?url={}&cols=64&ramp=standard",
                encode_uri_component(&pod("media/public/cat.jpg"))
            )])
        );
        assert_eq!(
            ascii_route("", "", "https://cdn.other.com/x.png", 64, "standard"),
            AsciiRoute::Unavailable
        );
    }

    #[test]
    fn placeholder_names_the_file() {
        assert_eq!(
            media_file_name(&format!(
                "https://p.example/pods/{OWNER}/media/zones/z/My%20Cat.png?v=2#x"
            )),
            "My Cat.png"
        );
        assert_eq!(media_file_name("https://p.example/"), "image");
        assert_eq!(media_file_name("https://p.example"), "image");
        assert_eq!(media_file_name("/images/a.webp"), "a.webp");
        assert_eq!(
            protected_reason(&format!(
                "https://p.example/pods/{OWNER}/media/zones/z/a.png"
            )),
            "protected zone media"
        );
        assert_eq!(
            protected_reason(&format!("https://p.example/pods/{OWNER}/private/a.png")),
            "private pod file"
        );
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(percent_decode("%zz%41"), "%zzA");
    }

    #[test]
    fn an_outcome_is_kept_for_the_session() {
        let key = ascii_cache_key("https://cdn.other.com/kept.png", 64, "standard");
        let (slot, fresh) = ascii_slot(&key, AsciiState::Loading);
        assert!(fresh, "the first mount fetches");
        slot.set(AsciiState::Error);
        let (again, fresh) = ascii_slot(&key, AsciiState::Loading);
        assert!(!fresh, "a remount does not fetch again");
        assert_eq!(again.get_untracked(), AsciiState::Error);
        // Another width is another render.
        let (_, fresh) = ascii_slot(
            &ascii_cache_key("https://cdn.other.com/kept.png", 40, "standard"),
            AsciiState::Loading,
        );
        assert!(fresh);
    }

    #[test]
    fn encode_matches_encode_uri_component() {
        assert_eq!(encode_uri_component("a b"), "a%20b");
        assert_eq!(encode_uri_component("x=1&y=2"), "x%3D1%26y%3D2");
        assert_eq!(
            encode_uri_component("https://h/p.png"),
            "https%3A%2F%2Fh%2Fp.png"
        );
        // Unreserved set is preserved verbatim.
        assert_eq!(encode_uri_component("-_.!~*'()AzZ09"), "-_.!~*'()AzZ09");
    }

    #[test]
    fn make_absolute_resolves_root_relative_only() {
        let o = "https://dreamlab-ai.com";
        assert_eq!(
            make_absolute(o, "/images/heroes/lake.webp"),
            "https://dreamlab-ai.com/images/heroes/lake.webp"
        );
        assert_eq!(
            make_absolute(o, "images/x.png"),
            "https://dreamlab-ai.com/images/x.png"
        );
        // Already absolute / empty pass through untouched.
        assert_eq!(
            make_absolute(o, "https://cdn.other.com/x.png"),
            "https://cdn.other.com/x.png"
        );
        assert_eq!(make_absolute(o, "  "), "");
        // Trailing slash on origin is normalised.
        assert_eq!(make_absolute("https://h/", "/a.png"), "https://h/a.png");
    }

    #[test]
    fn image_name_classification() {
        assert!(is_image_name("photo.PNG"));
        assert!(is_image_name("a.jpeg"));
        assert!(is_image_name("b.webp"));
        assert!(is_image_name("c.png?cache=1"));
        assert!(!is_image_name("notes.txt"));
        assert!(!is_image_name("README"));
        assert!(!is_image_name("png"));
    }

    #[test]
    fn image_url_requires_http_scheme() {
        assert!(is_image_url("https://x.com/a.png"));
        assert!(is_image_url("http://x.com/a.JPG"));
        assert!(!is_image_url("ftp://x.com/a.png"));
        assert!(!is_image_url("/local/a.png"));
        assert!(!is_image_url("https://x.com/page"));
    }

    #[test]
    fn extract_urls_strips_punctuation_and_dedups() {
        let content =
            "see (https://x.com/a.png) and https://x.com/b.jpg! also https://x.com/a.png again";
        let urls = extract_image_urls(content);
        assert_eq!(
            urls,
            vec![
                "https://x.com/a.png".to_string(),
                "https://x.com/b.jpg".to_string()
            ]
        );
    }

    #[test]
    fn extract_urls_ignores_non_images() {
        let urls = extract_image_urls("hello https://x.com/page and a.png without scheme");
        assert!(urls.is_empty());
    }
}
