//! Zone-restricted pod media: upload targets, detection, authenticated fetch
//! and a small in-memory blob cache.
//!
//! Images posted in a forum zone live at
//! `{pod}/pods/<owner>/media/zones/<zone-id>/<name>`. The pod worker serves them
//! only to a requester whose live relay membership can read that zone's
//! messages, so every read needs a NIP-98 `Authorization` header, which an
//! `<img src>` cannot send. [`fetch_restricted_blob`] makes the authenticated
//! request; the component renders the bytes through an object URL it creates
//! and revokes itself.
//!
//! Only URLs on this deployment's own pod origin are ever signed for
//! ([`is_restricted_media_url`]). A `/media/zones/` path on any other host is
//! treated as an ordinary image link, so a planted URL cannot turn every viewer
//! into a signer of requests to a third party.

use std::cell::RefCell;
use std::collections::VecDeque;

use crate::utils::pod_client::POD_API;

/// Where an upload from the composer goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MediaTarget {
    /// `media/public/`: deployments without zone config, DMs, avatars.
    Public,
    /// `media/zones/<zone-id>/`: a channel in a configured zone.
    Zone(String),
    /// Zones are configured but this channel's section names none: attaching an
    /// image is refused rather than silently made public.
    Unzoned,
}

impl MediaTarget {
    /// The container path inside the pod (no leading or trailing slash), or
    /// `None` when uploads must be refused.
    pub fn container_path(&self) -> Option<String> {
        match self {
            MediaTarget::Public => Some("media/public".to_string()),
            MediaTarget::Zone(z) if is_valid_zone_segment(z) => Some(format!("media/zones/{z}")),
            MediaTarget::Zone(_) | MediaTarget::Unzoned => None,
        }
    }
}

/// Zone ids as the pod worker accepts them in a path:
/// `[a-z0-9][a-z0-9_-]{0,63}`.
pub fn is_valid_zone_segment(zone: &str) -> bool {
    let b = zone.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Upload target for a channel `section` given the configured zone ids
/// (`None` = the deployment declares no zones).
pub fn media_target_for(section: Option<&str>, zone_ids: Option<&[String]>) -> MediaTarget {
    let Some(ids) = zone_ids else {
        return MediaTarget::Public;
    };
    let Some(section) = section.map(str::to_lowercase).filter(|s| !s.is_empty()) else {
        return MediaTarget::Unzoned;
    };
    ids.iter()
        .find(|id| {
            let id = id.to_lowercase();
            section == id || section.starts_with(&format!("{id}-"))
        })
        .map(|id| MediaTarget::Zone(id.clone()))
        .unwrap_or(MediaTarget::Unzoned)
}

/// Whether `url` is a zone-restricted object on THIS deployment's pod (origin
/// `pod_base`), so it must be fetched with NIP-98. Any other URL, including a
/// `/media/zones/` path on a foreign host, is not.
pub fn is_restricted_media_url_for(url: &str, pod_base: &str) -> bool {
    let base = pod_base.trim_end_matches('/');
    if base.is_empty() {
        return false;
    }
    let Some(rest) = url.strip_prefix(base) else {
        return false;
    };
    // The base must end exactly at a path boundary: `https://pod.x/pods/…`,
    // never `https://pod.x.evil/…` or `https://pod.x@evil/…`.
    let Some(path) = rest.strip_prefix("/pods/") else {
        return false;
    };
    // Exactly the URL that is signed is fetched: no query, fragment, userinfo,
    // escapes or backslashes that the browser might rewrite on the wire.
    if path.contains(['?', '#', '@', '%', '\\']) {
        return false;
    }
    // Dot segments are normalised away by the browser before sending, so the
    // signed `u` would never match what the pod receives.
    if path.split('/').any(|seg| seg == "." || seg == "..") {
        return false;
    }
    let Some((owner, tail)) = path.split_once('/') else {
        return false;
    };
    owner.len() == 64
        && owner.bytes().all(|b| b.is_ascii_hexdigit())
        && tail.starts_with("media/zones/")
}

/// [`is_restricted_media_url_for`] against the build's pod API origin.
pub fn is_restricted_media_url(url: &str) -> bool {
    is_restricted_media_url_for(url, POD_API)
}

/// Most bytes a sealed search manifest (`m.json`) may hold.
pub const SEALED_MANIFEST_MAX_BYTES: u64 = 256 * 1024;

/// Most bytes one sealed search shard (`*.age`) may hold: the pod's own upload
/// limit (`nostr-bbs-pod-worker` `zone_media::MAX_SEARCH_OBJECT_BYTES`).
pub const SEALED_SHARD_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// If `url` is a sealed search object on THIS deployment's pod
/// (`{pod_base}/pods/<owner>/media/zones/<zone>/search/<name>`, `name` being
/// `m.json` or a `*.age` shard), the most bytes it may hold; otherwise `None`.
/// Applies every rule of [`is_restricted_media_url_for`] first.
pub fn sealed_search_object_cap(url: &str, pod_base: &str) -> Option<u64> {
    if !is_restricted_media_url_for(url, pod_base) {
        return None;
    }
    let path = url.strip_prefix(pod_base.trim_end_matches('/'))?;
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    // ["pods", owner, "media", "zones", zone, "search", name]
    let [_, _, _, _, zone, "search", name] = segs.as_slice() else {
        return None;
    };
    if !is_valid_zone_segment(zone) {
        return None;
    }
    if *name == "m.json" {
        return Some(SEALED_MANIFEST_MAX_BYTES);
    }
    let stem = name.strip_suffix(".age")?;
    let stem_ok = !stem.is_empty()
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    stem_ok.then_some(SEALED_SHARD_MAX_BYTES)
}

/// A small LRU keyed by URL and scoped to one signed-in identity, bounded by
/// entry count and total weight (bytes). Generic so it is testable natively.
#[derive(Debug)]
pub struct WeightedLru<V> {
    owner: Option<String>,
    entries: VecDeque<(String, V, u64)>,
    total: u64,
    max_entries: usize,
    max_weight: u64,
}

impl<V: Clone> WeightedLru<V> {
    /// An empty cache with the given bounds.
    pub fn new(max_entries: usize, max_weight: u64) -> Self {
        Self {
            owner: None,
            entries: VecDeque::new(),
            total: 0,
            max_entries,
            max_weight,
        }
    }

    /// Drop everything when the identity changes, so one user's fetched bytes
    /// are never shown to the next.
    fn scope(&mut self, owner: &str) {
        if self.owner.as_deref() != Some(owner) {
            self.clear();
            self.owner = Some(owner.to_string());
        }
    }

    /// Look up `url` for `owner`, marking it most recently used.
    pub fn get(&mut self, owner: &str, url: &str) -> Option<V> {
        self.scope(owner);
        let pos = self.entries.iter().position(|(u, _, _)| u == url)?;
        let entry = self.entries.remove(pos)?;
        let value = entry.1.clone();
        self.entries.push_back(entry);
        Some(value)
    }

    /// Insert `url` for `owner`, evicting least recently used entries until the
    /// bounds hold. An entry heavier than the whole budget is not cached.
    pub fn put(&mut self, owner: &str, url: &str, value: V, weight: u64) {
        self.scope(owner);
        if let Some(pos) = self.entries.iter().position(|(u, _, _)| u == url) {
            if let Some((_, _, w)) = self.entries.remove(pos) {
                self.total -= w;
            }
        }
        if weight > self.max_weight || self.max_entries == 0 {
            return;
        }
        self.entries.push_back((url.to_string(), value, weight));
        self.total += weight;
        while self.entries.len() > self.max_entries || self.total > self.max_weight {
            match self.entries.pop_front() {
                Some((_, _, w)) => self.total -= w,
                None => break,
            }
        }
    }

    /// Empty the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.total = 0;
    }

    /// Number of cached entries.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Cache bounds: 24 images or 24 MB, whichever comes first.
const CACHE_ENTRIES: usize = 24;
const CACHE_BYTES: u64 = 24 * 1024 * 1024;

thread_local! {
    /// Fetched zone images (Blobs, never object URLs: each mounted component
    /// makes and revokes its own object URL, so eviction can never invalidate
    /// an image on screen).
    static BLOBS: RefCell<WeightedLru<web_sys::Blob>> =
        RefCell::new(WeightedLru::new(CACHE_ENTRIES, CACHE_BYTES));
}

/// Drop every cached image (sign-out).
pub fn clear_media_cache() {
    BLOBS.with(|c| c.borrow_mut().clear());
}

/// Raster types a zone image may be rendered as. Anything else (SVG, HTML,
/// octet-stream) is refused: a `blob:` URL takes on the forum's origin and
/// does not carry the pod's sandbox headers.
pub const RENDERABLE_IMAGE_TYPES: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
    "image/avif",
];

/// The renderable raster media type of a `Content-Type` value, if it is one.
pub fn renderable_image_type(content_type: Option<&str>) -> Option<&'static str> {
    let media = content_type?
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    RENDERABLE_IMAGE_TYPES.iter().copied().find(|t| *t == media)
}

/// Cached blob for `url` under the signed-in `owner`.
pub fn cached_blob(owner: &str, url: &str) -> Option<web_sys::Blob> {
    BLOBS.with(|c| c.borrow_mut().get(owner, url))
}

/// Remember a fetched blob.
pub fn cache_blob(owner: &str, url: &str, blob: &web_sys::Blob) {
    let weight = blob.size() as u64;
    BLOBS.with(|c| c.borrow_mut().put(owner, url, blob.clone(), weight));
}

/// Why a restricted fetch produced no image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestrictedFetchError {
    /// 401/403: the viewer may not read this zone (or is signed out).
    Locked,
    /// Anything else (network, CORS, 404, 5xx, signer refusal).
    Failed(String),
}

/// Map an HTTP status to the fetch outcome class.
pub fn classify_status(status: u16) -> Result<(), RestrictedFetchError> {
    match status {
        200..=299 => Ok(()),
        401 | 403 => Err(RestrictedFetchError::Locked),
        s => Err(RestrictedFetchError::Failed(format!("HTTP {s}"))),
    }
}

/// The served media type sealed search objects (`m.json`, `*.age`) carry: the
/// pod always serves them as opaque bytes and as an attachment
/// (`nostr-bbs-pod-worker` `zone_media::served_content_type`).
pub const SEALED_OBJECT_TYPE: &str = "application/octet-stream";

/// Whether a served `Content-Type` is the sealed-object type (parameters and
/// case ignored). Anything else, images included, is refused.
pub fn is_sealed_object_type(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|c| c.split(';').next())
        .map(|m| m.trim().eq_ignore_ascii_case(SEALED_OBJECT_TYPE))
        .unwrap_or(false)
}

/// GET a zone-restricted pod URL with a fresh NIP-98 token bound to this exact
/// URL. CORS mode, no credentials (the token is the only credential), no HTTP
/// cache (the pod answers `no-store` anyway), redirects refused.
async fn fetch_restricted_response(
    url: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<web_sys::Response, RestrictedFetchError> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    let token = crate::auth::nip98::create_nip98_token_with_signer(signer, url, "GET", None)
        .await
        .map_err(|e| RestrictedFetchError::Failed(format!("NIP-98: {e}")))?;
    let fail = |e: wasm_bindgen::JsValue| RestrictedFetchError::Failed(format!("{e:?}"));

    let window = web_sys::window().ok_or(RestrictedFetchError::Failed("no window".into()))?;
    let init = web_sys::RequestInit::new();
    init.set_method("GET");
    init.set_mode(web_sys::RequestMode::Cors);
    init.set_credentials(web_sys::RequestCredentials::Omit);
    init.set_cache(web_sys::RequestCache::NoStore);
    init.set_redirect(web_sys::RequestRedirect::Error);
    let headers = web_sys::Headers::new().map_err(fail)?;
    headers
        .set("Authorization", &format!("Nostr {token}"))
        .map_err(fail)?;
    init.set_headers(&headers);
    let req = web_sys::Request::new_with_str_and_init(url, &init).map_err(fail)?;

    let resp: web_sys::Response = JsFuture::from(window.fetch_with_request(&req))
        .await
        .map_err(fail)?
        .dyn_into()
        .map_err(fail)?;
    classify_status(resp.status())?;
    Ok(resp)
}

async fn response_blob(resp: &web_sys::Response) -> Result<web_sys::Blob, RestrictedFetchError> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    let fail = |e: wasm_bindgen::JsValue| RestrictedFetchError::Failed(format!("{e:?}"));
    JsFuture::from(resp.blob().map_err(fail)?)
        .await
        .map_err(fail)?
        .dyn_into()
        .map_err(fail)
}

/// GET a zone-restricted image (see [`fetch_restricted_response`]). Only an
/// allow-listed raster type is accepted; the blob is re-typed to exactly it.
pub async fn fetch_restricted_blob(
    url: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<web_sys::Blob, RestrictedFetchError> {
    let resp = fetch_restricted_response(url, signer).await?;
    let served = resp.headers().get("content-type").ok().flatten();
    let Some(mime) = renderable_image_type(served.as_deref()) else {
        return Err(RestrictedFetchError::Failed(
            "not a renderable image".into(),
        ));
    };
    let blob = response_blob(&resp).await?;
    // Re-type the bytes as exactly the allow-listed raster type (no copy).
    blob.slice_with_f64_and_f64_and_content_type(0.0, blob.size(), mime)
        .map_err(|e| RestrictedFetchError::Failed(format!("{e:?}")))
}

/// GET a zone-restricted sealed search object (`m.json` or a `*.age` shard; see
/// [`fetch_restricted_response`]). Only [`SEALED_OBJECT_TYPE`] is accepted; the
/// caller verifies the bytes against the signed manifest.
pub async fn fetch_restricted_object(
    url: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<web_sys::Blob, RestrictedFetchError> {
    let pod = crate::utils::relay_url::pod_api_base();
    let Some(cap) = sealed_search_object_cap(url, &pod) else {
        return Err(RestrictedFetchError::Failed(
            "not a sealed search object URL".into(),
        ));
    };
    let resp = fetch_restricted_response(url, signer).await?;
    let served = resp.headers().get("content-type").ok().flatten();
    if !is_sealed_object_type(served.as_deref()) {
        return Err(RestrictedFetchError::Failed(format!(
            "not a sealed search object ({})",
            served.as_deref().unwrap_or("no content-type")
        )));
    }
    // Refuse an oversize object before reading it when the length is declared,
    // and in any case once read.
    let declared = resp
        .headers()
        .get("content-length")
        .ok()
        .flatten()
        .and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|n| n > cap) {
        return Err(RestrictedFetchError::Failed(format!(
            "sealed search object over {cap} bytes"
        )));
    }
    let blob = response_blob(&resp).await?;
    if blob.size() as u64 > cap {
        return Err(RestrictedFetchError::Failed(format!(
            "sealed search object over {cap} bytes"
        )));
    }
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POD: &str = "https://pods.example.com";
    const PK: &str = "75876d9075c15bda6d724511ab9edcaabd53ebfa69ace15f918527e89e077968";

    #[test]
    fn sealed_search_object_paths_and_caps() {
        let base = format!("{POD}/pods/{PK}/media/zones/zone2/search");
        assert_eq!(
            sealed_search_object_cap(&format!("{base}/m.json"), POD),
            Some(SEALED_MANIFEST_MAX_BYTES)
        );
        assert_eq!(
            sealed_search_object_cap(&format!("{base}/b-5-0-v2.age"), POD),
            Some(SEALED_SHARD_MAX_BYTES)
        );
        assert_eq!(
            sealed_search_object_cap(&format!("{base}/q-5-4-v2.age"), "https://pods.example.com/"),
            Some(SEALED_SHARD_MAX_BYTES)
        );
        // Not a search object: zone images, other names, other depths.
        for bad in [
            format!("{POD}/pods/{PK}/media/zones/zone2/1-a.webp"),
            format!("{base}/x.webp"),
            format!("{base}/m.json.age.webp"),
            format!("{base}/.age"),
            format!("{base}/"),
            format!("{base}/sub/b-1-0-v1.age"),
            format!("{POD}/pods/{PK}/media/zones/zone2/search"),
            format!("{POD}/pods/{PK}/media/public/search/m.json"),
            format!("{POD}/pods/{PK}/media/zones//search/m.json"),
            format!("{POD}/pods/{PK}/media/zones/zo%2Fne/search/m.json"),
            format!("{base}/m.json?x=1"),
            format!("{base}/../search/m.json"),
            format!("https://evil.example.com/pods/{PK}/media/zones/zone2/search/m.json"),
            format!("{POD}.evil/pods/{PK}/media/zones/zone2/search/m.json"),
            format!("{POD}/pods/nothex/media/zones/zone2/search/m.json"),
            format!("{POD}/pods/{PK}/media/zones/Zone2/search/m.json"),
        ] {
            assert_eq!(sealed_search_object_cap(&bad, POD), None, "{bad}");
        }
        assert_eq!(
            sealed_search_object_cap(&format!("{base}/m.json"), ""),
            None
        );
        const { assert!(SEALED_SHARD_MAX_BYTES >= 13 * 1024 * 1024) };
    }

    #[test]
    fn sealed_objects_accept_only_octet_stream() {
        assert!(is_sealed_object_type(Some("application/octet-stream")));
        assert!(is_sealed_object_type(Some(
            "Application/Octet-Stream; charset=binary"
        )));
        assert!(!is_sealed_object_type(Some("application/json")));
        assert!(!is_sealed_object_type(Some("image/webp")));
        assert!(!is_sealed_object_type(Some("")));
        assert!(!is_sealed_object_type(None));
    }

    #[test]
    fn restricted_only_on_our_pod_origin_and_zone_prefix() {
        let ok = format!("{POD}/pods/{PK}/media/zones/zone2/1-a.webp");
        assert!(is_restricted_media_url_for(&ok, POD));
        assert!(is_restricted_media_url_for(
            &ok,
            "https://pods.example.com/"
        ));
        for no in [
            format!("{POD}/pods/{PK}/media/public/a.webp"),
            format!("https://evil.example/pods/{PK}/media/zones/zone2/a.webp"),
            format!("https://pods.example.com.evil.example/pods/{PK}/media/zones/z/a.webp"),
            format!("https://pods.example.com@evil.example/pods/{PK}/media/zones/z/a.webp"),
            format!("{POD}/pods/short/media/zones/zone2/a.webp"),
            format!("{POD}/x/pods/{PK}/media/zones/zone2/a.webp"),
            format!("{POD}/pods/{PK}/media/public/x?media/zones/"),
            format!("{POD}/pods/{PK}/media/zones/zone2/a.webp?x=1"),
            format!("{POD}/pods/{PK}/media/zones/zone2/a.webp#f"),
            format!("{POD}/pods/{PK}/media/zones/zone2/a%2Fb.webp"),
            format!("{POD}/pods/{PK}/media/zones/../../x.webp"),
            format!("{POD}/pods/{PK}/media/zones/zone2/./a.webp"),
        ] {
            assert!(!is_restricted_media_url_for(&no, POD), "{no}");
        }
        assert!(!is_restricted_media_url_for(&ok, ""));
    }

    #[test]
    fn upload_target_follows_the_strict_section_zone() {
        let ids = vec!["zone1".to_string(), "zone2".to_string()];
        assert_eq!(
            media_target_for(Some("zone2-rants"), None),
            MediaTarget::Public
        );
        assert_eq!(
            media_target_for(Some("zone2-rants"), Some(&ids)),
            MediaTarget::Zone("zone2".into())
        );
        assert_eq!(
            media_target_for(Some("ZONE1"), Some(&ids)),
            MediaTarget::Zone("zone1".into())
        );
        assert_eq!(
            media_target_for(Some("minimoonoir-x"), Some(&ids)),
            MediaTarget::Unzoned
        );
        assert_eq!(
            media_target_for(Some("zone22"), Some(&ids)),
            MediaTarget::Unzoned
        );
        assert_eq!(media_target_for(None, Some(&ids)), MediaTarget::Unzoned);
        assert_eq!(media_target_for(Some(""), Some(&ids)), MediaTarget::Unzoned);
    }

    #[test]
    fn container_paths_refuse_unzoned_and_bad_ids() {
        assert_eq!(
            MediaTarget::Public.container_path().as_deref(),
            Some("media/public")
        );
        assert_eq!(
            MediaTarget::Zone("zone2".into())
                .container_path()
                .as_deref(),
            Some("media/zones/zone2")
        );
        assert_eq!(MediaTarget::Zone("Zone2".into()).container_path(), None);
        assert_eq!(MediaTarget::Zone("../x".into()).container_path(), None);
        assert_eq!(MediaTarget::Unzoned.container_path(), None);
    }

    #[test]
    fn lru_evicts_by_count_and_weight_and_scopes_to_identity() {
        let mut c: WeightedLru<u32> = WeightedLru::new(2, 100);
        c.put("me", "a", 1, 10);
        c.put("me", "b", 2, 10);
        assert_eq!(c.get("me", "a"), Some(1)); // a is now most recent
        c.put("me", "c", 3, 10); // evicts b
        assert_eq!(c.get("me", "b"), None);
        assert_eq!(c.len(), 2);

        c.put("me", "big", 4, 95); // weight forces out the rest
        assert_eq!(c.len(), 1);
        c.put("me", "huge", 5, 101); // over budget: not cached
        assert_eq!(c.get("me", "huge"), None);

        assert_eq!(c.get("you", "big"), None, "identity change clears");
        assert!(c.is_empty());
    }

    #[test]
    fn only_raster_types_render() {
        assert_eq!(
            renderable_image_type(Some("image/webp")),
            Some("image/webp")
        );
        assert_eq!(
            renderable_image_type(Some("IMAGE/PNG; x=y")),
            Some("image/png")
        );
        for no in ["image/svg+xml", "text/html", "application/octet-stream", ""] {
            assert_eq!(renderable_image_type(Some(no)), None, "{no}");
        }
        assert_eq!(renderable_image_type(None), None);
    }

    #[test]
    fn status_classes() {
        assert_eq!(classify_status(200), Ok(()));
        assert_eq!(classify_status(401), Err(RestrictedFetchError::Locked));
        assert_eq!(classify_status(403), Err(RestrictedFetchError::Locked));
        assert!(matches!(
            classify_status(404),
            Err(RestrictedFetchError::Failed(_))
        ));
        assert!(matches!(
            classify_status(503),
            Err(RestrictedFetchError::Failed(_))
        ));
    }
}
