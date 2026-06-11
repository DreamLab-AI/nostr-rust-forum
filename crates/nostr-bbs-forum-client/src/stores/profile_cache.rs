//! In-memory profile cache for kind-0 metadata, with debounced batched fetch
//! against the relay-worker `/api/profiles/batch` endpoint.
//!
//! This store powers nickname rendering across the forum UI. The cache is
//! populated from three sources:
//!   1. IndexedDB hydration on app boot (warm start)
//!   2. Live kind-0 EVENT messages from the relay subscription
//!   3. On-demand HTTP batch fetch when the UI requests an unknown pubkey
//!
//! The fetcher is intentionally tolerant of a missing endpoint: if the
//! relay-worker has not yet shipped `/api/profiles/batch` (STREAM-N1), every
//! batch request gracefully degrades to `Ok(Vec::new())` so the UI continues
//! to fall back to `shorten_pubkey` without errors.

use std::collections::{HashMap, HashSet};

use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};

use crate::stores::indexed_db::{CachedProfile, ForumDb};

/// Maximum pubkeys per `/api/profiles/batch` request.
const MAX_BATCH_SIZE: usize = 200;

/// Debounce window after the last `lookup` miss before flushing the queue.
const FLUSH_DEBOUNCE_MS: i32 = 100;

/// One profile entry, materialised from kind-0 metadata.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProfileEntry {
    pub pubkey: String,
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub picture: Option<String>,
    pub nip05: Option<String>,
    /// Unix seconds when this entry was last fetched/refreshed.
    pub fetched_at: u64,
}

impl ProfileEntry {
    fn from_kind0_content(pubkey: String, content: &str, created_at: u64) -> Option<Self> {
        let obj = serde_json::from_str::<serde_json::Value>(content).ok()?;
        Some(Self {
            pubkey,
            name: obj.get("name").and_then(|v| v.as_str()).map(String::from),
            display_name: obj
                .get("display_name")
                .and_then(|v| v.as_str())
                .map(String::from),
            picture: obj
                .get("picture")
                .and_then(|v| v.as_str())
                .map(String::from),
            nip05: obj.get("nip05").and_then(|v| v.as_str()).map(String::from),
            fetched_at: created_at,
        })
    }

    /// Best human label for this profile, in precedence order:
    ///   display_name -> name -> NIP-05 handle -> None.
    pub fn best_label(&self) -> Option<String> {
        if let Some(d) = self.display_name.as_ref() {
            let t = d.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
        if let Some(n) = self.name.as_ref() {
            let t = n.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
        if let Some(nip) = self.nip05.as_ref() {
            return Some(format_nip05_handle(nip));
        }
        None
    }
}

/// The operator-configured "own" NIP-05 root domain (without subdomain).
///
/// Set at build time via the `NOSTR_BBS_NIP05_DOMAIN` env var; when unset,
/// every NIP-05 renders fully qualified. Operators of branded forks override
/// this in their `forum-config/` package.
fn own_nip05_root_domain() -> Option<&'static str> {
    option_env!("NOSTR_BBS_NIP05_DOMAIN")
}

/// Internal: render a NIP-05 identifier as a forum handle, with the
/// "own root domain" passed in explicitly so tests can exercise both paths.
fn format_nip05_handle_with_domain(nip05: &str, own_root: Option<&str>) -> String {
    let trimmed = nip05.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some((local, domain)) = trimmed.split_once('@') {
        if let Some(root) = own_root {
            let pods = format!("pods.{root}");
            if domain.eq_ignore_ascii_case(root) || domain.eq_ignore_ascii_case(&pods) {
                return format!("@{}", local);
            }
        }
        return format!("@{}@{}", local, domain);
    }
    format!("@{}", trimmed)
}

/// Render a NIP-05 identifier as a forum handle.
///
/// `alice@<own-domain>` -> `@alice` when the domain matches the operator's
/// configured `NOSTR_BBS_NIP05_DOMAIN` (or its `pods.<domain>` subdomain).
/// `alice@external.com` -> `@alice@external.com` for cross-relay handles.
pub fn format_nip05_handle(nip05: &str) -> String {
    format_nip05_handle_with_domain(nip05, own_nip05_root_domain())
}

// --- Cache --------------------------------------------------------------------

/// Reactive profile cache provided via Leptos context.
#[derive(Clone, Copy)]
pub struct ProfileCache {
    /// Resolved entries keyed by hex pubkey.
    pub entries: RwSignal<HashMap<String, ProfileEntry>>,
    /// Pubkeys queued for the next batched fetch.
    pending: RwSignal<Vec<String>>,
    /// Pubkeys already requested in the current debounce window — prevents
    /// duplicate enqueue when many components request the same pubkey.
    in_flight: RwSignal<HashSet<String>>,
    /// Whether a debounce flush is already scheduled.
    flush_scheduled: RwSignal<bool>,
}

impl Default for ProfileCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ProfileCache {
    pub fn new() -> Self {
        Self {
            entries: RwSignal::new(HashMap::new()),
            pending: RwSignal::new(Vec::new()),
            in_flight: RwSignal::new(HashSet::new()),
            flush_scheduled: RwSignal::new(false),
        }
    }

    /// Look up a profile entry. Returns immediately. If the entry is missing,
    /// schedules a debounced batch fetch and the cache will populate
    /// reactively once the response arrives.
    pub fn lookup(&self, pubkey: &str) -> Option<ProfileEntry> {
        let entries = self.entries.get_untracked();
        if let Some(entry) = entries.get(pubkey) {
            return Some(entry.clone());
        }
        // Schedule a fetch for the missing pubkey
        self.schedule_fetch(pubkey);
        None
    }

    /// Reactive lookup — re-evaluates whenever the underlying entries change.
    pub fn lookup_reactive(&self, pubkey: &str) -> Option<ProfileEntry> {
        let entries = self.entries.get();
        if let Some(entry) = entries.get(pubkey) {
            return Some(entry.clone());
        }
        // Schedule fetch but do not subscribe to pending/in_flight signals.
        self.schedule_fetch(pubkey);
        None
    }

    /// Tracked read of a profile's `picture` URL by pubkey.
    ///
    /// Subscribes to the entries signal (so the enclosing reactive scope
    /// re-runs when kind-0 metadata arrives) and schedules the debounced
    /// batch fetch on a miss. Only returns non-empty http(s) URLs — anything
    /// else falls back to `None` so callers render the identicon disc.
    pub fn picture_reactive(&self, pubkey: &str) -> Option<String> {
        self.lookup_reactive(pubkey)
            .and_then(|e| e.picture)
            .map(|p| p.trim().to_string())
            .filter(|p| p.starts_with("http://") || p.starts_with("https://"))
    }

    /// Insert or update an entry from a kind-0 nostr event.
    pub fn upsert_from_kind0(&self, pubkey: &str, content_json: &str, created_at: u64) {
        if pubkey.is_empty() {
            return;
        }
        if let Some(entry) =
            ProfileEntry::from_kind0_content(pubkey.to_string(), content_json, created_at)
        {
            self.upsert_entry(entry);
        }
    }

    /// Insert or update a fully-formed entry, refreshing the reactive signal.
    pub fn upsert_entry(&self, entry: ProfileEntry) {
        let pubkey = entry.pubkey.clone();
        // Skip if the existing entry is newer.
        let mut should_persist = true;
        self.entries.update(|map| {
            if let Some(existing) = map.get(&pubkey) {
                if existing.fetched_at > entry.fetched_at && entry.fetched_at != 0 {
                    should_persist = false;
                    return;
                }
            }
            map.insert(pubkey.clone(), entry.clone());
        });
        // Drop from in_flight so future misses can re-fetch if needed.
        self.in_flight.update(|set| {
            set.remove(&pubkey);
        });
        if should_persist {
            persist_one(&entry);
        }
    }

    /// Hydrate the in-memory cache from IndexedDB. Best-effort; failures are
    /// logged and ignored so an offline cache miss never blocks startup.
    pub async fn hydrate(&self) {
        let db = match ForumDb::open().await {
            Ok(db) => db,
            Err(e) => {
                web_sys::console::warn_1(
                    &format!("[profile_cache] hydrate: cannot open IDB: {:?}", e).into(),
                );
                return;
            }
        };
        match db.get_all_profiles().await {
            Ok(profiles) => {
                if profiles.is_empty() {
                    return;
                }
                self.entries.update(|map| {
                    for p in profiles {
                        let entry = ProfileEntry {
                            pubkey: p.pubkey.clone(),
                            name: p.name.clone(),
                            display_name: None,
                            picture: p.picture,
                            nip05: None,
                            fetched_at: p.updated_at,
                        };
                        map.entry(p.pubkey).or_insert(entry);
                    }
                });
            }
            Err(e) => {
                web_sys::console::warn_1(
                    &format!("[profile_cache] get_all_profiles: {:?}", e).into(),
                );
            }
        }
    }

    /// Try to populate this cache from IndexedDB for a single pubkey.
    /// Called as part of the debounced fetch flow so a warm IDB hit avoids
    /// an HTTP round-trip.
    async fn prime_from_idb(&self, pubkey: &str) -> bool {
        let db = match ForumDb::open().await {
            Ok(db) => db,
            Err(_) => return false,
        };
        match db.get_profile(pubkey).await {
            Ok(Some(cached)) => {
                let entry = ProfileEntry {
                    pubkey: cached.pubkey,
                    name: cached.name,
                    display_name: None,
                    picture: cached.picture,
                    nip05: None,
                    fetched_at: cached.updated_at,
                };
                self.entries.update(|map| {
                    map.entry(entry.pubkey.clone()).or_insert(entry);
                });
                true
            }
            _ => false,
        }
    }

    /// Persist a slice of entries to IndexedDB. Failures are logged.
    pub async fn persist(&self, entries: &[ProfileEntry]) {
        if entries.is_empty() {
            return;
        }
        let db = match ForumDb::open().await {
            Ok(db) => db,
            Err(e) => {
                web_sys::console::warn_1(
                    &format!("[profile_cache] persist: cannot open IDB: {:?}", e).into(),
                );
                return;
            }
        };
        let cached: Vec<CachedProfile> = entries
            .iter()
            .map(|entry| CachedProfile {
                pubkey: entry.pubkey.clone(),
                name: entry.display_name.clone().or_else(|| entry.name.clone()),
                picture: entry.picture.clone(),
                about: None,
                updated_at: entry.fetched_at,
            })
            .collect();
        if let Err(e) = db.put_profiles(&cached).await {
            web_sys::console::warn_1(
                &format!("[profile_cache] put_profiles failed: {:?}", e).into(),
            );
        }
    }

    fn schedule_fetch(&self, pubkey: &str) {
        if pubkey.is_empty() {
            return;
        }
        // Skip if already queued or already known.
        let mut already = false;
        self.in_flight.update(|set| {
            if !set.insert(pubkey.to_string()) {
                already = true;
            }
        });
        if already {
            return;
        }
        // Skip if already cached (race-safe re-check).
        if self.entries.with_untracked(|map| map.contains_key(pubkey)) {
            self.in_flight.update(|set| {
                set.remove(pubkey);
            });
            return;
        }
        self.pending.update(|q| q.push(pubkey.to_string()));

        if !self.flush_scheduled.get_untracked() {
            self.flush_scheduled.set(true);
            let cache = *self;
            crate::utils::set_timeout_once(
                move || {
                    cache.flush();
                },
                FLUSH_DEBOUNCE_MS,
            );
        }
    }

    fn flush(&self) {
        self.flush_scheduled.set(false);
        let pending: Vec<String> = self.pending.get_untracked();
        if pending.is_empty() {
            return;
        }
        self.pending.set(Vec::new());

        // Chunk into batches no larger than MAX_BATCH_SIZE.
        let cache = *self;
        for chunk in pending.chunks(MAX_BATCH_SIZE) {
            let pubkeys: Vec<String> = chunk.to_vec();
            spawn_local(async move {
                // Try IDB cache first for each pubkey before hitting the wire.
                let mut still_missing = Vec::with_capacity(pubkeys.len());
                for pk in &pubkeys {
                    if !cache.prime_from_idb(pk).await {
                        still_missing.push(pk.clone());
                    } else {
                        cache.in_flight.update(|set| {
                            set.remove(pk);
                        });
                    }
                }
                if still_missing.is_empty() {
                    return;
                }
                let fetched = fetch_batch(&still_missing).await;
                #[cfg(target_arch = "wasm32")]
                let now = (js_sys::Date::now() / 1000.0) as u64;
                #[cfg(not(target_arch = "wasm32"))]
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut to_persist = Vec::with_capacity(fetched.len());
                for mut entry in fetched {
                    if entry.fetched_at == 0 {
                        entry.fetched_at = now;
                    }
                    let pk = entry.pubkey.clone();
                    cache.entries.update(|map| {
                        map.insert(pk.clone(), entry.clone());
                    });
                    cache.in_flight.update(|set| {
                        set.remove(&pk);
                    });
                    to_persist.push(entry);
                }
                if !to_persist.is_empty() {
                    cache.persist(&to_persist).await;
                }
                // Drop any pubkeys that the server didn't return so future
                // lookups can retry after some interval.
                cache.in_flight.update(|set| {
                    for pk in &still_missing {
                        set.remove(pk);
                    }
                });
            });
        }
    }
}

// --- Context provider --------------------------------------------------------

/// Provide the `ProfileCache` via Leptos context. Call once at app root.
pub fn provide_profile_cache() {
    let cache = ProfileCache::new();
    provide_context(cache);
    // Hydrate from IDB in the background — non-blocking.
    spawn_local(async move {
        cache.hydrate().await;
    });
}

/// Read the cache from context. Returns None if `provide_profile_cache` was
/// not called (e.g. in tests).
pub fn try_use_profile_cache() -> Option<ProfileCache> {
    use_context::<ProfileCache>()
}

// --- Persistence helpers ------------------------------------------------------

fn persist_one(entry: &ProfileEntry) {
    let entry = entry.clone();
    spawn_local(async move {
        let db = match ForumDb::open().await {
            Ok(db) => db,
            Err(_) => return,
        };
        let cached = CachedProfile {
            pubkey: entry.pubkey.clone(),
            name: entry.display_name.clone().or_else(|| entry.name.clone()),
            picture: entry.picture.clone(),
            about: None,
            updated_at: entry.fetched_at,
        };
        let _ = db.put_profile(&cached).await;
    });
}

// --- HTTP batch fetch --------------------------------------------------------

#[derive(Serialize)]
struct BatchRequest<'a> {
    pubkeys: &'a [String],
}

#[derive(Deserialize)]
struct BatchResponseEntry {
    pubkey: String,
    #[serde(default)]
    profile: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct BatchResponseFlat {
    pubkey: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
    #[serde(default)]
    nip05: Option<String>,
    #[serde(default)]
    last_kind0_at: Option<u64>,
    #[serde(default)]
    fetched_at: Option<u64>,
}

/// Fetch a batch of profiles from the relay-worker. Returns an empty vec
/// (logged at debug level) on any non-200 response, including 404 — this is
/// the deliberate graceful-degrade path that lets the UI ship before the
/// relay-worker endpoint is deployed.
async fn fetch_batch(pubkeys: &[String]) -> Vec<ProfileEntry> {
    if pubkeys.is_empty() {
        return Vec::new();
    }

    let base = crate::utils::relay_url::relay_api_base();
    let url = format!("{}/api/profiles/batch", base);

    let body = match serde_json::to_string(&BatchRequest { pubkeys }) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let win = match web_sys::window() {
        Some(w) => w,
        None => return Vec::new(),
    };

    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    let headers = match web_sys::Headers::new() {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };
    let _ = headers.set("Content-Type", "application/json");
    init.set_headers(&headers);
    init.set_body(&wasm_bindgen::JsValue::from_str(&body));

    let request = match web_sys::Request::new_with_str_and_init(&url, &init) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let resp_val = match JsFuture::from(win.fetch_with_request(&request)).await {
        Ok(v) => v,
        Err(e) => {
            web_sys::console::log_1(
                &format!(
                    "[profile_cache] /api/profiles/batch unavailable, falling back: {:?}",
                    e
                )
                .into(),
            );
            return Vec::new();
        }
    };

    let resp: web_sys::Response = match resp_val.dyn_into() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    if !resp.ok() {
        // 404, 500, etc. — degrade gracefully.
        return Vec::new();
    }

    let text_promise = match resp.text() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let text_val = match JsFuture::from(text_promise).await {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let text = match text_val.as_string() {
        Some(s) => s,
        None => return Vec::new(),
    };

    parse_batch_response(&text)
}

/// Parse a `/api/profiles/batch` response, accepting either of the two
/// shapes that the relay-worker may return:
///
///   1. `[{ "pubkey": "...", "profile": { "name": "...", ... } }, ...]`
///   2. `[{ "pubkey": "...", "name": "...", ... }, ...]`  (flat)
///   3. `{ "profiles": [...] }` (wrapped)
fn parse_batch_response(text: &str) -> Vec<ProfileEntry> {
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let array = match &value {
        serde_json::Value::Array(arr) => arr.clone(),
        serde_json::Value::Object(obj) => match obj.get("profiles") {
            Some(serde_json::Value::Array(arr)) => arr.clone(),
            _ => return Vec::new(),
        },
        _ => return Vec::new(),
    };

    let mut out = Vec::with_capacity(array.len());
    #[cfg(target_arch = "wasm32")]
    let now = (js_sys::Date::now() / 1000.0) as u64;
    #[cfg(not(target_arch = "wasm32"))]
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for item in array {
        // Try wrapped shape first.
        if let Ok(wrapped) = serde_json::from_value::<BatchResponseEntry>(item.clone()) {
            if let Some(profile) = wrapped.profile {
                let entry = ProfileEntry {
                    pubkey: wrapped.pubkey,
                    name: profile
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    display_name: profile
                        .get("display_name")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    picture: profile
                        .get("picture")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    nip05: profile
                        .get("nip05")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    fetched_at: profile
                        .get("last_kind0_at")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(now),
                };
                out.push(entry);
                continue;
            }
        }
        // Try flat shape.
        if let Ok(flat) = serde_json::from_value::<BatchResponseFlat>(item) {
            let entry = ProfileEntry {
                pubkey: flat.pubkey,
                name: flat.name,
                display_name: flat.display_name,
                picture: flat.picture,
                nip05: flat.nip05,
                fetched_at: flat.last_kind0_at.or(flat.fetched_at).unwrap_or(now),
            };
            out.push(entry);
        }
    }

    out
}

// --- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nip05_local_domain_is_short() {
        assert_eq!(
            format_nip05_handle_with_domain("alice@example.test", Some("example.test")),
            "@alice"
        );
        assert_eq!(
            format_nip05_handle_with_domain("bob@pods.example.test", Some("example.test")),
            "@bob"
        );
    }

    #[test]
    fn nip05_external_domain_is_long() {
        assert_eq!(
            format_nip05_handle_with_domain("alice@example.com", Some("example.test")),
            "@alice@example.com"
        );
    }

    #[test]
    fn nip05_no_own_domain_is_always_long() {
        assert_eq!(
            format_nip05_handle_with_domain("alice@example.test", None),
            "@alice@example.test"
        );
    }

    #[test]
    fn nip05_no_at_falls_back() {
        assert_eq!(format_nip05_handle("alice"), "@alice");
        assert_eq!(format_nip05_handle(""), "");
    }

    #[test]
    fn parse_wrapped_response() {
        let json = r#"[{"pubkey":"abc","profile":{"name":"alice","nip05":"alice@example.test"}}]"#;
        let parsed = parse_batch_response(json);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].pubkey, "abc");
        assert_eq!(parsed[0].name.as_deref(), Some("alice"));
        assert_eq!(parsed[0].nip05.as_deref(), Some("alice@example.test"));
    }

    #[test]
    fn parse_flat_response() {
        let json = r#"[{"pubkey":"abc","display_name":"Alice","name":"alice"}]"#;
        let parsed = parse_batch_response(json);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].display_name.as_deref(), Some("Alice"));
        assert_eq!(parsed[0].name.as_deref(), Some("alice"));
    }

    #[test]
    fn parse_object_wrapped_response() {
        let json = r#"{"profiles":[{"pubkey":"abc","name":"alice"}]}"#;
        let parsed = parse_batch_response(json);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].pubkey, "abc");
    }

    #[test]
    fn parse_invalid_returns_empty() {
        assert!(parse_batch_response("not json").is_empty());
        assert!(parse_batch_response("\"plain string\"").is_empty());
    }

    #[test]
    fn entry_best_label_precedence() {
        let mut e = ProfileEntry {
            pubkey: "abc".into(),
            name: Some("alice".into()),
            display_name: Some("Alice Wonderland".into()),
            picture: None,
            nip05: Some("alice@example.test".into()),
            fetched_at: 1,
        };
        assert_eq!(e.best_label().as_deref(), Some("Alice Wonderland"));
        e.display_name = None;
        assert_eq!(e.best_label().as_deref(), Some("alice"));
        e.name = None;
        // Without NOSTR_BBS_NIP05_DOMAIN env var, NIP-05 renders fully qualified
        assert_eq!(e.best_label().as_deref(), Some("@alice@example.test"));
        e.nip05 = None;
        assert!(e.best_label().is_none());
    }

    #[test]
    fn from_kind0_parses_metadata() {
        let content = r#"{"name":"alice","display_name":"Alice","picture":"https://x/y.png","nip05":"alice@example.test"}"#;
        let entry = ProfileEntry::from_kind0_content("abc".into(), content, 1234).expect("valid");
        assert_eq!(entry.pubkey, "abc");
        assert_eq!(entry.name.as_deref(), Some("alice"));
        assert_eq!(entry.display_name.as_deref(), Some("Alice"));
        assert_eq!(entry.fetched_at, 1234);
    }

    #[test]
    fn from_kind0_invalid_json_returns_none() {
        assert!(ProfileEntry::from_kind0_content("abc".into(), "not json", 0).is_none());
    }
}
