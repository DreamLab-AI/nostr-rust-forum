//! `@`-mention autocomplete dropdown for the message composer.
//!
//! This is the reusable, self-contained mention engine extracted from the
//! composer. It owns:
//!   * the user-list source (search endpoint + ProfileCache + known-users seed),
//!   * candidate ranking and de-duplication,
//!   * the dropdown view with keyboard navigation and click-to-select.
//!
//! The composer (`message_input.rs`) drives it by feeding the active `@<query>`
//! token and reading back the selected [`MentionCandidate`] (which carries a
//! canonical hex `pubkey`). The composer is responsible for splicing the
//! handle into the textarea and for stashing the pubkey so the publish path
//! can emit a `["p", <pubkey>]` tag on the kind-42 event.
//!
//! ## User-list source (the `forum-kit-userlist-api` contract)
//!
//! The agent that owns identity (`admin-identity`) is concurrently defining a
//! canonical "known users" contract under the ruflo memory key
//! `forum-kit-userlist-api`. Until that lands, this component resolves
//! candidates from three layered, individually-degradable sources, in order
//! of richness:
//!
//!   1. **Relay search endpoint** — `GET {relay}/api/profiles/search?q=&limit=`.
//!      The authoritative typeahead. Returns empty (silently) when the endpoint
//!      is not yet deployed or the `profiles` table is empty.
//!   2. **`ProfileCache`** (read-only; owned by `admin-identity`/profile_cache).
//!      Populated by the live kind-0 relay subscription + IndexedDB hydration.
//!      Lets `@mention` work for anyone the client has already seen post, even
//!      when the search endpoint is down — directly mitigating the live
//!      "display names resolve empty -> hex fallback" issue.
//!   3. **Known-users seed** — a tiny static roster of well-known ecosystem
//!      pubkeys (welcome-bot, moderation-bot, and the QA fixture
//!      `@junkiejarvis`). Guarantees mentions of these accounts always resolve
//!      to a real pubkey and therefore always emit a correct `["p", pubkey]`
//!      tag — even on a cold client with no cache and no search backend.
//!
//! When `admin-identity` publishes a richer enumeration contract, the search
//! source (#1) is the seam to swap; #2 and #3 remain as offline fallbacks.

use std::collections::HashMap;

use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::stores::profile_cache::{try_use_profile_cache, ProfileEntry};
use crate::utils::relay_url::relay_api_base;

/// Minimum query length before the relay search endpoint is hit. Below this,
/// only the cheap local sources (read-only ProfileCache + known-users seed)
/// populate the dropdown — so a bare `@` already shows the local roster.
pub(crate) const NETWORK_SEARCH_MIN_LEN: usize = 2;

/// One autocomplete candidate. `pubkey` is the canonical 64-char hex pubkey
/// used to build the `["p", pubkey]` tag; the optional metadata drives display.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) struct MentionCandidate {
    pub pubkey: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub nip05: Option<String>,
    #[serde(default)]
    pub picture: Option<String>,
}

impl MentionCandidate {
    /// Best human-facing handle, precedence:
    /// display_name -> name -> nip05 -> first 8 hex chars.
    pub fn handle(&self) -> String {
        self.display_name
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| {
                self.name
                    .as_ref()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(String::from)
            })
            .or_else(|| {
                self.nip05
                    .as_ref()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(String::from)
            })
            .unwrap_or_else(|| self.pubkey.chars().take(8).collect())
    }

    /// True when any human-facing label of this candidate contains `q`
    /// (case-insensitive). The empty query matches everything.
    fn matches(&self, q: &str) -> bool {
        if q.is_empty() {
            return true;
        }
        // Lowercase the query here so the helper is genuinely case-insensitive
        // regardless of caller (the search path also pre-lowercases — a no-op).
        let ql = q.to_lowercase();
        let needle = ql.as_str();
        let hay = |s: &Option<String>| {
            s.as_ref()
                .map(|v| v.to_lowercase().contains(needle))
                .unwrap_or(false)
        };
        hay(&self.display_name)
            || hay(&self.name)
            || hay(&self.nip05)
            || self.pubkey.to_lowercase().starts_with(needle)
    }

    fn from_entry(entry: &ProfileEntry) -> Self {
        Self {
            pubkey: entry.pubkey.clone(),
            name: entry.name.clone(),
            display_name: entry.display_name.clone(),
            nip05: entry.nip05.clone(),
            picture: entry.picture.clone(),
        }
    }
}

/// Wrapper deserialiser tolerant of both `[..]` and `{"results":[..]}` shapes.
#[derive(Deserialize)]
#[serde(untagged)]
enum SearchResponse {
    Array(Vec<MentionCandidate>),
    Wrapped { results: Vec<MentionCandidate> },
}

impl SearchResponse {
    fn into_vec(self) -> Vec<MentionCandidate> {
        match self {
            Self::Array(v) => v,
            Self::Wrapped { results } => results,
        }
    }
}

// -- Known-users seed ---------------------------------------------------------

/// `(handle, pubkey-hex)` pairs for well-known ecosystem accounts.
///
/// This is the floor of the user-list source: even with no search backend and
/// a cold ProfileCache, mentioning one of these resolves to a real pubkey and
/// emits a correct `["p", pubkey]` tag. `@junkiejarvis` is the QA fixture the
/// bridge round-trips on, so it MUST be present and MUST carry exactly the
/// pubkey below.
const KNOWN_USERS: &[(&str, &str)] = &[
    (
        "junkiejarvis",
        "2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9",
    ),
    (
        "welcome-bot",
        "94f74e9c8938e0eae3223fcd9ce3a799e84cff389fd994aeb9dd336add0adf8f",
    ),
    (
        "moderation-bot",
        "5d80b5facd2d746689d7d2e400db6acce5843456967054adcf6956e4c734c54c",
    ),
    (
        "calendar-bot",
        "be92ccf53d9d535fd21f3388201fd83b49588552fff5a1395fb60b6998df2243",
    ),
];

/// The known-users seed as [`MentionCandidate`]s.
fn seed_candidates() -> Vec<MentionCandidate> {
    KNOWN_USERS
        .iter()
        .map(|(handle, pk)| MentionCandidate {
            pubkey: (*pk).to_string(),
            name: Some((*handle).to_string()),
            display_name: None,
            nip05: None,
            picture: None,
        })
        .collect()
}

// -- Local (synchronous) candidate resolution ---------------------------------

/// Resolve candidates from the cheap local sources only: the read-only
/// `ProfileCache` plus the known-users seed. Used to populate the dropdown
/// instantly (before any network search returns) so `@mention` works even when
/// the search endpoint is unavailable.
///
/// Performed inside a reactive scope, this subscribes to the `ProfileCache`
/// entries signal, so newly-arrived kind-0 metadata expands the candidate set.
pub(crate) fn local_candidates(query: &str, limit: usize) -> Vec<MentionCandidate> {
    let q_lower = query.to_lowercase();

    // 1. ProfileCache (read-only): anyone we've seen post in this session.
    let mut from_cache: Vec<MentionCandidate> = Vec::new();
    if let Some(cache) = try_use_profile_cache() {
        // Reactive read — re-runs when kind-0 metadata arrives.
        let entries = cache.entries.get();
        for entry in entries.values() {
            let cand = MentionCandidate::from_entry(entry);
            if cand.matches(&q_lower) {
                from_cache.push(cand);
            }
        }
    }

    // 2. Known-users seed (always available).
    let from_seed: Vec<MentionCandidate> = seed_candidates()
        .into_iter()
        .filter(|c| c.matches(&q_lower))
        .collect();

    dedup_by_pubkey(from_cache.into_iter().chain(from_seed), limit)
}

// -- Publish-time content mention resolution ----------------------------------

/// Characters that make up a `@handle` token in free text.
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

/// Extract every `@handle` token from free-text `content`.
///
/// Scans ALL `@` occurrences (not only whitespace-anchored ones) so a mention
/// glued to the preceding word — e.g. `please@junkiejarvis`, which is how the
/// composer can leave it — is still picked up. False positives (e.g. an email
/// domain) are harmless: resolution only succeeds for an exact candidate handle
/// or a curated known-user prefix, neither of which a domain matches.
fn extract_mention_tokens(content: &str) -> Vec<String> {
    let chars: Vec<char> = content.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '@' {
            let mut j = i + 1;
            while j < chars.len() && is_token_char(chars[j]) {
                j += 1;
            }
            if j > i + 1 {
                let tok: String = chars[i + 1..j].iter().collect();
                let tok = tok.trim_matches('.').to_string();
                if !tok.is_empty() {
                    out.push(tok);
                }
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    out
}

/// Resolve free-text `@handle` mentions in `content` to hex pubkeys, so a
/// mention that was TYPED (not picked from the dropdown) still produces a
/// `["p", pubkey]` tag. Without this, the relay's `#p`-filtered agent
/// subscriptions (e.g. `@junkiejarvis`) never receive a content-only mention,
/// so the agent never replies.
///
/// Per token (case-insensitive):
///   1. exact handle match against the known-users seed + read-only ProfileCache;
///   2. else the longest KNOWN_USERS handle that PREFIXES the token (covers a
///      missing separator like `@junkiejarvishello`). Restricted to the curated
///      seed so a short ProfileCache handle cannot greedily swallow words.
///
/// Best-effort outside a reactive scope: the ProfileCache read is skipped when
/// unavailable, but the always-present seed still resolves the ecosystem bots.
pub fn resolve_content_mentions(content: &str) -> Vec<String> {
    let tokens = extract_mention_tokens(content);
    if tokens.is_empty() {
        return Vec::new();
    }

    // Candidate pool: ProfileCache (if reachable) + the known-users seed.
    // `get_untracked` so this is safe to call outside a reactive scope (e.g.
    // from inside a `spawn_local` publish path).
    let mut pool: Vec<MentionCandidate> = Vec::new();
    if let Some(cache) = try_use_profile_cache() {
        for entry in cache.entries.get_untracked().values() {
            pool.push(MentionCandidate::from_entry(entry));
        }
    }
    pool.extend(seed_candidates());

    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for token in tokens {
        let tl = token.to_lowercase();
        let exact = pool.iter().find(|c| {
            [&c.display_name, &c.name, &c.nip05].iter().any(|f| {
                f.as_ref()
                    .map(|v| v.trim().to_lowercase() == tl)
                    .unwrap_or(false)
            })
        });
        let resolved = if let Some(c) = exact {
            Some(c.pubkey.clone())
        } else {
            KNOWN_USERS
                .iter()
                .filter(|(h, _)| tl.starts_with(&h.to_lowercase()))
                .max_by_key(|(h, _)| h.len())
                .map(|(_, pk)| (*pk).to_string())
        };
        if let Some(pk) = resolved {
            if seen.insert(pk.clone()) {
                out.push(pk);
            }
        }
    }
    out
}

/// De-duplicate candidates by pubkey, preserving first-seen order and
/// preferring whichever record carries a real `display_name`/`picture`.
fn dedup_by_pubkey<I>(iter: I, limit: usize) -> Vec<MentionCandidate>
where
    I: IntoIterator<Item = MentionCandidate>,
{
    let mut out: Vec<MentionCandidate> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for c in iter {
        if let Some(&idx) = seen.get(&c.pubkey) {
            if out[idx].display_name.is_none() && c.display_name.is_some() {
                out[idx].display_name = c.display_name;
            }
            if out[idx].picture.is_none() && c.picture.is_some() {
                out[idx].picture = c.picture;
            }
            if out[idx].nip05.is_none() && c.nip05.is_some() {
                out[idx].nip05 = c.nip05;
            }
            continue;
        }
        seen.insert(c.pubkey.clone(), out.len());
        out.push(c);
    }
    out.truncate(limit);
    out
}

/// Merge network search results with the current local candidates, preferring
/// the (richer) network records but never dropping a local-only candidate that
/// still matches. Network entries come first so they win ordering; missing
/// fields on a network record are back-filled from the local one. De-duplicated
/// by pubkey.
pub(crate) fn merge_candidates(
    network: Vec<MentionCandidate>,
    local: Vec<MentionCandidate>,
    limit: usize,
) -> Vec<MentionCandidate> {
    dedup_by_pubkey(network.into_iter().chain(local), limit)
}

// -- Network search -----------------------------------------------------------

/// Minimal URL-encode helper for query-string values.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Query the relay-worker profile-search endpoint. Returns an empty list
/// (never an error to the UI) when the endpoint is missing or the table is
/// empty — the local sources keep the dropdown useful regardless.
pub(crate) async fn search_profiles(query: &str, limit: usize) -> Vec<MentionCandidate> {
    let query = query.trim();
    if query.is_empty() {
        return Vec::new();
    }
    // Lowercase the query the client sends so handle search is case-insensitive
    // even against a relay-worker whose query path doesn't fold case itself
    // (the current worker does, via `LOWER(...)`, but the client must not rely
    // on a particular server version). The results are still re-filtered
    // case-insensitively by `MentionCandidate::matches` downstream.
    let q_lower = query.to_lowercase();
    let url = format!(
        "{}/api/profiles/search?q={}&limit={}",
        relay_api_base(),
        url_encode(&q_lower),
        limit
    );
    let result: Result<Vec<MentionCandidate>, String> = async {
        let win = web_sys::window().ok_or_else(|| "no window".to_string())?;
        let init = web_sys::RequestInit::new();
        init.set_method("GET");
        let req = web_sys::Request::new_with_str_and_init(&url, &init)
            .map_err(|e| format!("request build failed: {:?}", e))?;
        let resp_val = JsFuture::from(win.fetch_with_request(&req))
            .await
            .map_err(|e| format!("fetch failed: {:?}", e))?;
        let resp: web_sys::Response = resp_val
            .dyn_into()
            .map_err(|_| "bad response type".to_string())?;
        if !resp.ok() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let txt_promise = resp.text().map_err(|e| format!("text() failed: {:?}", e))?;
        let txt_val = JsFuture::from(txt_promise)
            .await
            .map_err(|e| format!("await text failed: {:?}", e))?;
        let txt = txt_val
            .as_string()
            .ok_or_else(|| "non-string body".to_string())?;
        let parsed: SearchResponse =
            serde_json::from_str(&txt).map_err(|e| format!("parse failed: {}", e))?;
        Ok(parsed.into_vec())
    }
    .await;

    match result {
        Ok(v) => v,
        Err(e) => {
            web_sys::console::warn_1(
                &format!(
                    "[mention] profile search degraded ({}); using local sources",
                    e
                )
                .into(),
            );
            Vec::new()
        }
    }
}

// -- Dropdown view ------------------------------------------------------------

/// Reactive props the composer passes into the dropdown. The dropdown reads
/// these signals and writes back the user's selection via `on_select`.
#[component]
pub(crate) fn MentionAutocomplete(
    /// Whether the dropdown is visible (composer detected an active `@<query>`).
    open: RwSignal<bool>,
    /// The current `@<query>` text (without the leading `@`).
    query: RwSignal<String>,
    /// Ranked candidate list (composer owns fetch/merge; dropdown only renders).
    candidates: RwSignal<Vec<MentionCandidate>>,
    /// Index of the keyboard-highlighted row.
    active_idx: RwSignal<usize>,
    /// Fired with the chosen candidate when a row is clicked or Enter/Tab is hit.
    on_select: Callback<MentionCandidate>,
) -> impl IntoView {
    view! {
        <Show when=move || open.get()>
            <div class="absolute bottom-full left-0 mb-1 w-72 max-w-full glass-card rounded-xl shadow-lg z-50 overflow-hidden">
                {move || {
                    let list = candidates.get();
                    if list.is_empty() {
                        let q = query.get();
                        let msg = if q.is_empty() {
                            "Type a name to mention\u{2026}"
                        } else {
                            "No matching users"
                        };
                        view! {
                            <div class="px-3 py-2 text-xs text-gray-500">{msg}</div>
                        }
                        .into_any()
                    } else {
                        let active = active_idx.get();
                        view! {
                            <ul role="listbox" aria-label="User mention suggestions" class="max-h-60 overflow-y-auto">
                                {list
                                    .into_iter()
                                    .enumerate()
                                    .map(|(i, c)| {
                                        let handle = c.handle();
                                        let nip05 = c.nip05.clone().unwrap_or_default();
                                        let pic = c.picture.clone();
                                        let is_active = i == active;
                                        let class = if is_active {
                                            "flex items-center gap-2 px-3 py-2 cursor-pointer bg-amber-500/15 text-amber-100"
                                        } else {
                                            "flex items-center gap-2 px-3 py-2 cursor-pointer hover:bg-gray-800/60 text-gray-200"
                                        };
                                        let candidate = c.clone();
                                        view! {
                                            <li
                                                role="option"
                                                aria-selected=is_active
                                                class=class
                                                on:mousedown=move |ev| {
                                                    // mousedown (not click) so the textarea's blur
                                                    // doesn't tear down the dropdown before selection.
                                                    ev.prevent_default();
                                                    on_select.run(candidate.clone());
                                                }
                                            >
                                                {pic
                                                    .map(|src| {
                                                        view! {
                                                            <img
                                                                src=src
                                                                alt=""
                                                                class="w-6 h-6 rounded-full bg-gray-700 object-cover flex-shrink-0"
                                                            />
                                                        }
                                                    })}
                                                <div class="flex-1 min-w-0">
                                                    <div class="text-xs font-medium truncate">{handle}</div>
                                                    {(!nip05.is_empty())
                                                        .then(|| {
                                                            view! {
                                                                <div class="text-[10px] text-gray-400 truncate">
                                                                    "@"{nip05}
                                                                </div>
                                                            }
                                                        })}
                                                </div>
                                            </li>
                                        }
                                    })
                                    .collect_view()}
                            </ul>
                        }
                        .into_any()
                    }
                }}
            </div>
        </Show>
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(pk: &str, dn: Option<&str>, name: Option<&str>) -> MentionCandidate {
        MentionCandidate {
            pubkey: pk.to_string(),
            name: name.map(String::from),
            display_name: dn.map(String::from),
            nip05: None,
            picture: None,
        }
    }

    #[test]
    fn seed_contains_junkiejarvis_with_exact_pubkey() {
        let seeds = seed_candidates();
        let jj = seeds
            .iter()
            .find(|c| c.name.as_deref() == Some("junkiejarvis"))
            .expect("junkiejarvis must be in the seed");
        assert_eq!(
            jj.pubkey,
            "2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9"
        );
        // The handle the composer splices, and the pubkey the p-tag carries.
        assert_eq!(jj.handle(), "junkiejarvis");
    }

    #[test]
    fn matches_is_case_insensitive_substring() {
        let c = cand("ff", Some("Alice In Wonderland"), Some("alice"));
        assert!(c.matches("alice"));
        assert!(c.matches("WONDER"));
        assert!(c.matches("")); // empty query matches all
        assert!(!c.matches("bob"));
    }

    #[test]
    fn matches_on_pubkey_prefix() {
        let c = cand("2de44d5622eef795", None, None);
        assert!(c.matches("2de4"));
        assert!(!c.matches("ffff"));
    }

    #[test]
    fn handle_precedence() {
        assert_eq!(cand("ff", Some("Disp"), Some("nm")).handle(), "Disp");
        assert_eq!(cand("ff", None, Some("nm")).handle(), "nm");
        assert_eq!(cand("abcdef0123456789", None, None).handle(), "abcdef01");
        // Blank display_name falls through to name.
        assert_eq!(cand("ff", Some("   "), Some("nm")).handle(), "nm");
    }

    #[test]
    fn merge_prefers_network_and_dedups_by_pubkey() {
        let network = vec![cand("aa", Some("Net Alice"), None)];
        let local = vec![
            cand("aa", None, Some("alice")), // dup pubkey -> dropped, but enriches nothing
            cand("bb", Some("Bob"), None),   // local-only -> kept
        ];
        let merged = merge_candidates(network, local, 10);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].pubkey, "aa");
        assert_eq!(merged[0].display_name.as_deref(), Some("Net Alice"));
        assert_eq!(merged[1].pubkey, "bb");
    }

    #[test]
    fn merge_enriches_missing_fields_from_local() {
        // Network knows the pubkey but lacks a picture/nip05; local fills them.
        let network = vec![MentionCandidate {
            pubkey: "aa".into(),
            name: None,
            display_name: Some("Net".into()),
            nip05: None,
            picture: None,
        }];
        let local = vec![MentionCandidate {
            pubkey: "aa".into(),
            name: None,
            display_name: None,
            nip05: Some("a@b.c".into()),
            picture: Some("https://x/y.png".into()),
        }];
        let merged = merge_candidates(network, local, 10);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].nip05.as_deref(), Some("a@b.c"));
        assert_eq!(merged[0].picture.as_deref(), Some("https://x/y.png"));
        assert_eq!(merged[0].display_name.as_deref(), Some("Net"));
    }

    #[test]
    fn merge_respects_limit() {
        let network: Vec<MentionCandidate> = (0..5)
            .map(|i| cand(&format!("n{i}"), Some("x"), None))
            .collect();
        let local: Vec<MentionCandidate> = (0..5)
            .map(|i| cand(&format!("l{i}"), Some("y"), None))
            .collect();
        let merged = merge_candidates(network, local, 3);
        assert_eq!(merged.len(), 3);
    }

    #[test]
    fn search_response_array_and_wrapped() {
        let a: SearchResponse =
            serde_json::from_str(r#"[{"pubkey":"abc","name":"alice"}]"#).unwrap();
        assert_eq!(a.into_vec().len(), 1);
        let w: SearchResponse =
            serde_json::from_str(r#"{"results":[{"pubkey":"abc","display_name":"A"}]}"#).unwrap();
        let v = w.into_vec();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].display_name.as_deref(), Some("A"));
    }

    #[test]
    fn url_encode_basic() {
        assert_eq!(url_encode("alice"), "alice");
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("a&b"), "a%26b");
    }

    #[test]
    fn extract_mention_tokens_basic() {
        assert_eq!(extract_mention_tokens("hi @Alice there"), vec!["Alice"]);
        assert_eq!(
            extract_mention_tokens("@JunkieJarvis hello"),
            vec!["JunkieJarvis"]
        );
        assert!(extract_mention_tokens("no mentions here").is_empty());
    }

    #[test]
    fn resolve_content_mentions_is_case_insensitive_against_seed() {
        // The known-users seed handle is lowercase "junkiejarvis"; a mention
        // typed in any case must still resolve to the same hex pubkey, so the
        // `["p", pubkey]` tag fires regardless of how the author cased it.
        let expected = "2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9";
        for content in [
            "ping @junkiejarvis",
            "ping @JunkieJarvis",
            "ping @JUNKIEJARVIS",
        ] {
            let resolved = resolve_content_mentions(content);
            assert_eq!(
                resolved,
                vec![expected.to_string()],
                "mention resolution must be case-insensitive for: {content}"
            );
        }
    }
}
