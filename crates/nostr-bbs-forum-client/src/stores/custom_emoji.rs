//! Per-user custom reaction emoji, persisted to localStorage.
//!
//! Motivated by user feedback on the reaction bar: *"Configurable / add your
//! own emojis"*. The picker previously offered exactly the eight hardcoded
//! entries in [`REACTION_EMOJIS`](crate::components::reaction_bar), which is
//! fine for a first pass and useless the moment a community develops its own
//! in-jokes. This store holds whatever emoji the viewer types in, keeps them
//! across reloads and tabs, and the reaction bar renders them next to the
//! built-ins.
//!
//! Nothing downstream needs to change: a custom emoji is just a kind-7 content
//! string under NIP-25, so it flows through the existing
//! `toggle_reaction` → sign → publish path and aggregates in the
//! [`ReactionStore`](crate::stores::reactions) exactly like a built-in.
//!
//! ## Why the validation is deliberately *thin*
//!
//! We do **not** try to decide whether a string "is really an emoji". That is
//! an unwinnable game: flags are regional-indicator pairs, families are ZWJ
//! sequences, skin tones are modifiers, and the Unicode emoji tables move every
//! year — any whitelist we ship is wrong by the next release and silently
//! rejects something the user can see rendering fine in their own message box.
//! Instead we only *bound* the input: trim it, refuse empty/whitespace-only,
//! refuse anything containing whitespace or control characters (that is a
//! pasted sentence, not a reaction), and cap the length at
//! [`MAX_EMOJI_CHARS`] scalar values so nobody can paste a novel into a
//! localStorage key. A ZWJ family sequence is 7 scalars and a keycap is 3, so
//! the cap is generous for anything genuinely emoji-shaped.
//!
//! The list itself is capped at [`MAX_CUSTOM_EMOJI`] so localStorage cannot
//! grow without bound, and eviction is FIFO — oldest added is the one that
//! falls off — so a user who keeps adding sees a predictable result rather than
//! an arbitrary entry vanishing.
//!
//! The persistence shape (`nostrbbs:` key prefix, serde round-trip,
//! `provide_*`/`use_*` context pair, cross-tab reload) mirrors
//! [`crate::stores::preferences`] so there is one storage idiom in the client.

use leptos::prelude::*;

/// localStorage key holding the viewer's custom reaction emoji (JSON array).
const CUSTOM_EMOJI_KEY: &str = "nostrbbs:custom-emojis";

/// Maximum number of custom emoji kept per user.
///
/// The picker is a popover, not a settings page — past a couple of rows it
/// stops being scannable — and this is also the bound that keeps the
/// localStorage entry small. Adding beyond the cap evicts the oldest.
pub const MAX_CUSTOM_EMOJI: usize = 32;

/// Maximum number of Unicode scalar values accepted in one custom emoji.
///
/// Bounds the input without pretending to validate "emoji-ness". For scale:
/// `👍` is 1, a flag is 2, `❤️` is 2, a skin-toned hand is 2, `#️⃣` is 3, and the
/// four-person ZWJ family `👨‍👩‍👧‍👦` is 7. Sixteen leaves headroom for future ZWJ
/// sequences while making a pasted paragraph impossible.
pub const MAX_EMOJI_CHARS: usize = 16;

// -- Pure logic (host-testable, no web_sys) -----------------------------------

/// Validate and normalise one user-typed custom emoji.
///
/// Returns the trimmed string, or `None` when the input is empty, contains
/// whitespace or control characters (i.e. it is prose, not a reaction), or is
/// longer than [`MAX_EMOJI_CHARS`] scalar values.
///
/// Deliberately *not* an emoji whitelist — see the module docs.
pub fn normalise_custom_emoji(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Interior whitespace or control chars means someone pasted text (or a
    // newline snuck in from a copy). Reject rather than persist a "reaction"
    // that renders as a line break in every client on the relay.
    if trimmed
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    if trimmed.chars().count() > MAX_EMOJI_CHARS {
        return None;
    }
    Some(trimmed.to_string())
}

/// Append `item` to `list`, de-duplicated and capped at `cap` entries.
///
/// - Already present → the list is returned unchanged. Re-adding an emoji must
///   not reshuffle the picker under the user's finger.
/// - Over `cap` → the OLDEST entry (front) is dropped. FIFO is the predictable
///   rule: the thing you added longest ago is the thing you lose.
/// - `cap == 0` → the list is left alone (there is nowhere to put it).
pub fn insert_capped(mut list: Vec<String>, item: String, cap: usize) -> Vec<String> {
    if cap == 0 {
        return list;
    }
    if list.iter().any(|e| e == &item) {
        return list;
    }
    list.push(item);
    while list.len() > cap {
        list.remove(0);
    }
    list
}

// -- Store --------------------------------------------------------------------

/// Reactive, localStorage-backed list of the viewer's custom reaction emoji.
///
/// `Copy`, so handlers in `view!` can capture it without cloning — same shape
/// as the other stores in this module.
#[derive(Clone, Copy)]
pub struct CustomEmojiStore {
    inner: RwSignal<Vec<String>>,
}

impl CustomEmojiStore {
    fn new() -> Self {
        Self {
            inner: RwSignal::new(load_custom_emojis()),
        }
    }

    /// Reactive getter: the viewer's custom emoji, oldest first.
    pub fn emojis(&self) -> Vec<String> {
        self.inner.get()
    }

    /// The backing signal, for callers that need to build a `Memo` or drive a
    /// `<For>` key off it.
    #[allow(dead_code)]
    pub fn signal(&self) -> RwSignal<Vec<String>> {
        self.inner
    }

    /// Add a user-typed emoji. Returns `true` when the list changed.
    ///
    /// Invalid input (see [`normalise_custom_emoji`]) and duplicates are
    /// silently no-ops returning `false`, which the caller uses to decide
    /// whether to clear the input box.
    pub fn add(&self, raw: &str) -> bool {
        let Some(emoji) = normalise_custom_emoji(raw) else {
            return false;
        };
        let before = self.inner.get_untracked();
        let after = insert_capped(before.clone(), emoji, MAX_CUSTOM_EMOJI);
        if after == before {
            return false;
        }
        self.inner.set(after);
        self.persist();
        true
    }

    /// Remove a custom emoji. Existing kind-7 reactions already published with
    /// it are untouched — this only drops it from the viewer's picker.
    pub fn remove(&self, emoji: &str) {
        let mut changed = false;
        self.inner.update(|list| {
            if let Some(pos) = list.iter().position(|e| e == emoji) {
                list.remove(pos);
                changed = true;
            }
        });
        if changed {
            self.persist();
        }
    }

    fn persist(&self) {
        let list = self.inner.get_untracked();
        if let Some(storage) = get_local_storage() {
            if let Ok(json) = serde_json::to_string(&list) {
                let _ = storage.set_item(CUSTOM_EMOJI_KEY, &json);
            }
        }
    }
}

/// Provide the custom-emoji store into Leptos context. Call once near the app
/// root; [`use_custom_emoji_store`] self-provisions if you don't.
///
/// `dead_code` is allowed because the app-root wiring is not in place yet: the
/// reaction bar reaches the store through [`use_custom_emoji_store`]'s
/// self-provisioning fallback. Calling this at the root is still the right
/// thing to do — it is what turns on cross-tab sync.
#[allow(dead_code)]
pub fn provide_custom_emoji_store() {
    let store = CustomEmojiStore::new();
    provide_context(store);
    // Cross-tab sync: a sibling tab adding an emoji must not be clobbered by
    // this tab persisting its stale whole-list snapshot. Reload from the
    // authoritative localStorage copy on every sibling write, exactly as
    // `provide_preferences` does. LOAD-ONLY — persisting here would echo.
    let inner = store.inner;
    crate::utils::on_cross_tab_storage_write(CUSTOM_EMOJI_KEY, move || {
        inner.set(load_custom_emojis());
    });
}

/// Retrieve the custom-emoji store from context.
///
/// Falls back to creating and providing one on first use rather than panicking
/// like `expect_context()`. The reaction bar renders deep inside message lists
/// and a missing `provide_custom_emoji_store()` at the app root would otherwise
/// take down the whole WASM runtime over a cosmetic feature — the same class of
/// panic the comments in `reaction_bar.rs` warn about. The fallback still reads
/// the persisted list, so behaviour is identical; only cross-tab sync is
/// skipped until the root provider exists.
pub fn use_custom_emoji_store() -> CustomEmojiStore {
    if let Some(store) = use_context::<CustomEmojiStore>() {
        return store;
    }
    let store = CustomEmojiStore::new();
    provide_context(store);
    store
}

fn get_local_storage() -> Option<web_sys::Storage> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
}

/// Load the persisted list, re-validating every entry.
///
/// Storage is user-writable (devtools, a sibling tab running an older build, a
/// hand-edited key), so we do not trust what comes back: each entry goes
/// through [`normalise_custom_emoji`] and the whole list through the same
/// dedupe/cap path as a fresh add. A corrupt or missing key yields an empty
/// list rather than an error the caller has to handle.
fn load_custom_emojis() -> Vec<String> {
    let raw = get_local_storage()
        .and_then(|s| s.get_item(CUSTOM_EMOJI_KEY).ok())
        .flatten()
        .unwrap_or_default();
    let parsed: Vec<String> = serde_json::from_str(&raw).unwrap_or_default();
    sanitise_list(parsed)
}

/// Re-validate, de-duplicate and cap a list read back from storage.
fn sanitise_list(list: Vec<String>) -> Vec<String> {
    list.into_iter()
        .filter_map(|e| normalise_custom_emoji(&e))
        .fold(Vec::new(), |acc, e| {
            insert_capped(acc, e, MAX_CUSTOM_EMOJI)
        })
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- normalise_custom_emoji ----------------------------------------------

    #[test]
    fn normalise_trims_surrounding_whitespace() {
        assert_eq!(
            normalise_custom_emoji("  \u{1F984}\n"),
            Some("\u{1F984}".to_string())
        );
    }

    #[test]
    fn normalise_rejects_empty_and_whitespace_only() {
        assert_eq!(normalise_custom_emoji(""), None);
        assert_eq!(normalise_custom_emoji("   "), None);
        assert_eq!(normalise_custom_emoji("\t\n "), None);
    }

    #[test]
    fn normalise_rejects_interior_whitespace_and_control_chars() {
        // A pasted phrase is not a reaction.
        assert_eq!(normalise_custom_emoji("\u{1F984} \u{1F308}"), None);
        assert_eq!(normalise_custom_emoji("\u{1F984}\u{0007}"), None);
    }

    #[test]
    fn normalise_rejects_over_long_input() {
        let novel = "\u{1F984}".repeat(MAX_EMOJI_CHARS + 1);
        assert_eq!(normalise_custom_emoji(&novel), None);
        // Exactly at the cap is still accepted.
        let at_cap = "\u{1F984}".repeat(MAX_EMOJI_CHARS);
        assert_eq!(normalise_custom_emoji(&at_cap), Some(at_cap.clone()));
    }

    #[test]
    fn normalise_accepts_multi_codepoint_sequences() {
        // ZWJ family (7 scalars), flag (2 regional indicators), skin-tone
        // modifier, and a VS16 presentation selector must all survive intact —
        // this is the case a naive "one char" or emoji-whitelist check breaks.
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}";
        let flag = "\u{1F1EC}\u{1F1E7}";
        let skin_tone = "\u{1F44D}\u{1F3FE}";
        let heart = "\u{2764}\u{FE0F}";
        for s in [family, flag, skin_tone, heart] {
            assert_eq!(normalise_custom_emoji(s), Some(s.to_string()), "{s:?}");
        }
    }

    // -- insert_capped --------------------------------------------------------

    #[test]
    fn insert_capped_appends_in_order() {
        let list = insert_capped(Vec::new(), "a".into(), 4);
        let list = insert_capped(list, "b".into(), 4);
        assert_eq!(list, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn insert_capped_dedupes_without_reordering() {
        let list = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(insert_capped(list.clone(), "b".into(), 8), list);
    }

    #[test]
    fn insert_capped_evicts_oldest_first() {
        let list = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        // Full at cap 3: adding "d" drops "a" (FIFO), not an arbitrary entry.
        let after = insert_capped(list, "d".into(), 3);
        assert_eq!(
            after,
            vec!["b".to_string(), "c".to_string(), "d".to_string()]
        );
    }

    #[test]
    fn insert_capped_trims_an_oversized_list_down_to_cap() {
        // 5 existing + 1 new = 6, capped to 3 by dropping from the FRONT.
        let list: Vec<String> = (0..5).map(|i| i.to_string()).collect();
        let after = insert_capped(list, "new".into(), 3);
        assert_eq!(
            after,
            vec!["3".to_string(), "4".to_string(), "new".to_string()]
        );
    }

    #[test]
    fn insert_capped_with_zero_cap_is_a_noop() {
        assert!(insert_capped(Vec::new(), "a".into(), 0).is_empty());
    }

    // -- sanitise_list --------------------------------------------------------

    #[test]
    fn sanitise_list_drops_junk_dedupes_and_caps() {
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}";
        let mut raw = vec![
            "  \u{1F44D} ".to_string(),   // trimmed
            "\u{1F44D}".to_string(),      // duplicate of the above post-trim
            "".to_string(),               // dropped
            "a b".to_string(),            // dropped (interior whitespace)
            family.to_string(),           // multi-codepoint survives
            "x".repeat(MAX_EMOJI_CHARS + 1), // dropped (too long)
        ];
        raw.extend((0..MAX_CUSTOM_EMOJI).map(|i| format!("e{i}")));
        let out = sanitise_list(raw);
        assert_eq!(out.len(), MAX_CUSTOM_EMOJI);
        // FIFO eviction: the earliest valid entries fell off, the last added stayed.
        assert_eq!(
            out.last().map(String::as_str),
            Some(format!("e{}", MAX_CUSTOM_EMOJI - 1).as_str())
        );
        assert!(!out.contains(&"\u{1F44D}".to_string()));
        assert!(out.iter().all(|e| normalise_custom_emoji(e).is_some()));
    }

    #[test]
    fn sanitise_list_keeps_a_short_valid_list_intact() {
        let flag = "\u{1F1EC}\u{1F1E7}".to_string();
        let list = vec!["\u{1F984}".to_string(), flag.clone()];
        assert_eq!(sanitise_list(list.clone()), list);
    }
}
