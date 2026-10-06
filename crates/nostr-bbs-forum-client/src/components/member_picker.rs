//! Pick a member by nickname; the selection is their hex pubkey.
//!
//! Members are found by typing part of a nickname, the same search the
//! `@`-mention dropdown uses ([`local_candidates`] from the profile cache and
//! the known-users seed, merged with the relay's profile search). A pasted
//! 64-hex key or `npub` is still accepted.
//!
//! Nicknames are not unique. When two members share one, each is shown with
//! the shortest key prefix (at least [`KEY_HINT_MIN`] hex characters) that
//! tells them apart — a copyable hint that appears only while the clash
//! exists, so the common case reads as plain names.

use std::collections::HashMap;

use leptos::prelude::*;

use crate::components::copy_key::CopyKey;
use crate::components::mention_autocomplete::{
    local_candidates, merge_candidates, search_profiles, MentionCandidate,
};
use crate::components::user_display::try_display_name_tracked;
use crate::stores::profile_cache::try_use_profile_cache;

/// Shortest key prefix shown to tell same-named members apart.
pub(crate) const KEY_HINT_MIN: usize = 8;

/// Candidates shown in the dropdown.
const PICKER_LIMIT: usize = 8;

/// Typing pause before the relay profile search runs.
const SEARCH_DEBOUNCE_MS: i32 = 200;

/// Nickname as compared for clashes: trimmed, case-folded.
fn label_key(label: &str) -> String {
    label.trim().to_lowercase()
}

/// Key hints for every member whose nickname is shared by another member in
/// `pool` (`(pubkey, nickname)` pairs; repeats of one pubkey count once).
///
/// Each hint is the shortest prefix of the member's key, at least
/// [`KEY_HINT_MIN`] characters, that differs from every other key carrying
/// the same nickname. Members with a unique nickname get no entry.
pub(crate) fn key_hints<'a, I>(pool: I) -> HashMap<String, String>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    for (pk, label) in pool {
        let key = label_key(label);
        if key.is_empty() || pk.is_empty() {
            continue;
        }
        let pk = pk.to_lowercase();
        let group = groups.entry(key).or_default();
        if !group.contains(&pk) {
            group.push(pk);
        }
    }
    let mut hints = HashMap::new();
    for group in groups.values().filter(|g| g.len() > 1) {
        for pk in group {
            let mut n = KEY_HINT_MIN.min(pk.len());
            while n < pk.len()
                && group
                    .iter()
                    .any(|other| other != pk && other.get(..n) == pk.get(..n))
            {
                n += 1;
            }
            hints.insert(pk.clone(), pk.get(..n).unwrap_or(pk).to_string());
        }
    }
    hints
}

/// A pasted key: 64 hex characters (any case) or an `npub`, as lowercase hex.
pub(crate) fn parse_pubkey_input(input: &str) -> Option<String> {
    let s = input.trim();
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(s.to_lowercase());
    }
    if s.starts_with("npub1") {
        return nostr_bbs_core::nip19::decode_npub(s).ok();
    }
    None
}

/// `(pubkey, nickname)` for every named member in the profile cache. Tracked:
/// call inside a reactive scope so newly resolved names re-run it.
fn cached_names() -> Vec<(String, String)> {
    let Some(cache) = try_use_profile_cache() else {
        return Vec::new();
    };
    cache.entries.with(|entries| {
        entries
            .values()
            .filter_map(|e| e.best_label().map(|l| (e.pubkey.clone(), l)))
            .collect()
    })
}

/// The disambiguating key hint for `pubkey` among the known members plus
/// `peers` (other keys on screen beside it), or `None` when its nickname is
/// unique or unresolved. Tracked.
pub(crate) fn member_key_hint_tracked(pubkey: &str, peers: &[String]) -> Option<String> {
    let mut pool = cached_names();
    for pk in peers.iter().map(String::as_str).chain([pubkey]) {
        if let Some(label) = try_display_name_tracked(pk) {
            pool.push((pk.to_string(), label));
        }
    }
    key_hints(pool.iter().map(|(p, l)| (p.as_str(), l.as_str()))).remove(&pubkey.to_lowercase())
}

/// One dropdown row: the candidate, its nickname, and a key hint on clashes.
#[derive(Clone, PartialEq)]
struct PickerRow {
    pubkey: String,
    label: Option<String>,
    hint: Option<String>,
    nip05: Option<String>,
}

/// Type-to-search member picker. Fires `on_pick` with the chosen member's hex
/// pubkey; members in `exclude` (already assigned) are not offered.
#[component]
pub(crate) fn MemberPicker(
    /// Hex pubkeys not to offer.
    exclude: Vec<String>,
    /// Fired with the chosen hex pubkey.
    on_pick: Callback<String>,
    /// Input placeholder.
    #[prop(optional, into)]
    placeholder: Option<String>,
) -> impl IntoView {
    let query = RwSignal::new(String::new());
    let open = RwSignal::new(false);
    let active = RwSignal::new(0usize);
    let network = RwSignal::new(Vec::<MentionCandidate>::new());
    let generation = StoredValue::new(0u32);
    let exclude: Vec<String> = exclude.iter().map(|p| p.to_lowercase()).collect();

    let rows = Memo::new(move |_| {
        let q = query.get();
        let mut list = merge_candidates(
            network.get(),
            local_candidates(q.trim(), PICKER_LIMIT * 2),
            PICKER_LIMIT * 2,
        );
        if let Some(pk) = parse_pubkey_input(&q) {
            if !list.iter().any(|c| c.pubkey.eq_ignore_ascii_case(&pk)) {
                list.insert(
                    0,
                    MentionCandidate {
                        pubkey: pk,
                        name: None,
                        display_name: None,
                        nip05: None,
                        picture: None,
                    },
                );
            }
        }
        list.retain(|c| !exclude.contains(&c.pubkey.to_lowercase()));
        list.truncate(PICKER_LIMIT);

        let labelled: Vec<(MentionCandidate, Option<String>)> = list
            .into_iter()
            .map(|c| {
                let label = try_display_name_tracked(&c.pubkey)
                    .or_else(|| (!c.handle_is_key()).then(|| c.handle()));
                (c, label)
            })
            .collect();
        let mut pool = cached_names();
        pool.extend(
            labelled
                .iter()
                .filter_map(|(c, l)| l.clone().map(|l| (c.pubkey.clone(), l))),
        );
        let hints = key_hints(pool.iter().map(|(p, l)| (p.as_str(), l.as_str())));
        labelled
            .into_iter()
            .map(|(c, label)| PickerRow {
                hint: hints.get(&c.pubkey.to_lowercase()).cloned(),
                pubkey: c.pubkey,
                label,
                nip05: c.nip05.filter(|n| !n.trim().is_empty()),
            })
            .collect::<Vec<_>>()
    });

    // Debounced relay search; a newer keystroke discards an older result.
    let search = move |q: String| {
        let gen = generation.try_update_value(|g| {
            *g = g.wrapping_add(1);
            *g
        });
        let Some(gen) = gen else { return };
        crate::utils::set_timeout_once(
            move || {
                if generation.try_get_value() != Some(gen) {
                    return;
                }
                wasm_bindgen_futures::spawn_local(async move {
                    let found = search_profiles(&q, PICKER_LIMIT * 2).await;
                    if generation.try_get_value() == Some(gen) {
                        network.try_set(found);
                    }
                });
            },
            SEARCH_DEBOUNCE_MS,
        );
    };

    let pick = move |pk: String| {
        on_pick.run(pk);
        query.set(String::new());
        network.set(Vec::new());
        open.set(false);
        active.set(0);
    };

    view! {
        // The list renders in flow, not as an overlay: board columns sit in
        // an `overflow-x-auto` strip that would clip a floating dropdown.
        <div class="w-full">
            <input
                type="text"
                placeholder=placeholder.unwrap_or_else(|| "Add member\u{2026}".to_string())
                aria-label="Search members by nickname"
                aria-autocomplete="list"
                autocomplete="off"
                prop:value=move || query.get()
                on:focus=move |_| {
                    open.set(true);
                    search(query.get_untracked());
                }
                on:blur=move |_| open.set(false)
                on:input=move |ev| {
                    let v = event_target_value(&ev);
                    query.set(v.clone());
                    active.set(0);
                    open.set(true);
                    search(v);
                }
                on:keydown=move |ev: leptos::ev::KeyboardEvent| {
                    let n = rows.with_untracked(Vec::len);
                    match ev.key().as_str() {
                        "ArrowDown" if n > 0 => {
                            ev.prevent_default();
                            open.set(true);
                            active.update(|i| *i = (*i + 1) % n);
                        }
                        "ArrowUp" if n > 0 => {
                            ev.prevent_default();
                            active.update(|i| *i = (*i + n - 1) % n);
                        }
                        "Enter" => {
                            ev.prevent_default();
                            let i = active.get_untracked();
                            if let Some(row) = rows.with_untracked(|r| r.get(i).cloned()) {
                                pick(row.pubkey);
                            }
                        }
                        "Escape" => open.set(false),
                        _ => {}
                    }
                }
                class="w-40 bg-gray-900 border border-gray-600 rounded px-2 py-0.5 text-[11px] text-white placeholder-gray-500 za-focus"
            />
            <Show when=move || open.get()>
                <div class="mt-1 w-full max-w-xs glass-card rounded-lg overflow-hidden">
                    {move || {
                        let list = rows.get();
                        if list.is_empty() {
                            let msg = if query.with(|q| q.trim().is_empty()) {
                                "Type a nickname\u{2026}"
                            } else {
                                "No matching members"
                            };
                            return view! {
                                <div class="px-3 py-2 text-xs text-gray-500">{msg}</div>
                            }
                                .into_any();
                        }
                        let current = active.get();
                        view! {
                            <ul role="listbox" aria-label="Members" class="max-h-56 overflow-y-auto">
                                {list
                                    .into_iter()
                                    .enumerate()
                                    .map(|(i, row)| {
                                        let class = if i == current {
                                            "flex items-center gap-2 px-3 py-1.5 cursor-pointer bg-amber-500/15 text-amber-100"
                                        } else {
                                            "flex items-center gap-2 px-3 py-1.5 cursor-pointer hover:bg-gray-800/60 text-gray-200"
                                        };
                                        let pk = row.pubkey.clone();
                                        view! {
                                            <li
                                                role="option"
                                                aria-selected=i == current
                                                class=class
                                                // mousedown (not click) so the input's blur
                                                // does not close the list before the pick.
                                                on:mousedown=move |ev| {
                                                    ev.prevent_default();
                                                    pick(pk.clone());
                                                }
                                            >
                                                <span class="text-xs font-medium truncate flex-1 min-w-0">
                                                    {match row.label {
                                                        Some(l) => l.into_any(),
                                                        None => {
                                                            view! {
                                                                <CopyKey
                                                                    full=row.pubkey.clone()
                                                                    class="font-mono"
                                                                    keep_focus=true
                                                                />
                                                            }
                                                                .into_any()
                                                        }
                                                    }}
                                                </span>
                                                {row
                                                    .hint
                                                    .map(|h| {
                                                        view! {
                                                            <span
                                                                class="font-mono text-[10px] text-amber-300/80 flex-shrink-0"
                                                                title="Same nickname as another member: key prefix"
                                                            >
                                                                {h}
                                                            </span>
                                                        }
                                                    })}
                                                {row
                                                    .nip05
                                                    .map(|n| {
                                                        view! {
                                                            <span class="text-[10px] text-gray-500 truncate max-w-[6rem]">
                                                                {n}
                                                            </span>
                                                        }
                                                    })}
                                            </li>
                                        }
                                    })
                                    .collect_view()}
                            </ul>
                        }
                            .into_any()
                    }}
                </div>
            </Show>
        </div>
    }
}

/// A member's nickname, followed by a copyable key hint only while another
/// member (known to this client, or among `peers`) shares that nickname.
/// Falls back to the copyable abridged key until a nickname resolves.
#[component]
pub(crate) fn MemberName(
    /// Hex pubkey of the member.
    #[prop(into)]
    pubkey: String,
    /// Other keys rendered alongside (e.g. the card's other assignees).
    #[prop(optional)]
    peers: Vec<String>,
) -> impl IntoView {
    let pk = pubkey.clone();
    let name = Memo::new(move |_| try_display_name_tracked(&pk));
    let pk = pubkey.clone();
    let hint = Memo::new(move |_| member_key_hint_tracked(&pk, &peers));
    move || match name.get() {
        Some(n) => {
            let pubkey = pubkey.clone();
            view! {
            <span>{n}</span>
            {move || {
                let pubkey = pubkey.clone();
                hint.get()
                    .map(|h| {
                        view! {
                            <CopyKey
                                full=pubkey.clone()
                                display=h
                                class="ml-1 font-mono text-[10px] text-amber-300/80"
                            />
                        }
                    })
            }}
            }
            .into_any()
        }
        None => view! { <CopyKey full=pubkey.clone() /> }.into_any(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaa11111111111111111111111111111111111111111111111111111111";
    const B: &str = "bbbbbbbb22222222222222222222222222222222222222222222222222222222";
    const C: &str = "aaaaaaaa1111ffff111111111111111111111111111111111111111111111111";

    #[test]
    fn unique_nicknames_get_no_hint() {
        let hints = key_hints([(A, "alice"), (B, "bob")]);
        assert!(hints.is_empty());
    }

    #[test]
    fn shared_nickname_hints_both_members() {
        let hints = key_hints([(A, "Sam"), (B, "sam ")]);
        assert_eq!(hints.get(A).map(String::as_str), Some("aaaaaaaa"));
        assert_eq!(hints.get(B).map(String::as_str), Some("bbbbbbbb"));
    }

    #[test]
    fn hint_grows_until_keys_differ() {
        let hints = key_hints([(A, "sam"), (C, "sam")]);
        assert_eq!(hints.get(A).map(String::as_str), Some("aaaaaaaa11111"));
        assert_eq!(hints.get(C).map(String::as_str), Some("aaaaaaaa1111f"));
        // Distinct prefixes, shortest that separates them.
        assert_ne!(hints[A], hints[C]);
    }

    #[test]
    fn repeats_of_one_member_are_not_a_clash() {
        let hints = key_hints([(A, "sam"), (A, "Sam"), (&A.to_uppercase(), "sam")]);
        assert!(hints.is_empty());
    }

    #[test]
    fn blank_nicknames_never_clash() {
        let hints = key_hints([(A, ""), (B, "  ")]);
        assert!(hints.is_empty());
    }

    #[test]
    fn three_way_clash_hints_everyone() {
        let hints = key_hints([(A, "x"), (B, "x"), (C, "x"), ("cc", "y")]);
        assert_eq!(hints.len(), 3);
        assert!(!hints.contains_key("cc"));
    }

    #[test]
    fn pasted_hex_key_is_accepted_and_lowercased() {
        assert_eq!(
            parse_pubkey_input(&format!(" {} ", A.to_uppercase())),
            Some(A.to_string())
        );
        assert_eq!(parse_pubkey_input("alice"), None);
        assert_eq!(parse_pubkey_input(&A[..63]), None);
        assert_eq!(parse_pubkey_input(&"z".repeat(64)), None);
    }

    #[test]
    fn pasted_npub_round_trips() {
        let npub = nostr_bbs_core::nip19::encode_npub(A).unwrap();
        assert_eq!(parse_pubkey_input(&npub), Some(A.to_string()));
        assert_eq!(parse_pubkey_input("npub1notvalid"), None);
    }
}
