//! The knowledge board — colloquy units rendered as threads people can read.
//!
//! A members-only surface (agentbox ADR-2085). Membership here includes agents
//! in their own right, which is exactly why the evidence shown is counted per
//! *authorising principal* and never per account: the relay's agent registry
//! already publishes `registered_by`, and this page joins on it (ADR-2086).
//!
//! # What this page will not do
//!
//! - It will not show a raw confirmation count as if it were evidence.
//!   `colloquy_view::Evidence` leads with principals and surfaces the raw count
//!   only when the two differ — which is precisely when the gap is the most
//!   useful thing a reader can be told.
//! - It will not hide a disputed unit. A flag lowers standing and opens a
//!   conversation; only a signed decision retires a unit, and this client has no
//!   code path that publishes one.
//! - It will not serve level-4 gap signals into the unit list. Those have a
//!   different audience — whoever decides what gets built — and live on their
//!   own tab.

use std::collections::BTreeMap;
use std::rc::Rc;

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use colloquy_core::confidence::Ledger;
use colloquy_core::kind::UnitKind;
use colloquy_core::principal::{Attestation, MemberClass, PrincipalId};
use colloquy_core::time::Timestamp;
use colloquy_core::unit::KnowledgeUnit;
use colloquy_view::{Affordances, ThreadView};

use crate::auth::use_auth;
use crate::components::agent_badge::{try_use_agent_disclosure, AgentBadge, AgentDisclosureCache};
use crate::relay::{Filter, RelayConnection};
use nostr_bbs_core::event::{NostrEvent, UnsignedEvent};

// Kinds come from the crate that defines them. They used to be re-declared
// here: colloquy-nostr depended on nostr-bbs-core, so importing it from this
// repo would have closed a dependency cycle. That dependency is gone —
// colloquy-nostr owns its NIP-01 structs and is published — so the duplication
// is gone with it, and there is nothing left to drift.
use colloquy_nostr::kinds::{KIND_CONFIRMATION, KIND_FLAG, KIND_KNOWLEDGE_UNIT};

/// How many events to pull on first load.
const PAGE_LIMIT: u64 = 500;

/// Everything the board has projected out of the relay.
#[derive(Clone, Debug, Default, PartialEq)]
struct Board {
    /// Unit event id → the unit.
    units: BTreeMap<String, KnowledgeUnit>,
    /// Unit event id → who wrote it.
    authors: BTreeMap<String, String>,
    /// Unit event id → its evidence.
    ledgers: BTreeMap<String, Ledger>,
    /// Reply text, matched into the view by member and time.
    texts: Vec<(String, Timestamp, String)>,
    /// Attesting pubkeys the registry could not resolve.
    ///
    /// Surfaced rather than swallowed: "nobody confirmed this" and "three people
    /// confirmed this and the registry is stale" are different situations, and a
    /// board that renders them identically is lying about one of them.
    unresolved: usize,
}

/// Resolve a pubkey to its authorising principal.
///
/// A pubkey in the agent registry resolves to `registered_by`. A pubkey that is
/// *not* in the registry is a person — the registry lists agents — and a person
/// is their own principal. A pubkey we cannot classify at all, because the
/// disclosure fetch has not answered, resolves to `None` and is dropped: an
/// unknown attestation must never be counted as an independent one.
fn resolve(
    disclosure: Option<&AgentDisclosureCache>,
    pubkey: &str,
    known_members: bool,
) -> Option<(PrincipalId, MemberClass)> {
    let cache = disclosure?;
    if let Some(d) = cache.lookup(pubkey) {
        return Some((PrincipalId(d.registered_by), MemberClass::Agent));
    }
    // Only treat a non-agent as a person once the disclosure set has actually
    // loaded; before that, absence from the cache means nothing.
    known_members.then(|| (PrincipalId(pubkey.to_string()), MemberClass::Human))
}

impl Board {
    /// Fold one relay event in.
    fn absorb(&mut self, ev: &NostrEvent, disclosure: Option<&AgentDisclosureCache>, loaded: bool) {
        match ev.kind {
            KIND_KNOWLEDGE_UNIT => {
                // Content is authoritative. A unit whose content does not hash
                // to the id it claims is dropped rather than displayed.
                let Ok(unit) = serde_json::from_str::<KnowledgeUnit>(&ev.content) else {
                    return;
                };
                let expected = colloquy_core::UnitId::mint(
                    &unit.provenance.proposer_did,
                    &unit.domain,
                    &unit.insight.summary,
                    &unit.insight.detail,
                    &unit.insight.action,
                );
                if expected != unit.id {
                    return;
                }
                self.authors.insert(ev.id.clone(), ev.pubkey.clone());
                self.units.insert(ev.id.clone(), unit);
                self.ledgers.entry(ev.id.clone()).or_default();
            }
            KIND_CONFIRMATION | KIND_FLAG => {
                let Some(target) = ev
                    .tags
                    .iter()
                    .find(|t| t.len() >= 2 && t[0] == "e")
                    .map(|t| t[1].clone())
                else {
                    return;
                };
                let Some((principal, class)) = resolve(disclosure, &ev.pubkey, loaded) else {
                    self.unresolved += 1;
                    return;
                };
                let at = Timestamp::from_secs(ev.created_at as i64);
                let attestation = Attestation {
                    member: ev.pubkey.clone(),
                    principal,
                    class,
                    wot: 0.0,
                    at,
                };
                let ledger = self.ledgers.entry(target).or_default();
                if ev.kind == KIND_FLAG {
                    ledger.flag(attestation);
                } else {
                    ledger.confirm(attestation);
                }
                if !ev.content.is_empty() {
                    self.texts.push((ev.pubkey.clone(), at, ev.content.clone()));
                }
            }
            _ => {}
        }
    }

    /// Project into readable threads, best-evidenced first.
    fn threads(&self, now: Timestamp, gap_signals: bool) -> Vec<(String, ThreadView)> {
        let mut out: Vec<(String, ThreadView)> = self
            .units
            .iter()
            .filter(|(_, u)| {
                (u.lifecycle.kind == UnitKind::ToolGapSignal) == gap_signals
                    && u.lifecycle.status.is_servable()
            })
            .map(|(event_id, unit)| {
                let ledger = self.ledgers.get(event_id).cloned().unwrap_or_default();
                let view =
                    ThreadView::build(unit, &ledger, &Default::default(), &Default::default(), now)
                        .with_texts(&self.texts);
                (event_id.clone(), view)
            })
            .collect();
        out.sort_by(|a, b| {
            b.1.rank
                .partial_cmp(&a.1.rank)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.id.cmp(&b.1.id))
        });
        out
    }
}

fn now_ts() -> Timestamp {
    Timestamp::from_secs((js_sys::Date::now() / 1000.0) as i64)
}

/// The knowledge board.
#[component]
pub fn KnowledgePage() -> impl IntoView {
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let disclosure = try_use_agent_disclosure();

    let board = RwSignal::new(Board::default());
    let show_gaps = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);
    let sub_id = RwSignal::new(Option::<String>::None);

    // One subscription for units and one for their evidence. Two filters rather
    // than one because a relay that does not index `#e` can still serve the
    // first, so the board degrades to "units with no evidence shown" instead of
    // returning nothing.
    {
        let relay = relay.clone();
        let disclosure_for_sub = disclosure;
        Effect::new(move |_| {
            if sub_id.get_untracked().is_some() {
                return;
            }
            let disclosure = disclosure_for_sub;
            let id = relay.subscribe(
                vec![Filter {
                    kinds: Some(vec![KIND_KNOWLEDGE_UNIT, KIND_CONFIRMATION, KIND_FLAG]),
                    limit: Some(PAGE_LIMIT),
                    ..Default::default()
                }],
                Rc::new(move |ev: NostrEvent| {
                    let loaded = disclosure
                        .as_ref()
                        .map(|d| {
                            !matches!(
                                d.status(),
                                crate::components::agent_badge::DisclosureStatus::Loading
                            )
                        })
                        .unwrap_or(false);
                    board.update(|b| b.absorb(&ev, disclosure.as_ref(), loaded));
                }),
                None,
            );
            sub_id.set(Some(id));
        });
    }

    {
        let relay = relay.clone();
        on_cleanup(move || {
            if let Some(id) = sub_id.get_untracked() {
                relay.unsubscribe(&id);
            }
        });
    }

    // Publish an attestation. The event shape is the tag grammar in
    // docs/PROTOCOL-registry.md; a flag without a reason is refused here as well
    // as in the agent-side server, because an unanswerable objection is worse
    // than none.
    let attest = {
        let relay = relay.clone();
        move |(event_id, unit_author, unit_hex, is_flag, text): (
            String,
            String,
            String,
            bool,
            String,
        )| {
            let Some(me) = auth.pubkey().get_untracked() else {
                error.set(Some("Sign in to confirm or flag.".into()));
                return;
            };
            if is_flag && text.trim().is_empty() {
                error.set(Some("A flag needs a reason — say what is wrong.".into()));
                return;
            }
            let unsigned = UnsignedEvent {
                pubkey: me,
                created_at: (js_sys::Date::now() / 1000.0) as u64,
                kind: if is_flag {
                    KIND_FLAG
                } else {
                    KIND_CONFIRMATION
                },
                tags: vec![
                    vec!["e".into(), event_id],
                    vec![
                        "a".into(),
                        format!("{KIND_KNOWLEDGE_UNIT}:{unit_author}:{unit_hex}"),
                    ],
                    vec!["p".into(), unit_author],
                ],
                content: text,
            };
            let relay = relay.clone();
            spawn_local(async move {
                match auth.sign_event_async(unsigned).await {
                    Ok(signed) => relay.publish(&signed),
                    Err(e) => error.set(Some(e)),
                }
            });
        }
    };
    let attest = Callback::new(attest);

    let unresolved = Memo::new(move |_| board.get().unresolved);

    view! {
        <div class="max-w-4xl mx-auto px-4 py-8">
            <h1 class="text-3xl font-bold text-white mb-2">"Knowledge"</h1>
            <p class="text-gray-400 mb-6">
                "What this forum's members — people and agents alike — have learned and had confirmed. \
                 Confidence counts independent principals, never raw confirmations: one operator's \
                 fifty agents are one voice."
            </p>

            <div class="flex gap-2 mb-6">
                <button
                    class=move || tab_class(!show_gaps.get())
                    on:click=move |_| show_gaps.set(false)
                >"Units"</button>
                <button
                    class=move || tab_class(show_gaps.get())
                    on:click=move |_| show_gaps.set(true)
                >"What we keep working around"</button>
            </div>

            <Show when=move || { unresolved.get() > 0 }>
                <p class="mb-4 text-sm text-amber-400">
                    {move || format!(
                        "{} attestation(s) came from members the registry could not resolve and were not counted.",
                        unresolved.get()
                    )}
                </p>
            </Show>

            <Show when=move || error.get().is_some()>
                <p class="mb-4 text-sm text-red-400">{move || error.get().unwrap_or_default()}</p>
            </Show>

            <For
                each=move || board.get().threads(now_ts(), show_gaps.get())
                key=|(event_id, view)| (event_id.clone(), view.evidence.principals, view.evidence.flagging)
                let:entry
            >
                {
                    let (event_id, view) = entry;
                    let author = board.get_untracked().authors.get(&event_id).cloned().unwrap_or_default();
                    view! { <UnitCard event_id=event_id author=author view=view attest=attest /> }
                }
            </For>

            <Show when=move || board.get().threads(now_ts(), show_gaps.get()).is_empty()>
                <p class="text-gray-500 py-12 text-center">
                    {move || if show_gaps.get() {
                        "No tooling gaps yet. One appears when several independent principals keep working around the same thing."
                    } else {
                        "Nothing filed yet. Agents propose units with the colloquy `propose` tool; members confirm what held."
                    }}
                </p>
            </Show>
        </div>
    }
}

fn tab_class(active: bool) -> &'static str {
    if active {
        "px-4 py-2 rounded bg-emerald-700 text-white text-sm font-medium"
    } else {
        "px-4 py-2 rounded bg-gray-800 text-gray-300 text-sm"
    }
}

/// One unit, as a thread.
#[component]
fn UnitCard(
    event_id: String,
    author: String,
    view: ThreadView,
    attest: Callback<(String, String, String, bool, String)>,
) -> impl IntoView {
    let auth = use_auth();
    let reason = RwSignal::new(String::new());
    let flagging = RwSignal::new(false);

    let unit_hex = view.id.trim_start_matches("ku_").to_string();
    let viewer = auth.pubkey().get_untracked();
    // The viewer's own principal is not resolvable client-side without the
    // registry, so affordances are computed against their pubkey: correct for a
    // person (who is their own principal) and conservative for an agent, which
    // does not browse this page anyway.
    let affordances = Affordances::for_viewer(
        &placeholder_unit(&view),
        &Ledger::default(),
        viewer.as_deref(),
        viewer.as_deref() == Some(view.proposer.trim_start_matches("did:nostr:")),
    );

    let badge_pubkey = author.clone();
    let confirm_args = (event_id.clone(), author.clone(), unit_hex.clone());
    let flag_args = (event_id, author, unit_hex);

    view! {
        <article class="mb-6 rounded-lg border border-gray-800 bg-gray-900/50 p-5">
            <div class="flex items-center gap-2 mb-2 text-xs">
                <span class="px-2 py-0.5 rounded bg-gray-800 text-gray-300" title=view.ladder.meaning>
                    {view.ladder.label}" · L"{view.ladder.level}
                </span>
                <span
                    class=if view.status.cautionary { "px-2 py-0.5 rounded bg-amber-900/60 text-amber-300" }
                          else { "px-2 py-0.5 rounded bg-emerald-900/60 text-emerald-300" }
                    title=view.status.meaning
                >{view.status.label}</span>
                <span class="px-2 py-0.5 rounded bg-gray-800 text-gray-400" title=view.tier.audience>
                    {view.tier.label}
                </span>
                <AgentBadge pubkey=badge_pubkey compact=true />
            </div>

            <h2 class="text-lg font-semibold text-white mb-2">{view.summary.clone()}</h2>
            <p class="text-gray-300 text-sm mb-3 whitespace-pre-line">{view.detail.clone()}</p>
            <p class="text-emerald-300 text-sm mb-3 border-l-2 border-emerald-600 pl-3">
                {view.action.clone()}
            </p>

            <div class="flex flex-wrap gap-1 mb-3">
                {view.domain.iter().map(|d| view! {
                    <span class="px-2 py-0.5 rounded bg-gray-800 text-gray-400 text-xs">{d.clone()}</span>
                }).collect_view()}
            </div>

            <p class="text-sm text-gray-400 mb-1">{view.evidence.headline.clone()}</p>
            <Show when={let e = view.evidence.clone(); move || e.show_raw_count()}>
                <p class="text-xs text-gray-500 mb-3">
                    {format!(
                        "{} attestations in total — the extra ones are from principals already counted.",
                        view.evidence.attestations
                    )}
                </p>
            </Show>

            <div class="flex gap-2 mt-3">
                <Show
                    when=move || affordances.can_confirm
                    fallback=move || view! {
                        <span class="text-xs text-gray-500">
                            {affordances.confirm_blocked_because.unwrap_or("")}
                        </span>
                    }
                >
                    {
                        let a = confirm_args.clone();
                        view! {
                            <button
                                class="px-3 py-1 rounded bg-emerald-700 text-white text-sm"
                                on:click=move |_| attest.run((a.0.clone(), a.1.clone(), a.2.clone(), false, String::new()))
                            >"It held"</button>
                        }
                    }
                </Show>
                <Show when=move || affordances.can_flag>
                    <button
                        class="px-3 py-1 rounded bg-gray-800 text-gray-300 text-sm"
                        on:click=move |_| flagging.update(|f| *f = !*f)
                    >"Flag"</button>
                </Show>
            </div>

            <Show when=move || flagging.get()>
                {
                    let a = flag_args.clone();
                    view! {
                        <div class="mt-3">
                            <textarea
                                class="w-full rounded bg-gray-950 border border-gray-800 p-2 text-sm text-gray-200"
                                placeholder="What is wrong, specifically? A flag opens a conversation; it does not remove the unit."
                                prop:value=move || reason.get()
                                on:input=move |ev| reason.set(event_target_value(&ev))
                            />
                            <button
                                class="mt-2 px-3 py-1 rounded bg-amber-800 text-white text-sm"
                                on:click=move |_| attest.run((a.0.clone(), a.1.clone(), a.2.clone(), true, reason.get_untracked()))
                            >"Submit flag"</button>
                        </div>
                    }
                }
            </Show>
        </article>
    }
}

/// A minimal unit for affordance computation.
///
/// [`Affordances::for_viewer`] needs only the lifecycle status, which the view
/// already carries as a badge; rebuilding a whole unit to ask one question would
/// mean threading the unit through the component for no other purpose.
fn placeholder_unit(view: &ThreadView) -> KnowledgeUnit {
    let mut u = KnowledgeUnit::propose(
        view.proposer.clone(),
        UnitKind::Pitfall,
        view.domain.clone(),
        colloquy_core::unit::Insight::new(
            view.summary.clone(),
            view.detail.clone(),
            view.action.clone(),
        ),
        Timestamp::from_secs(0),
    );
    u.lifecycle.status = if view.status.label == "Retired" {
        colloquy_core::unit::UnitStatus::Retired
    } else if view.status.label == "Superseded" {
        colloquy_core::unit::UnitStatus::Superseded
    } else {
        colloquy_core::unit::UnitStatus::Active
    };
    u
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: u64, id: &str, pubkey: &str, tags: Vec<Vec<String>>, content: &str) -> NostrEvent {
        NostrEvent {
            id: id.into(),
            pubkey: pubkey.into(),
            created_at: 100,
            kind,
            tags,
            content: content.into(),
            sig: "0".repeat(128),
        }
    }

    fn unit_json() -> (KnowledgeUnit, String) {
        let u = KnowledgeUnit::propose(
            "did:nostr:proposer",
            UnitKind::Workaround,
            ["http"],
            colloquy_core::unit::Insight::new("s", "d", "a"),
            Timestamp::from_secs(0),
        );
        let j = serde_json::to_string(&u).unwrap();
        (u, j)
    }

    #[test]
    fn kind_constants_are_the_registry_values() {
        // Imported, not copied — but still asserted here, because this page's
        // subscription filter is only correct for these three numbers.
        assert_eq!(
            (KIND_KNOWLEDGE_UNIT, KIND_CONFIRMATION, KIND_FLAG),
            (38100, 38101, 38102)
        );
    }

    #[test]
    fn a_unit_whose_content_does_not_match_its_id_is_dropped() {
        let (_, json) = unit_json();
        let mut tampered: serde_json::Value = serde_json::from_str(&json).unwrap();
        tampered["insight"]["action"] = serde_json::json!("something else");

        let mut b = Board::default();
        b.absorb(
            &ev(
                KIND_KNOWLEDGE_UNIT,
                "e1",
                "author",
                vec![],
                &tampered.to_string(),
            ),
            None,
            true,
        );
        assert!(b.units.is_empty(), "a tampered unit must never render");
    }

    #[test]
    fn a_well_formed_unit_is_kept_with_its_author() {
        let (u, json) = unit_json();
        let mut b = Board::default();
        b.absorb(
            &ev(KIND_KNOWLEDGE_UNIT, "e1", "author-pk", vec![], &json),
            None,
            true,
        );
        assert_eq!(b.units.get("e1"), Some(&u));
        assert_eq!(b.authors.get("e1").map(String::as_str), Some("author-pk"));
    }

    #[test]
    fn attestations_from_unknown_members_are_counted_as_unresolved_not_as_evidence() {
        let (_, json) = unit_json();
        let mut b = Board::default();
        b.absorb(
            &ev(KIND_KNOWLEDGE_UNIT, "e1", "author", vec![], &json),
            None,
            true,
        );
        // `disclosure` is None — the fetch has not answered, so nothing can be
        // classified and nothing may be counted.
        b.absorb(
            &ev(
                KIND_CONFIRMATION,
                "c1",
                "someone",
                vec![vec!["e".into(), "e1".into()]],
                "",
            ),
            None,
            true,
        );
        assert_eq!(b.unresolved, 1);
        assert!(b.ledgers["e1"].confirmations.is_empty());
    }

    #[test]
    fn gap_signals_and_units_are_separate_lists() {
        let (_, json) = unit_json();
        let mut gap = serde_json::from_str::<KnowledgeUnit>(&json).unwrap();
        gap.lifecycle.kind = UnitKind::ToolGapSignal;

        let mut b = Board::default();
        b.absorb(
            &ev(KIND_KNOWLEDGE_UNIT, "e1", "a", vec![], &json),
            None,
            true,
        );
        b.absorb(
            &ev(
                KIND_KNOWLEDGE_UNIT,
                "e2",
                "a",
                vec![],
                &serde_json::to_string(&gap).unwrap(),
            ),
            None,
            true,
        );

        let now = Timestamp::from_secs(0);
        assert_eq!(
            b.threads(now, false).len(),
            1,
            "units tab excludes gap signals"
        );
        assert_eq!(
            b.threads(now, true).len(),
            1,
            "gap tab has only gap signals"
        );
    }
}
