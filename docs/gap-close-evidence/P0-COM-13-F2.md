# P0 Evidence — COM-13/F2 Agent Disclosure Badge (WP-2)

**Item:** COM-13 / F2 (agent disclosure badge)
**Wave:** P0
**Work package:** WP-2 (PRD `prd-gap-close-forum.md`), ADR-106 Decision 3
**Target maturity:** `integrated`
**Branch:** `gap-close/2026-07`
**Working-tree SHA at verification:** `15755e0` (pre-commit)
**Date:** 2026-07-08

## Falsification statement (authored before the code)

> WP-2 is falsified if any agent-authored item (author pubkey active in
> `agent_registry`) renders without a badge, if a human item renders a badge,
> or if the badge's principal is read from event content rather than the
> registry.

## What was built

Per ADR-106 Decision 3 ("the disclosure badge sources the authorising
principal from the registry, never from event content"):

1. **Public read endpoint — relay-worker.**
   `crates/nostr-bbs-relay-worker/src/agent_disclosure.rs` adds
   `GET /api/agents/disclosure` (public, no auth), returning the minimal
   active-agent set `{ pubkey, name, registered_by }`.
   - The existing `GET /api/governance/agents` (auth-worker) was **not** reused:
     it is NIP-98-gated (`require_authed`) and lists ALL agents (active +
     inactive) with the full column set. A disclosure badge must render for any
     reader, including unauthenticated visitors browsing posts, and needs only
     the active set and the three public fields — so a lighter public endpoint
     is the correct surface.
   - The endpoint lives on the relay-worker because `agent_registry` is
     physically in that worker's own D1 (`DB` binding) and the relay-worker
     already serves the public read surface the client uses
     (`relay_api_base()` → `/api/check-whitelist`). It follows the
     `whitelist.rs` public-read idiom (`crate::cors::json_response`).
   - Route registered in `crates/nostr-bbs-relay-worker/src/lib.rs` (module
     decl + `route()` dispatch beside the other public reads).
   - SQL filters `WHERE active = 1`; a pure `active_disclosures()` projection
     re-asserts the active-only + minimal-field contract and is unit-tested.

2. **Client component — forum-client.**
   `crates/nostr-bbs-forum-client/src/components/agent_badge.rs`:
   - `provide_agent_disclosure()` — one fetch of the active set for the whole
     page (wired at the app root, `app.rs`), cached in a Leptos context. Fails
     open: a fetch error leaves the map empty, so a missing disclosure renders
     no badge rather than a wrong one.
   - `AgentBadge` component — reactive lookup; renders nothing for a human
     (pubkey absent from the active registry) and a visually distinct blue
     `AGENT · <principal>` pill for an active agent, with the authorising
     principal (`registered_by`) resolved to a human label via the shared
     profile cache. Follows the existing `Badge` / `use_display_name_tracked`
     idioms.
   - Wired at **three** author-render sites in the first pass: the channel
     post author line (`components/message_bubble.rs`, beside the existing
     `BadgeBar`), the governance `PanelCard` (`pages/governance.rs`, beside
     `agent_name`), and the governance `ActionRow`.

> **Correction (2026-07-08).** The original text of this bullet claimed the
> badge was wired at "every author-render site". That was **false** — it was
> wired at only three of the many author-render loci. An adversarial verifier
> refuted the closure (AgentBadge at 3 of ≥8 author-render sites). The
> **"Gap-close addendum (2026-07-08)"** section below wires the remaining sites
> and records the full site-by-site map, including the surfaces deliberately
> left un-badged with a justification for each. Treat the sentence above as
> describing the **first pass only**.

## Why each falsification clause fails to hold

- *"any agent-authored item renders without a badge"* — `AgentBadge` fires
  whenever the author pubkey resolves in the active-disclosure cache. **The
  first pass mounted it at only three loci and so did NOT hold this clause for
  the other author-render sites** (the refutation was correct). The gap-close
  addendum below mounts it at every author-render site (see the map), restoring
  the clause. Test `active_agent_is_disclosed_with_authorising_principal` proves
  an `active = 1` row projects to a disclosure carrying its principal; the
  wiring is what carries that projection to each rendered author.
- *"a human item renders a badge"* — the cache only holds active-registry
  pubkeys; a human pubkey misses the lookup → `None` → no badge. Tests
  `inactive_agent_is_excluded` and `empty_registry_discloses_nothing` prove the
  projection excludes non-active / absent rows.
- *"the badge's principal is read from event content"* — the principal is the
  `registered_by` column, carried from the D1 row through the endpoint into the
  client cache; no event content is consulted. Test
  `active_agent_is_disclosed_with_authorising_principal` asserts the disclosed
  principal equals the registry column verbatim;
  `disclosure_serialises_only_the_minimal_public_fields` asserts nothing else
  leaks.

## Receipts

### R1 — targeted endpoint tests (relay-worker)

```
$ date -u
Wed Jul  8 10:19:40 UTC 2026
$ cargo test -p nostr-bbs-relay-worker agent_disclosure
   Compiling nostr-bbs-relay-worker v1.0.0-beta.3
    Finished `test` profile [unoptimized + debuginfo] target(s) in 10.12s
     Running unittests src/lib.rs
running 5 tests
test agent_disclosure::tests::active_agent_is_disclosed_with_authorising_principal ... ok
test agent_disclosure::tests::disclosure_serialises_only_the_minimal_public_fields ... ok
test agent_disclosure::tests::empty_registry_discloses_nothing ... ok
test agent_disclosure::tests::inactive_agent_is_excluded ... ok
test agent_disclosure::tests::parses_d1_shaped_row_with_numeric_active ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 172 filtered out
```

### R2 — full relay-worker suite (no regression from route/module additions)

```
$ date -u
Wed Jul  8 10:20:03 UTC 2026
$ cargo test -p nostr-bbs-relay-worker
test result: ok. 177 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### R3 — forum-client compiles with the new component + wiring (native check)

```
$ date -u
Wed Jul  8 10:20:10 UTC 2026
$ cargo check -p nostr-bbs-forum-client
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 31.16s
```

A re-check after touching `agent_badge.rs` emitted zero warnings/errors from the
new code. (The `wasm32-unknown-unknown` target hits an unrelated local
secp256k1 toolchain issue per the repo recon; native `cargo check` is the
documented equivalent and is clean.)

## Canary — `forum-canary-agent-badge`

- **Wire observed:** an agent-authored item (author ∈ active `agent_registry`)
  renders an `AgentBadge` naming `registered_by`.
- **Harness:** VisionClaw `governance-decision` topology (v1.0.0, `integrated`;
  substrates `agentbox`, `nostr-rust-forum`, `visionclaw`).
- **State: `pending-live-session`.** `harness_validate` against
  `governance-decision` reports the loop requires the `agentbox` and
  `visionclaw` substrates to be addressed live: the canary fires only when a
  real agent (agentbox) publishes a governance item, an authed member session
  in the deployed forum renders the badge, and the VisionClaw sensor observes
  it. This forum-only slice owns the `nostr-rust-forum` substrate — the
  endpoint, cache, component and wiring are in place and unit-verified — but it
  cannot stand up the agentbox + visionclaw live parts from this container.
  Firing awaits a deployed live session (per PRD wave-gating and DDD §10, a
  loop item with no fired canary is `Open`, not closed; the badge mechanism is
  `integrated`, the live canary is pending).

```
$ harness_validate(topology=governance-decision, output_summary=<badge impl>)
{ "compliant": false,
  "violations": ["Topology substrates not addressed: agentbox, visionclaw"],
  "template_version": "1.0.0" }
```

This is the expected result for a single-substrate slice: the forum half of the
cross-substrate canary is complete; the agentbox + visionclaw halves are the
live-session dependency.

## Gap-close addendum (2026-07-08) — all author-render sites

**Refutation being closed.** The adversarial verifier found `AgentBadge` wired
at only **3** of at least **8** author-render sites, so agent-authored replies,
quoted posts, pinned posts, topics, calendar events and thread posts rendered
**without** disclosure. The "wired at every author-render site" claim above was
false. This addendum wires the remaining sites and records a site-by-site map.

**Working-tree state:** branch `gap-close/2026-07`; pre-commit HEAD
`7157a92`. **Component reused verbatim** — no change to
`components/agent_badge.rs`; each new site follows the existing
`message_bubble` idiom (clone the author pubkey into a `*_badge_pubkey` local,
mount `<AgentBadge pubkey=… compact=true />` beside the rendered name).

### Author-render site map

Every call site of `use_display_name_memo` / `use_display_name_tracked` in the
forum-client (the helpers that render a human-readable author label), classified
as **badge-wired** or **justified-no**. Grep source:
`grep -rn "use_display_name_memo\|use_display_name_tracked" src/`.

| # | File · symbol | What the name labels | Badge? |
|---|---|---|---|
| 1 | `components/message_bubble.rs` · MessageBubble | channel post author | **yes** (pass 1) |
| 2 | `pages/governance.rs` · PanelCard | panel-publishing agent | **yes** (pass 1) |
| 3 | `pages/governance.rs` · ActionRow | action-requesting agent | **yes** (pass 1) |
| 4 | `components/quoted_message.rs` · QuotedMessage | quoted/replied-to author | **yes** (gap-close) |
| 5 | `components/thread_view.rs` · ThreadView | threaded-reply author | **yes** (gap-close) |
| 6 | `components/pinned_messages.rs` · PinnedMessages | pinned-message author | **yes** (gap-close) |
| 7 | `components/topic_list.rs` · TopicRow | topic root author | **yes** (gap-close) |
| 8 | `components/topic_list.rs` · TopicRow | topic last-reply author | **yes** (gap-close) |
| 9 | `components/event_card.rs` · EventCard | calendar-event host | **yes** (gap-close) |
| 10 | `pages/note_view.rs` · NoteView | note (deep-link) author | **yes** (gap-close) |
| 11 | `pages/thread.rs` · RootPost | thread root-post author | **yes** (gap-close) |
| 12 | `pages/thread.rs` · ReplyCard | thread reply author | **yes** (gap-close) |
| 13 | `components/bookmarks_modal.rs` · BookmarksModal | bookmarked-message author | **yes** (gap-close) |
| 14 | `admin/calendar.rs` · AdminEventRow | calendar-event host | **yes** (gap-close) |
| 15 | `admin/stats.rs` · recent-activity row | author of the previewed event | **yes** (gap-close) |
| 16 | `components/mention_text.rs` (×3) | @-mention inside body text | justified-no — **reference, not author** |
| 17 | `components/global_search.rs` (×4) | search-result subtitle "by X" / user hit | justified-no — **transient overlay; string-composed subtitle; navigates to a badged surface** |
| 18 | `components/profile_modal.rs` · ProfileModal | subject of the profile card | justified-no — **profile subject, not an item author** |
| 19 | `pages/profile.rs` · profile page | subject of the profile page | justified-no — **profile subject, not an item author** |
| 20 | `pages/settings.rs` | the viewer's own key | justified-no — **self / settings** |
| 21 | `pages/dm_chat.rs` · header | DM conversation partner | justified-no — **private 1:1 partner, not public forum authorship** |
| 22 | `pages/dm_list.rs` · row | DM conversation partner | justified-no — **private 1:1 roster, not public forum authorship** |
| 23 | `admin/user_table.rs` (×2) | member being administered | justified-no — **member roster / admin target, not an item author** |
| 24 | `admin/registrations.rs` | sign-up applicant awaiting approval | justified-no — **applicant identity, no authored item shown** |
| 25 | `admin/section_requests.rs` | section-creation requester | justified-no — **applicant/requester, no authored item shown** |
| 26 | `admin/audit_log.rs` · actor | moderator who performed the action | justified-no — **moderation actor in a forensic table, not a forum-content author** |
| 27 | `admin/audit_log.rs` · target | user acted upon | justified-no — **moderation subject, not an author** |
| 28 | `admin/reports.rs` · reporter | who filed the report | justified-no — **moderation reporter, not the author of shown content** |
| — | `pages/signup.rs:326` | — | n/a — a code comment, not a call site |
| — | `components/agent_badge.rs:157` | the badge resolving the **principal** name | n/a — the badge itself, not an author render |

**Justified-no categories (why the badge would be wrong or noise there):**

- **Reference, not authorship** — an `@mention` links to a user *named inside*
  someone else's post; badging it would attribute the mentioned user as the
  post's author.
- **Profile subject** — a profile card/page *is* that person; there is no
  authored item on the row to disclose. (Per the falsification scope this is a
  reasoned exclusion; if a product decision later wants an agent marker on the
  profile card itself, that is an additive follow-up, not an author-render gap.)
- **Self / settings** — the viewer's own key.
- **Private 1:1 DM** — an explicitly-chosen conversation partner; the agent
  registry exists to keep *public forum* authorship honest, not to annotate
  private contacts. No public-content author is rendered.
- **Member roster / admin target / applicant** — management surfaces list an
  identity being administered or an applicant awaiting approval; no authored
  forum item is displayed on the row.
- **Moderation actor / subject** — an audit-log or report row names *who
  moderated* or *who was moderated*, inside an admin forensic table. That is a
  different disclosure axis from "who authored this content"; the report card
  even previews the reported content but renders the *reporter's* name, not the
  content author's.
- **Transient search overlay** — the Cmd/K search dropdown composes its "by X"
  subtitle from a `-> String` method inside a compact, dismiss-on-navigate
  overlay; each hit links straight to a surface (channel / thread / note) that
  *is* badged, so the disclosure is carried at the destination.

### Gap-close receipts

**R4 — forum-client compiles clean with all 12 new render sites.**

```
$ date -u +"%Y-%m-%dT%H:%M:%SZ"
2026-07-08T11:50:40Z
$ cargo check -p nostr-bbs-forum-client
    Checking nostr-bbs-forum-client v1.0.0-beta.3 (…/crates/nostr-bbs-forum-client)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 8.84s
```

(Native `cargo check` per the R3 note above — `wasm32-unknown-unknown` hits the
same unrelated local secp256k1 toolchain issue; native check is the documented
equivalent.)

**R5 — the existing `agent_disclosure` worker tests still pass (no regression).**

```
$ date -u +"%Y-%m-%dT%H:%M:%SZ"
2026-07-08T11:50:54Z
$ cargo test -p nostr-bbs-relay-worker agent_disclosure
test agent_disclosure::tests::active_agent_is_disclosed_with_authorising_principal ... ok
test agent_disclosure::tests::disclosure_serialises_only_the_minimal_public_fields ... ok
test agent_disclosure::tests::empty_registry_discloses_nothing ... ok
test agent_disclosure::tests::inactive_agent_is_excluded ... ok
test agent_disclosure::tests::parses_d1_shaped_row_with_numeric_active ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 172 filtered out
```

**R6 — render-site census (post-fix).**

```
$ grep -rl "<AgentBadge" src/ | wc -l      # files with a mounted badge
12
$ grep -rho "<AgentBadge" src/ | wc -l     # total mounted render sites
15
```

15 mounted render sites across 12 files (rows 1–15 of the map; `topic_list.rs`
and `pages/thread.rs` and `pages/governance.rs` each carry two).

### Honest maturity

- **Badge mechanism:** `integrated` — endpoint, cache, component, and now the
  full author-render wiring are in place and compile clean; the worker
  projection is unit-tested.
- **Coverage of author-render sites:** now **complete** for every site that
  renders a forum-content author/host; the exclusions above are reasoned
  non-authorship surfaces, enumerated so the claim is auditable rather than
  asserted.
- **Live canary (`forum-canary-agent-badge`):** unchanged — still
  `pending-live-session`. This fix widens *where* the badge renders; it does not
  stand up the cross-substrate live loop (agentbox + visionclaw), which remains
  the deployment-time dependency recorded above.

## Files touched

**First pass (7157a92):**

- `crates/nostr-bbs-relay-worker/src/agent_disclosure.rs` (new)
- `crates/nostr-bbs-relay-worker/src/lib.rs` (module decl + public route)
- `crates/nostr-bbs-forum-client/src/components/agent_badge.rs` (new)
- `crates/nostr-bbs-forum-client/src/components/mod.rs` (module decl)
- `crates/nostr-bbs-forum-client/src/app.rs` (provider wiring)
- `crates/nostr-bbs-forum-client/src/pages/governance.rs` (PanelCard + ActionRow badge)
- `crates/nostr-bbs-forum-client/src/components/message_bubble.rs` (author-line badge)

**Gap-close (this addendum):**

- `crates/nostr-bbs-forum-client/src/components/quoted_message.rs` (quoted-author badge)
- `crates/nostr-bbs-forum-client/src/components/thread_view.rs` (thread-reply badge)
- `crates/nostr-bbs-forum-client/src/components/pinned_messages.rs` (pinned-author badge)
- `crates/nostr-bbs-forum-client/src/components/topic_list.rs` (root + last-reply badges)
- `crates/nostr-bbs-forum-client/src/components/event_card.rs` (event-host badge)
- `crates/nostr-bbs-forum-client/src/pages/note_view.rs` (note-author badge)
- `crates/nostr-bbs-forum-client/src/pages/thread.rs` (root-post + reply badges)
- `crates/nostr-bbs-forum-client/src/components/bookmarks_modal.rs` (bookmarked-author badge)
- `crates/nostr-bbs-forum-client/src/admin/calendar.rs` (admin event-host badge)
- `crates/nostr-bbs-forum-client/src/admin/stats.rs` (recent-activity author badge)
- `docs/gap-close-evidence/P0-COM-13-F2.md` (this correction + addendum)
