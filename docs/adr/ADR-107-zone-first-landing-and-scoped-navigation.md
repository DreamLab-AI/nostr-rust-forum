# ADR-107: Zone-first landing and scoped navigation

**Status:** Accepted
**Date:** 2026-07-16
**Decision Owners:** nostr-rust-forum maintainers (DreamLab AI)
**Related:** ADR-022 NIP-29 Group Access Model (upstream/historical kit record — the relay zone read gate), [ADR-090 Path Discipline at the FORUM_BASE Boundary](ADR-090-forum-base-path-discipline.md), [ADR-092 Deep-link Self-Bootstrap](ADR-092-deeplink-self-bootstrap.md), [ADR-106 Gap-Close Forum Governance Surfaces](ADR-106-gap-close-forum-governance-surfaces.md), [`docs/architecture.md` § Zone Enforcement](../architecture.md), Soak-test follow-on ([overlay `docs/sprint/soak-test-2026-07-16.md`](../../../docs/sprint/soak-test-2026-07-16.md))

## Context

The forum's zone org model (a public landing zone plus locked cohort zones,
authored by the operator overlay's `[[zones]]` config and projected into
`window.__ENV__.ZONE_CONFIG`) assumes a member browses a shelf of zones and
chooses one. That assumption holds for a multi-zone operator. It does not hold
for the common case a single-zone community: an operator who runs one gated zone
(a cohort, a cohort's private space) for which every non-admin member is
authorised for exactly that one zone. For those members the `/forums` index is
a one-tile landing page — a shelf with a single item — that adds a click and a
concept ("zones") the community does not otherwise use. The soak-test pass and a
direct operator request both surfaced the same friction: single-zone members
land on a generic index that reads as scaffolding, then have to identify and
open the only tile they can enter.

The relay is and stays the security boundary (ADR-022): the client's rendering
must never gate access, only follow it. Any landing behaviour must therefore be
derived from the same access facts the relay already returns (the member's
cohorts and admin flag), be driven by the operator's `ZONE_CONFIG` rather than
hardcoded zone ids, and must not disturb the multi-zone or admin experience,
deep links, or the auth-gated `returnTo` flow (ADR-090). This ADR records how the
forum client resolves and follows a member's "home zone" without moving any
enforcement client-side.

## Decision 1 — Derive the home zone client-side from `ZONE_CONFIG × cohorts`, never from a hardcoded id

The "home zone" is a pure function of the operator's zone list and the member's
access facts. `home_zone_for(zones, cohorts, is_admin)`
(`stores/zone_access.rs`) returns the single **locked** zone the member is
authorised for, or `None`. A zone qualifies only when it has non-empty
`required_cohorts` (an open/public landing zone with empty `required_cohorts` is
never a home zone) **and** the member's cohorts satisfy `Zone::is_member`
(`stores/zones.rs`) — the same membership predicate the tile renderer and the
relay read gate use. The reactive wrapper `ZoneAccess::home_zone` reads
`loaded`, `is_admin` and `cohorts` unconditionally so every consumer re-runs when
any of them change, and returns `None` until the whitelist/access fetch has
completed so nothing forwards prematurely.

The derivation is deliberately total and config-driven: it names no zone id, so a
one-zone operator, a four-zone operator, and a renamed-zone operator all get
correct behaviour from the same code. When `ZONE_CONFIG` is absent the client
falls back to the legacy zone list (`load_zones`), so the feature is simply
dormant — never wrong — under a config that does not describe locked cohorts the
member holds.

| Alternative | Verdict | Rationale |
|---|---|---|
| Operator-configured per-user (or per-cohort) default zone id in `dreamlab.toml` | Rejected | Introduces a second source of truth about "where a member belongs" that can drift from the access facts the relay already returns, and forces the operator to hand-maintain a mapping the cohort list already implies. The home zone is *derivable*; deriving it keeps it consistent with the access gate by construction. |
| Hardcode a landing zone id (for example `members`) in the client | Rejected | Couples the client to one operator's zone naming, breaks every other operator, and reintroduces the exact legacy-flag coupling (`home`/`members`/`private`) the config-driven tile work removed. |
| Derive from `ZONE_CONFIG × cohorts` via `Zone::is_member` | **Accepted** | One source of truth (the member's cohorts), no operator-maintained mapping, correct for 0/1/N zones and any zone naming, and dormant-not-wrong when the config does not apply. |

## Decision 2 — The `/forums` index auto-forwards with replace navigation, exactly-one-zone only

When `home_zone()` resolves to a zone, the `/forums` index page forwards to that
zone's root (`/forums/{zone.id}`) with `NavigateOptions { replace: true, .. }`
(`pages/forums.rs`). The forward runs in an `Effect`, so it fires only once the
access fetch has completed (`home_zone` gates on `loaded`) and never on an admin
or multi-zone member (both resolve to `None`). `replace: true` means the bare
index is not pushed onto history, so the browser "back" button skips it: a member
who forwarded to their zone and presses back does not bounce through the index
they never chose to visit.

Forwarding only on **exactly one** accessible locked zone is the load-bearing
constraint. A member with two or more accessible locked zones is a genuine
multi-zone member with no single landing target, and keeps the index unchanged.

| Alternative | Verdict | Rationale |
|---|---|---|
| Server-side redirect (relay or a Worker rewrites `/forums` → `/forums/{zone}`) | Rejected | The home zone depends on the *authenticated member's* cohorts; a static-hosting / edge redirect has no session and cannot compute it without duplicating the access lookup at the edge. The forum is a client-rendered SPA whose access facts already live client-side after the whitelist fetch — deriving and forwarding there needs no new server round-trip and no new trust surface. |
| A new dedicated landing route (for example `/home` that renders the resolved zone) | Rejected | Adds a route, a component, and a second place breadcrumbs and nav anchors must special-case, for no gain over reusing the existing zone page. The zone root (`/forums/{id}`) already renders exactly the zone-scoped view a single-zone member wants. |
| `push` navigation instead of `replace` | Rejected | Leaves the bare index on the history stack, so "back" from the zone returns to the one-tile shelf the member never chose — the friction the feature exists to remove. |
| Auto-forward on the first accessible zone even when several exist | Rejected | Silently hides the other zones a multi-zone member is entitled to; the index is the correct surface when there is a real choice to make. |

## Decision 3 — Navigation anchors and breadcrumbs re-root on the home zone, index otherwise

The header nav anchor (desktop, `app.rs`), the mobile bottom-nav "Forums" tab
(`components/mobile_bottom_nav.rs`), and the zone-page breadcrumb
(`pages/category.rs`, `pages/section.rs`) all branch on `home_zone()`:

- **Nav anchor.** When `home_zone()` is `Some(zone)`, the "Forums" item's label
  becomes the zone's display name (`zone.label()`) and its `href` points at the
  zone root (`/forums/{zone.id}`). For admins and multi-zone members it stays the
  generic "Forums" → `/forums`. Both the desktop and mobile anchors bind to the
  same reactive `home_zone()`, so they never disagree.
- **Breadcrumb.** On a zone-scoped page a single-zone member sees
  `Home › {Zone}` (the zone as the current, non-linked crumb, `Home` linking to
  `/`), with **no** intermediate global "Forums" crumb — a crumb that would link
  back to an index the member is auto-forwarded away from anyway. Admins and
  multi-zone members keep the full `Home › Forums › {Zone}` trail. The generic
  `/forums` index keeps `Home › Forums` for everyone.
- **Hero.** No new work: each zone's page hero is already branded from the zone's
  configured `banner_image_url` (`pages/category.rs`, `pages/section.rs`,
  `components/zone_hero.rs`), so landing directly on the zone lands on a
  zone-branded surface rather than the generic index hero.

Alternative considered: keep the anchors and breadcrumbs pointing at `/forums`
and rely solely on the auto-forward. Rejected. A member who clicks "Forums"
would visibly bounce (index → forward → zone) on every click, and the breadcrumb
would advertise a "Forums" step that immediately redirects — a confusing
round-trip. Re-rooting the anchors on the resolved zone makes the single-zone
member's whole navigation vocabulary their zone, with no bounce.

## Behaviour matrix

The behaviour is fully determined by two facts: whether the member is an admin,
and how many accessible **locked** zones (`required_cohorts` non-empty and
`Zone::is_member(cohorts)` true) their cohorts resolve to. `home_zone()` returns
`None` in every row except the single non-admin one-zone case.

| Accessible locked zones | Admin? | `home_zone()` | `/forums` index | Nav anchor | Breadcrumb on a zone page |
|---|---|---|---|---|---|
| 0 | No | `None` | Renders (index/empty-state) | "Forums" → `/forums` | `Home › Forums › {Zone}` |
| 1 | No | `Some(zone)` | **Auto-forwards** to `/forums/{zone.id}` (replace) | `{Zone}` → `/forums/{zone.id}` | `Home › {Zone}` |
| N ≥ 2 | No | `None` | Renders (all tiles) | "Forums" → `/forums` | `Home › Forums › {Zone}` |
| 0 / 1 / N | **Yes** | `None` (admin early-return) | Renders (all tiles, all openable) | "Forums" → `/forums` | `Home › Forums › {Zone}` |

The admin early-return in `home_zone_for` guarantees the whole bottom row
regardless of `ZONE_CONFIG` or how many zones an admin's cohorts would otherwise
match: admins see every zone, so they have no single home and are never
forwarded, re-labelled, or re-rooted.

## What this ADR does not decide

- **Access enforcement.** The relay remains the security boundary (ADR-022). The
  home-zone derivation reads the member's cohorts to decide *where to land*, never
  *what to permit*; a member forwarded to a zone still passes the relay's read
  gate to see anything in it.
- **The zone model itself.** Zone authoring, `required_cohorts`, visibility and
  encryption stay owned by the operator's `[[zones]]` config (projected into
  `ZONE_CONFIG`) and `docs/architecture.md` § Zone Enforcement. This ADR consumes
  that model; it does not change it.
- **Multi-zone default selection.** For a genuine multi-zone member the index is
  the answer; picking a "preferred" zone among several is explicitly out of scope
  (and Decision 1 rejects an operator-configured default).

## Consequences

Positive. A single-zone community's members never see the generic index: they
land on, navigate within, and breadcrumb inside their own zone, on a
zone-branded hero, with no "zones" concept surfaced. The behaviour is derived
from the access facts already fetched, so it needs no new server round-trip, no
operator-maintained mapping, and no hardcoded zone id — a renamed or re-cohorted
zone is picked up automatically from `ZONE_CONFIG`.

Neutral / unchanged. Multi-zone members and admins see exactly the prior index,
anchors, and breadcrumbs (`home_zone()` is `None` for them by construction). Deep
links are unaffected: a direct link to any `/forums/{zone}`, section or thread
resolves as before, and the auth-gated `returnTo` flow (ADR-090) still preserves
the intended target verbatim through login — the auto-forward only rewrites the
bare `/forums` index, not a deep target. Under a `ZONE_CONFIG` that does not
describe a locked zone the member holds (or no `ZONE_CONFIG` at all — the legacy
fallback), `home_zone()` is `None` and the feature is dormant, so navigation
never regresses.

Tradeoffs. The landing target is now computed client-side after the whitelist
fetch, so a single-zone member briefly sees the index before the `Effect`
forwards (bounded by the access fetch, then replaced out of history). Three
surfaces (nav anchor, mobile tab, breadcrumb) now branch on `home_zone()` rather
than rendering a constant "Forums" label; they are all bound to the one reactive
source so they cannot drift, but the label/href is no longer a compile-time
constant.

## Verification

Implemented in `nostr-bbs-forum-client` and exercised by a browser smoke pass on
2026-07-16 (recorded in the operator overlay's
`docs/sprint/soak-test-2026-07-16.md`): compile clean
(`cargo check --target wasm32-unknown-unknown -p nostr-bbs-forum-client
--features dev-auth`, warnings only); single-zone landing auto-forwards to the
zone root with the history entry replaced; the nav anchor and breadcrumb re-root
on the zone; and the admin path shows no forward and the full index — validated
against a reproduced production-intent `ZONE_CONFIG`, since the live dev server
injects an empty `window.__ENV__` and therefore leaves the feature dormant under
its legacy fallback zones.
