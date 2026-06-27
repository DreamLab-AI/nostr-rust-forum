# Agentic QE Fleet Audit — nostr-rust-forum

**Date:** 2026-06-27
**Scope:** Full workspace — 12 crates, ~91k LOC Rust + WASM (Cloudflare Workers + Leptos CSR client)
**Tooling:** `agentic-qe` v3.11.2 (`aqe init --auto`) — 13 audit lenses, 50 agents, ~2.29M analysis tokens, 597 tool-uses, adversarial verification of every High/Medium finding
**Grounded in:** downstream consumer audit [`DreamLab-AI/dreamlab-ai-website` PR #38](https://github.com/DreamLab-AI/dreamlab-ai-website/pull/38) and its `upstream-security-report-2026-06.md`
**Machine-readable findings:** [`2026-06-27-aqe-findings.json`](./2026-06-27-aqe-findings.json)

---

## 1. Executive summary

The cryptographic and authorization **foundations of this kit are strong** — Schnorr/event-id verification, NIP-44/04 delegation to audited `rust-nostr`, NIP-98 with D1-backed replay protection, WebAuthn ceremony hardening, deny-by-default WAC on the pod, path-traversal defense, and client-side markdown sanitization were all independently verified as correctly implemented (see §6). The audit **confirmed 31 findings** (after adversarially refuting 6 plausible-but-wrong ones), reducing to **5 distinct High-severity root issues**. The recurring theme is **not weak primitives but inconsistent application of an otherwise-correct read-authorization model on secondary code paths** the careful `REQ` path does not share.

### Headline risk — a single XSS becomes full account takeover

Two findings chain into the most serious risk in the repo:

- **H5** — the Leptos client persists the **raw 32-byte Schnorr master private key as hex in `localStorage` by default** (remember-me defaults *on*) for local-key / imported-nsec users.
- **H3** — the pod worker serves **attacker-controlled stored content as `text/html`** (content-type confusion), giving reachable same-origin stored XSS, with **no `nosniff`/CSP** anywhere.

Independently these are High. Together, any stored-XSS on a shared pod/app origin escalates from session-scoped compromise to **durable exfiltration of the user's master signing key** — the one secret the entire `did:nostr` identity model assumes never leaves the device.

### Severity tally (post-verification, de-duplicated to root issues)

| Severity | Distinct root issues | Primary locations |
|---|---|---|
| **High** | 5 | relay COUNT, relay broadcast, pod stored-XSS, auth-worker WoT, client localStorage key |
| **Medium** | ~9 | pod inbox-quota DoS, relay filter-DoS, pod `nosniff`, preview SSRF wiring, CI gating |
| **Low** | ~14 | CORS hygiene, config validation, SSRF IPv6 edge forms, supply-chain hygiene, test gaps |

### Reconciliation with the downstream PR #38 upstream report

| Downstream upstream item | Status against current code | Where |
|---|---|---|
| Relay zone-gating read bypass (A1–A3) | **REQ path MITIGATED**; the real bypass is on **COUNT** and **live broadcast** | §5 H1, H2 |
| COUNT auth not validated | **CONFIRMED — present & reachable** | §5 H1 |
| Web of Trust dead code | **CONFIRMED — worse than "unused": a silently-bypassed trust gate** | §5 H4 |
| Pod stored-XSS + CORS | **Stored-XSS CONFIRMED; `nosniff` missing CONFIRMED; credentialed-wildcard CORS REFINED to hygiene-only** | §5 H3, §7 |
| Container listing enumeration | **MITIGATED — gated by deny-by-default WAC Read** | §6 |
| NIP-05 enumeration | **By design (public lookup); a clean existence oracle, rate-limited fail-open** | §8 (Low) |
| Quota-to-owner mapping | **Key binding CORRECT; but a distinct inbox quota-exhaustion DoS exists** | §5 M, §6 |
| Proposed patch (nosniff + drop credentialed wildcard CORS) | **`nosniff` genuinely needed; credentialed-wildcard is spec-violating hygiene, not a browser-exploitable leak** | §5, §7 |
| "Event spoofing via hostile relay" | **N/A here** — that was the *website's* relay client; this repo's relay calls `verify_event_strict` on every inbound EVENT (`nip_handlers.rs:164`) | §6 |

---

## 2. Methodology

`aqe init --auto` provisioned the AQE v3 fleet (87 skills, 53 specialized QE agents, code-intelligence index of 255 files, governance plane). The audit then ran a 13-lens multi-agent workflow:

- **4 downstream-verification lenses** — one per PR #38 upstream item, tasked to confirm/refute against *current* code.
- **9 discovery lenses** — crypto-core, relay-deep, pod-deep, auth-worker, preview-SSRF, client-XSS/secrets, supply-chain/robustness, config/search/quality, test-coverage.
- **Adversarial verification** — every High/Medium finding was handed to an independent skeptic agent instructed to *refute* it by re-reading the cited code. This filtered **6 false positives** (§7) and corrected several severities downward.

Every confirmed finding below carries a file:line citation and quoted evidence the agents actually read. This is a static/source audit; no dynamic exploitation was performed, and findings note where exploitability depends on deployment topology (shared vs. per-user origin) or runtime behavior (CF Workers egress routing).

---

## 3. The critical chain (read first)

```
  [H5] master privkey in localStorage (default on)        [H3] pod serves stored bytes as text/html
        crates/.../auth/session.rs:117-148                       content_negotiation.rs:84-86
                    │                                                     │
                    └──────────────► same-origin script ◄────────────────┘
                                   (any stored XSS, malicious
                                    dependency, or extension)
                                            │
                                            ▼
                          exfiltrate "nostr_bbs_sk" → full account takeover
                                  (sign as victim forever; no breach DB to rotate)
```

**Fix priority:** default `remember_me` to **off** (sessionStorage) or encrypt the at-rest key (NIP-49 / WebCrypto non-extractable wrap) **and** stop serving stored pod content as active HTML **and** add `nosniff`. Any one link broken downgrades the chain; fixing all three is cheap and high-leverage.

---

## 4. Strong controls (verified, keep these)

The adversarial pass explicitly confirmed these as correctly implemented — documented so future refactors don't regress them:

- **Crypto core:** `verify_event_strict` recomputes the event id from canonical NIP-01 serialization and verifies BIP-340 Schnorr over the *recomputed* id (never trusts client id); panic-free on attacker input. NIP-44 v2 / NIP-04 fully delegated to audited `rust-nostr` (no kit-owned nonce/IV/MAC). NIP-98 binds token to exact URL + case-insensitive method + freshness + recomputed id + body hash, with atomic D1 replay store. `SecretKey` zeroizes on drop.
- **Pod authorization:** WAC is deny-by-default (no ACL ⇒ deny-all, well-tested ~44 tests); `.acl` writes coerced to require `acl:Control` (blocks Write→Control escalation); path traversal blocked at `parse_pod_route` and re-validated on Slug-derived child paths; container listing gated behind WAC Read; `remote_storage.rs` makes no outbound requests (no SSRF); git smart-HTTP routes are inert 501 stubs (no subprocess).
- **Auth worker:** WebAuthn enforces origin/RP-ID/crossOrigin-rejection/challenge-binding/UV-UP flags/counter, fail-closed on missing config; invite codes CSPRNG-generated with atomic, idempotent, self-redeem-blocked redemption; username validation ASCII-only `[a-z0-9_-]` (blocks homoglyph squatting), atomic via UNIQUE; device ops owner-scoped to NIP-98 author; admin endpoints uniformly `require_admin` with self-lockout protection; login-options enumeration oracle closed (identical response shape).
- **Client XSS:** all user-content `inner_html` sinks route through `utils/sanitize.rs` (comrak `unsafe_=false` + tagfilter), which also neutralizes `javascript:`/`data:`/`vbscript:` and entity-encoded schemes (empirically confirmed against the pinned comrak 0.38.0). DM plaintext rendered escaped, in-memory only.
- **Relay (REQ path):** zone filtering, deny-by-default calendar projection, kind-1059 `#p` injection, NIP-42 AUTH (CSPRNG challenge + per-session match), NIP-09 deletion authz, gift-wrap recipient gating, query LIMIT cap — all correctly implemented.
- **Robustness:** all 15 `unsafe` occurrences are sound (test-only Wakers, wasm32 `SendWrapper`, in-place zeroize, one English-word "unsafe" in a comment). Attacker-reachable panics in request paths are essentially zero after filtering `#[cfg(test)]`.

---

## 5. Confirmed findings

> Each finding lists the consolidating root issue, evidence location, recommended minimal-diff fix, and the adversarial verifier's verdict. Where multiple lenses surfaced the same root independently, that is noted as corroboration (raises confidence).

### HIGH

#### H1 — `COUNT` (NIP-45) bypasses all read authorization that `REQ` enforces
**`crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:976-984`** · dispatch `relay_do/mod.rs:242-254` · *corroborated by 4 lenses*

`handle_count` is dispatched **without `session_id`** and calls `query_events()` directly — pure filter→SQL with zero zone/cohort/auth/calendar gating. All read authorization lives only in `handle_req`'s post-query loop (kind-1059 auth gate + mandatory `#p` rewrite at 599-638; per-event zone filter at 696-763; calendar projection at 705-720). An **unauthenticated** client can therefore:
- `["COUNT","s",{"kinds":[1059],"#p":["<victim>"]}]` → learn how many sealed DMs a target has received;
- `["COUNT","s",{"kinds":[42],"#e":[<hidden_channel>]}]` → message counts for Locked/Hidden zones;
- count gated NIP-52 calendar/RSVP events the projector would Omit.

This is the downstream "COUNT auth" item, **confirmed present and reachable**. It leaks existence/cardinality (not content), which keeps it just under a content-disclosure rating, but it is a genuine unauthenticated authorization bypass.

**Fix:** thread `session_id` into `handle_count` (it is already in scope at `mod.rs:254`); refactor `handle_req`'s per-event gating into a shared `gated_events(session_id, filters)` helper and have COUNT tally only its survivors. Deny-by-default: an unauth COUNT touching a non-public zone or kind-1059 must count 0.

#### H2 — Live broadcast pushes zone-private content to unauthorized subscribers
**`crates/nostr-bbs-relay-worker/src/relay_do/broadcast.rs:41-66`**

`broadcast_event` applies a zone/recipient gate **only for kind-1059**; for every other event it sends to any session whose plain filter matches. So kind-42 Locked/Hidden channel content and calendar kinds (31922/31923/31925) are **pushed live** to subscribers who lack read access — bypassing the careful `handle_req` projection. The EVENT write path gates the *author* (`has_zone_write_access`) but not the *recipients*. The initial-query and live-push paths provably diverge, and the push path is the weaker one — this is the real read-path authorization bypass behind the downstream A1–A3 framing.

**Fix:** before `send_event` in `broadcast_event`, apply the same per-recipient decision `handle_req` uses (resolve channel zone + `has_zone_access`; run `project_calendar_for_viewer` per session). Share the gating so the two paths cannot drift.

#### H3 — Pod stored XSS via content-type confusion
**`crates/nostr-bbs-pod-worker/src/content_negotiation.rs:84-86`** + `lib.rs:645,881,946,1012-1019` · *corroborated by pod-deep + ds-pod-cors lenses*

PUT stores the client-supplied `Content-Type` verbatim into R2 metadata (`lib.rs:1015`). On GET, `negotiate()` returns `text/html` whenever the request carries `Accept: text/html` — **regardless of the stored type** (`content_negotiation.rs:84-86`, with a passing test `negotiate_html_returns_html` confirming it is intended behavior) — and that is set as the response `Content-Type` over the raw stored bytes (`lib.rs:946`) with **no escaping/sanitization and no `nosniff`/CSP**. `provision.rs:206-240` makes `public/` and `media/public/` world-readable, so an attacker who owns a pod can PUT malicious HTML into `public/` and any visitor (browsers send `Accept: text/html`) executes script on the pod web origin. On the common shared-origin deployment (`/pods/{pubkey}/`) this is **same-origin cross-user stored XSS** — and the entry point for the §3 key-exfiltration chain.

**Fix:** stop honoring `Accept: text/html` for stored resources — change the arm to `HTML if stored_content_type == HTML => ...` so a stored `.json/.txt/.svg` can never be relabeled; force a safe `Content-Type` (e.g. `application/octet-stream`) for stored user content; add `nosniff` (see M3).

#### H4 — Web-of-Trust registration gate is dead code → registration silently ungated when admins enable WoT
**`crates/nostr-bbs-auth-worker/src/webauthn.rs:827-1028`** (insert at `:1000`) · helpers `wot.rs:431`, `invites.rs:608` · *corroborated by 2 lenses*

The WoT admin CRUD API is wired and admin-gated, but the **enforcement** is not: `wot::is_allowed_by_wot` (documented "used from webauthn.rs when wot_enabled = 1") has **zero callers**; `register_verify` runs the WebAuthn ceremony then `INSERT INTO webauthn_credentials` with **no WoT/invite check**; the companion `invites::consume_for_registration` is also never called and the parsed `invite_code` field (`webauthn.rs:177`) is never read. Net: an admin can set `wot_enabled=1` and configure a referente follow-list **believing registration is gated, while any pubkey can still register**. This is a silently-bypassed security control, not merely unused code — strictly worse than the downstream "dead code" framing.

**Fix:** **wire it, do not delete** — between the duplicate-credential check (`:976`) and the INSERT (`:1000`), call `is_allowed_by_wot`; on deny, require and consume `invite_code` via `consume_for_registration`, else return 403. Add an integration test asserting a non-trusted pubkey gets 403 when `wot_enabled=1`. (Deleting would leave the admin UI advertising an inert control.)

#### H5 — Master private key persisted in `localStorage` by default
**`crates/nostr-bbs-forum-client/src/auth/session.rs:117-148`** (callers `auth/mod.rs:357-360,439`)

`remember_me()` defaults to **true** (`.unwrap_or(true)`); when true, `save_privkey_session` writes the raw 32-byte Schnorr secret as bare hex to `localStorage["nostr_bbs_sk"]` with no encryption — durably readable by any same-origin script and surviving tab close. Scoped to local-key / imported-nsec users (passkey users correctly never persist; they re-derive via PRF). The code itself flags this as a known "TRANSITIONAL PATH (audit C2/B8)", and a docstring at `mod.rs:351` even *falsely* claims "never persisted to storage" immediately before persisting it.

**Fix:** default `remember_me` to **off** (sessionStorage scope) with an explicit "keep me signed in" opt-in and a clear warning; **or** encrypt at rest (NIP-49 `ncryptsec` / WebCrypto non-extractable wrap). Minimal diff: flip `.unwrap_or(true)` → `false`. This caps the blast radius of any future XSS at session scope instead of full account takeover.

### MEDIUM (selected — full list in the JSON)

- **M1 — Inbox quota-exhaustion DoS chargeable to the victim owner.** `crates/nostr-bbs-pod-worker/src/provision.rs:273-299` grants `acl:AuthenticatedAgent` `acl:Append` on `/inbox/`; a POST there is charged to the **route owner** (`lib.rs:1107`, single 50 MB owner-keyed quota, no inbox sub-quota or per-writer cap). Any authenticated third party can fill the owner's quota and block the owner's own writes (availability-only, reversible via DELETE). By-design Solid inbox semantics colliding with owner-keyed quota. *Fix:* separate inbox sub-quota keyed to the writer, or per-source rate-limit/byte-cap on inbox Append.
- **M2 — `max_filters` advertised (10) but unenforced → REQ/COUNT fan-out amplification DoS.** `relay_do/mod.rs:221-254` collects filters with no cap; `query_events` runs one D1 round-trip per filter; REQ/COUNT are **not rate-limited** (the 10/s limit is only on `handle_event`). One unauthenticated COUNT frame with many tiny filters is an N-query amplifier. *Fix:* hard `MAX_FILTERS` cap in both arms before dispatch.
- **M3 — No `X-Content-Type-Options: nosniff` on any pod response.** Repo-wide zero matches; `cors_headers()` and all builders omit it. Defense-in-depth for H3; the exact downstream-proposed patch. *Fix:* one line in the shared header builder (`cors_headers()` / `add_ldp_headers`).
- **M4 — WebID `/profile/card` served as `text/html` without sanitization.** `lib.rs:858` + `validate_webid_html` (`:1518`) only checks for a parseable JSON-LD block; arbitrary `<script>` outside it passes and is served as HTML from a world-readable container (`provision.rs:301-309`). *Fix:* serve as `application/ld+json` (extract the JSON-LD) or sanitize with an allowlist; add `nosniff`.
- **M5 — Preview-worker egress allowlist (the documented "authoritative" DNS-rebinding mitigation) is never wired.** `crates/nostr-bbs-preview-worker/src/ssrf.rs:132-151`: `set_allowlist()` has **zero callers** and the `std::env` fallback is inert under CF Workers WASM (vars arrive via the JS `Env`), so production runs in **denylist-only, rebind-vulnerable** mode by construction. *Fix:* in `lib.rs fetch()`, read `env.var("PREVIEW_ALLOWED_HOSTS")` and call `set_allowlist(...)` once per request.
- **M6 — SSRF IPv6 denylist misses NAT64 / IPv4-compatible / 6to4 / site-local embeddings.** `ssrf.rs:320-345` matches by textual prefix only; `http://[64:ff9b::7f00:1]/`, `http://[::a9fe:a9fe]/`, `http://[2002:7f00:1::]/`, `http://[fec0::1]/` all return *not blocked*. *Fix:* parse with `std::net::Ipv6Addr`, block loopback/unspecified/ULA/link-local, and extract embedded IPv4 from NAT64/6to4/IPv4-compat forms for `is_private_ipv4`.
- **M7 — DNS-rebinding residual in denylist-only mode** (`ssrf.rs:7-25`): honestly documented TOCTOU limit of the CF runtime; resolved only once M5 is wired and operators set `PREVIEW_ALLOWED_HOSTS`.
- **M8 — CI `test` job is `continue-on-error` → security tests do not gate merges.** `.github/workflows/ci.yml:92,201-211`: the required `ci-pass` aggregator gates only `fmt` and `wasm`; `test`/`clippy`/`doc`/`deny` are advisory. The SSRF/WAC/gift-wrap/moderation unit tests are effectively decorative for merge protection. *Fix:* make `test` (at least for `nostr-bbs-core`/`relay-worker`/`pod-worker`) a required result.
- **M9 — `cargo-deny` never gates merges** (`ci.yml:162-211`, `continue-on-error: true`): license/advisory/ban/source policy cannot block a PR. *Fix:* move `deny` into the hard-gate loop or drop `continue-on-error`.
- **Coverage mediums (tie-ins to the above code issues):** COUNT path has zero tests; the REQ zone projector / async `has_zone_access` have no integration test (only leaf predicates); no test forbids wildcard-Origin+credentials; no test enforces `nosniff`. Fixing these alongside H1/H3 prevents silent regression.

### Search worker — refined, not refuted (information-disclosure, Low–Medium)

The discovery lens framed the unauthenticated `/search` + `/embed` endpoints (`crates/nostr-bbs-search-worker`) as a HIGH content bypass; **adversarial verification correctly downgraded this** (see §7): `handle_search` returns only `{id, distance, score}` — never content, author, or zone — and bodies are re-hydrated through the **relay**, which enforces zone gating, so withheld content stays withheld. The genuine residual is a **metadata/semantic-inference oracle**: an anonymous caller can submit a query embedding and learn the **event-IDs and similarity scores of indexed-but-restricted posts** (and that "a message semantically near X exists"). Event-IDs are public, non-secret hashes, so this is a real but **Low-to-Medium info-disclosure**, not a read-path authorization bypass. *Fix (defense-in-depth):* NIP-98-gate `/search`, or store/enforce zone metadata in the index and filter results, or stop indexing restricted-zone content.

---

## 6. Notable Low findings (full list in the JSON)

| ID | Crate | Category | Issue |
|---|---|---|---|
| L-nip98 | core | crypto | Stateless `verify_nip98`/`verify_token` entry points have **no replay protection** and the docs don't warn callers (the stateful, D1-backed path does) |
| L-kind | core | quality | `u64→u16` kind truncation in `to_upstream_builder` diverges from the kit's u64 canonical id serializer for kinds >65535 (interop/signing, not a verify bypass) |
| L-did | pod | auth | Delegation shortcut accepts any `did:nostr`-prefixed agent without validating the 64-hex body |
| L-nip05a | pod | enumeration | NIP-05 `/.well-known/nostr.json` is a designed public lookup but a clean existence oracle; rate limiter **fails open** on KV degradation |
| L-quota2 | pod | quota | Provisioning still seeds quota via deprecated non-atomic **KV** path while writes use D1 (split-brain usage counter) |
| L-cors | pod | cors | NIP-05 forces `Allow-Origin:*` with inherited `Allow-Credentials:true` — spec-violating hygiene (browsers reject the combo; not exploitable) — drop credentials when origin is `*` |
| L-mesh | mesh / config | auth | `mesh.peer_relays` URLs never validated (no `wss://` enforcement, unlike `relay.url`); transport is scaffold-only and doesn't assert peer auth before federated broadcast |
| L-zoneid | config | config | `validate_config` doesn't enforce zone `id` uniqueness; `ZoneConfig::get` first-match means a duplicate id with weaker cohorts can silently shadow the intended one |
| L-admincase | auth | auth | Admin authz compares NIP-98 pubkey without case normalization (robustness) |
| L-cohort | auth | auth | Username claim auto-grants relay-whitelist `members` cohort via cross-D1 write (deliberate but privilege-granting) |
| L-rng | relay | dos | `getrandom().expect()` on the unauthenticated WS-connect (NIP-42 challenge) path |
| L-linkprev | client | xss | Link-preview `href` uses worker-supplied `data.url` without scheme validation |
| L-advisory | repo | supply-chain | `audit.yml` ignores 2 advisories (RUSTSEC-2026-0097/0173) absent from `deny.toml` and undocumented; no ignore carries an expiry/review date |
| L-tests | relay | coverage | `whitelist_tests.rs` re-implements access logic locally (false-confidence); NIP-42 AUTH handler has no challenge-mismatch/replay/stale test |

---

## 7. Refuted / corrected by adversarial verification (rigor record)

Six plausible findings were **refuted or materially downgraded** after a skeptic agent re-read the code — documented so they are not "re-discovered" later:

1. **Credentialed wildcard CORS = exploitable** → **Refuted.** Browsers reject `Allow-Origin: *` + `Allow-Credentials: true` for credentialed requests, so this *breaks* credentialed CORS rather than opening it; and the origin is never reflected from the request `Origin` (only `EXPECTED_ORIGIN` env or literal `*`). Remains a header-hygiene fix (L-cors), not a credential-theft vector.
2. **Moderation auto-hide Sybil censorship (3 reports from any pubkey)** → **Refuted.** kind-1984 reports are TL1+ trust-gated *before* insertion (`nip_handlers.rs:299-308`); sub-TL1 pubkeys never reach `insert_report`. Residual: COUNT(*) vs COUNT(DISTINCT reporter) lets one TL1+ account self-trip a *reversible* soft-hide — a low-sev defense-in-depth nit.
3–5. **Search worker "restricted-zone content discoverable" (3 findings)** → **Refuted as HIGH, refined to Low/Med info-disclosure.** Search returns only IDs/scores; content is gated at relay hydration (`global_search.rs:621`: "zone-withheld events are simply absent"). The `encrypted` zone flag is an inert UX hint (posts are published plaintext to the relay regardless), so the "embedding defeats encryption" premise is false. See §5.
6. **Quota owner-isolation "wholly untested"** → **Refuted.** `parse_pod_route` extracts a fixed 64-hex owner segment and *has* the recommended tests (`parse_pod_route_rejects_traversal` at `lib.rs:1782`, plus `is_safe_resource_path_*`). Only `quota.rs`'s SQL predicate is uncovered (untestable in WASM without a live D1).

---

## 8. Prioritized remediation roadmap

**P0 — break the account-takeover chain (small diffs, high leverage):**
1. H5 — default `remember_me` off / encrypt at-rest key (`session.rs`).
2. H3 + M3 — stop serving stored content as `text/html`; add `nosniff` (`content_negotiation.rs`, shared header builder).

**P1 — close the read-authorization bypasses:**
3. H1 — share `handle_req` gating into a `gated_events` helper; route COUNT through it (`nip_handlers.rs`).
4. H2 — apply per-recipient gating in `broadcast_event` (`broadcast.rs`).
5. H4 — wire `is_allowed_by_wot` + invite bypass into `register_verify` (`webauthn.rs`).

**P2 — DoS & SSRF hardening:**
6. M2 — `MAX_FILTERS` cap; M1 — inbox sub-quota / rate-limit; M5/M6/M7 — wire `set_allowlist`, parse IPv6 properly.

**P3 — make the safety nets real (process):**
7. M8/M9 — promote `test` and `deny` to required CI gates so every fix above is regression-protected; add the missing security unit/integration tests (COUNT gating, REQ projector, CORS combination, `nosniff`, NIP-42 AUTH).

**P4 — hygiene:** the Low table (CORS, config validation, advisory-list drift, DID-shape, fail-open rate limiter, mesh URL validation, doc corrections).

---

## 9. Appendix — per-lens summaries & raw data

Full per-lens narratives, every confirmed finding with verifier rationale, and the refuted set are in **[`2026-06-27-aqe-findings.json`](./2026-06-27-aqe-findings.json)** (31 confirmed · 6 refuted · 68 low/info · 13 lenses · 50 agents).

*Generated by the Agentic QE v3 fleet (`agentic-qe` 3.11.2), grounded in DreamLab-AI/dreamlab-ai-website PR #38. Static source audit; severities reflect post-verification consensus and note deployment/runtime-dependent exploitability.*
