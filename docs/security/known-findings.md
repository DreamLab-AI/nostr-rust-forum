# Known security findings — open, owned, untriaged-by-default is not allowed

Findings raised by `deepsec-gate --diff` that are **pre-existing** and were not
fixed by the branch that surfaced them. A finding reaches this table only with an
owner and a disposition; "we saw it and moved on" is not a disposition.

The gate scans the *blast radius* of a change, not only its lines, so a branch
routinely surfaces defects it did not introduce. Fixing all of them inside a
feature branch is how a feature branch becomes unreviewable. Recording them here
with an owner is the alternative — the point is that the finding survives the
branch that found it.

**This table is not a suppression list.** Nothing here is waived, and no entry
makes a gate green. `docs/security/advisory-exceptions.md` is the separate,
narrower thing: accepted risk in third-party dependencies.

Surfaced by `feat/augmentation-conditions` (ADR-2011), runs
`.deepsec-gate/reports/20260914T1[45]*`.

| # | Severity | Location | Finding | Why not fixed here | Owner |
|---|---|---|---|---|---|
| KF-1 | HIGH_BUG | `crates/nostr-bbs-relay-worker/src/cron.rs:417-420` | The NIP-40 expiry sweep matches on `CAST(value AS INTEGER) < ?1`. SQLite's `CAST` yields `0` for a non-numeric string, and `0 < now`, so an event whose `expiration` tag is malformed or negative is **silently deleted** on the next 5-minute tick — while the accept/serve path parses the same tag properly and treats it as "no expiration". The reap predicate and the serve predicate disagree, and the reap side wins. | Contained (a validity guard on the predicate) and worth doing, but it is data-loss in the retention sweep, not one of the two gate-blocking `HIGH`s this branch was asked to triage, and the branch already carries two unrequested relay fixes. Recommended as a standalone change: restrict the match to digit-only values before the `CAST`, with a test that a malformed tag survives a sweep. | relay maintainers |
| KF-2 | MEDIUM | `crates/nostr-bbs-auth-worker/src/governance_api.rs` — `handle_list_agents`, `handle_list_cases`, `handle_get_case`, `handle_list_decisions`, `handle_list_roles` | These read endpoints are gated by `require_admin`-adjacent `require_authed`, which verifies a NIP-98 signature but performs **no membership check**; the crate has no `require_member`. Anyone can mint a keypair and sign a valid token, so "authenticated" is effectively "anonymous" for the agent registry, broker cases, decision reasoning and the role map. | A product decision, not a bug fix: whether forum governance data is member-only or public is the operator's call, and `require_member` does not exist yet. **Note:** ADR-2011 slightly widens what this gate exposes, adding `effective_tier`, `declared_tier` and the task-property triple to the case projection — low-sensitivity fields, but a real widening. | auth-worker maintainers / operator |
| KF-2a | MEDIUM | `crates/nostr-bbs-auth-worker/src/governance_api.rs` — `handle_list_decisions` vs `handle_list_reviewers` | A sharper form of KF-2, and partly caused by this branch: `GET /api/governance/reviewers` is correctly `require_admin`, but the raw material it aggregates — per-decision `broker_pubkey`, `outcome` and `reasoning` — is readable from `GET /api/governance/decisions` under `require_authed`. Anyone with a keypair can therefore reconstruct reviewer attribution and override rates and bypass the admin gate on the aggregate. | Adding an admin gate to a new endpoint does not retro-gate the older endpoint it derives from; closing it means changing the read posture of `/decisions`, which is the same operator decision as KF-2 and should be taken once, for both. | auth-worker maintainers / operator |
| KF-7 | MEDIUM | `crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:1515-1525` | NIP-42 `AUTH` runs Schnorr signature verification before any rate limiting, so an unauthenticated socket can force unbounded secp256k1 verifications and exhaust worker CPU. | Pre-existing, in the AUTH handshake, and the fix is a rate-limit placement decision on the WebSocket path — unrelated to this expectation and not contained within it. | relay maintainers |
| KF-3 | MEDIUM | `crates/nostr-bbs-relay-worker/src/lib.rs:160` calls `ensure_schema` (`:593`) | ~75 sequential D1 DDL statements run on **every** HTTP request, before the CORS short-circuit, the WebSocket upgrade branch and any authentication, with no rate limit on the HTTP surface. Unauthenticated D1 load and cost amplification. | Touching the schema bootstrap while this branch depends on it for migration 0006 is the wrong order of operations. The fix is a run-once latch per isolate, or moving DDL off the request path entirely. | relay maintainers |
| KF-4 | MEDIUM | `crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:795-845` | The write gate resolves a device key to its owner (`effective_pubkey`) for the whitelist check, but the moderation gates that follow key on the **raw signing pubkey**: `check_suspension`, `mod_cache.is_blocked`. A suspended or banned user can therefore keep writing through a registered device key. Gift-wrap (1059) senders escape the same gates. | ADR-099 device-key semantics; the fix is to resolve the effective principal once and feed it to every author-scoped gate. Out of this expectation's scope and it interacts with the device-key model. | relay maintainers |
| KF-5 | BUG | `crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs` — `plan_action_response` | `decision_id` is `dec-` plus a **16-hex (64-bit) truncation** of the event id. A projection key derived from a truncated identity invites collision between two distinct signed decisions. | Pre-existing and load-bearing: `broker_decisions.decision_id` is a primary key with rows already written under this scheme, so changing it is a migration, not an edit. | relay maintainers |
| KF-6 | MEDIUM | `crates/nostr-bbs-core/src/governance.rs` — `BrokerCase::record_decision`, `claim`, `supersede_authority` | The self-review and original-signer guards compare pubkeys with case-sensitive `String` equality. NIP-98 accepts case-insensitive hex and returns `event.pubkey` verbatim, so the same key can present in two casings and slip a separate-of-duties check. | This branch normalised casing in every path it added (agent registry, broker roles, case delegations). Normalising the core aggregate's identity comparisons is a wider change to published crate behaviour and wants its own review. | core maintainers |

## Probe blindness — a documented limitation, not an open finding

`deepsec` raised probe blindness four times across these runs. It is not listed
above because it is a **known, recorded design limitation** rather than an
untriaged defect: the `probe` tag is kept out of `event_tags` and out of every
D1/REST projection of an undecided case, but it remains on the raw signed 31402,
because stripping it invalidates the signature both clients verify strictly and
the probe would disappear rather than render blind. It is stated in
`nostr-bbs-core/src/governance.rs` on `TAG_PROBE`, in migration `0006`, in
ADR-2011 (`implementation_status: partial`, and its `review_trigger`), in the
CHANGELOG, and in the EXP-AC-006 evidence, which records that scenario as
PARTIAL. Closing it properly means keeping the digest off the signed event.
| KF-8 | BUG | `crates/nostr-bbs-core/src/governance.rs:32, :1174` | `KIND_PANEL_RETIRED` and `KIND_GOVERNANCE_AUDIT_LOG` are **both 31405**. `validate_governance_event` applies its append-only audit rules to the kind, so a legitimate `PanelRetired` is validated as an audit-log entry and the two semantics are entangled on one wire kind. | Assigning the audit log a distinct kind is a **protocol change** to a published crate: it changes what a deployed relay accepts and what both clients emit, and `GOVERNANCE_KIND_RANGE`, the client dispatch and the relay projection all move with it. That is an ADR, not a line edit, and doing it inside a feature branch would make the branch unreviewable. Recommended shape: give the audit log a **non-replaceable** kind, so append-only is enforced by the kind's own semantics rather than by a validator. | core maintainers |
| KF-9 | MEDIUM | `crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:804-875` | Sharper restatement of KF-4 for **gift-wrap**: for a kind-1059 the `event.pubkey` is a fresh ephemeral key that is never whitelisted and never moderated, so `check_suspension`, `mod_cache.is_blocked` and the trust lookup all pass vacuously. A suspended or banned user can keep sending gift-wrapped DMs. | Same root cause and same fix as KF-4 — resolve the effective principal once and feed every author-scoped gate — but gift-wrap is the case where there *is* no author to resolve on the envelope, so it needs a decision about what moderation means for an unlinkable sender. Wider than KF-4 and wants its own review. | relay maintainers |

### Re-raised by the merged-tree run `.deepsec-gate/reports/20260914T204117Z`

That run reported seven net-new findings against `20260914T194052Z`. Four were
fixed on the branch (client NIP-33 replaceability and the 31402 duplicate, the
probe-blinding trigger, and the agent-registration pubkey casing — see the
CHANGELOG). Of the remaining three, two are restatements of entries already in
this table and one is new:

- **`ensure_schema` runs ~50 DDL statements on every request, before auth** —
  already **KF-3**, unchanged. The branch adds statements to that path rather
  than fixing its shape, which is recorded there.
- **Gift-wrap escapes the moderation gates** — the specific case of **KF-4**,
  broken out as **KF-9** above because the fix is not the same one line.
- **31405 defined twice** — new, **KF-8** above.
