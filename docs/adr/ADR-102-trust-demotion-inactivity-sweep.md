# ADR-102 — Trust demotion via a time-driven inactivity-decay sweep

- **Status:** Accepted (retrospective — recorded 2026-07-03). The decision was
  **implemented before this record was written**: commit `1e49c3e` (EOSE read
  tallying, promotion path) and commit `42b1ded` (cron demotion sweep). This ADR
  backfills the register so the number reserved for it in `docs/adr/README.md`
  maps to a real, code-referenced decision rather than an "incoming" placeholder.
- **Date:** 2026-07-03 (documents work landed ~2026-06-11)
- **Owners:** `nostr-bbs-relay-worker` (`src/trust.rs`, `src/cron.rs`, `src/lib.rs`).
- **Related:** anomaly register O1 / R10
  ([`docs/diagrams/00-anomaly-register.md`](../diagrams/00-anomaly-register.md));
  ADR-104 (relay admission, unchanged by this decision).

---

## 1. Context

The relay runs a four-level trust model (`trust.rs`):

- **TL0 Newcomer** — default on whitelist entry.
- **TL1 Member** — 3+ days active, 10+ posts read, 1+ post created.
- **TL2 Regular** — 14+ days, 50+ reads, 10+ posts, 0 mod actions.
- **TL3 Trusted** — admin-granted only; never auto-computed.

Promotion is activity-driven and was already modelled by the pure
`compute_trust_level`. Two gaps (anomaly O1) made the model inert at runtime:

1. **`increment_posts_read` was never called** — the `posts_read` counter that
   gates the TL0→TL1 transition never advanced, so a reader could not be promoted.
2. **`check_demotion` was unwired** — there was no trigger that applied demotion,
   so a user who went inactive kept a trust level their activity no longer earned.

Demotion has an awkward property: its precondition is **absence of activity**
(the design demotes only after ~6 months of inactivity, with 90% hysteresis).
A request handler is therefore the wrong trigger — it fires precisely for the
**active** users demotion must not touch.

## 2. Decision

### 2.1 Promotion is request-driven, batched at EOSE

Reads are tallied **after** the per-event zone/cohort/calendar read gate, batched
per REQ, and written once via `trust::increment_posts_read_by(pubkey, delivered, env)`
(`relay_do/nip_handlers.rs`), then `check_promotion` runs at end-of-stored-events.
Batching keeps a subscription that delivers N events to one D1 write, not N.

### 2.2 Demotion is time-driven only, applied by a paged cron sweep

`check_demotion` is called **exclusively** from
`cron::sweep_inactive_demotions`, invoked from the Worker `#[event(scheduled)]`
handler (`lib.rs`). Firing it from a request path is explicitly rejected: the
precondition is a ~6-month inactivity gate, so a request-driven caller would
target active users, the opposite of the intent. The sweep:

- selects only whitelist rows in `[TL1, TL2]` past the inactivity cutoff
  (TL0 is the floor, TL3 is never auto-demoted), paged and bounded so a large
  table cannot blow the CPU budget;
- computes the inactivity cutoff once, in Rust, and binds it as a parameter (the
  SQL carries no clock or arithmetic);
- applies 90% hysteresis (`demotion_hysteresis_pct`) so a user hovering at a
  threshold does not flap between levels;
- **exempts admins** (`is_admin = 1`) and TL3 unconditionally — the guard lives
  in `check_demotion` itself so it holds for every call path;
- logs each level change to `admin_log` with reason `auto-demotion (hysteresis)`;
- never propagates errors into the keep-warm tick (a sweep failure is logged only).

## 3. Consequences

- **Positive.** The trust model is now reachable in both directions: reads earn
  promotion, sustained inactivity earns demotion. O1 is closed (R10 in the
  anomaly register). Thresholds stay operator-configurable via the `settings`
  table; defaults match PRD v7.0.
- **Positive.** Demotion is decoupled from the request path, so it adds zero
  latency to reads/writes and cannot be triggered against active users.
- **Negative / accepted.** Demotion is only as timely as the scheduled tick, and
  the sweep is best-effort (per-row failures are indistinguishable from
  "did not need demoting" through the `Option` return, so the reported `demoted`
  count reflects actual decreases only). Acceptable for a slow, 6-month-horizon
  decay process.

## 4. References

- `crates/nostr-bbs-relay-worker/src/trust.rs` — `check_promotion`,
  `check_demotion` (hysteresis + admin/TL3 exemption), `increment_posts_read_by`.
- `crates/nostr-bbs-relay-worker/src/cron.rs` — `sweep_inactive_demotions`
  (paged, parameterised inactivity cutoff).
- `crates/nostr-bbs-relay-worker/src/lib.rs` — `#[event(scheduled)]` invoking the
  sweep on the keep-warm tick.
- `docs/diagrams/00-anomaly-register.md` — R10 / O1 (both marked RESOLVED).
- Commits `1e49c3e` (EOSE read tallying), `42b1ded` (cron demotion sweep).
