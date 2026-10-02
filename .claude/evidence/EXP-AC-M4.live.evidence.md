# EXP-AC M4 — live probe suite, 2026-10-02

PRD-augmentation-conditions M4: "probe suite run against the live edge forum
(relay, auth API) — receipt of each probe; deploy status recorded honestly".
Raw receipts are in `m4-2026-10-02/`; this file is the reading of them.

## Deploy status (what is on the edge)

| Fact | Evidence |
|---|---|
| Website pins forum kit `49904f48b7f4367ea23b92c0cd6078d4ac3b5cd2` | dreamlab-ai-website `6ae4576`, `.github/workflows/workers-deploy.yml` `KIT_REF` |
| That pin deployed | GitHub Actions "Deploy Cloudflare Workers" run `37003273172`, push of `6ae4576`, started 2026-10-02T11:50:58Z, conclusion `success` |
| The ADR-2011 tree is in the deployed kit | `git merge-base --is-ancestor 81aa0d9 49904f4` → true (81aa0d9 is ADR-2011's previous `verified_commit`) |
| Relay worker crate version | NIP-11 and `/health` report `1.0.0-beta.10` — the relay-worker crate's own version at `49904f4`, not a commit identifier |
| `nostr-bbs-core` / `nostr-bbs-mesh` published | crates.io: `1.0.0-beta.11` 2026-09-15T20:22Z / 20:23Z; `1.0.0-beta.12` 2026-10-01T12:26Z / 12:27Z; none yanked. Both versions' `governance.rs` export `TaskProperties`, `effective_tier` and `ReceiptStage` (checked in the downloaded `.crate`s) |
| Migration 0006 columns live | P06: `effective_tier`, `declared_tier`, `task_properties`, `max_pending_hours`, `probe` returned for a case projected today |

Endpoints: relay `wss://dreamlab-nostr-relay.solitary-paper-764d.workers.dev`,
auth API `https://dreamlab-auth-api.solitary-paper-764d.workers.dev`.

Read-only pre-probe (`readonly-probe.txt`, 2026-10-02T13:10:11Z): NIP-11
advertises `default_escalation_tier: medium`, `default_posture:
escalate_to_human`; every governance route answers 401 unsigned. An unsigned
request to an unknown `/api/...` path also answers 401, so unsigned reads
cannot tell a deployed route from an absent one — which is why the suite signs.

## The suite

`crates/nostr-bbs-governance-probe` (commit `1ba78ba`; `--get` added later the
same day). Signer: the registered agent JunkieJarvis,
`2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9`, key read
from `JUNKIEJARVIS_PRIVKEY_HEX` in the environment (never printed). No owner
key was used. Every published event is on the probe panel
`31400:2de44d56…16e9:adr-2011-m4-probe`, carries `t=adr-2011-m4-probe`, and
is titled `M4 PROBE · …`.

## Run 1 — `run-20261002t131900z` — NOT PASSED (kept as the honest record)

P02 was judged FAIL: the signed read of `GET /api/governance/reviewers`
returned **200 with reviewer telemetry**, and the verdict function assumed a
non-admin signer (expected 403). The signer is in fact an admin: on the relay through the D1
admin flag (it is not in the relay's static `ADMIN_PUBKEYS`), and on the auth
worker through its admin secret or the same D1 flag. The runner's guard therefore
refused to sign P08 (NOT RUN), by design. P01, P03–P07, P09 (case unchanged)
and P10 (withdrawal) passed. Probe case `m4-probe-20261002t131900z`, request
`0ec931ede3e196bfb4d93e7cb44c3e501d4516bebed5ebcd5f31d7763ca73107`.

The suite was then corrected so no verdict depends on the signer's role (P02:
unsigned 401 **and** signed 200-or-403; P08/P09 split so an admin signer
exercises the rationale gate and the projection guard instead of admission).
That is a change to the instrument after seeing a result, and is recorded as
such.

## Run 2 — `run-20261002t132144z` — PASSED, 11/11

| Probe | At (UTC) | Result | Event / response |
|---|---|---|---|
| P01 NIP-11 escalation default | 13:21:44 | PASS | `medium` / `escalate_to_human`, surface enabled |
| P02 reviewers route gated | 13:21:46 | PASS | unsigned 401; signed 200 (signer is admin) |
| P03 application route + stage ladder | 13:21:47 | PASS | 400 `stage must be one of consumer-received, applied, not-applied, applied-manually` |
| P04 probe panel (inspectable / irreversible / significant) | 13:21:49 | PASS | `1a353e9845f32daaece94eb14400ee7cd85fc1e0262a47cdffbdc01312f11528` |
| P05 probe request, declared `low` | 13:21:49 | PASS | `03afc126494248c64246188be5b5519a82e7b4fa39c7529eb0b0139fe1640fd9` |
| P06 stored effective tier | 13:21:50 | PASS | `effective_tier: high`, `declared_tier: low`, `probe: null`, digest absent from the whole projection |
| P07 `#probe` REQ | 13:21:50 | PASS | 0 matches; `#d` control 1 match |
| P08 31403 without rationale | 13:21:50 | PASS | `055db1df060993fa38a37eb33ba18aac35d9a3a16eac0b7237ff5c5d500a8801` refused `rationale_required` (admitted as admin, refused before storage) |
| P09 31403 `system:` decider, 72-character rationale | 13:21:51 | PASS | `b46238b26fd409bc8f6aeba4cfbea437f617015318908d07d8bfb62989291d2b` stored (OK true) |
| P10 case unchanged | 13:21:54 | PASS | `state: open`, `probe: null` |
| P11 withdrawal (request + stored 31403) | 13:21:54 | PASS | `76a3fd33e6128cc930de7695cd7fdcf851994fd5f2f09ee193f5229e39fe3d56` |

Supplementary, `adr-2010-receipts-run2.json` (relay `GET
/api/governance/receipts?case=m4-probe-20261002t132144z`, signed by the same
admin agent): the P09 response is at stage **`projection-failed`**, `applied:
false`, `stageError: ShareTransitionRejected("effective tier high requires a
human 31403; System(\"system:adr-2011-m4-probe\") may not resolve it")`. That
is ADR-2011 §4's projection guard firing on the edge, and ADR-2010's receipt
distinguishing a refused write from an applied one, on a signed journey.
`requestEventId` is `null` although the 31403 carried an `e` tag naming the
request — the correlation gap ADR-2010's 2026-09-07 audit names.

## Findings the run surfaced

1. **The requesting agent holds decision authority.** JunkieJarvis — the agent
   that raises every dream-machine case — is an admin on both the relay and
   the auth worker. ADR-2011 §4 decides "human" from the 31403's own
   `decided_by`; an admin agent that writes 20+ characters of rationale and
   omits `decided_by` (or names a `did:nostr`) is indistinguishable from the
   owner. The suite deliberately did **not** test this live: doing so would
   mint a decision ADR-2011 accepts as human. The boundary is therefore only
   as strong as the admin list. Owner action: drop JunkieJarvis's admin flag
   unless something requires it, or adopt a relay rule that a high/critical
   case may not be decided by the pubkey that requested it.
2. **Calibration key presence is unverified.** `CALIBRATION_SELECTION_KEY` is a
   Worker secret; checking it needs Cloudflare credentials this run did not
   use. When unset the relay logs a warning and samples on an unkeyed hash.
   Owner action: `wrangler secret list --name dreamlab-nostr-relay`.
3. **Probe rows persist.** A kind-5 removes the events, not the `broker_cases`
   rows: `m4-probe-20261002t131900z` and `m4-probe-20261002t132144z` remain
   `open` with a probe digest and will draw `escalated-on-age` side receipts
   after 24 h. They are identifiable (`created_by` = the probe agent,
   `subject_kind = m4-probe`) and decided by nobody.
4. **Exit item 6 is visible but not established.** The reviewers endpoint
   returned one real row: `b41654017f6850b13857d19d8ae0e3f88f1365600cab0321e8101c9e92682f7a`,
   1 decision, median and p90 time-to-decision 176,133,000 ms (48.9 h). One
   decision is a real, non-synthetic row, not a distribution.
5. **No live high-tier case exists for a human.** `--list-cases` after run 2:
   52 open cases; the only `high` ones are the two probe cases. Every real case
   is a dream-machine case at `low`/`medium` (that panel declares
   inspectable / reversible / bounded) or predates migration 0006.

## Reproduce

```
cargo build -p nostr-bbs-governance-probe
target/debug/nostr-bbs-governance-probe \
  --relay wss://dreamlab-nostr-relay.solitary-paper-764d.workers.dev \
  --auth-api https://dreamlab-auth-api.solitary-paper-764d.workers.dev \
  --out .claude/evidence/m4-$(date -u +%F)
```
