# Jev option (opt-in typed decisions)

Three forum Workers can optionally ask [Jev](https://api.typesafe.ai) (TypeSafe System One:
Choice / Score / Noul over `POST /v1/systemone`) a bounded semantic question. **Every option is off by
default.** With its flag off, no request is built, nothing leaves the Worker, and behaviour is
byte-for-byte the pre-change behaviour. On *any* failure (no endpoint, timeout, non-2xx, malformed
body, missing answer, low confidence) the Worker falls back to the pre-change behaviour and logs one
reason token (`flag-off`, `no-endpoint`, `timeout`, `http-<code>`, `malformed`, `low-confidence`),
never request content. Jev never writes, signs, approves, hides, bans or changes permissions.

Status of every item: **proposed research candidate; no measured uplift.** The wiring and fallback
tests show equivalence, not value; thresholds are unfitted defaults.

Shared adapter: `crates/nostr-bbs-jev` (pure request/response core, injectable transport, Workers
`fetch` transport with an `AbortController` + `Delay` deadline of at most 4 s and no retries).

## Endpoint resolution (first match wins)

1. `JEV_ENDPOINT` (+ `JEV_MODEL`, and `JEV_API_KEY_NAME` naming the **secret** that holds the key).
2. `AGENTBOX_SYSTEM_ONE_ENDPOINT` + `AGENTBOX_SYSTEM_ONE_MODEL` when `AGENTBOX_SYSTEM_ONE_PROXY=1`
   (agentbox loopback, no Authorization header; only reachable from `wrangler dev` on the same host).
3. `https://api.typesafe.ai/v1/systemone`, model `jev-latest`, `Authorization: Bearer` from the
   `TYPESAFE_API_KEY` **secret** (`wrangler secret put TYPESAFE_API_KEY`). Never put the key in
   `[vars]`; it is held in a redacting config type and never logged.
4. Otherwise Jev is unavailable and the Worker falls back.

`JEV_DEADLINE_MS` may shorten the 4000 ms default (clamped to 100..4000). Local-only consumers
(below) refuse steps 2 and 3 unless the backend is declared local (`JEV_LOCAL=1` with an explicit
endpoint, or `AGENTBOX_SYSTEM_ONE_BACKEND_LOCAL=1`).

## Items

| Item | Worker | Flag (default off) | What leaves | Question set |
| --- | --- | --- | --- | --- |
| NF-07-S1-01 rerank visible search results | search-worker | `JEV_SEARCH_RERANK=1` | the trimmed query text plus up to 10 public snippets (<= 280 chars, stored at ingest only for `public: true` entries when the flag is on) | `forum-search-rerank/1` |
| NF-03-S1-01 moderation triage | relay-worker (cron) | `JEV_TRIAGE=1` | plaintext of an already-admitted kind-42 post in a public-read, non-encrypted zone, plus the post it replies to in the same channel | `forum-moderation-triage/1` |
| NF-06-S1-01 rationale/evidence check | auth-worker | `JEV_RATIONALE_CHECK=1` | case title, summary, effective tier, task properties and the reviewer's draft rationale; **local-only** | `forum-governance-evidence-quality/1-local` |

Tunables: `JEV_SEARCH_MIN_CONFIDENCE` (default 0.5), `JEV_TRIAGE_QUEUE_THRESHOLD` (default 0.5). Both
are unfitted; fit on labelled data before relying on them.

### NF-07-S1-01 — search rerank
Runs after the embedding-model gate and the public-visibility filter (`visible_top_k`), so it cannot
surface a hidden or non-indexed candidate. Only the first 10 visible hits may be permuted; the tail
keeps cosine order. Any head candidate without a stored snippet, or any answer below the confidence
floor, falls back. The "no useful match" Noul is an annotation (`jev.noUsefulMatch`); it never drops a
result. An accepted rerank adds a `jev` object to the response; a fallback response has no `jev` key
and is byte-identical to before. Ingest accepts an optional `snippet` per entry; it is persisted
(KV `<RVF_STORE_KEY>:snippets`) only when the flag is on and the entry is `public: true`.

### NF-03-S1-01 — moderation triage
A cron sweep, **after** the normal admission pipeline has stored the event. It does not touch
admission, auth, trust, `reports` (which feeds the three-report auto-hide) or `hidden_events`. It
writes advisory rows to `jev_triage` (migration `0011`), at most 5 posts per tick, stopping at the
first outage so an outage costs one deadline. Eligible posts are kind-42 events in channels whose zone
is public-read and not encrypted, received in the last 24 h, not already hidden or triaged; zone
ciphertext is never sent. Moderators read the queue at `GET /api/jev/triage?queued=1` (NIP-98 admin);
any action goes through the existing moderation endpoints. Community rules text is not supplied
because the zone config holds none.

### NF-06-S1-01 — decision-card rationale check
`POST /api/governance/cases/:id/rationale-check` with `{"rationale": "..."}` (NIP-98 authed). The
route does not exist while the flag is off. The answer is advice only (`advisory: true`) and nothing
reads it: not `rationale_required`/`rationale_satisfied`, tier assignment, 31403 signing, promotion or
demotion, request correlation, or seeded-probe enforcement. The probe digest, pubkeys and keys are
never sent. The estate shares one governance evidence-quality rubric (ES-05, agentbox); until it is
published this uses a local version string, to be aligned. No forum-client UI is wired yet.

## Operating it

Enable per Worker with `wrangler.toml` `[vars]` (flag, endpoint, model) and `wrangler secret put` (key).
No flag is set in the committed `wrangler.toml` files.
