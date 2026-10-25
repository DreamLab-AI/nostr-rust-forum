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
| NF-06-S1-01 rationale/evidence check | auth-worker | `JEV_RATIONALE_CHECK=1` | case title, summary, effective tier, task properties and the reviewer's draft rationale; **local-only** | `governance-evidence-quality/1` (ES-05) |

Tunables: `JEV_SEARCH_MIN_CONFIDENCE` (default 0.5), `JEV_TRIAGE_QUEUE_THRESHOLD` (default 0.5). Both
are unfitted; fit on labelled data before relying on them.

### NF-07-S1-01 — search rerank
Runs after the embedding-model gate and the public-visibility filter (`visible_top_k`), so it cannot
surface a hidden or non-indexed candidate. Only the first 10 visible hits may be permuted; the tail
keeps cosine order. Any head candidate without a stored snippet, or any answer below the confidence
floor, falls back. The "no useful match" Noul is an annotation (`jev.noUsefulMatch`); it never drops a
result. An accepted rerank adds a `jev` object to the response; a fallback response has no `jev` key
and is byte-identical to before. The forum client's `ingest_message_signer` sends `snippet` (first 280 chars) for `public: true` entries only; until the flag is on the worker ignores it, and until snippets have been ingested every flag-on search falls back with `malformed` (an expected state, not a Jev fault; re-ingest to populate). Ingest accepts an optional `snippet` per entry; it is persisted
(KV `<RVF_STORE_KEY>:snippets`) only when the flag is on and the entry is `public: true`.

### NF-03-S1-01 — moderation triage
A cron sweep, **after** the normal admission pipeline has stored the event. It does not touch
admission, auth, trust, `reports` (which feeds the three-report auto-hide) or `hidden_events`. It
writes advisory rows to `jev_triage` (migration `0011` is the record; the table is created lazily by the sweep only once the flag is on, never by the relay boot path; the list route is likewise unmatched while the flag is off), at most 5 posts per tick, stopping at the
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
never sent. It uses the estate-shared ES-05 rubric `governance-evidence-quality` v1, vendored byte-for-byte at
`crates/nostr-bbs-auth-worker/src/rubrics/governance-evidence-quality.v1.json` from agentbox
(`management-api/lib/rubrics/governance-evidence-quality.v1.json`, branch `feat/jev-option-p1-b`).
Its canonical-JSON sha256 is pinned (`3a338a77939ffec84e03413186619b6e58ad59f8d098543a9e127987fc9a6910`)
and a test fails on drift; changing a question means a new version and digest. Card mapping: `title` =
case title; `subject` = subject kind/id; `rationale` = the reviewer's draft (null if empty);
`evidence` = summary, effective tier and typed task properties; `context_url` = null (the case row has
none). Output: per-question signals in [0,1], a flag for any yes/no signal below 0.5, and a completeness
score; `authority: "none"`. The rubric's request-digest binding is not recorded because this route
reads a case row, not the unsigned event content/tags the digest covers. No forum-client UI yet.

## Snippet lifecycle (NF-07)

With the flag on, every ingest entry rewrites its snippet: an edit overwrites it, and an un-publish
(`public:false`) or a text-less re-ingest deletes it. With the flag off the worker does not touch the
snippet store, so a post un-published meanwhile keeps a stale snippet in KV until the next flag-on
re-ingest of that entry. It is never sent anyway, because rerank candidates come only from
`visible_top_k`, which drops non-public labels.

## Operating it

Enable per Worker with `wrangler.toml` `[vars]` (flag, endpoint, model) and `wrangler secret put` (key).
No flag is set in the committed `wrangler.toml` files.
