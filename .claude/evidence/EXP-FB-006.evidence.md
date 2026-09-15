# Evidence — EXP-FB-006 (search)

## Defect 1 — every indexed vector was marked unreachable

`pages/channel.rs:762-769` at `11b674c`:

```rust
let _ = crate::utils::search_client::ingest_message_signer(
    &event_id, &content_for_index, Some(&channel_for_index),
    false,                      // <- `public`, hardcoded
    &*signer,
).await;
```

Worker side, `crates/nostr-bbs-search-worker/src/lib.rs:544-548` maintains
`public_labels` from that flag, and `handle_search` filters every result through
`is_search_visible` (`:385`, `:116-118`). So **search could only ever return
`[]`** — for every user, on every device. That is the whole of "seems completely
broken", and it explains why it was unclear whether it was mobile-only: it
wasn't.

The empty-index path returns HTTP 200 with `{"results":[]}` (`:361-368`), so the
UI showed "No results found" rather than an error — no signal that anything was
wrong.

### The fix, and why it is not simply `public: true`

`/search` is **unauthenticated**. Blanket `public: true` would publish gated
zones' message content to anyone who can reach the worker, bypassing the zone
ACL. The flag is now derived from the owning zone's read policy —
`Zone::required_cohorts.is_empty()`, the kit's own definition of unauthenticated
read (`stores/zones.rs:87-89`) — resolved through the same channel→section→zone
path the page already uses for its accent colour, and **failing closed** to
`false` for any zone that cannot be resolved. Note the deliberate asymmetry with
`zone_accent`, which falls back to the first zone: an accent guessing wrong is
cosmetic, a visibility flag guessing wrong is a disclosure.

The worker's fail-closed `is_search_visible` default is **kept**, and `/ingest`
now rejects an all-private batch with a 400 before writing anything, so this
class of bug cannot silently recur. Deliberate private ingest opts in with
`allowPrivate`.

## Defect 2 — truncate before filter

`store.rs:71` truncated to `k`, then `lib.rs:383-397` applied the visibility
filter. A top-`k` dominated by private vectors yielded far fewer than `k` hits,
or none. Now over-fetches (`OVERFETCH_FACTOR = 4`, `OVERFETCH_CAP = 400`) and
takes `k` after filtering.

## Defect 3 — the base URL was unresolvable, and the two client files disagreed

| Location | Value |
|---|---|
| `components/global_search.rs:40-43` | `members-search-api.solitary-paper-764d.workers.dev` |
| `utils/search_client.rs:9-12` | **`https://search.example.com`** (RFC 2606 reserved) |
| `wrangler.toml:1` | deploys as `nostr-bbs-search-api` |
| `e2e-smoke-test.mjs:7` | `dreamlab-search-api...` |

`search_similar()` and `get_search_status()` therefore could never work — the
"RuVector / text only" pill was permanently stuck on *text only*. Compounded by
`SETUP.md:173` documenting the variable as `SEARCH_API_URL` while the code read
`VITE_SEARCH_API_URL`.

Now one resolver in `search_client.rs`: runtime `window.__ENV__`
(`SEARCH_API`/`SEARCH_URL`/`SEARCH_BASE_URL`/`SEARCH_API_URL`/`VITE_SEARCH_API_URL`
— the first three matching `bbs-client/src/config.rs:148`), then the compile-time
value, then a reachable default. Split into a pure
`resolve_search_base(runtime, compile_time)` plus a wasm-only reader so it is
host-testable. SETUP.md reconciled.

## Defect 4 — `limit` vs `k`

`global_search.rs:685` and `search_core.rs:59-61` both sent `"limit"`; the
worker's `SearchRequest` (`lib.rs:94-110`) has only `k`. Masked by
`default_k() == 10` — and **locked in** by `search_core.rs:179-185`, a test that
asserted the wrong wire field. Fixed in all three places, with the contract now
living in tested pure builders (`build_embedding_search_body`,
`build_query_search_body`).

## Defect 5 — mobile had no entry point

`app.rs:1071` puts the nav search button inside `hidden sm:flex`; `app.rs:1160`
puts the hamburger's "Search" item inside `<Show when=is_authed>`;
`mobile_bottom_nav.rs:66-126` has no search entry; Ctrl/Cmd+K does not exist on
touch. A signed-out mobile visitor could not open search **at all**. A search
button now sits beside the hamburger, outside any auth gate (`app.rs:1149`).

The UI trigger itself was fine: `on:input` with a 300/500 ms debounce
(`global_search.rs:453-484`), result rows are real `<button on:click>`. Not a
keyboard-only trigger.

## Also fixed

- Whitespace-only query: `lib.rs:328-335` rejected `""` but did not trim, so
  `"   "` reached the hash embedder, which emits an all-zero vector
  (`embed.rs:115-131`); cosine 0.0 against a `minScore` default of `0.0` under
  `>=` (`store.rs:66`) returned **the entire index** at score 0. Now trimmed
  before the empty check, on the worker and both clients.
- `SearchResult.score` gained `#[serde(default)]` (`search_client.rs:19`) — one
  score-less row no longer fails the whole parse.
- The `channel` filter (`search_client.rs:77-79`) was a silent no-op; removed
  client-side and documented, because the index is a flat `(label, vector)` store
  with no per-vector channel metadata — a real filter is a schema change plus a
  full re-ingest.

## Tests — 20 added

```
$ cargo test -p nostr-bbs-forum-client   → ok. 450 passed; 0 failed
$ cargo test -p nostr-bbs-search-worker  → ok.  51 passed; 0 failed   (baseline 43)
$ cargo test -p nostr-bbs-bbs-client     → ok. 162 passed; 0 failed   (baseline 160)
$ cargo clippy -p nostr-bbs-search-worker → clean
$ cargo clippy -p nostr-bbs-bbs-client    → clean
```

Worker: `overfetch_pulls_more_candidates_than_requested`,
`overfetch_then_filter_returns_k_visible_hits` (40 candidates, every 4th public,
k=10 → exactly 10 visible hits in score order), `visible_top_k_filters_before_truncating`,
`visible_top_k_returns_empty_when_nothing_is_public`, `whitespace_only_query_is_rejected`,
`non_empty_query_is_trimmed_not_rejected`, `all_private_batch_is_rejected_with_a_warning_body`,
`mixed_and_opted_in_batches_are_accepted`.

Forum client: `runtime_env_wins_over_compile_time_and_fallback`,
`compile_time_used_when_no_runtime_value`, `blank_values_fall_through_to_the_reachable_default`,
`trailing_slash_is_stripped_so_paths_never_double_up`, `env_keys_cover_both_documented_spellings`,
`embedding_search_body_uses_k_not_limit`, `query_search_body_uses_k_and_trims`,
`search_body_carries_no_channel_key`, `search_result_parses_without_a_score_field`,
`search_result_still_reads_a_full_row`, `overlay_semantic_body_uses_k_not_limit`,
`overlay_and_search_client_share_one_base_url`.

BBS client: `build_search_body_uses_k_not_limit`,
`build_search_body_trims_whitespace_only_query_to_empty`; the wrong `"limit":10`
assertion in `build_search_body_escapes_query` removed.

## Honest limits

- **No live worker was called.** Every test is unit-level against the request
  builders and the filter logic. Whether the deployed worker's
  `ALLOWED_ORIGINS` is still the placeholder `https://example.com`
  (`wrangler.toml:30-31`) is unverified — and if it is, `cors_origin()`
  (`lib.rs:42-55`) echoes the first configured origin rather than omitting the
  header, so every browser request fails with an opaque `TypeError`. That is a
  **deployment check, not a code fix**: run
  `curl -i -X POST https://<deployed>/search -H 'Origin: https://<forum-origin>' ...`
  and confirm the returned `Access-Control-Allow-Origin`.
- **Vectors already ingested with `public: false` remain invisible.** The flag is
  written only at ingest time and there is no backfill job. Existing content
  needs re-ingesting before search returns anything for it.
- `/ingest` is admin-gated (`auth.rs:86-88`) but called as the ordinary posting
  user (`channel.rs`), and the result is discarded with `let _ =`. So for
  non-admins ingest still 403s silently. Not fixed: making it work means either
  relaxing the gate (a security decision) or moving ingest server-side (a
  feature). Flagged as the next thing to do.
