# Evidence — deepsec gate run and remediation

## Run 1 — `20260915205620-0c26947e072bcdee`

```
$ scripts deepsec-gate.sh --diff main
Processing complete: 27 analyses, 5 findings
deepsec-gate: PASS — 5 finding(s)
  {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 1, 'HIGH_BUG': 2, 'BUG': 2, 'LOW': 0}
  0 at/above HIGH; candidates=0
receipt: .deepsec-gate/reports/20260915T205617Z/receipt.json
GATE_EXIT=0
```

The gate passed on its own terms (nothing at or above HIGH). Four of the five
findings were nonetheless fixed, because they sit directly in the paths this
feedback pass touched and two of them undermine the fixes themselves.

## Fixed

### HIGH BUG — gift-wrap timestamps jittered into the FUTURE

`crates/nostr-bbs-core/src/gift_wrap.rs:125-142`. `randomized_timestamp()` chose
add-vs-subtract from a random bit, jittering symmetrically ±48h about `now`. The
wrap's `created_at` is the only timestamp a relay can see (the seal's is inside
the ciphertext), and relays routinely refuse events dated ahead of now
(strfry's `max_created_at`). So roughly **half of all outbound DMs were stamped
up to two days in the future and silently dropped at admission**, while the
sender saw a normal optimistic bubble.

This directly undercut EXP-FB-004: the forum client widens its realtime `since`
window by `GIFT_WRAP_LOOKBACK_SECS` precisely because NIP-59 backdates, and a
future-stamped wrap defeats that too. Now `now.saturating_sub(offset)`, always.

Regression test `wrap_timestamps_are_never_in_the_future` draws 200 wraps; a
return to symmetric jitter fails it with probability `1 - 2^-200`.

### HIGH BUG — byte-index slice on attacker-controlled text panicked the runtime

`crates/nostr-bbs-forum-client/src/components/global_search.rs:107-108` and
`:395-396` did `&content[..77]` / `&ev.content[..97]` after checking
`content.len() > 80` / `> 100`. `len()` is **bytes**; any content whose cut point
landed mid-codepoint panicked, and a Rust panic in WASM aborts the module. Both
inputs are fully attacker-controlled (a message body, a kind-40 channel
description), so one post containing an emoji at the wrong offset would take
down the whole client for everyone who searched and matched it.

Replaced with a char-counting `ellipsise()` helper, plus three tests covering
emoji, combining marks, CJK and a ZWJ flag sequence.

### BUG — throwaway secret-key zeroize operated on a copy

`gift_wrap.rs:248, 278-279`. The cleanup made a *second* copy of the key array
and zeroized that, leaving the original binding (and the `SigningKey` built from
it) holding live bytes until ordinary stack teardown — the intended
defence-in-depth scrub was a no-op, and it did not run at all on the early `?`
returns. Now `Zeroizing<[u8;32]>`, which scrubs on drop on every exit path.

### BUG — optimistic DM local id collided

`dm/mod.rs:381`. `format!("local-{}-{}", now, content.len())` with `now` in whole
seconds: two messages of equal byte length sent in the same second ("hey" /
"yo!") produced the same key, so the second bubble was never pushed and the
re-key step corrupted the dedup index for both. Both messages still reached the
relay — the sender simply could not see one, which reads as a lost message. Now
carries a random 32-bit nonce.

## NOT fixed — and why

### MEDIUM — unauthenticated `/embed` and `/search` drive paid Workers AI

`crates/nostr-bbs-search-worker/src/lib.rs:529-772`. Both endpoints call
Cloudflare Workers AI (a metered service) with no authentication; the only
protection is a per-IP rate limiter that is fail-open on KV error and racy
(get-then-put rather than atomic).

This is real, and it is **out of scope for a member-feedback pass**: the fix is
either an auth/capability decision for the operator (who may want `/embed`
public) or a rate-limiter rewrite onto a Durable Object counter. Neither is a
bug introduced here — the endpoints and the limiter predate this branch; the
finding surfaced because the diff touched `handle_search`. Flagged for a
follow-on, with the gate's own recommendation recorded above.

## Run 2 — after remediation

See the second receipt in `.deepsec-gate/reports/`.
