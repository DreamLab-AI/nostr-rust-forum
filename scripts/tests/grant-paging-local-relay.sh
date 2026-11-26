#!/usr/bin/env bash
# Grant paging against a LOCAL relay worker (PR #95).
#
# Builds the relay worker, runs it with `wrangler dev --local` (workerd and
# miniflare: the relay Durable Object and a local D1 under a throwaway
# directory, no remote binding, no credentials), whitelists two throwaway
# keys (a member, and an admin who seals the grants), and runs the ignored
# test `zone_crypto::grant_paging_local_relay`, which seeds more than two
# pages of gift wraps over NIP-42-authenticated EVENT frames and checks that
# the grant sync's driver delivers every wrap and settles every grant.
#
# Never point this at a deployed relay: the test refuses any URL that is not
# ws://127.0.0.1:<port> or ws://localhost:<port>.
#
# Needs: wrangler, worker-build 0.8.4 (the version the deploy workflow pins:
# 0.8.5+ emits an abort handler these crates are not built for), openssl,
# curl. If worker-build cannot run its downloaded wasm-bindgen (a noexec
# cache), set WASM_BINDGEN_BIN to a wasm-bindgen CLI matching Cargo.lock and
# XDG_CACHE_HOME to an executable directory.
#
# Env: PORT (default 8799), SKIP_BUILD=1 to reuse build/worker, EVIDENCE_DIR
# to keep the wrangler log and test output.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
worker="$root/crates/nostr-bbs-relay-worker"
port="${PORT:-8799}"
url="ws://127.0.0.1:$port"
state="$(mktemp -d)"
wrangler_pid=""

cleanup() {
  if [ -n "$wrangler_pid" ]; then
    kill "$wrangler_pid" 2>/dev/null || true
    wait "$wrangler_pid" 2>/dev/null || true
  fi
  if [ -n "${EVIDENCE_DIR:-}" ]; then
    mkdir -p "$EVIDENCE_DIR"
    cp "$state"/*.log "$EVIDENCE_DIR"/ 2>/dev/null || true
  fi
  rm -rf "$state"
}
trap cleanup EXIT

log() { printf '[grant-paging-local] %s\n' "$*" >&2; }

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  log "building the relay worker"
  (cd "$worker" && worker-build --release)
fi
[ -f "$worker/build/worker/shim.mjs" ] || { log "no build/worker/shim.mjs"; exit 1; }

cd "$worker"
# No `d1 migrations apply`: as deployed, the schema comes from the worker's
# own `ensure_schema()` on its first request (the checked-in migrations are
# the readable record and do not apply standalone), which the readiness poll
# below makes.
log "starting wrangler dev --local on $url"
wrangler dev --local --ip 127.0.0.1 --port "$port" --persist-to "$state" \
  --var "RELAY_URL:$url" --var "RATE_LIMIT_MSGS_PER_SEC:100000" --var "AUTH_MODE:nip42" \
  >"$state/wrangler.log" 2>&1 &
wrangler_pid=$!
for _ in $(seq 1 120); do
  if curl -fsS "http://127.0.0.1:$port/api/check-whitelist?pubkey=$(printf '0%.0s' $(seq 1 64))" \
    >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$wrangler_pid" 2>/dev/null; then
    log "wrangler exited:"; tail -40 "$state/wrangler.log" >&2; exit 1
  fi
  sleep 1
done

# `event_tags` (which every `#p` filter is driven from) comes only from
# migration 0004, which an operator applies after the first boot. Apply its
# table, indexes and delete trigger; not its v1 insert trigger, which
# `ensure_schema()` has already replaced with `trg_event_tags_ai_v2`.
log "creating event_tags as migration 0004 does"
CI=true wrangler d1 execute nostr-bbs-relay --local --persist-to "$state" --command \
  "CREATE TABLE IF NOT EXISTS event_tags (event_id TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL DEFAULT ''); \
   CREATE INDEX IF NOT EXISTS idx_event_tags_lookup ON event_tags(name, value, event_id); \
   CREATE INDEX IF NOT EXISTS idx_event_tags_event ON event_tags(event_id); \
   CREATE TRIGGER IF NOT EXISTS trg_event_tags_ad AFTER DELETE ON events BEGIN DELETE FROM event_tags WHERE event_id = OLD.id; END;" \
  >"$state/event-tags.log" 2>&1

export GRANT_PAGING_LOCAL_RELAY="$url"
GRANT_PAGING_MEMBER_SK="$(openssl rand -hex 32)"
GRANT_PAGING_ADMIN_SK="$(openssl rand -hex 32)"
export GRANT_PAGING_MEMBER_SK GRANT_PAGING_ADMIN_SK

run_test() {
  GRANT_PAGING_PHASE="$1" cargo test --manifest-path "$root/Cargo.toml" \
    -p nostr-bbs-forum-client --all-features grant_paging_against_a_local_relay \
    -- --ignored --nocapture
}

log "deriving the throwaway pubkeys"
keys="$(run_test keys 2>/dev/null)"
member_pk="$(printf '%s\n' "$keys" | sed -n 's/^MEMBER_PK=//p')"
admin_pk="$(printf '%s\n' "$keys" | sed -n 's/^ADMIN_PK=//p')"
[ ${#member_pk} -eq 64 ] && [ ${#admin_pk} -eq 64 ] || { log "no pubkeys: $keys"; exit 1; }

log "whitelisting member ${member_pk:0:12}… and admin ${admin_pk:0:12}…"
now="$(date +%s)"
CI=true wrangler d1 execute nostr-bbs-relay --local --persist-to "$state" --command \
  "INSERT INTO whitelist (pubkey, added_at, is_admin) VALUES ('$admin_pk', $now, 1), ('$member_pk', $now, 0);" \
  >"$state/whitelist.log" 2>&1

log "running the test"
run_test run 2>&1 | tee "$state/test.log"
