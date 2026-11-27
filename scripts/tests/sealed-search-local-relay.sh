#!/usr/bin/env bash
# The sealed-search builder against a LOCAL relay worker: `--from-relay` over a
# NIP-42-authenticated WebSocket, paging `#zk` with `since`, kind-5 reads and
# `ids` / `#sealed` lookups, through the relay's own filter code.
#
# Runs the relay with `wrangler dev --local` (workerd and miniflare, a local D1
# under a throwaway directory, no remote binding, no credentials), whitelists
# two throwaway publishers, and seeds synthetic zone events (the example
# `synth_zone`: generated sentences, throwaway keys) straight into the local
# D1: ingest is not what is under test, and an encrypted zone's ingest gates
# need a zone binding this harness does not set up. Then, against a pod
# directory (no pod worker): the archivist's base, the indexer's first update
# (nothing new), a night of new posts with an edit and two deletions, and a
# compaction. The relay serves the deleted posts still (they were seeded, not
# deleted through it), so their exclusion comes from the kind-5s alone. The
# indexer seeds its author book before its first update, as the runbook says.
#
# Never point this at a deployed relay: it only ever starts its own on
# 127.0.0.1.
#
# Needs: wrangler, worker-build 0.8.4 (as grant-paging-local-relay.sh),
# python3, curl, and the bge-small-en-v1.5 FP32 checkpoint (MODEL_DIR, with
# pytorch_model.bin and vocab.txt) and its Q8 GGUF (MODEL_Q8, from
# `nostr-bbs-search-build model-q8`).
#
# Env: PORT (default 8799), SKIP_BUILD=1 to reuse build/worker, KEEP=1 to keep
# the work directory.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
worker="$root/crates/nostr-bbs-relay-worker"
port="${PORT:-8799}"
url="ws://127.0.0.1:$port"
work="$(mktemp -d)"
state="$work/relay"
wrangler_pid=""
: "${MODEL_DIR:?set MODEL_DIR to the bge-small-en-v1.5 checkpoint directory}"
: "${MODEL_Q8:?set MODEL_Q8 to the Q8 GGUF}"

cleanup() {
  if [ -n "$wrangler_pid" ]; then
    kill "$wrangler_pid" 2>/dev/null || true
    wait "$wrangler_pid" 2>/dev/null || true
  fi
  if [ "${KEEP:-0}" = "1" ]; then
    echo "kept $work" >&2
  else
    rm -rf "$work"
  fi
}
trap cleanup EXIT

log() { printf '[sealed-search-local] %s\n' "$*" >&2; }
d1() { CI=true wrangler d1 execute nostr-bbs-relay --local --persist-to "$state" "$@" >>"$work/d1.log" 2>&1; }

log "building the builder and the synthetic-zone example"
cargo build --release --manifest-path "$root/Cargo.toml" -p nostr-bbs-search-build \
  --bin nostr-bbs-search-build --example synth_zone >"$work/cargo.log" 2>&1
bin="$root/target/release/nostr-bbs-search-build"
synth="$root/target/release/examples/synth_zone"

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  log "building the relay worker"
  (cd "$worker" && worker-build --release) >"$work/worker-build.log" 2>&1
fi
[ -f "$worker/build/worker/shim.mjs" ] || { log "no build/worker/shim.mjs"; exit 1; }

cd "$worker"
mkdir -p "$state"
# event_tags (which every tag filter is driven from) comes from migration
# 0004 plus the time column; create it before the first request, so the
# worker's ensure_schema() installs its tag trigger on it.
d1 --command "CREATE TABLE IF NOT EXISTS event_tags (event_id TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT 0); \
  CREATE INDEX IF NOT EXISTS idx_event_tags_lookup ON event_tags(name, value, event_id); \
  CREATE INDEX IF NOT EXISTS idx_event_tags_event ON event_tags(event_id);"
log "starting wrangler dev --local on $url"
wrangler dev --local --ip 127.0.0.1 --port "$port" --persist-to "$state" \
  --var "RELAY_URL:$url" --var "RATE_LIMIT_MSGS_PER_SEC:100000" --var "AUTH_MODE:nip42" \
  >"$work/wrangler.log" 2>&1 &
wrangler_pid=$!
for _ in $(seq 1 120); do
  if curl -fsS "http://127.0.0.1:$port/api/check-whitelist?pubkey=$(printf '0%.0s' $(seq 1 64))" >/dev/null 2>&1; then
    break
  fi
  kill -0 "$wrangler_pid" 2>/dev/null || { log "wrangler exited:"; tail -40 "$work/wrangler.log" >&2; exit 1; }
  sleep 1
done

zone="$work/zone"
log "generating 2,000 imported and 500 live synthetic posts"
ids="$("$synth" "$zone" 2000 500 1700000000 7 2)"
archivist="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["archivist"])' "$ids")"
indexer="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["indexer"])' "$ids")"
now="$(date +%s)"
d1 --command "INSERT OR IGNORE INTO whitelist (pubkey, added_at, is_admin) VALUES ('$archivist', $now, 0), ('$indexer', $now, 0);"

# Seed every event not yet in the relay's D1.
seeded=0
seed() {
  python3 - "$zone/events.jsonl" "$work/seed.sql" "$seeded" <<'PY'
import json, sys
src, out, skip = sys.argv[1], sys.argv[2], int(sys.argv[3])
q = lambda s: "'" + s.replace("'", "''") + "'"
rows = [json.loads(l) for l in open(src) if l.strip()][skip:]
with open(out, "w") as f:
    for e in rows:
        f.write("INSERT OR IGNORE INTO events (id, pubkey, created_at, kind, tags, content, sig, d_tag, received_at) VALUES "
                f"({q(e['id'])}, {q(e['pubkey'])}, {e['created_at']}, {e['kind']}, {q(json.dumps(e['tags'], separators=(',', ':')))}, "
                f"{q(e['content'])}, {q(e['sig'])}, '', {e['created_at']});\n")
print(len(rows))
PY
}
n="$(seed)"; d1 --file "$work/seed.sql"; seeded=$((seeded + n))
log "seeded $seeded events"

common=(--zone zone2 --from-relay "$url" --relay-url "$url" --keys-file "$zone/keys.json"
  --pod-dir "$work/pods" --publishers "$archivist,$indexer"
  --model-dir "$MODEL_DIR" --model-q8 "$MODEL_Q8")
indexer_args=(--key-file "$zone/indexer.key" --state "$work/state.json" --cache-dir "$work/cache")
field() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d[sys.argv[2]])' "$1" "$2"; }
expect() {
  local got; got="$(field "$1" "$2")"
  if [ "$got" = "$3" ]; then log "ok   $2 = $3"; else log "FAIL $2: want $3, got $got"; exit 1; fi
}

log "archivist: full build from the relay"
"$bin" "${common[@]}" --key-file "$zone/archivist.key" >"$work/full.json"
expect "$work/full.json" rows_added 2500
expect "$work/full.json" index_version 1

log "indexer: seed the author book from the zone"
"$bin" seed-book "${common[@]}" "${indexer_args[@]}" >"$work/seed.json"
expect "$work/seed.json" recorded 2500

log "indexer: first update reads the whole zone, finds nothing new"
"$bin" update "${common[@]}" "${indexer_args[@]}" >"$work/u1.json"
expect "$work/u1.json" published False
expect "$work/u1.json" already_indexed 2500

log "a night: 300 new live posts, an edit and two deletions"
"$synth" "$zone" 0 300 1700100000 9 2 1 >/dev/null
n="$(seed)"; d1 --file "$work/seed.sql"; seeded=$((seeded + n))
"$bin" update "${common[@]}" "${indexer_args[@]}" >"$work/u2.json"
expect "$work/u2.json" published True
expect "$work/u2.json" index_version 2
expect "$work/u2.json" rows_added 301
expect "$work/u2.json" excluded_added 3
expect "$work/u2.json" objects_foreign 2
log "update report: $(cat "$work/u2.json")"

log "compaction (folds the base's shard and the update)"
"$bin" compact "${common[@]}" "${indexer_args[@]}" >"$work/c1.json"
expect "$work/c1.json" published True
expect "$work/c1.json" folded_pairs 2
expect "$work/c1.json" dropped_rows 3
expect "$work/c1.json" missing_rows 0
expect "$work/c1.json" objects_foreign 0
log "compaction report: $(cat "$work/c1.json")"
log "all passed against $url"
