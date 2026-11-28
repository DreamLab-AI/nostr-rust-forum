#!/usr/bin/env bash
# Nightly sealed-search job for one encrypted zone: an incremental update,
# then a compaction once enough update shards have accumulated.
#
#   scripts/sealed-search-nightly.sh /etc/nostr-bbs/sealed-search-zone2.env
#
# The argument is a config file (KEY=value lines, sourced; it must be owned
# by the user running the job and writable by nobody else). It holds paths
# and URLs only. No secret goes in argv or in the config: the indexer key is
# read by the builder from NBSS_KEY_FILE (mode 0600). See
# docs/runbooks/sealed-search-incremental.md for the operator steps.
#
# Config:
#   NBSS_BIN            builder binary (default: nostr-bbs-search-build on PATH)
#   NBSS_ZONE           zone id (required)
#   NBSS_RELAY          relay WebSocket URL to read from, NIP-42 as the indexer (required)
#   NBSS_EVENTS         a NIP-01 JSONL export to read instead of NBSS_RELAY (local runs only)
#   NBSS_RELAY_URL      the deployment's relay URL as clients use it (default: NBSS_RELAY)
#   NBSS_POD            pod base URL (required unless NBSS_POD_DIR)
#   NBSS_POD_DIR        a directory laid out as the pods are (local runs only)
#   NBSS_PUBLISHERS     clients' SEARCH_PUBLISHERS, comma-separated (required)
#   NBSS_KEY_FILE       indexer key file, mode 0600 (required)
#   NBSS_KEYS_FILE      zone-migrate key file (default: the indexer's own grants)
#   NBSS_STATE_DIR      state, lock, cache and log directory (required)
#   NBSS_MODEL_DIR      bge-small-en-v1.5 FP32 checkpoint directory (required)
#   NBSS_MODEL_Q8       browser model (GGUF Q8_0) the index pins (required)
#   NBSS_ORIGIN         Origin header for the relay (default http://localhost)
#   NBSS_COMPACT_AT     compact when this many partial shard pairs exist (default 14)
#   NBSS_FULL_COMPACT_EXCLUDED_AT
#                       compact --all when this many ids are excluded (default 4096, a
#                       quarter of the manifest's cap of 16384; 0 disables it)
#   NBSS_TIMEOUT        seconds the whole job may take (default 3600)
#   NBSS_MODERATORS     comma-separated admin/moderator pubkeys whose kind-5 deletes
#                       any post (default: none; authors still delete their own)
#   NBSS_WORKERS        embedding threads (default: the builder's, half the CPUs)
#   NBSS_ZONE_CONFIG    the deployment's ZONE_CONFIG JSON (a file). With it, posts of a
#                       channel the config pins to another zone (ADR-2037) are left out
#                       of this zone's index, and already-indexed ones the relay still
#                       serves the indexer are excluded (default: no pins honoured)
#
# Exit codes:
#   0  done (published, or nothing new)
#   3  published, but posts under an epoch the indexer holds no key for were
#      held back (grant the epoch; the next run picks them up)
#   9  the author book is not seeded: run `nostr-bbs-search-build seed-book`
#      once (see the runbook) before the first update
#   1, 4, 6, 7, 8  the builder's: error; relay not NIP-42 authenticated; the
#      pods show an older index than the state recorded (rollback or
#      withholding); the relay serves none of the zone's indexed posts to the
#      indexer (not admitted to the zone's cohorts); the exclusion list would
#      pass its cap (run compact --all)
#   (5 is retired: compaction no longer refuses on rows the relay does not serve)
#   10 another run holds the lock
#   11 timed out
#   12 configuration error
set -euo pipefail
umask 077

die_config() {
  printf 'sealed-search-nightly: %s\n' "$*" >&2
  exit 12
}

[ $# -eq 1 ] || die_config "usage: $0 <config file>"
config="$1"
[ -f "$config" ] || die_config "no config file $config"
# A config file anyone else could edit would run their code as this user.
owner="$(stat -c %u "$config")"
mode="$(stat -c %a "$config")"
[ "$owner" = "$(id -u)" ] || die_config "$config is not owned by the user running the job"
case "$mode" in
  *[2367]? | *[2367]) die_config "$config is writable by group or others (mode $mode)" ;;
esac
# Nor may anyone else replace it: its directory must not be group/other writable.
config_dir="$(dirname "$config")"
dir_owner="$(stat -c %u "$config_dir")"
[ "$dir_owner" = "$(id -u)" ] || [ "$dir_owner" = 0 ] ||
  die_config "$config_dir is owned by neither the job user nor root"
dir_mode="$(stat -c %a "$config_dir")"
case "$dir_mode" in
  *[2367]? | *[2367]) die_config "$config_dir is writable by group or others (mode $dir_mode)" ;;
esac
# shellcheck source=/dev/null
. "$config"

bin="${NBSS_BIN:-nostr-bbs-search-build}"
command -v "$bin" >/dev/null 2>&1 || [ -x "$bin" ] || die_config "builder $bin not found"
[ -n "${NBSS_RELAY:-}${NBSS_EVENTS:-}" ] || die_config "NBSS_RELAY is not set"
for v in NBSS_ZONE NBSS_PUBLISHERS NBSS_KEY_FILE NBSS_STATE_DIR NBSS_MODEL_DIR NBSS_MODEL_Q8; do
  [ -n "${!v:-}" ] || die_config "$v is not set"
done
[ -n "${NBSS_POD:-}${NBSS_POD_DIR:-}" ] || die_config "NBSS_POD (or NBSS_POD_DIR) is not set"
[ -f "$NBSS_KEY_FILE" ] || die_config "no key file $NBSS_KEY_FILE"
owner_only() {
  case "$(stat -c %a "$1")" in
    ?00) ;;
    *) die_config "$1 must be mode 0600 (it holds secrets)" ;;
  esac
}
owner_only "$NBSS_KEY_FILE"
if [ -n "${NBSS_KEYS_FILE:-}" ]; then
  [ -f "$NBSS_KEYS_FILE" ] || die_config "no zone-key file $NBSS_KEYS_FILE"
  owner_only "$NBSS_KEYS_FILE"
fi
compact_at="${NBSS_COMPACT_AT:-14}"
full_at="${NBSS_FULL_COMPACT_EXCLUDED_AT:-4096}"
budget="${NBSS_TIMEOUT:-3600}"
for n in "$compact_at" "$full_at" "$budget"; do
  [[ "$n" =~ ^[0-9]+$ ]] || die_config "NBSS_COMPACT_AT, NBSS_FULL_COMPACT_EXCLUDED_AT and NBSS_TIMEOUT must be whole numbers"
done

mkdir -p "$NBSS_STATE_DIR"
# State, author book, object cache and log: the job user's alone.
[ "$(stat -c %u "$NBSS_STATE_DIR")" = "$(id -u)" ] ||
  die_config "$NBSS_STATE_DIR is not owned by the user running the job"
case "$(stat -c %a "$NBSS_STATE_DIR")" in
  ?00) ;;
  *) die_config "$NBSS_STATE_DIR must be mode 0700" ;;
esac
zone="$NBSS_ZONE"
log="$NBSS_STATE_DIR/$zone.log"
lock="$NBSS_STATE_DIR/$zone.lock"
deadline=$(($(date +%s) + budget))

say() { printf '%s %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$zone" "$*" >>"$log"; }

exec 9>"$lock"
if ! flock -n 9; then
  say "another run holds the lock; not starting"
  exit 10
fi

common=(
  --zone "$zone"
  --relay-url "${NBSS_RELAY_URL:-${NBSS_RELAY:-}}"
  --origin "${NBSS_ORIGIN:-http://localhost}"
  --publishers "$NBSS_PUBLISHERS"
  --key-file "$NBSS_KEY_FILE"
  --state "$NBSS_STATE_DIR/$zone.state.json"
  --cache-dir "$NBSS_STATE_DIR/$zone.cache"
  --model-dir "$NBSS_MODEL_DIR"
  --model-q8 "$NBSS_MODEL_Q8"
)
if [ -n "${NBSS_EVENTS:-}" ]; then
  common+=(--from-events "$NBSS_EVENTS")
else
  common+=(--from-relay "$NBSS_RELAY")
fi
if [ -n "${NBSS_POD_DIR:-}" ]; then
  common+=(--pod-dir "$NBSS_POD_DIR")
else
  common+=(--pod "$NBSS_POD")
fi
if [ -n "${NBSS_KEYS_FILE:-}" ]; then
  common+=(--keys-file "$NBSS_KEYS_FILE")
else
  common+=(--fetch-grants)
fi
if [ -n "${NBSS_MODERATORS:-}" ]; then
  common+=(--moderators "$NBSS_MODERATORS")
fi
if [ -n "${NBSS_WORKERS:-}" ]; then
  common+=(--workers "$NBSS_WORKERS")
fi
if [ -n "${NBSS_ZONE_CONFIG:-}" ]; then
  common+=(--zone-config "$NBSS_ZONE_CONFIG")
fi

# Run the builder within what is left of the budget; its JSON report goes to
# the log (counts only, never text or keys). Sets `rc` and `out`.
run() {
  local left=$((deadline - $(date +%s)))
  if [ "$left" -le 0 ]; then
    say "out of time before: $*"
    exit 11
  fi
  set +e
  out="$(timeout --kill-after=30 "$left" "$bin" "$@" "${common[@]}" 2>>"$log")"
  rc=$?
  set -e
  [ -n "$out" ] && say "$1: $out"
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    say "$1 timed out"
    exit 11
  fi
}

result=0
run update
case "$rc" in
  0) ;;
  3) result=3 ;;
  *) say "update failed with exit $rc"; exit "$rc" ;;
esac

run status --field partial_pairs
[ "$rc" -eq 0 ] || { say "status failed with exit $rc"; exit "$rc"; }
partial="$out"
run status --field excluded
[ "$rc" -eq 0 ] || { say "status failed with exit $rc"; exit "$rc"; }
excluded="$out"

if [ "$full_at" -gt 0 ] && [ "$excluded" -ge "$full_at" ]; then
  run compact --all
  [ "$rc" -eq 0 ] || { say "compact --all failed with exit $rc"; exit "$rc"; }
elif [ "$partial" -ge "$compact_at" ]; then
  run compact
  [ "$rc" -eq 0 ] || { say "compact failed with exit $rc"; exit "$rc"; }
fi

say "done (exit $result)"
exit "$result"
