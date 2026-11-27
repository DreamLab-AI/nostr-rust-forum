#!/usr/bin/env bash
# Tests for scripts/sealed-search-nightly.sh against a stub builder: the
# compaction decision, exit codes, the lock, the timeout and the config
# checks. No network, no keys of any value.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
job="$root/scripts/sealed-search-nightly.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0

# The stub logs its subcommand and answers from environment variables.
cat >"$tmp/builder" <<'STUB'
#!/usr/bin/env bash
sub="$1"; shift
printf '%s %s\n' "$sub" "$*" >>"$STUB_LOG"
case "$sub" in
  update) [ -n "${STUB_SLEEP:-}" ] && sleep "$STUB_SLEEP"; echo '{"mode":"update"}'; exit "${STUB_UPDATE_RC:-0}" ;;
  status)
    case "$*" in
      *"--field partial_pairs"*) echo "${STUB_PARTIAL:-0}" ;;
      *"--field excluded"*) echo "${STUB_EXCLUDED:-0}" ;;
    esac ;;
  compact) echo '{"mode":"compact"}'; exit "${STUB_COMPACT_RC:-0}" ;;
esac
exit 0
STUB
chmod 700 "$tmp/builder"
printf '%s' "$(printf '7f%.0s' $(seq 1 32))" >"$tmp/key"
chmod 600 "$tmp/key"

write_config() {
  cat >"$tmp/zone.env" <<EOF
NBSS_BIN=$tmp/builder
NBSS_ZONE=zone2
NBSS_RELAY=ws://127.0.0.1:1
NBSS_POD_DIR=$tmp/pods
NBSS_PUBLISHERS=$(printf 'a%.0s' $(seq 1 64))
NBSS_KEY_FILE=$tmp/key
NBSS_STATE_DIR=$tmp/state
NBSS_MODEL_DIR=$tmp/model
NBSS_MODEL_Q8=$tmp/model/q8.gguf
NBSS_COMPACT_AT=3
NBSS_TIMEOUT=${1:-60}
EOF
  chmod 600 "$tmp/zone.env"
}

check() {
  local name="$1" want="$2" got="$3"
  if [ "$want" = "$got" ]; then
    printf 'ok   %s\n' "$name"
  else
    printf 'FAIL %s: want %s, got %s\n' "$name" "$want" "$got"
    fails=$((fails + 1))
  fi
}

run_job() {
  export STUB_LOG="$tmp/calls"
  : >"$STUB_LOG"
  set +e
  "$job" "$tmp/zone.env"
  rc=$?
  set -e
}

write_config

STUB_PARTIAL=1 run_job
check "quiet night: exit 0" 0 "$rc"
check "quiet night: no compaction" 0 "$(grep -c '^compact' "$tmp/calls" || true)"
check "every call passes the key as a path" "$(wc -l <"$tmp/calls")" "$(grep -c -- "--key-file $tmp/key" "$tmp/calls")"
check "no key material in argv" 0 "$(grep -c '7f7f' "$tmp/calls" || true)"

STUB_PARTIAL=3 run_job
check "enough partial pairs: compaction runs" 1 "$(grep -c '^compact' "$tmp/calls" || true)"
check "compaction is partial" 0 "$(grep -c '^compact.*--all' "$tmp/calls" || true)"

STUB_UPDATE_RC=3 STUB_PARTIAL=0 run_job
check "held-back posts: exit 3" 3 "$rc"

STUB_UPDATE_RC=6 STUB_PARTIAL=9 run_job
check "rollback refusal propagates" 6 "$rc"
check "no compaction after a refusal" 0 "$(grep -c '^compact' "$tmp/calls" || true)"

STUB_PARTIAL=9 STUB_COMPACT_RC=5 run_job
check "compaction refusal propagates" 5 "$rc"

sed -i 's/^NBSS_COMPACT_AT=3$/NBSS_COMPACT_AT=3\nNBSS_FULL_COMPACT_EXCLUDED_AT=10/' "$tmp/zone.env"
STUB_PARTIAL=0 STUB_EXCLUDED=12 run_job
check "many exclusions: compact --all" 1 "$(grep -c '^compact.*--all' "$tmp/calls" || true)"
write_config

# The lock: a second run while one holds it.
mkdir -p "$tmp/state"
exec 8>"$tmp/state/zone2.lock"
flock -n 8
run_job
check "lock held: exit 10" 10 "$rc"
exec 8>&-

# The budget.
write_config 1
STUB_SLEEP=5 run_job
check "timeout: exit 11" 11 "$rc"
write_config

# Config checks.
chmod 666 "$tmp/zone.env"
run_job
check "config writable by others: exit 12" 12 "$rc"
chmod 600 "$tmp/zone.env"
chmod 644 "$tmp/key"
run_job
check "key file readable by others: exit 12" 12 "$rc"
chmod 600 "$tmp/key"
sed -i '/^NBSS_ZONE=/d' "$tmp/zone.env"
run_job
check "missing zone: exit 12" 12 "$rc"
write_config

# The zone-key file holds zone secrets: owner-only too.
printf '{}' >"$tmp/zonekeys.json"
chmod 644 "$tmp/zonekeys.json"
printf 'NBSS_KEYS_FILE=%s\n' "$tmp/zonekeys.json" >>"$tmp/zone.env"
run_job
check "zone-key file readable by others: exit 12" 12 "$rc"
chmod 600 "$tmp/zonekeys.json"
run_job
check "zone-key file 0600: runs" 0 "$rc"
write_config

# A config in a directory others can write could be swapped for theirs.
mkdir -p "$tmp/shared"
cp "$tmp/zone.env" "$tmp/shared/zone.env"
chmod 600 "$tmp/shared/zone.env"
chmod 777 "$tmp/shared"
export STUB_LOG="$tmp/calls"
set +e
"$job" "$tmp/shared/zone.env" 2>/dev/null
rc=$?
set -e
check "config in a world-writable directory: exit 12" 12 "$rc"
chmod 700 "$tmp/shared"

# By default the exclusion list is emptied by compact --all well before its cap.
STUB_PARTIAL=0 STUB_EXCLUDED=4096 run_job
check "default: compact --all at 4096 exclusions" 1 "$(grep -c '^compact.*--all' "$tmp/calls" || true)"
STUB_PARTIAL=0 STUB_EXCLUDED=4095 run_job
check "default: no compaction below it" 0 "$(grep -c '^compact' "$tmp/calls" || true)"

[ "$fails" -eq 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }
