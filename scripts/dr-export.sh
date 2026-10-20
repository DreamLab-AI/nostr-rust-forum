#!/usr/bin/env bash
# dr-export.sh - SAFE-READ disaster-recovery export of both D1 databases.
#
# Usage: scripts/dr-export.sh <backup-root>
#
# Writes <backup-root>/<UTC timestamp>/{relay.sql,auth.sql,SHA256SUMS,bookmarks.txt}.
# Only read operations are issued: `d1 export --remote` and `d1 time-travel info`.
# Refuses to run if <backup-root> is inside the repository (backups hold personal
# data and must never be committable). Output never prints row content.
set -euo pipefail

if [[ $# -ne 1 || -z "${1:-}" ]]; then
  echo "usage: $0 <backup-root>" >&2
  exit 64
fi

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
root="$(realpath -m -- "$1")"
if [[ "$root" == "$repo" || "$root" == "$repo"/* ]]; then
  echo "refusing: $root is inside the repository $repo" >&2
  exit 65
fi

# This config binds both databases by immutable UUID, so the live account names
# (dreamlab-relay / dreamlab-auth) and the config names (nostr-bbs-*) both resolve.
cfg="$repo/crates/nostr-bbs-relay-worker/wrangler.toml"
[[ -f "$cfg" ]] || { echo "missing $cfg" >&2; exit 66; }

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
dest="$root/$stamp"
mkdir -p -- "$dest"
chmod 700 -- "$dest"

bookmark() {
  # wrangler has no --json for time-travel info; extract the quoted bookmark.
  # Under `set -e` a failing pipeline inside $(...) would exit the script
  # silently, so capture status explicitly and surface wrangler's own text.
  local out bm
  if ! out="$(wrangler d1 time-travel info "$1" --config "$cfg" 2>&1)"; then
    printf 'could not read Time Travel bookmark for %s:\n%s\n' "$1" "$out" >&2
    return 1
  fi
  bm="$(grep -o "current bookmark is '[^']*'" <<<"$out" | sed "s/.*'\(.*\)'/\1/" || true)"
  if [ -z "$bm" ]; then
    printf 'could not parse Time Travel bookmark for %s from:\n%s\n' "$1" "$out" >&2
    return 1
  fi
  printf '%s\n' "$bm"
}

: >"$dest/bookmarks.txt"
for pair in "relay:nostr-bbs-relay" "auth:nostr-bbs-auth"; do
  label="${pair%%:*}"
  db="${pair#*:}"
  before="$(bookmark "$db")"
  [[ -n "$before" ]] || { echo "could not read Time Travel bookmark for $db" >&2; exit 1; }
  wrangler d1 export "$db" --remote --config "$cfg" --output "$dest/$label.sql" >/dev/null
  after="$(bookmark "$db")"
  printf '%s before=%s after=%s\n' "$db" "$before" "$after" >>"$dest/bookmarks.txt"
  if [[ "$before" != "$after" ]]; then
    echo "note: $db changed during export; restore point is the 'before' bookmark" >&2
  fi
done

(cd -- "$dest" && sha256sum relay.sql auth.sql >SHA256SUMS)
echo "export directory: $dest"
cat -- "$dest/SHA256SUMS"
cat -- "$dest/bookmarks.txt"
