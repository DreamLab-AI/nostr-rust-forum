#!/usr/bin/env bash
# Print the locked version of each watched crate and compare it with the latest
# crates.io release. Informational only: always exits 0, and degrades to a
# warning when offline or when the registry cannot be reached.
#
# Usage: scripts/ci/dep-watchlist.sh [lockfile] [watchlist]
set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lock="${1:-$root/Cargo.lock}"
list="${2:-$root/scripts/ci/dep-watchlist.txt}"

latest_version() {
  curl -fsS --max-time 10 -A "nostr-rust-forum-dep-watchlist" \
    "https://crates.io/api/v1/crates/$1" 2>/dev/null \
    | grep -o '"max_stable_version":"[^"]*"' | head -n1 | cut -d'"' -f4
}

printf '%-14s %-12s %-12s %s\n' crate locked latest status
while IFS= read -r crate; do
  crate="${crate%%#*}"; crate="$(echo "$crate" | tr -d '[:space:]')"
  [ -z "$crate" ] && continue
  locked="$(grep -A1 -x "name = \"$crate\"" "$lock" | sed -n 's/^version = "\(.*\)"$/\1/p' | sort -uV | paste -sd, -)"
  if [ -z "$locked" ]; then
    printf '%-14s %-12s %-12s %s\n' "$crate" "-" "-" "not in lockfile"
    continue
  fi
  latest="$(latest_version "$crate")"
  if [ -z "$latest" ]; then
    printf '%-14s %-12s %-12s %s\n' "$crate" "$locked" "?" "unknown"
    echo "::warning::dep-watchlist: could not reach crates.io for $crate (offline?); skipping comparison"
  elif [ "$locked" = "$latest" ]; then
    printf '%-14s %-12s %-12s %s\n' "$crate" "$locked" "$latest" "current"
  else
    printf '%-14s %-12s %-12s %s\n' "$crate" "$locked" "$latest" "BEHIND"
    echo "::warning::dep-watchlist: $crate locked at $locked, latest is $latest"
  fi
done < "$list"
exit 0
