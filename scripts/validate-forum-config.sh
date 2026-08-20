#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${1:-$REPO_ROOT/forum.toml}"

cargo run --quiet --manifest-path "$REPO_ROOT/Cargo.toml" \
  -p nostr-bbs-config --bin validate-forum-config -- "$CONFIG_PATH"
