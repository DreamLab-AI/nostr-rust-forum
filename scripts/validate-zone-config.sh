#!/usr/bin/env bash
# Check a deployed ZONE_CONFIG JSON file (ADR-2037 channel pins) before it is
# rendered into the workers' bindings. Usage: scripts/validate-zone-config.sh <file>
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

cargo run --quiet --manifest-path "$REPO_ROOT/Cargo.toml" \
  -p nostr-bbs-config --bin validate-zone-config -- "${1:?usage: validate-zone-config.sh <ZONE_CONFIG json file>}"
