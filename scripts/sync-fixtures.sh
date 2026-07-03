#!/usr/bin/env bash
# scripts/sync-fixtures.sh — nostr-rust-forum (forum kit) substrate
#
# Per ADR-082 D5: the forum substrate consumes cross-substrate fixtures from
# VisionClaw (the master host). This script clones VisionClaw, copies
# tests/fixtures/ into tests/fixtures/ at the workspace root, and writes
# CHECKSUM.txt for CI drift detection.
#
# Canonical source path: VisionClaw's fixtures were relocated from
# tests/fixtures/ to tests/fixtures/ on 2026-06-29 (VisionClaw commit
# 031f539a5, clean-room documentation rebuild). This script tracks that move.
#
# Usage:
#   scripts/sync-fixtures.sh                    # full sync
#   scripts/sync-fixtures.sh --verify           # CI gate: exit non-zero on drift
#   VISIONCLAW_FIXTURES_PATH=/local/path \
#     scripts/sync-fixtures.sh                  # offline / local-monorepo dev
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="$REPO_ROOT/tests/fixtures"
SOURCE="${VISIONCLAW_FIXTURES_PATH:-https://github.com/DreamLab-AI/VisionClaw.git}"

mkdir -p "$TARGET_DIR"

case "${1:-}" in
  --verify)
    if [ ! -f "$TARGET_DIR/CHECKSUM.txt" ]; then
      echo "ERROR: $TARGET_DIR/CHECKSUM.txt missing — run sync-fixtures.sh first" >&2
      exit 1
    fi
    cd "$TARGET_DIR"
    sha256sum -c CHECKSUM.txt --quiet
    echo "OK: $(wc -l < CHECKSUM.txt) fixture file(s) match recorded checksums."
    exit 0
    ;;
esac

if [[ "$SOURCE" =~ ^https://.*\.git$ ]]; then
  TMPDIR=$(mktemp -d)
  trap "rm -rf $TMPDIR" EXIT
  git clone --depth=1 --filter=blob:none --sparse --quiet "$SOURCE" "$TMPDIR"
  (cd "$TMPDIR" && git sparse-checkout add tests/fixtures)
  # Use cp if rsync is not available
  if command -v rsync &>/dev/null; then
    rsync -a --delete \
      --exclude='CHECKSUM.txt' --exclude='CHECKSUMS.txt' \
      --exclude='mod.rs' --exclude='data-model' --exclude='ontology' --exclude='ontologies' \
      "$TMPDIR/tests/fixtures/" "$TARGET_DIR/"
  else
    rm -rf "$TARGET_DIR"/*.json "$TARGET_DIR"/*.md "$TARGET_DIR"/*.txt "$TARGET_DIR"/schemas 2>/dev/null
    mkdir -p "$TARGET_DIR/schemas"
    cp -a "$TMPDIR/tests/fixtures/"*.json "$TMPDIR/tests/fixtures/"*.md "$TMPDIR/tests/fixtures/"*.txt "$TARGET_DIR/" 2>/dev/null || true
    cp -a "$TMPDIR/tests/fixtures/schemas/"* "$TARGET_DIR/schemas/" 2>/dev/null || true
  fi
else
  if [ ! -d "$SOURCE/tests/fixtures" ]; then
    echo "ERROR: VISIONCLAW_FIXTURES_PATH=$SOURCE has no tests/fixtures/" >&2
    exit 1
  fi
  if command -v rsync &>/dev/null; then
    rsync -a --delete \
      --exclude='CHECKSUM.txt' --exclude='CHECKSUMS.txt' \
      --exclude='mod.rs' --exclude='data-model' --exclude='ontology' --exclude='ontologies' \
      "$SOURCE/tests/fixtures/" "$TARGET_DIR/"
  else
    rm -rf "$TARGET_DIR"/*.json "$TARGET_DIR"/*.md "$TARGET_DIR"/*.txt "$TARGET_DIR"/schemas 2>/dev/null
    mkdir -p "$TARGET_DIR/schemas"
    cp -a "$SOURCE/tests/fixtures/"*.json "$SOURCE/tests/fixtures/"*.md "$SOURCE/tests/fixtures/"*.txt "$TARGET_DIR/" 2>/dev/null || true
    cp -a "$SOURCE/tests/fixtures/schemas/"* "$TARGET_DIR/schemas/" 2>/dev/null || true
  fi
fi

cd "$TARGET_DIR"
sha256sum *.json README.md UPSTREAM_PINS.md COVERAGE_MATRIX.md \
  $(find schemas -type f 2>/dev/null) > CHECKSUM.txt

echo "Synced $(wc -l < CHECKSUM.txt) fixture file(s) into $TARGET_DIR"
echo "Run 'scripts/sync-fixtures.sh --verify' in CI to detect drift."
