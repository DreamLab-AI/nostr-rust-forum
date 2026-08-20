#!/usr/bin/env bash
set -euo pipefail

# Every exception is reviewed in docs/security/advisory-exceptions.md. Keep
# this list aligned with deny.toml; cargo-audit has no shared config format.
cargo audit --deny warnings \
  --ignore RUSTSEC-2025-0141 \
  --ignore RUSTSEC-2024-0384 \
  --ignore RUSTSEC-2024-0436 \
  --ignore RUSTSEC-2026-0097 \
  --ignore RUSTSEC-2026-0173 \
  --ignore RUSTSEC-2026-0221
