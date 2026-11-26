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
  --ignore RUSTSEC-2026-0221 \
  --ignore RUSTSEC-2026-0543 \
  --ignore RUSTSEC-2026-0367 \
  --ignore RUSTSEC-2026-0368 \
  --ignore RUSTSEC-2026-0369 \
  --ignore RUSTSEC-2026-0429 \
  --ignore RUSTSEC-2026-0545 \
  --ignore RUSTSEC-2026-0546 \
  --ignore RUSTSEC-2026-0547 \
  --ignore RUSTSEC-2026-0548 \
  --ignore RUSTSEC-2026-0374 \
  --ignore RUSTSEC-2026-0253 \
  --ignore RUSTSEC-2026-0002
