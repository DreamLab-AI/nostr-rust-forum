#!/usr/bin/env bash
# scripts/anti-drift-lint.sh — ADR-077 P3 anti-drift lint (forum substrate)
#
# Forum-substrate scope:
#   1. Reject hand-rolled stale Schnorr verification key suite identifiers
#      (NostrSchnorrKey2024, SchnorrSecp256k1VerificationKey2022 / 2025). The
#      canonical identifier per ADR-074 D1 is
#      SchnorrSecp256k1VerificationKey2019.
#   2. Reject construction of arbitrary `did:nostr:...` strings outside
#      crates/nostr-bbs-core/ and crates/nostr-bbs-pod-worker/src/did.rs
#      (the canonical DID-Doc rendering sites).
#   3. Reject re-introduction of branded operator strings (DreamLab) in kit
#      source — operators must inject branding via forum-config/ overlay,
#      not hardcode it back into the substrate.
#
# Exit code 0 = clean, 1 = drift detected.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

EXIT=0

# --- Rule 1: stale Schnorr verification suite identifiers ------------------
# Match string-literal occurrences only (preceded + followed by quote).
STALE_SUITES=$(
  grep -RIn \
    --include='*.rs' --include='*.js' --include='*.ts' --include='*.json' \
    -E '["'"'"'](NostrSchnorrKey2024|SchnorrSecp256k1VerificationKey20(2[245]|26))["'"'"']' \
    crates 2>/dev/null \
    | grep -v '/target/' \
    | grep -v 'node_modules' \
    | grep -v '/scripts/anti-drift-lint.sh' \
    || true
)

if [ -n "$STALE_SUITES" ]; then
  echo "::error::ADR-074 D1: stale Schnorr verification suite identifier in source."
  echo "Canonical: SchnorrSecp256k1VerificationKey2019"
  echo "$STALE_SUITES"
  EXIT=1
fi

# --- Rule 2: ad-hoc DID-Doc emission outside canonical sites ---------------
# Forum has many legitimate did:nostr:<pk> URI references (auth, ACL agent
# fields, etc.) so we don't reject did:nostr URI construction wholesale.
# Instead we look for the strong drift signal: any source file outside the
# canonical DID Document renderer that constructs a JSON object containing
# both `verificationMethod` AND a Schnorr suite type — that is the shape of
# a hand-rolled DID Document and ALL such sites must use the canonical
# renderer at crates/pod-worker/src/did.rs (or nostr-core).
HANDROLL_DIDDOC=$(
  grep -RInl --include='*.rs' --include='*.js' \
    -E 'verificationMethod' \
    crates 2>/dev/null \
    | xargs -I{} grep -l "SchnorrSecp256k1VerificationKey" {} 2>/dev/null \
    | grep -v 'crates/nostr-bbs-pod-worker/src/did.rs' \
    | grep -v 'crates/nostr-bbs-core/' \
    | grep -v '/tests?/' \
    || true
)

if [ -n "$HANDROLL_DIDDOC" ]; then
  echo "::error::ADR-074 D1 + ADR-077 P3: hand-rolled DID Document emitter detected."
  echo "Use the canonical renderer at crates/nostr-bbs-pod-worker/src/did.rs."
  echo "$HANDROLL_DIDDOC"
  EXIT=1
fi

# --- Rule 3: branded operator strings re-introduced into substrate --------
# Operators must inject branding via forum-config/, not hardcode it back into
# the substrate crates. The kit-repo URL in NIP-11 is allowlisted.
BRANDED_RES=$(
  grep -RIn \
    --include='*.rs' --include='*.toml' --include='*.html' --include='*.css' --include='*.js' \
    -E '\bDreamLab\b|\bdreamlab\b|\bminimoonoir\b' \
    crates 2>/dev/null \
    | grep -v '/target/' \
    | grep -v 'node_modules' \
    | grep -v 'github\.com/DreamLab-AI/nostr-rust-forum' \
    || true
)

if [ -n "$BRANDED_RES" ]; then
  echo "::error::ADR-085 + PRD-012 X1: branded operator strings detected in kit substrate."
  echo "Move branding into the forum-config/ overlay, not the kit crates."
  echo "$BRANDED_RES"
  EXIT=1
fi

if [ $EXIT -eq 0 ]; then
  echo "anti-drift lint (forum): clean."
fi
exit $EXIT
