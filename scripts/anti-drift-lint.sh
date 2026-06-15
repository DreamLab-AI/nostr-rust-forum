#!/usr/bin/env bash
# scripts/anti-drift-lint.sh — ADR-077 P3 anti-drift lint (forum substrate)
#
# Forum-substrate scope (post ADR-125 did:nostr Multikey convergence):
#   1. Reject the SUPERSEDED Schnorr verification-key suite identifiers in
#      emitted source. The canonical verification-method type per ADR-125
#      (superseding ADR-074 D2) is `Multikey`. The 2019 suite term
#      (SchnorrSecp256k1VerificationKey2019) — and every fabricated variant
#      (…2022 / …2025 / …2026, NostrSchnorrKey2024) — is drift when emitted.
#      NOTE: ADR-074 D1 (x-only hex = canonical identity, I4) STAYS; only the
#      2019 DID-doc shape (D2) is superseded.
#   1b. Reject malformed publicKeyMultibase forms:
#         - the missing-parity `fe701` + 64 hex (67-char) form  → must carry
#           the `02` even-y parity byte (`fe70102` + 64 hex, 71 chars), C1/C2;
#         - uppercase hex under an `f` base16-lower indicator    → C2/C3;
#         - the legacy `z`+base58btc form                        → superseded.
#   2. Reject construction of arbitrary `did:nostr:...` DID DOCUMENTS outside
#      crates/nostr-bbs-core/ and crates/nostr-bbs-pod-worker/src/did.rs
#      (the canonical DID-Doc rendering sites). did:nostr URI references
#      (auth, ACL agent fields) are fine — the I1 string is unchanged.
#   3. Reject re-introduction of branded operator strings (DreamLab) in kit
#      source — operators must inject branding via forum-config/ overlay,
#      not hardcode it back into the substrate.
#
# Exit code 0 = clean, 1 = drift detected.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

EXIT=0

# --- Rule 1: superseded Schnorr verification suite identifiers -------------
# Match string-literal occurrences only (preceded + followed by quote).
# Post ADR-125 the canonical VM type is `Multikey`; ALL SchnorrSecp256k1…
# suite identifiers (2019 included) plus NostrSchnorrKey2024 are superseded
# when EMITTED. Exclude:
#   - negative test assertions (assert_ne! proving the canonical type is NOT a
#     superseded suite)
#   - test fixture JSON files (which carry superseded identifiers as negative
#     vectors)
#   - test source files under tests/ directories
STALE_SUITES=$(
  grep -RIn \
    --include='*.rs' --include='*.js' --include='*.ts' --include='*.json' \
    -E '["'"'"'](NostrSchnorrKey2024|SchnorrSecp256k1VerificationKey20(19|2[245]|26))["'"'"']' \
    crates 2>/dev/null \
    | grep -v '/target/' \
    | grep -v 'node_modules' \
    | grep -v '/scripts/anti-drift-lint.sh' \
    | grep -v 'assert_ne!' \
    | grep -v 'contains_key' \
    | grep -v '/tests/' \
    | grep -v '/fixtures/' \
    | grep -v '\.jsonld' \
    || true
)

if [ -n "$STALE_SUITES" ]; then
  echo "::error::ADR-125 (supersedes ADR-074 D2): superseded Schnorr verification suite identifier emitted in source."
  echo "Canonical verification-method type: Multikey"
  echo "$STALE_SUITES"
  EXIT=1
fi

# --- Rule 1b: malformed publicKeyMultibase forms ---------------------------
# Canonical did:nostr Multikey multibase (ADR-125 §2.1, C1/C2/C3):
#   "fe70102" + 64 lowercase hex  (71 chars total)
#     f      = base16-lower multibase indicator
#     e701   = unsigned-varint(0xe7) = secp256k1-pub multicodec
#     02     = SEC1 compressed even-y parity byte (load-bearing payload)
#     <hex>  = 32-byte x-only key, == the did:nostr:<hex> body
# Reject, in emitted (non-test, non-fixture) source:
#   - the missing-parity 67-char form: fe701 immediately followed by 64 hex;
#   - uppercase hex under an 'f' indicator;
#   - the legacy z+base58btc form for a schnorr/nostr key.
MULTIBASE_DRIFT=$(
  grep -RIn \
    --include='*.rs' --include='*.js' --include='*.ts' --include='*.json' \
    -E 'fe701[0-9a-f]{64}([^0-9a-f]|$)|fe70102[0-9A-F]*[A-F][0-9A-Fa-f]*|fe701[0-9A-F]{2,}[A-F]' \
    crates 2>/dev/null \
    | grep -v '/target/' \
    | grep -v 'node_modules' \
    | grep -v '/scripts/anti-drift-lint.sh' \
    | grep -v '/tests/' \
    | grep -v '/fixtures/' \
    || true
)

# Legacy z+base58 multibase emitted next to a verificationMethod/schnorr site.
LEGACY_Z_MULTIBASE=$(
  grep -RIn \
    --include='*.rs' --include='*.js' --include='*.ts' \
    -E "(publicKeyMultibase|format_multibase).*['\"]z" \
    crates 2>/dev/null \
    | grep -v '/target/' \
    | grep -v 'node_modules' \
    | grep -v '/scripts/anti-drift-lint.sh' \
    | grep -v '/tests/' \
    | grep -v '/fixtures/' \
    || true
)

if [ -n "$MULTIBASE_DRIFT" ] || [ -n "$LEGACY_Z_MULTIBASE" ]; then
  echo "::error::ADR-125 C1/C2/C3: malformed publicKeyMultibase. Canonical form is fe70102 + 64 lowercase hex (71 chars)."
  echo "  - missing 0x02 parity byte (fe701 + 64 hex = 67 chars) is WRONG;"
  echo "  - uppercase hex under an 'f' indicator is WRONG;"
  echo "  - z+base58btc is superseded."
  [ -n "$MULTIBASE_DRIFT" ] && echo "$MULTIBASE_DRIFT"
  [ -n "$LEGACY_Z_MULTIBASE" ] && echo "$LEGACY_Z_MULTIBASE"
  EXIT=1
fi

# --- Rule 2: ad-hoc DID-Doc emission outside canonical sites ---------------
# Forum has many legitimate did:nostr:<pk> URI references (auth, ACL agent
# fields, etc.) so we don't reject did:nostr URI construction wholesale.
# Instead we look for the strong drift signal: any source file outside the
# canonical DID Document renderer that constructs a JSON object containing
# both `verificationMethod` AND a verification-method TYPE (the canonical
# `Multikey`, or any superseded SchnorrSecp256k1… suite) — that is the shape
# of a hand-rolled DID Document and ALL such sites must use the canonical
# renderer at crates/pod-worker/src/did.rs (or nostr-core).
HANDROLL_DIDDOC=$(
  grep -RInl --include='*.rs' --include='*.js' \
    -E 'verificationMethod' \
    crates 2>/dev/null \
    | xargs -I{} grep -lE "SchnorrSecp256k1VerificationKey|[\"']Multikey[\"']" {} 2>/dev/null \
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
