#!/usr/bin/env bash
# Package a repo's high-value code + metadata into a single review blob.
# Usage: package-repo.sh <repo_path> <output_file> [max_chars]
# Targets ~800K tokens ≈ ~3.2M chars (4 chars/token average for code)

set -uo pipefail

REPO="$1"
OUTPUT="$2"
MAX_CHARS="${3:-3200000}"
REPO_NAME=$(basename "$REPO")

# Temp working file
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

echo "=== Packaging $REPO_NAME from $REPO ==="

# Priority tiers (processed in order, stop when budget exhausted):
#
# T1: Metadata + config (Cargo.toml, package.json, wrangler.toml, ADRs, PRDs, CLAUDE.md)
# T2: Core source (*.rs, *.ts, *.tsx, *.js excluding tests/node_modules/vendor)
# T3: Infrastructure (Dockerfile, docker-compose, flake.nix, CI configs)
# T4: Tests (*.test.*, *_tests.rs, tests/ dirs)
# T5: Documentation (*.md excluding node_modules)

write_header() {
  echo "" >> "$TMP"
  echo "================================================================================" >> "$TMP"
  echo "FILE: $1" >> "$TMP"
  echo "================================================================================" >> "$TMP"
}

current_chars() {
  wc -c < "$TMP"
}

budget_ok() {
  local cur
  cur=$(current_chars)
  [[ $cur -lt $MAX_CHARS ]]
}

add_file() {
  local f="$1"
  local rel="${f#$REPO/}"
  local fsize
  fsize=$(wc -c < "$f" 2>/dev/null || echo 0)

  # Skip files > 200KB individually (likely generated/vendored)
  if [[ $fsize -gt 200000 ]]; then
    echo "  SKIP (>200KB): $rel" >&2
    return
  fi

  # Skip binary files
  if file "$f" 2>/dev/null | grep -q "binary\|executable\|image\|archive"; then
    return
  fi

  if budget_ok; then
    write_header "$rel"
    cat "$f" >> "$TMP" 2>/dev/null || true
  fi
}

# Exclusion patterns for find
EXCLUDE=(-not -path "*/node_modules/*" \
         -not -path "*/target/*" \
         -not -path "*/.git/*" \
         -not -path "*/dist/*" \
         -not -path "*/build/*" \
         -not -path "*/.next/*" \
         -not -path "*/vendor/*" \
         -not -path "*/__pycache__/*" \
         -not -path "*/.cache/*" \
         -not -path "*/backups/*" \
         -not -path "*/cleaned/*" \
         -not -path "*/.vscode/*" \
         -not -path "*/Cargo.lock" \
         -not -path "*/package-lock.json" \
         -not -path "*/flake.lock" \
         -not -path "*/*.rvf" \
         -not -path "*/*.rvf.lock" \
         -not -path "*/*.jpg" \
         -not -path "*/*.png" \
         -not -path "*/*.gif" \
         -not -path "*/*.ico" \
         -not -path "*/*.woff*" \
         -not -path "*/*.ttf" \
         -not -path "*/*.svg" \
         -not -path "*/*.wasm" \
         -not -path "*/*.so" \
         -not -path "*/*.o" \
         -not -path "*/*.a" \
         -not -path "*/*.map")

# Write preamble
cat >> "$TMP" << EOF
================================================================================
PROJECT: $REPO_NAME
PACKAGED: $(date -u +%Y-%m-%dT%H:%M:%SZ)
PURPOSE: Code review blob for cross-ecosystem analysis
================================================================================

EOF

echo "--- T1: Metadata + Config ---" >&2

# T1a: Root config files
for pat in Cargo.toml package.json wrangler.toml tsconfig.json flake.nix \
           deny.toml config.yml agentbox.toml CLAUDE.md README.md CHANGELOG.md \
           build.rs Dockerfile.dev Dockerfile.production docker-compose.yml; do
  f="$REPO/$pat"
  [[ -f "$f" ]] && add_file "$f"
done

# T1b: Nested Cargo.toml / wrangler.toml / package.json
find "$REPO" -maxdepth 4 "${EXCLUDE[@]}" \
  \( -name "Cargo.toml" -o -name "wrangler.toml" -o -name "package.json" \) \
  -not -path "$REPO/Cargo.toml" -not -path "$REPO/package.json" \
  -type f | sort | while read -r f; do add_file "$f"; done

# T1c: ADRs and PRDs
find "$REPO" -maxdepth 5 "${EXCLUDE[@]}" \
  \( -path "*/adr/*" -o -path "*/ADR/*" -o -path "*/prd/*" -o -path "*/PRD/*" \
     -o -path "*/decisions/*" \) \
  -name "*.md" -type f | sort | while read -r f; do
  budget_ok && add_file "$f"
done

# T1d: Skills metadata
find "$REPO" -maxdepth 5 "${EXCLUDE[@]}" \
  -name "SKILL.md" -type f | sort | while read -r f; do
  budget_ok && add_file "$f"
done

echo "  T1 done: $(current_chars) chars" >&2

echo "--- T2: Core Source ---" >&2

# T2: Source code (excluding tests initially)
find "$REPO" "${EXCLUDE[@]}" \
  \( -name "*.rs" -o -name "*.ts" -o -name "*.tsx" -o -name "*.js" \
     -o -name "*.cu" -o -name "*.cuh" -o -name "*.py" \
     -o -name "*.toml" -o -name "*.sql" \) \
  -not -name "*.test.*" -not -name "*_test.*" -not -name "*_tests.*" \
  -not -path "*/tests/*" -not -path "*/test/*" -not -path "*/__tests__/*" \
  -not -path "*/fixtures/*" \
  -type f | sort | while read -r f; do
  budget_ok && add_file "$f"
done

echo "  T2 done: $(current_chars) chars" >&2

echo "--- T3: Infrastructure ---" >&2

# T3: CI, Docker, Nix
find "$REPO" -maxdepth 4 "${EXCLUDE[@]}" \
  \( -name "Dockerfile*" -o -name "docker-compose*" -o -name "*.nix" \
     -o -name "*.yml" -o -name "*.yaml" \) \
  -not -path "$REPO/docker-compose.yml" \
  -not -path "$REPO/Dockerfile.*" \
  -type f | sort | while read -r f; do
  budget_ok && add_file "$f"
done

echo "  T3 done: $(current_chars) chars" >&2

echo "--- T4: Tests ---" >&2

# T4: Test files
find "$REPO" "${EXCLUDE[@]}" \
  \( -name "*.test.*" -o -name "*_test.*" -o -name "*_tests.*" \
     -o -path "*/tests/*.rs" -o -path "*/test/*.ts" -o -path "*/__tests__/*" \) \
  -type f | sort | while read -r f; do
  budget_ok && add_file "$f"
done

echo "  T4 done: $(current_chars) chars" >&2

echo "--- T5: Documentation ---" >&2

# T5: Remaining markdown docs
find "$REPO" -maxdepth 4 "${EXCLUDE[@]}" \
  -name "*.md" -type f \
  -not -name "README.md" -not -name "CHANGELOG.md" -not -name "CLAUDE.md" \
  -not -path "*/adr/*" -not -path "*/ADR/*" -not -path "*/prd/*" \
  -not -path "*/PRD/*" -not -path "*/decisions/*" -not -name "SKILL.md" \
  | sort | while read -r f; do
  budget_ok && add_file "$f"
done

echo "  T5 done: $(current_chars) chars" >&2

# Final stats
TOTAL_CHARS=$(current_chars)
EST_TOKENS=$((TOTAL_CHARS / 4))
echo "" >&2
echo "=== $REPO_NAME COMPLETE ===" >&2
echo "  Total chars: $TOTAL_CHARS" >&2
echo "  Est tokens:  ~${EST_TOKENS}" >&2
echo "  Output:      $OUTPUT" >&2

cp "$TMP" "$OUTPUT"
