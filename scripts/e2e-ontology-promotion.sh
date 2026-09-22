#!/usr/bin/env bash
# ADR-2013 / PRD-sovereign-corpus acceptance 4 — the ontology promotion loop,
# end to end, on real code.
#
#   scripts/e2e-ontology-promotion.sh [--keep]
#
# WHAT THIS EXERCISES, and with what
#
#   1. FIXTURE   A real BIP-340-signed 31402 ActionRequest and 31403
#                ActionResponse, produced by `cargo run --example
#                ontology_promotion_fixture` — the same `nostr-bbs-core`
#                signing path the relay verifies with.
#   2. TIERING   The schema-level request is floored at tier `High` by the real
#                `governance::effective_tier` + `ontology_governance`
#                property floor, asserted on the fixture's own output.
#   3. RELAY     The local relay. `broker_cases` / `broker_decisions` /
#                `case_side_receipts` are created from the repository's OWN
#                migrations (0002, 0006, 0007) in an in-memory SQLite, and the
#                projection and expiry SQL are EXTRACTED FROM THE RUST SOURCE
#                rather than retyped — the idiom `scripts/tests/
#                test_governance_transaction.py` already uses, so the script
#                cannot drift from the worker by being edited.
#   4. APPLY     agentbox's `handleGovernanceDecision` driven with a signed
#                31403. Two modes:
#
#                STUB (default) — a stub `vault` on PATH records argv; the
#                assertion is the argv: `vault --repo <root> edit <page> --set
#                status=stable --set verified+={…} --expect docs=1,blocks=2`.
#
#                REAL (`E2E_REAL_VAULT=1`) — assertions on OUTCOMES:
#                a scratch repo (vocabulary + manifest copied read-only from
#                $E2E_VAULT_SOURCE, default ~/workspace/visionGraph; add
#                E2E_FULL_CORPUS=1 for every page) is seeded with a validated
#                draft fixture page and committed; agentbox's runVaultPropose
#                runs the real `vault propose --dry-run` at content and schema
#                level; the real 31402s are signature-verified and tiered by
#                the relay's own rule (schema ⇒ High); human 31403s bound to the
#                real case id are applied and the page is READ BACK — Promote ⇒
#                `status: stable` + one `verified` naming the human at the
#                31403 instant; Reject ⇒ sha256-identical, vault never spawned;
#                Demote ⇒ `status: deprecated`, no stamp. The ledger is the real
#                Loom façade on a scratch data dir when built (else a recording
#                HTTP stub; force with E2E_LEDGER=stub) and must hold the same
#                case id for every entry.
#   5. EXPIRY    A fixture whose `stale_after` is in the past is swept by the
#                real expiry SQL and must end `closed` with an `expired`
#                side receipt, and NO `broker_decisions` row.
#
# WHY NOT `wrangler dev`
#
#   The worker is a Durable Object over D1; `wrangler dev` needs a Cloudflare
#   session this container has no business holding, and a relay that only runs
#   with network access is a test that only runs sometimes. Executing the
#   worker's own SQL against SQLite is what the repository already does for the
#   governance transaction, and it tests the statement that actually ships.
#
# REAL-MODE KNOBS
#
#   E2E_REAL_VAULT=1     switch step 4 to the real binary and a scratch corpus
#   E2E_VAULT_BIN        the vault binary (default:
#                        ~/workspace/project/target/release/vault, else PATH)
#   E2E_VAULT_SOURCE     corpus to copy vocabulary/manifest from (READ ONLY)
#   E2E_FULL_CORPUS=1    also copy every knowledge page into the scratch repo
#   E2E_LOOM_BIN         loom-facade binary for the real ledger
#   E2E_LEDGER=stub      use the recording HTTP stub instead of Loom
#   E2E_TMP              where the scratch work dir goes (default $TMPDIR)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENTBOX_ROOT="${AGENTBOX_ROOT:-/home/devuser/workspace/project/agentbox}"
KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

WORK="$(mktemp -d "${E2E_TMP:-${TMPDIR:-/tmp}}/e2e-ontology-XXXXXX")"
cleanup() { [[ $KEEP -eq 1 ]] && { echo "artefacts kept in $WORK"; return; }; rm -rf "$WORK"; }
trap cleanup EXIT

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }
check(){ if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 — expected [$3], got [$2]"; fi; }

# ───────────────────────────────────────────────────────────────────────────
step "1. Fixture — signed 31402 / 31403 from the real signing path"

cd "$REPO_ROOT"

# scratch_git ARGS… — git inside the scratch vault repo ONLY. `git -C dir` walks
# up to the nearest enclosing repository when `dir` is not itself a repo root,
# which once committed this script's fixtures into the forum repository. Refuse
# unless the scratch dir is its own repository top level.
scratch_git() {
  local top
  top="$(git -C "$SCRATCH" rev-parse --show-toplevel 2>/dev/null || true)"
  if [[ "$(cd "$SCRATCH" && pwd -P)" != "$(cd "${top:-/nonexistent}" 2>/dev/null && pwd -P)" ]]; then
    echo "e2e: refusing git in $SCRATCH — not its own repository (top level: ${top:-none})" >&2
    return 1
  fi
  git -C "$SCRATCH" "$@"
}
cargo run -q -p nostr-bbs-core --example ontology_promotion_fixture > "$WORK/fixture.json"
python3 -c "import json,sys; json.load(open('$WORK/fixture.json'))"
ok "fixture generated and parses ($(wc -c < "$WORK/fixture.json") bytes)"

jqf() { python3 -c "
import json,sys
d=json.load(open('$WORK/fixture.json'))
for k in sys.argv[1].split('.'):
    d = d[int(k)] if k.isdigit() else d[k]
print(d if not isinstance(d,(dict,list)) else json.dumps(d))
" "$1"; }

check "the fixture's events verify (asserted inside the example)" "$(jqf schema.case_id)" "sha256:e2e-schema-case"

# ───────────────────────────────────────────────────────────────────────────
step "2. Tiering — a schema proposal is floored at High (ADR-2011/ADR-2013)"

check "schema-level effective tier"        "$(jqf schema.effective_tier)" "high"
check "the agent's own declaration stands as telemetry" "$(jqf schema.declared_tier)" "low"
check "the panel deadline matches stale_after (14d)"    "$(jqf schema.max_pending_hours)" "336"

# The unit suites are the authority for the rule; run them so a green e2e can
# never mask a red unit test of the same property.
cargo test -q -p nostr-bbs-core --lib ontology_governance > "$WORK/core-tests.txt" 2>&1 \
  && ok "nostr-bbs-core ontology_governance unit suite" \
  || { bad "nostr-bbs-core ontology_governance unit suite"; tail -20 "$WORK/core-tests.txt"; }

cargo test -q -p nostr-bbs-relay-worker --lib ontology_governance_boundary > "$WORK/relay-tests.txt" 2>&1 \
  && ok "relay-worker ontology boundary suite" \
  || { bad "relay-worker ontology boundary suite"; tail -20 "$WORK/relay-tests.txt"; }

# ───────────────────────────────────────────────────────────────────────────
step "3. Relay — projection and expiry against the worker's own SQL"

# A crash here must FAIL, not vanish: the reader loop below only counts lines
# that start `ok`/`FAIL`, so an unhandled traceback would otherwise be silent.
python3 - "$WORK/fixture.json" "$REPO_ROOT" <<'PY' > "$WORK/relay.out" 2>&1 \
  || echo "FAIL the relay step crashed (traceback above)" >> "$WORK/relay.out"
import json, re, sqlite3, sys
from pathlib import Path

fixture = json.load(open(sys.argv[1]))
root = Path(sys.argv[2])
now = fixture["now"]

# The schema comes from the repository's migrations, not from this script, so a
# column added there without being added here is a failure HERE.
# In migration order. It matters: 0006 ALTERs `governance_receipts`, which 0005
# creates, and 0007 ALTERs `broker_cases`, which 0002 creates. Running them out
# of order fails here exactly as it would against a real D1.
# EVERY migration, in name order — which is `wrangler d1 migrations apply`'s
# own order. Not a curated subset: 0005's foreign keys reach back to 0001's
# `events`, 0006 ALTERs 0005's `governance_receipts`, and a subset that happens
# to work today is a subset that breaks the day someone adds a dependency.
mig_dir = root / "crates/nostr-bbs-relay-worker/migrations"
MIGRATIONS = sorted(p.name for p in mig_dir.glob("*.sql"))
ddl = "".join((mig_dir / m).read_text() for m in MIGRATIONS)
db = sqlite3.connect(":memory:")
# `events` is the relay's envelope table. It lives in the Durable Object's own
# SQLite, not in D1, so no D1 migration creates it — but 0004 backfills its
# tag index FROM it. An empty shim with the columns 0004 reads is therefore
# exactly right here: the backfill runs over zero rows, as it does against a
# fresh relay, and the governance tables under test are unaffected.
db.executescript(
    "PRAGMA foreign_keys=ON;"
    "CREATE TABLE IF NOT EXISTS events ("
    "  id TEXT PRIMARY KEY, pubkey TEXT, created_at INTEGER, kind INTEGER,"
    "  tags TEXT DEFAULT '[]', content TEXT, sig TEXT);"
)
db.executescript(ddl)

def project_request(case, tier, stale_after, created_at):
    """What `project_action_request` writes. Mirrors nip_handlers.rs."""
    db.execute(
        "INSERT OR IGNORE INTO broker_cases "
        "(id, category, subject_kind, subject_id, title, summary, state, priority, "
        " created_by, nostr_event_id, created_at, updated_at, declared_tier, effective_tier, "
        " tp_verifiability, tp_reversibility, tp_stakes, calibration_sample, probe_digest, "
        " max_pending_hours, stale_after) "
        "VALUES (?,?,?,?,?,?, 'open', 50, ?,?,?,?, 'low', ?, 'partial','reversible','critical', 0, NULL, 336, ?)",
        (case["case_id"], "knowledge_enrichment", "opaque", fixture["iri"],
         "Promote " + fixture["page"], case["request"]["content"],
         case["request"]["pubkey"], case["request"]["id"], created_at, created_at,
         tier, stale_after),
    )

project_request(fixture["schema"], "high", fixture["schema"]["stale_after"], now)
project_request(fixture["expired"], "medium", fixture["expired"]["stale_after"], now - 20 * 86400)
db.commit()

results = []
def check(name, got, want):
    results.append((name, got == want, got, want))

check("schema case projected open with tier high",
      db.execute("SELECT state, effective_tier FROM broker_cases WHERE id=?",
                 (fixture["schema"]["case_id"],)).fetchone(), ("open", "high"))
check("the expiry column carries the proposal's own instant",
      db.execute("SELECT stale_after FROM broker_cases WHERE id=?",
                 (fixture["expired"]["case_id"],)).fetchone()[0],
      fixture["expired"]["stale_after"])

# ── The 31403 projection, using the worker's real SQL ──────────────────────
receipts = (root / "crates/nostr-bbs-relay-worker/src/relay_do/receipts.rs").read_text()
def sql(name):
    m = re.search(r'const ' + name + r': &str = r#"(.*?)"#;', receipts, re.S)
    assert m, f"{name} not found in receipts.rs — the script must track the worker"
    return m.group(1)

resp = fixture["schema"]["response"]
outcome = json.loads(resp["content"])
# The receipt the relay writes when it stores the signed envelope. The
# projection SQL below advances THIS row rather than inserting one, so it has
# to exist first — exactly as it does on the live path (ADR-2010).
db.execute(
    "INSERT INTO governance_receipts "
    "(event_id, kind, case_id, request_event_id, signer_pubkey, decision_outcome, "
    " stage, signed_at, accepted_at, projected_at) "
    "VALUES (?,31403,?,?,?,?, 'relay-accepted', ?, ?, NULL)",
    (resp["id"], fixture["schema"]["case_id"], fixture["schema"]["request"]["id"],
     resp["pubkey"], outcome["action"], resp["created_at"], resp["created_at"]))
db.commit()

decision_id = "dec-" + resp["id"][:16]
db.execute(sql("PROJECTION_DECISION_SQL"),
           (decision_id, fixture["schema"]["case_id"], outcome["action"], outcome["iri"],
            resp["pubkey"], outcome["reasoning"], None, resp["created_at"],
            "open", fixture["schema"]["request"]["id"], resp["id"]))
db.execute(sql("PROJECTION_CASE_SQL"), ("promoted", resp["pubkey"], resp["created_at"], fixture["schema"]["case_id"]))
db.execute(sql("PROJECTION_RECEIPT_SQL"), ("projection-committed", resp["created_at"], decision_id, resp["id"]))
db.commit()

check("the signed promote projects with its IRI as outcome_detail",
      db.execute("SELECT outcome, outcome_detail FROM broker_decisions WHERE decision_id=?",
                 (decision_id,)).fetchone(), ("promote", fixture["iri"]))
check("the promoted case reaches state 'promoted'",
      db.execute("SELECT state FROM broker_cases WHERE id=?",
                 (fixture["schema"]["case_id"],)).fetchone()[0], "promoted")

# ── The expiry sweep, using the worker's real SQL from cron.rs ─────────────
cron = (root / "crates/nostr-bbs-relay-worker/src/cron.rs").read_text()
def cron_sql(marker):
    """Pull a statement out of the Rust line-continued string literal."""
    m = re.search(r'\.prepare\(\s*"((?:[^"\\]|\\.)*' + marker + r'(?:[^"\\]|\\.)*)"', cron, re.S)
    assert m, f"no cron statement containing {marker!r}"
    return re.sub(r'\\\s*\n\s*', '', m.group(1)).replace('?1','?').replace('?2','?').replace('?3','?')

select_sql = cron_sql("stale_after IS NOT NULL")
rows = db.execute(select_sql, (now, 201)).fetchall()
check("the expiry scan finds exactly the past-due proposal", [r[0] for r in rows],
      [fixture["expired"]["case_id"]])

insert_sql = cron_sql("case_side_receipts")
update_sql = cron_sql("UPDATE broker_cases SET state")
for case_id, stale_after in rows:
    db.execute(insert_sql, (case_id, "expired", now, "proposal stale_after passed; closed without a decision"))
    db.execute(update_sql, ("closed", now, case_id))
db.commit()

check("the expired proposal carries an 'expired' side receipt",
      db.execute("SELECT stage FROM case_side_receipts WHERE case_id=?",
                 (fixture["expired"]["case_id"],)).fetchall(), [("expired",)])
check("the expired case is closed",
      db.execute("SELECT state FROM broker_cases WHERE id=?",
                 (fixture["expired"]["case_id"],)).fetchone()[0], "closed")
check("closed WITHOUT a decision — no broker_decisions row",
      db.execute("SELECT count(*) FROM broker_decisions WHERE case_id=?",
                 (fixture["expired"]["case_id"],)).fetchone()[0], 0)
check("expiry is idempotent — a second sweep re-receipts nothing",
      (db.execute(insert_sql, (fixture["expired"]["case_id"], "expired", now, "x")),
       db.execute("SELECT count(*) FROM case_side_receipts WHERE case_id=?",
                  (fixture["expired"]["case_id"],)).fetchone()[0])[1], 1)
check("the promoted case is NOT swept by expiry",
      db.execute("SELECT state FROM broker_cases WHERE id=?",
                 (fixture["schema"]["case_id"],)).fetchone()[0], "promoted")

for name, passed, got, want in results:
    print(("ok   " if passed else "FAIL ") + name + ("" if passed else f" — expected {want!r}, got {got!r}"))
PY

while IFS= read -r line; do
  case "$line" in
    ok\ *)   ok "${line#ok   }" ;;
    FAIL\ *) bad "${line#FAIL }" ;;
    *)       [[ -n "$line" ]] && printf '       %s\n' "$line" ;;
  esac
done < "$WORK/relay.out"

# ───────────────────────────────────────────────────────────────────────────
step "4. Apply — agentbox handleGovernanceDecision → vault edit"

# Read an `ok …` / `FAIL …` stream produced by an embedded driver into the
# counters. Anything else is echoed indented, so a traceback is visible.
tally() {
  while IFS= read -r line; do
    case "$line" in
      ok\ *)   ok "${line#ok   }" ;;
      FAIL\ *) bad "${line#FAIL }" ;;
      *)       [[ -n "$line" ]] && printf '       %s\n' "$line" ;;
    esac
  done < "$1"
}

TEST_PAGE="Test E2E Promotion"
TEST_IRI="urn:ngm:class:test-e2e-promotion"

if [[ ! -d "$AGENTBOX_ROOT" ]]; then
  bad "agentbox not found at $AGENTBOX_ROOT (set AGENTBOX_ROOT)"
elif [[ "${E2E_REAL_VAULT:-0}" != "1" ]]; then
  # ── 4s. STUB mode: the argv contract, no corpus ─────────────────────────
  STUB_DIR="$WORK/bin"
  mkdir -p "$STUB_DIR" "$WORK/stub-repo/ontology"
  # The apply path now refuses to run vault without a resolvable repo root, so
  # the stub gets a minimal one: just the marker the resolver checks for.
  printf 'version: 1\n' > "$WORK/stub-repo/ontology/vocabulary.yaml"
  # apply reads the page's current status (read-only) to plan the key set.
  mkdir -p "$WORK/stub-repo/knowledge/pages"
  printf -- '---\ntype: Class\nresource: %s\nstatus: draft\n---\n' "$TEST_IRI" \
    > "$WORK/stub-repo/knowledge/pages/$TEST_PAGE.md"
  cat > "$STUB_DIR/vault" <<'STUB'
#!/bin/sh
# Stub `vault`. Records argv verbatim (including the --repo pin), answers C2.
{ for a in "$@"; do printf '%s\n' "$a"; done; printf -- '--\n'; } >> "$(dirname "$0")/argv.log"
[ "$1" = "--repo" ] && shift 2
case "$1" in
  find) printf '%s' '[{"id":"Test E2E Promotion","title":"Test E2E Promotion","type":"Class","score":1}]' ;;
  edit) printf '%s' '{"ok":true,"docs":1,"blocks":2}' ;;
  *)    printf '%s' 'null' ;;
esac
STUB
  chmod +x "$STUB_DIR/vault"
  ok "stub vault installed at $STUB_DIR/vault"

  PATH="$STUB_DIR:$PATH" AGENTBOX_ROOT="$AGENTBOX_ROOT" AGENTBOX_NPUB="" VAULT_REPO="$WORK/stub-repo" VAULT_BIN="" \
  node - "$WORK/fixture.json" "$STUB_DIR/argv.log" <<'NODE' > "$WORK/apply.out" 2>&1 || true
const fs = require('fs'), os = require('os'), path = require('path');
const root = process.env.AGENTBOX_ROOT;
const { LocalProcessManagerOrchestratorAdapter } =
  require(path.join(root, 'management-api/adapters/orchestrator/local-process-manager'));

const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const logPath = process.argv[3];
const results = [];
const check = (name, got, want) =>
  results.push([name, JSON.stringify(got) === JSON.stringify(want), got, want]);

(async () => {
  // The ledger answers 404 here (fail-open is the property under test); the
  // real ledger is exercised in E2E_REAL_VAULT=1 mode.
  const attests = [];
  const fetchFn = async (url, opts) => {
    attests.push({ url, body: JSON.parse(opts.body) });
    return { ok: false, status: 404 };
  };

  const adapter = new LocalProcessManagerOrchestratorAdapter({});
  adapter._ontologyDeps = { fetchFn };

  // Run from an unrelated cwd: the --repo pin must not depend on it.
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-gov-'));
  const prev = process.cwd();
  process.chdir(cwd);
  const res = await adapter.handleGovernanceDecision(fixture.schema.response);
  process.chdir(prev);
  fs.rmSync(cwd, { recursive: true, force: true });

  check('the signed promote applied', res.ontology && res.ontology.applied, true);
  check('it resolved the IRI to the vault page', res.ontology && res.ontology.page, fixture.page);
  check('a 404 from the ledger did not undo the write', res.ontology && res.ontology.attested, false);

  const raw = fs.existsSync(logPath)
    ? fs.readFileSync(logPath, 'utf8').split('--\n').filter(Boolean).map(b => b.split('\n').filter(Boolean))
    : [];
  check('every vault call is pinned to the resolved repo with --repo',
        raw.length > 0 && raw.every(c => c[0] === '--repo' && c[1] === process.env.VAULT_REPO), true);
  const calls = raw.map(c => (c[0] === '--repo' ? c.slice(2) : c));
  const edit = calls.find(c => c[0] === 'edit') || [];

  check('vault edit names the resolved page', edit.slice(0, 2), ['edit', fixture.page]);
  check('vault edit sets status=stable', edit.includes('status=stable'), true);
  check('vault edit declares the blast radius docs=1,blocks=2 (status + verified)',
        edit[edit.indexOf('--expect') + 1], 'docs=1,blocks=2');

  const verified = edit.find(a => a.startsWith('verified+='));
  check('vault edit APPENDS a human attestation', typeof verified, 'string');
  if (verified) {
    const v = JSON.parse(verified.slice('verified+='.length));
    check('the attestation names the signing human', v.by.startsWith('human:'), true);
    check('the attestation instant is the 31403 created_at, not wall clock',
          v.at, new Date(fixture.schema.response.created_at * 1000).toISOString());
  }

  check('the ledger was called once with the case id, digest and outcome',
        attests.length && { ...attests[0].body, at: undefined },
        { case_id: fixture.schema.case_id,
          digest: fixture.schema.case_id,
          outcome: 'promote',
          signer: attests[0] && attests[0].body.signer,
          at: undefined });

  for (const [name, passed, got, want] of results) {
    console.log((passed ? 'ok   ' : 'FAIL ') + name +
      (passed ? '' : ` — expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`));
  }
})().catch(e => { console.log('FAIL apply step threw: ' + (e && e.message)); process.exit(0); });
NODE
  tally "$WORK/apply.out"
else
  # ── 4r. REAL mode: a real vault, a scratch corpus, a real ledger ────────
  #
  # Every write goes to a scratch repository under $WORK. The source corpus is
  # only ever READ (vocabulary + manifest, plus pages with E2E_FULL_CORPUS=1).
  # The project's own release build first: it is what WS-C ships next, and a
  # vault on PATH may be an older image build without `create`.
  VAULT_REAL="${E2E_VAULT_BIN:-/home/devuser/workspace/project/target/release/vault}"
  [[ -x "$VAULT_REAL" ]] || VAULT_REAL="$(command -v vault || true)"
  VAULT_SOURCE="${E2E_VAULT_SOURCE:-/home/devuser/workspace/visionGraph}"
  SCRATCH="$WORK/vault-repo"

  if [[ ! -x "$VAULT_REAL" ]]; then
    bad "E2E_REAL_VAULT=1 but no vault binary (set E2E_VAULT_BIN)"
  elif [[ ! -f "$VAULT_SOURCE/ontology/vocabulary.yaml" || ! -f "$VAULT_SOURCE/vault.toml" ]]; then
    bad "E2E_VAULT_SOURCE=$VAULT_SOURCE holds no ontology/vocabulary.yaml + vault.toml"
  else
    ok "using the REAL vault: $("$VAULT_REAL" --version) ($VAULT_REAL)"

    # (a) scratch repository: the governing files, copied read-only-source.
    mkdir -p "$SCRATCH/ontology" "$SCRATCH/knowledge/pages" "$SCRATCH/working/pages"
    cp "$VAULT_SOURCE/ontology/vocabulary.yaml" "$SCRATCH/ontology/"
    cp "$VAULT_SOURCE/vault.toml" "$SCRATCH/"
    if [[ "${E2E_FULL_CORPUS:-0}" == "1" ]]; then
      cp -r "$VAULT_SOURCE/knowledge/pages/." "$SCRATCH/knowledge/pages/"
      ok "scratch repo carries the full corpus ($(find "$SCRATCH/knowledge/pages" -name '*.md' | wc -l) pages)"
    fi
    [[ -e "$SCRATCH/knowledge/pages/$TEST_PAGE.md" ]] \
      && bad "the source corpus already holds '$TEST_PAGE' — refusing to shadow it"

    # (b) the fixture page: a draft, private Class the proposal will promote.
    cat > "$SCRATCH/knowledge/pages/$TEST_PAGE.md" <<EOF
---
type: Class
resource: $TEST_IRI
public: false
status: draft
domain: artificial-intelligence
generated:
  by: process:e2e-ontology-promotion/1.0
  at: 2026-09-22T00:00:00Z
---
A fixture class used only by the ontology-promotion end-to-end test. It never
exists in a real corpus; its IRI is namespaced \`test\` for that reason.
EOF
    sed 's/^status: draft$/status: stable/' "$SCRATCH/knowledge/pages/$TEST_PAGE.md" > "$WORK/proposed.md"
    git -C "$SCRATCH" init -q
    scratch_git add -A
    scratch_git -c user.email=e2e@localhost -c user.name=e2e commit -qm "seed $TEST_PAGE"
    ok "scratch repo seeded and committed at $SCRATCH"

    "$VAULT_REAL" --repo "$SCRATCH" validate --strict --json > "$WORK/validate.json" || true
    check "vault validate --strict: the fixture page has no issues" \
      "$(python3 -c "
import json,sys
d=json.load(open('$WORK/validate.json'))['knowledge']
print(len([i for i in d['issues'] if i['path']=='$TEST_PAGE']))")" "0"

    # A counting wrapper: every real invocation is logged, then exec'd, so the
    # Reject case can prove the vault was never even spawned.
    mkdir -p "$WORK/bin"
    cat > "$WORK/bin/vault" <<WRAP
#!/bin/sh
{ for a in "\$@"; do printf '%s\n' "\$a"; done; printf -- '--\n'; } >> "$WORK/vault-calls.log"
exec "$VAULT_REAL" "\$@"
WRAP
    chmod +x "$WORK/bin/vault"
    : > "$WORK/vault-calls.log"

    # (c) propose, through agentbox's own runVaultPropose (so the --repo pin
    #     and the signing-env passthrough are on the path under test). The
    #     agent key is the fixture's deterministic all-0x11 secret.
    AGENTBOX_ROOT="$AGENTBOX_ROOT" VAULT_BIN="$WORK/bin/vault" VAULT_REPO="$SCRATCH" \
    VAULT_NOSTR_SECRET="$(printf '11%.0s' {1..32})" AGENTBOX_DID="did:nostr:e2e" \
    node - "$WORK" "$TEST_IRI" "$TEST_PAGE" <<'NODE' > "$WORK/propose.out" 2>&1 || true
const fs = require('fs'), os = require('os'), path = require('path');
const { runVaultPropose } = require(path.join(process.env.AGENTBOX_ROOT, 'management-api/lib/ontology-propose'));
const [work, iri, page] = process.argv.slice(2);
const results = [];
const check = (name, got, want) =>
  results.push([name, JSON.stringify(got) === JSON.stringify(want), got, want]);

(async () => {
  const prev = process.cwd();
  fs.mkdirSync(path.join(work, 'cwd'), { recursive: true });
  process.chdir(path.join(work, 'cwd')); // --repo, not cwd, must find the corpus
  for (const level of ['content', 'schema']) {
    const out = await runVaultPropose({
      action: 'create',
      preferred_term: page,
      definition: 'A fixture class used only by the ontology-promotion e2e test.',
      owl_class: 'TestE2EPromotion', physicality: 'abstract', role: 'fixture',
      domain: 'artificial-intelligence',
      level,
      hypothesis: 'The e2e fixture page is stable enough to publish.',
      diff: path.join(work, 'proposed.md'),
    });
    check(`${level}: vault propose ran unblocked`, [out.error, out.blocked], [null, false]);
    const p = out.proposal || {}, e = out.event || {};
    check(`${level}: the minted IRI is the fixture's`, out.command.iri, iri);
    check(`${level}: PatchProposal names level, IRI and page`, [p.level, p.iri, p.page], [level, iri, page]);
    check(`${level}: no blockers`, p.blockers, []);
    check(`${level}: dry-run — built, not published`, out.command.argv.includes('--dry-run'), true);
    check(`${level}: the 31402 is kind 31402`, e.kind, 31402);
    const tag = (n) => ((e.tags || []).find(t => t[0] === n) || [])[1];
    check(`${level}: its d tag (the case id) IS the proposal digest`, 'sha256:' + tag('d'), p.digest);
    check(`${level}: its level tag`, tag('level'), level);
    check(`${level}: it names the ontology-governance panel`, tag('panel'), 'ontology-governance');
    fs.writeFileSync(path.join(work, `request-${level}.json`), JSON.stringify({ proposal: p, event: e }));
  }
  process.chdir(prev);
  const calls = fs.readFileSync(path.join(work, 'vault-calls.log'), 'utf8')
    .split('--\n').filter(Boolean).map(b => b.split('\n').filter(Boolean));
  check('both proposals pinned --repo to the scratch repo',
        calls.map(c => c.slice(0, 2)), calls.map(() => ['--repo', process.env.VAULT_REPO]));
  for (const [name, passed, got, want] of results) {
    console.log((passed ? 'ok   ' : 'FAIL ') + name +
      (passed ? '' : ` — expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`));
  }
})().catch(e => { console.log('FAIL propose step threw: ' + (e && e.stack)); process.exit(0); });
NODE
    tally "$WORK/propose.out"

    # The relay's tier rule, applied to the REAL 31402s, and a human's signed
    # 31403s bound to the real case id.
    for level in content schema; do
      if [[ -s "$WORK/request-$level.json" ]] && ( cd "$REPO_ROOT" && cargo run -q -p nostr-bbs-core \
           --example ontology_promotion_fixture -- --from-request "$WORK/request-$level.json" \
           > "$WORK/decision-$level.json" 2> "$WORK/decision-$level.err" ); then
        dq() { python3 -c "import json;print(json.load(open('$WORK/decision-$level.json'))$1)"; }
        check "$level: the real 31402's BIP-340 signature verifies" "$(dq "['request_verified']")" "True"
        check "$level: case id carried to the 31403s" "$(dq "['promote']['tags'][0][1]")" "$(dq "['case_id']")"
      else
        bad "$level: could not decide the real 31402 ($(tail -1 "$WORK/decision-$level.err" 2>/dev/null))"
      fi
    done
    check "a SCHEMA-level real proposal is floored at tier High" \
      "$(python3 -c "import json;print(json.load(open('$WORK/decision-schema.json'))['effective_tier'])" 2>/dev/null)" "high"
    check "a CONTENT-level real proposal is not floored (panel tier)" \
      "$(python3 -c "import json;print(json.load(open('$WORK/decision-content.json'))['effective_tier'])" 2>/dev/null)" "medium"

    # (e) the ledger: the real Loom façade on a scratch data dir when it is
    #     built, else a recording HTTP stub. Either way, a real HTTP POST.
    LOOM_BIN="${E2E_LOOM_BIN:-/home/devuser/workspace/loom/target/debug/loom-facade}"
    LOOM_FIXTURE="${E2E_LOOM_FIXTURE:-/home/devuser/workspace/loom/tests/golden-python/fixture.json}"
    LEDGER_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
    mkdir -p "$WORK/ledger"
    if [[ -x "$LOOM_BIN" && -f "$LOOM_FIXTURE" && "${E2E_LEDGER:-loom}" == "loom" ]]; then
      LEDGER_KIND=loom
      cp "$LOOM_FIXTURE" "$WORK/ledger/scaffold-index.json"
      ( cd "$WORK/ledger" && exec env ONTOLOGY_INDEX="$WORK/ledger/scaffold-index.json" \
          LOOM_LEDGER_PATH="$WORK/ledger/ledger.jsonl" LOOM_FACADE_PORT="$LEDGER_PORT" \
          DISTILL_BACKEND_URL=http://127.0.0.1:9 "$LOOM_BIN" ) > "$WORK/ledger/server.log" 2>&1 &
    else
      LEDGER_KIND=stub
      python3 - "$LEDGER_PORT" "$WORK/ledger/ledger.jsonl" <<'PY' > "$WORK/ledger/server.log" 2>&1 &
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
port, out = int(sys.argv[1]), sys.argv[2]
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"status":"ok"}')
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('content-length', 0)))
        with open(out, 'a') as f:
            f.write(json.dumps({"path": self.path, "body": json.loads(body)}) + "\n")
        self.send_response(201); self.end_headers(); self.wfile.write(b'{"entry_id":"stub"}')
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
    fi
    LEDGER_PID=$!
    for _ in $(seq 1 100); do curl -sf "http://127.0.0.1:$LEDGER_PORT/health" >/dev/null && break; sleep 0.1; done
    if curl -sf "http://127.0.0.1:$LEDGER_PORT/health" >/dev/null; then
      ok "ledger up: $LEDGER_KIND on :$LEDGER_PORT"
    else
      bad "ledger ($LEDGER_KIND) did not come up — see $WORK/ledger/server.log"
    fi

    # (d) apply, and assert OUTCOMES by reading the page back.
    AGENTBOX_ROOT="$AGENTBOX_ROOT" AGENTBOX_NPUB="" VAULT_BIN="$WORK/bin/vault" VAULT_REPO="$SCRATCH" \
    LOOM_BASE_URL="http://127.0.0.1:$LEDGER_PORT" VAULT_REAL="$VAULT_REAL" \
    node - "$WORK" "$TEST_PAGE" <<'NODE' > "$WORK/apply.out" 2>&1 || true
const fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');
const mapi = path.join(process.env.AGENTBOX_ROOT, 'management-api');
const yaml = require(require.resolve('js-yaml', { paths: [mapi] }));
const { LocalProcessManagerOrchestratorAdapter: Adapter } =
  require(path.join(mapi, 'adapters/orchestrator/local-process-manager'));

const [work, page] = process.argv.slice(2);
const repo = process.env.VAULT_REPO;
const file = path.join(repo, 'knowledge', 'pages', `${page}.md`);
const decision = JSON.parse(fs.readFileSync(path.join(work, 'decision-schema.json'), 'utf8'));
const results = [];
const check = (name, got, want) =>
  results.push([name, JSON.stringify(got) === JSON.stringify(want), got, want]);

const sha = () => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const front = () => yaml.load(fs.readFileSync(file, 'utf8').split(/^---$/m)[1]);
const reset = () => execFileSync('git', ['-C', repo, 'checkout', '-q', '--', '.']);
const dirty = () => execFileSync('git', ['-C', repo, 'status', '--porcelain'], { encoding: 'utf8' })
  .split('\n').filter(Boolean).map(l => l.slice(3).replace(/^"|"$/g, ''));
const vaultCalls = () => fs.readFileSync(path.join(work, 'vault-calls.log'), 'utf8').split('--\n').filter(Boolean).length;
// --strict exits non-zero on ANY corpus warning (E2E_FULL_CORPUS=1 carries the
// real corpus's own), so read the report whatever the exit status and judge
// only the fixture page.
const pageIssues = () => {
  const r = spawnSync(process.env.VAULT_REAL, ['--repo', repo, 'validate', '--strict', '--json'],
    { encoding: 'utf8', maxBuffer: 512 * 1024 * 1024 });
  return JSON.parse(r.stdout).knowledge.issues.filter(i => i.path === page);
};

(async () => {
  const human = Adapter._hexToNpub(decision.human_pubkey);
  const decidedAt = (e) => new Date(e.created_at * 1000).toISOString();
  const adapter = new Adapter({});
  const run = async (event) => {
    const prev = process.cwd();
    // Never the scratch repo (--repo must carry it), and a throwaway dir: the
    // adapter persists each decision under its cwd.
    const cwd = path.join(work, 'cwd');
    fs.mkdirSync(cwd, { recursive: true });
    process.chdir(cwd);
    try { return await adapter.handleGovernanceDecision(event); } finally { process.chdir(prev); }
  };
  const seedSha = sha();

  // ── Promote (the ontology panel's Approve) ─────────────────────────────
  let res = await run(decision.promote);
  let fm = front();
  check('promote: applied and attested', [res.ontology.applied, res.ontology.attested, res.ontology.attestError],
        [true, true, null]);
  check('promote: page read back is status: stable', fm.status, 'stable');
  check('promote: exactly one verified entry', Array.isArray(fm.verified) && fm.verified.length, 1);
  check('promote: verified.by names the human signer', fm.verified && fm.verified[0].by, `human:${human}`);
  check('promote: verified.at is the 31403 created_at',
        fm.verified && new Date(fm.verified[0].at).toISOString(), decidedAt(decision.promote));
  check('promote: nothing else on the page changed',
        Object.keys(fm).sort(), ['domain', 'generated', 'public', 'resource', 'status', 'type', 'verified']);
  check('promote: only the fixture page was written', dirty(), [`knowledge/pages/${page}.md`]);
  check('promote: the written page still validates --strict', pageIssues(), []);

  // ── Re-promote a stable page: a RE-ATTESTATION ─────────────────────────
  res = await run(decision.promote);
  fm = front();
  check('re-promote: applied as a re-attestation of one block',
        [res.ontology.applied, res.ontology.reattest, res.ontology.blocks, res.ontology.attested], [true, true, 1, true]);
  check('re-promote: status unchanged (stable)', fm.status, 'stable');
  check('re-promote: exactly one more verified entry', fm.verified && fm.verified.length, 2);
  check('re-promote: the page still validates --strict', pageIssues(), []);

  // ── Reject: writes nothing, spawns nothing ─────────────────────────────
  reset();
  check('reset restores the seeded bytes', sha(), seedSha);
  const callsBefore = vaultCalls();
  res = await run(decision.reject);
  check('reject: no ontology write was attempted', res.ontology, null);
  check('reject: the page is byte-identical (sha256)', sha(), seedSha);
  check('reject: the vault binary was never spawned', vaultCalls(), callsBefore);
  check('reject: the working tree is clean', dirty(), []);

  // ── Demote on the draft: deprecated, and no verified stamp ─────────────
  res = await run(decision.demote);
  fm = front();
  check('demote: applied and attested', [res.ontology.applied, res.ontology.attested], [true, true]);
  check('demote: page read back is status: deprecated', fm.status, 'deprecated');
  check('demote: no verified stamp at all', 'verified' in fm, false);

  // ── Demote after promote: the earlier human stamp stays, none is added ──
  reset();
  await run(decision.promote);
  res = await run(decision.demote);
  fm = front();
  check('promote→demote: status: deprecated', fm.status, 'deprecated');
  check('promote→demote: the demotion added no verified entry', fm.verified && fm.verified.length, 1);
  reset();

  for (const [name, passed, got, want] of results) {
    console.log((passed ? 'ok   ' : 'FAIL ') + name +
      (passed ? '' : ` — expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`));
  }
})().catch(e => { console.log('FAIL apply step threw: ' + (e && e.stack)); process.exit(0); });
NODE
    tally "$WORK/apply.out"

    # (f) elevation: a seeded WORKING note is elevated through agentbox's
    #     gate — staged as a page, validated on its own, `vault propose --diff`.
    cat > "$SCRATCH/working/pages/Test E2E Elevation Note.md" <<'NOTE_MD'
---
type: Draft Concept
title: Test E2E Elevation Note
status: draft
---
A working note about a concept worth elevating into the governed corpus.
NOTE_MD
    scratch_git add -A
    scratch_git -c user.email=e2e@localhost -c user.name=e2e commit -qm "seed working note"
    AGENTBOX_ROOT="$AGENTBOX_ROOT" VAULT_BIN="$WORK/bin/vault" VAULT_REPO="$SCRATCH" \
    VAULT_NOSTR_SECRET="$(printf '11%.0s' {1..32})" AGENTBOX_DID="did:nostr:e2e" \
    node - "$WORK" "$SCRATCH" <<'NODE' > "$WORK/elevate.out" 2>&1 || true
const fs = require('fs'), path = require('path');
const { execFileSync } = require('child_process');
const mapi = path.join(process.env.AGENTBOX_ROOT, 'management-api');
const { extractProposals } = require(path.join(mapi, 'lib/kg-proposal-extractor'));
const { gateElevation } = require(path.join(mapi, 'lib/elevation-stage'));
const [work, repo] = process.argv.slice(2);
const results = [];
const check = (name, got, want) =>
  results.push([name, JSON.stringify(got) === JSON.stringify(want), got, want]);
const env = { ...process.env, AGENTBOX_X_ONLY_PUBKEY_HEX: 'e2'.repeat(32) };
const descriptor = (value) => extractProposals([{ key: 'e2e-note', value }],
  { ownerPubkey: 'e2'.repeat(32), env, minScore: 0 }).proposals[0];
const NOTE = {
  preferred_term: 'Test E2E Elevation',
  definition: 'A concept elevated by the e2e test from a seeded working note into the governed corpus.',
  domain: 'artificial-intelligence', physicality: 'abstract', role: 'fixture',
  working_page: 'Test E2E Elevation Note',
  is_subclass_of: ['urn:ngm:class:test-e2e-promotion'],
};
const tmpRoot = path.join(work, 'elevation-tmp');
fs.mkdirSync(tmpRoot, { recursive: true });
const clean = () => execFileSync('git', ['-C', repo, 'status', '--porcelain'], { encoding: 'utf8' }) === '';

(async () => {
  // A page that is NOT sound on its own is refused by the REAL validate,
  // before any proposal is built.
  const bad = await gateElevation(descriptor({ ...NOTE, relationships: { frobnicates: ['X'] } }), { env, tmpRoot });
  check('elevation: an unknown relation key is not proposable (real validate)',
        [bad.proposable, (bad.stage_issues[0] || {}).code], [false, 'UNKNOWN_KEY']);
  check('elevation: the refusal names the vault reason', /UNKNOWN_KEY/.test(bad.error || ''), true);

  // The sound candidate: staged, validated alone, proposed with --diff.
  const out = await gateElevation(descriptor(NOTE), { env, tmpRoot });
  check('elevation: the staged page passes vault validate on its own', out.stage_issues, []);
  check('elevation: vault propose accepted the staged NEW page', [out.proposable, out.error], [true, null]);
  const p = out.proposal || {}, e = out.event || {};
  check('elevation: the PatchProposal names the new class', [p.iri, p.page],
        ['urn:ngm:class:test-e2e-elevation', 'Test E2E Elevation']);
  check('elevation: the diff creates the page with its origin in the working note',
        /\+status: draft/.test(p.diff || '') && /Test E2E Elevation Note/.test(p.diff || ''), true);
  check('elevation: a content-level 31402 was built (dry-run)',
        [e.kind, ((e.tags || []).find(t => t[0] === 'level') || [])[1]], [31402, 'content']);
  check('elevation: vault marks it kind: create (a page no corpus page answers to)', p.kind, 'create');
  check('elevation: the staged page declared its title', /\+title: "?Test E2E Elevation"?/.test(p.diff || ''), true);
  if (e.id) fs.writeFileSync(path.join(work, 'request-elevation.json'), JSON.stringify({ proposal: p, event: e }));
  check('elevation: the corpus is untouched (dry-run writes nothing)', clean(), true);
  check('elevation: every staging dir was removed', fs.readdirSync(tmpRoot), []);
  for (const [name, passed, got, want] of results) {
    console.log((passed ? 'ok   ' : 'FAIL ') + name +
      (passed ? '' : ` — expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`));
  }
})().catch(e => { console.log('FAIL elevation step threw: ' + (e && e.stack)); process.exit(0); });
NODE
    tally "$WORK/elevate.out"

    # (g) the elevation's create proposal, APPROVED: a human-signed Promote of
    #     the real vault-built 31402, applied by agentbox through ONE
    #     `vault create` of the page the signed diff adds; the created page is
    #     read back and must pass `vault validate`.
    if [[ -s "$WORK/request-elevation.json" ]] && ( cd "$REPO_ROOT" && cargo run -q -p nostr-bbs-core \
         --example ontology_promotion_fixture -- --from-request "$WORK/request-elevation.json" \
         > "$WORK/decision-elevation.json" 2> "$WORK/decision-elevation.err" ); then
      AGENTBOX_ROOT="$AGENTBOX_ROOT" AGENTBOX_NPUB="" VAULT_BIN="$WORK/bin/vault" VAULT_REPO="$SCRATCH" \
      LOOM_BASE_URL="http://127.0.0.1:$LEDGER_PORT" VAULT_REAL="$VAULT_REAL" \
      node - "$WORK" "$SCRATCH" <<'NODE' > "$WORK/create.out" 2>&1 || true
const fs = require('fs'), path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const mapi = path.join(process.env.AGENTBOX_ROOT, 'management-api');
const yaml = require(require.resolve('js-yaml', { paths: [mapi] }));
const { LocalProcessManagerOrchestratorAdapter: Adapter } =
  require(path.join(mapi, 'adapters/orchestrator/local-process-manager'));
const [work, repo] = process.argv.slice(2);
const req = JSON.parse(fs.readFileSync(path.join(work, 'request-elevation.json'), 'utf8'));
const dec = JSON.parse(fs.readFileSync(path.join(work, 'decision-elevation.json'), 'utf8'));
const page = req.proposal.page;
const file = path.join(repo, 'knowledge', 'pages', `${page}.md`);
const results = [];
const check = (name, got, want) =>
  results.push([name, JSON.stringify(got) === JSON.stringify(want), got, want]);
const git = (...a) => execFileSync('git', ['-C', repo, ...a], { encoding: 'utf8' });

(async () => {
  check('create: the real 31402 verifies and is the elevation case',
        [dec.request_verified, dec.case_id], [true, req.event.tags.find(t => t[0] === 'd')[1]]);
  check('create: the page does not exist before approval', fs.existsSync(file), false);

  // The relay consumer's stored copy of the 31402, as the adapter looks it up.
  const stored = { event_id: req.event.id, kind: 31402, d_tag: dec.case_id,
                   content: req.event.content, tags: req.event.tags };
  const adapter = new Adapter({});
  adapter._ontologyDeps = { fetchRequest: async (id) => (id === req.event.id ? stored : null) };
  const cwd = path.join(work, 'cwd');
  fs.mkdirSync(cwd, { recursive: true });
  const prev = process.cwd();
  process.chdir(cwd);
  let res;
  try { res = await adapter.handleGovernanceDecision(dec.promote); } finally { process.chdir(prev); }
  const o = res.ontology || {};
  check('create: applied through vault create, and attested',
        [o.applied, o.created, o.attested, o.error || null], [true, true, true, null]);
  check('create: ONE vault create, no edit',
        fs.readFileSync(path.join(work, 'vault-calls.log'), 'utf8').split('--\n').filter(Boolean)
          .map(b => b.split('\n')).filter(a => a[2] === 'create' || (a[2] === 'edit' && a[3] === page))
          .map(a => a[2]), ['create']);

  const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
  const fm = text ? yaml.load(text.split(/^---$/m)[1]) : {};
  check('create: the page now exists at knowledge/pages/<title>.md', fs.existsSync(file), true);
  check('create: status: stable, stamped in the same write', fm.status, 'stable');
  check('create: one verified entry naming the human at the 31403 instant',
        (fm.verified || []).map(v => [v.by, new Date(v.at).toISOString()]),
        [[`human:${Adapter._hexToNpub(dec.human_pubkey)}`, new Date(dec.promote.created_at * 1000).toISOString()]]);
  // The attestation must land as a YAML MAPPING with exactly by/at — a flow
  // mapping passed wrongly is stored as a plain string, which this catches.
  check('create: verified[0] is a mapping with exactly the keys by, at',
        (fm.verified || []).map(v => (v && typeof v === 'object' && !Array.isArray(v) ? Object.keys(v) : typeof v)),
        [['by', 'at']]);
  check('create: on disk, verified is block YAML (by/at lines), not a quoted string',
        /^verified:\n- by: human:npub1\S+\n  at: \S+$/m.test(text), true);
  check('create: resource and origin are the proposed ones',
        [fm.resource, (fm.sources || [])[0] && fm.sources[0].resource],
        [req.proposal.iri, '[[Test E2E Elevation Note]]']);
  const r = spawnSync(process.env.VAULT_REAL, ['--repo', repo, 'validate', '--strict', '--json'],
    { encoding: 'utf8', maxBuffer: 512 * 1024 * 1024 });
  const issues = JSON.parse(r.stdout).knowledge.issues.filter(i => i.path === page);
  check('create: the created page passes vault validate --strict', issues, []);
  check('create: only the new page was written',
        git('status', '--porcelain').split('\n').filter(Boolean).map(l => l.slice(3).replace(/^"|"$/g, '')),
        [`knowledge/pages/${page}.md`]);

  // Approving the same create again: the vault refuses (EXISTS), nothing is
  // written, nothing is ledgered.
  const before = fs.readFileSync(file, 'utf8');
  process.chdir(cwd);
  try { res = await adapter.handleGovernanceDecision(dec.promote); } finally { process.chdir(prev); }
  check('create again: applied:false reason exists, not attested',
        [res.ontology.applied, res.ontology.reason, res.ontology.attested], [false, 'exists', false]);
  check('create again: the page is byte-identical', fs.readFileSync(file, 'utf8'), before);

  for (const [name, passed, got, want] of results) {
    console.log((passed ? 'ok   ' : 'FAIL ') + name +
      (passed ? '' : ` — expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`));
  }
})().catch(e => { console.log('FAIL create step threw: ' + (e && e.stack)); process.exit(0); });
NODE
      tally "$WORK/create.out"
    else
      bad "create: no real elevation 31402 to decide ($(tail -1 "$WORK/decision-elevation.err" 2>/dev/null))"
    fi


    # The ledger: five attestations (promote, re-promote, demote, promote,
    # demote), every
    # one keyed by the SAME case id the real 31402 carries as its d tag.
    python3 - "$LEDGER_KIND" "$WORK/ledger/ledger.jsonl" "$WORK/decision-schema.json" \
              "$WORK/request-schema.json" <<'PY' > "$WORK/ledger.out" 2>&1 || echo "FAIL ledger check crashed" >> "$WORK/ledger.out"
import json, sys
kind, path, dec, req = sys.argv[1:]
case = json.load(open(dec))["case_id"]
digest = json.load(open(req))["proposal"]["digest"]
rows = [json.loads(l) for l in open(path)] if __import__("os").path.exists(path) else []
import os
elev = os.path.join(os.path.dirname(dec), "decision-elevation.json")
elev_case = json.load(open(elev))["case_id"] if os.path.exists(elev) else None
def case_of(r):
    return r["subject"] if kind == "loom" else r["body"]["case_id"]
elev_rows = [r for r in rows if case_of(r) == elev_case]
rows = [r for r in rows if case_of(r) != elev_case]
if kind == "loom":
    got = [(r["subject"], r["predicate"], r["passed"], json.loads(r["detail"])) for r in rows]
    norm = [(s, p.split(":", 1)[1], ok, d["digest"], d["signer"]) for s, p, ok, d in got]
else:
    norm = [(r["body"]["case_id"], r["body"]["outcome"], r["body"]["outcome"] == "promote",
             r["body"]["digest"], r["body"]["signer"]) for r in rows]
def check(name, got, want):
    print(("ok   " if got == want else "FAIL ") + name + ("" if got == want else f" — expected {want!r}, got {got!r}"))
check(f"ledger ({kind}): five entries, in decision order",
      [n[1] for n in norm], ["promote", "promote", "demote", "promote", "demote"])
check(f"ledger ({kind}): every entry carries the real proposal's case id",
      sorted({n[0] for n in norm}), [case])
check(f"ledger ({kind}): the digest is the canonical sha256: form of the same PatchProposal",
      sorted({n[3] for n in norm}), [digest])
check(f"ledger ({kind}): only a promote admits content", [n[2] for n in norm], [True, True, False, True, False])
check(f"ledger ({kind}): the approved create is ledgered ONCE, under its own case id",
      [(case_of(r), r["predicate"] if kind == "loom" else r["body"]["outcome"]) for r in elev_rows],
      [(elev_case, "governance-decision:promote" if kind == "loom" else "promote")])
check(f"ledger ({kind}): the signer is the human actor URI",
      all(n[4].startswith("human:npub1") for n in norm) and len(norm) > 0, True)
PY
    if [[ "$LEDGER_KIND" == "loom" ]]; then
      check "ledger (loom): GET /loom/attest/verify re-hashes a sound 6-entry chain" \
        "$(curl -sf "http://127.0.0.1:$LEDGER_PORT/loom/attest/verify")" '{"ok":true,"length":6}'
    fi
    tally "$WORK/ledger.out"
    kill "$LEDGER_PID" 2>/dev/null || true
    wait "$LEDGER_PID" 2>/dev/null || true
  fi
fi

if [[ -d "$AGENTBOX_ROOT" ]]; then
  # The agentbox unit suites are the authority for the argv contract and the
  # repo-resolution rule; the e2e cannot be green while they are red.
  ( cd "$AGENTBOX_ROOT" && node --test management-api/tests/ontology-apply.test.js \
      management-api/tests/ontology-propose-vault.test.js management-api/tests/elevation-stage.test.js ) \
    > "$WORK/agentbox-tests.txt" 2>&1 \
    && ok "agentbox ontology-apply + ontology-propose + elevation-stage unit suites" \
    || { bad "agentbox ontology-apply + ontology-propose + elevation-stage unit suites"; tail -20 "$WORK/agentbox-tests.txt"; }
fi

# ───────────────────────────────────────────────────────────────────────────
printf '\n\033[1mResult\033[0m  %d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]] || exit 1
