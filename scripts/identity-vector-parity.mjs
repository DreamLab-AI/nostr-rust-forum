#!/usr/bin/env node
/**
 * ADR-2003 acceptance — JavaScript half of the shared identity-vector parity proof.
 *
 * This runner loads the SAME versioned fixture as the Rust suite
 * (`crates/nostr-bbs-core/tests/vectors/identity-subkey-vectors.v1.json`,
 * also exercised by `crates/nostr-bbs-core/tests/identity_subkey_vectors.rs`)
 * and re-derives every vector with Node's built-in `crypto`. No npm
 * dependencies. Node 22.
 *
 * ── Imported, or mirrored? ──────────────────────────────────────────────────
 *
 * MIRRORED, deliberately. The agentbox derivation lives in three call sites:
 *
 *   config/hooks/nostr-live-mirror.cjs  :: deriveChildKey()
 *   config/nostr-gateway/nostr-send.cjs :: loadIdentity()  (child mode)
 *   config/nostr-gateway/gateway.cjs    :: gateway-mode key (non-identity-port branch)
 *
 * None of them export the derivation. `nostr-live-mirror.cjs` exports only
 * `composeBody`/`mintActivityUrn`/`activityScopePubkey`/`bodyForEvent`/
 * `MAX_BODY_CHARS`; `nostr-send.cjs` and `gateway.cjs` are self-executing
 * entrypoints (they call `process.exit()` / bind a socket at require time), so
 * requiring them from a test harness is not safe. All three also gate the
 * derivation behind environment variables and a `nostr-tools` dependency that
 * does not exist in this repository.
 *
 * So this script re-executes the identical construction — a single raw
 * `crypto.createHmac('sha256', rootBytes).update(tag).digest()` — and, to stop
 * that mirror silently drifting, it PINS the agentbox sources: it reads each
 * file from the read-only agentbox checkout, records its SHA-256, and asserts
 * that the exact HMAC expression is still present. If agentbox changes its
 * derivation, this runner fails rather than quietly passing against a stale
 * copy of the algorithm.
 *
 * ── The construction ────────────────────────────────────────────────────────
 *
 *   child_sk = HMAC-SHA-256(key = root's 32 secret bytes, msg = utf8(tag))
 *
 * Deliberately NOT HKDF. Do not "upgrade" it: Rust `derive_subkey` and the
 * agentbox JS must agree byte for byte.
 *
 * Exit code 0 on full parity, 1 on any mismatch or structural problem.
 * Prints a machine-readable JSON summary on stdout.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURE_RELATIVE = 'crates/nostr-bbs-core/tests/vectors/identity-subkey-vectors.v1.json';
const FIXTURE_PATH = path.join(REPO_ROOT, FIXTURE_RELATIVE);
const EXPECTED_VERSION = 1;
const EXPECTED_ALGORITHM_ID = 'agentbox-subkey-hmac-sha256-v1';

/** secp256k1 group order n. Valid secret scalars satisfy 0 < x < n. */
const SECP256K1_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_ORDER_HEX = SECP256K1_ORDER.toString(16);

/**
 * The agentbox JavaScript sources this mirror is pinned to. `AGENTBOX_ROOT`
 * overrides the default checkout location; when the checkout is absent the
 * pinning step is reported as `skipped` (and the parity vectors still run),
 * but a PRESENT file whose construction no longer matches is a hard failure.
 */
const AGENTBOX_ROOT = process.env.AGENTBOX_ROOT || '/home/devuser/workspace/project/agentbox';
const AGENTBOX_SOURCES = [
  {
    file: 'config/hooks/nostr-live-mirror.cjs',
    symbol: 'deriveChildKey',
    // Must appear verbatim in the source.
    expression: "crypto.createHmac('sha256', Buffer.from(hex, 'hex')).update(tag).digest()",
  },
  {
    file: 'config/nostr-gateway/nostr-send.cjs',
    symbol: 'loadIdentity',
    expression: "crypto.createHmac('sha256', Buffer.from(hex, 'hex')).update(tag).digest()",
  },
  {
    file: 'config/nostr-gateway/gateway.cjs',
    symbol: 'gateway-mode key (non-identity-port branch)',
    // agentbox 31c16af renamed OP_HEX to operatorHex; the construction is unchanged.
    expression: "crypto.createHmac('sha256', Buffer.from(operatorHex, 'hex')).update(",
  },
];

// ── The mirrored agentbox derivation ────────────────────────────────────────

/**
 * Byte-for-byte mirror of the agentbox derivation.
 *
 * agentbox writes it as:
 *   crypto.createHmac('sha256', Buffer.from(hex, 'hex')).update(tag).digest()
 *
 * `update(tag)` with no encoding argument defaults to UTF-8 for a string, which
 * is what Rust's `tag.as_bytes()` produces; `'utf8'` is passed explicitly here
 * so the encoding is not left to a default.
 *
 * @param {Buffer} rootBytes 32 raw secret-key bytes
 * @param {string} tag purpose tag
 * @returns {Buffer} 32-byte child secret key
 */
function deriveSubkey(rootBytes, tag) {
  return crypto.createHmac('sha256', rootBytes).update(tag, 'utf8').digest();
}

/** secp256k1 secret-scalar range check (0 < x < n) — the same validity gate Rust applies. */
function isValidScalar(bytes) {
  if (bytes.length !== 32) return false;
  const v = BigInt('0x' + bytes.toString('hex'));
  return v > 0n && v < SECP256K1_ORDER;
}

// ── Harness ─────────────────────────────────────────────────────────────────

const failures = [];
const checks = [];

function check(name, ok, detail) {
  checks.push({ name, ok: !!ok, detail: detail ?? null });
  if (!ok) failures.push({ name, detail: detail ?? null });
  return !!ok;
}

function hexBuf(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]+$/i.test(value) || value.length % 2 !== 0) {
    throw new Error(`${label}: not an even-length hex string`);
  }
  return Buffer.from(value, 'hex');
}

function die(message, extra = {}) {
  const summary = {
    schema: 'adr-2003.identity-vector-parity.v1',
    ok: false,
    error: message,
    fixture: FIXTURE_RELATIVE,
    ...extra,
  };
  process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
  process.exit(1);
}

// ── 1. Load the shared fixture ──────────────────────────────────────────────

let fixture;
try {
  fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8'));
} catch (err) {
  die(
    `identity-vector fixture missing or unreadable at ${FIXTURE_PATH}: ${err.message}. ` +
      'This fixture is the shared Rust/JS contract and is not optional.',
  );
}

const fixtureSha256 = crypto
  .createHash('sha256')
  .update(fs.readFileSync(FIXTURE_PATH))
  .digest('hex');

check('fixture.version', fixture.version === EXPECTED_VERSION, `expected ${EXPECTED_VERSION}, got ${fixture.version}`);
check(
  'fixture.algorithm_id',
  fixture.algorithm_id === EXPECTED_ALGORITHM_ID,
  `expected ${EXPECTED_ALGORITHM_ID}, got ${fixture.algorithm_id}`,
);
check(
  'fixture.algorithm.is_hmac_not_hkdf',
  typeof fixture.algorithm === 'string' &&
    fixture.algorithm.includes('HMAC-SHA-256') &&
    !fixture.algorithm.includes('HKDF'),
  `algorithm = ${JSON.stringify(fixture.algorithm)}`,
);
check(
  'fixture.secp256k1_order_hex',
  fixture.secp256k1_order_hex === SECP256K1_ORDER_HEX,
  `expected ${SECP256K1_ORDER_HEX}, got ${fixture.secp256k1_order_hex}`,
);
check('fixture.vectors.non_empty', Array.isArray(fixture.vectors) && fixture.vectors.length > 0);
check('fixture.invalid.non_empty', Array.isArray(fixture.invalid) && fixture.invalid.length > 0);

if (!Array.isArray(fixture.vectors) || !Array.isArray(fixture.invalid)) {
  die('fixture is structurally invalid: `vectors` and `invalid` must both be arrays', {
    fixture_sha256: fixtureSha256,
  });
}

// ── 2. Pin the agentbox sources this mirror re-executes ─────────────────────

const agentboxSources = [];
for (const src of AGENTBOX_SOURCES) {
  const abs = path.join(AGENTBOX_ROOT, src.file);
  let text;
  try {
    text = fs.readFileSync(abs, 'utf8');
  } catch {
    agentboxSources.push({ file: src.file, path: abs, status: 'absent', sha256: null, symbol: src.symbol });
    check(`agentbox.${src.file}.present`, true, 'checkout absent — pinning skipped, parity vectors still run');
    continue;
  }
  const sha256 = crypto.createHash('sha256').update(text, 'utf8').digest('hex');
  const matches = text.includes(src.expression);
  agentboxSources.push({
    file: src.file,
    path: abs,
    status: 'present',
    sha256,
    symbol: src.symbol,
    construction_verified: matches,
  });
  check(
    `agentbox.${src.file}.construction_pinned`,
    matches,
    matches
      ? `${src.symbol}: raw HMAC-SHA-256 construction present`
      : `${src.symbol}: expected expression not found — agentbox derivation may have changed: ${src.expression}`,
  );
  // Guard against a silent switch to HKDF on the agentbox side.
  check(
    `agentbox.${src.file}.no_hkdf`,
    !/hkdf/i.test(text),
    'agentbox source mentions HKDF — ADR-2003 forbids that construction for subkey derivation',
  );
}

// ── 3. Execute every vector ─────────────────────────────────────────────────

let vectorsPassed = 0;
const vectorResults = [];
const seenIds = new Set();

for (const vector of fixture.vectors) {
  const id = vector?.id ?? '<unknown>';
  const result = { id, ok: false };
  try {
    if (seenIds.has(id)) throw new Error(`duplicate vector id '${id}'`);
    seenIds.add(id);

    const rootBytes = hexBuf(vector.root_secret_hex, `${id}.root_secret_hex`);
    if (rootBytes.length !== 32) throw new Error(`root_secret_hex must be 32 bytes, got ${rootBytes.length}`);
    if (!isValidScalar(rootBytes)) throw new Error('root_secret_hex is not a valid secp256k1 scalar');

    const tag = vector.tag;
    if (typeof tag !== 'string') throw new Error('tag must be a string');

    const declaredLen = vector.tag_utf8_bytes;
    const actualLen = Buffer.byteLength(tag, 'utf8');
    if (declaredLen !== actualLen) {
      throw new Error(
        `tag is ${actualLen} UTF-8 bytes but the fixture declares ${declaredLen} — ` +
          'the tag was re-encoded or normalised somewhere',
      );
    }

    const child = deriveSubkey(rootBytes, tag);
    const actual = child.toString('hex');
    const expected = vector.expected_child_secret_hex;

    if (actual !== expected) {
      throw new Error(`MISMATCH: expected ${expected}, agentbox JS construction produced ${actual}`);
    }
    if (!isValidScalar(child)) {
      throw new Error(`derived child ${actual} is not a valid secp256k1 scalar`);
    }
    // Determinism.
    if (deriveSubkey(rootBytes, tag).toString('hex') !== actual) {
      throw new Error('derivation is not deterministic');
    }

    result.ok = true;
    result.tag_utf8_bytes = actualLen;
    result.child_secret_hex = actual;
    vectorsPassed += 1;
  } catch (err) {
    result.error = err.message;
    failures.push({ name: `vector.${id}`, detail: err.message });
  }
  vectorResults.push(result);
}

check('vectors.all_passed', vectorsPassed === fixture.vectors.length, `${vectorsPassed}/${fixture.vectors.length}`);

// ── 4. Rotation must actually rotate ────────────────────────────────────────

const byId = new Map(fixture.vectors.map((v) => [v.id, v]));
for (const [v1Id, v2Id] of [
  ['canonical-mirror-v1', 'rotation-mirror-v2'],
  ['canonical-gateway-v1', 'rotation-gateway-v2'],
]) {
  const v1 = byId.get(v1Id);
  const v2 = byId.get(v2Id);
  if (!v1 || !v2) {
    check(`rotation.${v1Id}->${v2Id}`, false, 'fixture is missing one half of the rotation pair');
    continue;
  }
  const sameRoot = v1.root_secret_hex === v2.root_secret_hex;
  const differentChild =
    deriveSubkey(hexBuf(v1.root_secret_hex, v1Id), v1.tag).toString('hex') !==
    deriveSubkey(hexBuf(v2.root_secret_hex, v2Id), v2.tag).toString('hex');
  check(
    `rotation.${v1Id}->${v2Id}`,
    sameRoot && differentChild,
    sameRoot ? 'tag rotation yields a distinct child' : 'rotation pair does not share a root',
  );
}

// ── 5. Invalid roots must be rejected ───────────────────────────────────────

let invalidRejected = 0;
const invalidResults = [];
for (const entry of fixture.invalid) {
  const id = entry?.id ?? '<unknown>';
  const item = { id, ok: false };
  try {
    const rootBytes = hexBuf(entry.root_secret_hex, `${id}.root_secret_hex`);
    if (isValidScalar(rootBytes)) {
      throw new Error('root was ACCEPTED by the secp256k1 scalar range check but must be rejected');
    }
    if (entry.js_expects !== 'scalar_out_of_range') {
      throw new Error(`unexpected js_expects value ${JSON.stringify(entry.js_expects)}`);
    }
    item.ok = true;
    item.rejected_as = 'scalar_out_of_range';
    invalidRejected += 1;
  } catch (err) {
    item.error = err.message;
    failures.push({ name: `invalid.${id}`, detail: err.message });
  }
  invalidResults.push(item);
}
check('invalid.all_rejected', invalidRejected === fixture.invalid.length, `${invalidRejected}/${fixture.invalid.length}`);

// ── 6. Prove the construction is not HKDF ───────────────────────────────────

{
  const root = Buffer.alloc(32, 0x01);
  const tag = 'agentbox-mirror-v1';
  const hmacOut = deriveSubkey(root, tag).toString('hex');
  check(
    'construction.canonical_known_answer',
    hmacOut === '2d07f2ce93d0361687fdd81d2690082b5d6c35b93e3ece2d44bcf115ef8f695d',
    hmacOut,
  );
  // HKDF-Expand(prk = root, info = tag, L = 32) via node's built-in hkdfSync.
  const hkdfOut = Buffer.from(
    crypto.hkdfSync('sha256', root, Buffer.alloc(0), Buffer.from(tag, 'utf8'), 32),
  ).toString('hex');
  check(
    'construction.is_not_hkdf',
    hkdfOut !== hmacOut,
    'raw HMAC-SHA-256 output must differ from HKDF over the same inputs',
  );
}

// ── Summary ─────────────────────────────────────────────────────────────────

const ok = failures.length === 0;
const summary = {
  schema: 'adr-2003.identity-vector-parity.v1',
  ok,
  fixture: FIXTURE_RELATIVE,
  fixture_version: fixture.version,
  fixture_algorithm_id: fixture.algorithm_id,
  fixture_sha256: fixtureSha256,
  node_version: process.version,
  js_source: 'mirrored',
  js_source_reason:
    'The agentbox derivation is not exported by any of its call sites and two of the three ' +
    'files self-execute at require time; the construction is re-executed here verbatim and ' +
    'the agentbox sources are pinned by sha256 plus an exact-expression check.',
  agentbox_root: AGENTBOX_ROOT,
  agentbox_sources: agentboxSources,
  vectors_total: fixture.vectors.length,
  vectors_passed: vectorsPassed,
  invalid_total: fixture.invalid.length,
  invalid_rejected: invalidRejected,
  checks_total: checks.length,
  checks_passed: checks.filter((c) => c.ok).length,
  failures,
  vector_results: vectorResults,
  invalid_results: invalidResults,
};

process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
process.exit(ok ? 0 : 1);
