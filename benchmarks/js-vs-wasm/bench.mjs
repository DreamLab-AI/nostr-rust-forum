/**
 * DreamLab Crypto Benchmarks: JS vs WASM
 *
 * Compares pure-JavaScript crypto (noble/hashes, noble/curves, nostr-tools)
 * against Rust-compiled WASM (@dreamlab/nostr-core-wasm) for the 7 core
 * operations used in the DreamLab community forum.
 *
 * Usage: node --experimental-wasm-modules bench.mjs
 */

import { performance } from 'node:perf_hooks';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// ── JS imports ──────────────────────────────────────────────────────────────

import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import {
  generateSecretKey,
  getPublicKey,
  finalizeEvent,
  getEventHash,
} from 'nostr-tools';
import * as nip44js from 'nostr-tools/nip44';

// ── WASM imports ────────────────────────────────────────────────────────────

import {
  derive_keypair_from_prf,
  schnorr_sign,
  compute_event_id,
  nip44_encrypt as wasm_nip44_encrypt,
  nip44_decrypt as wasm_nip44_decrypt,
  create_nip98_token as wasm_create_nip98_token,
} from '@dreamlab/nostr-core-wasm';

// ── Helpers ─────────────────────────────────────────────────────────────────

function hexToUint8(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function randomBytes(n) {
  const buf = new Uint8Array(n);
  for (let i = 0; i < n; i++) buf[i] = (Math.random() * 256) | 0;
  return buf;
}

function randomHex(n) {
  return bytesToHex(randomBytes(n));
}

/** Compute statistics from an array of durations in ms. */
function computeStats(durations) {
  const sorted = [...durations].sort((a, b) => a - b);
  const n = sorted.length;
  const sum = sorted.reduce((a, b) => a + b, 0);
  const mean = sum / n;
  const median = n % 2 === 0
    ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2
    : sorted[Math.floor(n / 2)];
  const p95 = sorted[Math.floor(n * 0.95)];
  const p99 = sorted[Math.floor(n * 0.99)];
  const opsPerSec = 1000 / mean;
  return { mean, median, p95, p99, opsPerSec, n };
}

/** Run a function `iterations` times and collect per-call durations. */
function benchmark(fn, iterations) {
  // Warmup: 10% of iterations or at least 10
  const warmup = Math.max(10, Math.floor(iterations * 0.1));
  for (let i = 0; i < warmup; i++) fn();

  const durations = new Array(iterations);
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    fn();
    durations[i] = performance.now() - start;
  }
  return computeStats(durations);
}

/** Run an async function `iterations` times sequentially. */
async function benchmarkAsync(fn, iterations) {
  const warmup = Math.max(10, Math.floor(iterations * 0.1));
  for (let i = 0; i < warmup; i++) await fn();

  const durations = new Array(iterations);
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    await fn();
    durations[i] = performance.now() - start;
  }
  return computeStats(durations);
}

function formatMs(ms) {
  if (ms < 0.001) return `${(ms * 1_000_000).toFixed(0)} ns`;
  if (ms < 1) return `${(ms * 1000).toFixed(1)} us`;
  return `${ms.toFixed(3)} ms`;
}

function formatOps(ops) {
  if (ops >= 1_000_000) return `${(ops / 1_000_000).toFixed(2)}M`;
  if (ops >= 1_000) return `${(ops / 1_000).toFixed(1)}K`;
  return `${ops.toFixed(0)}`;
}

// ── Pre-generate shared test data ───────────────────────────────────────────

const PRF_OUTPUT = randomBytes(32);
const SECRET_KEY = generateSecretKey();
const PUBLIC_KEY_HEX = getPublicKey(SECRET_KEY);
const PUBLIC_KEY_BYTES = hexToUint8(PUBLIC_KEY_HEX);

// Second keypair for NIP-44
const SECRET_KEY_2 = generateSecretKey();
const PUBLIC_KEY_2_HEX = getPublicKey(SECRET_KEY_2);
const PUBLIC_KEY_2_BYTES = hexToUint8(PUBLIC_KEY_2_HEX);

// Pre-compute conversation key for JS NIP-44 (used in "cached" variants)
const JS_CONV_KEY = nip44js.v2.utils.getConversationKey(SECRET_KEY, PUBLIC_KEY_2_HEX);
const JS_CONV_KEY_DECRYPT = nip44js.v2.utils.getConversationKey(SECRET_KEY_2, PUBLIC_KEY_HEX);

const MSG_HASH = sha256(new TextEncoder().encode('benchmark message'));
const TIMESTAMP = Math.floor(Date.now() / 1000);
const TAGS_JSON = JSON.stringify([['p', PUBLIC_KEY_HEX], ['e', randomHex(32)]]);

const PLAINTEXT_1KB = 'A'.repeat(1024);
const PLAINTEXT_10KB = 'B'.repeat(10240);

// Pre-encrypt for decrypt benchmarks
const JS_CIPHERTEXT_1KB = nip44js.v2.encrypt(PLAINTEXT_1KB, JS_CONV_KEY);
const JS_CIPHERTEXT_10KB = nip44js.v2.encrypt(PLAINTEXT_10KB, JS_CONV_KEY);
const WASM_CIPHERTEXT_1KB = wasm_nip44_encrypt(SECRET_KEY, PUBLIC_KEY_2_BYTES, PLAINTEXT_1KB);
const WASM_CIPHERTEXT_10KB = wasm_nip44_encrypt(SECRET_KEY, PUBLIC_KEY_2_BYTES, PLAINTEXT_10KB);

// NIP-98 test data
const NIP98_URL = 'https://api.dreamlab-ai.com/pods/abc123/media/upload';
const NIP98_METHOD = 'POST';
const NIP98_BODY = new TextEncoder().encode('{"file":"test.jpg","size":12345}');

// ── Benchmark definitions ───────────────────────────────────────────────────

const results = [];

async function runAll() {
  console.log('='.repeat(76));
  console.log('  DreamLab Crypto Benchmarks: JS vs WASM');
  console.log('  ' + new Date().toISOString());
  console.log('  Node.js ' + process.version);
  console.log('='.repeat(76));
  console.log();

  // ── 1. HKDF-PRF Key Derivation (1000 iterations) ───────────────────────

  console.log('[1/7] HKDF-PRF Key Derivation (1000 iterations)');

  const jsHkdf = await benchmarkAsync(async () => {
    // Match passkey.ts: Web Crypto HKDF with SHA-256, empty salt, "nostr-secp256k1-v1" info
    // Since Web Crypto is async in Node, we use @noble/hashes HKDF which is the sync equivalent
    const derived = hkdf(sha256, PRF_OUTPUT, new Uint8Array(0), 'nostr-secp256k1-v1', 32);
    // Derive public key to match full operation
    const pk = getPublicKey(derived);
    return pk;
  }, 1000);

  const wasmHkdf = benchmark(() => {
    const kp = derive_keypair_from_prf(PRF_OUTPUT);
    return kp.publicKey;
  }, 1000);

  const hkdfSpeedup = jsHkdf.mean / wasmHkdf.mean;
  results.push({
    name: 'HKDF-PRF Key Derivation',
    iterations: 1000,
    js: jsHkdf,
    wasm: wasmHkdf,
    speedup: hkdfSpeedup,
  });
  printResult('HKDF-PRF Key Derivation', jsHkdf, wasmHkdf, hkdfSpeedup);

  // ── 2. Schnorr Sign (1000 iterations) ───────────────────────────────────

  console.log('[2/7] Schnorr Sign (1000 iterations)');

  const jsSchnorr = benchmark(() => {
    schnorr.sign(MSG_HASH, SECRET_KEY);
  }, 1000);

  const wasmSchnorr = benchmark(() => {
    schnorr_sign(SECRET_KEY, MSG_HASH);
  }, 1000);

  const schnorrSpeedup = jsSchnorr.mean / wasmSchnorr.mean;
  results.push({
    name: 'Schnorr Sign',
    iterations: 1000,
    js: jsSchnorr,
    wasm: wasmSchnorr,
    speedup: schnorrSpeedup,
  });
  printResult('Schnorr Sign', jsSchnorr, wasmSchnorr, schnorrSpeedup);

  // ── 3. NIP-44 Encrypt 1KB (500 iterations) ─────────────────────────────
  // Full encrypt: ECDH conversation key + ChaCha20-Poly1305 + HMAC + base64
  // JS side includes getConversationKey to match WASM which computes ECDH internally.

  console.log('[3/7] NIP-44 Encrypt 1KB (500 iterations)');

  const jsEnc1k = benchmark(() => {
    const ck = nip44js.v2.utils.getConversationKey(SECRET_KEY, PUBLIC_KEY_2_HEX);
    nip44js.v2.encrypt(PLAINTEXT_1KB, ck);
  }, 500);

  const wasmEnc1k = benchmark(() => {
    wasm_nip44_encrypt(SECRET_KEY, PUBLIC_KEY_2_BYTES, PLAINTEXT_1KB);
  }, 500);

  const enc1kSpeedup = jsEnc1k.mean / wasmEnc1k.mean;
  results.push({
    name: 'NIP-44 Encrypt 1KB',
    iterations: 500,
    js: jsEnc1k,
    wasm: wasmEnc1k,
    speedup: enc1kSpeedup,
  });
  printResult('NIP-44 Encrypt 1KB', jsEnc1k, wasmEnc1k, enc1kSpeedup);

  // ── 4. NIP-44 Encrypt 10KB (200 iterations) ────────────────────────────

  console.log('[4/7] NIP-44 Encrypt 10KB (200 iterations)');

  const jsEnc10k = benchmark(() => {
    const ck = nip44js.v2.utils.getConversationKey(SECRET_KEY, PUBLIC_KEY_2_HEX);
    nip44js.v2.encrypt(PLAINTEXT_10KB, ck);
  }, 200);

  const wasmEnc10k = benchmark(() => {
    wasm_nip44_encrypt(SECRET_KEY, PUBLIC_KEY_2_BYTES, PLAINTEXT_10KB);
  }, 200);

  const enc10kSpeedup = jsEnc10k.mean / wasmEnc10k.mean;
  results.push({
    name: 'NIP-44 Encrypt 10KB',
    iterations: 200,
    js: jsEnc10k,
    wasm: wasmEnc10k,
    speedup: enc10kSpeedup,
  });
  printResult('NIP-44 Encrypt 10KB', jsEnc10k, wasmEnc10k, enc10kSpeedup);

  // ── 5. NIP-44 Decrypt 1KB (500 iterations) ─────────────────────────────
  // Full decrypt: ECDH conversation key + HMAC verify + ChaCha20-Poly1305 + unpad
  // JS side includes getConversationKey to match WASM which computes ECDH internally.

  console.log('[5/7] NIP-44 Decrypt 1KB (500 iterations)');

  const jsDec1k = benchmark(() => {
    const ck = nip44js.v2.utils.getConversationKey(SECRET_KEY_2, PUBLIC_KEY_HEX);
    nip44js.v2.decrypt(JS_CIPHERTEXT_1KB, ck);
  }, 500);

  const wasmDec1k = benchmark(() => {
    wasm_nip44_decrypt(SECRET_KEY_2, PUBLIC_KEY_BYTES, WASM_CIPHERTEXT_1KB);
  }, 500);

  const dec1kSpeedup = jsDec1k.mean / wasmDec1k.mean;
  results.push({
    name: 'NIP-44 Decrypt 1KB',
    iterations: 500,
    js: jsDec1k,
    wasm: wasmDec1k,
    speedup: dec1kSpeedup,
  });
  printResult('NIP-44 Decrypt 1KB', jsDec1k, wasmDec1k, dec1kSpeedup);

  // ── 6. Event ID Computation (2000 iterations) ──────────────────────────

  console.log('[6/7] Event ID Computation (2000 iterations)');

  // JS: SHA-256 of NIP-01 canonical JSON [0, pubkey, created_at, kind, tags, content]
  const canonicalPrefix = `[0,"${PUBLIC_KEY_HEX}",${TIMESTAMP},1,${TAGS_JSON},"benchmark event content"]`;

  const jsEventId = benchmark(() => {
    const hash = sha256(new TextEncoder().encode(canonicalPrefix));
    bytesToHex(hash);
  }, 2000);

  const wasmEventId = benchmark(() => {
    compute_event_id(PUBLIC_KEY_HEX, TIMESTAMP, 1, TAGS_JSON, 'benchmark event content');
  }, 2000);

  const eventIdSpeedup = jsEventId.mean / wasmEventId.mean;
  results.push({
    name: 'Event ID Computation',
    iterations: 2000,
    js: jsEventId,
    wasm: wasmEventId,
    speedup: eventIdSpeedup,
  });
  printResult('Event ID Computation', jsEventId, wasmEventId, eventIdSpeedup);

  // ── 7. NIP-98 Token Creation (500 iterations) ──────────────────────────

  console.log('[7/7] NIP-98 Token Creation (500 iterations)');

  // JS: Full NIP-98 flow (build kind:27235 event, SHA-256 body hash, finalize+sign, base64)
  const jsNip98 = benchmark(() => {
    const bodyHash = bytesToHex(sha256(NIP98_BODY));
    const event = {
      kind: 27235,
      tags: [
        ['u', NIP98_URL],
        ['method', NIP98_METHOD],
        ['payload', bodyHash],
      ],
      created_at: TIMESTAMP,
      content: '',
    };
    const signed = finalizeEvent(event, SECRET_KEY);
    // Base64 encode
    const json = JSON.stringify(signed);
    return Buffer.from(json).toString('base64');
  }, 500);

  // WASM: create_nip98_token uses std::time::SystemTime::now() which panics in WASM.
  // We benchmark the equivalent operation decomposed: event_id + schnorr_sign
  // This gives a fair comparison of the crypto work without the WASM time syscall issue.
  let wasmNip98;
  let nip98WasmNote = '';
  try {
    wasmNip98 = benchmark(() => {
      wasm_create_nip98_token(SECRET_KEY, NIP98_URL, NIP98_METHOD, NIP98_BODY);
    }, 500);
  } catch {
    // Expected: WASM create_nip98_token panics because std::time::SystemTime::now()
    // is not available in WASM. Measure constituent operations instead.
    nip98WasmNote = ' (composite: hash + event_id + sign)';
    wasmNip98 = benchmark(() => {
      // 1. SHA-256 body hash (done in WASM internally)
      const bodyHash = sha256(NIP98_BODY);
      // 2. Compute event ID (the core NIP-01 canonical JSON + SHA-256)
      const tagsJson = JSON.stringify([
        ['u', NIP98_URL],
        ['method', NIP98_METHOD],
        ['payload', bytesToHex(bodyHash)],
      ]);
      const eventId = compute_event_id(PUBLIC_KEY_HEX, TIMESTAMP, 27235, tagsJson, '');
      // 3. Schnorr sign the event ID
      const idBytes = hexToUint8(eventId);
      schnorr_sign(SECRET_KEY, idBytes);
    }, 500);
  }

  const nip98Speedup = jsNip98.mean / wasmNip98.mean;
  results.push({
    name: 'NIP-98 Token Creation' + nip98WasmNote,
    iterations: 500,
    js: jsNip98,
    wasm: wasmNip98,
    speedup: nip98Speedup,
    note: nip98WasmNote ? 'WASM create_nip98_token panics (SystemTime unavailable); measured composite of hash + event_id + sign instead.' : '',
  });
  printResult('NIP-98 Token Creation', jsNip98, wasmNip98, nip98Speedup, nip98WasmNote);

  // ── Summary ────────────────────────────────────────────────────────────

  console.log();
  console.log('='.repeat(76));
  console.log('  SUMMARY');
  console.log('='.repeat(76));
  console.log();

  const avgSpeedup = results.reduce((s, r) => s + r.speedup, 0) / results.length;
  const minSpeedup = Math.min(...results.map(r => r.speedup));
  const maxSpeedup = Math.max(...results.map(r => r.speedup));

  console.log(`  Average speedup:  ${avgSpeedup.toFixed(2)}x`);
  console.log(`  Min speedup:      ${minSpeedup.toFixed(2)}x`);
  console.log(`  Max speedup:      ${maxSpeedup.toFixed(2)}x`);
  console.log();

  // Go/No-Go assessment
  const cryptoOps = results.filter(r =>
    r.name.includes('HKDF') || r.name.includes('Schnorr') || r.name.includes('NIP-44') || r.name.includes('Event ID')
  );
  const cryptoAvg = cryptoOps.reduce((s, r) => s + r.speedup, 0) / cryptoOps.length;
  const allAbove2x = cryptoOps.every(r => r.speedup >= 2.0);
  const allAbove3x = cryptoOps.every(r => r.speedup >= 3.0);

  console.log('  Go/No-Go Assessment (PRD criteria):');
  console.log(`    Crypto average speedup: ${cryptoAvg.toFixed(2)}x`);
  console.log(`    All crypto ops >= 2x:   ${allAbove2x ? 'YES' : 'NO'}`);
  console.log(`    All crypto ops >= 3x:   ${allAbove3x ? 'YES (preferred)' : 'NO'}`);

  if (allAbove3x) {
    console.log('    Verdict: GO -- exceeds preferred 3x threshold');
  } else if (allAbove2x) {
    console.log('    Verdict: GO -- meets minimum 2x threshold');
  } else {
    console.log('    Verdict: CONDITIONAL -- some ops below 2x minimum; evaluate reliability wins');
  }

  console.log();

  // Write JSON results for report.html consumption
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const jsonPath = join(__dirname, 'results.json');
  writeFileSync(jsonPath, JSON.stringify({
    timestamp: new Date().toISOString(),
    node: process.version,
    platform: `${process.platform} ${process.arch}`,
    results: results.map(r => ({
      name: r.name,
      iterations: r.iterations,
      js: { mean: r.js.mean, median: r.js.median, p95: r.js.p95, p99: r.js.p99, opsPerSec: r.js.opsPerSec },
      wasm: { mean: r.wasm.mean, median: r.wasm.median, p95: r.wasm.p95, p99: r.wasm.p99, opsPerSec: r.wasm.opsPerSec },
      speedup: r.speedup,
      note: r.note || '',
    })),
    summary: {
      avgSpeedup,
      minSpeedup,
      maxSpeedup,
      cryptoAvgSpeedup: cryptoAvg,
      allAbove2x,
      allAbove3x,
      verdict: allAbove3x ? 'GO (preferred)' : allAbove2x ? 'GO (minimum)' : 'CONDITIONAL',
    },
  }, null, 2));
  console.log(`  Results written to: ${jsonPath}`);
}

function printResult(name, js, wasm, speedup, note = '') {
  const tag = speedup >= 3 ? '\x1b[32m' : speedup >= 2 ? '\x1b[33m' : '\x1b[31m';
  const reset = '\x1b[0m';

  console.log(`  JS   mean: ${formatMs(js.mean).padStart(10)}  median: ${formatMs(js.median).padStart(10)}  p95: ${formatMs(js.p95).padStart(10)}  ops/s: ${formatOps(js.opsPerSec).padStart(8)}`);
  console.log(`  WASM mean: ${formatMs(wasm.mean).padStart(10)}  median: ${formatMs(wasm.median).padStart(10)}  p95: ${formatMs(wasm.p95).padStart(10)}  ops/s: ${formatOps(wasm.opsPerSec).padStart(8)}`);
  console.log(`  ${tag}Speedup: ${speedup.toFixed(2)}x${reset}${note}`);
  console.log();
}

await runAll();
