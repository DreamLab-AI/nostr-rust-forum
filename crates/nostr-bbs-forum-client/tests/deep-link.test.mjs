// GitHub Pages SPA deep-link restore (`__p`) in index.html.
// Run: node --test crates/nostr-bbs-forum-client/tests/
//
// Loads the real inline script from index.html into a vm sandbox with a
// stubbed `window.location` and `history`, then checks where it points the
// address bar. The script must never move the URL outside /community/, and
// must always strip `__p` (the operator site may inject a second, older copy
// of the pickup after this one; with `__p` gone that copy is inert).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const html = fs.readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'index.html'),
  'utf8'
);
const m = html.match(/SPA deep-link restore[\s\S]*?<script>([\s\S]*?)<\/script>/);
assert.ok(m, 'deep-link restore script not found in index.html');
const script = m[1];

/** Run the script against `href`; return the replaceState target (or null). */
function restore(href) {
  const url = new URL(href);
  const calls = [];
  const location = {
    href: url.href,
    origin: url.origin,
    pathname: url.pathname,
    search: url.search,
    hash: url.hash,
  };
  const sandbox = {
    URL,
    URLSearchParams,
    window: { location },
    history: { replaceState: (_s, _t, u) => calls.push(u) },
  };
  sandbox.window.history = sandbox.history;
  vm.runInNewContext(script, sandbox);
  assert.ok(calls.length <= 1, 'replaceState called more than once');
  return calls.length ? calls[0] : null;
}

const O = 'https://forum.example';

test('no __p leaves the URL alone', () => {
  assert.equal(restore(`${O}/community/`), null);
  assert.equal(restore(`${O}/community/?x=1#frag`), null);
});

test('restores an ordinary sub-path with query and hash', () => {
  assert.equal(restore(`${O}/community/?__p=%2Flogin`), '/community/login');
  assert.equal(
    restore(`${O}/community/?__p=%2Fchannel%2Fabc&tab=2#k`),
    '/community/channel/abc?tab=2#k'
  );
});

test('dot-segment traversal out of /community is refused', () => {
  for (const p of [
    '/../contact/',
    '/..',
    '/%2e%2e/contact',
    '/%2E%2E/%2e%2e/admin',
    '/foo/../../contact',
    '/.%2e/contact',
  ]) {
    const got = restore(`${O}/community/?__p=${encodeURIComponent(p)}`);
    assert.equal(got, '/community/', `__p=${p} must fall back, got ${got}`);
  }
});

test('backslash and scheme tricks are refused or stay inside /community', () => {
  for (const p of ['/\\..\\contact', '\\\\evil.example/x', 'https://evil.example/', 'javascript:alert(1)', '']) {
    const got = restore(`${O}/community/?__p=${encodeURIComponent(p)}`);
    assert.ok(
      got === '/community/' || got.startsWith('/community/'),
      `__p=${JSON.stringify(p)} escaped: ${got}`
    );
    assert.ok(!got.includes('evil.example') || got.startsWith('/community/'), got);
  }
});

test('protocol-relative __p stays a same-origin path under /community', () => {
  const got = restore(`${O}/community/?__p=${encodeURIComponent('//evil.example/x')}`);
  assert.ok(got.startsWith('/community/'), got);
  assert.ok(new URL(got, O).origin === O);
});

test('a refused __p is still stripped, keeping other params and the hash', () => {
  assert.equal(
    restore(`${O}/community/?__p=${encodeURIComponent('/../contact')}&a=b#h`),
    '/community/?a=b#h'
  );
});

test('the result never leaves /community', () => {
  const nasty = ['/a/../../b', '/%5c..%5cb', '/./../x', '/community/../../x', '/;/../x'];
  for (const p of nasty) {
    const got = restore(`${O}/community/?__p=${encodeURIComponent(p)}`);
    const u = new URL(got, O);
    assert.equal(u.origin, O);
    assert.ok(u.pathname === '/community' || u.pathname.startsWith('/community/'), `${p} -> ${got}`);
  }
});
