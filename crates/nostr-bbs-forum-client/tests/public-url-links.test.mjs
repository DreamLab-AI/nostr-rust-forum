// The post_build hook tools/public-url-links.sh, run against the real
// index.html as Trunk stages it, for several public URLs.
// Run: node --test crates/nostr-bbs-forum-client/tests/

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const crate = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = fs.readFileSync(path.join(crate, 'index.html'), 'utf8');
const hook = path.join(crate, 'tools', 'public-url-links.sh');

/** Stage `html`, run the hook with `publicUrl`, return the result. */
function run(publicUrl, html = source) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'public-url-links-'));
  try {
    fs.writeFileSync(path.join(dir, 'index.html'), html);
    const env = { ...process.env, TRUNK_STAGING_DIR: dir };
    if (publicUrl === undefined) delete env.TRUNK_PUBLIC_URL;
    else env.TRUNK_PUBLIC_URL = publicUrl;
    execFileSync('bash', [hook], { env });
    return fs.readFileSync(path.join(dir, 'index.html'), 'utf8');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const hrefOf = (html, rel, extra = '') => {
  const m = html.match(new RegExp(`<link rel="${rel}" href="([^"]*)"${extra}`));
  return m && m[1];
};

const MARKED = ['manifest', 'icon', 'apple-touch-icon'];

test('the manifest and icon links are marked in index.html', () => {
  for (const rel of MARKED) {
    assert.match(source, new RegExp(`<link rel="${rel}" href="[^"]*"[^>]* data-public-url`), rel);
  }
});

test('an absolute public URL prefixes every marked href and drops the marker', () => {
  const out = run('/community/');
  assert.equal(hrefOf(out, 'manifest'), '/community/manifest.webmanifest');
  assert.equal(hrefOf(out, 'icon', ' type="image/svg\\+xml"'), '/community/icons/icon.svg');
  assert.equal(hrefOf(out, 'icon', ' sizes="192x192"'), '/community/icons/icon-192.png');
  assert.equal(hrefOf(out, 'apple-touch-icon'), '/community/icons/apple-touch-icon.png');
  assert.doesNotMatch(out, /data-public-url/);
});

test('the root public URL, with or without the variable, gives root paths', () => {
  for (const pub of ['/', undefined]) {
    const out = run(pub);
    assert.equal(hrefOf(out, 'manifest'), '/manifest.webmanifest', String(pub));
  }
});

test('a public URL without a trailing slash still joins with one', () => {
  assert.equal(hrefOf(run('/x/y'), 'manifest'), '/x/y/manifest.webmanifest');
});

test('a relative public URL leaves the hrefs relative', () => {
  const out = run('./');
  assert.equal(hrefOf(out, 'manifest'), 'manifest.webmanifest');
  assert.doesNotMatch(out, /data-public-url/);
});

test('only marked, relative hrefs change; everything else is byte-identical', () => {
  const html =
    '<head><link rel="stylesheet" href="a.css">' +
    '<link rel="icon" href="/abs.png" data-public-url>' +
    '<link rel="icon" href="https://cdn.example/x.png" data-public-url>' +
    '<link rel="icon" href="data:image/png;base64,AA==" data-public-url>' +
    '<link rel="manifest" href="m.json" data-public-url></head>';
  assert.equal(
    run('/community/', html),
    '<head><link rel="stylesheet" href="a.css">' +
      '<link rel="icon" href="/abs.png">' +
      '<link rel="icon" href="https://cdn.example/x.png">' +
      '<link rel="icon" href="data:image/png;base64,AA==">' +
      '<link rel="manifest" href="/community/m.json"></head>\n'
  );
  // Outside the marked tags the document is unchanged.
  const out = run('/community/');
  assert.equal(
    out.replaceAll('href="/community/', 'href="'),
    source.replaceAll(' data-public-url', '').replace(/\n*$/, '\n')
  );
});

// The retro BBS client shares this hook (its Trunk.toml runs this script):
// its manifest and touch-icon links resolve under /community/bbs/.
const bbsCrate = path.join(crate, '..', 'nostr-bbs-bbs-client');
const bbsSource = fs.readFileSync(path.join(bbsCrate, 'index.html'), 'utf8');

test('the BBS marks its manifest and touch icon and runs this hook', () => {
  for (const rel of ['manifest', 'apple-touch-icon']) {
    assert.match(bbsSource, new RegExp(`<link rel="${rel}" href="[^"]*"[^>]* data-public-url`), rel);
  }
  const trunk = fs.readFileSync(path.join(bbsCrate, 'Trunk.toml'), 'utf8');
  assert.match(trunk, /stage = "post_build"\s*\ncommand = "bash"\s*\ncommand_arguments = \["\.\.\/nostr-bbs-forum-client\/tools\/public-url-links\.sh"\]/);
});

test('the BBS public URL prefixes its marked hrefs and leaves the rest alone', () => {
  const out = run('/community/bbs/', bbsSource);
  assert.equal(hrefOf(out, 'manifest'), '/community/bbs/manifest.webmanifest');
  assert.equal(hrefOf(out, 'apple-touch-icon'), '/community/bbs/icons/icon-192.png');
  assert.doesNotMatch(out, /data-public-url/);
  assert.equal(
    out.replaceAll('href="/community/bbs/', 'href="'),
    bbsSource.replaceAll(' data-public-url', '').replace(/\n*$/, '\n')
  );
});
