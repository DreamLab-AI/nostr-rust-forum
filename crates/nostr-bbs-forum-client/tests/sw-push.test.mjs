// Service-worker Web Push behaviour (ADR-2023). Run: node --test tests/sw-push.test.mjs
//
// Loads the real sw.js into a vm sandbox with stubbed worker globals, then
// drives its `push` and `notificationclick` listeners.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const swSource = fs.readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'sw.js'),
  'utf8'
);

/** Build a sandbox. `cfg` is the IndexedDB record; `drain` the relay reply. */
function makeWorker({ cfg, drain, windows = [] }) {
  const listeners = {};
  const shown = [];
  const opened = [];
  const fetched = [];
  const focused = [];
  const navigated = [];
  const stored = new Map(); // Cache API stand-in, keyed by request URL

  const fakeIdb = {
    open() {
      const req = {};
      queueMicrotask(() => {
        req.result = {
          createObjectStore() {},
          close() {},
          transaction: () => ({
            objectStore: () => ({
              get() {
                const g = {};
                queueMicrotask(() => {
                  g.result = cfg === undefined ? undefined : JSON.stringify(cfg);
                  g.onsuccess && g.onsuccess();
                });
                return g;
              },
            }),
          }),
        };
        req.onupgradeneeded && req.onupgradeneeded();
        req.onsuccess && req.onsuccess();
      });
      return req;
    },
  };

  const self = {
    location: { origin: 'https://forum.example', pathname: '/community/sw.js' },
    registration: {
      scope: 'https://forum.example/community/',
      showNotification: async (title, opts) => shown.push({ title, ...opts }),
    },
    clients: {
      matchAll: async () => windows,
      openWindow: async (u) => opened.push(u),
      claim: async () => {},
    },
    addEventListener: (type, fn) => (listeners[type] = fn),
    skipWaiting: () => {},
  };
  const sandbox = {
    self,
    indexedDB: fakeIdb,
    fetch: async (url, init) => {
      fetched.push({ url, init });
      if (drain === 'network-error') throw new Error('offline');
      return { ok: drain !== null, json: async () => drain, clone() { return this; }, from: 'network' };
    },
    URL,
    JSON,
    Promise,
    Response: class {
      constructor(body, init) {
        Object.assign(this, { body }, init);
      }
    },
    caches: {
      open: async () => ({ put: async (req, res) => stored.set(req.url, res) }),
      keys: async () => [],
      match: async (req) => stored.get(typeof req === 'string' ? req : req.url),
    },
    console,
    queueMicrotask,
  };
  vm.createContext(sandbox);
  vm.runInContext(swSource, sandbox);

  const fire = async (type, event) => {
    let pending;
    listeners[type]({ ...event, waitUntil: (p) => (pending = p) });
    await pending;
  };
  /** Fire a same-origin GET `fetch` event; resolves to what respondWith got
   *  (`undefined` when the worker declined to handle it). */
  const fetchEvent = async (pathname, mode = 'no-cors') => {
    let responded;
    listeners.fetch({
      request: { method: 'GET', url: 'https://forum.example' + pathname, mode },
      respondWith: (p) => (responded = Promise.resolve(p)),
    });
    const res = responded && (await responded);
    await new Promise((r) => setTimeout(r)); // let the fire-and-forget cache.put land
    return res;
  };
  return { fire, fetchEvent, stored, shown, opened, fetched, focused, navigated };
}

const CFG = { api: 'https://relay.example', id: 'sub1', token: 'tok', brand: 'DreamLab' };

test('push drains with the stored credentials and shows one notification per category', async () => {
  const w = makeWorker({
    cfg: CFG,
    drain: { dm: 1, reply: 3, topic: 0, post: 0, link_reply: '/go/abc' },
  });
  await w.fire('push', {});
  assert.equal(w.fetched.length, 1);
  assert.equal(w.fetched[0].url, 'https://relay.example/api/push/drain');
  assert.deepEqual(JSON.parse(w.fetched[0].init.body), { id: 'sub1', token: 'tok' });

  assert.equal(w.shown.length, 2);
  const dm = w.shown.find((n) => n.tag === 'nbbs-dm');
  const reply = w.shown.find((n) => n.tag === 'nbbs-reply');
  assert.equal(dm.title, 'DreamLab');
  assert.equal(dm.body, 'New direct message');
  assert.equal(dm.data.url, 'dm');
  assert.equal(reply.body, '3 new replies and mentions');
  assert.equal(reply.data.url, 'go/abc', 'leading slash stripped so it resolves inside the scope');
});

test('notifications never carry message content, only counts', async () => {
  const w = makeWorker({ cfg: CFG, drain: { dm: 2, reply: 0, topic: 1, post: 4 } });
  await w.fire('push', {});
  for (const n of w.shown) {
    assert.match(n.body, /^(New|\d+ new)/);
    assert.ok(!/[a-f0-9]{16}/.test(n.body), 'no ids or keys in the body');
  }
  assert.deepEqual(
    w.shown.map((n) => n.tag).sort(),
    ['nbbs-dm', 'nbbs-post', 'nbbs-topic']
  );
});

test('an empty drain still shows a generic notification (userVisibleOnly)', async () => {
  const w = makeWorker({ cfg: CFG, drain: { dm: 0, reply: 0, topic: 0, post: 0 } });
  await w.fire('push', {});
  assert.equal(w.shown.length, 1);
  assert.equal(w.shown[0].tag, 'nbbs-generic');
});

test('a failed or unreachable drain falls back to the generic notification', async () => {
  for (const drain of [null, 'network-error']) {
    const w = makeWorker({ cfg: CFG, drain });
    await w.fire('push', {});
    assert.equal(w.shown.length, 1, String(drain));
    assert.equal(w.shown[0].tag, 'nbbs-generic');
  }
});

test('missing credentials never call the relay and still show something', async () => {
  const w = makeWorker({ cfg: undefined, drain: {} });
  await w.fire('push', {});
  assert.equal(w.fetched.length, 0);
  assert.equal(w.shown.length, 1);
  assert.equal(w.shown[0].title, 'Community');
});

test('a visible window suppresses the notification but still drains the counters', async () => {
  const w = makeWorker({
    cfg: CFG,
    drain: { dm: 1 },
    windows: [{ visibilityState: 'visible', url: 'https://forum.example/community/' }],
  });
  await w.fire('push', {});
  assert.equal(w.shown.length, 0);
  assert.equal(w.fetched.length, 1, 'drained anyway, or the relay keeps waking this device');
});

test('clicking opens the deep link inside the scope when no window exists', async () => {
  const w = makeWorker({ cfg: CFG, drain: {} });
  let closed = false;
  await w.fire('notificationclick', {
    notification: { close: () => (closed = true), data: { url: 'go/abc' } },
  });
  assert.ok(closed);
  assert.deepEqual(w.opened, ['https://forum.example/community/go/abc']);
});

test('clicking focuses and navigates an existing app window', async () => {
  const log = [];
  const win = {
    url: 'https://forum.example/community/forums',
    visibilityState: 'hidden',
    focus: async () => log.push('focus'),
    navigate: async (u) => log.push(`navigate ${u}`),
  };
  const w = makeWorker({ cfg: CFG, drain: {}, windows: [win] });
  await w.fire('notificationclick', {
    notification: { close() {}, data: { url: 'dm' } },
  });
  assert.deepEqual(log, ['focus', 'navigate https://forum.example/community/dm']);
  assert.equal(w.opened.length, 0);
});

test('a click target cannot escape the app scope', async () => {
  for (const url of ['https://evil.example/x', '//evil.example/x', '/elsewhere']) {
    const w = makeWorker({ cfg: CFG, drain: {} });
    await w.fire('notificationclick', { notification: { close() {}, data: { url } } });
    assert.deepEqual(w.opened, ['https://forum.example/community/'], url);
  }
});

test('a visible window outside the app scope does not swallow the alert', async () => {
  const w = makeWorker({
    cfg: CFG,
    drain: { dm: 1 },
    windows: [
      { visibilityState: 'visible', url: 'https://forum.example/' }, // marketing site, same origin
      { visibilityState: 'visible', url: 'https://forum.example/community/bbs/' }, // separate SPA + SW
    ],
  });
  await w.fire('push', {});
  assert.equal(w.shown.length, 1);
  assert.equal(w.shown[0].tag, 'nbbs-dm');
});

test('clicking never focuses the BBS window or one outside the scope', async () => {
  const log = [];
  const bbs = { url: 'https://forum.example/community/bbs/', focus: async () => log.push('bbs'), navigate: async () => log.push('bbs-nav') };
  const site = { url: 'https://forum.example/', focus: async () => log.push('site'), navigate: async () => log.push('site-nav') };
  const w = makeWorker({ cfg: CFG, drain: {}, windows: [bbs, site] });
  await w.fire('notificationclick', { notification: { close() {}, data: { url: 'dm' } } });
  assert.deepEqual(log, []);
  assert.deepEqual(w.opened, ['https://forum.example/community/dm']);
});

// Real Trunk output names (from a `trunk build` dist listing).
const WASM = '/community/nostr-bbs-forum-client-fe2d3df96da40e55_bg.wasm';
const BUNDLE_JS = '/community/nostr-bbs-forum-client-fe2d3df96da40e55.js';
const SNIPPET = '/community/snippets/nostr-bbs-forum-client-0123456789abcdef/js/push.js';
const ICON = '/community/icons/icon-192.png';

test('fingerprinted and snippet assets are served cache-first', async () => {
  for (const p of [WASM, BUNDLE_JS, SNIPPET]) {
    const w = makeWorker({ cfg: CFG, drain: {} });
    w.stored.set('https://forum.example' + p, { from: 'cache' });
    const res = await w.fetchEvent(p);
    assert.equal(res.from, 'cache', p);
    assert.equal(w.fetched.length, 0, 'no network round trip on a hit');
  }
  // a miss goes to the network and is stored
  const w = makeWorker({ cfg: CFG, drain: {} });
  const p = '/community/app-0123456789abcdef.css';
  const res = await w.fetchEvent(p);
  assert.equal(res.from, 'network');
  assert.ok(w.stored.has('https://forum.example' + p));
});

test('stable-URL static files are network-first with a cache fallback', async () => {
  // online: the network wins even though a stale copy is cached
  const w = makeWorker({ cfg: CFG, drain: {} });
  w.stored.set('https://forum.example' + ICON, { from: 'cache' });
  const fresh = await w.fetchEvent(ICON);
  assert.equal(fresh.from, 'network');
  assert.equal(w.stored.get('https://forum.example' + ICON).from, 'network', 'cache refreshed');

  // offline: falls back to the cached copy, else a 503
  const off = makeWorker({ cfg: CFG, drain: 'network-error' });
  off.stored.set('https://forum.example' + ICON, { from: 'cache' });
  assert.equal((await off.fetchEvent(ICON)).from, 'cache');
  const cold = makeWorker({ cfg: CFG, drain: 'network-error' });
  assert.equal((await cold.fetchEvent(ICON)).status, 503);
});

test('the shell documents are never cache-first', async () => {
  for (const p of ['/community/index.html', '/community/sw.js', '/community/manifest.webmanifest']) {
    const w = makeWorker({ cfg: CFG, drain: {} });
    w.stored.set('https://forum.example' + p, { from: 'cache' });
    const res = await w.fetchEvent(p);
    assert.equal(res.from, 'network', p);
  }
});
