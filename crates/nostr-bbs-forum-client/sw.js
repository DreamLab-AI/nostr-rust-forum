/// Service worker for the nostr-bbs community forum.
///
/// Freshness strategy (PWA standard — fixes stale-deploy bug):
///   * Navigation / HTML document  -> NETWORK-FIRST with HTTP-cache BYPASS.
///     index.html carries the deploy's `window.__ENV__.BUILD_HASH` and the
///     content-hashed WASM/JS bundle references, so it MUST be re-fetched from
///     the network (not the browser HTTP cache) on every load. A stale shell
///     pins a stale build hash and a stale bundle pointer across reloads.
///   * Content-hashed static assets (wasm/js/css/img/font) -> CACHE-FIRST.
///     Trunk fingerprints these (`name-<hash>.ext`), so a new build emits a new
///     URL; cache-first on an immutable URL is safe and fast.
///   * Everything else (API, WS upgrades) -> NETWORK-ONLY.
///
/// The cache name embeds a build token so each deploy gets a fresh cache and
/// `activate` deletes every prior cache. `__SW_BUILD__` is rewritten by the
/// operator deploy pipeline (sed) to the build SHA; if left unsubstituted it
/// falls back to a static tag and the navigation-network-first rule alone still
/// guarantees a fresh index.html (and thus a fresh build) on every load.

const BUILD_TOKEN = '__SW_BUILD__';
const CACHE_VERSION =
  BUILD_TOKEN === ('__SW_' + 'BUILD__') ? 'v2' : BUILD_TOKEN;
const CACHE_NAME = `nostr-bbs-forum-${CACHE_VERSION}`;

const STATIC_ASSETS = ['./', './index.html'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      // Bypass the HTTP cache while precaching the shell so the very first
      // install of a new worker grabs the freshly-deployed index.html.
      .then((cache) =>
        Promise.all(
          STATIC_ASSETS.map((url) =>
            fetch(url, { cache: 'reload' })
              .then((r) => (r.ok ? cache.put(url, r) : undefined))
              .catch(() => undefined)
          )
        )
      )
  );
  // Take over without waiting for existing tabs to close.
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
        )
      )
      // Refresh the offline-fallback shell on activation, bypassing the HTTP
      // cache, so the cached fallback never pins stale content-hashed refs.
      .then(() =>
        caches.open(CACHE_NAME).then((cache) =>
          fetch('./index.html', { cache: 'reload' })
            .then((r) => (r.ok ? cache.put('./index.html', r) : undefined))
            .catch(() => undefined)
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Skip non-GET and cross-origin requests (API/WS handled by the network).
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) {
    return;
  }

  // The retro BBS is a SEPARATE SPA mounted under this SW's scope at
  // `<scope>bbs/` (e.g. /community/bbs/). It has its own index.html and its own
  // assets — the forum SW must NOT touch it. Without this bypass the navigate
  // branch below would (a) cache the BBS index.html under this SW's
  // `./index.html` key, poisoning the forum's offline shell with BBS markup,
  // and (b) on any offline/stale path serve the forum shell for a /bbs/ URL,
  // which the forum router can't resolve (→ NotFound / "404"). Leave every
  // BBS request to the network so both apps stay independent.
  const scopePath = new URL(self.registration.scope).pathname;
  if (url.pathname === scopePath + 'bbs' || url.pathname.startsWith(scopePath + 'bbs/')) {
    return; // no respondWith → default browser network handling
  }

  // Network-first WITH HTTP-cache bypass for the SPA navigation document.
  // This is the crux of the stale-deploy fix: a plain fetch(request) may return
  // a stale browser-HTTP-cached index.html, re-pinning the old BUILD_HASH and
  // old bundle pointer. `cache: 'reload'` forces a conditional revalidation
  // against the origin. Falls back to the cached shell only when offline.
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request, { cache: 'reload' })
        .then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches
              .open(CACHE_NAME)
              .then((cache) => cache.put('./index.html', clone));
          }
          return response;
        })
        .catch(() =>
          caches
            .match('./index.html')
            .then(
              (cached) =>
                cached ||
                new Response('Offline', {
                  status: 503,
                  statusText: 'Offline',
                })
            )
        )
    );
    return;
  }

  // Cache-first for immutable, content-hashed static assets.
  if (url.pathname.match(/\.(wasm|js|css|png|jpg|jpeg|svg|ico|webp|woff2?)$/)) {
    event.respondWith(
      caches.match(event.request).then(
        (cached) =>
          cached ||
          fetch(event.request).then((response) => {
            if (response.ok) {
              const clone = response.clone();
              caches
                .open(CACHE_NAME)
                .then((cache) => cache.put(event.request, clone));
            }
            return response;
          })
      )
    );
    return;
  }

  // Network-only for everything else (API calls, WebSocket upgrades).
  event.respondWith(fetch(event.request));
});

// Allow the page to ask a waiting worker to activate immediately.
self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// ---------------------------------------------------------------------------
// Web Push (ADR-2023): content-free wake-ups.
//
// The relay sends an EMPTY push. We wake, read the drain credentials the page
// stored in IndexedDB ("nostr-bbs-push" / "kv" / "cfg" — written by js/push.js),
// ask the relay over HTTPS what is pending, and show generic notifications.
// Nothing about a message ever travels through the push service, and the
// Nostr key is never needed here.
// ---------------------------------------------------------------------------

const PUSH_DB = 'nostr-bbs-push';
const PUSH_STORE = 'kv';
const PUSH_CFG_KEY = 'cfg';

function readPushCfg() {
  return new Promise((resolve) => {
    try {
      const open = indexedDB.open(PUSH_DB, 1);
      open.onupgradeneeded = () => open.result.createObjectStore(PUSH_STORE);
      open.onerror = () => resolve(null);
      open.onsuccess = () => {
        const db = open.result;
        const get = db.transaction(PUSH_STORE, 'readonly').objectStore(PUSH_STORE).get(PUSH_CFG_KEY);
        get.onsuccess = () => {
          db.close();
          try {
            resolve(get.result ? JSON.parse(get.result) : null);
          } catch (_) {
            resolve(null);
          }
        };
        get.onerror = () => {
          db.close();
          resolve(null);
        };
      };
    } catch (_) {
      resolve(null);
    }
  });
}

async function drainPending(cfg) {
  if (!cfg || !cfg.api || !cfg.id || !cfg.token) return null;
  try {
    const resp = await fetch(`${cfg.api}/api/push/drain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: cfg.id, token: cfg.token }),
    });
    return resp.ok ? await resp.json() : null;
  } catch (_) {
    return null;
  }
}

function plural(n, one, many) {
  return n === 1 ? one : `${n} ${many}`;
}

/** Notifications to show for a drain result: [{tag, body, url}]. */
function composePushNotifications(drained) {
  const out = [];
  if (!drained) return out;
  if (drained.dm > 0) {
    out.push({ tag: 'nbbs-dm', body: plural(drained.dm, 'New direct message', 'new direct messages'), url: 'dm' });
  }
  if (drained.reply > 0) {
    out.push({
      tag: 'nbbs-reply',
      body: plural(drained.reply, 'New reply or mention', 'new replies and mentions'),
      url: (drained.link_reply || '').replace(/^\//, '') || '',
    });
  }
  if (drained.topic > 0) {
    out.push({
      tag: 'nbbs-topic',
      body: plural(drained.topic, 'New topic', 'new topics'),
      url: (drained.link_topic || '').replace(/^\//, '') || '',
    });
  }
  if (drained.post > 0) {
    out.push({
      tag: 'nbbs-post',
      body: plural(drained.post, 'New message', 'new messages'),
      url: (drained.link_post || '').replace(/^\//, '') || '',
    });
  }
  return out;
}

/**
 * Windows that belong to the forum app: inside this SW's scope, and not the
 * retro BBS (a separate SPA under scope/bbs/ with its own service worker).
 * `matchAll` returns every window on the origin, and on a branded deployment
 * the marketing site shares it, so an unfiltered check would let a visible
 * marketing tab swallow every forum alert.
 */
async function forumWindows() {
  const scope = self.registration.scope;
  const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  return all.filter((w) => w.url.startsWith(scope) && !w.url.startsWith(scope + 'bbs'));
}

async function handlePush() {
  // A visible, focused window already shows the activity in-app.
  const cfg = await readPushCfg();
  const drained = await drainPending(cfg);
  if ((await forumWindows()).some((c) => c.visibilityState === 'visible')) {
    // The member is looking at the app, which already shows this. Draining
    // anyway clears the counters server side: if they stayed above zero the
    // relay would see an outstanding burst and keep waking this device.
    return;
  }

  const items = composePushNotifications(drained);
  const title = (cfg && cfg.brand) || 'Community';
  if (items.length === 0) {
    // Another device already drained, or the relay was unreachable. A push
    // must still show something (userVisibleOnly), so keep it generic.
    items.push({ tag: 'nbbs-generic', body: 'There is new activity. Open to catch up.', url: '' });
  }
  await Promise.all(
    items.map((n) =>
      self.registration.showNotification(title, {
        body: n.body,
        tag: n.tag,
        renotify: true,
        icon: 'icons/icon-192.png',
        badge: 'icons/icon-192.png',
        data: { url: n.url },
      })
    )
  );
}

self.addEventListener('push', (event) => {
  event.waitUntil(handlePush());
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const rel = (event.notification.data && event.notification.data.url) || '';
  // Only ever open a page inside our own scope: a click target is data that
  // came over the network, so an off-origin value falls back to the app root.
  const scope = new URL(self.registration.scope);
  let targetUrl = new URL(rel, scope);
  if (targetUrl.origin !== scope.origin || !targetUrl.pathname.startsWith(scope.pathname)) {
    targetUrl = scope;
  }
  const target = targetUrl.href;
  event.waitUntil(
    (async () => {
      for (const w of await forumWindows()) {
        if ('focus' in w) {
          await w.focus();
          if ('navigate' in w) {
            try {
              await w.navigate(target);
            } catch (_) {
              /* cross-scope or uncontrolled: focus is enough */
            }
          }
          return;
        }
      }
      await self.clients.openWindow(target);
    })()
  );
});
