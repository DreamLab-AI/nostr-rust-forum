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
