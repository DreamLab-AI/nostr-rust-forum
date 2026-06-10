/// Service worker for the nostr-bbs community forum.
/// Provides cache-first for static assets and network-first for navigation.

const CACHE_NAME = 'nostr-bbs-forum-v1';

const STATIC_ASSETS = [
  './',
  './index.html',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      )
    ).then(() =>
      // Refresh the offline-fallback copy of index.html on every activation —
      // the install-time precache otherwise pins a stale shell (and with it,
      // stale content-hashed asset references) across deploys.
      caches.open(CACHE_NAME).then((cache) =>
        fetch('./index.html', { cache: 'no-cache' })
          .then((r) => (r.ok ? cache.put('./index.html', r) : undefined))
          .catch(() => undefined)
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Skip non-GET and cross-origin requests
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) {
    return;
  }

  // Cache-first for static assets (wasm, js, css, images, fonts)
  if (url.pathname.match(/\.(wasm|js|css|png|jpg|jpeg|svg|ico|webp|woff2?)$/)) {
    event.respondWith(
      caches.match(event.request).then(
        (cached) =>
          cached ||
          fetch(event.request).then((response) => {
            if (response.ok) {
              const clone = response.clone();
              caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
            }
            return response;
          })
      )
    );
    return;
  }

  // Network-first for HTML / SPA navigation; keep the offline fallback fresh
  // by updating the cached shell whenever the network copy succeeds.
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put('./index.html', clone));
          }
          return response;
        })
        .catch(() => caches.match('./index.html'))
    );
    return;
  }

  // Network-first for everything else (API calls, WebSocket upgrades)
  event.respondWith(fetch(event.request));
});
