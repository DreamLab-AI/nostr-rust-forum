/*
 * BBS service worker (ADR-109) — scoped to /community/bbs/.
 *
 * Purpose: make the BBS installable (a fetch-handling SW is still required for
 * `beforeinstallprompt` since Chrome 108/112) WITHOUT ever serving a stale app
 * shell — this repo previously shipped a BBS cache-404 where a cached
 * index.html was served for a path the client could not resolve. The rules
 * below make that class structurally impossible:
 *
 *   1. Navigations / HTML documents  -> NETWORK-FIRST, HTTP-cache-bypassing.
 *      index.html carries the deploy's __ENV__ + content-hashed WASM/JS refs, so
 *      it is re-fetched from the network every load ({cache:'reload'}). It is
 *      NEVER served from Cache Storage for a navigation. On a network failure we
 *      serve a cached fallback ONLY if one already exists — never a poisoned
 *      shell — else the failure propagates.
 *   2. Trunk content-hashed static assets (name-<hash>.ext) -> CACHE-FIRST.
 *      These URLs are immutable (the hash changes when the bytes change), so
 *      caching them can never serve stale content.
 *   3. Everything else (relay WS, POD/PREVIEW/SEARCH APIs, cross-origin,
 *      non-GET) -> NETWORK-ONLY (no respondWith → default browser handling).
 *
 * Because this SW is served at /community/bbs/bbs-sw.js its default max scope is
 * /community/bbs/ — longest-scope-wins routes BBS fetches here in preference to
 * the forum's /community/ SW, and no Service-Worker-Allowed header is needed.
 *
 * __SW_BUILD__ is stamped per-deploy (deploy.yml) so each release gets a fresh
 * cache; activation deletes every prior cache.
 */

'use strict';

var BUILD = '__SW_BUILD__';
var CACHE_NAME = 'bbs-assets-' + BUILD;

// A Trunk fingerprinted asset: name-<hex hash>.<ext>. Only these are cacheable.
var HASHED_ASSET = /-[0-9a-f]{8,}\.(?:wasm|js|css|png|svg|opus|woff2?)$/i;

self.addEventListener('install', function (event) {
  // Take over as soon as installed; navigations remain network-first regardless.
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(
        keys.map(function (k) {
          if (k !== CACHE_NAME) return caches.delete(k);
          return undefined;
        })
      );
    }).then(function () {
      return self.clients.claim();
    })
  );
});

self.addEventListener('fetch', function (event) {
  var req = event.request;

  // Only GET, same-origin requests are ours; everything else falls through to
  // the browser's default network handling (no respondWith).
  if (req.method !== 'GET') return;

  var url;
  try {
    url = new URL(req.url);
  } catch (e) {
    return;
  }
  if (url.origin !== self.location.origin) return;

  var isNavigation =
    req.mode === 'navigate' ||
    (req.headers.get('accept') || '').indexOf('text/html') !== -1;

  if (isNavigation) {
    // NETWORK-FIRST with HTTP-cache bypass. Never serve index.html from cache
    // for a navigation; only fall back to a pre-existing cached response if the
    // network is unreachable (and never write the shell into the cache here).
    event.respondWith(
      fetch(req, { cache: 'reload' }).catch(function () {
        return caches.match(req).then(function (hit) {
          return hit || Response.error();
        });
      })
    );
    return;
  }

  if (HASHED_ASSET.test(url.pathname)) {
    // CACHE-FIRST for immutable fingerprinted assets.
    event.respondWith(
      caches.match(req).then(function (hit) {
        if (hit) return hit;
        return fetch(req).then(function (resp) {
          if (resp && resp.ok) {
            var copy = resp.clone();
            caches.open(CACHE_NAME).then(function (cache) {
              cache.put(req, copy);
            });
          }
          return resp;
        });
      })
    );
    return;
  }

  // NETWORK-ONLY for everything else — no respondWith, default handling.
});
