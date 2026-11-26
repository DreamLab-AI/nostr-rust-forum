// Web Push bridge for the forum client (ADR-2023).
//
// Everything here is browser plumbing the Rust side cannot do without a pile
// of web-sys feature flags: permission, PushManager, and the tiny IndexedDB
// record the service worker reads when a push wakes it. sw.js reads the same
// database ("nostr-bbs-push", store "kv", key "cfg"); keep the names in sync.
//
// The record holds the relay API base, the subscription id and the bearer
// token used by POST /api/push/drain. It never holds the Nostr secret key:
// service workers cannot reach localStorage, and the key must not move.

const DB_NAME = 'nostr-bbs-push';
const STORE = 'kv';
const CFG_KEY = 'cfg';

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function withStore(mode, fn) {
  return openDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        let tx;
        try {
          tx = db.transaction(STORE, mode);
          const result = fn(tx.objectStore(STORE));
          tx.oncomplete = () => {
            db.close();
            resolve(result && result.result !== undefined ? result.result : undefined);
          };
          tx.onerror = () => {
            db.close();
            reject(tx.error);
          };
          // A quota or version abort fires onabort, not onerror: without this the
          // promise never settles and the connection leaks.
          tx.onabort = () => {
            db.close();
            reject(tx.error || new Error('IndexedDB transaction aborted'));
          };
        } catch (e) {
          // transaction()/put() can throw synchronously (closed database,
          // unserialisable value): release the connection and fail the promise.
          db.close();
          reject(e);
        }
      })
  );
}

function b64urlToBytes(b64) {
  const pad = '='.repeat((4 - (b64.length % 4)) % 4);
  const raw = atob((b64 + pad).replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function sameKey(buf, bytes) {
  if (!buf) return false;
  const a = new Uint8Array(buf);
  if (a.length !== bytes.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== bytes[i]) return false;
  return true;
}

/** Whether this browser can do Web Push at all. */
export function pushSupported() {
  return (
    typeof window !== 'undefined' &&
    'serviceWorker' in navigator &&
    'PushManager' in window &&
    'Notification' in window
  );
}

/** System notifications possible at all: Notification API + a service worker. */
export function pushNotificationsSupported() {
  return typeof window !== 'undefined' && 'Notification' in window && 'serviceWorker' in navigator;
}

/** "default" | "granted" | "denied" | "unsupported". */
export function pushPermission() {
  return 'Notification' in window ? Notification.permission : 'unsupported';
}

/** Ask for notification permission. Call from a user gesture. */
export function pushRequestPermission() {
  return Notification.requestPermission();
}

/** True when running as an installed app (iOS needs this for Web Push). */
export function pushIsStandalone() {
  return (
    (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) ||
    navigator.standalone === true
  );
}

/** Subscribe (or reuse the subscription) and return its endpoint URL. */
export async function pushSubscribe(vapidPublicKeyB64) {
  const reg = await navigator.serviceWorker.ready;
  const key = b64urlToBytes(vapidPublicKeyB64);
  let sub = await reg.pushManager.getSubscription();
  if (sub && !sameKey(sub.options && sub.options.applicationServerKey, key)) {
    // Subscribed under a different VAPID key (operator rotated it).
    await sub.unsubscribe();
    sub = null;
  }
  if (!sub) {
    sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: key,
    });
  }
  return sub.endpoint;
}

/** Endpoint of the current subscription, or "" when there is none. */
export async function pushCurrentEndpoint() {
  if (!('serviceWorker' in navigator)) return '';
  const reg = await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.getSubscription();
  return sub ? sub.endpoint : '';
}

/** Drop the browser-side subscription. Returns the endpoint it had, or "". */
export async function pushUnsubscribe() {
  const reg = await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.getSubscription();
  if (!sub) return '';
  const endpoint = sub.endpoint;
  await sub.unsubscribe();
  return endpoint;
}

/** Persist the drain credentials for the service worker (JSON string). */
export function pushStoreCfg(json) {
  return withStore('readwrite', (s) => s.put(json, CFG_KEY));
}

/** Forget the drain credentials. */
export function pushClearCfg() {
  return withStore('readwrite', (s) => s.delete(CFG_KEY));
}

/**
 * Show a system notification through the service worker registration (the only
 * form Android Chrome allows). `url` is the in-app path to open on click.
 */
export async function pushShowLocal(title, body, url, tag) {
  const reg = await navigator.serviceWorker.ready;
  await reg.showNotification(title, {
    body,
    tag,
    renotify: true,
    icon: 'icons/icon-192.png',
    badge: 'icons/icon-192.png',
    data: { url },
  });
}

/**
 * Fire-and-forget POST that survives page navigation (logout redirects at once).
 * `text/plain` keeps it a CORS "simple" request, so no preflight is needed.
 */
export function pushBeacon(url, body) {
  try {
    return navigator.sendBeacon(url, new Blob([body], { type: 'text/plain' }));
  } catch (_) {
    return false;
  }
}
