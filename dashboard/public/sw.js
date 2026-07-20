/*
 * MCPIP console service worker — the minimum for an INSTALLABLE, offline-capable
 * PWA, and nothing that could compromise the fail-closed contract.
 *
 * Caching policy (deliberately conservative):
 *   - Navigations (the HTML shell): NETWORK-FIRST, falling back to the cached
 *     shell only when offline. So a fresh deploy is always picked up when online —
 *     the console never serves a stale build that could misrepresent live state.
 *   - Hashed static assets (/assets/*, Vite's content-hashed, immutable output)
 *     + the icons/manifest: CACHE-FIRST. Safe because the filename changes on
 *     every change, so a cache hit is byte-identical to the network.
 *   - EVERYTHING ELSE is passed straight through (no respondWith): cross-origin
 *     requests (the gateway API lives on another origin) and any same-origin
 *     `/v1/*` or `/metrics` call are NEVER cached or served from cache — the
 *     authorization path always hits the live gateway, never a stale worker.
 */
const CACHE = 'mcpip-console-v1';
const SHELL = ['/', '/index.html', '/manifest.webmanifest', '/icon.svg', '/icon-maskable.svg'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  // Only ever touch our OWN origin's static shell; the gateway API (cross-origin,
  // or same-origin /v1//metrics) is always live, never cached.
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/v1/') || url.pathname === '/metrics') return;

  // Navigations → network-first with an offline fallback to the cached shell.
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put('/', copy)).catch(() => {});
          return res;
        })
        .catch(() => caches.match('/').then((r) => r || caches.match('/index.html'))),
    );
    return;
  }

  // Hashed immutable assets → cache-first (populate on first fetch).
  if (url.pathname.startsWith('/assets/') || SHELL.includes(url.pathname)) {
    event.respondWith(
      caches.match(req).then(
        (hit) =>
          hit ||
          fetch(req).then((res) => {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
            return res;
          }),
      ),
    );
  }
});
