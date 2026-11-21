// Offline shell only: static files under /app/. Never /api, never non-GET, never any user data or tokens.
const CACHE = 'ayuza-shell-v1';
const SHELL = ['./', 'index.html', 'styles.css', 'app.js', 'logic.js', 'manifest.webmanifest', 'icon.svg'];

function cacheable(request, origin) {
  const url = new URL(request.url);
  return request.method === 'GET' && url.origin === origin && url.pathname.startsWith('/app/') && !url.pathname.startsWith('/api/');
}

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener('fetch', (event) => {
  if (!cacheable(event.request, self.location.origin)) return;            // the browser handles everything else as usual
  event.respondWith(fetch(event.request).then((response) => {
    if (response.ok) { const copy = response.clone(); caches.open(CACHE).then((cache) => cache.put(event.request, copy)); }
    return response;
  }).catch(() => caches.match(event.request).then((hit) => hit || caches.match('index.html'))));
});
