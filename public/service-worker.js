const CACHE_NAME = 'sdi-accounting-v1';

const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/admin.html',
  '/login.html',
  '/manifest.json',
  '/pwa-192x192.png',
  '/pwa-512x512.png',
  'https://cdn.tailwindcss.com'
];

// Install Event - Pre-cache static UI shell
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('[ServiceWorker] Pre-caching offline UI shell...');
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn('[ServiceWorker] Some static assets failed to pre-cache:', err);
      });
    }).then(() => self.skipWaiting())
  );
});

// Activate Event - Clean up old cache versions
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cache) => {
          if (cache !== CACHE_NAME) {
            console.log('[ServiceWorker] Deleting legacy cache:', cache);
            return caches.delete(cache);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch Event - Network first with fallback to cache, bypassing API calls
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // CRITICAL: Bypass cache for API endpoints, Supabase backend calls, or non-GET requests
  if (
    req.method !== 'GET' ||
    url.pathname.startsWith('/api/') ||
    url.hostname.includes('supabase.co') ||
    url.hostname.includes('onrender.com') ||
    url.hostname.includes('railway.app')
  ) {
    return; // Direct network fetch for live data
  }

  // Network-First strategy with Cache Fallback for static assets
  event.respondWith(
    fetch(req)
      .then((networkResponse) => {
        if (networkResponse && networkResponse.status === 200 && networkResponse.type === 'basic') {
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(req, responseToCache);
          });
        }
        return networkResponse;
      })
      .catch(async () => {
        const cachedResponse = await caches.match(req);
        if (cachedResponse) {
          return cachedResponse;
        }
        if (req.mode === 'navigate') {
          return caches.match('/index.html') || caches.match('/login.html');
        }
      })
  );
});
