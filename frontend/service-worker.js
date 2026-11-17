/* ==========================================================
   CYBERMIND — service worker
   Caches the app shell for offline viewing. Message analysis
   ALWAYS requires the backend; it is never faked offline.
   ========================================================== */

const CACHE_NAME = "cybermind-shell-v2";

const APP_SHELL = [
  "./",
  "./index.html",
  "./offline.html",
  "./css/style.css",
  "./css/responsive.css",
  "./css/gmail.css",
  "./js/api.js",
  "./js/history.js",
  "./js/app.js",
  "./js/gmail.js",
  "./assets/logo.svg",
  "./assets/icons/icon-192.png",
  "./assets/icons/icon-512.png",
  "./assets/icons/icon-maskable-512.png",
  "./assets/icons/apple-touch-icon-180.png",
  "./manifest.json"
];

function shellUrl(path) {
  return new URL(path, self.registration.scope).href;
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(APP_SHELL.map(shellUrl)))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key !== CACHE_NAME)
            .map((key) => caches.delete(key))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "SKIP_WAITING") {
    self.skipWaiting();
  }
});

self.addEventListener("fetch", (event) => {
  const request = event.request;

  // Only GET requests can be cached.
  if (request.method !== "GET") {
    return;
  }

  const url = new URL(request.url);

  // Never cache cross-origin requests.
  if (url.origin !== self.location.origin) {
    return;
  }

  // API, docs, and status endpoints must always hit the network.
  if (
    url.pathname === "/" ||
    url.pathname === "/health" ||
    url.pathname === "/analyze" ||
    url.pathname.startsWith("/gmail") ||
    url.pathname.startsWith("/docs") ||
    url.pathname.startsWith("/openapi") ||
    url.pathname.startsWith("/redoc")
  ) {
    return;
  }

  // Navigation: network first, then offline fallback.
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy = response.clone();

          caches
            .open(CACHE_NAME)
            .then((cache) => cache.put(request, copy))
            .catch(() => {});

          return response;
        })
        .catch(() =>
          caches
            .match(request)
            .then(
              (cached) =>
                cached || caches.match(shellUrl("./offline.html"))
            )
        )
    );

    return;
  }

  // Static assets: cache first, refresh in the background.
  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) {
        return cached;
      }

      return fetch(request)
        .then((response) => {
          if (response && response.ok && response.type === "basic") {
            const copy = response.clone();

            caches
              .open(CACHE_NAME)
              .then((cache) => cache.put(request, copy))
              .catch(() => {});
          }

          return response;
        })
        .catch(() => caches.match(shellUrl("./offline.html")));
    })
  );
});
