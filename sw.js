// Service worker : l'application fonctionne entièrement hors ligne (avion, escale sans réseau).
// Chaque génération change VERSION ; la nouvelle version s'installe en arrière-plan et l'appli propose de recharger.
const VERSION = "72899fadda";
const PREFIX = "bats-"; // « missions- » (David, version publique) ou « bats- » (édition BATS)
const CACHE = `${PREFIX}${VERSION}`;
const FILES = ["./", "index.html", "manifest.webmanifest", "icon.svg", "icon-192.png", "icon-512.png", "apple-touch-icon.png", "wordmark.png", "cargo-hcu6e-loaded.png", "pdf.min.js", "pdf.worker.min.js", "qrcode.js", "jsqr.js", "relais-client.js"];

self.addEventListener("install", (e) => {
  // cache: "reload" : on télécharge toujours la version du serveur, jamais une copie du cache HTTP du navigateur
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES.map((u) => new Request(u, { cache: "reload" })))));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith(PREFIX) && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("message", (e) => { if (e.data === "skip") self.skipWaiting(); });

// Cache d'abord (hors ligne garanti) ; la mise à jour passe par une nouvelle version du service worker.
self.addEventListener("fetch", (e) => {
  if (e.request.method !== "GET") return;
  const url = new URL(e.request.url);
  if (url.origin !== location.origin) return;
  e.respondWith(
    caches.match(e.request, { ignoreSearch: true }).then((hit) =>
      hit || (e.request.mode === "navigate" ? caches.match("index.html") : null) || fetch(e.request)
    )
  );
});
