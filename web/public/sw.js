// WardenBroker service worker: push notifications + an offline app shell.
const SHELL = 'wardenbroker-shell-v1'

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(SHELL).then((c) => c.addAll(['/', '/manifest.webmanifest', '/icon.svg'])).then(() => self.skipWaiting()))
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== SHELL).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  )
})

self.addEventListener('fetch', (event) => {
  const req = event.request
  const url = new URL(req.url)
  if (req.method !== 'GET' || url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return
  // Network first so a deploy is picked up immediately; cache as a fallback.
  event.respondWith(
    fetch(req)
      .then((res) => {
        if (res.ok && (req.mode === 'navigate' || url.pathname.startsWith('/assets/'))) {
          const copy = res.clone()
          caches.open(SHELL).then((c) => c.put(req.mode === 'navigate' ? '/' : req, copy))
        }
        return res
      })
      .catch(() => caches.match(req.mode === 'navigate' ? '/' : req).then((r) => r || Response.error())),
  )
})

self.addEventListener('push', (event) => {
  let msg = { title: 'WardenBroker', body: 'Something needs your approval', tag: 'wardenbroker', url: '/' }
  try {
    msg = { ...msg, ...event.data.json() }
  } catch {}
  event.waitUntil(
    (async () => {
      await self.registration.showNotification(msg.title, {
        body: msg.body,
        tag: msg.tag,
        icon: '/icon-192.png',
        badge: '/icon-192.png',
        data: { url: msg.url },
        requireInteraction: msg.tag !== 'test',
      })
      const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
      for (const client of clients) client.postMessage({ type: 'wardenbroker:refresh' })
    })(),
  )
})

self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  const target = new URL(event.notification.data?.url || '/', self.location.origin).href
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
      const existing = windows.find((c) => new URL(c.url).origin === self.location.origin)
      if (existing) {
        await existing.focus()
        existing.postMessage({ type: 'wardenbroker:refresh' })
        return
      }
      await self.clients.openWindow(target)
    })(),
  )
})
