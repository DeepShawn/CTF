// 离线缓存：页面与 ctfkit 先用缓存、后台更新；Pyodide（CDN 上带版本号的文件）缓存后不再下载。
const VERSION = 'ctfkit-0.1.0-bce1b24';
const PYODIDE = 'https://cdn.jsdelivr.net/pyodide/';

self.addEventListener('install', (e) => { self.skipWaiting(); });
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k.startsWith('ctfkit-') && k !== VERSION).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener('fetch', (e) => {
  const url = e.request.url;
  if (e.request.method !== 'GET') return;
  if (url.startsWith(PYODIDE)) {
    e.respondWith(caches.open('ctfkit-pyodide').then(async (c) => {
      const hit = await c.match(e.request);
      if (hit) return hit;
      const res = await fetch(e.request);
      if (res.ok) c.put(e.request, res.clone());
      return res;
    }));
    return;
  }
  if (new URL(url).origin !== self.location.origin) return;
  e.respondWith(caches.open(VERSION).then(async (c) => {
    const hit = await c.match(e.request);
    const net = fetch(e.request).then((res) => { if (res.ok) c.put(e.request, res.clone()); return res; }).catch(() => hit);
    return hit || net;
  }));
});
