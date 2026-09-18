#!/usr/bin/env node
// NEXUS OSINT — Dark Web Tor Relay (local, sin dependencias)
// ------------------------------------------------------------------
// Busca en la dark web (.onion) enrutando TODO el tráfico a través del
// proxy SOCKS5 de Tor (Tor Browser 127.0.0.1:9150 o Tor daemon 127.0.0.1:9050).
//
// BLINDAJE DE LA MÁQUINA (por diseño):
//  * Solo escucha en 127.0.0.1 (nada sale de tu máquina).
//  * ÚNICAMENTE se permite conectar a destinos .onion — jamás a la internet clara.
//  * Ninguna petición sale por tu IP real: todo viaja dentro de circuitos Tor.
//  * No se siguen redirecciones, no se guardan cookies, no se escribe nada en disco.
//  * El HTML recibido se SANITIZA (se elimina script/style/iframe/object/embed,
//    atributos on* y URIs javascript:/data:) y se trunca a 2 MB.
//  * Timeouts estrictos por conexión y por petición.
//  * Resultados devueltos solo como JSON (texto plano) a la app local.
//
// USO:
//   1) Abre Tor Browser y déjalo corriendo (o instala Tor daemon).
//   2) node darkweb-relay/relay.mjs            (o ejecuta start-relay.ps1)
//   3) En la app usa "Search Dark Web": se detectará el relay automáticamente.
//
// ENDPOINTS:
//   GET /ping          -> estado del proxy Tor
//   GET /api/search?q= -> búsqueda multi-motor (.onion), JSON sanitizado

import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';

const PORT = 18909;
const HOST = '127.0.0.1';
const MAX_BODY = 2 * 1024 * 1024;      // 2 MB por respuesta
const CONNECT_TIMEOUT = 10000;          // 10 s handshake SOCKS
const REQUEST_TIMEOUT = 20000;          // 20 s por motor
const MAX_QUERY = 200;
const TOR_PROXIES = [
  { host: '127.0.0.1', port: 9150, label: 'Tor Browser' },
  { host: '127.0.0.1', port: 9050, label: 'Tor daemon' },
];

// Motores de búsqueda de la dark web (.onion). Direcciones best-effort;
// el relay reporta por motor si respondió o falló sin romper la búsqueda.
const ENGINES = [
  { name: 'ahmia', url: (q) => `http://juhanurmihxlp77nkq76byazcldy2hlcyfu6jd3sarnchcpopfblxehid.onion/search/?q=${q}` },
  { name: 'tor66', url: (q) => `http://tor66sezptuu2nta.onion/search?q=${q}` },
  { name: 'haystak', url: (q) => `http://haystak5njsmn2hqkekewbij4ezxcc3nb2s6hty6wkd7ujkuqof4zpeyd.onion/search?q=${q}` },
  { name: 'phobos', url: (q) => `http://phobosxiladw2jg2eld5tyhjojhzv67ex5mvps2sdu5vq2jccy7bg3ad.onion/search?query=${q}` },
  { name: 'duckduckgo-onion', url: (q) => `https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/?q=${q}&iax=web` },
];

// ------------------------------------------------------------------
// SOCKS5 (sin autenticación) sobre TCP plano + soporte TLS para https://
// ------------------------------------------------------------------
function socks5Connect(proxy, host, port, timeoutMs = CONNECT_TIMEOUT) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: proxy.host, port: proxy.port });
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('SOCKS timeout')); }, timeoutMs);
    socket.on('error', reject);
    let buf = Buffer.alloc(0);
    let stage = 0; // 0 = greeting, 1 = connect reply

    socket.on('connect', () => {
      socket.write(Buffer.from([0x05, 0x01, 0x00])); // SOCKS5, 1 método, no-auth
    });

    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      try {
        if (stage === 0) {
          if (buf.length < 2) return;
          if (buf[0] !== 0x05 || buf[1] !== 0x00) throw new Error('SOCKS auth method not accepted');
          const hostBuf = Buffer.from(host, 'utf8');
          if (hostBuf.length > 255) throw new Error('Host too long');
          const req = Buffer.concat([
            Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
            hostBuf,
            Buffer.from([(port >> 8) & 0xff, port & 0xff]),
          ]);
          socket.write(req);
          buf = Buffer.alloc(0);
          stage = 1;
        } else {
          if (buf.length < 4) return;
          if (buf[0] !== 0x05 || buf[1] !== 0x00) throw new Error(`SOCKS connect rejected (${buf[1]})`);
          const atyp = buf[3];
          let total = 4;
          if (atyp === 1) total += 4;
          else if (atyp === 4) total += 16;
          else if (atyp === 3) total += 1 + buf[4];
          total += 2;
          if (buf.length < total) return;
          socket.removeAllListeners('data');
          clearTimeout(timer);
          resolve(socket);
        }
      } catch (err) {
        clearTimeout(timer);
        socket.destroy();
        reject(err);
      }
    });
  });
}

async function httpRequestOverTor(rawUrl, { timeoutMs = REQUEST_TIMEOUT } = {}) {
  const u = new URL(rawUrl);
  if (!u.hostname.endsWith('.onion')) throw new Error('Solo se permiten destinos .onion');
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('Protocolo no soportado');

  const proxy = await findTorProxy();
  if (!proxy) throw new Error('Proxy Tor no disponible');

  const socket = await socks5Connect(proxy, u.hostname, u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80);
  const stream = u.protocol === 'https:'
    ? tls.connect({ socket, servername: u.hostname, rejectUnauthorized: false })
    : socket;

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { stream.destroy(); reject(new Error('Request timeout')); }, timeoutMs);
    let body = Buffer.alloc(0);
    let status = 0;
    let headers = '';
    let done = false;

    stream.on('error', (err) => { clearTimeout(timer); if (!done) { done = true; reject(err); } });
    stream.on('data', (chunk) => {
      try {
        if (status === 0) {
          const idx = chunk.indexOf(Buffer.from('\r\n\r\n'));
          if (idx === -1) { headers += chunk.toString('latin1').slice(0, 4096); return; }
          headers += chunk.toString('latin1').slice(0, idx);
          const statusMatch = headers.match(/^HTTP\/1\.[01]\s+(\d{3})/);
          status = statusMatch ? Number(statusMatch[1]) : 0;
          body = Buffer.concat([body, chunk.subarray(idx + 4)]);
        } else {
          body = Buffer.concat([body, chunk]);
        }
        if (body.length > MAX_BODY) { stream.destroy(); throw new Error('Respuesta demasiado grande'); }
      } catch (err) {
        clearTimeout(timer);
        if (!done) { done = true; reject(err); }
      }
    });
    stream.on('close', () => {
      clearTimeout(timer);
      if (!done) {
        done = true;
        if (status >= 300 && status < 400) resolve({ status, headers, body, redirected: true });
        else resolve({ status, headers, body });
      }
    });

    const reqPath = u.pathname + u.search;
    const req = [
      `GET ${reqPath} HTTP/1.1`,
      `Host: ${u.hostname}`,
      'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0 (NEXUS-OSINT-Tor)',
      'Accept: text/html,application/xhtml+xml,*/*;q=0.8',
      'Accept-Language: en-US,en;q=0.5',
      'Connection: close',
      '\r\n',
    ].join('\r\n');
    stream.write(req);
  });
}

// ------------------------------------------------------------------
// Detección del proxy Tor activo (cache 10 s)
// ------------------------------------------------------------------
let proxyCache = { at: 0, proxy: null };
async function findTorProxy(force = false) {
  if (!force && proxyCache.proxy && Date.now() - proxyCache.at < 10000) return proxyCache.proxy;
  for (const p of TOR_PROXIES) {
    try {
      const s = await socks5Connect(p, 'cthulhu.onion', 80, 2500); // handshake de prueba
      s.destroy();
      proxyCache = { at: Date.now(), proxy: p };
      return p;
    } catch { /* siguiente proxy */ }
  }
  proxyCache = { at: Date.now(), proxy: null };
  return null;
}

// ------------------------------------------------------------------
// Sanitización estricta del HTML recibido
// ------------------------------------------------------------------
function sanitizeHtml(html) {
  let s = String(html || '');
  s = s.replace(/<script[\s\S]*?<\/script>/gi, ' ');
  s = s.replace(/<style[\s\S]*?<\/style>/gi, ' ');
  s = s.replace(/<iframe[\s\S]*?<\/iframe>/gi, ' ');
  s = s.replace(/<object[\s\S]*?<\/object>/gi, ' ');
  s = s.replace(/<embed[\s\S]*?\/?>/gi, ' ');
  s = s.replace(/<link[\s\S]*?\/?>/gi, ' ');
  s = s.replace(/\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, ' ');
  s = s.replace(/\s(href|src|action)\s*=\s*("|')(javascript|data)\s*:/gi, ' ');
  return s;
}

const ONION_RE = /(?:https?:\/\/)?([a-z0-9]{8,56}\.onion)(?:\/[^\s"'<>]*)?/gi;
const ANCHOR_RE = /<a[^>]*href\s*=\s*("([^"]*)"|'([^']*)')[^>]*>([\s\S]*?)<\/a>/gi;
const BLOCK_RE = /<(?:li|div|tr|section|article)[^>]*>([\s\S]*?)<\/(?:li|div|tr|section|article)>/gi;

function stripTags(t) {
  return String(t || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
}

function extractResults(html, engineName) {
  const sanitized = sanitizeHtml(html);
  const anchors = [];
  let m;
  ANCHOR_RE.lastIndex = 0;
  while ((m = ANCHOR_RE.exec(sanitized)) !== null) {
    const href = (m[2] || m[3] || '').trim();
    const text = stripTags(m[4]);
    if (href && text.length >= 2) anchors.push({ href, text });
  }

  const onionHosts = new Set();
  ONION_RE.lastIndex = 0;
  while ((m = ONION_RE.exec(sanitized)) !== null) onionHosts.add(m[1].toLowerCase());

  const results = new Map(); // key: url
  const addResult = (title, url, snippet) => {
    const host = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
    if (!host.endsWith('.onion')) return;
    const clean = url.startsWith('http') ? url : `http://${url}`;
    const key = clean.replace(/\/+$/, '');
    const existing = results.get(key);
    if (existing) {
      if (!existing.engines.includes(engineName)) existing.engines.push(engineName);
      if (!existing.snippet && snippet) existing.snippet = snippet;
      return;
    }
    results.set(key, { title: title || host, url: clean, host, snippet: snippet || '', engines: [engineName] });
  };

  // 1) Anclajes con href .onion
  for (const a of anchors) {
    let url = a.href;
    if (!url.startsWith('http') && !url.startsWith('/')) continue;
    if (url.startsWith('http')) {
      if (!url.toLowerCase().includes('.onion')) continue;
    } else {
      // rutas relativas de motores tipo ahmia: /address/<host>
      const rel = url.replace(/^\/address\//i, '');
      if (!rel.toLowerCase().endsWith('.onion')) continue; // filtrar rutas internas
      url = `http://${rel}`;
    }
    addResult(a.text, url, '');
  }

  // 2) Hosts .onion desnudos -> título desde texto cercano
  for (const host of onionHosts) {
    if (results.has(`http://${host}/`)) continue;
    let snippet = '';
    const idx = sanitized.toLowerCase().indexOf(host);
    if (idx !== -1) {
      const near = sanitized.slice(idx, idx + 600);
      const p = near.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
      if (p) snippet = stripTags(p[1]).slice(0, 320);
      const h = near.match(/<(?:h[2-4]|b|strong|em)[^>]*>([^<]{3,160})<\//i);
      if (h && !h[1].startsWith('http')) {
        const title = stripTags(h[1]);
        addResult(title.slice(0, 160), `http://${host}`, snippet);
        continue;
      }
    }
    addResult(host, `http://${host}`, snippet);
  }

  // 3) Bloque genérico: hosts dentro de <li>/<div> con párrafo cercano
  BLOCK_RE.lastIndex = 0;
  while ((m = BLOCK_RE.exec(sanitized)) !== null) {
    const block = m[1];
    const innerHost = block.match(/([a-z0-9]{8,56}\.onion)/i);
    if (!innerHost) continue;
    const url = `http://${innerHost[1].toLowerCase()}`;
    if (results.has(url)) continue;
    const h = block.match(/<(?:h[2-4]|b|strong)[^>]*>([^<]{3,160})<\//i);
    const p = block.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
    addResult(h ? stripTags(h[1]).slice(0, 160) : innerHost[1], url, p ? stripTags(p[1]).slice(0, 320) : '');
  }

  return [...results.values()].slice(0, 40);
}

// ------------------------------------------------------------------
// Búsqueda multi-motor (paralelo, tolerante a fallos)
// ------------------------------------------------------------------
async function searchAllEngines(query, signal) {
  const q = encodeURIComponent(query);
  const engineResults = await Promise.all(
    ENGINES.map(async (engine) => {
      const started = Date.now();
      try {
        const { status, body, redirected } = await httpRequestOverTor(engine.url(q));
        const text = body.toString('utf8');
        if (status < 200 || status >= 400) {
          return { engine: engine.name, ok: false, error: `HTTP ${status}`, count: 0, results: [] };
        }
        if (redirected) {
          return { engine: engine.name, ok: false, error: 'Redirección (no seguida por seguridad)', count: 0, results: [] };
        }
        const results = extractResults(text, engine.name);
        return { engine: engine.name, ok: true, error: '', count: results.length, results, ms: Date.now() - started };
      } catch (err) {
        return { engine: engine.name, ok: false, error: String(err.message || err).slice(0, 120), count: 0, results: [], ms: Date.now() - started };
      }
    })
  );

  // Merge + dedupe entre motores
  const merged = new Map();
  engineResults.forEach((er) => {
    er.results.forEach((r) => {
      const existing = merged.get(r.url.replace(/\/+$/, ''));
      if (existing) {
        r.engines.forEach((e) => { if (!existing.engines.includes(e)) existing.engines.push(e); });
        if (!existing.snippet && r.snippet) existing.snippet = r.snippet;
      } else {
        merged.set(r.url.replace(/\/+$/, ''), { ...r });
      }
    });
  });

  return {
    engines: engineResults.map(({ engine, ok, error, count, ms }) => ({ engine, ok, error, count, ms })),
    results: [...merged.values()].slice(0, 60),
    totalRaw: [...merged.values()].length,
  };
}

// ------------------------------------------------------------------
// Servidor HTTP local (127.0.0.1 únicamente)
// ------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Nexus-Origin');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  const u = new URL(req.url, `http://${HOST}:${PORT}`);
  const json = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(obj));
  };

  try {
    if (u.pathname === '/ping') {
      const proxy = await findTorProxy(true);
      return json(200, {
        ok: true,
        torConnected: !!proxy,
        proxy: proxy ? `${proxy.host}:${proxy.port} (${proxy.label})` : null,
        engines: ENGINES.map((e) => e.name),
      });
    }

    if (u.pathname === '/api/search') {
      const rawQuery = u.searchParams.get('q') || '';
      const query = rawQuery.trim().slice(0, MAX_QUERY);
      if (!query) return json(400, { ok: false, error: 'Parámetro q requerido' });
      if (/[\x00-\x1f\x7f]/.test(query)) return json(400, { ok: false, error: 'Query inválida' });

      const proxy = await findTorProxy(true);
      if (!proxy) {
        return json(503, {
          ok: false,
          error: 'Proxy Tor no disponible. Abre Tor Browser (o inicia el daemon Tor) y reintenta.',
          action: 'abrir-tor-browser',
        });
      }

      const out = await searchAllEngines(query);
      const serviceable = out.engines.filter((e) => e.ok).length;
      return json(200, {
        ok: true,
        mode: 'tor-relay',
        torConnected: true,
        proxy: `${proxy.host}:${proxy.port} (${proxy.label})`,
        query,
        engines: out.engines,
        results: out.results,
        serviceable,
        warnings: [
          'Tráfico 100% a través de circuitos Tor (tu IP nunca contacta los .onion)',
          'Contenido sanitizado: se eliminó todo código activo (scripts, iframes, objetos) de las respuestas',
          'No se siguieron redirecciones ni se almacenaron cookies',
          'Abre los .onion únicamente dentro de Tor Browser; la red clara no puede resolverlos',
        ],
        safety: {
          destinationFilter: 'solo .onion',
          redirects: 0,
          cookies: 0,
          diskWrites: 0,
          activeContent: 'eliminado',
          maxBodyBytes: MAX_BODY,
        },
        ts: new Date().toISOString(),
      });
    }

    return json(404, { ok: false, error: 'Ruta no encontrada. Usa /ping o /api/search?q=...' });
  } catch (err) {
    return json(500, { ok: false, error: String(err.message || err).slice(0, 200) });
  }
});

server.listen(PORT, HOST, async () => {
  const proxy = await findTorProxy(true);
  console.log('');
  console.log('============================================================');
  console.log(' NEXUS OSINT — Dark Web Tor Relay');
  console.log(' Escuchando en  http://127.0.0.1:' + PORT + '  (solo localhost)');
  console.log(' Proxy Tor:   ' + (proxy ? `${proxy.host}:${proxy.port} (${proxy.label})` : 'NO DETECTADO — abre Tor Browser'));
  console.log(' Motores:     ' + ENGINES.map((e) => e.name).join(', '));
  console.log(' Seguridad:   solo .onion · sin redirects · sin cookies ·');
  console.log('              HTML sanitizado · sin escritura en disco ·');
  console.log('              tráfico 100% por circuitos Tor');
  console.log('============================================================');
  console.log('');
});