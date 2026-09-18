// URL Sandbox engine — real, keyless dynamic capture.
// Runs on the Vercel Node runtime: performs a real HTTP fetch with manual
// redirect following, captures TLS certificate metadata, parses the rendered
// HTML for behavioral signals, and probes a sample of referenced resources.
//
// This is NOT a simulated detonation: the requests genuinely hit the target.

import * as tls from 'tls';
import type {
  ContentAnalysis, ContentForm, ContentIndicator, HttpFingerprint,
  RedirectHop, ResourceProbe, TlsInfo,
} from './types';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 NEXUS-INTEL/1.0';
const MAX_REDIRECTS = 8;
const MAX_HTML_BYTES = 2_000_000;
const RESOURCE_SAMPLE = 14;
const RESOURCE_CONCURRENCY = 5;

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

function normalizeUrl(base: string, location: string): string {
  try {
    return new URL(location, base).href;
  } catch {
    return location;
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

async function fetchOnce(url: string, headers: Record<string, string>): Promise<{
  response: Response;
  ttfbMs: number;
}> {
  const started = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(url, {
      redirect: 'manual',
      headers,
      signal: controller.signal,
    });
    return { response, ttfbMs: Date.now() - started };
  } finally {
    clearTimeout(timeout);
  }
}

export async function captureHttp(url: string): Promise<{
  http: HttpFingerprint | null;
  redirects: RedirectHop[];
}> {
  const redirects: RedirectHop[] = [];
  let current = url;
  const headers: Record<string, string> = {
    'User-Agent': UA,
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Upgrade-Insecure-Requests': '1',
  };
  const started = Date.now();

  try {
    for (let i = 0; i <= MAX_REDIRECTS; i++) {
      const { response, ttfbMs } = await fetchOnce(current, headers);
      const status = response.status;
      const location = response.headers.get('location');

      if (REDIRECT_CODES.has(status) && location) {
        redirects.push({ index: i, url: current, status });
        current = normalizeUrl(current, location);
        continue;
      }

      redirects.push({ index: i, url: current, status });
      const isHtml = (response.headers.get('content-type') || '').includes('text/html');
      let html: string | null = null;
      if (isHtml) {
        const buf = await response.arrayBuffer();
        html = new TextDecoder('utf-8')
          .decode(buf.slice(0, MAX_HTML_BYTES))
          .replace(/^\uFEFF/, '');
      }

      const http: HttpFingerprint = {
        finalUrl: response.url || current,
        status,
        statusText: response.statusText || '',
        ok: response.ok,
        protocol: response.url?.startsWith('https') ? 'HTTPS' : 'HTTP',
        server: response.headers.get('server'),
        contentType: response.headers.get('content-type'),
        contentLength: Number(response.headers.get('content-length')) || null,
        contentEncoding: response.headers.get('content-encoding'),
        headers: Object.fromEntries(response.headers.entries()),
        timings: { ttfbMs, totalMs: Date.now() - started },
        html,
      };
      return { http, redirects };
    }
  } catch {
    /* target unreachable / timeout */
  }

  return { http: null, redirects };
}

export async function captureTls(url: string): Promise<TlsInfo | null> {
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    return null;
  }

  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: TlsInfo | null) => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve(value);
      }
    };
    const timer = setTimeout(() => finish(null), 6000);

    const socket = tls.connect({
      host,
      port: 443,
      servername: host,
      rejectUnauthorized: false,
    });

    socket.on('secureConnect', () => {
      clearTimeout(timer);
      try {
        const cert = socket.getPeerCertificate(true);
        const sanRaw: string[] = [];
        const san = cert.subjectaltname;
        if (san) {
          san.split('\n').forEach((entry) => {
            const m = entry.match(/^(DNS|IP Address):(.+)$/i);
            if (m) sanRaw.push(m[2].trim());
          });
        }
        const cn = cert.subject?.CN ? String(cert.subject.CN) : null;
        const subjectOrg = cert.subject?.O ? String(cert.subject.O) : null;
        const issuerCn = cert.issuer?.CN ? String(cert.issuer.CN) : null;
        const issuerOrg = cert.issuer?.O ? String(cert.issuer.O) : null;
        const hostnameMismatch = !!cn && host !== cn && !sanRaw.some((d) => d === host || (d.startsWith('*.') && host.endsWith(d.slice(1))));
        const now = new Date();
        const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
        finish({
          protocol: socket.getProtocol() || '',
          cipher: (socket.getCipher()?.name as string) || '',
          subjectCn: cn,
          subjectOrg,
          issuerCn,
          issuerOrg,
          san: sanRaw,
          validFrom: cert.valid_from ? String(cert.valid_from) : null,
          validTo: cert.valid_to ? String(cert.valid_to) : null,
          expired: !validTo || validTo < now,
          selfSigned: (issuerCn || '').toLowerCase().includes((cn || '__none__').toLowerCase()),
          hostnameMismatch,
        });
      } catch {
        finish(null);
      }
    });

    socket.on('error', () => finish(null));
    socket.on('timeout', () => finish(null));
    socket.setTimeout(6000);
  });
}

// ---------------- content analysis ----------------

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const TELEGRAM_BOT_RE = /\b(\d{8,10}):[A-Za-z0-9_-]{35}\b/g;
const TELEGRAM_CHAT_RE = /(?:chat_id|chatId)["']?\s*[:=]\s*["']?(-?\d{6,15})["']?/gi;

function isExternal(action: string | null, finalHost: string): boolean {
  if (!action) return false;
  try {
    return new URL(action, `http://${finalHost}/`).hostname !== finalHost;
  } catch {
    return true;
  }
}

export function analyzeContent(html: string, finalHost: string): ContentAnalysis {
  const indicators: ContentIndicator[] = [];
  const title = html.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1]?.trim() || null;
  const description = html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i)?.[1] || null;
  const lang = html.match(/<html[^>]+lang=["']([^"']+)["']/i)?.[1] || null;
  const favicon = html.match(/<link[^>]+rel=["'](?:shortcut )?icon["'][^>]+href=["']([^"']+)["']/i)?.[1] || null;

  const forms: ContentForm[] = [];
  const formRe = /<form[^>]*>/gi;
  let fm: RegExpExecArray | null;
  while ((fm = formRe.exec(html)) !== null && forms.length < 20) {
    const tag = fm[0];
    const action = tag.match(/action=["']([^"']*)["']/i)?.[1] ?? null;
    const method = (tag.match(/method=["']([^"']*)["']/i)?.[1] || 'GET').toUpperCase();
    const external = isExternal(action, finalHost);
    forms.push({ action, method, external });
    if (external) {
      indicators.push({
        label: 'Form posts off-domain',
        category: 'exfiltration',
        severity: 'HIGH',
        detail: `Form action "${action}" targets a different host than ${finalHost}`,
      });
    }
  }

  const iframes: { src: string | null }[] = [];
  const iframeRe = /<iframe[^>]*>/gi;
  let im: RegExpExecArray | null;
  while ((im = iframeRe.exec(html)) !== null && iframes.length < 20) {
    iframes.push({ src: im[0].match(/src=["']([^"']*)["']/i)?.[1] ?? null });
  }
  if (iframes.length > 0) {
    indicators.push({ label: 'Embedded iframes', category: 'cloaking', severity: 'MEDIUM', detail: `${iframes.length} iframe(s) — often used to hide phishing content or ads` });
  }

  const metaRefresh = /<meta[^>]+http-equiv=["']refresh["']/i.test(html);
  if (metaRefresh) {
    indicators.push({ label: 'Meta refresh redirect', category: 'cloaking', severity: 'MEDIUM', detail: 'Meta refresh tag detected — can silently redirect the victim' });
  }

  const scripts: string[] = [];
  const scriptSrcRe = /<script[^>]+src=["']([^"']+)["']/gi;
  let sm: RegExpExecArray | null;
  while ((sm = scriptSrcRe.exec(html)) !== null && scripts.length < 30) {
    scripts.push(sm[1]);
  }

  // Inline script obfuscation detection
  const inlineBlocks = html.match(/<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/gi) || [];
  let inlineJsBytes = 0;
  let obfuscatedJs = false;
  for (const block of inlineBlocks) {
    const body = block.replace(/<script[^>]*>/i, '').replace(/<\/script>/i, '').trim();
    inlineJsBytes += body.length;
    if (
      !obfuscatedJs &&
      (/(?:eval\s*\(|atob\s*\(|fromCharCode|unescape\s*\(|\\x[0-9a-f]{2}|document\.write\s*\()/i.test(body) ||
        /(?:base64|btoa\s*\()/i.test(body))
    ) {
      obfuscatedJs = true;
    }
  }
  if (obfuscatedJs) {
    indicators.push({ label: 'Obfuscated JavaScript', category: 'evasion', severity: 'HIGH', detail: 'Inline script uses eval/atob/fromCharCode — classic anti-analysis technique' });
  }

  const emails = Array.from(new Set(html.match(EMAIL_RE) || [])).filter((e) => !e.toLowerCase().includes('example.')).slice(0, 30);
  const telegramTokens = Array.from(new Set(html.match(TELEGRAM_BOT_RE) || [])).slice(0, 10);
  const telegramChatIds = Array.from(new Set((html.match(TELEGRAM_CHAT_RE) || []).map((m) => m.match(/(-?\d{6,15})/)?.[1] || m))).slice(0, 10);

  const openDirListing = /<title[^>]*>\s*Index of [^<]*<\/title>/i.test(html) && /<h1>\s*Index of \//i.test(html);
  if (openDirListing) {
    indicators.push({ label: 'Open directory listing', category: 'exposure', severity: 'HIGH', detail: 'Server exposes an "Index of /" listing — often hosts leaked files or phishing kits' });
  }

  if (telegramTokens.length > 0) {
    indicators.push({ label: 'Telegram bot token', category: 'attribution', severity: 'CRITICAL', detail: `${telegramTokens.length} Telegram bot token(s) found — C2/exfil channel` });
  }
  if (telegramChatIds.length > 0) {
    indicators.push({ label: 'Telegram chat ID', category: 'attribution', severity: 'HIGH', detail: `${telegramChatIds.length} Telegram chat ID(s) found` });
  }
  if (emails.length > 0) {
    indicators.push({ label: 'Embedded emails', category: 'attribution', severity: 'LOW', detail: `${emails.length} email address(es) in page` });
  }

  return {
    title,
    description,
    lang,
    favicon,
    forms,
    iframes,
    metaRefresh,
    obfuscatedJs,
    inlineJsBytes,
    scripts,
    emails,
    telegramTokens,
    telegramChatIds,
    indicators,
    finalHost,
  };
}

// ---------------- resource probing ----------------

function resourceType(href: string): ResourceProbe['type'] {
  const lower = href.toLowerCase();
  if (/\.js(\?|$)/.test(lower)) return 'script';
  if (/\.css(\?|$)/.test(lower)) return 'stylesheet';
  if (/\.(png|jpe?g|gif|svg|webp|ico)(\?|$)/.test(lower)) return 'image';
  if (/\.(woff2?|ttf|otf|eot)(\?|$)/.test(lower)) return 'font';
  return 'other';
}

function extractResourceUrls(html: string, pageUrl: string): { url: string; type: ResourceProbe['type'] }[] {
  const found: { url: string; type: ResourceProbe['type'] }[] = [];
  const patterns: [RegExp, ResourceProbe['type']][] = [
    [/<script[^>]+src=["']([^"']+)["']/gi, 'script'],
    [/<link[^>]+rel=["']stylesheet["'][^>]+href=["']([^"']+)["']/gi, 'stylesheet'],
    [/<link[^>]+href=["']([^"']+)["'][^>]+rel=["']stylesheet["']/gi, 'stylesheet'],
    [/<img[^>]+src=["']([^"']+)["']/gi, 'image'],
    [/<iframe[^>]+src=["']([^"']+)["']/gi, 'iframe'],
    [/url\(["']?([^"')]+)["']?\)/gi, 'font'],
  ];
  for (const [re, type] of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) !== null) {
      const href = m[1];
      if (href.startsWith('data:') || href.startsWith('#')) continue;
      try {
        const abs = new URL(href, pageUrl).href;
        if (abs.startsWith('http')) found.push({ url: abs, type });
      } catch {
        /* skip malformed */
      }
    }
  }
  return found;
}

async function probeResource(item: { url: string; type: ResourceProbe['type'] }, pageHost: string): Promise<ResourceProbe | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 6000);
  try {
    const res = await fetch(item.url, {
      redirect: 'follow',
      headers: { 'User-Agent': UA },
      signal: controller.signal,
    });
    return {
      url: item.url,
      host: hostOf(item.url),
      type: item.type,
      status: res.status,
      finalHost: pageHost,
    };
  } catch {
    return { url: item.url, host: hostOf(item.url), type: item.type, status: null, finalHost: pageHost };
  } finally {
    clearTimeout(timeout);
  }
}

export async function probeResources(html: string, pageUrl: string): Promise<ResourceProbe[]> {
  const pageHost = hostOf(pageUrl);
  const urls = extractResourceUrls(html, pageUrl).slice(0, RESOURCE_SAMPLE);
  const results: ResourceProbe[] = [];
  for (let i = 0; i < urls.length; i += RESOURCE_CONCURRENCY) {
    const chunk = urls.slice(i, i + RESOURCE_CONCURRENCY);
    const settled = await Promise.allSettled(chunk.map((u) => probeResource(u, pageHost)));
    settled.forEach((s) => {
      if (s.status === 'fulfilled' && s.value) results.push(s.value);
    });
  }
  return results;
}
