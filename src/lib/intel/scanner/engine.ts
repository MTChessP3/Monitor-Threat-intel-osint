// URL Scanner engine — attack-surface analysis, keyless.
// 1) Fuzzes a curated list of sensitive paths on the target host to surface
//    exposed config/backup/panel files.
// 2) Downloads a bounded sample of referenced scripts + discovered interesting
//    files, computes their SHA-256 and fingerprints known phishing-kit families.
// 3) Attribution: extracts exfiltration endpoints (Telegram / email / remote
//    form posts) and gathers artifacts (IoC) from captured content.

import { createHash } from 'crypto';
import type {
  ContentAnalysis,
  ExfilEndpoint,
  FuzzPathResult,
  KitArtifact,
  KitMatch,
  ResourceProbe,
  ScannerArtifact,
} from './types';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 NEXUS-INTEL/1.0';

const FUZZ_CONCURRENCY = 6;
const FUZZ_TIMEOUT_MS = 6000;
const KIT_DOWNLOAD_LIMIT = 8;
const MAX_KIT_FILE_BYTES = 2_000_000;
const MAX_KIT_HASH_BYTES = 500_000;

// Paths commonly abused by phishing kits / exposed on compromised hosts.
// `sensitive: true` marks entries that should never be public (config, backups,
// shell/panel endpoints, source-control metadata).
const FUZZ_PATHS: { path: string; sensitive: boolean; note: string }[] = [
  { path: '/.env', sensitive: true, note: 'Environment config (secrets)' },
  { path: '/.git/config', sensitive: true, note: 'Git metadata (source leak)' },
  { path: '/.git/HEAD', sensitive: true, note: 'Git metadata (source leak)' },
  { path: '/config.php', sensitive: true, note: 'PHP config' },
  { path: '/config.inc.php', sensitive: true, note: 'PHP config (include)' },
  { path: '/configuration.php', sensitive: true, note: 'Config (Joomla-style)' },
  { path: '/wp-config.php.bak', sensitive: true, note: 'Backup of WP config' },
  { path: '/backup.zip', sensitive: true, note: 'Site backup archive' },
  { path: '/backup.tar.gz', sensitive: true, note: 'Site backup archive' },
  { path: '/db.sql', sensitive: true, note: 'SQL dump' },
  { path: '/dump.sql', sensitive: true, note: 'SQL dump' },
  { path: '/database.sql', sensitive: true, note: 'SQL dump' },
  { path: '/admin', sensitive: true, note: 'Admin panel' },
  { path: '/admin/', sensitive: true, note: 'Admin panel' },
  { path: '/admin/login.php', sensitive: true, note: 'Admin login' },
  { path: '/panel', sensitive: true, note: 'Control panel' },
  { path: '/panel/', sensitive: true, note: 'Control panel' },
  { path: '/login.php', sensitive: true, note: 'Login endpoint' },
  { path: '/phpinfo.php', sensitive: true, note: 'PHP info (info disclosure)' },
  { path: '/info.php', sensitive: true, note: 'PHP info (info disclosure)' },
  { path: '/shell.php', sensitive: true, note: 'Web shell (RCE)' },
  { path: '/c99.php', sensitive: true, note: 'Web shell family (RCE)' },
  { path: '/r57.php', sensitive: true, note: 'Web shell family (RCE)' },
  { path: '/b374k.php', sensitive: true, note: 'Web shell family (RCE)' },
  { path: '/wso.php', sensitive: true, note: 'Web shell family (RCE)' },
  { path: '/cmd.php', sensitive: true, note: 'Command endpoint' },
  { path: '/upload.php', sensitive: true, note: 'File upload endpoint' },
  { path: '/uploads/', sensitive: true, note: 'Uploaded payloads' },
  { path: '/logs/', sensitive: true, note: 'Access/error logs' },
  { path: '/error_log', sensitive: true, note: 'Error log (info leak)' },
  { path: '/access.log', sensitive: true, note: 'Access log (info leak)' },
  { path: '/bot.php', sensitive: true, note: 'Bot / C2 endpoint' },
  { path: '/result.php', sensitive: true, note: 'Phishing kit result page' },
  { path: '/save.php', sensitive: true, note: 'Credential stealer receiver' },
  { path: '/send.php', sensitive: true, note: 'Credential stealer receiver' },
  { path: '/robots.txt', sensitive: false, note: 'Crawl policy (may expose paths)' },
  { path: '/sitemap.xml', sensitive: false, note: 'Sitemap (may expose paths)' },
  { path: '/phpmyadmin/', sensitive: true, note: 'DB admin panel' },
  { path: '/web.config', sensitive: true, note: 'IIS config' },
  { path: '/composer.json', sensitive: true, note: 'Dependency manifest' },
];

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function normalizeUrl(base: string, href: string): string | null {
  try {
    const abs = new URL(href, base);
    if (abs.protocol === 'http:' || abs.protocol === 'https:') return abs.href;
  } catch {
    /* ignore */
  }
  return null;
}

// ---------------- path fuzzing ----------------

async function probePath(baseUrl: string, entry: { path: string; sensitive: boolean; note: string }): Promise<FuzzPathResult> {
  const url = baseUrl + entry.path.replace(/^\//, '');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FUZZ_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      redirect: 'follow',
      headers: { 'User-Agent': UA },
      signal: controller.signal,
    });
    const size = Number(response.headers.get('content-length')) || null;
    const contentType = response.headers.get('content-type');
    let note = entry.note;
    const status = response.status;
    if (status >= 200 && status < 300) note += ` — EXPOSED (${status})`;
    else if (status === 301 || status === 302 || status === 303 || status === 307 || status === 308) note += ` — redirect (${status})`;
    else note += ` — ${status}`;
    return { path: entry.path, url, status, contentType, size, sensitive: entry.sensitive, note };
  } catch {
    return { path: entry.path, url, status: null, contentType: null, size: null, sensitive: entry.sensitive, note: `${entry.note} — timeout/unreachable` };
  } finally {
    clearTimeout(timer);
  }
}

export async function fuzzPaths(baseUrl: string): Promise<FuzzPathResult[]> {
  const results: FuzzPathResult[] = [];
  for (let i = 0; i < FUZZ_PATHS.length; i += FUZZ_CONCURRENCY) {
    const chunk = FUZZ_PATHS.slice(i, i + FUZZ_CONCURRENCY);
    const settled = await Promise.allSettled(chunk.map((e) => probePath(baseUrl, e)));
    settled.forEach((s) => {
      if (s.status === 'fulfilled') results.push(s.value);
    });
  }
  return results;
}

export interface CatchAllBaseline {
  status: number | null;
  size: number | null;
  contentType: string | null;
  catchAll: boolean;
  rootContentType: string | null;
  rootSize: number | null;
}

// Probes the root page and a random non-existent path. When the server serves
// the same generic content type for both, sensitive-path findings must not
// trust bare 2xx alone (SPA / catch-all shells).
export async function probeBaseline(baseUrl: string): Promise<CatchAllBaseline> {
  const nonce = `__nexus_${Date.now()}_${Math.floor(Math.random() * 1e6)}__`;
  const root = await probePath(baseUrl, { path: '/', sensitive: false, note: 'Root page' });
  const res = await probePath(baseUrl, { path: `/${nonce}`, sensitive: false, note: 'Catch-all baseline probe' });
  const catchAll = res.status !== null && res.status >= 200 && res.status < 300;
  return {
    status: res.status,
    size: res.size,
    contentType: res.contentType,
    catchAll,
    rootContentType: root.contentType,
    rootSize: root.size,
  };
}

export function looksLikeBaseline(f: FuzzPathResult, baseline: CatchAllBaseline): boolean {
  // Core SPA signal: the sensitive path returns 2xx with the SAME generic
  // content type as the root page (the app shell). Real exposed files (env,
  // config, archives, SQL dumps) are served with a distinct content type, so
  // same-type-as-root on a 2xx is the strongest indicator of a catch-all.
  if (
    f.status !== null &&
    f.status >= 200 &&
    f.status < 300 &&
    baseline.rootContentType &&
    f.contentType &&
    baseline.rootContentType === f.contentType
  ) {
    return true;
  }
  if (!baseline.catchAll) return false;
  if (f.status !== baseline.status) return false;
  // A different content type strongly implies real content, not the catch-all.
  if (f.contentType && baseline.contentType && f.contentType !== baseline.contentType) return false;
  // Same status. If both sizes known, require the size to differ meaningfully
  // (SPA pages embed the requested URL, so the catch-all is rarely byte-identical).
  if (f.size !== null && baseline.size !== null && baseline.size > 0) {
    const diff = Math.abs(f.size - baseline.size);
    if (diff > baseline.size * 0.3 && diff > 4000) return false;
    return true;
  }
  // Unknown size + same content type → treat as likely catch-all.
  return true;
}

// ---------------- kit download + fingerprinting ----------------

export function sha256hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

async function fetchBytes(url: string, maxBytes: number): Promise<{ status: number; contentType: string | null; buf: Buffer; truncated: boolean } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(url, {
      redirect: 'follow',
      headers: { 'User-Agent': UA },
      signal: controller.signal,
    });
    const contentType = response.headers.get('content-type');
    const arr = new Uint8Array(await response.arrayBuffer());
    const truncated = arr.byteLength > maxBytes;
    const buf = Buffer.from(arr.slice(0, maxBytes));
    return { status: response.status, contentType, buf, truncated };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function classifyKind(contentType: string | null, url: string): KitArtifact['kind'] {
  const lower = url.toLowerCase();
  if (/\.(zip|tar|gz|rar|7z|tgz)(\?|$)/.test(lower)) return 'archive';
  if (/\.(sql|db|dump)(\?|$)/.test(lower) || /(sql|dump)/i.test(contentType || '')) return 'config';
  if (/\.(php|asp|aspx|jsp|env|json|conf|inc|bak|txt|log)(\?|$)/.test(lower)) return 'config';
  if (/\.js(\?|$)/.test(lower) || /javascript/.test(contentType || '')) return 'script';
  if (/\.html?(\?|$)/.test(lower) || /text\/html/.test(contentType || '')) return 'page';
  return 'other';
}

// Kit-family signatures matched against downloaded file content.
// Generic families require an exfiltration channel (telegram / off-domain
// post / encoded stealer) to fire — otherwise legit JS (atob, getElementById,
// login forms) would false-positive.
const KIT_SIGNATURES: { family: string; confidence: number; indicators: string[]; patterns: RegExp[]; needsExfil: boolean }[] = [
  {
    family: 'Telegram Exfil Kit',
    confidence: 0.85,
    indicators: ['bot token', 'chat_id', 'sendMessage'],
    patterns: [/api\.telegram\.org\/bot\d{8,10}:[A-Za-z0-9_-]{35}/, /chat_id/, /sendMessage/],
    needsExfil: false,
  },
  {
    family: 'OTP / 2FA Harvester',
    confidence: 0.7,
    indicators: ['one-time-code field', 'SMS/OTP endpoint'],
    patterns: [/one.?time.?code|otp|verification.?code/i, /(?:sms|email).{0,30}(?:code|otp)/i],
    needsExfil: true,
  },
  {
    family: 'Credential Stealer JS',
    confidence: 0.7,
    indicators: ['reads password field', 'atob/base64 encode', 'exfil by base64/telegram'],
    patterns: [/atob\s*\(|fromCharCode|btoa\s*\(/, /(?:getElementById|querySelector)\(['"]{0,2}(?:pass|user|login|email|password)['"]{0,2}\)/i, /(?:\+|\s*\.\s*)(?:atob|btoa)\s*\(/],
    needsExfil: true,
  },
  {
    family: 'GenericPHP Phishing Kit',
    confidence: 0.7,
    indicators: ['login/password POST handler', 'exfil function'],
    patterns: [/<\?php/i, /(?:$_POST|$_GET)\[['"]?(?:username|login|user|email|password|pass)['"]?\]/i, /(?:mail\s*\(|file_get_contents\s*\(\s*['"]https?:\/\/|curl_|base64_(?:encode|decode))/i],
    needsExfil: true,
  },
];

function noteMatches(text: string): string[] {
  const notes: string[] = [];
  for (const sig of KIT_SIGNATURES) {
    for (const pattern of sig.patterns) {
      if (pattern.test(text)) {
        notes.push(`${sig.family}: ${pattern.source}`);
        break;
      }
    }
  }
  return Array.from(new Set(notes)).slice(0, 8);
}

export function fingerprintKitFiles(files: KitArtifact[], hasExfil: boolean): KitMatch[] {
  const matches: KitMatch[] = [];
  const familyHits: Record<string, { hits: number; indicators: Set<string> }> = {};
  for (const file of files) {
    const text = `${file.url}\n${file.notable.join('\n')}`;
    for (const sig of KIT_SIGNATURES) {
      let hits = 0;
      for (const pattern of sig.patterns) {
        if (pattern.test(text)) hits++;
      }
      if (hits > 0) {
        const acc = (familyHits[sig.family] ||= { hits: 0, indicators: new Set() });
        acc.hits += hits;
        sig.indicators.forEach((i) => acc.indicators.add(i));
      }
    }
  }
  for (const [family, acc] of Object.entries(familyHits)) {
    const sig = KIT_SIGNATURES.find((s) => s.family === family)!;
    // Generic families only confirmed when an exfiltration channel exists.
    if (sig.needsExfil && !hasExfil) continue;
    matches.push({
      family,
      confidence: Math.min(1, sig.confidence + (acc.hits >= 2 ? 0.1 : 0)),
      indicators: Array.from(acc.indicators),
    });
  }
  return matches;
}

export async function downloadKitFiles(baseUrl: string, content: ContentAnalysis | null, resources: ResourceProbe[]): Promise<KitArtifact[]> {
  const candidates: string[] = [];

  // Referenced scripts (bounded)
  for (const script of content?.scripts || []) {
    const abs = normalizeUrl(baseUrl, script);
    if (abs) candidates.push(abs);
  }
  for (const res of resources) {
    if (res.type === 'script') candidates.push(res.url);
  }

  const unique: string[] = Array.from(new Set(candidates)).slice(0, KIT_DOWNLOAD_LIMIT);
  const artifacts: KitArtifact[] = [];
  for (const url of unique) {
    const fetched = await fetchBytes(url, MAX_KIT_FILE_BYTES);
    if (!fetched || fetched.status >= 400) continue;
    const kind = classifyKind(fetched.contentType, url);
    const sha256 = sha256hex(fetched.buf.slice(0, MAX_KIT_HASH_BYTES));
    const preview = fetched.buf.toString('utf8').slice(0, 120_000);
    artifacts.push({
      url,
      status: fetched.status,
      size: fetched.buf.byteLength,
      sha256,
      kind,
      notable: noteMatches(preview),
    });
  }
  return artifacts;
}

// ---------------- attribution + artifacts ----------------

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const TELEGRAM_BOT_RE = /\b(\d{8,10}):[A-Za-z0-9_-]{35}\b/g;
const IP_RE = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;

// Placeholder / template addresses that appear in legit sites and are noise.
const PLACEHOLDER_EMAIL_RE = /(example\.|domain\.com|you@|your@|yourname|your-?email|user@|test@|foo@|bar@|someone@|email@|@example|mail\.com$|@microsoft|@apple\.com|@paypal)/i;

function originOf(baseUrl: string): string {
  try {
    return new URL(baseUrl).origin;
  } catch {
    return '';
  }
}

export function collectExfil(content: ContentAnalysis | null, baseUrl: string): ExfilEndpoint[] {
  const out: ExfilEndpoint[] = [];
  const origin = originOf(baseUrl);
  const host = hostOf(baseUrl);

  for (const token of content?.telegramTokens || []) {
    out.push({ url: `https://api.telegram.org/bot${token.slice(0, 14)}…`, kind: 'telegram', detail: 'Telegram bot token in page — C2/exfil channel' });
  }
  for (const chat of content?.telegramChatIds || []) {
    out.push({ url: `chat_id ${chat}`, kind: 'telegram', detail: 'Telegram chat_id in page' });
  }
  for (const form of content?.forms || []) {
    if (form.external && form.action) {
      const abs = normalizeUrl(baseUrl, form.action);
      out.push({ url: abs || form.action, kind: 'remote-form', detail: `Form posts off-domain (${host})` });
    }
  }
  for (const email of content?.emails || []) {
    if (PLACEHOLDER_EMAIL_RE.test(email)) continue;
    out.push({ url: `mailto:${email}`, kind: 'email', detail: 'Email address in page' });
  }

  // dedupe by url
  const seen = new Set<string>();
  return out.filter((e) => {
    if (seen.has(e.url)) return false;
    seen.add(e.url);
    return e.url.startsWith('http') ? new URL(e.url).origin !== origin : true;
  });
}

export function collectArtifacts(params: {
  content: ContentAnalysis | null;
  resources: ResourceProbe[];
  exfil: ExfilEndpoint[];
  host: string;
}): ScannerArtifact[] {
  const { content, resources, exfil, host } = params;
  const artifacts: ScannerArtifact[] = [];
  const seen = new Set<string>();

  const push = (type: ScannerArtifact['type'], value: string, source: string, severity: ScannerArtifact['severity']) => {
    if (!value || value.length > 400) return;
    const key = `${type}:${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    artifacts.push({ type, value, source, severity });
  };

  push('domain', host, 'target URL', 'INFO');

  // exfil endpoints
  for (const e of exfil) {
    if (e.kind === 'telegram') push('telegram', e.url, 'page content', 'CRITICAL');
    if (e.kind === 'remote-form') push('url', e.url, 'form action', 'HIGH');
    if (e.kind === 'email') push('email', e.url.replace('mailto:', ''), 'page content', 'MEDIUM');
  }

  // content emails + tokens
  for (const email of content?.emails || []) {
    if (PLACEHOLDER_EMAIL_RE.test(email)) continue;
    push('email', email, 'page content', 'MEDIUM');
  }
  for (const token of content?.telegramTokens || []) push('telegram', token, 'page content', 'CRITICAL');

  // external resource hosts
  for (const res of resources) {
    const rHost = hostOf(res.url);
    if (rHost && rHost !== host) push('domain', rHost, `resource: ${res.url}`, 'LOW');
    const ipMatch = res.url.match(IP_RE)?.[0];
    if (ipMatch) push('ip', ipMatch, `resource: ${res.url}`, 'MEDIUM');
  }

  // IP literals embedded in content (redirect targets etc.)
  const bodyIps = Array.from(new Set((content?.description || '').match(IP_RE) || []));
  for (const ip of bodyIps) push('ip', ip, 'page metadata', 'LOW');

  return artifacts;
}
