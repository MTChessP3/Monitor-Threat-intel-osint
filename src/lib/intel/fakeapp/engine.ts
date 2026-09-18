// Real static APK analysis engine — MobSF-style.
// Downloads an APK, unzips it in-memory, decodes the binary AndroidManifest.xml
// (AXML), parses the META-INF signing certificate (PKCS#7) and scans the dex
// bytecode for hardcoded secrets, URLs, domains and risky API usage. Produces a
// structured report with a weighted risk score and a FAKE/SUSPICIOUS/BENIGN verdict.
// Runtime-agnostic: works in Node (API route) and browser (client-side upload analysis).

import { md5 } from 'js-md5';
import * as forge from 'node-forge';
import { unzipSync } from 'fflate';
import { parseAxml, collapseAttributes } from './axml';

export interface AppComponent {
  name: string;
  exported?: boolean;
  permission?: string;
}

export interface RiskObject {
  id: string;
  type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  recommendation: string;
}

export interface CertInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  selfSigned: boolean;
  signatureAlgorithm?: string;
  expired?: boolean;
}

export interface PermissionAnalysis {
  total: number;
  dangerous: string[];
  dangerousCount: number;
  custom: string[];
}

export interface NetworkFindings {
  urls: string[];
  domains: string[];
  emails: string[];
  ips: string[];
  suspiciousDomains: string[];
}

export interface SecretFinding {
  type: string;
  match: string;
  severity: string;
}

export interface CodeAnalysis {
  dexCount: number;
  nativeLibraries: string[];
  usesDexLoader: boolean;
  usesReflection: boolean;
  usesWebViewJsInterface: boolean;
  usesCleartextHttp: boolean;
  rootIndicators: string[];
  riskyCalls: string[];
}

export interface FakeAppReport {
  fileName: string;
  fileType: string;
  sha256: string;
  md5: string;
  sha1: string;
  sizeBytes: number;
  apkUrl: string;
  appInfo: {
    package: string;
    versionName: string;
    versionCode: string;
    minSdk: string;
    targetSdk: string;
    appName?: string;
    label?: string;
  };
  manifest: {
    allowBackup: boolean | undefined;
    debuggable: boolean | undefined;
    usesCleartextTraffic: boolean | undefined;
    hasNetworkSecurityConfig: boolean;
    exportedCount: number;
    exportedComponents: AppComponent[];
  };
  permissions: PermissionAnalysis;
  components: {
    activities: AppComponent[];
    services: AppComponent[];
    receivers: AppComponent[];
    providers: AppComponent[];
    launcherActivities: string[];
    intentFilters: number;
  };
  certificate: CertInfo | null;
  network: NetworkFindings;
  secrets: SecretFinding[];
  code: CodeAnalysis;
  riskObjects: RiskObject[];
  score: number;
  verdict: string;
  confidence: number;
  categories: Record<string, number>;
}

const MAX_APK_SIZE = 200 * 1024 * 1024; // 200 MB safety cap
const DOWNLOAD_TIMEOUT = 45_000;

const DANGEROUS_PERMS = [
  'android.permission.SEND_SMS',
  'android.permission.RECEIVE_SMS',
  'android.permission.READ_SMS',
  'android.permission.RECEIVE_MMS',
  'android.permission.RECORD_AUDIO',
  'android.permission.CAMERA',
  'android.permission.READ_CONTACTS',
  'android.permission.WRITE_CONTACTS',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.ACCESS_COARSE_LOCATION',
  'android.permission.READ_CALL_LOG',
  'android.permission.WRITE_CALL_LOG',
  'android.permission.READ_PHONE_STATE',
  'android.permission.READ_EXTERNAL_STORAGE',
  'android.permission.WRITE_EXTERNAL_STORAGE',
  'android.permission.GET_ACCOUNTS',
  'android.permission.READ_PHONE_NUMBERS',
  'android.permission.PROCESS_OUTGOING_CALLS',
  'android.permission.ACCESS_BACKGROUND_LOCATION',
  'android.permission.BODY_SENSORS',
  'android.permission.ACTIVITY_RECOGNITION',
  'android.permission.MANAGE_EXTERNAL_STORAGE',
  'android.permission.QUERY_ALL_PACKAGES',
  'android.permission.REQUEST_INSTALL_PACKAGES',
  'android.permission.REQUEST_DELETE_PACKAGES',
  'android.permission.WRITE_SETTINGS',
  'android.permission.SYSTEM_ALERT_WINDOW',
];

// Permissions that are strong signals for credential harvesting / OTP interception
const HIGH_RISK_PERMS = [
  'android.permission.SEND_SMS',
  'android.permission.RECEIVE_SMS',
  'android.permission.READ_SMS',
  'android.permission.RECEIVE_MMS',
  'android.permission.RECORD_AUDIO',
  'android.permission.CAMERA',
  'android.permission.READ_CONTACTS',
  'android.permission.WRITE_CONTACTS',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.ACCESS_COARSE_LOCATION',
  'android.permission.READ_CALL_LOG',
  'android.permission.WRITE_CALL_LOG',
  'android.permission.READ_PHONE_STATE',
  'android.permission.GET_ACCOUNTS',
  'android.permission.READ_PHONE_NUMBERS',
  'android.permission.PROCESS_OUTGOING_CALLS',
  'android.permission.ACCESS_BACKGROUND_LOCATION',
  'android.permission.BODY_SENSORS',
];

// Well-known TLDs that should NOT count as "suspicious"
const COMMON_TLDS = new Set([
  'com', 'org', 'net', 'io', 'co', 'app', 'dev', 'me', 'info', 'xyz', 'site',
  'top', 'online', 'pro', 'tech', 'store', 'live', 'cloud', 'club', 'space',
  'today', 'world', 'shop', 'blog', 'news', 'media', 'social', 'link', 'click',
  'work', 'email', 'app', 'guru', 'center', 'digital', 'web', 'agency', 'city',
  'be', 'tv', 'fm', 'ai', 'gg', 'cc', 'su', 'de', 'cn', 'ru', 'br', 'in', 'jp',
  'uk', 'us', 'ca', 'au', 'eu', 'es', 'it', 'fr', 'nl', 'pl', 'se', 'ch', 'at',
  'no', 'dk', 'fi', 'ie', 'cz', 'pt', 'mx', 'ar', 'co', 'za', 'nz', 'sg', 'hk',
  'kr', 'id', 'th', 'vn', 'tw', 'tr', 'ph', 'my', 'ro', 'bg', 'hr', 'rs', 'ua',
  'sk', 'si', 'lt', 'lv', 'ee', 'gr', 'hu', 'il', 'ae', 'sa', 'qa', 'kz',
  'android', 'java', 'apache', 'googleapis', 'gstatic', 'google',
]);

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'buzz', 'club', 'online',
  'live', 'click', 'link', 'win', 'bid', 'download', 'rest', 'men', 'loan',
  'review', 'stream', 'racing', 'work', 'icu', 'vip', 'pro', 'lol', 'pics',
]);

// Official / well-known hosts that should never be flagged as suspicious even
// if they use an otherwise-dicey TLD (e.g. fdroid.link is F-Droid's shortener).
const KNOWN_GOOD_HOSTS = new Set([
  'fdroid.link', 'goo.gl', 'bit.ly', 'github.com', 'github.io', 'gitlab.com',
  'android.com', 'androiddevelopers.googleblog.com', 'developer.android.com',
  'schemas.android.com', 'apache.org', 'google.com', 'googleapis.com',
  'gstatic.com', 'w3.org', 'xmlpull.org', 'kotlinlang.org', 'jetbrains.com',
]);

const RISKY_API_CALLS: Array<{ pattern: RegExp; type: string; weight: number }> = [
  { pattern: /Ldalvik\/system\/DexClassLoader;|Ldalvik\/system\/PathClassLoader;/, type: 'DEX_LOADER', weight: 20 },
  { pattern: /addJavascriptInterface/, type: 'WEBVIEW_JS_BRIDGE', weight: 12 },
  { pattern: /Cipher\.getInstance\("(DES|RC4|MD5|SHA-1|SHA1)"/i, type: 'WEAK_CRYPTO', weight: 10 },
  { pattern: /MODE_WORLD_READABLE|MODE_WORLD_WRITABLE/, type: 'INSECURE_FILE_MODE', weight: 10 },
  { pattern: /Runtime\.getRuntime\(\)\.exec|ProcessBuilder/, type: 'COMMAND_EXEC', weight: 6 },
  { pattern: /java\/lang\/reflect\b/, type: 'REFLECTION', weight: 4 },
  { pattern: /HttpURLConnection|URLConnection|OkHttpClient/, type: 'HTTP_CLIENT', weight: 2 },
  { pattern: /getInstalledPackages|queryIntentActivities/, type: 'PACKAGE_ENUM', weight: 2 },
];

const ROOT_INDICATORS = [
  '/system/app/Superuser.apk',
  '/system/xbin/su',
  '/system/bin/su',
  '/system/app/SuperSU',
  'com.noshufou.android.su',
  'eu.chainfire.supersu',
  'net.dinglisch.android.taskerm',
  'test-keys',
  'adbd',
  'isRooted',
  'rootbeer',
];

const SECRET_PATTERNS: Array<{ type: string; regex: RegExp; severity: string }> = [
  { type: 'AWS_ACCESS_KEY', regex: /AKIA[0-9A-Z]{16}/g, severity: 'HIGH' },
  { type: 'GOOGLE_API_KEY', regex: /AIza[0-9A-Za-z_\-]{35}/g, severity: 'HIGH' },
  { type: 'PRIVATE_KEY', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, severity: 'CRITICAL' },
  { type: 'GENERIC_PASSWORD', regex: /(?:password|passwd|pwd)[=:]["']?[^"'=:\s][^"'=\s]{3,}/gi, severity: 'HIGH' },
  { type: 'API_TOKEN', regex: /(?:api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|secret)[=:]["']?[^"'=:\s][^"'=\s]{7,}/gi, severity: 'HIGH' },
  { type: 'FIREBASE_URL', regex: /https:\/\/[a-zA-Z0-9-]+\.firebaseio\.com/g, severity: 'MEDIUM' },
  { type: 'GITHUB_TOKEN', regex: /ghp_[A-Za-z0-9]{36}/g, severity: 'HIGH' },
  { type: 'SLACK_TOKEN', regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g, severity: 'HIGH' },
];

export async function downloadApk(url: string): Promise<Uint8Array> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DOWNLOAD_TIMEOUT);
  try {
    const res = await fetch(url, { signal: controller.signal, redirect: 'follow' });
    if (!res.ok) throw new Error(`Download failed: HTTP ${res.status}`);
    const contentLength = Number(res.headers.get('content-length') || 0);
    if (contentLength > MAX_APK_SIZE) {
      throw new Error(`APK too large (${Math.round(contentLength / 1048576)} MB)`);
    }
    const arrayBuffer = await res.arrayBuffer();
    if (arrayBuffer.byteLength > MAX_APK_SIZE) {
      throw new Error('APK exceeds 200 MB safety cap');
    }
    return new Uint8Array(arrayBuffer);
  } finally {
    clearTimeout(timer);
  }
}

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

async function sha256(buf: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buf as unknown as ArrayBuffer);
  return toHex(new Uint8Array(digest));
}

async function sha1(buf: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-1', buf as unknown as ArrayBuffer);
  return toHex(new Uint8Array(digest));
}

async function getHashes(buf: Uint8Array): Promise<{ sha256: string; md5: string; sha1: string }> {
  return {
    sha256: await sha256(buf),
    md5: md5(buf as unknown as Uint8Array),
    sha1: await sha1(buf),
  };
}

function isCertFile(name: string): boolean {
  return /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(name);
}

function toBinaryString(bytes: Uint8Array): string {
  let out = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK) as unknown as number[]);
  }
  return out;
}

export function parseCertificate(certBuf: Uint8Array): CertInfo | null {
  try {
    const asn1 = forge.asn1.fromDer(toBinaryString(certBuf));
    let p7: any;
    try {
      p7 = forge.pkcs7.messageFromAsn1(asn1);
    } catch {
      p7 = null;
    }
    let cert: any = null;
    if (p7 && p7.certificates && p7.certificates.length) {
      cert = p7.certificates[p7.certificates.length - 1];
    } else {
      // Fallback: try parsing as raw X.509
      cert = forge.pki.certificateFromAsn1(asn1);
    }
    if (!cert) return null;
    const subjAttr = (a: any) => a.value;
    const subject = cert.subject.attributes.map(subjAttr).join(', ');
    const issuer = cert.issuer.attributes.map(subjAttr).join(', ');
    const notBefore = new Date(cert.validity.notBefore);
    const notAfter = new Date(cert.validity.notAfter);
    return {
      subject,
      issuer,
      serialNumber: cert.serialNumber || '',
      validFrom: notBefore.toISOString(),
      validTo: notAfter.toISOString(),
      selfSigned: subject === issuer,
      signatureAlgorithm: cert.signatureOid || undefined,
      expired: notAfter.getTime() < Date.now(),
    };
  } catch {
    return null;
  }
}

// Extract printable ASCII string runs from a byte buffer.
export function extractStrings(data: Uint8Array, minLen = 4): string[] {
  const strings: string[] = [];
  let current: string[] = [];
  for (let i = 0; i < data.length; i++) {
    const c = data[i];
    if (c >= 32 && c < 127) {
      current.push(String.fromCharCode(c));
    } else {
      if (current.length >= minLen) strings.push(current.join(''));
      current = [];
    }
  }
  if (current.length >= minLen) strings.push(current.join(''));
  return strings;
}

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/;
const URL_RE = /https?:\/\/[^\s"'<>]+/gi;
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/g;

function validHost(host: string): boolean {
  const labels = host.toLowerCase().replace(/\.+$/, '').split('.');
  if (labels.length < 2 || labels.length > 8) return false;
  for (const label of labels) {
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) return false;
  }
  const tld = labels[labels.length - 1];
  return COMMON_TLDS.has(tld);
}

function isSuspiciousHost(host: string): boolean {
  const clean = host.toLowerCase().replace(/^www\./, '');
  if (KNOWN_GOOD_HOSTS.has(clean)) return false;
  const labels = clean.replace(/\.+$/, '').split('.');
  const tld = labels[labels.length - 1];
  return SUSPICIOUS_TLDS.has(tld);
}

export function analyzeNetworkFindings(strings: string[]): NetworkFindings {
  const urls = new Set<string>();
  const domains = new Set<string>();
  const emails = new Set<string>();
  const ips = new Set<string>();
  const suspicious = new Set<string>();

  for (const s of strings) {
    for (const m of s.match(URL_RE) || []) {
      urls.add(m);
      try {
        const host = new URL(m).hostname;
        if (validHost(host)) {
          domains.add(host.replace(/^www\./, ''));
          if (isSuspiciousHost(host)) suspicious.add(host.replace(/^www\./, ''));
        }
      } catch {
        /* ignore malformed URL */
      }
    }
    for (const m of s.match(EMAIL_RE) || []) {
      emails.add(m.toLowerCase());
      const domain = m.split('@')[1];
      if (domain && validHost(domain)) domains.add(domain.replace(/^www\./, ''));
    }
    for (const m of s.match(IPV4_RE) || []) {
      const octets = m.split('.').map(Number);
      const isPrivate = octets[0] === 10 || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) || octets[0] === 192 && octets[1] === 168 || octets[0] === 127;
      if (!isPrivate) ips.add(m);
    }
  }

  return {
    urls: [...urls].slice(0, 100),
    domains: [...domains].sort().slice(0, 150),
    emails: [...emails].slice(0, 50),
    ips: [...ips].slice(0, 50),
    suspiciousDomains: [...suspicious].sort().slice(0, 30),
  };
}

export function findSecrets(strings: string[]): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const seen = new Set<string>();
  for (const s of strings) {
    // Only scan short, plausible assignment strings to reduce dex noise
    if (s.length > 500) continue;
    for (const pattern of SECRET_PATTERNS) {
      for (const m of s.matchAll(pattern.regex)) {
        const key = `${pattern.type}:${m[0]}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({ type: pattern.type, match: m[0], severity: pattern.severity });
      }
    }
  }
  return findings.slice(0, 50);
}

function analyzeCode(dexBuffers: Uint8Array[], strings: string[], nativeLibraries: string[], manifest: any): CodeAnalysis {
  const joined = dexBuffers.map((d) => extractStrings(d, 5)).flat().join('\n');
  const riskyCalls: string[] = [];
  const rootIndicators: string[] = [];

  for (const rule of RISKY_API_CALLS) {
    if (rule.pattern.test(joined)) riskyCalls.push(rule.type);
  }
  for (const s of strings) {
    for (const root of ROOT_INDICATORS) {
      if (s.includes(root)) {
        rootIndicators.push(root);
        break;
      }
    }
  }
  return {
    dexCount: dexBuffers.length,
    nativeLibraries: [...new Set(nativeLibraries)],
    usesDexLoader: riskyCalls.includes('DEX_LOADER'),
    usesReflection: riskyCalls.includes('REFLECTION'),
    usesWebViewJsInterface: riskyCalls.includes('WEBVIEW_JS_BRIDGE'),
    usesCleartextHttp: riskyCalls.includes('HTTP_CLIENT'),
    rootIndicators: [...new Set(rootIndicators)].slice(0, 10),
    riskyCalls,
  };
}

function weightSeverity(sev: string): number {
  switch (sev) {
    case 'CRITICAL': return 30;
    case 'HIGH': return 16;
    case 'MEDIUM': return 8;
    default: return 3;
  }
}

export function scoreAnalysis(
  manifest: any,
  perms: PermissionAnalysis,
  cert: CertInfo | null,
  network: NetworkFindings,
  secrets: SecretFinding[],
  code: CodeAnalysis,
  exportedComponents: AppComponent[],
  components: any
): { score: number; verdict: string; confidence: number; categories: Record<string, number>; riskObjects: RiskObject[] } {
  const riskObjects: RiskObject[] = [];
  let riskId = 1001;

  const pushRisk = (type: string, severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL', description: string, recommendation: string) => {
    riskObjects.push({ id: `RISK-${riskId++}`, type, severity, description, recommendation });
  };

  // --- Manifest score ---
  let manifestScore = 0;
  const manifestMax = 100;
  if (manifest?.allowBackup === true) {
    manifestScore += 25;
    pushRisk('ALLOW_BACKUP', 'MEDIUM', 'App allows full system backup via AndroidManifest', 'Set android:allowBackup="false" to prevent local data extraction');
  }
  if (manifest?.debuggable === true) {
    manifestScore += 40;
    pushRisk('DEBUGGABLE', 'CRITICAL', 'Application is debuggable — can be attached to by any debugger', 'Remove android:debuggable="true" before release');
  }
  if (manifest?.usesCleartextTraffic === true) {
    manifestScore += 30;
    pushRisk('CLEARTEXT_TRAFFIC', 'HIGH', 'Network security config permits cleartext HTTP', 'Enforce HTTPS and certificate pinning');
  }
  if (exportedComponents.length > 0) {
    const sensitiveExported = exportedComponents.filter((c) => !c.permission);
    manifestScore += Math.min(35, sensitiveExported.length * 7);
    if (sensitiveExported.length > 0) {
      pushRisk('EXPORTED_COMPONENTS', sensitiveExported.length > 3 ? 'HIGH' : 'MEDIUM', `${sensitiveExported.length} component(s) exported without permission protection`, 'Restrict exported components with android:exported="false" or permissions');
    }
  }

  // --- Permissions score ---
  let permScore = 0;
  if (perms.dangerousCount > 0) {
    const highRiskCount = perms.dangerous.filter((p) => HIGH_RISK_PERMS.includes(p)).length;
    permScore = Math.min(100, highRiskCount * 20 + (perms.dangerousCount - highRiskCount) * 4);
    if (perms.dangerous.some((p) => p.includes('SMS') || p.includes('RECORD_AUDIO'))) {
      pushRisk('HIGH_RISK_PERMISSIONS', 'HIGH', 'Sensitive permissions requested (SMS / audio)', 'Review need; OTP interception and ambient recording vectors');
    } else if (highRiskCount >= 3) {
      pushRisk('HIGH_RISK_PERMISSIONS', 'MEDIUM', `${highRiskCount} high-risk permission(s) requested`, 'Review each permission for necessity');
    } else if (perms.dangerous.length >= 5) {
      pushRisk('DANGEROUS_PERMISSIONS', 'LOW', `${perms.dangerousCount} dangerous permission(s) requested (mostly legacy)`, 'Review each permission for necessity');
    }
  }

  // --- Certificate score ---
  let certScore = 0;
  if (cert) {
    if (cert.expired) {
      certScore += 35;
      pushRisk('EXPIRED_CERT', 'HIGH', 'Signing certificate has expired', 'Treat as stale or repackaged signature');
    } else if (cert.selfSigned) {
      // Self-signed is the Android norm; only a low informational note
      certScore += 5;
      pushRisk('SELF_SIGNED_CERT', 'LOW', 'APK signed with a self-signed certificate (common for sideloaded apps)', 'Verify the signature matches the legitimate vendor key');
    }
    if (!cert.selfSigned && /Unknown|Untrusted|Unverified/i.test(cert.issuer)) {
      certScore += 20;
      pushRisk('UNVERIFIED_ISSUER', 'MEDIUM', 'Certificate issuer is not a well-known CA', 'Validate certificate chain');
    }
  }

  // --- Network score ---
  let netScore = 0;
  if (network.suspiciousDomains.length > 0) {
    netScore += Math.min(45, network.suspiciousDomains.length * 8);
    pushRisk('SUSPICIOUS_DOMAINS', 'HIGH', `${network.suspiciousDomains.length} suspicious domain(s) referenced in binary`, 'Correlate domains against threat intel');
  }
  if (code.usesDexLoader) {
    netScore += 20;
    pushRisk('DYNAMIC_CODE_LOADING', 'HIGH', 'Dynamically loads DEX bytecode at runtime', 'Dynamic loading can hide malicious payloads');
  }
  if (code.usesCleartextHttp) {
    netScore += 5;
  }

  // --- Secrets score ---
  let secretScore = 0;
  if (secrets.length > 0) {
    secretScore = Math.min(100, secrets.reduce((acc, s) => acc + weightSeverity(s.severity), 0));
    const critical = secrets.filter((s) => s.severity === 'CRITICAL').length;
    pushRisk(
      'HARDCODED_SECRETS',
      critical > 0 ? 'CRITICAL' : 'HIGH',
      `${secrets.length} hardcoded secret(s) found in binary (${critical} critical)`,
      'Rotate leaked keys; move secrets to secure backend storage'
    );
  }

  // --- Code score ---
  let codeScore = 0;
  if (code.riskyCalls.length > 0) {
    for (const call of code.riskyCalls) {
      const rule = RISKY_API_CALLS.find((r) => r.type === call);
      codeScore += rule ? rule.weight : 3;
    }
    codeScore = Math.min(100, codeScore);
  }
  if (code.rootIndicators.length > 0) {
    codeScore += 15;
    pushRisk('ROOT_CHECKS', 'MEDIUM', 'Root detection indicators present in binary', 'Common in malware to evade sandboxes');
  }

  const categories = {
    manifest: Math.min(manifestMax, manifestScore),
    permissions: permScore,
    certificate: certScore,
    network: netScore,
    secrets: secretScore,
    code: codeScore,
  };

  // Weighted overall score (MobSF-like average). No baseline constant: a clean
  // app with only informational findings should land in the BENIGN range.
  const score = Math.round(
    categories.manifest * 0.2 +
    categories.permissions * 0.3 +
    categories.certificate * 0.1 +
    categories.network * 0.15 +
    categories.secrets * 0.15 +
    categories.code * 0.1
  );
  const normalized = Math.min(100, score);

  let verdict = 'BENIGN';
  let confidence = 55;
  if (normalized >= 45) {
    verdict = 'FAKE';
    confidence = Math.min(95, 60 + normalized * 0.35);
  } else if (normalized >= 25) {
    verdict = 'SUSPICIOUS';
    confidence = Math.min(85, 45 + normalized * 0.8);
  } else {
    confidence = Math.max(30, 55 - normalized);
  }

  if (riskObjects.length === 0) {
    pushRisk('CLEAN', 'LOW', 'No high-risk indicators detected in static analysis', 'Continue to dynamic analysis for confirmation');
  }

  return { score: normalized, verdict, confidence: Math.round(confidence), categories, riskObjects };
}

export interface AnalyzeOptions {
  maxWaitMs?: number;
}

// Recursively locate an AndroidManifest.xml in a container (APK, AAB, XAPK, APKS, ZIP)
function findManifestEntry(unzipped: Record<string, Uint8Array>): { path: string; data: Uint8Array } | null {
  const candidates = [
    'AndroidManifest.xml',
    'base/manifest/AndroidManifest.xml', // AAB
    'base/AndroidManifest.xml',
  ];
  for (const c of candidates) {
    if (unzipped[c]) return { path: c, data: unzipped[c] };
  }
  // Fallback: search any AndroidManifest.xml anywhere in the tree
  const found = Object.keys(unzipped).find((n) => n.endsWith('AndroidManifest.xml'));
  if (found) return { path: found, data: unzipped[found] };
  return null;
}

// Parse the binary AXML manifest into the same object shape the engine expects.
function parseManifestAxml(manifestEntry: Uint8Array): any {
  const doc = parseAxml(manifestEntry);
  const collapse = (el: any): any => {
    const out: Record<string, any> = {};
    for (const attr of el.attributes || []) out[attr.name] = attr.value;
    return out;
  };

  const manifest: any = {
    usesPermissions: [],
    permissions: [],
    usesSdk: null,
    application: { activities: [], services: [], receivers: [], providers: [], launcherActivities: [], activityAliases: [] },
  };
  Object.assign(manifest, collapse(doc));

  const collectComponent = (el: any, list: any[], launcherList: any[], isActivity: boolean) => {
    const comp = collapse(el);
    comp.intentFilters = [];
    for (const child of el.childNodes || []) {
      if (child.nodeName === 'intent-filter') {
        const filter: any = { actions: [], categories: [] };
        Object.assign(filter, collapse(child));
        for (const fc of child.childNodes || []) {
          if (fc.nodeName === 'action') filter.actions.push(collapse(fc));
          else if (fc.nodeName === 'category') filter.categories.push(collapse(fc));
          else if (fc.nodeName === 'data') (filter.data = filter.data || []).push(collapse(fc));
        }
        comp.intentFilters.push(filter);
      }
    }
    list.push(comp);
    if (isActivity) {
      const isLauncher = comp.intentFilters.some(
        (f: any) =>
          f.actions.some((a: any) => a.name === 'android.intent.action.MAIN') &&
          (f.categories.some((c: any) => c.name === 'android.intent.category.LAUNCHER') || f.categories.some((c: any) => c.name === 'android.intent.category.LEANBACK_LAUNCHER'))
      );
      if (isLauncher) launcherList.push(comp);
    }
  };

  for (const child of doc.childNodes || []) {
    switch (child.nodeName) {
      case 'uses-permission':
        manifest.usesPermissions.push(collapse(child));
        break;
      case 'uses-sdk':
        manifest.usesSdk = collapse(child);
        break;
      case 'application':
        Object.assign(manifest.application, collapse(child));
        for (const appChild of child.childNodes || []) {
          switch (appChild.nodeName) {
            case 'activity':
              collectComponent(appChild, manifest.application.activities, manifest.application.launcherActivities, true);
              break;
            case 'activity-alias':
              collectComponent(appChild, manifest.application.activityAliases, manifest.application.launcherActivities, true);
              break;
            case 'service':
              collectComponent(appChild, manifest.application.services, [], false);
              break;
            case 'receiver':
              collectComponent(appChild, manifest.application.receivers, [], false);
              break;
            case 'provider':
              collectComponent(appChild, manifest.application.providers, [], false);
              break;
          }
        }
        break;
    }
  }

  return manifest;
}

export async function analyzeApkBytes(
  apkBytes: Uint8Array,
  meta: { apkUrl?: string; fileName?: string; fileType?: string }
): Promise<FakeAppReport> {
  const hashes = await getHashes(apkBytes);

  const unzipped: Record<string, Uint8Array> = unzipSync(apkBytes);

  const manifestFound = findManifestEntry(unzipped);
  if (!manifestFound) {
    throw new Error('Invalid package: no AndroidManifest.xml found (not an APK/AAB)');
  }

  let manifest: any = null;
  try {
    manifest = parseManifestAxml(manifestFound.data);
  } catch (e) {
    throw new Error(`Failed to decode AndroidManifest.xml: ${e instanceof Error ? e.message : e}`);
  }

  // Certificate (APK META-INF; AAB META-INF too)
  const certFileName = Object.keys(unzipped).find(isCertFile);
  const cert = certFileName ? parseCertificate(unzipped[certFileName]) : null;

  // Permissions
  const usesPermissions: any[] = manifest.usesPermissions || [];
  const dangerous = usesPermissions
    .map((p: any) => p.name)
    .filter((name: string) => DANGEROUS_PERMS.includes(name))
    .filter((v: string, i: number, a: string[]) => a.indexOf(v) === i);
  const custom = usesPermissions
    .map((p: any) => p.name)
    .filter((name: string) => name && !name.startsWith('android.permission.'));

  const permissions: PermissionAnalysis = {
    total: usesPermissions.length,
    dangerous,
    dangerousCount: dangerous.length,
    custom: [...new Set(custom)],
  };

  // Components
  const app = manifest.application || {};
  const act = (c: any) => ({ name: c.name, exported: c.exported === true || c.exported === undefined ? undefined : c.exported, permission: c.permission });
  const activities: AppComponent[] = (app.activities || []).map(act);
  const services: AppComponent[] = (app.services || []).map(act);
  const receivers: AppComponent[] = (app.receivers || []).map(act);
  const providers: AppComponent[] = (app.providers || []).map(act);

  const exportedComponents: AppComponent[] = [...activities, ...services, ...receivers, ...providers].filter(
    (c) => c.exported === true
  );

  let intentFilters = 0;
  [...activities, ...services, ...receivers].forEach((c: any) => {
    intentFilters += (c.intentFilters || []).length;
  });

  // Native libraries
  const nativeLibraries = Object.keys(unzipped)
    .filter((n) => n.startsWith('lib/') && /\.so$/.test(n))
    .map((n) => n.split('/').pop() || n);

  // Dex + strings (APK: classes*.dex; AAB: base/dex/*.dex)
  const dexBuffers = Object.keys(unzipped)
    .filter((n) => /(^|\/)(classes\d*\.dex)$/i.test(n))
    .map((n) => unzipped[n]);

  let allStrings: string[] = [];
  const scannedEntries = [
    ...dexBuffers,
    ...Object.keys(unzipped)
      .filter((n) => n.startsWith('assets/') || n === 'resources.arsc' || n === 'base/assets/')
      .map((n) => unzipped[n]),
  ];
  const MAX_STRINGS = 2_000_000;
  for (const buf of scannedEntries) {
    const strs = extractStrings(buf, 4);
    allStrings = allStrings.concat(strs);
    if (allStrings.length > MAX_STRINGS) break;
  }

  const network = analyzeNetworkFindings(allStrings);
  const secrets = findSecrets(allStrings);
  const code = analyzeCode(dexBuffers, allStrings, nativeLibraries, manifest);

  const manifestFlags = {
    allowBackup: app.allowBackup === true ? true : app.allowBackup === false ? false : undefined,
    debuggable: app.debuggable === true ? true : app.debuggable === false ? false : undefined,
    usesCleartextTraffic: app.usesCleartextTraffic === true ? true : app.usesCleartextTraffic === false ? false : undefined,
    hasNetworkSecurityConfig: Object.keys(unzipped).some((n) => n.includes('network_security_config')),
    exportedCount: exportedComponents.length,
    exportedComponents,
  };

  const components = {
    activities,
    services,
    receivers,
    providers,
    launcherActivities: (app.launcherActivities || []).map((a: any) => a.name),
    intentFilters,
  };

  const { score, verdict, confidence, categories, riskObjects } = scoreAnalysis(
    manifestFlags,
    permissions,
    cert,
    network,
    secrets,
    code,
    exportedComponents,
    components
  );

  const fileType = meta.fileType || 'APK';
  const fileName = meta.fileName || (meta.apkUrl ? new URL(meta.apkUrl).pathname.split('/').pop() : undefined) || 'unknown.apk';

  return {
    fileName,
    fileType,
    sha256: hashes.sha256,
    md5: hashes.md5,
    sha1: hashes.sha1,
    sizeBytes: apkBytes.length,
    apkUrl: meta.apkUrl || '',
    appInfo: {
      package: manifest.package || 'unknown',
      versionName: manifest.versionName || '',
      versionCode: manifest.versionCode !== undefined ? String(manifest.versionCode) : '',
      minSdk: manifest.usesSdk?.minSdkVersion !== undefined ? String(manifest.usesSdk.minSdkVersion) : '',
      targetSdk: manifest.usesSdk?.targetSdkVersion !== undefined ? String(manifest.usesSdk.targetSdkVersion) : '',
      appName: app.name,
      label: app.label,
    },
    manifest: manifestFlags,
    permissions,
    components,
    certificate: cert,
    network,
    secrets,
    code,
    riskObjects,
    score,
    verdict,
    confidence,
    categories,
  };
}

export async function analyzeApkFromBuffer(apkBuffer: Uint8Array, apkUrl: string, fileName?: string): Promise<FakeAppReport> {
  return analyzeApkBytes(apkBuffer, { apkUrl, fileName });
}

export async function analyzeApkFromUrl(url: string, opts?: AnalyzeOptions): Promise<FakeAppReport> {
  const apkBytes = await downloadApk(url);
  return analyzeApkBytes(apkBytes, { apkUrl: url });
}
