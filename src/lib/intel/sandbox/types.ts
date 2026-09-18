// Shared types for the URL Sandbox module.
// The engine (`engine.ts`) captures real HTTP/TLS/content signals, the
// reputation layer (`index.ts`) reuses the IP/Domain intel engines, and
// `index.ts` orchestrates and scores the final verdict.

export interface RedirectHop {
  index: number;
  url: string;
  status: number | null;
}

export interface HttpFingerprint {
  finalUrl: string;
  status: number;
  statusText: string;
  ok: boolean;
  protocol: string;
  server: string | null;
  contentType: string | null;
  contentLength: number | null;
  contentEncoding: string | null;
  headers: Record<string, string>;
  timings: {
    ttfbMs: number;
    totalMs: number;
  };
  html: string | null;
}

export interface TlsInfo {
  protocol: string;
  cipher: string;
  subjectCn: string | null;
  subjectOrg: string | null;
  issuerCn: string | null;
  issuerOrg: string | null;
  san: string[];
  validFrom: string | null;
  validTo: string | null;
  expired: boolean;
  selfSigned: boolean;
  hostnameMismatch: boolean;
}

export interface ContentForm {
  action: string | null;
  method: string;
  external: boolean;
}

export interface ContentIndicator {
  label: string;
  category: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  detail: string;
}

export interface ContentAnalysis {
  title: string | null;
  description: string | null;
  lang: string | null;
  favicon: string | null;
  forms: ContentForm[];
  iframes: { src: string | null }[];
  metaRefresh: boolean;
  obfuscatedJs: boolean;
  inlineJsBytes: number;
  scripts: string[];
  emails: string[];
  telegramTokens: string[];
  telegramChatIds: string[];
  indicators: ContentIndicator[];
  finalHost: string;
}

export interface ResourceProbe {
  url: string;
  host: string;
  type: 'script' | 'stylesheet' | 'image' | 'iframe' | 'font' | 'other';
  status: number | null;
  finalHost: string;
}

export interface DomainReputation {
  ip: string | null;
  geo: string | null;
  asn: string | null;
  isp: string | null;
  dnsblListed: number;
  dnsblBlocked: number;
  torExit: boolean;
  urlhausCount: number;
  hosting: boolean;
  proxy: boolean;
  whoisCreated: string | null;
  domainAgeDays: number | null;
  domainExpires: string | null;
}

export interface StaticFlag {
  label: string;
  weight: number;
  category: string;
}

export interface SandboxVerdict {
  score: number;
  level: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';
  verdict: string;
  reasons: string[];
}

export interface SandboxResult {
  url: string;
  host: string;
  timestamp: string;
  source: string;
  live: boolean;
  http: HttpFingerprint | null;
  redirects: RedirectHop[];
  tls: TlsInfo | null;
  content: ContentAnalysis | null;
  resources: ResourceProbe[];
  reputation: DomainReputation;
  staticFlags: StaticFlag[];
  verdict: SandboxVerdict;
  screenshotUrl: string | null;
}
