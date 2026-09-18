// Shared types for the URL Scanner module.
// Complements the sandbox (dynamic detonation) with attack-surface analysis:
// path fuzzing, phishing-kit fingerprinting, exfiltration attribution and
// artifact (IoC) collection.

import type {
  ContentAnalysis,
  HttpFingerprint,
  RedirectHop,
  ResourceProbe,
  SandboxVerdict,
  StaticFlag,
  TlsInfo,
} from '@/lib/intel/sandbox/types';

export type { ContentAnalysis, ResourceProbe, SandboxVerdict, StaticFlag };

export interface FuzzPathResult {
  path: string;
  url: string;
  status: number | null;
  contentType: string | null;
  size: number | null;
  sensitive: boolean;
  note: string;
}

export interface KitArtifact {
  url: string;
  status: number | null;
  size: number | null;
  sha256: string | null;
  kind: 'script' | 'archive' | 'config' | 'page' | 'other';
  notable: string[];
}

export interface KitMatch {
  family: string;
  confidence: number;
  indicators: string[];
}

export interface ExfilEndpoint {
  url: string;
  kind: 'telegram' | 'email' | 'remote-form' | 'http-post';
  detail: string;
}

export interface ScannerArtifact {
  type: 'url' | 'domain' | 'ip' | 'email' | 'telegram' | 'file';
  value: string;
  source: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface UrlScannerResult {
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
  fuzz: FuzzPathResult[];
  kitFiles: KitArtifact[];
  kit: { detected: boolean; matches: KitMatch[] };
  exfil: ExfilEndpoint[];
  artifacts: ScannerArtifact[];
  staticFlags: StaticFlag[];
  verdict: SandboxVerdict;
  screenshotUrl: string | null;
}
