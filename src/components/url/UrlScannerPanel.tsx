'use client';

// URL Scanner Panel — interactive UI for the attack-surface scanner module.
// Renders: verdict, sensitive-path fuzzing results, phishing-kit fingerprint
// (downloaded files + SHA-256), exfiltration attribution and artifact (IoC)
// list. Decoupled from page.tsx.

import React, { useState } from 'react';
import {
  Search, Loader2, Copy, ChevronDown, ChevronRight, Shield, ShieldAlert,
  ShieldCheck, AlertTriangle, CheckCircle, XCircle, Network, Server, Lock,
  Globe, Mail, Fingerprint, MapPin, FileCode, Bug, ArrowRight, ExternalLink,
  Image, RefreshCw, Eye, FileSearch, FolderOpen, Hash, Send, Binary, Printer,
} from 'lucide-react';

interface ScannerData {
  url: string;
  host: string;
  http: {
    finalUrl: string; status: number; statusText: string; ok: boolean;
    protocol: string; server: string | null; contentType: string | null;
    contentLength: number | null; contentEncoding: string | null;
    headers: Record<string, string>;
    timings: { ttfbMs: number; totalMs: number };
  } | null;
  redirects: { index: number; url: string; status: number | null }[];
  tls: {
    protocol: string; cipher: string; subjectCn: string | null; subjectOrg: string | null;
    issuerCn: string | null; issuerOrg: string | null; san: string[];
    validFrom: string | null; validTo: string | null; expired: boolean;
    selfSigned: boolean; hostnameMismatch: boolean;
  } | null;
  content: {
    title: string | null; description: string | null; lang: string | null;
    favicon: string | null;
    forms: { action: string | null; method: string; external: boolean }[];
    iframes: { src: string | null }[];
    metaRefresh: boolean; obfuscatedJs: boolean; inlineJsBytes: number;
    scripts: string[]; emails: string[]; telegramTokens: string[]; telegramChatIds: string[];
    indicators: { label: string; category: string; severity: string; detail: string }[];
  } | null;
  resources: { url: string; host: string; type: string; status: number | null }[];
  fuzz: { path: string; url: string; status: number | null; contentType: string | null; size: number | null; sensitive: boolean; note: string }[];
  kitFiles: { url: string; status: number | null; size: number | null; sha256: string | null; kind: string; notable: string[] }[];
  kit: { detected: boolean; matches: { family: string; confidence: number; indicators: string[] }[] };
  exfil: { url: string; kind: string; detail: string }[];
  artifacts: { type: string; value: string; source: string; severity: string }[];
  staticFlags: { label: string; weight: number; category: string }[];
  verdict: { score: number; level: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS'; verdict: string; reasons: string[] };
  screenshotUrl: string | null;
}

interface VirusTotalResult {
  source: string;
  analyzed: boolean;
  url: string;
  reputation: number;
  lastAnalysisDate: string | null;
  lastAnalysisStats: { malicious: number; suspicious: number; undetected: number; harmless: number; timeout: number };
  totalEngines: number;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
  categories: string[];
  votes: { harmless: number; malicious: number };
  tags: string[];
  firstSeen: string | null;
  lastSeen: string | null;
}

interface Props {
  data: ScannerData | null;
  virusTotal: VirusTotalResult | null;
  loading: boolean;
  inputValue: string;
  setInputValue: (v: string) => void;
  onScan: (url?: string) => void;
  onCopy: (text: string) => void;
  onReport?: () => void;
}

const LEVEL_STYLES: Record<string, { badge: string; bar: string; icon: any }> = {
  MALICIOUS: { badge: 'bg-red-500/20 text-red-400 border-red-500/40', bar: 'bg-red-500', icon: ShieldAlert },
  SUSPICIOUS: { badge: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40', bar: 'bg-yellow-500', icon: AlertTriangle },
  BENIGN: { badge: 'bg-green-500/20 text-green-400 border-green-500/40', bar: 'bg-green-500', icon: ShieldCheck },
};

const KIND_STYLE: Record<string, string> = {
  script: 'bg-purple-500/15 text-purple-300',
  archive: 'bg-orange-500/15 text-orange-300',
  config: 'bg-cyan-500/15 text-cyan-300',
  page: 'bg-blue-500/15 text-blue-300',
  other: 'bg-gray-800 text-gray-400',
};

const ARTIFACT_TYPE: Record<string, { icon: any; color: string }> = {
  url: { icon: Globe, color: 'text-lime-400' },
  domain: { icon: Network, color: 'text-cyan-400' },
  ip: { icon: MapPin, color: 'text-blue-400' },
  email: { icon: Mail, color: 'text-yellow-400' },
  telegram: { icon: Send, color: 'text-sky-400' },
  file: { icon: FileCode, color: 'text-purple-400' },
};

function statusColor(status: number | null): string {
  if (status === null) return 'text-red-400';
  if (status >= 400) return 'text-red-400';
  if (status >= 300) return 'text-yellow-400';
  return 'text-green-400';
}

function fmtBytes(bytes: number | null): string {
  if (bytes === null || bytes < 0) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

export default function UrlScannerPanel({ data, virusTotal, loading, inputValue, setInputValue, onScan, onCopy, onReport }: Props) {
  const [openSection, setOpenSection] = useState<string | null>('fuzz');
  const [showAllFuzz, setShowAllFuzz] = useState(false);
  const [showAllArtifacts, setShowAllArtifacts] = useState(false);

  const verdict = data?.verdict;
  const style = verdict ? LEVEL_STYLES[verdict.level] || LEVEL_STYLES.BENIGN : null;
  const VerdictIcon = style?.icon || Shield;

  const exposed = (data?.fuzz || []).filter((f) => f.status !== null && f.status < 400 && f.status >= 200) || [];
  const shownFuzz = showAllFuzz ? data?.fuzz || [] : exposed;
  const visibleArtifacts = showAllArtifacts ? data?.artifacts || [] : (data?.artifacts || []).slice(0, 12);

  const toggle = (id: string) => setOpenSection(openSection === id ? null : id);

  return (
    <div className="space-y-6">
      {/* ===== Input ===== */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <div className="flex gap-4">
          <div className="flex-1">
            <input
              type="text"
              placeholder="URL to scan (e.g., https://login-update.secure/verify)"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && onScan()}
              className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-yellow-500 focus:outline-none"
            />
          </div>
          <button
            onClick={() => onScan()}
            disabled={loading || !inputValue}
            className="px-6 py-3 bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            Scan
          </button>
        </div>
<div className="mt-3 flex flex-wrap gap-2 items-center">
            {data ? (
              <>
                <span className="px-2 py-1 bg-gray-800 rounded text-xs font-mono text-gray-300">
                  {verdict ? (
                    <span className={style?.badge || LEVEL_STYLES.BENIGN.badge}>{verdict.level}</span>
                  ) : (
                    'Scanned'
                  )}
                </span>
                {data.http && (
                  <span className="px-2 py-1 bg-gray-800 rounded text-xs font-mono text-gray-300">
                    {data.http.status} {data.http.statusText}
                  </span>
                )}
                {exposed.length > 0 && (
                  <span className="px-2 py-1 bg-red-500/20 border border-red-500/40 rounded text-xs font-mono text-red-300">
                    {exposed.length} exposed paths
                  </span>
                )}
                {(data?.kitFiles || []).length > 0 && (
                  <span className="px-2 py-1 bg-purple-500/20 border border-purple-500/40 rounded text-xs font-mono text-purple-300">
                    {(data?.kitFiles || []).length} kit files
                  </span>
                )}
                {(data?.exfil || []).length > 0 && (
                  <span className="px-2 py-1 bg-red-500/20 border border-red-500/40 rounded text-xs font-mono text-red-300">
                    {(data?.exfil || []).length} exfil endpoints
                  </span>
                )}
                {virusTotal && (
                  <span className={`px-2 py-1 rounded text-xs font-mono ${
                    virusTotal.verdict === 'MALICIOUS' ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                    : virusTotal.verdict === 'SUSPICIOUS' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                    : virusTotal.verdict === 'CLEAN' ? 'bg-green-500/20 text-green-300 border border-green-500/40'
                    : 'bg-gray-800 text-gray-300 border border-gray-600'
                  }`}>
                    VT: {virusTotal.verdict} ({virusTotal.lastAnalysisStats.malicious}/{virusTotal.totalEngines})
                  </span>
                )}
                <span className="ml-auto text-xs text-yellow-400/80 flex items-center gap-1">
                  <FileSearch className="w-3 h-3" /> path fuzzing + kit fingerprint - real probes
                </span>
              </>
            ) : (
              <span className="ml-auto text-xs text-yellow-400/80 flex items-center gap-1">
                <FileSearch className="w-3 h-3" /> path fuzzing + kit fingerprint - real probes
              </span>
            )}
          </div>
      </div>

      {!data && !loading && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
          <FileSearch className="w-16 h-16 mx-auto mb-4 text-gray-600" />
          <h3 className="text-lg font-semibold mb-2">URL Scanner Ready</h3>
          <p className="text-gray-400 max-w-xl mx-auto">Probe the target for exposed config/backup/panel files, fingerprint downloaded scripts against known phishing-kit families, map exfiltration channels and collect artifacts.</p>
        </div>
      )}

      {data && verdict && style && (
        <>
          {/* ===== Verdict ===== */}
          <div className={`rounded-xl p-5 border ${verdict.level === 'MALICIOUS' ? 'bg-red-500/10 border-red-500/50' : verdict.level === 'SUSPICIOUS' ? 'bg-yellow-500/10 border-yellow-500/50' : 'bg-green-500/10 border-green-500/50'}`}>
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="min-w-0">
                <div className="flex items-center gap-3 flex-wrap">
                  <VerdictIcon className={`w-6 h-6 ${verdict.level === 'MALICIOUS' ? 'text-red-400' : verdict.level === 'SUSPICIOUS' ? 'text-yellow-400' : 'text-green-400'}`} />
                  <h3 className="font-semibold">Scan Verdict</h3>
                  <span className={`px-2.5 py-1 rounded-lg text-xs font-semibold border ${style.badge}`}>{verdict.level}</span>
                  <span className="px-2 py-1 rounded bg-gray-900 text-xs text-gray-400">{verdict.score}/100</span>
                </div>
                <p className="text-sm text-gray-400 mt-1 font-mono break-all">{data.url}</p>
                <p className="text-sm text-gray-300 mt-2">{verdict.verdict}</p>
              </div>
              <button onClick={() => onCopy(data.url)} className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm flex items-center gap-2 shrink-0">
                <Copy className="w-4 h-4" /> Copy URL
              </button>
            </div>
            <div className="mt-4 h-2 rounded-full bg-gray-900 overflow-hidden">
              <div className={`h-full transition-all ${style.bar}`} style={{ width: `${Math.max(verdict.score, 2)}%` }} />
            </div>
            {(verdict.reasons || []).length > 0 && (
              <div className="mt-4">
                <p className="text-xs text-gray-400 mb-2">Detected signals ({(verdict.reasons || []).length})</p>
                <div className="flex flex-wrap gap-2">
                  {(verdict.reasons || []).slice(0, 8).map((r, i) => (
                    <span key={i} className="px-2 py-1 rounded text-xs bg-gray-900 border border-gray-700 text-gray-300">{r}</span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* ===== Quick stats ===== */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: 'HTTP Status', value: data.http ? String(data.http.status) : '—', icon: <Server className="w-4 h-4" /> },
              { label: 'Exposed Paths', value: String(exposed.length), icon: <FolderOpen className="w-4 h-4" /> },
              { label: 'Kit Files', value: String((data?.kitFiles || []).length), icon: <FileCode className="w-4 h-4" /> },
              { label: 'Exfil Endpoints', value: String((data?.exfil || []).length), icon: <Send className="w-4 h-4" /> },
            ].map((s) => (
              <div key={s.label} className="bg-gray-900 border border-gray-800 rounded-xl p-3 flex flex-col gap-1">
                <div className="flex items-center gap-2 text-gray-500 text-xs">{s.icon} {s.label}</div>
                <div className={`text-xl font-bold ${s.label === 'Exposed Paths' && exposed.length > 0 ? 'text-red-400' : ''}`}>{s.value}</div>
              </div>
            ))}
          </div>

          {/* ===== VirusTotal current indicators ===== */}
          {virusTotal && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <div className="flex items-center gap-3 mb-3 flex-wrap">
                <h3 className="font-semibold flex items-center gap-2">
                  <Shield className="w-5 h-5 text-orange-400" /> VirusTotal Indicators
                </h3>
                <span className={`px-2.5 py-1 rounded-lg text-xs font-semibold border ${
                  virusTotal.verdict === 'MALICIOUS' ? 'bg-red-500/20 text-red-400 border-red-500/40'
                  : virusTotal.verdict === 'SUSPICIOUS' ? 'bg-orange-500/20 text-orange-400 border-orange-500/40'
                  : virusTotal.verdict === 'CLEAN' ? 'bg-green-500/20 text-green-400 border-green-500/40'
                  : 'bg-gray-700 text-gray-300 border-gray-600'
                }`}>
                  {virusTotal.verdict}
                </span>
                <a href={virusTotal.url} target="_blank" rel="noreferrer" className="text-xs text-orange-400 hover:text-orange-300 flex items-center gap-1 ml-auto">
                  <ExternalLink className="w-3.5 h-3.5" /> View on VirusTotal
                </a>
              </div>
              <div className="flex flex-wrap items-start gap-4">
                <div className="flex items-center gap-3">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-red-400">{virusTotal.lastAnalysisStats.malicious}</div>
                    <div className="text-[10px] text-gray-500">malicious</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-orange-400">{virusTotal.lastAnalysisStats.suspicious}</div>
                    <div className="text-[10px] text-gray-500">suspicious</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-gray-300">{virusTotal.lastAnalysisStats.harmless}</div>
                    <div className="text-[10px] text-gray-500">harmless</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-gray-500">{virusTotal.totalEngines}</div>
                    <div className="text-[10px] text-gray-500">engines</div>
                  </div>
                </div>
                <div className="flex-1 min-w-[200px]">
                  <div className="h-2 rounded-full bg-gray-800 overflow-hidden flex">
                    {virusTotal.totalEngines > 0 && (
                      <>
                        <div className="h-full bg-red-500" style={{ width: `${(virusTotal.lastAnalysisStats.malicious / virusTotal.totalEngines) * 100}%` }} />
                        <div className="h-full bg-orange-500" style={{ width: `${(virusTotal.lastAnalysisStats.suspicious / virusTotal.totalEngines) * 100}%` }} />
                        <div className="h-full bg-green-500" style={{ width: `${(virusTotal.lastAnalysisStats.harmless / virusTotal.totalEngines) * 100}%` }} />
                      </>
                    )}
                  </div>
                  <div className="mt-2 text-xs text-gray-400 space-y-1">
                    <div><span className="text-gray-500">Detection:</span> {virusTotal.lastAnalysisStats.malicious}/{virusTotal.totalEngines} engines · <span className="text-gray-500">Reputation:</span> {virusTotal.reputation}</div>
                    {virusTotal.lastAnalysisDate && <div><span className="text-gray-500">Last analysis:</span> {new Date(virusTotal.lastAnalysisDate).toISOString().slice(0, 10)}</div>}
                    {virusTotal.votes && <div><span className="text-gray-500">Community votes:</span> {virusTotal.votes.malicious} malicious · {virusTotal.votes.harmless} harmless</div>}
                    {virusTotal.categories && virusTotal.categories.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {virusTotal.categories.slice(0, 5).map((c, i) => (
                          <span key={i} className="px-2 py-0.5 bg-gray-800 rounded text-[10px] font-mono text-gray-400">{c}</span>
                        ))}
                      </div>
                    )}
                    {virusTotal.tags && virusTotal.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {virusTotal.tags.slice(0, 8).map((t, i) => (
                          <span key={i} className="px-1.5 py-0.5 bg-gray-800/60 rounded text-[10px] font-mono text-orange-300/70">#{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ===== Kit fingerprint ===== */}
          <div className={`rounded-xl p-5 border ${data.kit.detected ? 'bg-red-500/10 border-red-500/40' : 'bg-gray-900 border-gray-800'}`}>
            <div className="flex items-center gap-2 mb-3">
              <Bug className={`w-5 h-5 ${data.kit.detected ? 'text-red-400' : 'text-gray-500'}`} />
              <h3 className="font-semibold">Phishing Kit Fingerprint</h3>
              <span className={`ml-auto px-2 py-0.5 rounded text-xs border ${data.kit.detected ? 'bg-red-500/20 text-red-300 border-red-500/40' : 'bg-green-500/20 text-green-300 border-green-500/40'}`}>
                {data.kit.detected ? 'KIT SIGNATURES' : 'NO KIT SIGNATURES'}
              </span>
            </div>
            {data.kit.detected && (
              <div className="space-y-2 mb-4">
                {data.kit.matches.map((m, i) => (
                  <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-red-500/10 border border-red-500/30">
                    <AlertTriangle className="w-4 h-4 mt-0.5 text-red-300 shrink-0" />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-red-200">{m.family}</span>
                        <span className="text-[10px] text-red-400">{Math.round(m.confidence * 100)}% confidence</span>
                      </div>
                      <p className="text-xs text-gray-400 mt-0.5">{m.indicators.join(' · ')}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
            {(data.kitFiles || []).length > 0 ? (
              <div className="space-y-1.5">
                {(data.kitFiles || []).map((f, i) => (
                  <div key={i} className="flex items-center gap-3 p-2 bg-gray-800/40 rounded-lg min-w-0">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] shrink-0 ${KIND_STYLE[f.kind] || KIND_STYLE.other}`}>{f.kind}</span>
                    <span className={`text-xs font-mono shrink-0 ${statusColor(f.status)}`}>{f.status ?? 'ERR'}</span>
                    <span className="text-[10px] text-gray-600 shrink-0">{fmtBytes(f.size)}</span>
                    <span className="text-xs font-mono text-gray-300 truncate flex-1">{f.url}</span>
                    {f.sha256 && (
                      <button onClick={() => onCopy(f.sha256!)} className="text-[10px] font-mono text-purple-400 hover:text-purple-300 shrink-0 hidden md:inline" title="Copy SHA-256">
                        {f.sha256.slice(0, 16)}…
                      </button>
                    )}
                    {f.notable.length > 0 && (
                      <span className="text-[10px] text-red-300 shrink-0 hidden lg:inline" title={f.notable.join('; ')}>
                        {f.notable.length} signal(s)
                      </span>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-gray-500">No referenced scripts downloaded (page has no script resources).</p>
            )}
          </div>

          {/* ===== Fuzzing accordion ===== */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <button onClick={() => toggle('fuzz')} className="w-full flex items-center justify-between px-5 py-3 hover:bg-gray-800/50 transition-colors">
              <span className="flex items-center gap-2 font-semibold">
                {openSection === 'fuzz' ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
                <FolderOpen className="w-5 h-5 text-yellow-400" /> Path Fuzzing
              </span>
              <span className={`text-sm font-mono ${exposed.length > 0 ? 'text-red-400' : 'text-green-400'}`}>{exposed.length} exposed / {(data.fuzz || []).length} probed</span>
            </button>
            {openSection === 'fuzz' && (
              <div className="px-5 pb-4">
                {shownFuzz.length > 0 ? (
                  <div className="space-y-1.5 max-h-96 overflow-y-auto">
                    {shownFuzz.map((f, i) => (
                      <div key={i} className={`flex items-center gap-3 p-2 rounded-lg min-w-0 ${f.status !== null && f.status < 400 && f.status >= 200 ? 'bg-red-500/10 border border-red-500/30' : 'bg-gray-800/40'}`}>
                        <span className={`px-2 py-0.5 rounded text-xs font-mono shrink-0 ${statusColor(f.status)}`}>{f.status ?? 'ERR'}</span>
                        {f.sensitive && <span className="text-[10px] text-red-400 shrink-0">SENSITIVE</span>}
                        <span className="text-xs font-mono text-gray-300 truncate flex-1">{f.path}</span>
                        <span className="text-[10px] text-gray-600 shrink-0 hidden md:inline">{f.note}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-green-400 flex items-center gap-1.5"><ShieldCheck className="w-4 h-4" /> No sensitive paths returned 2xx/3xx — nothing obviously exposed.</p>
                )}
                {(data.fuzz || []).length > 0 && (
                  <div className="mt-3">
                    <button onClick={() => setShowAllFuzz(!showAllFuzz)} className="text-xs text-yellow-400 hover:text-yellow-300">
                      {showAllFuzz ? 'Show only exposed' : `Show all ${(data.fuzz || []).length} probed paths`}
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* ===== Attribution / Exfil ===== */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <Send className="w-5 h-5 text-sky-400" /> Exfiltration Attribution ({data.exfil.length})
            </h3>
            {data.exfil.length > 0 ? (
              <div className="space-y-2">
                {data.exfil.map((e, i) => (
                  <div key={i} className="flex items-start gap-3 p-3 rounded-lg border bg-gray-800/40 border-gray-700">
                    {e.kind === 'telegram' ? <Send className="w-4 h-4 mt-0.5 text-sky-400 shrink-0" /> : e.kind === 'email' ? <Mail className="w-4 h-4 mt-0.5 text-yellow-400 shrink-0" /> : <ExternalLink className="w-4 h-4 mt-0.5 text-red-400 shrink-0" />}
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] uppercase tracking-wide text-gray-500">{e.kind}</span>
                        <button onClick={() => onCopy(e.url)} className="text-xs font-mono text-gray-300 truncate hover:text-lime-400">
                          {e.url}
                        </button>
                      </div>
                      <p className="text-xs text-gray-500 mt-0.5">{e.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-green-400 flex items-center gap-1.5"><ShieldCheck className="w-4 h-4" /> No exfiltration channels found in captured content.</p>
            )}
          </div>

          {/* ===== Content indicators ===== */}
          {data.content && data.content.indicators.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <Bug className="w-5 h-5 text-lime-400" /> Content Indicators ({data.content.indicators.length})
              </h3>
              <div className="flex flex-wrap gap-2">
                {data.content.indicators.map((ind, i) => (
                  <span key={i} className={`px-2 py-1 rounded text-xs border ${ind.severity === 'CRITICAL' || ind.severity === 'HIGH' ? 'bg-red-500/10 text-red-300 border-red-500/30' : ind.severity === 'MEDIUM' ? 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30' : 'bg-gray-800 text-gray-300 border-gray-700'}`}>
                    {ind.label}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* ===== Artifacts ===== */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-semibold flex items-center gap-2">
                <Fingerprint className="w-5 h-5 text-lime-400" /> Artifacts / IoCs ({(data.artifacts || []).length})
              </h3>
              {(data.artifacts || []).length > 12 && (
                <button onClick={() => setShowAllArtifacts(!showAllArtifacts)} className="text-xs text-lime-400 hover:text-lime-300">
                  {showAllArtifacts ? 'Collapse' : `Show all ${data.artifacts.length}`}
                </button>
              )}
            </div>
            {visibleArtifacts.length > 0 ? (
              <div className="space-y-1.5">
                {visibleArtifacts.map((a, i) => {
                  const ArtIcon = ARTIFACT_TYPE[a.type]?.icon || Hash;
                  return (
                    <div key={i} className="flex items-center gap-3 p-2 bg-gray-800/40 rounded-lg min-w-0">
                      <ArtIcon className={`w-4 h-4 shrink-0 ${ARTIFACT_TYPE[a.type]?.color || 'text-gray-500'}`} />
                      <span className={`text-[10px] uppercase shrink-0 ${a.severity === 'CRITICAL' ? 'text-red-400' : a.severity === 'HIGH' ? 'text-orange-400' : a.severity === 'MEDIUM' ? 'text-yellow-400' : 'text-gray-500'}`}>{a.type}</span>
                      <button onClick={() => onCopy(a.value)} className="text-xs font-mono text-gray-300 truncate flex-1 hover:text-lime-400 text-left">{a.value}</button>
                      <span className="text-[10px] text-gray-600 shrink-0 hidden md:inline">{a.source}</span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-xs text-gray-500">No artifacts collected.</p>
            )}
          </div>

          {/* ===== HTTP + TLS accordions ===== */}
          <div className="space-y-3">
            <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              <button onClick={() => toggle('http')} className="w-full flex items-center justify-between px-5 py-3 hover:bg-gray-800/50 transition-colors">
                <span className="flex items-center gap-2 font-semibold">
                  {openSection === 'http' ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
                  <Server className="w-5 h-5 text-cyan-400" /> HTTP Fingerprint
                </span>
                <span className={`text-sm font-mono ${statusColor(data.http?.status ?? null)}`}>{data.http ? `${data.http.status} ${data.http.statusText}` : 'unreachable'}</span>
              </button>
              {openSection === 'http' && data.http && (
                <div className="px-5 pb-4">
                  <div className="flex items-start gap-2 py-1.5 border-b border-gray-800/60 last:border-0"><span className="text-xs text-gray-500 w-28 shrink-0">Final URL</span><span className="text-xs font-mono break-all text-gray-300">{data.http.finalUrl}</span></div>
                  <div className="flex items-start gap-2 py-1.5 border-b border-gray-800/60 last:border-0"><span className="text-xs text-gray-500 w-28 shrink-0">Server</span><span className="text-xs font-mono break-all text-gray-300">{data.http.server || '—'}</span></div>
                  <div className="flex items-start gap-2 py-1.5 border-b border-gray-800/60 last:border-0"><span className="text-xs text-gray-500 w-28 shrink-0">TTFB</span><span className="text-xs font-mono text-gray-300">{data.http.timings ? `${data.http.timings.ttfbMs} ms` : '—'}</span></div>
                  <div className="mt-3">
                    <p className="text-xs text-gray-500 mb-1">Response headers</p>
                    <div className="max-h-48 overflow-y-auto rounded bg-gray-950 border border-gray-800 p-3 space-y-0.5">
                      {Object.entries(data.http.headers).map(([k, v]) => (
                        <div key={k} className="text-xs font-mono"><span className="text-purple-400">{k}:</span> <span className="text-gray-400 break-all">{v}</span></div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              <button onClick={() => toggle('tls')} className="w-full flex items-center justify-between px-5 py-3 hover:bg-gray-800/50 transition-colors">
                <span className="flex items-center gap-2 font-semibold">
                  {openSection === 'tls' ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
                  <Lock className="w-5 h-5 text-purple-400" /> TLS Certificate
                </span>
                {data.tls ? (
                  <span className={`px-2 py-0.5 rounded text-xs ${data.tls.expired ? 'bg-red-500/20 text-red-300' : data.tls.selfSigned || data.tls.hostnameMismatch ? 'bg-yellow-500/20 text-yellow-300' : 'bg-green-500/20 text-green-300'}`}>
                    {data.tls.expired ? 'EXPIRED' : data.tls.selfSigned ? 'SELF-SIGNED' : data.tls.hostnameMismatch ? 'MISMATCH' : 'VALID'}
                  </span>
                ) : <span className="text-xs text-gray-500">no TLS</span>}
              </button>
              {openSection === 'tls' && data.tls && (
                <div className="px-5 pb-4">
                  <div className="flex items-start gap-2 py-1.5 border-b border-gray-800/60 last:border-0"><span className="text-xs text-gray-500 w-28 shrink-0">Subject CN</span><span className="text-xs font-mono break-all text-gray-300">{data.tls.subjectCn || '—'}</span></div>
                  <div className="flex items-start gap-2 py-1.5 border-b border-gray-800/60 last:border-0"><span className="text-xs text-gray-500 w-28 shrink-0">Issuer CN</span><span className="text-xs font-mono break-all text-gray-300">{data.tls.issuerCn || '—'}</span></div>
                  <div className="flex items-start gap-2 py-1.5 border-b border-gray-800/60 last:border-0"><span className="text-xs text-gray-500 w-28 shrink-0">Valid To</span><span className="text-xs font-mono text-gray-300">{data.tls.validTo || '—'}</span></div>
                  <div className="flex items-start gap-2 py-1.5 border-b border-gray-800/60 last:border-0"><span className="text-xs text-gray-500 w-28 shrink-0">Cipher</span><span className="text-xs font-mono text-gray-300">{data.tls.cipher || '—'}</span></div>
                </div>
              )}
            </div>
          </div>

          {/* ===== Static flags ===== */}
          {(data.staticFlags || []).length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <Binary className="w-5 h-5 text-lime-400" /> URL Heuristics
              </h3>
              <div className="flex flex-wrap gap-2">
                {(data.staticFlags || []).map((f, i) => (
                  <span key={i} className={`px-2 py-1 rounded text-xs border ${f.weight >= 3 ? 'bg-red-500/10 text-red-300 border-red-500/30' : 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30'}`}>
                    +{f.weight} · {f.label}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* ===== Screenshot ===== */}
          {data.screenshotUrl && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <Image className="w-5 h-5 text-lime-400" /> Live Screenshot
                <span className="text-xs text-gray-500 font-normal">rendered by WordPress mshots</span>
              </h3>
              <a href={data.screenshotUrl} target="_blank" rel="noopener noreferrer" className="block">
                <img src={data.screenshotUrl} alt={`Screenshot of ${data.host}`} className="w-full rounded-lg border border-gray-800 bg-gray-950" loading="lazy" />
              </a>
            </div>
          )}

          {/* ===== Actions ===== */}
          <div className="flex flex-wrap gap-2">
            <button onClick={() => onCopy(data.url)} className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm flex items-center gap-2"><Copy className="w-4 h-4" /> Copy URL</button>
            <button onClick={() => onCopy(data.http?.finalUrl || data.url)} className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm flex items-center gap-2"><ExternalLink className="w-4 h-4" /> Copy Final URL</button>
            {onReport && (
              <button onClick={onReport} className="px-3 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-lg text-sm flex items-center gap-2"><Printer className="w-4 h-4" /> Informe Imprimible HTML</button>
            )}
            <button onClick={() => onScan()} className="px-3 py-2 bg-yellow-600/20 hover:bg-yellow-600/30 border border-yellow-500/40 rounded-lg text-sm flex items-center gap-2"><RefreshCw className="w-4 h-4" /> Re-scan</button>
          </div>
        </>
      )}
    </div>
  );
}
