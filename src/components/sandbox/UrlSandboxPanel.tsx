'use client';

// URL Sandbox Panel — interactive UI for the real (keyless) sandbox module.
// Renders: verdict, redirect chain, HTTP fingerprint, TLS certificate,
// content indicators (forms/iframes/obfuscation/tokens), resource tree,
// reputation and a live screenshot. Decoupled from page.tsx.

import React, { useState } from 'react';
import {
  Zap, Search, Loader2, Copy, ChevronDown, ChevronRight, Shield, ShieldAlert,
  ShieldCheck, AlertTriangle, CheckCircle, XCircle, Network, Server, Lock,
  Globe, Mail, Fingerprint, MapPin, FileCode, Bug, ArrowRight, ExternalLink,
  Image, RefreshCw, Eye, Printer,
} from 'lucide-react';

interface SandboxData {
  url: string;
  host: string;
  source: string;
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
  reputation: {
    ip: string | null; geo: string | null; asn: string | null; isp: string | null;
    dnsblListed: number; dnsblBlocked: number; torExit: boolean; urlhausCount: number;
    hosting: boolean; proxy: boolean; whoisCreated: string | null;
    domainAgeDays: number | null; domainExpires: string | null;
  };
  staticFlags: { label: string; weight: number; category: string }[];
  verdict: { score: number; level: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS'; verdict: string; reasons: string[] };
  screenshotUrl: string | null;
}

interface Props {
  data: SandboxData | null;
  loading: boolean;
  inputValue: string;
  setInputValue: (v: string) => void;
  onDetonate: (url?: string) => void;
  onCopy: (text: string) => void;
  onReport?: () => void;
}

const LEVEL_STYLES: Record<string, { badge: string; bar: string; icon: any }> = {
  MALICIOUS: { badge: 'bg-red-500/20 text-red-400 border-red-500/40', bar: 'bg-red-500', icon: ShieldAlert },
  SUSPICIOUS: { badge: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40', bar: 'bg-yellow-500', icon: AlertTriangle },
  BENIGN: { badge: 'bg-green-500/20 text-green-400 border-green-500/40', bar: 'bg-green-500', icon: ShieldCheck },
};

const SEV_STYLE: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-300 border-red-500/40',
  HIGH: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
  MEDIUM: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
  LOW: 'bg-gray-800 text-gray-300 border-gray-700',
  INFO: 'bg-gray-800 text-gray-400 border-gray-700',
};

const RES_TYPE_COLORS: Record<string, string> = {
  script: 'bg-purple-500/15 text-purple-300',
  stylesheet: 'bg-blue-500/15 text-blue-300',
  image: 'bg-green-500/15 text-green-300',
  iframe: 'bg-red-500/15 text-red-300',
  font: 'bg-teal-500/15 text-teal-300',
  other: 'bg-gray-800 text-gray-400',
};

function statusColor(status: number | null): string {
  if (status === null) return 'text-red-400';
  if (status >= 400) return 'text-red-400';
  if (status >= 300) return 'text-yellow-400';
  return 'text-green-400';
}

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 10);
}

export default function UrlSandboxPanel({ data, loading, inputValue, setInputValue, onDetonate, onCopy, onReport }: Props) {
  const [openSection, setOpenSection] = useState<string | null>('http');
  const [showAllResources, setShowAllResources] = useState(false);
  const [showAllReasons, setShowAllReasons] = useState(false);
  const [showAllEmails, setShowAllEmails] = useState(false);

  const verdict = data?.verdict;
  const style = verdict ? LEVEL_STYLES[verdict.level] || LEVEL_STYLES.BENIGN : null;
  const VerdictIcon = style?.icon || Shield;

  const visibleResources = showAllResources ? data?.resources || [] : (data?.resources || []).slice(0, 10);

  const toggle = (id: string) => setOpenSection(openSection === id ? null : id);

  const headerRow = (label: string, value: string | null, status?: 'ok' | 'warn' | 'bad') => (
    <div className="flex items-start gap-2 py-1.5 border-b border-gray-800/60 last:border-0">
      <span className="text-xs text-gray-500 w-28 shrink-0">{label}</span>
      <span className={`text-xs font-mono break-all min-w-0 ${status === 'bad' ? 'text-red-400' : status === 'warn' ? 'text-yellow-400' : 'text-gray-300'}`}>{value || '—'}</span>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* ===== Input ===== */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <div className="flex gap-4">
          <div className="flex-1">
            <input
              type="text"
              placeholder="URL to detonate (e.g., http://evil-site.top/verify.php)"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && onDetonate()}
              className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-lime-500 focus:outline-none"
            />
          </div>
          <button
            onClick={() => onDetonate()}
            disabled={loading || !inputValue}
            className="px-6 py-3 bg-lime-600 hover:bg-lime-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
            Detonate
          </button>
        </div>
        <div className="mt-3 flex flex-wrap gap-2 items-center">
            {data ? (
              <>
                <span className="px-2 py-1 bg-gray-800 rounded text-xs font-mono text-gray-300">
                  {verdict ? (
                    <span className={style?.badge || LEVEL_STYLES.BENIGN.badge}>{verdict.level}</span>
                  ) : (
                    'Detonated'
                  )}
                </span>
                {data.http && (
                  <span className="px-2 py-1 bg-gray-800 rounded text-xs font-mono text-gray-300">
                    {data.http.status} {data.http.statusText}
                  </span>
                )}
                {data.redirects && data.redirects.length > 0 && (
                  <span className="px-2 py-1 bg-blue-500/20 border border-blue-500/40 rounded text-xs font-mono text-blue-300">
                    {data.redirects.length} redirect(s)
                  </span>
                )}
                {data.tls && (
                  <span className={`px-2 py-1 rounded text-xs font-mono ${
                    data.tls.expired ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                    : data.tls.selfSigned || data.tls.hostnameMismatch ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40'
                    : 'bg-green-500/20 text-green-300 border border-green-500/40'
                  }`}>
                    TLS: {data.tls.expired ? 'EXPIRED' : data.tls.selfSigned ? 'SELF-SIGNED' : data.tls.hostnameMismatch ? 'MISMATCH' : 'VALID'}
                  </span>
                )}
                {data.content && data.content.forms && data.content.forms.length > 0 && (
                  <span className="px-2 py-1 bg-purple-500/20 border border-purple-500/40 rounded text-xs font-mono text-purple-300">
                    {data.content.forms.length} form(s)
                  </span>
                )}
                {data.content && data.content.iframes && data.content.iframes.length > 0 && (
                  <span className="px-2 py-1 bg-orange-500/20 border border-orange-500/40 rounded text-xs font-mono text-orange-300">
                    {data.content.iframes.length} iframe(s)
                  </span>
                )}
                {data.resources && data.resources.length > 0 && (
                  <span className="px-2 py-1 bg-gray-800 rounded text-xs font-mono text-gray-300">
                    {data.resources.length} resource(s)
                  </span>
                )}
                {data.staticFlags && data.staticFlags.length > 0 && (
                  <span className="px-2 py-1 bg-yellow-500/20 border border-yellow-500/40 rounded text-xs font-mono text-yellow-300">
                    {data.staticFlags.length} heuristic(s)
                  </span>
                )}
                <span className="ml-auto text-xs text-lime-400/80 flex items-center gap-1">
                  <RefreshCw className="w-3 h-3" /> real capture — no API key
                </span>
              </>
            ) : (
              <span className="ml-auto text-xs text-lime-400/80 flex items-center gap-1">
                <RefreshCw className="w-3 h-3" /> real capture — no API key
              </span>
            )}
          </div>
      </div>

      {!data && !loading && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
          <Zap className="w-16 h-16 mx-auto mb-4 text-gray-600" />
          <h3 className="text-lg font-semibold mb-2">URL Sandbox Ready</h3>
          <p className="text-gray-400 max-w-xl mx-auto">Detonate a URL to capture the real redirect chain, HTTP/TLS fingerprint, page content indicators (forms, iframes, obfuscated JS, Telegram tokens), resource tree and IP reputation.</p>
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
                  <h3 className="font-semibold">Sandbox Verdict</h3>
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
            {verdict.reasons.length > 0 && (
              <div className="mt-4">
                <div className="flex items-center justify-between">
                  <p className="text-xs text-gray-400 mb-2">Detected signals ({verdict.reasons.length})</p>
                  {verdict.reasons.length > 5 && (
                    <button onClick={() => setShowAllReasons(!showAllReasons)} className="text-xs text-lime-400 hover:text-lime-300 mb-2">
                      {showAllReasons ? 'Collapse' : 'Show all'}
                    </button>
                  )}
                </div>
                <div className="flex flex-wrap gap-2">
                  {(showAllReasons ? verdict.reasons : verdict.reasons.slice(0, 5)).map((r, i) => (
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
              { label: 'Redirects', value: String(data.redirects.length), icon: <ArrowRight className="w-4 h-4" /> },
              { label: 'Resources', value: String(data.resources.length), icon: <FileCode className="w-4 h-4" /> },
              { label: 'Indicators', value: String(data.content?.indicators?.length || 0), icon: <Bug className="w-4 h-4" /> },
            ].map((s) => (
              <div key={s.label} className="bg-gray-900 border border-gray-800 rounded-xl p-3 flex flex-col gap-1">
                <div className="flex items-center gap-2 text-gray-500 text-xs">{s.icon} {s.label}</div>
                <div className="text-xl font-bold">{s.value}</div>
              </div>
            ))}
          </div>

          {/* ===== Screenshot ===== */}
          {data.screenshotUrl && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <Image className="w-5 h-5 text-lime-400" /> Live Screenshot
                <span className="text-xs text-gray-500 font-normal">rendered by WordPress mshots</span>
              </h3>
              <a href={data.screenshotUrl} target="_blank" rel="noopener noreferrer" className="block">
                <img
                  src={data.screenshotUrl}
                  alt={`Screenshot of ${data.host}`}
                  className="w-full rounded-lg border border-gray-800 bg-gray-950"
                  loading="lazy"
                />
              </a>
            </div>
          )}

          {/* ===== Redirect chain ===== */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <ArrowRight className="w-5 h-5 text-lime-400" /> Redirect Chain
            </h3>
            {data.redirects.length > 0 ? (
              <div className="space-y-2">
                {data.redirects.map((r, i) => (
                  <div key={i} className="flex items-start gap-3">
                    <div className="flex flex-col items-center">
                      <span className={`px-2 py-0.5 rounded text-xs font-mono ${statusColor(r.status)}`}>{r.status ?? 'ERR'}</span>
                      {i < data.redirects.length - 1 && <span className="w-px h-3 bg-gray-700 my-1" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-mono text-gray-300 break-all">{r.url}</div>
                      {i < data.redirects.length - 1 && <div className="text-[10px] text-gray-600">hop {i + 1} → {i + 2}</div>}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-gray-500">No redirects — final URL served directly (status {data.http?.status ?? 'unreachable'}).</p>
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
                  {headerRow('Final URL', data.http.finalUrl)}
                  {headerRow('Protocol', data.http.protocol)}
                  {headerRow('Server', data.http.server)}
                  {headerRow('Content-Type', data.http.contentType)}
                  {headerRow('Content-Encoding', data.http.contentEncoding)}
                  {headerRow('Content-Length', data.http.contentLength !== null ? String(data.http.contentLength) : null)}
                  {headerRow('TTFB', data.http.timings ? `${data.http.timings.ttfbMs} ms` : null)}
                  {headerRow('Total', data.http.timings ? `${data.http.timings.totalMs} ms` : null)}
                  <div className="mt-3">
                    <p className="text-xs text-gray-500 mb-1">Response headers</p>
                    <div className="max-h-48 overflow-y-auto rounded bg-gray-950 border border-gray-800 p-3 space-y-0.5">
                      {Object.entries(data.http.headers).map(([k, v]) => (
                        <div key={k} className="text-xs font-mono">
                          <span className="text-purple-400">{k}:</span> <span className="text-gray-400 break-all">{v}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
              {openSection === 'http' && !data.http && (
                <div className="px-5 pb-4 text-xs text-gray-500">Host unreachable or TLS handshake failed.</div>
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
                ) : (
                  <span className="text-xs text-gray-500">no TLS</span>
                )}
              </button>
              {openSection === 'tls' && data.tls && (
                <div className="px-5 pb-4">
                  {headerRow('Protocol', data.tls.protocol)}
                  {headerRow('Cipher', data.tls.cipher)}
                  {headerRow('Subject CN', data.tls.subjectCn)}
                  {headerRow('Subject Org', data.tls.subjectOrg)}
                  {headerRow('Issuer CN', data.tls.issuerCn, data.tls.selfSigned ? 'warn' : undefined)}
                  {headerRow('Issuer Org', data.tls.issuerOrg)}
                  {headerRow('Valid From', fmtDate(data.tls.validFrom))}
                  {headerRow('Valid To', fmtDate(data.tls.validTo), data.tls.expired ? 'bad' : undefined)}
                  {data.tls.san.length > 0 && (
                    <div className="mt-2">
                      <p className="text-xs text-gray-500 mb-1">SAN ({data.tls.san.length})</p>
                      <div className="flex flex-wrap gap-1">
                        {data.tls.san.slice(0, 20).map((s, i) => (
                          <span key={i} className="px-2 py-0.5 bg-gray-800 rounded text-xs font-mono text-gray-300">{s}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
              {openSection === 'tls' && !data.tls && (
                <div className="px-5 pb-4 text-xs text-gray-500">No TLS certificate captured (non-HTTPS or handshake failed).</div>
              )}
            </div>
          </div>

          {/* ===== Content indicators ===== */}
          {data.content && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <Bug className="w-5 h-5 text-lime-400" /> Content Analysis
                <span className="text-xs text-gray-500 font-normal">{data.content.title ? `"${data.content.title}"` : 'no title'}</span>
              </h3>
              {data.content.indicators.length > 0 ? (
                <div className="space-y-2">
                  {data.content.indicators.map((ind, i) => (
                    <div key={i} className={`flex items-start gap-3 p-3 rounded-lg border ${SEV_STYLE[ind.severity] || SEV_STYLE.LOW}`}>
                      {ind.severity === 'CRITICAL' || ind.severity === 'HIGH' ? <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" /> : ind.severity === 'MEDIUM' ? <ShieldAlert className="w-4 h-4 mt-0.5 shrink-0" /> : <CheckCircle className="w-4 h-4 mt-0.5 shrink-0" />}
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium">{ind.label}</span>
                          <span className="text-[10px] uppercase tracking-wide text-gray-500">{ind.category} · {ind.severity}</span>
                        </div>
                        <p className="text-xs opacity-80 mt-0.5">{ind.detail}</p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-green-400 flex items-center gap-1.5"><ShieldCheck className="w-4 h-4" /> No suspicious content indicators detected.</p>
              )}

              {(data.content.forms.length > 0 || data.content.iframes.length > 0 || data.content.obfuscatedJs || data.content.metaRefresh) && (
                <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                  {data.content.forms.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 mb-1">Forms ({data.content.forms.length})</p>
                      <div className="space-y-1">
                        {data.content.forms.map((f, i) => (
                          <div key={i} className={`flex items-center gap-2 text-xs font-mono p-2 rounded ${f.external ? 'bg-red-500/10 text-red-300' : 'bg-gray-800 text-gray-300'}`}>
                            <span>{f.method}</span>
                            <button onClick={() => onCopy(f.action || '')} className="text-gray-500 hover:text-lime-400 shrink-0"><Copy className="w-3 h-3" /></button>
                            <span className="truncate break-all">{f.action || '(self)'}</span>
                            {f.external && <span className="ml-auto text-[10px] text-red-400 shrink-0">external</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {data.content.iframes.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 mb-1">Iframes ({data.content.iframes.length})</p>
                      <div className="space-y-1 max-h-40 overflow-y-auto">
                        {data.content.iframes.map((ifr, i) => (
                          <div key={i} className="text-xs font-mono text-gray-300 p-2 bg-gray-800 rounded truncate">{ifr.src || '(no src)'}</div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {(data.content.telegramTokens.length > 0 || data.content.telegramChatIds.length > 0) && (
                <div className="mt-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30">
                  <p className="text-xs text-red-300 font-medium mb-1">Telegram attribution found</p>
                  <div className="space-y-1">
                    {data.content.telegramTokens.map((t, i) => (
                      <div key={i} className="text-xs font-mono text-red-300 flex items-center gap-2">
                        <Mail className="w-3 h-3 shrink-0" /> bot:{t.slice(0, 14)}… <button onClick={() => onCopy(t)} className="text-gray-500 hover:text-red-300"><Copy className="w-3 h-3" /></button>
                      </div>
                    ))}
                    {data.content.telegramChatIds.map((c, i) => (
                      <div key={`c${i}`} className="text-xs font-mono text-yellow-300">chat_id: {c}</div>
                    ))}
                  </div>
                </div>
              )}

              {data.content.emails.length > 0 && (
                <div className="mt-4">
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-gray-500 mb-1">Emails found ({data.content.emails.length})</p>
                    {data.content.emails.length > 8 && (
                      <button onClick={() => setShowAllEmails(!showAllEmails)} className="text-xs text-lime-400 hover:text-lime-300 mb-1">
                        {showAllEmails ? 'Collapse' : 'Show all'}
                      </button>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {(showAllEmails ? data.content.emails : data.content.emails.slice(0, 8)).map((e, i) => (
                      <button key={i} onClick={() => onCopy(e)} className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded text-xs font-mono text-gray-300" title="Copy">
                        <Fingerprint className="w-3 h-3 inline mr-1 text-gray-500" />{e}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ===== Resource tree ===== */}
          {data.resources.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-semibold flex items-center gap-2">
                  <Network className="w-5 h-5 text-lime-400" /> Resource Tree ({data.resources.length})
                </h3>
                {data.resources.length > 10 && (
                  <button onClick={() => setShowAllResources(!showAllResources)} className="text-xs text-lime-400 hover:text-lime-300">
                    {showAllResources ? 'Collapse' : `Show all ${data.resources.length}`}
                  </button>
                )}
              </div>
              <div className="space-y-1.5">
                {visibleResources.map((r, i) => (
                  <div key={i} className="flex items-center gap-3 p-2 bg-gray-800/40 rounded-lg min-w-0">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] shrink-0 ${RES_TYPE_COLORS[r.type] || RES_TYPE_COLORS.other}`}>{r.type}</span>
                    <span className={`text-xs font-mono shrink-0 ${statusColor(r.status)}`}>{r.status ?? 'ERR'}</span>
                    <span className="text-xs font-mono text-gray-300 truncate flex-1">{r.url}</span>
                    <span className="text-[10px] text-gray-600 shrink-0 hidden md:inline">{r.host}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ===== Reputation ===== */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <MapPin className="w-5 h-5 text-lime-400" /> Reputation & Infrastructure
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                {headerRow('IP Address', data.reputation.ip)}
                {headerRow('Geo', data.reputation.geo)}
                {headerRow('ASN', data.reputation.asn)}
                {headerRow('ISP', data.reputation.isp)}
                {headerRow('WHOIS Created', fmtDate(data.reputation.whoisCreated))}
                {headerRow('Domain Age', data.reputation.domainAgeDays !== null ? `${data.reputation.domainAgeDays} days` : null)}
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-gray-500 text-xs w-28 shrink-0">DNSBL listings</span>
                  <span className={data.reputation.dnsblListed > 0 ? 'px-2 py-0.5 rounded bg-red-500/20 text-red-300 text-xs font-bold' : 'px-2 py-0.5 rounded bg-green-500/20 text-green-300 text-xs font-bold'}>
                    {data.reputation.dnsblListed} listed
                  </span>
                  {data.reputation.dnsblBlocked > 0 && <span className="px-2 py-0.5 rounded bg-yellow-500/20 text-yellow-300 text-xs">{data.reputation.dnsblBlocked} blocked</span>}
                </div>
                {data.reputation.torExit && (
                  <div className="flex items-center gap-2 text-xs text-red-300 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
                    <Eye className="w-4 h-4 shrink-0" /> Tor exit node
                  </div>
                )}
                {data.reputation.urlhausCount > 0 && (
                  <div className="flex items-center gap-2 text-xs text-red-300 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
                    <Bug className="w-4 h-4 shrink-0" /> {data.reputation.urlhausCount} URLhaus hits
                  </div>
                )}
                {data.reputation.proxy && (
                  <div className="flex items-center gap-2 text-xs text-yellow-300 bg-yellow-500/10 border border-yellow-500/30 rounded-lg px-3 py-2">
                    <Globe className="w-4 h-4 shrink-0" /> Proxy / VPN flagged
                  </div>
                )}
                {data.reputation.hosting && (
                  <div className="flex items-center gap-2 text-xs text-yellow-300 bg-yellow-500/10 border border-yellow-500/30 rounded-lg px-3 py-2">
                    <Server className="w-4 h-4 shrink-0" /> Hosting / data-center range
                  </div>
                )}
                {!data.reputation.torExit && data.reputation.urlhausCount === 0 && !data.reputation.proxy && (
                  <p className="text-xs text-green-400 flex items-center gap-1.5"><ShieldCheck className="w-4 h-4" /> No negative reputation hits.</p>
                )}
              </div>
            </div>
          </div>

          {/* ===== Static flags ===== */}
          {data.staticFlags.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <Fingerprint className="w-5 h-5 text-lime-400" /> URL Heuristics
              </h3>
              <div className="flex flex-wrap gap-2">
                {data.staticFlags.map((f, i) => (
                  <span key={i} className={`px-2 py-1 rounded text-xs border ${f.weight >= 3 ? 'bg-red-500/10 text-red-300 border-red-500/30' : 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30'}`}>
                    +{f.weight} · {f.label}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* ===== Actions ===== */}
          <div className="flex flex-wrap gap-2">
            <button onClick={() => onCopy(data.url)} className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm flex items-center gap-2">
              <Copy className="w-4 h-4" /> Copy URL
            </button>
            <button onClick={() => onCopy(data.http?.finalUrl || data.url)} className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm flex items-center gap-2">
              <ExternalLink className="w-4 h-4" /> Copy Final URL
            </button>
            {data.reputation.ip && (
              <button onClick={() => onCopy(data.reputation.ip!)} className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm flex items-center gap-2">
                <Server className="w-4 h-4" /> Copy IP ({data.reputation.ip})
              </button>
            )}
            {onReport && (
              <button onClick={onReport} className="px-3 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-lg text-sm flex items-center gap-2">
                <Printer className="w-4 h-4" /> Informe Imprimible HTML
              </button>
            )}
            <button onClick={() => onDetonate()} className="px-3 py-2 bg-lime-600/20 hover:bg-lime-600/30 border border-lime-500/40 rounded-lg text-sm flex items-center gap-2">
              <RefreshCw className="w-4 h-4" /> Re-detonate
            </button>
          </div>
        </>
      )}
    </div>
  );
}
