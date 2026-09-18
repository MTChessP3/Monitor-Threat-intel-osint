'use client';

// Domain Intel Panel — interactive UI for the Domain Intel module.
// Renders: risk verdict, email security, DNS records, WHOIS, subdomains,
// IP/ASN infrastructure, MX hosts and an interactive SVG relationship graph.
// Decoupled from page.tsx: receives props, renders its own state.

import React, { useMemo, useState } from 'react';
import {
  Search, Copy, Globe, Server, ShieldAlert, ShieldCheck, Shield, CheckCircle,
  XCircle, AlertTriangle, ChevronDown, ChevronRight, MapPin, Wifi, Database,
  Network, ExternalLink, Flag, Clock, Loader2, Mail, Fingerprint, Eye, ArrowRight,
  Printer,
} from 'lucide-react';

interface DomainIntelResult {
  domain: string;
  timestamp: string;
  source: string;
  live: boolean;
  records: {
    A: any[]; AAAA: any[]; CNAME: any[]; MX: any[]; NS: any[]; TXT: any[]; SOA: any[]; CAA: any[];
  };
  emailSecurity: {
    hasSPF: boolean; spfRaw: string | null; spfMechanisms: string[];
    spfHardFail: boolean; hasDMARC: boolean; dmarcRaw: string | null;
    dmarcPolicy: string | null; hasDKIM: boolean; dkimSelectors: string[];
    riskLevel: string; findings: string[];
  };
  whois: {
    registrar: string | null; created: string | null; updated: string | null;
    expires: string | null; nameservers: string[]; status: string[];
    registrantOrg: string | null; registrantCountry: string | null;
  } | null;
  subdomains: { name: string; ips: string[]; cname: string | null; source: string }[];
  ips: any[];
  mxHosts: { host: string; priority: number; ip: string | null; asn: string | null; asname: string | null }[];
  graph: { nodes: { id: string; label: string; kind: string; meta?: string }[]; edges: { source: string; target: string; label?: string }[] };
  risk: {
    score: number; level: string; verdict: string;
    signals: { label: string; points: number; detail: string; kind: string }[];
    recommendations: string[];
  };
  summary: string;
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
  intel: DomainIntelResult | null;
  virusTotal: VirusTotalResult | null;
  loading: boolean;
  inputValue: string;
  setInputValue: (v: string) => void;
  onAnalyze: (domain?: string) => void;
  onCopy: (text: string) => void;
  onGoForensics: (domain: string) => void;
  onReport?: () => void;
}

const LEVEL_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/40',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
  LOW: 'bg-green-500/20 text-green-400 border-green-500/40',
};

const LEVEL_BAR: Record<string, string> = {
  CRITICAL: 'bg-red-500',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-yellow-500',
  LOW: 'bg-green-500',
};

const NODE_COLORS: Record<string, string> = {
  domain: '#a78bfa',
  subdomain: '#60a5fa',
  ip: '#34d399',
  mx: '#f472b6',
  asn: '#fbbf24',
  ns: '#94a3b8',
};

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 10);
}

function flagEmoji(code?: string): string {
  if (!code || code.length !== 2) return '';
  return code.toUpperCase().replace(/./g, (c) => String.fromCodePoint(127397 + c.charCodeAt(0)));
}

export default function DomainIntelPanel({
  intel, virusTotal, loading, inputValue, setInputValue, onAnalyze, onCopy, onGoForensics, onReport,
}: Props) {
  const [openRecord, setOpenRecord] = useState<string | null>('A');
  const [showAllSubdomains, setShowAllSubdomains] = useState(false);
  const [hoverNode, setHoverNode] = useState<string | null>(null);

  const visibleSubs = showAllSubdomains ? intel?.subdomains || [] : (intel?.subdomains || []).slice(0, 12);

  // ---- radial graph layout: domain center, subdomain/mx ring 1, ip ring 2, asn ring 3 ----
  const layout = useMemo(() => {
    if (!intel) return { nodes: [], edges: [], positions: {} as Record<string, { x: number; y: number }> };
    const R1 = 92, R2 = 178, R3 = 262;
    const cx = 330, cy = 300;
    const positions: Record<string, { x: number; y: number }> = {};
    const groups: Record<string, { id: string; kind: string; label: string; meta?: string }[]> = {
      domain: [], subdomain: [], mx: [], ip: [], asn: [], ns: [],
    };
    intel.graph.nodes.forEach((n) => {
      (groups[n.kind] = groups[n.kind] || []).push(n);
    });
    const place = (items: { id: string }[], r: number) => {
      items.forEach((n, i) => {
        const angle = (i / Math.max(items.length, 1)) * Math.PI * 2 - Math.PI / 2;
        positions[n.id] = { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
      });
    };
    place(groups.domain, 0);
    place([...groups.subdomain, ...groups.mx, ...groups.ns], R1);
    place(groups.ip, R2);
    place(groups.asn, R3);
    return { nodes: intel.graph.nodes, edges: intel.graph.edges, positions };
  }, [intel]);

  const selectedNode = hoverNode
    ? layout.nodes.find((n) => n.id === hoverNode)
    : null;

  const risk = intel?.risk;

  return (
    <div className="space-y-6">
      {/* ===== Input ===== */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <div className="flex gap-4">
          <div className="flex-1">
            <input
              type="text"
              placeholder="Enter domain (e.g., google.com, example.org)"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && onAnalyze()}
              className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-purple-500 focus:outline-none"
            />
          </div>
          <button
              onClick={() => onAnalyze()}
              disabled={loading || !inputValue}
              className="px-6 py-3 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              Analyze Domain
            </button>
          </div>
        </div>

      {!intel && !loading && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
          <Globe className="w-16 h-16 mx-auto mb-4 text-gray-600" />
          <h3 className="text-lg font-semibold mb-2">Domain Intelligence Ready</h3>
          <p className="text-gray-400">Resolve DNS, email security, WHOIS, subdomains and infrastructure — then map the domain relationship graph.</p>
        </div>
      )}

      {intel && risk && (
        <>
          {/* ===== Header + Risk Verdict ===== */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="flex items-center gap-3 flex-wrap">
                  <h3 className="text-lg font-bold font-mono break-all">{intel.domain}</h3>
                  <span className={`px-2.5 py-1 rounded-lg text-xs font-semibold border ${LEVEL_COLORS[risk.level] || LEVEL_COLORS.MEDIUM}`}>
                    {risk.level} RISK
                  </span>
                  <span className="px-2 py-1 rounded bg-gray-800 text-xs text-gray-400">{risk.score}/100</span>
                </div>
                <p className="text-xs text-gray-500 mt-1">{intel.summary}</p>
                <p className="text-sm text-gray-300 mt-2 max-w-2xl">{risk.verdict}</p>
              </div>
              <div className="flex flex-col items-end gap-2">
                <button onClick={() => onCopy(intel.domain)} className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm flex items-center gap-2">
                  <Copy className="w-4 h-4" /> Copy
                </button>
                <button onClick={() => onGoForensics(intel.domain)} className="px-3 py-2 bg-red-600/20 hover:bg-red-600/30 border border-red-500/40 rounded-lg text-sm flex items-center gap-2">
                  <Eye className="w-4 h-4" /> Full Forensics
                </button>
              </div>
            </div>

            {/* Score bar */}
            <div className="mt-4 h-2 rounded-full bg-gray-800 overflow-hidden">
              <div className={`h-full transition-all ${LEVEL_BAR[risk.level]}`} style={{ width: `${risk.score}%` }} />
            </div>

            {/* Signal checks */}
            {risk.signals.length > 0 && (
              <div className="mt-4">
                <p className="text-xs text-gray-400 mb-2">What drives the score</p>
                <div className="flex flex-wrap gap-2">
                  {risk.signals.map((s, i) => (
                    <span
                      key={i}
                      title={s.detail}
                      className={`px-2 py-1 rounded text-xs border ${s.points > 0 ? 'bg-red-500/10 text-red-300 border-red-500/30' : 'bg-green-500/10 text-green-300 border-green-500/30'}`}
                    >
                      {s.points > 0 ? '+' : ''}{s.points} · {s.label}
                    </span>
                  ))}
                </div>
              </div>
            )}
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
                    {virusTotal.lastAnalysisDate && <div><span className="text-gray-500">Last analysis:</span> {fmtDate(virusTotal.lastAnalysisDate)}</div>}
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

          {/* ===== Quick stats ===== */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            {[
              { label: 'A Records', value: intel.records.A.length, icon: <Server className="w-4 h-4" /> },
              { label: 'MX', value: intel.records.MX.length, icon: <Mail className="w-4 h-4" /> },
              { label: 'NS', value: intel.records.NS.length, icon: <Network className="w-4 h-4" /> },
              { label: 'Subdomains', value: intel.subdomains.length, icon: <Globe className="w-4 h-4" /> },
              { label: 'IPs', value: intel.ips.length, icon: <Wifi className="w-4 h-4" /> },
              { label: 'TXT', value: intel.records.TXT.length, icon: <Database className="w-4 h-4" /> },
            ].map((s) => (
              <div key={s.label} className="bg-gray-900 border border-gray-800 rounded-xl p-3 flex flex-col gap-1">
                <div className="flex items-center gap-2 text-gray-500 text-xs">{s.icon} {s.label}</div>
                <div className="text-xl font-bold">{s.value}</div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* ===== Email security ===== */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-purple-400" /> Email Security
                <span className={`ml-auto px-2 py-0.5 rounded text-xs ${LEVEL_COLORS[intel.emailSecurity.riskLevel.toUpperCase()] || LEVEL_COLORS.MEDIUM}`}>
                  {intel.emailSecurity.riskLevel}
                </span>
              </h3>
              {[
                { label: 'SPF', ok: intel.emailSecurity.hasSPF, detail: intel.emailSecurity.spfHardFail ? 'hard fail (-all)' : intel.emailSecurity.spfRaw?.split(/\s+/).slice(0, 4).join(' ') || 'present' },
                { label: 'DMARC', ok: intel.emailSecurity.hasDMARC, detail: intel.emailSecurity.dmarcPolicy ? `policy=${intel.emailSecurity.dmarcPolicy}` : 'not found' },
                { label: 'DKIM', ok: intel.emailSecurity.hasDKIM, detail: intel.emailSecurity.hasDKIM ? `selectors: ${intel.emailSecurity.dkimSelectors.join(', ')}` : 'no common selector' },
              ].map((row) => (
                <div key={row.label} className="flex items-start gap-3 py-2 border-b border-gray-800 last:border-0">
                  {row.ok ? <CheckCircle className="w-4 h-4 mt-0.5 text-green-400" /> : <XCircle className="w-4 h-4 mt-0.5 text-red-400" />}
                  <div className="min-w-0">
                    <div className="text-sm font-medium">{row.label}</div>
                    <div className="text-xs text-gray-500 font-mono break-all">{row.detail}</div>
                  </div>
                </div>
              ))}
              <div className="mt-3 space-y-1">
                {intel.emailSecurity.findings.map((f, i) => (
                  <p key={i} className="text-xs text-gray-400 flex items-start gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" /> {f}
                  </p>
                ))}
              </div>
            </div>

            {/* ===== WHOIS ===== */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <Fingerprint className="w-5 h-5 text-purple-400" /> WHOIS / Registration
              </h3>
              {intel.whois ? (
                <div className="space-y-2">
                  <Row label="Registrar" value={intel.whois.registrar || '—'} />
                  <Row label="Registered" value={`${fmtDate(intel.whois.created)}`} icon={<Clock className="w-3 h-3" />} />
                  <Row label="Updated" value={fmtDate(intel.whois.updated)} />
                  <Row label="Expires" value={fmtDate(intel.whois.expires)} />
                  <Row label="Registrant" value={intel.whois.registrantOrg || '—'} />
                  <Row label="Country" value={intel.whois.registrantCountry || '—'} />
                  {intel.whois.nameservers.length > 0 && (
                    <div className="flex items-start gap-2">
                      <span className="text-xs text-gray-500 w-24 shrink-0">Nameservers</span>
                      <div className="flex flex-wrap gap-1">
                        {intel.whois.nameservers.map((ns, i) => (
                          <span key={i} className="px-2 py-0.5 bg-gray-800 rounded text-xs font-mono text-gray-300">{ns}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-xs text-gray-500">WHOIS data not available for this domain.</p>
              )}
            </div>
          </div>

          {/* ===== Relationship graph ===== */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-semibold flex items-center gap-2">
                <Network className="w-5 h-5 text-purple-400" /> Relationship Graph
              </h3>
              <div className="flex flex-wrap gap-2">
                {Object.entries(NODE_COLORS).map(([k, c]) => (
                  <span key={k} className="text-xs text-gray-500 flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: c }} /> {k}
                  </span>
                ))}
              </div>
            </div>
            <p className="text-xs text-gray-500 mb-2">Domain → subdomains → IPs → MX → ASN. Hover a node for details.</p>
            <svg viewBox="0 0 660 600" className="w-full border border-gray-800 rounded-lg bg-gray-950">
              <defs>
                <marker id="arrow" viewBox="0 0 8 8" refX="8" refY="4" markerWidth="6" markerHeight="6" orient="auto">
                  <path d="M0,0 L8,4 L0,8 z" fill="#374151" />
                </marker>
              </defs>
              {layout.edges.map((e, i) => {
                const s = layout.positions[e.source];
                const t = layout.positions[e.target];
                if (!s || !t) return null;
                return (
                  <line
                    key={i}
                    x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                    stroke={hoverNode === e.source || hoverNode === e.target ? '#8b5cf6' : '#374151'}
                    strokeWidth={hoverNode === e.source || hoverNode === e.target ? 1.5 : 0.75}
                  />
                );
              })}
              {layout.nodes.map((n) => {
                const p = layout.positions[n.id];
                if (!p) return null;
                const isHover = hoverNode === n.id;
                return (
                  <g key={n.id} onMouseEnter={() => setHoverNode(n.id)} onMouseLeave={() => setHoverNode(null)} className="cursor-pointer">
                    <circle
                      cx={p.x} cy={p.y}
                      r={isHover ? 9 : n.kind === 'domain' ? 12 : 7}
                      fill={NODE_COLORS[n.kind] || '#64748b'}
                      opacity={hoverNode && !isHover ? 0.3 : 0.9}
                    />
                    {n.kind === 'domain' && (
                      <circle cx={p.x} cy={p.y} r={17} fill="none" stroke={NODE_COLORS.domain} strokeOpacity="0.4" />
                    )}
                    {isHover && (
                      <text x={p.x} y={p.y - 12} textAnchor="middle" fontSize="10" fill="#e5e7eb" className="select-none">
                        {n.label.length > 28 ? n.label.slice(0, 27) + '…' : n.label}
                      </text>
                    )}
                  </g>
                );
              })}
            </svg>
            {selectedNode && (
              <div className="mt-3 p-3 bg-gray-800/60 rounded-lg border border-gray-700">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ background: NODE_COLORS[selectedNode.kind] }} />
                  <span className="font-mono text-sm">{selectedNode.label}</span>
                  <span className="text-xs text-gray-500">{selectedNode.kind}</span>
                  {selectedNode.meta && <span className="text-xs text-gray-400 ml-auto">{selectedNode.meta}</span>}
                </div>
              </div>
            )}
          </div>

          {/* ===== DNS records ===== */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <Server className="w-5 h-5 text-purple-400" /> DNS Records
            </h3>
            <div className="space-y-2">
              {RECORD_TYPES.map((type) => {
                const recs: any[] = intel.records[type as keyof typeof intel.records] || [];
                const open = openRecord === type;
                return (
                  <div key={type} className="border border-gray-800 rounded-lg overflow-hidden">
                    <button
                      onClick={() => setOpenRecord(open ? null : type)}
                      className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-gray-800/50 transition-colors"
                    >
                      <span className="flex items-center gap-2">
                        {open ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
                        <span className="text-sm font-mono font-semibold">{type}</span>
                        <span className="px-1.5 py-0.5 rounded bg-gray-800 text-xs text-gray-400">{recs.length}</span>
                      </span>
                      <span className="text-xs text-gray-500">{recs.length === 0 ? 'no records' : `${recs[0].ttl}s TTL`}</span>
                    </button>
                    {open && (
                      <div className="px-4 pb-3 space-y-1.5">
                        {recs.length === 0 ? (
                          <p className="text-xs text-gray-500">No {type} records.</p>
                        ) : (
                          recs.map((r, i) => (
                            <div key={i} className="flex items-start gap-2 bg-gray-800/40 rounded p-2">
                              <button onClick={() => onCopy(r.data)} className="text-gray-500 hover:text-purple-400 shrink-0 mt-0.5">
                                <Copy className="w-3.5 h-3.5" />
                              </button>
                              <div className="text-xs font-mono text-gray-300 break-all">
                                {r.priority ? <span className="text-gray-500">prio {r.priority} </span> : null}
                                {r.data}
                              </div>
                            </div>
                          ))
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* ===== Subdomains ===== */}
          {intel.subdomains.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-semibold flex items-center gap-2">
                  <Globe className="w-5 h-5 text-purple-400" /> Subdomains ({intel.subdomains.length})
                  <span className="text-xs text-gray-500 font-normal">crt.sh + brute force</span>
                </h3>
                <button
                  onClick={() => setShowAllSubdomains(!showAllSubdomains)}
                  className="text-xs text-purple-400 hover:text-purple-300 flex items-center gap-1"
                >
                  {showAllSubdomains ? 'Collapse' : `Show all ${intel.subdomains.length}`} <ChevronDown className={`w-3 h-3 transition-transform ${showAllSubdomains ? 'rotate-180' : ''}`} />
                </button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {visibleSubs.map((s, i) => (
                  <div key={i} className="flex items-center gap-2 bg-gray-800/40 rounded-lg px-3 py-2 min-w-0">
                    <div className="min-w-0 flex-1">
                      <div className="text-xs font-mono text-gray-200 truncate">{s.name}</div>
                      <div className="text-[10px] text-gray-500 truncate">
                        {s.ips.length > 0 ? `→ ${s.ips.join(', ')}` : s.cname ? `CNAME ${s.cname}` : 'no A record'}
                      </div>
                    </div>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] ${s.source === 'ct' ? 'bg-blue-500/10 text-blue-400' : 'bg-teal-500/10 text-teal-400'}`}>
                      {s.source === 'ct' ? 'CT' : 'brute'}
                    </span>
                    <button onClick={() => onCopy(s.name)} className="text-gray-500 hover:text-purple-400 shrink-0">
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ===== IP / ASN infrastructure ===== */}
          {intel.ips.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <MapPin className="w-5 h-5 text-purple-400" /> IP & ASN Infrastructure
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs text-gray-500 border-b border-gray-800">
                      <th className="py-2 pr-3">IP</th>
                      <th className="py-2 pr-3">Reverse DNS</th>
                      <th className="py-2 pr-3">Geo</th>
                      <th className="py-2 pr-3">ASN</th>
                      <th className="py-2 pr-3">ISP</th>
                      <th className="py-2 pr-3">Flags</th>
                    </tr>
                  </thead>
                  <tbody>
                    {intel.ips.slice(0, 15).map((ip, i) => (
                      <tr key={i} className="border-b border-gray-800/50 last:border-0">
                        <td className="py-2 pr-3 font-mono text-xs text-purple-300">{ip.ip}</td>
                        <td className="py-2 pr-3 font-mono text-xs text-gray-400 truncate max-w-[160px]">{ip.reverse || '—'}</td>
                        <td className="py-2 pr-3 text-xs text-gray-300">
                          {flagEmoji(ip.countryCode)} {ip.country} {ip.city ? `· ${ip.city}` : ''}
                        </td>
                        <td className="py-2 pr-3 text-xs text-gray-300">
                          {ip.asn ? <span className="font-mono">{ip.asn}</span> : '—'}
                          {ip.asname && <span className="text-gray-500"> {ip.asname}</span>}
                        </td>
                        <td className="py-2 pr-3 text-xs text-gray-400 truncate max-w-[160px]">{ip.isp}</td>
                        <td className="py-2 pr-3 text-xs">
                          <div className="flex gap-1">
                            {ip.hosting && <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400">hosting</span>}
                            {ip.proxy && <span className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">proxy</span>}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ===== Recommendations ===== */}
          {risk.recommendations.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <Shield className="w-5 h-5 text-purple-400" /> Recommendations
              </h3>
              <div className="space-y-1.5">
                {risk.recommendations.map((r, i) => (
                  <p key={i} className="text-sm text-gray-300 flex items-start gap-2">
                    <ArrowRight className="w-4 h-4 text-purple-400 mt-0.5 shrink-0" /> {r}
                  </p>
                ))}
              </div>
            </div>
          )}
           {/* ===== Actions ===== */}
           <div className="flex flex-wrap gap-2">
             <button onClick={() => onCopy(intel.domain)} className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm flex items-center gap-2">
               <Copy className="w-4 h-4" /> Copy Domain
             </button>
             {onReport && (
               <button onClick={onReport} className="px-3 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-lg text-sm flex items-center gap-2">
                 <Printer className="w-4 h-4" /> Informe Imprimible HTML
               </button>
             )}
             <button onClick={() => onGoForensics(intel.domain)} className="px-3 py-2 bg-red-600/20 hover:bg-red-600/30 border border-red-500/40 rounded-lg text-sm flex items-center gap-2">
               <Eye className="w-4 h-4" /> Full Forensics
             </button>
           </div>
         </>
       )}
     </div>
   );
 }

function Row({ label, value, icon }: { label: string; value: string; icon?: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2">
      <span className="text-xs text-gray-500 w-24 shrink-0 flex items-center gap-1">{icon} {label}</span>
      <span className="text-xs text-gray-300 font-mono break-all">{value}</span>
    </div>
  );
}
