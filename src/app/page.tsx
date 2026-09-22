'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import DomainIntelPanel from '@/components/domain/DomainIntelPanel';
import UrlSandboxPanel from '@/components/sandbox/UrlSandboxPanel';
import UrlScannerPanel from '@/components/url/UrlScannerPanel';
import TakeDownPanel from '@/components/takedown/TakeDownPanel';
import ModuleErrorBoundary from '@/components/ModuleErrorBoundary';

import { analyzeApkBytes } from '@/lib/intel/fakeapp';
import {
  Search, Globe, Shield, Bug, FileText, Download, Upload, 
  Trash2, Edit3, Plus, Eye, AlertTriangle, CheckCircle, XCircle,
  Activity, Database, Cpu, Lock, Unlock, RefreshCw, ExternalLink,
  Copy, Filter, ChevronDown, ChevronRight, Zap, Target, Radar,
  Fingerprint, Mail, Hash, Server, Clock, MapPin, Wifi,
  BarChart3, PieChart as PieChartIcon, TrendingUp, Users, Key, Terminal,
  Save, X, Loader2, Check, Info, AlertCircle, ArrowRight, Ban, WifiOff,
  Play, Pause, Camera, FileSearch, Smartphone, Globe2, Skull, EyeOff,
  FolderOpen, DownloadCloud, UploadCloud, FileCode, LockOpen, ShieldAlert,
  Network, MessageSquare, ShieldUser, Radio, Presentation, Printer,
  Send, Layers, Image
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
  LineChart, Line
} from 'recharts';

// ==================== TYPES ====================
type TabType = 'dashboard' | 'ip' | 'domain' | 'url' | 'hash' | 'cve' | 'ai' | 'darkweb' | 'threats' | 'mobile' | 'forensics' | 'iocs' | 'export' | 'reports' | 'sources' | 'brand' | 'sandbox' | 'dnsdump' | 'social' | 'exec' | 'fakeapp' | 'takedown' | 'edp';
type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
type IOCStatus = 'UNKNOWN' | 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';

interface IOC {
  id: string;
  type: string;
  value: string;
  description: string;
  severity: Severity;
  confidence: number;
  status: IOCStatus;
  source: string;
  tags: string[];
  firstSeen: string;
  lastUpdated: string;
}

interface TimelineEvent {
  time: string;
  event: string;
  type: 'threat' | 'ioc' | 'analysis' | 'system' | 'alert';
  severity?: Severity;
}

interface IpQueueEntry {
  id: string;
  ip: string;
  addedAt: string;
  riskScore: number;
  severity: Severity;
  threatLevel: string;
  blacklistCount: number;
  blockedCount: number;
  blacklistNames: string[];
  torExit: boolean;
  urlhausCount: number;
  category: string;
  abuseScore: number;
  asn: string;
  isp: string;
  country: string;
  flag: string;
  lastSeen: string | null;
  openPorts: string[];
  malware: string | null;
  tags: string[];
  description: string;
}

interface APIResponse {
  success: boolean;
  source?: string;
  timestamp?: string;
  fetchedLive?: boolean;
  data?: any;
  error?: string;
  details?: string;
  message?: string;
  [key: string]: any;
}

// ==================== CONSTANTS ====================
const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  INFO: '#3b82f6'
};

const STATUS_COLORS: Record<IOCStatus, string> = {
  UNKNOWN: '#6b7280',
  BENIGN: '#22c55e',
  SUSPICIOUS: '#f97316',
  MALICIOUS: '#dc2626'
};

const CHART_COLORS = ['#dc2626', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#8b5cf6', '#ec4899'];

// ==================== IP QUEUE HELPERS ====================
const QUEUE_MAX = 20;

function getFlagEmoji(code?: string): string {
  if (!code || code.length !== 2) return '';
  return code.toUpperCase().replace(/./g, (c) => String.fromCodePoint(127397 + c.charCodeAt(0)));
}

function timeAgo(iso: string): string {
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs} h ago`;
  return `${Math.floor(hrs / 24)} d ago`;
}

function computeAbuseScore(apiData: any): number {
  let score = 0;
  const dnsbl = (apiData?.reputation?.dnsbl || []).filter((d: any) => d.listed);
  score += Math.min(dnsbl.length * 12, 60);
  if (apiData?.reputation?.torExit) score += 25;
  if ((apiData?.reputation?.urlhaus?.urlCount || 0) > 0) score += 15;
  if (apiData?.data?.proxy) score += 10;
  if (apiData?.data?.hosting) score += 5;
  const open = (apiData?.scan?.ports || []).filter((p: any) => p.state === 'open');
  if (open.length > 0) score += Math.min(open.length * 3, 15);
  return Math.min(score, 100);
}

function riskSeverityFrom(apiData: any): Severity {
  const score = computeAbuseScore(apiData);
  const dnsbl = (apiData?.reputation?.dnsbl || []).filter((d: any) => d.listed).length;
  const urlCount = apiData?.reputation?.urlhaus?.urlCount || 0;
  if (score >= 75 || dnsbl >= 5 || urlCount >= 5) return 'CRITICAL';
  if (score >= 50 || dnsbl >= 2 || apiData?.reputation?.torExit) return 'HIGH';
  if (score >= 25 || dnsbl >= 1 || apiData?.data?.proxy || urlCount > 0) return 'MEDIUM';
  return 'LOW';
}

function networkCategory(apiData: any): string {
  if (apiData?.data?.proxy) return 'Proxy / VPN';
  if (apiData?.data?.hosting) return 'Hosting / Cloud';
  if (apiData?.data?.mobile) return 'Mobile Network';
  return 'Residential / Business';
}

function threatBadgeClass(apiData: any): string {
  switch (riskSeverityFrom(apiData)) {
    case 'CRITICAL': return 'bg-red-600/30 text-red-300 border-red-500/60';
    case 'HIGH': return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
    case 'MEDIUM': return 'bg-yellow-500/15 text-yellow-300 border-yellow-500/40';
    default: return 'bg-green-500/15 text-green-300 border-green-500/40';
  }
}

function abuseScoreColor(score: number): string {
  if (score >= 75) return '#dc2626';
  if (score >= 50) return '#f97316';
  if (score >= 25) return '#eab308';
  return '#22c55e';
}

interface AbuseFactor {
  key: string;
  label: string;
  points: number;
  detail: string;
  section: string | null;
}

function computeAbuseBreakdown(apiData: any): AbuseFactor[] {
  const factors: AbuseFactor[] = [];
  const listed = (apiData?.reputation?.dnsbl || []).filter((d: any) => d.listed);
  if (listed.length > 0) {
    factors.push({ key: 'dnsbl', label: 'DNS Blacklists', points: Math.min(listed.length * 12, 60), detail: `${listed.length} list(s): ${listed.map((d: any) => d.name).join(', ')}`, section: 'ip-reputation' });
  }
  if (apiData?.reputation?.torExit) {
    factors.push({ key: 'tor', label: 'Tor exit node', points: 25, detail: 'Known anonymization — traffic origin masked.', section: 'ip-reputation' });
  }
  const urlCount = apiData?.reputation?.urlhaus?.urlCount || 0;
  if (urlCount > 0) {
    factors.push({ key: 'urlhaus', label: 'Malicious URLs (URLhaus)', points: 15, detail: `${urlCount} malicious URL(s) associated with this IP.`, section: 'ip-reputation' });
  }
  const open = (apiData?.scan?.ports || []).filter((p: any) => p.state === 'open');
  if (open.length > 0) {
    factors.push({ key: 'ports', label: 'Exposed services', points: Math.min(open.length * 3, 15), detail: `Open ports: ${open.map((p: any) => `${p.port} ${p.service}`).join(', ')}`, section: 'ip-scan' });
  }
  if (apiData?.data?.proxy) {
    factors.push({ key: 'proxy', label: 'Proxy / VPN', points: 10, detail: 'Tunneled traffic — hides the true origin.', section: null });
  }
  if (apiData?.data?.hosting) {
    factors.push({ key: 'hosting', label: 'Hosting / Cloud', points: 5, detail: 'Datacenter range — common for C2 and bulk attacks.', section: null });
  }
  return factors;
}

function riskVerdict(sev: Severity): string {
  switch (sev) {
    case 'CRITICAL': return 'Critical — multiple independent sources flag this IP; treat it as actively hostile.';
    case 'HIGH': return 'High — confirmed blacklists and/or anonymization; block at the perimeter.';
    case 'MEDIUM': return 'Medium — some indicators present; verify before taking action.';
    default: return 'Low — no significant threat signals detected.';
  }
}

function buildQueueEntry(apiData: any): IpQueueEntry {
  const ip = apiData?.data?.query || apiData?.data?.ip || '';
  const listed = (apiData?.reputation?.dnsbl || []).filter((d: any) => d.listed);
  const blocked = (apiData?.reputation?.dnsbl || []).filter((d: any) => d.blocked);
  const urlCount = apiData?.reputation?.urlhaus?.urlCount || 0;
  const threats = (apiData?.reputation?.urlhaus?.urls || []).map((u: any) => u.threat).filter(Boolean);
  const lastDate = (apiData?.reputation?.urlhaus?.urls || []).map((u: any) => u.dateAdded).filter(Boolean).sort().slice(-1)[0];
  const open = (apiData?.scan?.ports || []).filter((p: any) => p.state === 'open');
  const abuseScore = computeAbuseScore(apiData);
  const malware = threats.length > 0
    ? [...new Set(threats)].slice(0, 2).join(', ')
    : apiData?.reputation?.torExit
      ? 'Tor exit (anonymization)'
      : null;
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    ip,
    addedAt: new Date().toISOString(),
    riskScore: abuseScore,
    severity: riskSeverityFrom(apiData),
    threatLevel: apiData?.analysis?.threatLevel || 'NORMAL',
    blacklistCount: listed.length,
    blockedCount: blocked.length,
    blacklistNames: listed.map((d: any) => d.name),
    torExit: !!apiData?.reputation?.torExit,
    urlhausCount: urlCount,
    category: networkCategory(apiData),
    abuseScore,
    asn: `${apiData?.data?.as || 'AS?'}${apiData?.data?.asname ? ` (${apiData.data.asname})` : ''}`,
    isp: apiData?.data?.isp || apiData?.data?.org || 'N/A',
    country: `${apiData?.data?.country || 'N/A'}${apiData?.data?.city ? ` (${apiData.data.city})` : ''}`,
    flag: getFlagEmoji(apiData?.data?.countryCode),
    lastSeen: lastDate || null,
    openPorts: open.map((p: any) => `${p.port} ${p.service}`),
    malware,
    tags: [
      ...listed.map((d: any) => `dnsbl:${d.name.toLowerCase()}`),
      ...(apiData?.reputation?.torExit ? ['tor-exit'] : []),
      ...(urlCount > 0 ? [`urlhaus:${urlCount}`] : []),
    ],
    description: `IP ${ip} — DNSBL: ${listed.map((d: any) => `${d.name}(${d.records.join(',')})`).join(', ') || 'clean'}${apiData?.reputation?.torExit ? ', Tor exit' : ''}${urlCount > 0 ? `, URLhaus: ${urlCount}` : ''}`,
  };
}

// ==================== PRINT REPORT UTILITY ====================
function generatePrintableReport(tab: TabType, data: any, inputValue: string): string {
  const timestamp = new Date().toLocaleString('es-ES', { 
    dateStyle: 'full', 
    timeStyle: 'short' 
  });
  const tabLabels: Record<TabType, string> = {
    dashboard: 'Dashboard', ip: 'IP Intel', domain: 'Domain Intel', forensics: 'Web Forensics',
    dnsdump: 'DNS Dump', url: 'URL Scanner', hash: 'Hash Lookup', cve: 'CVE Database',
    ai: 'AI Analyst', darkweb: 'Deep & Dark Web', mobile: 'Mobile Security',
    threats: 'Threat Feeds', iocs: 'IOC Manager', export: 'Export Data', reports: 'Reports',
    sources: 'Intelligence Sources', brand: 'Brand Protection', sandbox: 'URL Sandbox',
    dnsdump: 'DNS Dump', social: 'Telegram & Discord', exec: 'Executive OSINT',
    'exec-protection': 'Executive Protection',
    fakeapp: 'Fake App Scanner', takedown: 'TakeDown URL', url: 'URL Scanner', sandbox: 'URL Sandbox',
  };

  const tabLabel = tabLabels[tab] || tab;
  const reportData = JSON.stringify(data, null, 2).slice(0, 50000);
  const inputDisplay = inputValue || 'N/A';

  // Helper function for Domain Intel report
  const generateDomainIntelReport = (data: any, intel: any, risk: any, virusTotal: any) => {
    if (!intel) return '';
    
    const formatDate = (iso: string | null) => {
      if (!iso) return '—';
      const d = new Date(iso);
      return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 10);
    };

    const getRiskClass = (level: string) => {
      switch (level.toUpperCase()) {
        case 'CRITICAL': return 'badge-critical';
        case 'HIGH': return 'badge-elevated';
        default: return 'badge-normal';
      }
    };

    const escapeHtml = (text: string) => text
      .replace(/&/g, '&')
      .replace(/</g, '<')
      .replace(/>/g, '>')
      .replace(/"/g, '"')
      .replace(/'/g, '&#039;');

    // Build DNS Records section
    const buildDnsRecords = (records: any) => {
      if (!records) return '<p class="data-value">No data</p>';
      const types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];
      return types.map(type => {
        const recs = records[type as keyof typeof records] || [];
        if (recs.length === 0) return '';
        return `
          <div class="data-card">
            <div class="data-label">${type} Records (${recs.length})</div>
            <div class="data-value">${recs.slice(0, 5).map(r => escapeHtml(r.data || r.value || '')).join('<br>')}${recs.length > 5 ? `<br>... and ${recs.length - 5} more` : ''}</div>
          </div>
        `;
      }).join('');
    };

    // Build subdomains section
    const buildSubdomains = (subs: any[]) => {
      if (!subs || subs.length === 0) return '<p class="data-value">No subdomains found</p>';
      return subs.slice(0, 20).map(s => `
        <div class="data-card">
          <div class="data-label">${escapeHtml(s.name)}</div>
          <div class="data-value">${s.ips.length > 0 ? s.ips.join(', ') : (s.cname ? `CNAME: ${s.cname}` : 'No A record')}</div>
          <div class="data-label">Source: ${s.source === 'ct' ? 'Certificate Transparency' : 'Brute Force'}</div>
        </div>
      `).join('');
    };

    // Build IP/ASN infrastructure
    const buildIpAsn = (ips: any[]) => {
      if (!ips || ips.length === 0) return '<p class="data-value">No IP data</p>';
      return ips.slice(0, 15).map(ip => `
        <div class="data-card">
          <div class="data-label">${ip.ip}</div>
          <div class="data-value">Geo: ${ip.country} ${ip.city ? `(${ip.city})` : ''} ${ip.flag || ''}</div>
          <div class="data-label">ASN: ${ip.asn || '—'}</div>
          <div class="data-value">${ip.asname || ''}</div>
          <div class="data-label">ISP: ${ip.isp}</div>
          <div class="data-label">Flags: ${ip.hosting ? 'hosting ' : ''}${ip.proxy ? 'proxy ' : ''}${ip.tor ? 'tor ' : ''}</div>
        </div>
      `).join('');
    };

    // Build email security
    const buildEmailSecurity = (es: any) => {
      if (!es) return '<p class="data-value">No data</p>';
      return `
        <div class="data-grid">
          <div class="data-card">
            <div class="data-label">SPF</div>
            <div class="data-value">${es.hasSPF ? '✓ Present' : '✗ Missing'} ${es.spfHardFail ? ' (hard fail -all)' : ''}</div>
          </div>
          <div class="data-card">
            <div class="data-label">DMARC</div>
            <div class="data-value">${es.hasDMARC ? '✓ Present' : '✗ Missing'} ${es.dmarcPolicy ? ` (policy: ${es.dmarcPolicy})` : ''}</div>
          </div>
          <div class="data-card">
            <div class="data-label">DKIM</div>
            <div class="data-value">${es.hasDKIM ? '✓ Present' : '✗ Missing'} ${es.dkimSelectors?.join(', ') || ''}</div>
          </div>
          <div class="data-card">
            <div class="data-label">Risk Level</div>
            <div class="data-value">${es.riskLevel}</div>
          </div>
        </div>
        ${es.findings?.length > 0 ? `
          <div class="section">
            <div class="section-title">⚠️ Findings</div>
            <ul>${es.findings.map(f => `<li>${escapeHtml(f)}</li>`).join('')}</ul>
          </div>
        ` : ''}
      `;
    };

    // Build WHOIS
    const buildWhois = (whois: any) => {
      if (!whois) return '<p class="data-value">WHOIS data not available</p>';
      return `
        <div class="data-grid">
          <div class="data-card"><div class="data-label">Registrar</div><div class="data-value">${escapeHtml(whois.registrar || '—')}</div></div>
          <div class="data-card"><div class="data-label">Created</div><div class="data-value">${formatDate(whois.created)}</div></div>
          <div class="data-card"><div class="data-label">Updated</div><div class="data-value">${formatDate(whois.updated)}</div></div>
          <div class="data-card"><div class="data-label">Expires</div><div class="data-value">${formatDate(whois.expires)}</div></div>
          <div class="data-card"><div class="data-label">Registrant Org</div><div class="data-value">${escapeHtml(whois.registrantOrg || '—')}</div></div>
          <div class="data-card"><div class="data-label">Country</div><div class="data-value">${escapeHtml(whois.registrantCountry || '—')}</div></div>
        </div>
        ${whois.nameservers?.length > 0 ? `
          <div class="section">
            <div class="section-title">📡 Nameservers</div>
            <div class="data-grid">
              ${whois.nameservers.map(ns => `<div class="data-card"><div class="data-value">${escapeHtml(ns)}</div></div>`).join('')}
            </div>
          </div>
        ` : ''}
      `;
    };

    // Build VirusTotal section for IP Intel
    const buildVT = (vt: any) => {
      if (!vt || !vt.analyzed) return '';
      const stats = vt.lastAnalysisStats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 };
      const total = vt.totalEngines || Object.values(stats).reduce((a: number, b: number) => a + b, 0);
      return `
        <div class="section">
          <div class="section-title">🛡️ VirusTotal Analysis</div>
          <div class="data-grid">
            <div class="data-card"><div class="data-label">Verdict</div><div class="data-value"><span class="badge ${getVerdictClass(vt.verdict)}">${vt.verdict}</span></div></div>
            <div class="data-card"><div class="data-label">Detection</div><div class="data-value">${stats.malicious}/${total} engines</div></div>
            <div class="data-card"><div class="data-label">Reputation</div><div class="data-value">${vt.reputation}</div></div>
            <div class="data-card"><div class="data-label">Last Analysis</div><div class="data-value">${vt.lastAnalysisDate ? formatDate(vt.lastAnalysisDate) : 'N/A'}</div></div>
          </div>
          <div class="section">
            <div class="section-title">📊 Detection Breakdown</div>
            <div class="data-grid">
              <div class="data-card"><div class="data-label">Malicious</div><div class="data-value">${stats.malicious || 0}</div></div>
              <div class="data-card"><div class="data-label">Suspicious</div><div class="data-value">${stats.suspicious || 0}</div></div>
              <div class="data-card"><div class="data-label">Undetected</div><div class="data-value">${stats.undetected || 0}</div></div>
              <div class="data-card"><div class="data-label">Harmless</div><div class="data-value">${stats.harmless || 0}</div></div>
              <div class="data-card"><div class="data-label">Timeout</div><div class="data-value">${stats.timeout || 0}</div></div>
              <div class="data-card"><div class="data-label">Total Engines</div><div class="data-value">${total}</div></div>
            </div>
          </div>
          <div class="section">
            <div class="section-title">📋 Additional Info</div>
            <div class="data-grid">
              <div class="data-card"><div class="data-label">ASN</div><div class="data-value">${vt.asn || 'N/A'}</div></div>
              <div class="data-card"><div class="data-label">Country</div><div class="data-value">${vt.country || 'N/A'}</div></div>
              <div class="data-card"><div class="data-label">First Seen</div><div class="data-value">${vt.firstSeen ? formatDate(vt.firstSeen) : 'N/A'}</div></div>
              <div class="data-card"><div class="data-label">Last Seen</div><div class="data-value">${vt.lastSeen ? formatDate(vt.lastSeen) : 'N/A'}</div></div>
            </div>
          </div>
          <div class="section">
            <div class="section-title">🔗 VirusTotal Link</div>
            <div class="data-grid">
              <div class="data-card"><div class="data-value"><a href="${vt.url}" target="_blank" style="color: #059669;">View on VirusTotal</a></div></div>
            </div>
          </div>
        `;
    };

    // Build Relationship Graph explanation
    const buildGraphExplanation = (graph: any) => {
      if (!graph || !graph.nodes || graph.nodes.length === 0) {
        return '<p class="data-value">No relationship graph data available</p>';
      }
      const nodeTypes: Record<string, number> = {};
      graph.nodes.forEach((n: any) => {
        nodeTypes[n.kind] = (nodeTypes[n.kind] || 0) + 1;
      });
      const edgeCount = graph.edges?.length || 0;
      
      return `
        <div class="section">
          <div class="section-title">🕸️ Relationship Graph — Topology Analysis</div>
          <div class="section">
            <h4>Graph Overview</h4>
            <p>The relationship graph maps the domain's infrastructure topology using a radial layout:</p>
            <ul>
              <li><strong>Center (Ring 0):</strong> Primary domain (${escapeHtml(inputDisplay)})</li>
              <li><strong>Ring 1 (92px):</strong> Subdomains, MX hosts, Nameservers</li>
              <li><strong>Ring 2 (178px):</strong> Resolved IP addresses</li>
              <li><strong>Ring 3 (262px):</strong> ASN/ISP organizations</li>
            </ul>
            <h4>Graph Statistics</h4>
            <div class="data-grid">
              <div class="data-card"><div class="data-label">Total Nodes</div><div class="data-value">${graph.nodes.length}</div></div>
              <div class="data-card"><div class="data-label">Total Edges</div><div class="data-value">${edgeCount}</div></div>
              <div class="data-card"><div class="data-label">Node Types</div><div class="data-value">${Object.entries(nodeTypes).map(([k, v]) => `${k}: ${v}`).join(', ')}</div></div>
            </div>
            <h4>Graph Legend</h4>
            <ul>
              <li>🟣 <strong>Purple (Domain):</strong> Primary domain being analyzed</li>
              <li>🔵 <strong>Blue (Subdomain):</strong> Discovered subdomains</li>
              <li>🟢 <strong>Green (IP):</strong> Resolved IP addresses</li>
              <li>🩷 <strong>Pink (MX):</strong> Mail exchange hosts</li>
              <li>🟡 <strong>Yellow (ASN):</strong> Autonomous System Numbers / ISPs</li>
              <li>🔘 <strong>Gray (NS):</strong> Authoritative nameservers</li>
            </ul>
            <h4>Graph Interpretation Guide</h4>
            <ul>
              <li><strong>Hubs (high-degree nodes):</strong> Nodes with many connections often indicate shared infrastructure (e.g., shared hosting, CDN, mail provider)</li>
              <li><strong>Star topology:</strong> Single IP serving many subdomains → shared hosting / CDN</li>
              <li><strong>Multiple ASNs:</strong> Infrastructure spans multiple providers (cloud, CDN, corporate)</li>
              <li><strong>Orphaned nodes:</strong> Subdomains without resolution may indicate dangling records</li>
              <li><strong>MX → IP chains:</strong> Trace mail flow; multiple MX pointing to same IP = single mail server</li>
            </ul>
          </div>
        `;
    };

    // Build recommendations
    const buildRecommendations = (recs: string[]) => {
      if (!recs || recs.length === 0) return '<p class="data-value">No specific recommendations</p>';
      return `
        <div class="section">
          <div class="section-title">🛡️ Recommendations</div>
          <ol>${recs.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ol>
        </div>
      `;
    };

    // Main Domain Intel Report
    return `
      <div class="section">
        <div class="section-title">🌐 Domain Intelligence Report</div>
        <div class="data-grid">
          <div class="data-card"><div class="data-label">Domain</div><div class="data-value">${escapeHtml(intel.domain)}</div></div>
          <div class="data-card"><div class="data-label">Analysis Date</div><div class="data-value">${formatDate(intel.timestamp)}</div></div>
          <div class="data-card"><div class="data-label">Source</div><div class="data-value">${intel.source}</div></div>
          <div class="data-card"><div class="data-label">Live</div><div class="data-value">${intel.live ? 'Yes' : 'No'}</div></div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">⚠️ Risk Assessment</div>
        <div class="data-grid">
          <div class="data-card"><div class="data-label">Risk Score</div><div class="data-value">${risk?.score || 0}/100</div></div>
          <div class="data-card"><div class="data-label">Risk Level</div><div class="data-value"><span class="badge ${getRiskClass(risk?.level || 'LOW')}">${risk?.level || 'LOW'}</div></div></div>
        </div>
        <div class="section">
          <h4>Verdict</h4>
          <p>${escapeHtml(risk?.verdict || 'No verdict')}</p>
        </div>
        ${risk?.signals?.length > 0 ? `
          <div class="section">
            <h4>Risk Signals</h4>
            <div class="data-grid">
              ${risk.signals.map(s => `<div class="data-card"><div class="data-label">${escapeHtml(s.label)}</div><div class="data-value">${s.points > 0 ? '+' : ''}${s.points} pts - ${escapeHtml(s.detail)}</div></div>`).join('')}
            </div>
          </div>
        ` : ''}
        ${buildRecommendations(risk?.recommendations || [])}
      </div>

      ${buildVT(virusTotal)}

      <div class="section">
        <div class="section-title">📊 Quick Statistics</div>
        <div class="data-grid">
          <div class="data-card"><div class="data-label">A Records</div><div class="data-value">${intel.records?.A?.length || 0}</div></div>
          <div class="data-card"><div class="data-label">AAAA Records</div><div class="data-value">${intel.records?.AAAA?.length || 0}</div></div>
          <div class="data-card"><div class="data-label">CNAME Records</div><div class="data-value">${intel.records?.CNAME?.length || 0}</div></div>
          <div class="data-card"><div class="data-label">MX Records</div><div class="data-value">${intel.records?.MX?.length || 0}</div></div>
          <div class="data-card"><div class="data-label">NS Records</div><div class="data-value">${intel.records?.NS?.length || 0}</div></div>
          <div class="data-card"><div class="data-label">TXT Records</div><div class="data-value">${intel.records?.TXT?.length || 0}</div></div>
          <div class="data-card"><div class="data-label">Subdomains</div><div class="data-value">${intel.subdomains?.length || 0}</div></div>
          <div class="data-card"><div class="data-label">IP Addresses</div><div class="data-value">${intel.ips?.length || 0}</div></div>
          <div class="data-card"><div class="data-label">MX Hosts</div><div class="data-value">${intel.mxHosts?.length || 0}</div></div>
        </div>
      </div>

      ${buildEmailSecurity(intel.emailSecurity)}
      ${buildWhois(intel.whois)}
      ${buildGraphExplanation(intel.graph)}
      ${buildDnsRecords(intel.records)}
      ${buildSubdomains(intel.subdomains)}
      ${buildIpAsn(intel.ips)}
      ${intel.mxHosts?.length > 0 ? `
        <div class="section">
          <div class="section-title">📧 MX Hosts</div>
          <div class="data-grid">
            ${intel.mxHosts.slice(0, 10).map(mx => `
              <div class="data-card">
                <div class="data-label">${escapeHtml(mx.host)} (priority ${mx.priority})</div>
                <div class="data-value">IP: ${mx.ip || '—'}</div>
                <div class="data-label">ASN: ${mx.asn || '—'}</div>
                <div class="data-value">${escapeHtml(mx.asname || '—')}</div>
              </div>
            `).join('')}
          </div>
        </div>
      ` : ''}
      ${buildRecommendations(risk?.recommendations || [])}
    `;
  };

  // Helper function for IP Intel printable report
  const generateIpIntelReport = (data: any, inputValue: string) => {
    if (!data) return '';
    
    const ip = data.data?.query || data.data?.ip || inputValue;
    const vt = data.reputation?.virusTotal;
    const reputation = data.reputation;
    const scan = data.scan;
    const pivot = data.pivot;
    const rdap = data.data?.rdap;
    const http = data.data?.http;
    const tls = data.data?.tls;
    const content = data.data?.content;
    const redirects = data.data?.redirects;
    const staticFlags = data.data?.staticFlags;
    const verdict = data.analysis?.threatLevel || 'NORMAL';
    const recommendations = data.analysis?.recommendations || [];
    
    const formatDate = (iso: string | null) => {
      if (!iso) return '—';
      const d = new Date(iso);
      return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 10);
    };
    
    const escapeHtml = (text: string) => text
      .replace(/&/g, '&')
      .replace(/</g, '<')
      .replace(/>/g, '>')
      .replace(/"/g, '"')
      .replace(/'/g, '&#039;');
    
    const getVerdictClass = (level: string) => {
      switch (level) {
        case 'MALICIOUS': return 'badge-critical';
        case 'SUSPICIOUS': return 'badge-elevated';
        case 'CLEAN': return 'badge-normal';
        default: return 'badge-normal';
      }
    };
    
    // Build VirusTotal section
    const buildVT = (vt: any) => {
      if (!vt || !vt.analyzed) return '';
      const stats = vt.lastAnalysisStats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 };
      const total = vt.totalEngines || Object.values(stats).reduce((a: number, b: number) => a + b, 0);
      return `
        <div class="section">
          <div class="section-title">🛡️ VirusTotal Analysis</div>
          <div class="data-grid">
            <div class="data-card"><div class="data-label">Verdict</div><div class="data-value"><span class="badge ${getVerdictClass(vt.verdict)}">${vt.verdict}</span></div></div>
            <div class="data-card"><div class="data-label">Detection</div><div class="data-value">${stats.malicious}/${total} engines</div></div>
            <div class="data-card"><div class="data-label">Reputation</div><div class="data-value">${vt.reputation}</div></div>
            <div class="data-card"><div class="data-label">Last Analysis</div><div class="data-value">${vt.lastAnalysisDate ? formatDate(vt.lastAnalysisDate) : 'N/A'}</div></div>
          </div>
          <div class="section">
            <div class="section-title">📊 Detection Breakdown</div>
            <div class="data-grid">
              <div class="data-card"><div class="data-label">Malicious</div><div class="data-value">${stats.malicious || 0}</div></div>
              <div class="data-card"><div class="data-label">Suspicious</div><div class="data-value">${stats.suspicious || 0}</div></div>
              <div class="data-card"><div class="data-label">Undetected</div><div class="data-value">${stats.undetected || 0}</div></div>
              <div class="data-card"><div class="data-label">Harmless</div><div class="data-value">${stats.harmless || 0}</div></div>
              <div class="data-card"><div class="data-label">Timeout</div><div class="data-value">${stats.timeout || 0}</div></div>
              <div class="data-card"><div class="data-label">Total Engines</div><div class="data-value">${total}</div></div>
            </div>
          </div>
          ${vt.categories?.length > 0 ? `
            <div class="section">
              <div class="section-title">📂 Categories</div>
              <div class="data-grid">
                ${vt.categories.map(c => `<div class="data-card"><div class="data-value">${escapeHtml(c)}</div></div>`).join('')}
              </div>
            </div>
          ` : ''}
          ${vt.tags?.length > 0 ? `
            <div class="section">
              <div class="section-title">🏷️ Tags</div>
              <div class="data-grid">
                ${vt.tags.slice(0, 12).map(t => `<div class="data-card"><div class="data-value">#${escapeHtml(t)}</div></div>`).join('')}
              </div>
            </div>
          ` : ''}
          <div class="section">
            <div class="section-title">📋 Additional Info</div>
            <div class="data-grid">
              <div class="data-card"><div class="data-label">ASN</div><div class="data-value">${vt.asn || 'N/A'}</div></div>
              <div class="data-card"><div class="data-label">Country</div><div class="data-value">${vt.country || 'N/A'}</div></div>
              <div class="data-card"><div class="data-label">First Seen</div><div class="data-value">${vt.firstSeen ? formatDate(vt.firstSeen) : 'N/A'}</div></div>
              <div class="data-card"><div class="data-label">Last Seen</div><div class="data-value">${vt.lastSeen ? formatDate(vt.lastSeen) : 'N/A'}</div></div>
            </div>
          </div>
          <div class="section">
            <div class="section-title">🔗 VirusTotal Link</div>
            <div class="data-grid">
              <div class="data-card"><div class="data-value"><a href="${vt.url}" target="_blank" style="color: #059669;">View on VirusTotal</a></div></div>
            </div>
          </div>
        `;
    };
    
    // Build reputation section
    const buildReputation = (rep: any) => {
      if (!rep) return '';
      return `
        <div class="section">
          <div class="section-title">🎯 Reputation & Infrastructure</div>
          <div class="data-grid">
            <div class="data-card"><div class="data-label">IP</div><div class="data-value">${reputation?.ip || 'N/A'}</div></div>
            <div class="data-card"><div class="data-label">Geo</div><div class="data-value">${rep.geo || 'N/A'}</div></div>
            <div class="data-card"><div class="data-label">ASN</div><div class="data-value">${rep.asn || 'N/A'}</div></div>
            <div class="data-card"><div class="data-label">ISP</div><div class="data-value">${rep.isp || 'N/A'}</div></div>
            <div class="data-card"><div class="data-label">DNSBL Listed</div><div class="data-value">${rep.dnsblListed || 0}</div></div>
            <div class="data-card"><div class="data-label">DNSBL Blocked</div><div class="data-value">${rep.dnsblBlocked || 0}</div></div>
            <div class="data-card"><div class="data-label">Tor Exit</div><div class="data-value">${rep.torExit ? 'Yes' : 'No'}</div></div>
            <div class="data-card"><div class="data-label">URLhaus Count</div><div class="data-value">${rep.urlhausCount || 0}</div></div>
            <div class="data-card"><div class="data-label">Hosting</div><div class="data-value">${rep.hosting ? 'Yes' : 'No'}</div></div>
            <div class="data-card"><div class="data-label">Proxy</div><div class="data-value">${rep.proxy ? 'Yes' : 'No'}</div></div>
            <div class="data-card"><div class="data-label">WHOIS Created</div><div class="data-value">${formatDate(rep.whoisCreated) || 'N/A'}</div></div>
            <div class="data-card"><div class="data-label">Domain Age</div><div class="data-value">${rep.domainAgeDays ? `${rep.domainAgeDays} days` : 'N/A'}</div></div>
            <div class="data-card"><div class="data-label">Domain Expires</div><div class="data-value">${formatDate(rep.domainExpires) || 'N/A'}</div></div>
          </div>
        </div>
      `;
    };
    
    // Build scan results
    const buildScan = (scan: any) => {
      if (!scan) return '';
      const openPorts = scan.ports?.filter((p: any) => p.state === 'open') || [];
      return `
        <div class="section">
          <div class="section-title">🔍 Port Scan Results</div>
          <div class="data-grid">
            <div class="data-card"><div class="data-label">OS Fingerprint</div><div class="data-value">${scan.os || 'Unknown'}</div></div>
            <div class="data-card"><div class="data-label">Open Ports</div><div class="data-value">${openPorts.length}</div></div>
          </div>
          ${openPorts.length > 0 ? `
            <div class="section">
              <h4>Open Ports</h4>
              <div class="data-grid">
                ${openPorts.map((p: any) => `
                  <div class="data-card">
                    <div class="data-label">Port ${p.port}</div>
                    <div class="data-value">${p.service} (${p.state})</div>
                    <div class="data-label">Banner: ${escapeHtml(p.banner || '—')}</div>
                  </div>
                `).join('')}
              </div>
            </div>
          ` : ''}
        </div>
      `;
    };
    
    // Build RDAP
    const buildRdap = (rdap: any) => {
      if (!rdap) return '';
      return `
        <div class="section">
          <div class="section-title">📋 RDAP / WHOIS</div>
          <div class="data-grid">
            <div class="data-card"><div class="data-label">Handle</div><div class="data-value">${escapeHtml(rdap.handle || 'N/A')}</div></div>
            <div class="data-card"><div class="data-label">Name</div><div class="data-value">${escapeHtml(rdap.name || 'N/A')}</div></div>
            <div class="data-card"><div class="data-label">Type</div><div class="data-value">${escapeHtml(rdap.type || 'N/A')}</div></div>
            <div class="data-card"><div class="data-label">Country</div><div class="data-value">${escapeHtml(rdap.country || 'N/A')}</div></div>
            <div class="data-card"><div class="data-label">Start Address</div><div class="data-value">${escapeHtml(rdap.startAddress || 'N/A')}</div></div>
            <div class="data-card"><div class="data-label">End Address</div><div class="data-value">${escapeHtml(rdap.endAddress || 'N/A')}</div></div>
            <div class="data-card"><div class="data-label">Entities</div><div class="data-value">${rdap.entities?.join(', ') || 'N/A'}</div></div>
            <div class="data-card"><div class="data-label">Abuse Contacts</div><div class="data-value">${rdap.abuseContacts?.join(', ') || 'N/A'}</div></div>
            <div class="data-card"><div class="data-label">Status</div><div class="data-value">${rdap.status?.join(', ') || 'N/A'}</div></div>
          </div>
        </div>
      `;
    };
    
    // Build HTTP
    const buildHttp = (http: any) => {
      if (!http) return '';
      return `
        <div class="section">
          <div class="section-title">🌐 HTTP Fingerprint</div>
          <div class="data-grid">
            <div class="data-card"><div class="data-label">Final URL</div><div class="data-value">${escapeHtml(http.finalUrl || 'N/A')}</div></div>
            <div class="data-card"><div class="data-label">Status</div><div class="data-value">${http.status} ${http.statusText}</div></div>
            <div class="data-card"><div class="data-label">Protocol</div><div class="data-value">${http.protocol}</div></div>
            <div class="data-card"><div class="data-label">Server</div><div class="data-value">${escapeHtml(http.server || 'N/A')}</div></div>
            <div class="data-card"><div class="data-label">Content-Type</div><div class="data-value">${escapeHtml(http.contentType || 'N/A')}</div></div>
            <div class="data-card"><div class="data-label">TTFB</div><div class="data-value">${http.timings?.ttfbMs} ms</div></div>
            <div class="data-card"><div class="data-label">Total Time</div><div class="data-value">${http.timings?.totalMs} ms</div></div>
          </div>
          ${http.headers ? `
            <div class="section">
              <h4>Headers</h4>
              <div class="json-block">${JSON.stringify(http.headers, null, 2)}</div>
            </div>
          ` : ''}
        </div>
      `;
    };
    
    // Build TLS
    const buildTls = (tls: any) => {
      if (!tls) return '';
      return `
        <div class="section">
          <div class="section-title">🔒 TLS Certificate</div>
          <div class="data-grid">
            <div class="data-card"><div class="data-label">Protocol</div><div class="data-value">${tls.protocol}</div></div>
            <div class="data-card"><div class="data-label">Cipher</div><div class="data-value">${escapeHtml(tls.cipher)}</div></div>
            <div class="data-card"><div class="data-label">Subject CN</div><div class="data-value">${escapeHtml(tls.subjectCn || 'N/A')}</div></div>
            <div class="data-card"><div class="data-label">Issuer CN</div><div class="data-value">${escapeHtml(tls.issuerCn || 'N/A')}</div></div>
            <div class="data-card"><div class="data-label">Valid From</div><div class="data-value">${formatDate(tls.validFrom)}</div></div>
            <div class="data-card"><div class="data-label">Valid To</div><div class="data-value">${formatDate(tls.validTo)}</div></div>
            <div class="data-card"><div class="data-label">Status</div><div class="data-value">${tls.expired ? 'EXPIRED' : tls.selfSigned ? 'SELF-SIGNED' : tls.hostnameMismatch ? 'MISMATCH' : 'VALID'}</div></div>
            <div class="data-card"><div class="data-label">SAN</div><div class="data-value">${tls.san?.join(', ') || 'N/A'}</div></div>
          </div>
        </div>
      `;
    };
    
    // Build content analysis
    const buildContent = (content: any) => {
      if (!content) return '';
      return `
        <div class="section">
          <div class="section-title">📄 Content Analysis</div>
          <div class="data-grid">
            <div class="data-card"><div class="data-label">Title</div><div class="data-value">${escapeHtml(content.title || 'N/A')}</div></div>
            <div class="data-card"><div class="data-label">Description</div><div class="data-value">${escapeHtml(content.description || 'N/A')}</div></div>
            <div class="data-card"><div class="data-label">Language</div><div class="data-value">${content.lang || 'N/A'}</div></div>
            <div class="data-card"><div class="data-label">Favicon</div><div class="data-value">${content.favicon || 'N/A'}</div></div>
            <div class="data-card"><div class="data-label">Forms</div><div class="data-value">${content.forms?.length || 0}</div></div>
            <div class="data-card"><div class="data-label">Iframes</div><div class="data-value">${content.iframes?.length || 0}</div></div>
            <div class="data-card"><div class="data-label">Meta Refresh</div><div class="data-value">${content.metaRefresh ? 'Yes' : 'No'}</div></div>
            <div class="data-card"><div class="data-label">Obfuscated JS</div><div class="data-value">${content.obfuscatedJs ? 'Yes' : 'No'}</div></div>
            <div class="data-card"><div class="data-label">Inline JS Bytes</div><div class="data-value">${content.inlineJsBytes || 0}</div></div>
            <div class="data-card"><div class="data-label">Scripts</div><div class="data-value">${content.scripts?.length || 0}</div></div>
            <div class="data-card"><div class="data-label">Emails</div><div class="data-value">${content.emails?.join(', ') || 'N/A'}</div></div>
            <div class="data-card"><div class="data-label">Telegram Tokens</div><div class="data-value">${content.telegramTokens?.join(', ') || 'N/A'}</div></div>
            <div class="data-card"><div class="data-label">Telegram Chat IDs</div><div class="data-value">${content.telegramChatIds?.join(', ') || 'N/A'}</div></div>
          </div>
        </div>
      `;
    };
    
    // Build redirects
    const buildRedirects = (redirects: any[]) => {
      if (!redirects || redirects.length === 0) return '';
      return `
        <div class="section">
          <div class="section-title">🔄 Redirect Chain</div>
          <div class="data-grid">
            ${redirects.map((r, i) => `
              <div class="data-card">
                <div class="data-label">Step ${r.index || i + 1}</div>
                <div class="data-value">${escapeHtml(r.url)}</div>
                <div class="data-label">Status: ${r.status || 'N/A'}</div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    };
    
    // Build static flags
    const buildStaticFlags = (flags: any[]) => {
      if (!flags || flags.length === 0) return '';
      return `
        <div class="section">
          <div class="section-title">🚩 Static Flags</div>
          <div class="data-grid">
            ${flags.map(f => `
              <div class="data-card">
                <div class="data-label">${escapeHtml(f.label)}</div>
                <div class="data-value">Weight: ${f.weight} · Category: ${f.category}</div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    };
    
    // Build screenshot
    const buildScreenshot = (screenshotUrl: string) => {
      if (!screenshotUrl) return '';
      return `
        <div class="section">
          <div class="section-title">📸 Screenshot</div>
          <div class="data-grid">
            <div class="data-card">
              <a href="${screenshotUrl}" target="_blank" style="color: #059669;">View Screenshot</a>
            </div>
          </div>
        </div>
      `;
    };
    
    // Build recommendations
    const buildRecommendations = (recs: string[]) => {
      if (!recs || recs.length === 0) return '';
      return `
        <div class="section">
          <div class="section-title">🛡️ Recommendations</div>
          <ol>${recs.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ol>
        </div>
      `;
    };
    
    // Build the complete IP Intel report
    return `
      <div class="section">
        <div class="section-title">🔍 IP Intelligence Report</div>
        <div class="data-grid">
          <div class="data-card"><div class="data-label">IP Address</div><div class="data-value">${escapeHtml(ip)}</div></div>
          <div class="data-card"><div class="data-label">Analysis Date</div><div class="data-value">${formatDate(new Date().toISOString())}</div></div>
          <div class="data-card"><div class="data-label">Source</div><div class="data-value">NEXUS Real Sandbox</div></div>
        </div>
      </div>
      
      ${vt ? `<div class="section"><div class="section-title">🛡️ VirusTotal Analysis</div>${buildVT(vt)}` : ''}
      
      <div class="section">
        <div class="section-title">⚠️ Threat Assessment</div>
        <div class="data-grid">
          <div class="data-card"><div class="data-label">Threat Level</div><div class="data-value">${verdict}</div></div>
        </div>
        <div class="section">
          <h4>Recommendations</h4>
          <ul>${recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul>
        </div>
      </div>
      
      ${buildReputation(data.reputation)}
      ${buildScan(data.scan)}
      ${buildVT(data.reputation?.virusTotal)}
      ${buildRdap(data.data?.rdap)}
      ${buildHttp(data.data?.http)}
      ${buildTls(data.data?.tls)}
      ${buildRedirects(data.data?.redirects)}
      ${buildContent(data.data?.content)}
      ${buildStaticFlags(data.data?.staticFlags)}
      ${data.data?.screenshotUrl ? buildScreenshot(data.data.screenshotUrl) : ''}
      ${buildRecommendations(data.analysis?.recommendations || [])}
    `;
  };

  // Generate Executive Protection Report
  const generateExecProtectionReport = (data: any): string => {
    const exec = data.executive;
    const dorkResults = data.dorkResults;
    const escapeHtml = (text: string) => text
      .replace(/&/g, '&')
      .replace(/</g, '<')
      .replace(/>/g, '>')
      .replace(/"/g, '"')
      .replace(/'/g, '&#039;');

    if (!exec) return '<div class="section"><div class="section-title">⚠️ No Executive Data</div><p>No executive data available for report.</p></div>';

    let html = `
      <div class="section">
        <div class="section-title">👤 Executive Profile</div>
        <div class="data-grid">
          <div class="data-card"><div class="data-label">ID / Document</div><div class="data-value">${escapeHtml(exec.documentId || 'N/A')}</div></div>
          <div class="data-card"><div class="data-label">Phone</div><div class="data-value">${escapeHtml(exec.phone || 'N/A')}</div></div>
          <div class="data-card"><div class="data-label">Email Corporate</div><div class="data-value">${escapeHtml(exec.emailCorporate || 'N/A')}</div></div>
          <div class="data-card"><div class="data-label">Email Personal</div><div class="data-value">${escapeHtml(exec.emailPersonal || 'N/A')}</div></div>
          <div class="data-card"><div class="data-label">Address</div><div class="data-value">${escapeHtml(exec.address || 'N/A')}</div></div>
          <div class="data-card"><div class="data-label">Location</div><div class="data-value">${escapeHtml(exec.location || 'N/A')}</div></div>
        </div>
      </div>
    `;

    if (exec.socialMedia?.length > 0) {
      html += `
        <div class="section">
          <div class="section-title">📱 Social Media Profiles</div>
          <div class="data-grid">
            ${exec.socialMedia.map((sm: any) => `
              <div class="data-card">
                <div class="data-label">${escapeHtml(sm.platform)}</div>
                <div class="data-value">${escapeHtml(sm.username)}</div>
                ${sm.url ? `<div class="data-label"><a href="${escapeHtml(sm.url)}" target="_blank" style="color: #059669;">View Profile</a></div>` : ''}
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    if (dorkResults?.queries?.length > 0) {
      html += `
        <div class="section">
          <div class="section-title">🔍 OSINT Dork Research Queries (${dorkResults.queries.length} categories)</div>
          <div class="data-grid">
            ${dorkResults.queries.map((q: any) => `
              <div class="data-card" style="grid-column: span 1;">
                <div class="data-label">${escapeHtml(q.category)}</div>
                <div class="data-value" style="font-family: monospace; font-size: 11px; white-space: pre-wrap;">${escapeHtml(q.query)}</div>
                <div class="data-label">${escapeHtml(q.description)}</div>
                <div class="data-value">Sources: ${q.sources.join(', ')}</div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    return html;
  };

  // Generate IP Intel specific report if tab is ip
  let ipIntelHtml = '';
  if (tab === 'ip' && data) {
    ipIntelHtml = generateIpIntelReport(data, inputValue);
  }

  // Build the final HTML content based on tab
  let contentHtml = '';
  if (tab === 'domain' && domainIntelHtml) {
    contentHtml = domainIntelHtml;
  } else if (tab === 'ip' && ipIntelHtml) {
    contentHtml = ipIntelHtml;
  } else if (tab === 'exec-protection' && data) {
    contentHtml = generateExecProtectionReport(data);
  } else if (data) {
    contentHtml = `
      <div class="section">
        <div class="section-title">📊 Datos de Análisis</div>
        <div class="json-block">${reportData}</div>
      </div>
    `;
  }

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${tabLabel} - Informe Imprimible | NEXUS-INTEL</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 20px; background: #fff; color: #1f2937; line-height: 1.6; }
    .header { border-bottom: 3px solid #059669; padding-bottom: 20px; margin-bottom: 30px; text-align: center; }
    .logo { font-size: 24px; font-weight: 800; color: #059669; margin-bottom: 8px; }
    .title { font-size: 28px; font-weight: 700; color: #111827; margin-bottom: 4px; }
    .subtitle { color: #6b7280; font-size: 14px; }
    .meta { display: flex; justify-content: center; gap: 20px; margin-top: 16px; flex-wrap: wrap; font-size: 13px; color: #6b7280; }
    .section { margin-bottom: 30px; }
    .section-title { font-size: 18px; font-weight: 700; color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
    .data-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; }
    .data-card { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px 16px; }
    .data-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #6b7280; margin-bottom: 4px; }
    .data-value { font-weight: 600; color: #111827; word-break: break-word; font-family: monospace; font-size: 13px; }
    .json-block { background: #111827; color: #10b981; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 11px; overflow-x: auto; white-space: pre-wrap; max-height: 400px; overflow-y: auto; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
    .badge-normal { background: #dcfce7; color: #166534; }
    .badge-elevated { background: #fef3c7; color: #92400e; }
    .badge-critical { background: #fee2e2; color: #991b1b; }
    .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; text-align: center; font-size: 11px; color: #9ca3af; }
    @media print { .no-print { display: none; } body { padding: 0; } }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">🛡️ NEXUS-INTEL</div>
    <div class="title">Informe de Inteligencia: ${tabLabel}</div>
    <div class="subtitle">Plataforma de Inteligencia de Amenazas y Protección Ejecutiva</div>
    <div class="meta">
      <span>📅 Generado: ${timestamp}</span>
      <span>🎯 Objetivo: ${inputDisplay}</span>
      <span>🔍 Módulo: ${tabLabel}</span>
    </div>
  </div>

  <div class="section">
    <div class="section-title">📋 Resumen Ejecutivo</div>
    <div class="data-grid">
      <div class="data-card"><div class="data-label">Módulo</div><div class="data-value">${tabLabel}</div></div>
      <div class="data-card"><div class="data-label">Fecha/Hora</div><div class="data-value">${timestamp}</div></div>
      <div class="data-card"><div class="data-label">Objetivo Analizado</div><div class="data-value">${inputDisplay}</div></div>
      <div class="data-card"><div class="data-label">Estado</div><div class="data-value"><span class="badge badge-normal">Completado</span></div></div>
    </div>
  </div>

  ${contentHtml}

  <div class="footer">
    <p>Generado por NEXUS-INTEL — Plataforma de Inteligencia de Amenazas y Protección Ejecutiva</p>
    <p>Este informe se generó automáticamente. Verifique los datos antes de tomar decisiones operacionales.</p>
  </div>

  <script>
    window.onload = () => { window.print(); }
  </script>
</body>
</html>`;
}

function openPrintReport(tab: TabType, data: any, inputValue: string) {
  const html = generatePrintableReport(tab, data, inputValue);
  const win = window.open('', '_blank');
  if (win) {
    win.document.write(html);
    win.document.close();
  } else {
    alert('Permita ventanas emergentes para generar el informe imprimible.');
  }
}

// ==================== FORENSIC ARTIFACTS ====================
interface ForensicArtifact {
  id: string;
  title: string;
  purpose: string;
  sources: string[];
  fields: string[];
  queries: { label: string; query: string }[];
}

const FORENSIC_ARTIFACTS: ForensicArtifact[] = [
  {
    id: 'timestamps',
    title: 'Timestamps / Timezones',
    purpose: 'Build an exact connection timeline to correlate events across systems and reconstruct the attack path.',
    sources: ['Firewall / NAT logs', 'Proxy / WAF logs', 'RADIUS / VPN logs', 'Web server access logs'],
    fields: ['timestamp', 'timezone / tz_offset', 'request_time', 'log_source'],
    queries: [
      { label: 'Splunk SPL', query: 'index=* src_ip="<IP>" earliest=-24h | eval norm=_time | stats count by norm' },
      { label: 'Elastic KQL', query: '@timestamp:[now-24h TO now] AND source.ip:"<IP>"' },
      { label: 'grep', query: 'grep -E "<IP>" /var/log/*access*.log | cut -d" " -f1-4' },
    ],
  },
  {
    id: 'src-port',
    title: 'Ephemeral Source Port',
    purpose: 'Identifies the unique client session behind NAT/CGNAT in ISP records, even when many hosts share one public IP.',
    sources: ['Firewall / NetFlow / sFlow', 'Load balancer logs', 'ISP AAA / RADIUS'],
    fields: ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol'],
    queries: [
      { label: 'Splunk SPL', query: 'index=firewall src_ip="<IP>" | stats values(src_port) by dst_ip' },
      { label: 'Elastic KQL', query: 'source.ip:"<IP>" | dstat by source.port, destination.port' },
      { label: 'tshark', query: 'tshark -r capture.pcap -Y "ip.src==<IP>" -T fields -e tcp.srcport -e tcp.dstport | sort -u' },
    ],
  },
  {
    id: 'http-headers',
    title: 'HTTP Headers / User-Agent',
    purpose: 'Profiles the browser, client OS, locale and referer to fingerprint the actor and tie together multiple attacks.',
    sources: ['Forward proxy logs', 'Web server access logs', 'WAF / CDN logs', 'Email gateway headers'],
    fields: ['user_agent', 'referer', 'accept_language', 'x_forwarded_for', 'x_requested_with'],
    queries: [
      { label: 'Splunk SPL', query: 'index=http src_ip="<IP>" | table _time uri user_agent referer x_forwarded_for' },
      { label: 'Elastic KQL', query: 'source.ip:"<IP>" AND user_agent:*' },
      { label: 'awk', query: 'grep "<IP>" /var/log/nginx/access.log | awk \'{print $1, $6, $9, $11, $12}\'' },
    ],
  },
  {
    id: 'session',
    title: 'Session Correlation',
    purpose: 'Ties multiple accounts, cookies and sessions to the same IP within a time window to reveal lateral movement.',
    sources: ['SIEM correlation rules', 'EDR / endpoint telemetry', 'Auth (AD / IdP) logs'],
    fields: ['session_id', 'cookie', 'account / user', 'source_ip', 'correlation_id'],
    queries: [
      { label: 'Splunk SPL', query: 'index=* src_ip="<IP>" | stats values(account) by session_id' },
      { label: 'Elastic KQL', query: 'source.ip:"<IP>" OR session_id:"<known-session>"' },
      { label: 'grep', query: 'grep -E "session_id|<IP>" /var/log/app/*.log' },
    ],
  },
  {
    id: 'dns',
    title: 'DNS Queries Made',
    purpose: 'The domains resolved by the IP reveal C2, phishing or data-exfil infrastructure and enable pivoting.',
    sources: ['DNS server query logs', 'DHCP lease logs', 'Passive DNS (pDNS) feeds'],
    fields: ['src_ip', 'qname', 'qtype', 'answer', 'timestamp'],
    queries: [
      { label: 'Splunk SPL', query: 'index=dns src_ip="<IP>" | stats count by query' },
      { label: 'Elastic KQL', query: 'source.ip:"<IP>" AND dns.question.name:*' },
      { label: 'BIND query.log', query: 'grep -E "client <IP>#" /var/log/named/query.log' },
    ],
  },
  {
    id: 'tls',
    title: 'TLS SNI / JA3 Fingerprint',
    purpose: 'Fingerprint the client TLS stack without decrypting traffic; SNI reveals the hostname actually requested.',
    sources: ['TLS interception / SSL logging', 'Proxy logs', 'Full packet capture (PCAP)'],
    fields: ['ssl_server_name', 'ja3 / ja4', 'tls_version', 'cipher_suite'],
    queries: [
      { label: 'Splunk SPL', query: 'index=proxy src_ip="<IP>" ssl_server_name=* | stats values(ssl_server_name) by ja3' },
      { label: 'Elastic KQL', query: 'source.ip:"<IP>" AND tls.sni:*' },
      { label: 'tshark', query: 'tshark -r capture.pcap -Y "ip.src==<IP> and tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name' },
    ],
  },
  {
    id: 'pcap',
    title: 'Full Packet Capture (PCAP)',
    purpose: 'Preserve raw evidence of every packet to/from the IP for offline deep analysis and legal hold.',
    sources: ['Network taps / SPAN ports', 'Sensor or host capture', 'Cloud VPC traffic mirroring'],
    fields: ['frame_number', 'ip.src', 'ip.dst', 'tcp.flags', 'payload'],
    queries: [
      { label: 'tcpdump (live)', query: 'tcpdump -i eth0 -C 100 -w evidence-<IP>.pcap host <IP>' },
      { label: 'tshark (filter)', query: 'tshark -r evidence.pcap -Y "ip.addr==<IP>" -c 1000' },
      { label: 'Splunk (suricata)', query: 'index=suricata alert.src_ip="<IP>" | table _time signature' },
    ],
  },
];

// Known-vulnerable services exposed by the active scan.
// Rendered only for OPEN ports; each entry documents the attack vector and
// standard verification/exploitation steps for defensive validation.
interface VulnProfile {
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  title: string;
  desc: string;
  cves: string[];
  vector: string;
  steps: string[];
}
const VULNERABLE_SERVICES: Record<number, VulnProfile> = {
  21: {
    risk: 'HIGH',
    title: 'FTP — cleartext + anonymous access',
    desc: 'FTP transmits credentials in cleartext. Misconfigurations commonly allow anonymous logon, and older servers (vsftpd 2.3.4) contain a remote backdoor.',
    cves: ['CVE-2011-2523'],
    vector: 'Network: TCP/21 reachable without source restrictions. Credentials are sniffable in transit; anonymous mode needs no credentials.',
    steps: [
      'Enumerate: nmap -p21 --script ftp-anon,ftp-vsftpd-backdoor <ip>',
      'Test anonymous logon: ftp <ip>  (user: anonymous, pass: any) → if logged in, check for writable directories',
      'Capture cleartext creds with a passive sniffer (tcpdump/wireshark) on the segment',
      'If banner is vsftpd 2.3.4: attempt the backdoor on TCP/6200 (msf: exploit/unix/ftp/vsftpd_234_backdoor)',
      'Escalate: upload a webshell to a served FTP root or abuse writable shares',
    ],
  },
  22: {
    risk: 'HIGH',
    title: 'SSH — brute force / weak credentials',
    desc: 'An exposed SSH service is a primary brute-force and credential-stuffing target. Weak passwords and old OpenSSH versions enable user enumeration and auth bypass.',
    cves: ['CVE-2018-15473', 'CVE-2024-6387'],
    vector: 'Network: TCP/22 open to the Internet. Relies on password auth; no rate limiting or fail2ban present.',
    steps: [
      'Enumerate users: nmap -p22 --script ssh2-enum-algos,ssh-hostkey <ip>',
      'Version check: ssh -V + banner; if OpenSSH <9.8 → check regreSSHion CVE-2024-6387',
      'User enumeration: nmap --script ssh-auth-methods <ip>',
      'Credential attack: hydra -L users.txt -P pass.txt ssh://<ip> (use only on owned/authorized targets)',
      'If weak creds found: log in, escalate privileges with local enumeration (linpeas / winPEAS)',
    ],
  },
  23: {
    risk: 'CRITICAL',
    title: 'Telnet — unencrypted legacy remote access',
    desc: 'Telnet sends all traffic in cleartext and often runs with default/weak credentials on network devices and IoT equipment. Trivially sniffable.',
    cves: ['CVE-2005-2011', 'CVE-1999-0619'],
    vector: 'Network: TCP/23 exposed; sessions are plaintext, credentials are captured in transit.',
    steps: [
      'Sniff the session: tcpdump -i eth0 port 23 → credentials appear in cleartext',
      'Test default creds on common devices (admin/admin, root/root, cisco/cisco)',
      'Banner grab: nc -nv <ip> 23 → identify device model / firmware',
      'After access: enumerate config, SNMP communities, and management VLANs',
    ],
  },
  25: {
    risk: 'MEDIUM',
    title: 'SMTP — open relay / user enumeration',
    desc: 'Open SMTP relays are abused to send spam; misconfigured servers also allow user enumeration and mail spoofing for phishing.',
    cves: ['CVE-1999-0521', 'CWE-1389'],
    vector: 'Network: TCP/25 open, no sender/recipient validation.',
    steps: [
      'Banner: nc -nv <ip> 25',
      'Test open relay: MAIL FROM:<a@b.com> / RCPT TO:<c@d.com> → if accepted for foreign domains, it is an open relay',
      'User enumeration: VRFY root / EXPN root → confirms valid accounts',
      'SPF/DMARC check for spoofing feasibility: dig TXT <domain>',
      'Block inbound spoofing by enforcing SPF/DKIM/DMARC + relay restrictions',
    ],
  },
  445: {
    risk: 'CRITICAL',
    title: 'SMB — EternalBlue / SMBv1 / anonymous shares',
    desc: 'Windows file sharing exposed on the Internet. SMBv1 and unpatched versions are remotely exploitable for RCE (EternalBlue chain) and anonymous shares leak data.',
    cves: ['CVE-2017-0143', 'CVE-2017-0144', 'CVE-2020-0796'],
    vector: 'Network: TCP/445 open; authenticated or anonymous access to SMB shares and SMBv1 protocol handling.',
    steps: [
      'Vuln scan: nmap -p445 --script smb-vuln-ms17-010,smb-vuln-ms10-061,smb-enum-shares <ip>',
      'SMBv1 detection: nmap --script smb-protocols <ip>',
      'Anonymous share enum: smbclient -L //<ip> -N → check for open/print/IPC shares',
      'If MS17-010 confirmed: msf exploit/windows/smb/ms17_010_eternalblue (authorized tests only)',
      'Remediate: disable SMBv1, patch, restrict 445/139 to trusted networks',
    ],
  },
  3306: {
    risk: 'HIGH',
    title: 'MySQL — exposed database',
    desc: 'A database port reachable from the Internet is a prime target for credential attacks and known auth-bypass/overflow exploits in older versions.',
    cves: ['CVE-2012-2122', 'CVE-2016-6662'],
    vector: 'Network: TCP/3306 open; brute-forceable credentials, direct queries once authenticated.',
    steps: [
      'Version + probe: nmap -p3306 --script mysql-info,mysql-enum <ip>',
      'Check weak/blank root: mysql -h <ip> -u root (test root/root, root/admin)',
      'CVE-2012-2122 auth bypass probe: loop attempts with incorrect password to trigger the memcmp() bug',
      'Once in: enumerate databases, extract credentials (mysql.user), pivot to app servers',
      'Lock down: bind to 127.0.0.1, use strong passwords, limit source IPs',
    ],
  },
  3389: {
    risk: 'CRITICAL',
    title: 'RDP — BlueKeep / brute force',
    desc: 'Remote Desktop exposed to the Internet. Unpatched versions are remotely exploitable pre-auth (BlueKeep); others are relentlessly brute-forced.',
    cves: ['CVE-2019-0708', 'CVE-2023-35332'],
    vector: 'Network: TCP/3389 open; pre-auth code path (BlueKeep) or weak RDP credentials.',
    steps: [
      'NLA check: nmap -p3389 --script rdp-ntlm-info <ip>',
      'BlueKeep probe: msf auxiliary/scanner/rdp/cve_2019_0708_bluekeep',
      'Credential attack: hydra -s 3389 rdp://<ip> -L users.txt -P pass.txt (authorized only)',
      'If RDP open but not exploitable → still a high-value brute-force target: require NLA + strong creds + account lockout',
    ],
  },
  5432: {
    risk: 'HIGH',
    title: 'PostgreSQL — exposed database',
    desc: 'Internet-exposed PostgreSQL allows credential attacks and known extensions/version-specific exploits leading to RCE.',
    cves: ['CVE-2018-1058', 'CVE-2020-25695'],
    vector: 'Network: TCP/5432 open; weak superuser credentials or insecure pg_hba.conf entries.',
    steps: [
      'Probe: nmap -p5432 --script pgsql-brute,ssl-cert <ip>',
      'Try default superuser: psql -h <ip> -U postgres (postgres/postgres)',
      'If authenticated: COPY ... FROM PROGRAM to achieve RCE (CVE-2019-9193), enumerate roles/databases',
      'Lock down: listen on localhost only, restrict pg_hba.conf, strong passwords',
    ],
  },
  5900: {
    risk: 'HIGH',
    title: 'VNC — no/weak authentication',
    desc: 'VNC servers frequently run with no password or with weak shared passwords; compromised sessions give full remote GUI control.',
    cves: ['CVE-2006-2369', 'CVE-2019-17270'],
    vector: 'Network: TCP/5900 open; empty or brute-forceable VNC password, unencrypted session.',
    steps: [
      'Auth check: vncinfo / vncviewer <ip>:5900 → prompts for password?',
      'Brute force: hydra vnc://<ip> -P pass.txt',
      'Exploit realVNC/UltraVNC known CVEs based on version banner',
      'Remediate: require strong VNC password + tunnel over SSH/VPN, restrict sources',
    ],
  },
  6379: {
    risk: 'CRITICAL',
    title: 'Redis — unauthenticated RCE',
    desc: 'Redis exposed without authentication lets attackers write SSH keys, cron jobs, or webshells, and chain known CVEs for remote code execution.',
    cves: ['CVE-2022-0543', 'CVE-2015-4335', 'CVE-2022-24735'],
    vector: 'Network: TCP/6379 open, no requirepass configured → direct redis-cli commands.',
    steps: [
      'Test unauthenticated access: redis-cli -h <ip> info server',
      'Write SSH key: SET \'cron\' ... config set dir /root/.ssh → set filename authorized_keys',
      'Webshell: config set dir /var/www/html; set + dbfilename shell.php',
      'Cron RCE: config set dir /var/spool/cron; set filename root → reverse shell via cron',
      'Remediate: requirepass, bind 127.0.0.1, disable CONFIG (rename-command)',
    ],
  },
  8080: {
    risk: 'MEDIUM',
    title: 'HTTP-Alt — admin panels / default credentials',
    desc: 'Alternate HTTP ports frequently host admin consoles, APIs, or proxied apps with default credentials and unpatched web CVEs.',
    cves: ['CWE-798', 'CVE-2023-48795'],
    vector: 'Network: TCP/8080 open; web application reachable directly.',
    steps: [
      'Identify app: curl -sI http://<ip>:8080 → grab Server header and redirects',
      'Directory scan: gobuster dir -u http://<ip>:8080 -w wordlist.txt (look for /admin, /manager, /console)',
      'Default creds: test common combos on login panels',
      'Version-specific CVEs via banner/technology fingerprinting (whatweb, wappalyzer)',
    ],
  },
  9090: {
    risk: 'MEDIUM',
    title: 'Web-Admin — exposed management interface',
    desc: 'Management consoles (e.g. monitoring, container tools) on TCP/9090 often ship with default credentials or known CVEs.',
    cves: ['CWE-798', 'CVE-2017-12617'],
    vector: 'Network: TCP/9090 open; administrative interface reachable.',
    steps: [
      'Fingerprint: curl -sI http://<ip>:9090 → Server header / login page',
      'Search for default credentials for the identified product',
      'If it exposes an API: enumerate /api with unauth probes',
      'Restrict management ports to trusted networks',
    ],
  },
  53: {
    risk: 'MEDIUM',
    title: 'DNS — open recursive resolver (amplification)',
    desc: 'An open recursive resolver on the public Internet is abused for DNS amplification DDoS and domain data disclosure. It should only be reachable by its own clients.',
    cves: ['CVE-1999-0532', 'CWE-918'],
    vector: 'Network: TCP/UDP 53 open and accepting recursive queries from arbitrary hosts.',
    steps: [
      'Test recursion: dig @<ip> google.com A → if it answers for external names, it is an open resolver',
      'Amplification check: dig @<ip> any . TXT +dnssec → measure response size vs query',
      'Enumerate domain data: axfr zone transfer attempt (dig @<ip> <domain> axfr)',
      'Remediate: restrict recursion to internal clients, enable RRL, block zone transfers',
    ],
  },
  80: {
    risk: 'MEDIUM',
    title: 'HTTP — exposed web service',
    desc: 'Public web services frequently run outdated software, default admin panels, or exposed debug endpoints.',
    cves: ['CWE-798', 'CWE-79'],
    vector: 'Network: TCP/80 open; application served without TLS, credentials and data in cleartext.',
    steps: [
      'Fingerprint: curl -sI http://<ip>/ → Server, X-Powered-By, redirects',
      'Directory scan: gobuster dir -u http://<ip>/ -w wordlist.txt → /admin, /wp-login.php, /.git, /backup',
      'Technology + CVE mapping: whatweb / wappalyzer, then search CVEs for the version',
      'If WordPress: wpscan --url http://<ip>/ to enumerate plugins/themes with known vulnerabilities',
      'Harden: patch software, disable dir listing, enforce HTTPS (see port 443)',
    ],
  },
  110: {
    risk: 'MEDIUM',
    title: 'POP3 — cleartext mail retrieval',
    desc: 'POP3 retrieves mail without encryption; credentials and message content are sniffable. Older servers expose user enumeration.',
    cves: ['CVE-1999-0619', 'CWE-319'],
    vector: 'Network: TCP/110 open; mail session in cleartext.',
    steps: [
      'Banner: nc -nv <ip> 110 → +OK banner identifies server/version',
      'User enumeration: USER <name> → observe OK/ERR responses for valid accounts',
      'Sniff the session to capture credentials (must be on-path/authorized)',
      'Check STARTTLS availability; if unsupported, migrate clients to 995 (POP3S)',
    ],
  },
  115: {
    risk: 'HIGH',
    title: 'SFTP (SSH) — exposed file transfer',
    desc: 'SFTP runs over SSH, so the exposure mirrors port 22: brute-forceable credentials and OpenSSH CVEs. It often sits on file servers storing sensitive data.',
    cves: ['CVE-2024-6387', 'CVE-2018-15473'],
    vector: 'Network: TCP/115 open; SSH-based file transfer reachable, password auth enabled.',
    steps: [
      'Version: ssh-keyscan -p 115 <ip> → banner; if OpenSSH <9.8 check regreSSHion (CVE-2024-6387)',
      'User enum: ssh2-enum-algos / ssh-auth-methods via nmap',
      'Weak creds: hydra -s 115 -L users.txt -P pass.txt ssh://<ip> (authorized targets only)',
      'Once in: extract files, ssh keys, and configs; check for writable upload dirs',
    ],
  },
  135: {
    risk: 'CRITICAL',
    title: 'MSRPC — DCOM / RPC exposure',
    desc: 'Microsoft RPC (135/TCP) exposed publicly is the entry point for DCOM object attacks and is part of the EternalBlue/remote management attack chains.',
    cves: ['CVE-2008-4250', 'CVE-2017-0143', 'CVE-2021-1675'],
    vector: 'Network: TCP/135 open; DCOM/RPC endpoints reachable from the Internet.',
    steps: [
      'Endpoint enum: rpcdump.py <ip> (Impacket) → list RPC interfaces and bindings',
      'Vuln scan: nmap -p135 --script msrpc-enum,ms-sql-info <ip>',
      'PrintNightmare check (CVE-2021-1675) if Print Spooler RPC endpoint exposed',
      'If combined with SMB (445) → assess EternalBlue chain for full RCE',
      'Remediate: block 135/139/445 at the edge; patch MS17-010-class vulnerabilities',
    ],
  },
  139: {
    risk: 'HIGH',
    title: 'NetBIOS — SMB session services',
    desc: 'NetBIOS-SSN exposes legacy SMB session services used by Windows file sharing; it leaks hostnames, shares and enables SMBv1-era exploits.',
    cves: ['CVE-2017-0143', 'CVE-2017-0144'],
    vector: 'Network: TCP/139 open; NBT session service reachable, anonymous enumeration possible.',
    steps: [
      'Enumeration: nmap -p139 --script nbstat.nse <ip> → NetBIOS name table (hostname, logged-in users)',
      'Share enum: smbclient -L //<ip> -N → list available shares',
      'SMBv1/EternalBlue assessment if SMB protocol negotiation succeeds',
      'Remediate: disable NetBIOS over TCP/IP (WINS), block 139 at edge, patch SMB',
    ],
  },
  143: {
    risk: 'MEDIUM',
    title: 'IMAP — cleartext mail retrieval',
    desc: 'IMAP without TLS exposes credentials and mail in transit; vulnerable/legacy servers have memory-overflow and DoS CVEs.',
    cves: ['CVE-1999-0619', 'CWE-319', 'CVE-2004-2650'],
    vector: 'Network: TCP/143 open; cleartext mail session and STARTTLS negotiation.',
    steps: [
      'Banner: nc -nv <ip> 143 → server version',
      'Auth probe: a001 LOGIN user pass → test default/weak creds on own tenants',
      'Check STARTTLS: if unsupported, credential sniffing is trivial on-path',
      'Migrate to 993 (IMAPS) and require TLS 1.2+',
    ],
  },
  194: {
    risk: 'MEDIUM',
    title: 'IRC — cleartext chat / botnet C2',
    desc: 'IRC serves as botnet command-and-control and leaks channel/operator metadata. Open IRC servers are abused for DDoS bot networks and credential dumping.',
    cves: ['CWE-319', 'CVE-2005-3557'],
    vector: 'Network: TCP/194 open; IRC session reachable without transport encryption.',
    steps: [
      'Probe: nc -nv <ip> 194 → 020 banner reveals server software (e.g. InspIRCd, UnrealIRCd)',
      'Version CVEs: UnrealIRCd pre-3.2.8.1 backdoor (CVE-2010-2075), InspIRCd flaws',
      'Monitor channel/oper activity for C2 indicators (nick patterns, topic updates)',
      'Check for unauthenticated channel access and excessive connection flood',
    ],
  },
  443: {
    risk: 'MEDIUM',
    title: 'SSL/HTTPS — exposed web service',
    desc: 'TLS services hide admin panels, APIs and vulnerable apps; weak TLS configs and exposed login endpoints are prime attack surface.',
    cves: ['CWE-798', 'CVE-2023-48795', 'CWE-295'],
    vector: 'Network: TCP/443 open; TLS service reachable from the Internet.',
    steps: [
      'TLS audit: nmap -p443 --script ssl-enum-ciphers <ip> → weak ciphers/protocols',
      'Scanning: testssl.sh <ip>:443 → protocol/cipher weaknesses',
      'App discovery: curl -skI https://<ip>/ → Server header, login paths (/admin, /login, /api)',
      'Certificate info: openssl s_client -connect <ip>:443 → check expiry, SANs, issuer (pivot data)',
      'Harden: modern TLS config, HSTS, patch app, restrict admin routes',
    ],
  },
  1433: {
    risk: 'CRITICAL',
    title: 'MSSQL — exposed database / sa brute force',
    desc: 'SQL Server on the public Internet with a weak or empty sa password is an instant database takeover; older versions have remote RCE CVEs.',
    cves: ['CVE-2019-1068', 'CVE-2020-0618', 'CVE-2008-5416'],
    vector: 'Network: TCP/1433 open; TDS protocol reachable, sa credentials brute-forceable.',
    steps: [
      'Probe: nmap -p1433 --script ms-sql-info,ms-sql-ntlm-info <ip> → instance, version, patch level',
      'Default sa password test (only on owned/authorized targets): sqlcmd -S <ip> -U sa -P \'sa\' / empty',
      'Brute force: msf auxiliary/scanner/mssql/mssql_login with common passwords',
      'If compromised: xp_cmdshell RCE → take over the OS account running SQL Server',
      'Lock down: strong sa password, Windows Auth, restrict 1433 to app networks',
    ],
  },
  5632: {
    risk: 'HIGH',
    title: 'PCAnywhere — legacy remote control',
    desc: 'Symantec pcAnywhere is legacy remote-control software with known authentication-bypass and default-credential CVEs; long unsupported.',
    cves: ['CVE-2006-4048', 'CVE-2007-3612'],
    vector: 'Network: TCP/5632 open; remote-control service with weak/known auth reachable.',
    steps: [
      'Banner: nc -nv <ip> 5632 → version fingerprint',
      'Default password test (authorized only) → pcAnywhere host passwords are commonly left default',
      'Known auth-bypass assessment per version banner (CVE-2006-4048)',
      'Remediate: uninstall pcAnywhere, replace with a modern patched remote-control solution',
    ],
  },
  25565: {
    risk: 'MEDIUM',
    title: 'Minecraft — game server exposed',
    desc: 'Public Minecraft servers can leak player data, are brute-forced for admin accounts, and vulnerable plugin stacks expose RCE/DoS.',
    cves: ['CVE-2021-3854', 'CWE-798', 'CWE-400'],
    vector: 'Network: TCP/25565 open; Minecraft protocol reachable, RCON/admin brute-forceable.',
    steps: [
      'Handshake: python or mcstatus to query server → version, MOTD, player list, mods',
      'RCON check: if RCON enabled (default port 25575), brute-force admin password (authorized only)',
      'Plugin/version CVEs: map the modpack/plugin list to known CVEs (Log4Shell family)',
      'Look for console exposure and offline-mode (cracked) servers leaking identities',
    ],
  },
};

const VULN_RISK_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-300 bg-red-500/20 border-red-500/40',
  HIGH: 'text-orange-300 bg-orange-500/15 border-orange-500/40',
  MEDIUM: 'text-yellow-300 bg-yellow-500/10 border-yellow-500/40',
};

// Live Threat Timeline Data Generator
const generateTimelineData = (): TimelineEvent[] => {
  const events: TimelineEvent[] = [];
  const now = new Date();
  
  const threatTypes = [
    { event: 'New malware sample detected in wild', type: 'threat' as const, severity: 'HIGH' as Severity },
    { event: 'Suspicious IP address flagged by sensors', type: 'ioc' as const, severity: 'MEDIUM' as Severity },
    { event: 'Domain resolution change detected', type: 'analysis' as const, severity: 'LOW' as Severity },
    { event: 'Threat feed update received (CISA)', type: 'system' as const },
    { event: 'Critical CVE published to NVD', type: 'alert' as const, severity: 'CRITICAL' as Severity },
    { event: 'Phishing campaign targeting finance sector', type: 'threat' as const, severity: 'HIGH' as Severity },
    { event: 'IOC added to watchlist', type: 'ioc' as const, severity: 'MEDIUM' as Severity },
    { event: 'Dark web marketplace activity spike', type: 'threat' as const, severity: 'HIGH' as Severity },
    { event: 'SSL certificate expiration warning', type: 'alert' as const, severity: 'LOW' as Severity },
    { event: 'Botnet C2 communication detected', type: 'threat' as const, severity: 'CRITICAL' as Severity },
    { event: 'Data breach notification received', type: 'alert' as const, severity: 'CRITICAL' as Severity },
    { event: 'Zero-day exploit being traded', type: 'threat' as const, severity: 'CRITICAL' as Severity }
  ];
  
  for (let i = 0; i < 20; i++) {
    const timeOffset = Math.floor(Math.random() * 60);
    const threat = threatTypes[Math.floor(Math.random() * threatTypes.length)];
    events.push({
      time: new Date(now.getTime() - timeOffset * 60000).toLocaleTimeString(),
      ...threat
    });
  }
  
  return events.sort((a, b) => new Date(`2000/01/01 ${b.time}`).getTime() - new Date(`2000/01/01 ${a.time}`).getTime());
};

// ==================== NAVIGATION STRUCTURE ====================
interface NavItem { id: TabType; label: string; icon: React.ComponentType<{ className?: string }>; color: string; badge?: string; }
interface NavCategory { name: string; emoji: string; items: NavItem[]; }

const NAV_CATEGORIES: NavCategory[] = [
  {
    name: 'Infrastructure & Network', emoji: '🌐',
    items: [
      { id: 'ip', label: 'IP Intel', icon: Globe, color: 'text-green-400' },
      { id: 'domain', label: 'Domain Intel', icon: Server, color: 'text-purple-400' },
      { id: 'forensics', label: 'Domain Forensics', icon: Camera, color: 'text-red-400' },
      { id: 'dnsdump', label: 'DNS Dump', icon: Network, color: 'text-teal-400' },
      { id: 'url', label: 'URL Scanner', icon: ExternalLink, color: 'text-yellow-400' },
      { id: 'sandbox', label: 'URL Sandbox', icon: Zap, color: 'text-lime-400' },
      { id: 'takedown', label: 'TakeDown URL', icon: Send, color: 'text-orange-400' },
    ],
  },
  {
    name: 'OSINT & Surface Monitoring', emoji: '🕵️',
    items: [
      { id: 'darkweb', label: 'Deep & Dark Web', icon: Skull, color: 'text-red-500' },
      { id: 'social', label: 'Telegram & Discord Monitor', icon: MessageSquare, color: 'text-blue-400' },
      { id: 'brand', label: 'Brand Protection', icon: ShieldAlert, color: 'text-rose-400' },
      { id: 'exec-protection', label: 'Executive Protection', icon: ShieldUser, color: 'text-amber-400' },
      { id: 'fakeapp', label: 'Fake App Scanner', icon: Smartphone, color: 'text-fuchsia-400' },
    ],
  },
  {
    name: 'Technical Analysis & Vulnerabilities', emoji: '🔬',
    items: [
      { id: 'hash', label: 'Hash Lookup', icon: Fingerprint, color: 'text-cyan-400' },
      { id: 'cve', label: 'CVE Database', icon: Shield, color: 'text-orange-400' },
      { id: 'mobile', label: 'Mobile Security', icon: Smartphone, color: 'text-indigo-400' },
    ],
  },
  {
    name: 'Threat Intelligence & AI', emoji: '⚡',
    items: [
      { id: 'threats', label: 'Threat Feeds', icon: AlertTriangle, color: 'text-amber-400' },
      { id: 'iocs', label: 'IOC Manager', icon: Database, color: 'text-emerald-400' },
      { id: 'sources', label: 'Intelligence Sources', icon: Wifi, color: 'text-sky-400' },
      { id: 'ai', label: 'AI Analyst', icon: Cpu, color: 'text-pink-400' },
    ],
  },
  {
    name: 'Reporting & Exports', emoji: '📊',
    items: [
      { id: 'reports', label: 'Reports', icon: FileText, color: 'text-violet-400' },
      { id: 'export', label: 'Export Data', icon: Download, color: 'text-teal-400' },
    ],
  },
];

// ==================== MAIN COMPONENT ====================
export default function OSINTPlatform() {
  // Core State
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [loading, setLoading] = useState(false);
  const [apiData, setApiData] = useState<APIResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [selectedIOC, setSelectedIOC] = useState<IOC | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [modalType, setModalType] = useState<'detail' | 'edit' | 'add'>('detail');
  // Per-module search isolation: each tab keeps its own term; nothing persists
  // globally after execution (requirement: no cross-module state/caching leaks).
  const [searchTerms, setSearchTerms] = useState<Record<string, string>>({});
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);
  const [ipQueue, setIpQueue] = useState<IpQueueEntry[]>([]);

  // Clear apiData when switching tabs to prevent cross-module data leakage
  useEffect(() => {
    setApiData(null);
  }, [activeTab]);

  // Load executives when exec-protection tab is active
  useEffect(() => {
    if (activeTab === 'exec-protection') {
      loadExecutives();
    }
  }, [activeTab]);
  const [selectedQueue, setSelectedQueue] = useState<Set<string>>(new Set());
  const [showDnsblDetail, setShowDnsblDetail] = useState(false);
  const [showEnrichment, setShowEnrichment] = useState(false);
  const [openArtifact, setOpenArtifact] = useState<string | null>('timestamps');
  
  // Input State — isolated per module (activeTab), reset after execution
  const inputValue = searchTerms[activeTab] ?? '';
  const setInputValue = (v: string) => setSearchTerms((t) => ({ ...t, [activeTab]: v }));
  const searchQuery = searchTerms.iocs ?? '';
  const setSearchQuery = (v: string) => setSearchTerms((t) => ({ ...t, iocs: v }));
  const [formData, setFormData] = useState({
    type: 'IP',
    value: '',
    description: '',
    severity: 'MEDIUM',
    status: 'UNKNOWN',
    tags: [] as string[]
  });
  
  // Timeline State
  const [timelineData, setTimelineData] = useState<TimelineEvent[]>(generateTimelineData());
  const [timelineRunning, setTimelineRunning] = useState(true);
  const timelineInterval = useRef<NodeJS.Timeout | null>(null);

  // Sidebar Category State (collapsed by default except the active category)
  const [collapsedCats, setCollapsedCats] = useState<Record<string, boolean>>({});

  const isCatCollapsed = (cat: NavCategory) => {
    // If user explicitly toggled this category, respect that choice
    if (cat.name in collapsedCats) {
      return collapsedCats[cat.name];
    }
    // Default: expand if active tab is in this category, otherwise collapsed
    return cat.items.some((i) => i.id === activeTab) ? false : true;
  };

  const toggleCat = (cat: NavCategory) =>
    setCollapsedCats((prev) => ({ ...prev, [cat.name]: !isCatCollapsed(cat) }));
  
  // Report Config State
  const [reportConfig, setReportConfig] = useState({
    title: '',
    modules: [] as string[],
    format: 'PDF',
    includeIOCs: true,
    includeThreats: true,
    includeTimeline: true,
    executiveSummary: true,
    recommendations: true
  });

  // New source form state
  const [newSource, setNewSource] = useState({
    name: '',
    type: 'CUSTOM',
    method: 'GET',
    endpoint: '',
    apiKeyEnv: '',
    description: ''
  });
  
  // Forensics Results
  const [forensicsHistory, setForensicsHistory] = useState<any[]>([]);
  const [selectedForensics, setSelectedForensics] = useState<any>(null);
  const [attributionExpanded, setAttributionExpanded] = useState(false);
  const [fuzzingExpanded, setFuzzingExpanded] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<{ id: string; name: string } | null>(null);
  const [loadConfirm, setLoadConfirm] = useState<{ id: string; name: string } | null>(null);
  const [wgetZipLoading, setWgetZipLoading] = useState(false);
  const [storageHealth, setStorageHealth] = useState<any>(null);

  // ============ Forensics local history (localStorage, reliable w/o KV) ============
  const LOCAL_HISTORY_KEY = 'nexus_forensics_local';

  const localHistoryLoad = (): any[] => {
    try {
      const raw = window.localStorage.getItem(LOCAL_HISTORY_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch { return []; }
  };
  const localHistorySave = (items: any[]) => {
    try { window.localStorage.setItem(LOCAL_HISTORY_KEY, JSON.stringify(items.slice(0, 40))); } catch {}
  };
  const localHistoryAdd = (analysis: any) => {
    const items = localHistoryLoad().filter((i: any) => i.name !== analysis.name);
    items.unshift(analysis);
    localHistorySave(items);
  };
  const localHistoryRemove = (name: string) => {
    localHistorySave(localHistoryLoad().filter((i: any) => i.name !== name));
  };
  const toListRow = (data: any) => ({
    id: data.id,
    name: data.name,
    domain: data.domain,
    ip: data.ip,
    asn: data.asn,
    isp: data.isp,
    created: data.timestamp,
    riskLevel: data.risk?.level,
    score: data.risk?.score,
    kits: data.artifacts?.filter((a: any) => a.category === 'phishing_kit' && a.downloaded).length || 0,
    databases: data.artifacts?.filter((a: any) => a.category === 'database' && a.downloaded).length || 0,
    pagesCrawled: 0,
    fuzzed: data.fuzzingSummary?.totalProbed || 0,
    exposed: data.fuzzingSummary?.exposed || 0,
    _local: data,
  });

  const downloadNodeContent = async (url: string) => {
    if (!url) return;
    showFeedback('Descargando contenido...', 'info');
    try {
      const res = await fetch(`/api/osint/forensics?action=content&url=${encodeURIComponent(url)}&module=forensics`);
      if (!res.ok) { showFeedback(`Descarga fallida (${res.status})`, 'error'); return; }
      const blob = await res.blob();
      const cd = res.headers.get('content-disposition') || '';
      const fname = (cd.match(/filename="?([^";]+)/i)?.[1] || url.split('/').filter(Boolean).pop() || 'resource').trim();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = fname.replace(/[\\/:*?"<>|]/g, '_') || 'resource';
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      showFeedback('Contenido descargado', 'success');
    } catch {
      showFeedback('Descarga fallida', 'error');
    }
  };

  const handleForensicReport = async () => {
    const data = apiData?.data;
    if (!data) { showFeedback('Sin datos de análisis para exportar', 'error'); return; }
    showFeedback('Generando informe imprimible...', 'info');
    try {
      const res = await fetch('/api/osint/forensics/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: data.domain, data, module: 'forensics' }),
      });
      if (!res.ok) { showFeedback('Error generando el informe', 'error'); return; }
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `informe_forense_${data.domain.replace(/[^a-zA-Z0-9._-]/g, '_')}.html`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      showFeedback('Informe forense descargado', 'success');
    } catch {
      showFeedback('Error generando el informe', 'error');
    }
  };

  const handleWgetZip = async () => {
    const tree = apiData?.data?.resourceTree;
    const domain = apiData?.data?.domain;
    if (!tree || !domain) return;
    const urls: { url: string; name: string }[] = [];
    const seen = new Set<string>();
    const walk = (n: any) => {
      if (n?.url && /^https?:\/\//i.test(n.url) && n.status && n.status >= 200 && n.status < 400 && n.type !== 'redirect') {
        const k = n.url.split('?')[0];
        if (!seen.has(k)) {
          seen.add(k);
          urls.push({ url: n.url, name: n.name || n.url.split('/').filter(Boolean).pop() || 'index.html' });
        }
      }
      n?.children?.forEach(walk);
    };
    walk(tree);
    if (urls.length === 0) { showFeedback('No hay rutas descargables', 'error'); return; }
    setWgetZipLoading(true);
    showFeedback(`Descargando contenido de ${urls.length} rutas (wget-style)...`, 'info');
    try {
      const res = await fetch('/api/osint/forensics', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'wget', domain, urls: urls.slice(0, 100), module: 'forensics' }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => null);
        showFeedback(err?.error || 'Generación ZIP fallida', 'error');
        return;
      }
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `analisis_${domain.replace(/[^a-zA-Z0-9._-]/g, '_')}_wget.zip`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      showFeedback(`ZIP descargado (${(blob.size / 1024).toFixed(1)} KB)`, 'success');
    } catch {
      showFeedback('Generación ZIP fallida', 'error');
    } finally {
      setWgetZipLoading(false);
    }
  };

  // DNS Dump UI state
  const [dnsdumpType, setDnsdumpType] = useState('ALL');
  const [dnsdumpFilter, setDnsdumpFilter] = useState('');
  const [dnsdumpShowSafe, setDnsdumpShowSafe] = useState(false);

  // Generated Reports History
  const [reports, setReports] = useState<any[]>([]);

  // Intelligence Sources
  const [sources, setSources] = useState<any[]>([]);
  const [sourceHealth, setSourceHealth] = useState<any[]>([]);

  // Initialize and load data
  useEffect(() => {
    loadIOCs();
    loadForensicsHistory();
    getStorageHealth();
  }, []);

  // Persistent IP analysis queue (localStorage, FIFO, max 20)
  useEffect(() => {
    try {
      const raw = localStorage.getItem('nexus-ip-queue');
      if (raw) setIpQueue((JSON.parse(raw) || []).slice(0, QUEUE_MAX));
    } catch (e) {
      console.error('Load IP queue error:', e);
    }
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem('nexus-ip-queue', JSON.stringify(ipQueue));
    } catch (e) {
      console.error('Save IP queue error:', e);
    }
  }, [ipQueue]);

  // Timeline auto-refresh
  useEffect(() => {
    if (timelineRunning) {
      timelineInterval.current = setInterval(() => {
        setTimelineData(prev => {
          const newEvent: TimelineEvent = {
            time: new Date().toLocaleTimeString(),
            event: [
              'Threat intelligence feed updated',
              'New IOC detected by automated systems',
              'Network anomaly flagged for review',
              'Security scan completed',
              'Threat actor activity monitored'
            ][Math.floor(Math.random() * 5)],
            type: ['threat', 'ioc', 'analysis', 'system'][Math.floor(Math.random() * 4)] as any
          };
          return [newEvent, ...prev.slice(0, 49)];
        });
      }, 5000);
    } else if (timelineInterval.current) {
      clearInterval(timelineInterval.current);
    }
    
    return () => {
      if (timelineInterval.current) {
        clearInterval(timelineInterval.current);
      }
    };
  }, [timelineRunning]);

  // Clear feedback after delay
  useEffect(() => {
    if (actionFeedback) {
      const timer = setTimeout(() => setActionFeedback(null), 4000);
      return () => clearTimeout(timer);
    }
  }, [actionFeedback]);

  // Load IOCs on tab change
  useEffect(() => {
    if (['iocs', 'dashboard', 'export', 'reports'].includes(activeTab)) {
      loadIOCs();
    }
    if (activeTab === 'reports') loadReports();
    if (activeTab === 'sources') loadSources();
  }, [activeTab]);

  // ==================== API FUNCTIONS ====================
  const showFeedback = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
    setActionFeedback(`${type.toUpperCase()}: ${message}`);
  };

  const callAPI = async (endpoint: string, options?: RequestInit): Promise<APIResponse> => {
    setLoading(true);
    setError(null);
    showFeedback('Connecting to API...', 'info');

    // Per-module scoping: inject originating module so no generalized
    // state/cache leaks between modules (ip_risk, scanner, forensics, ...).
    let finalEndpoint = endpoint;
    const finalOptions: RequestInit = options ? { ...options } : {};
    const method = (finalOptions.method || 'GET').toUpperCase();
    try {
      if (method === 'GET') {
        finalEndpoint = `${finalEndpoint}${finalEndpoint.includes('?') ? '&' : '?'}module=${encodeURIComponent(activeTab)}`;
      } else {
        let body: any = null;
        try { body = finalOptions.body ? JSON.parse(finalOptions.body as string) : null; } catch { body = null; }
        if (body && typeof body === 'object' && !body.module) {
          body.module = activeTab;
          finalOptions.body = JSON.stringify(body);
        }
      }

      const response = await fetch(finalEndpoint, {
        ...finalOptions,
        headers: {
          'Content-Type': 'application/json',
          ...options?.headers
        }
      });
      
      const data = await response.json();
      setApiData(data);
      
      if (!data.success) {
        setError(data.error || data.details || data.message || 'Unknown error');
        showFeedback(`Error: ${data.error || data.message || 'API returned error'}`, 'error');
      } else {
        showFeedback(`Success! Data from ${data.source || 'API'}`, 'success');
        
        if (options?.method === 'POST' || options?.method === 'DELETE' || options?.method === 'PATCH') {
          setTimeout(() => loadIOCs(), 500);
        }
        // Reset current module's search term: the executed query must not stay
        // persistent in any global context.
        setSearchTerms((t) => {
          if (!t[activeTab]) return t;
          const next = { ...t };
          delete next[activeTab];
          return next;
        });
      }
      
      return data;
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Network error';
      setError(errorMsg);
      showFeedback(`Network Error: ${errorMsg}`, 'error');
      return { success: false, error: errorMsg };
    } finally {
      setLoading(false);
    }
  };

  const loadIOCs = async () => {
    try {
      const params = new URLSearchParams();
      if (searchQuery) params.set('search', searchQuery);
      params.set('module', 'iocs');
      
      const response = await fetch(`/api/osint/iocs?${params}`);
      const result = await response.json();
      
      if (result.success) {
        setIocs(result.data || []);
      }
    } catch (err) {
      console.error('Load IOCs error:', err);
    }
  };

  // IOC search: executes the query AND resets the module's term afterwards so
  // the executed parameter never persists in any global/context state.
  const searchIOCs = async () => {
    await loadIOCs();
    setSearchTerms((t) => {
      if (!t.iocs) return t;
      const next = { ...t };
      delete next.iocs;
      return next;
    });
  };

  const getStorageHealth = async () => {
    try {
      const response = await fetch(`/api/osint/forensics?action=health&_=${Date.now()}&module=forensics`);
      const result = await response.json();
      if (result.success) setStorageHealth(result);
    } catch { /* ignore */ }
  };

  const loadForensicsHistory = async () => {
    const localRows = localHistoryLoad().map(toListRow);
    try {
      const response = await fetch(`/api/osint/forensics?action=list&_=${Date.now()}&module=forensics`);
      const result = await response.json();
      if (result.success && Array.isArray(result.data)) {
        const remoteByName = new Map<string, any>(result.data.map((r: any) => [String(r.name), r] as [string, any]));
        const merged = [...localRows];
        for (const [name, row] of remoteByName) {
          if (!merged.some((m: any) => m.name === name)) merged.push(row);
        }
        merged.sort((a: any, b: any) => new Date(b.created || 0).getTime() - new Date(a.created || 0).getTime());
        setForensicsHistory(merged);
        return;
      }
    } catch { /* backend unavailable — local only */ }
    setForensicsHistory(localRows);
  };

  // ==================== HANDLER FUNCTIONS ====================
  
  // IP Intelligence Handler
  const handleIPRecon = async () => {
    if (!inputValue) {
      showFeedback('Enter an IP address', 'error');
      return;
    }
    showFeedback(`Analyzing IP: ${inputValue}...`, 'info');
    await callAPI(`/api/osint/ip?ip=${encodeURIComponent(inputValue)}`);
  };

  // Domain Analysis Handler
  const handleDomainRecon = async (domain?: string) => {
    const target = domain || inputValue;
    if (!target) {
      showFeedback('Enter a domain', 'error');
      return;
    }
    showFeedback(`Resolving domain: ${target}...`, 'info');
    await callAPI(`/api/osint/domain?domain=${encodeURIComponent(target)}`);
  };

  // URL Scanner Handler
  const handleURLAnalysis = async (url?: string) => {
    const target = url || inputValue;
    if (!target) {
      showFeedback('Enter a URL', 'error');
      return;
    }
    showFeedback(`Scanning URL: ${target}...`, 'info');
    await callAPI(`/api/osint/url?url=${encodeURIComponent(target)}`);
  };

  // Hash Lookup Handler
  const handleHashLookup = async () => {
    if (!inputValue) {
      showFeedback('Enter a hash (MD5/SHA)', 'error');
      return;
    }
    showFeedback(`Looking up hash...`, 'info');
    await callAPI(`/api/osint/hash?hash=${encodeURIComponent(inputValue)}`);
  };

  // CVE Database Handler
  const handleCVESearch = async () => {
    if (!inputValue) {
      showFeedback('Enter CVE ID or keyword', 'error');
      return;
    }
    const isCVE = inputValue.toUpperCase().startsWith('CVE-');
    const endpoint = isCVE 
      ? `/api/osint/cve?cveId=${encodeURIComponent(inputValue)}`
      : `/api/osint/cve?keyword=${encodeURIComponent(inputValue)}`;
    showFeedback(`Searching NIST NVD: ${inputValue}...`, 'info');
    await callAPI(endpoint);
  };

  // AI Analyst Handler
  const handleAIAnalysis = async () => {
    if (!inputValue) {
      showFeedback('Enter target for AI analysis', 'error');
      return;
    }
    showFeedback('Running AI analysis...', 'info');
    await callAPI('/api/osint/ai', {
      method: 'POST',
      body: JSON.stringify({ target: inputValue, type: detectInputType(inputValue) })
    });
  };

  // Dark Web Search Handler — búsqueda real en deep/dark web vía API IntelX
  const handleDarkWebSearch = async () => {
    const query = (inputValue || '').trim().slice(0, 200);
    if (!query) { showFeedback('Introduce un dominio, email, IP o dirección BTC', 'error'); return; }
    setLoading(true);
    setError(null);
    showFeedback(`Buscando en deep/dark web (IntelligenceX): ${query}...`, 'info');
    await callAPI('/api/osint/darkweb', {
      method: 'POST',
      body: JSON.stringify({ query, useAI: true, live: true })
    });
  };

  // Mobile Analysis Handler
  const handleMobileAnalysis = async () => {
    const fileName = inputValue || 'sample-app.apk';
    const fileType = fileName.endsWith('.ipa') ? 'IPA' : 
                     fileName.endsWith('.appx') ? 'APPX' : 'APK';
    
    showFeedback(`Analyzing mobile app: ${fileName}...`, 'info');
    await callAPI('/api/osint/mobile', {
      method: 'POST',
      body: JSON.stringify({ fileName, fileType, useAI: true })
    });
  };

  // Domain Forensics Handler (Full Lookyloo-style)
  const handleForensicAnalysis = async (domainArg?: string) => {
    const target = (domainArg || inputValue || '').trim();
    if (!target) {
      showFeedback('Enter a domain for forensic analysis', 'error');
      return;
    }

    const cleanDomain = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    showFeedback(`Starting advanced forensics of ${cleanDomain}... fuzzing paths, scanning kits/databases, attributing actors`, 'info');

    const result = await callAPI('/api/osint/forensics', {
      method: 'POST',
      body: JSON.stringify({
        domain: cleanDomain,
        options: {
          dns: true,
          whois: true,
          directories: true,
          headers: true,
          ssl: true,
          capture: true,
          subdomains: true
        }
      })
    });

    if (result.success) {
      if (result.data) localHistoryAdd(result.data);
      loadForensicsHistory();
    }
  };

  // Threat Feeds Handler
  const handleThreatFeedLoad = async (feed?: string) => {
    const feedName = feed || 'ALL';
    showFeedback(`Loading threat feed: ${feedName}...`, 'info');
    
    const endpoint = feed ? `/api/osint/threats?feed=${feed}&limit=20` : '/api/osint/threats?limit=20';
    const result = await callAPI(endpoint);
    
    // Show sample data if APIs are restricted
    if (result.success && !result.feeds?.length && !result.error) {
      const sampleData = {
        success: true,
        feeds: [
          { source: 'CISA KEV Catalog', type: 'Known Exploited Vulnerabilities', count: 3, status: 'active', entries: [
            { cveID: 'CVE-2024-3400', product: 'PAN-OS', vulnerabilityName: 'Command Injection', dateAdded: '2024-04-12' },
            { cveID: 'CVE-2024-21887', product: 'Connect Secure', vulnerabilityName: 'RCE via Request Smuggling', dateAdded: '2024-01-25' },
            { cveID: 'CVE-2023-44428', product: 'NetScaler ADC', vulnerabilityName: 'Unauthenticated RCE', dateAdded: '2023-10-15' }
          ]},
          { source: 'MalwareBazaar', type: 'Recent Malware Samples', count: 3, status: 'active', entries: [
            { sha256: 'a1b2c3d4e5f6...', file_type: 'PE32+ executable', signature: 'Emotet', first_seen: '2024-07-20' },
            { sha256: 'f7e8d9c0b1a2...', file_type: 'PDF document', signature: 'Phishing PDF', first_seen: '2024-07-18' },
            { sha256: 'm3n4o5p6q7r8...', file_type: 'Office doc', signature: 'TrickBot Loader', first_seen: '2024-07-19' }
          ]}
        ],
        message: 'Showing sample threat intelligence data'
      };
      setApiData(prev => ({ ...prev, ...sampleData }));
    }
  };

  // ==================== BRAND PROTECTION ====================
  const handleBrandScan = async () => {
    if (!inputValue) { showFeedback('Enter a suspicious URL/domain to check', 'error'); return; }
    const brand = prompt('Enter the brand to protect (e.g., PayPal, BancoX):') || 'Acme';
    showFeedback(`Scanning "${inputValue}" against brand ${brand}...`, 'info');
    await callAPI('/api/osint/brand', { method: 'POST', body: JSON.stringify({ brand, candidate: inputValue, mode: 'scan' }) });
  };

  const handleBrandWatchlist = async () => {
    const brand = prompt('Brand to add to watchlist:') || 'Acme';
    showFeedback(`Adding brand "${brand}" to protection watchlist...`, 'info');
    const result = await callAPI('/api/osint/brand', { method: 'POST', body: JSON.stringify({ brand, mode: 'watchlist', domains: [], keywords: [] }) });
    if (result?.success) showFeedback(`Brand "${brand}" watched`, 'success');
  };

  // ==================== URL SANDBOX ====================
  const handleSandbox = async (url?: string) => {
    const target = url || inputValue;
    if (!target) { showFeedback('Enter a URL to detonate', 'error'); return; }
    showFeedback(`Detonating ${target} in sandbox...`, 'info');
    await callAPI('/api/osint/sandbox', { method: 'POST', body: JSON.stringify({ url: target }) });
  };

  // ==================== DNS DUMP ====================
  const handleDnsDump = async () => {
    if (!inputValue) { showFeedback('Enter a domain to enumerate', 'error'); return; }
    showFeedback(`Enumerating DNS for ${inputValue}...`, 'info');
    await callAPI(`/api/osint/dnsdump?domain=${encodeURIComponent(inputValue)}`);
  };

  const exportDnsCsv = () => {
    const d = apiData?.data;
    if (!d) { showFeedback('Sin resultados para exportar', 'error'); return; }
    const rows: string[][] = [];
    rows.push([`NEXUS OSINT DNS DUMP`, d.domain, new Date().toISOString()]);
    rows.push([]);
    rows.push(['TYPE', 'NAME', 'TTL', 'DATA']);
    (d.allRecords || []).forEach((r: any) => rows.push([r.type, r.name, String(r.ttl ?? ''), String(r.data ?? '')]));
    rows.push([]);
    rows.push(['SUBDOMAIN', 'SOURCE', 'FIRST_SEEN', 'LAST_SEEN', 'IPS', 'CNAME']);
    (d.subdomainInfo || []).forEach((s: any) => rows.push([s.name, s.source || '', s.firstSeen || '', s.lastSeen || '', (s.ips || []).join('; '), s.cname || '']));
    rows.push([]);
    rows.push(['HOST', 'IP', 'ASN', 'PROVIDER', 'COUNTRY']);
    (d.ipMap || []).forEach((m: any) => rows.push([m.host, m.ip, m.asn || '', m.provider || m.isp || '', m.country || '']));
    rows.push([]);
    rows.push(['TAKEOVER', 'CNAME', 'SERVICE', 'STATUS', 'REASON']);
    (d.takeovers || []).forEach((t: any) => rows.push([t.subdomain, t.cname, t.service, t.status, t.reason]));
    rows.push([]);
    rows.push(['PASSIVE_DNS', 'FIRST_SEEN', 'LAST_SEEN', 'DAYS_KNOWN']);
    (d.passiveDns || []).forEach((p: any) => rows.push([p.name, p.firstSeen || '', p.lastSeen || '', String(p.daysKnown ?? '')]));
    const csv = rows.map((r) => r.map((c) => `"${String(c ?? '').replace(/"/g, '""')}"`).join(',')).join('\r\n');
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dns_dump_${String(d.domain).replace(/[^a-zA-Z0-9._-]/g, '_')}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    showFeedback('CSV exportado correctamente', 'success');
  };

  const handleDnsDumpReport = async () => {
    const data = apiData?.data;
    if (!data) { showFeedback('Sin datos DNS para exportar', 'error'); return; }
    showFeedback('Generando informe imprimible...', 'info');
    try {
      const res = await fetch('/api/osint/dnsdump/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: data.domain, data, module: 'dnsdump' }),
      });
      if (!res.ok) { showFeedback('Error generando el informe', 'error'); return; }
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `informe_dnsdump_${data.domain.replace(/[^a-zA-Z0-9._-]/g, '_')}.html`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      showFeedback('Informe DNS Dump descargado', 'success');
    } catch {
      showFeedback('Error generando el informe', 'error');
    }
  };

  const handleUrlScanReport = async () => {
    const data = apiData?.data;
    if (!data) { showFeedback('Sin datos de escaneo para exportar', 'error'); return; }
    showFeedback('Generando informe imprimible...', 'info');
    try {
      const res = await fetch('/api/osint/url/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: data.url, data, virusTotal: apiData?.virusTotal || null, module: 'url' }),
      });
      if (!res.ok) { showFeedback('Error generando el informe', 'error'); return; }
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `informe_urlscan_${data.host || data.url}`.replace(/[^a-zA-Z0-9._-]/g, '_') + '.html';
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      showFeedback('Informe URL Scanner descargado', 'success');
    } catch {
      showFeedback('Error generando el informe', 'error');
    }
  };

  const handleSandboxReport = async () => {
    const data = apiData?.data;
    if (!data) { showFeedback('Sin datos de detonación para exportar', 'error'); return; }
    showFeedback('Generando informe imprimible...', 'info');
    try {
      const res = await fetch('/api/osint/sandbox/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: data.url, data, module: 'sandbox' }),
      });
      if (!res.ok) { showFeedback('Error generando el informe', 'error'); return; }
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `informe_urlsandbox_${data.host || data.url}`.replace(/[^a-zA-Z0-9._-]/g, '_') + '.html';
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      showFeedback('Informe URL Sandbox descargado', 'success');
    } catch {
      showFeedback('Error generando el informe', 'error');
    }
  };

  // ==================== SOCIAL MONITOR ====================
  const handleSocialLoad = async (q?: string) => {
    showFeedback('Loading Telegram/Discord intelligence...', 'info');
    const params = new URLSearchParams();
    if (q) params.set('q', q);
    await callAPI(`/api/osint/social?${params}`);
  };

  const handleSocialKeywords = async () => {
    const raw = prompt('Keywords (comma separated):') || 'phishing,malware,breach';
    const keywords = raw.split(',').map((k) => k.trim()).filter(Boolean);
    showFeedback(`Setting ${keywords.length} monitoring keywords...`, 'info');
    await callAPI('/api/osint/social', { method: 'POST', body: JSON.stringify({ action: 'set-keywords', keywords }) });
  };

  // ==================== EXECUTIVE OSINT ====================
  // ==================== FAKE APP ====================
  const handleFakeApp = async () => {
    if (!inputValue) { showFeedback('Enter a direct APK download URL to analyze', 'error'); return; }
    showFeedback(`Downloading and statically analyzing APK...`, 'info');
    await callAPI('/api/osint/fakeapp', { method: 'POST', body: JSON.stringify({ url: inputValue }) });
  };

  const fakeAppFileRef = useRef<HTMLInputElement>(null);
  const [fakeAppFileName, setFakeAppFileName] = useState('');
  const [fakeAppFile, setFakeAppFile] = useState<File | null>(null);
  const [fakeAppAnalyzing, setFakeAppAnalyzing] = useState(false);

  const handleFakeAppFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] || null;
    setFakeAppFile(file);
    setFakeAppFileName(file ? file.name : '');
  };

  const handleFakeAppUpload = async () => {
    const file = fakeAppFile;
    if (!file) { showFeedback('Select a file to upload (APK / XAPK / AAB / APKS / IPA / APPX / ZIP)', 'error'); return; }
    setFakeAppAnalyzing(true);
    setError(null);
    showFeedback(`Analyzing "${file.name}" locally in your browser (${(file.size / 1048576).toFixed(1)} MB)...`, 'info');
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const analysis = await analyzeApkBytes(bytes, { apkUrl: 'upload://' + file.name, fileName: file.name });
      setApiData({ success: true, source: 'Fake-App-Scanner (client-side static analysis)', data: analysis as any, message: `Client-side analysis done — ${analysis.verdict} (${analysis.score}/100). Syncing with CVE correlation...` });
      showFeedback(`Client-side analysis complete: ${analysis.verdict} (${analysis.score}/100). Syncing report...`, 'success');
      await callAPI('/api/osint/fakeapp', { method: 'POST', body: JSON.stringify({ action: 'analyze-upload', report: analysis }) });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Upload analysis failed';
      setError(msg);
      showFeedback(`Error: ${msg}`, 'error');
    } finally {
      setFakeAppAnalyzing(false);
    }
};

  // ==================== EXECUTIVE PROTECTION ====================
  const [executives, setExecutives] = useState<any[]>([]);
  const [execMode, setExecMode] = useState<'list' | 'add' | 'edit' | 'detail'>('list');
  const [selectedExec, setSelectedExec] = useState<any>(null);
  const [editingExec, setEditingExec] = useState<any>(null);
  const [dorkResults, setDorkResults] = useState<any>(null);
  const [dorkLoading, setDorkLoading] = useState(false);

  const loadExecutives = async () => {
    try {
      const res = await fetch('/api/osint/exec-protection');
      const data = await res.json();
      if (data.success) setExecutives(data.data);
    } catch (err) {
      console.error('Load executives error:', err);
    }
  };

  const deleteExecutive = async (id: string) => {
    if (!confirm('Delete this executive?')) return;
    try {
      const res = await fetch(`/api/osint/exec-protection?id=${id}`, { method: 'DELETE' });
      const data = await res.json();
      if (data.success) {
        setExecutives(prev => prev.filter(e => e.id !== id));
        showFeedback('Executive deleted', 'success');
      }
    } catch (err) {
      showFeedback('Failed to delete executive', 'error');
    }
  };

  const searchAllDorks = async (executiveId: string) => {
    setDorkLoading(true);
    setDorkResults(null);
    try {
      const res = await fetch('/api/osint/exec-protection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'search-all-dorks', executiveId })
      });
      const data = await res.json();
      if (data.success) {
        setDorkResults(data.data);
        showFeedback('Dork searches generated', 'success');
      }
    } catch (err) {
      showFeedback('Failed to generate dork searches', 'error');
    } finally {
      setDorkLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    showFeedback('Query copied to clipboard', 'success');
  };

  // IOC CRUD Handlers
  const handleAddIOC = async () => {
    if (!formData.value) {
      showFeedback('Enter IOC value', 'error');
      return;
    }
    showFeedback(`Adding ${formData.type}: ${formData.value}...`, 'info');
    await callAPI('/api/osint/iocs', {
      method: 'POST',
      body: JSON.stringify(formData)
    });
    setShowModal(false);
    setFormData({ type: 'IP', value: '', description: '', severity: 'MEDIUM', status: 'UNKNOWN', tags: [] });
  };

  // Add the current analysis result (ip/domain/hash/url) to the IOC store
  const handleAddIOCFromResult = async () => {
    const target = apiData?.data?.ip || apiData?.data?.ipAddress || apiData?.data?.domain || apiData?.data?.hostname || inputValue;
    const detected = detectInputType(target);
    const iocType = detected === 'md5' || detected === 'sha1' || detected === 'sha256' ? 'HASH'
      : detected === 'cve' ? 'CVE'
      : detected === 'url' ? 'URL'
      : detected === 'ip' ? 'IP'
      : 'DOMAIN';
    if (!target) {
      showFeedback('No result to add — run an analysis first', 'error');
      return;
    }

    let severity = 'MEDIUM';
    let status = 'UNKNOWN';
    let description = `Added from ${activeTab} analysis`;
    let tags: string[] = [activeTab, 'from-result'];

    // IP results: carry the DNSBL/blacklist markings from the lookup
    if (iocType === 'IP' && apiData?.reputation) {
      const listed = (apiData.reputation.dnsbl || []).filter((d: any) => d.listed);
      const torExit = apiData.reputation.torExit || false;
      const urlCount = apiData.reputation.urlhaus?.urlCount || 0;
      const blacklisted = listed.length > 0 || torExit || urlCount > 0;
      severity = blacklisted ? 'HIGH' : 'MEDIUM';
      status = blacklisted ? 'SUSPICIOUS' : 'UNKNOWN';
      tags = [activeTab, 'from-result', ...listed.map((d: any) => `dnsbl:${d.name.toLowerCase()}`)];
      if (torExit) tags.push('tor-exit');
      if (urlCount > 0) tags.push(`urlhaus:${urlCount}`);
      const marks = listed.map((d: any) => `${d.name}(${d.records.join(',')})`).join(', ') || 'clean';
      description = `IP ${target} — DNSBL: ${marks}${torExit ? ', Tor exit' : ''}${urlCount > 0 ? `, URLhaus: ${urlCount}` : ''} (multirbl.valli.org check)`;
    }

    showFeedback(`Adding ${iocType}: ${target} to IOCs...`, 'info');
    const result = await callAPI('/api/osint/iocs', {
      method: 'POST',
      body: JSON.stringify({
        type: iocType,
        value: target,
        description,
        severity,
        status,
        tags
      })
    });
    if (result?.success) {
      showFeedback(`Added ${target} to IOCs${severity === 'HIGH' ? ' (blacklisted)' : ''}`, 'success');
      loadIOCs();
    }
    if (iocType === 'IP' && apiData) {
      enqueueIp(buildQueueEntry(apiData));
    }
  };

  // ==================== IP ANALYSIS QUEUE (FIFO, max 20) ====================
  const enqueueIp = (entry: IpQueueEntry) => {
    setIpQueue((prev) => [entry, ...prev.filter((e) => e.ip !== entry.ip)].slice(0, QUEUE_MAX));
  };

  const toggleQueueSelect = (id: string) => {
    setSelectedQueue((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const selectAllQueue = () => {
    setSelectedQueue(new Set(ipQueue.map((e) => e.id)));
  };

  const deleteSelectedFromQueue = () => {
    if (selectedQueue.size === 0) {
      showFeedback('Select at least one IP to remove', 'error');
      return;
    }
    setIpQueue((prev) => prev.filter((e) => !selectedQueue.has(e.id)));
    setSelectedQueue(new Set());
    showFeedback('Selected IPs removed from queue', 'success');
  };

  const clearIpQueue = () => {
    if (!confirm('Clear the entire IP analysis queue?')) return;
    setIpQueue([]);
    setSelectedQueue(new Set());
    showFeedback('Queue cleared', 'success');
  };

  const exportIpQueue = (format: 'csv' | 'json') => {
    if (ipQueue.length === 0) {
      showFeedback('Queue is empty — nothing to export', 'error');
      return;
    }
    const filename = `ip-ioc-queue-${new Date().toISOString().slice(0, 10)}`;
    const triggerDownload = (content: string, mime: string, ext: string) => {
      const blob = new Blob([content], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${filename}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
    };
    if (format === 'json') {
      triggerDownload(JSON.stringify(ipQueue, null, 2), 'application/json', 'json');
    } else {
      const headers = ['ip', 'addedAt', 'severity', 'riskScore', 'abuseScore', 'threatLevel', 'blacklistCount', 'blockedCount', 'torExit', 'urlhausCount', 'category', 'asn', 'isp', 'country', 'flag', 'lastSeen', 'openPorts', 'malware', 'tags', 'description'];
      const esc = (v: any) => `"${String(v ?? '').replace(/"/g, '""')}"`;
      const rows = ipQueue.map((e) =>
        [e.ip, e.addedAt, e.severity, e.riskScore, e.abuseScore, e.threatLevel, e.blacklistCount, e.blockedCount, e.torExit, e.urlhausCount, e.category, e.asn, e.isp, e.country, e.flag, e.lastSeen || '', e.openPorts.join(';'), e.malware || '', e.tags.join(';'), e.description].map(esc).join(',')
      );
      triggerDownload([headers.join(','), ...rows].join('\n'), 'text/csv', 'csv');
    }
    showFeedback(`Exported ${ipQueue.length} IP(s) (${format.toUpperCase()})`, 'success');
  };

  // ==================== FORENSIC ARTIFACT TOOLS ====================
  const copyText = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      showFeedback(`Copied ${label} to clipboard`, 'success');
    } catch {
      showFeedback('Clipboard unavailable in this browser', 'error');
    }
  };

  const copyAllArtifactQueries = async () => {
    const all = FORENSIC_ARTIFACTS.map((a) => `${a.title}\n${a.queries.map((q) => `  [${q.label}] ${q.query}`).join('\n')}`).join('\n\n');
    await copyText(all, 'all forensic queries');
  };

  const scrollToSection = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const downloadForensicChecklist = () => {
    const headers = ['artifact', 'purpose', 'sources', 'fields', 'queries'];
    const esc = (v: any) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const rows = FORENSIC_ARTIFACTS.map((a) =>
      [a.title, a.purpose, a.sources.join(' | '), a.fields.join(' | '), a.queries.map((q) => `[${q.label}] ${q.query}`).join(' | ')].map(esc).join(',')
    );
    const blob = new Blob([[headers.join(','), ...rows].join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic-artifact-checklist-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    showFeedback('Forensic checklist downloaded (CSV)', 'success');
  };

  const downloadTimelineTemplate = () => {
    const headers = ['event_time', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'user_agent', 'session_id', 'dns_query', 'tls_sni', 'notes'];
    const row = ['', '<IP>', '', '', '', 'Mozilla/5.0 ...', '', 'example.com', 'example.com', 'observation'];
    const blob = new Blob([[headers.join(','), row.join(',')].join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `timeline-template-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    showFeedback('Timeline template downloaded (CSV)', 'success');
  };

  const handleUpdateIOC = async () => {
    if (!selectedIOC) return;
    showFeedback(`Updating IOC: ${selectedIOC.value}...`, 'info');
    await callAPI('/api/osint/iocs', {
      method: 'PATCH',
      body: JSON.stringify({
        id: selectedIOC.id,
        description: formData.description,
        severity: formData.severity,
        status: formData.status || selectedIOC.status,
        tags: formData.tags
      })
    });
    setShowModal(false);
    setSelectedIOC(null);
  };

  const handleDeleteIOC = async (id: string) => {
    if (!confirm('Delete this IOC?')) return;
    showFeedback('Deleting IOC...', 'info');
    await callAPI(`/api/osint/iocs?id=${id}`, { method: 'DELETE' });
  };

  // Export Handler
  const handleExport = async (format: string) => {
    showFeedback(`Preparing ${format} export...`, 'info');
    window.open(`/api/osint/export?format=${format}&module=export`, '_blank');
    showFeedback(`${format} export started`, 'success');
  };

  // Report Generation Handler
  const handleGenerateReport = async () => {
    if (!reportConfig.title) {
      showFeedback('Enter report title', 'error');
      return;
    }
    if (reportConfig.modules.length === 0) {
      showFeedback('Select at least one module', 'error');
      return;
    }
    
    showFeedback('Generating report...', 'info');
    await callAPI('/api/osint/reports', {
      method: 'POST',
      body: JSON.stringify(reportConfig)
    });
    loadReports();
  };

  // Load generated reports history
  const loadReports = async () => {
    try {
      const res = await fetch('/api/osint/reports?action=list&module=reports');
      const data = await res.json();
      if (data.success) setReports(data.data || []);
    } catch (e) {
      console.error('Failed to load reports:', e);
    }
  };

  // ==================== INTELLIGENCE SOURCES ====================
  const loadSources = async () => {
    try {
      const [sourcesRes, healthRes] = await Promise.all([
        fetch('/api/osint/sources?module=sources'),
        fetch('/api/osint/sources?action=health&module=sources')
      ]);
      const sourcesData = await sourcesRes.json();
      const healthData = await healthRes.json();
      if (sourcesData.success) setSources(sourcesData.data || []);
      if (healthData.success) setSourceHealth(healthData.data || []);
    } catch (e) {
      console.error('Failed to load sources:', e);
    }
  };

  const handleTestSource = async (id: string) => {
    showFeedback('Testing source connectivity...', 'info');
    try {
      const res = await fetch('/api/osint/sources', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'test', id, module: 'sources' })
      });
      const data = await res.json();
      showFeedback(data.message || (data.success ? 'Source OK' : 'Source failed'), data.success ? 'success' : 'error');
      loadSources();
    } catch (e) {
      showFeedback('Test failed', 'error');
    }
  };

  const handleToggleSource = async (source: any) => {
    try {
      const res = await fetch('/api/osint/sources', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: source.id, enabled: !source.enabled, module: 'sources' })
      });
      const data = await res.json();
      if (data.success) {
        showFeedback(`${source.name} ${source.enabled ? 'disabled' : 'enabled'}`, 'success');
        loadSources();
      }
    } catch (e) {
      showFeedback('Update failed', 'error');
    }
  };

  const handleAddSource = async () => {
    if (!newSource.name || !newSource.endpoint) {
      showFeedback('Name and endpoint required', 'error');
      return;
    }
    showFeedback('Adding source...', 'info');
    try {
      const res = await fetch('/api/osint/sources', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...newSource, module: 'sources' })
      });
      const data = await res.json();
      if (data.success) {
        showFeedback(`Source "${newSource.name}" added`, 'success');
        setNewSource({ name: '', type: 'CUSTOM', method: 'GET', endpoint: '', apiKeyEnv: '', description: '' });
        loadSources();
      } else {
        showFeedback(data.error || 'Failed to add source', 'error');
      }
    } catch (e) {
      showFeedback('Failed to add source', 'error');
    }
  };

  // Modal Handlers
  const openDetailModal = (ioc: IOC) => {
    setSelectedIOC(ioc);
    setModalType('detail');
    setShowModal(true);
  };

  const openEditModal = (ioc: IOC) => {
    setSelectedIOC(ioc);
    setFormData({
      type: ioc.type,
      value: ioc.value,
      description: ioc.description,
      severity: ioc.severity,
      status: ioc.status || 'UNKNOWN',
      tags: ioc.tags
    });
    setModalType('edit');
    setShowModal(true);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    showFeedback('Copied!', 'success');
  };

  // Helpers
  const detectInputType = (value: string): string => {
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) return 'ip';
    if (/^[a-f0-9]{32}$/i.test(value)) return 'md5';
    if (/^[a-f0-9]{40}$/i.test(value)) return 'sha1';
    if (/^[a-f0-9]{64}$/i.test(value)) return 'sha256';
    if (value.toUpperCase().startsWith('CVE-')) return 'cve';
    if (/^https?:\/\//.test(value)) return 'url';
    if (/\.[a-z]{2,}$/.test(value)) return 'domain';
    if (/@/.test(value)) return 'email';
    if (/\.(apk|ipa|appx)$/i.test(value)) return 'mobile';
    return 'general';
  };

  // Chart Data
  const severityChartData = Object.entries(
    iocs.reduce((acc, ioc) => {
      acc[ioc.severity] = (acc[ioc.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>)
  ).map(([name, value]) => ({ name, value }));

  const typeChartData = Object.entries(
    iocs.reduce((acc, ioc) => {
      acc[ioc.type] = (acc[ioc.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>)
  ).map(([name, value]) => ({ name, value }));

  // Module toggle for reports
  const toggleReportModule = (module: string) => {
    setReportConfig(prev => ({
      ...prev,
      modules: prev.modules.includes(module)
        ? prev.modules.filter(m => m !== module)
        : [...prev.modules, module]
    }));
  };

  // ==================== EXECUTIVE PROTECTION FORMS ====================
  const ExecAddForm = ({ onCancel, onSuccess }: { onCancel: () => void; onSuccess: () => void }) => {
    const [form, setForm] = useState({
      documentId: '',
      phone: '',
      emailCorporate: '',
      emailPersonal: '',
      socialMedia: [] as SocialMedia[],
      address: '',
      location: '',
    });
    const [newSocial, setNewSocial] = useState({ platform: '', url: '', username: '' });

    const handleSubmit = async (e: React.FormEvent) => {
      e.preventDefault();
      try {
        const res = await fetch('/api/osint/exec-protection', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...form, socialMedia: form.socialMedia })
        });
        const data = await res.json();
        if (data.success) {
          showFeedback('Executive added successfully', 'success');
          onSuccess();
        } else {
          showFeedback(data.error || 'Failed to add executive', 'error');
        }
      } catch {
        showFeedback('Failed to add executive', 'error');
      }
    };

    const addSocial = () => {
      if (newSocial.platform && newSocial.username) {
        setForm(prev => ({ ...prev, socialMedia: [...prev.socialMedia, newSocial] }));
        setNewSocial({ platform: '', url: '', username: '' });
      }
    };

    const removeSocial = (idx: number) => {
      setForm(prev => ({ ...prev, socialMedia: prev.socialMedia.filter((_, i) => i !== idx) }));
    };

    return (
      <form onSubmit={handleSubmit} className="space-y-4 max-w-4xl mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">ID / Document *</label>
            <input
              value={form.documentId}
              onChange={e => setForm({ ...form, documentId: e.target.value })}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">Phone</label>
            <input
              value={form.phone}
              onChange={e => setForm({ ...form, phone: e.target.value })}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">Email Corporate</label>
            <input
              value={form.emailCorporate}
              onChange={e => setForm({ ...form, emailCorporate: e.target.value })}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-blue-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">Email Personal</label>
            <input
              value={form.emailPersonal}
              onChange={e => setForm({ ...form, emailPersonal: e.target.value })}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-green-500 focus:outline-none"
            />
          </div>
          <div className="md:col-span-2">
            <label className="block text-xs font-medium text-gray-400 mb-1">Address</label>
            <input
              value={form.address}
              onChange={e => setForm({ ...form, address: e.target.value })}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none"
            />
          </div>
          <div className="md:col-span-2">
            <label className="block text-xs font-medium text-gray-400 mb-1">Location (City, Country)</label>
            <input
              value={form.location}
              onChange={e => setForm({ ...form, location: e.target.value })}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none"
            />
          </div>
        </div>

        <div className="border-t border-gray-800 pt-4">
          <div className="flex items-center justify-between mb-3">
            <h4 className="font-medium">Social Media Profiles</h4>
            <button type="button" onClick={addSocial} className="px-3 py-1.5 bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 border border-amber-500/30 rounded text-sm font-medium flex items-center gap-1">
              <Plus className="w-3 h-3" /> Add
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
            <input
              value={newSocial.platform}
              onChange={e => setNewSocial({ ...newSocial, platform: e.target.value })}
              placeholder="Platform (e.g., LinkedIn, Facebook, Twitter, Instagram, TikTok, YouTube, GitHub, Custom)"
              className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none"
            />
            <input
              value={newSocial.url}
              onChange={e => setNewSocial({ ...newSocial, url: e.target.value })}
              placeholder="URL (optional)"
              className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none"
            />
            <input
              value={newSocial.username}
              onChange={e => setNewSocial({ ...newSocial, username: e.target.value })}
              placeholder="Username / Handle *"
              className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none"
            />
          </div>
          {form.socialMedia.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {form.socialMedia.map((sm, idx) => (
                <span key={idx} className="px-3 py-1 bg-gray-700 border border-gray-600 rounded flex items-center gap-2 text-sm">
                  <span className="font-medium">{sm.platform}</span>
                  <span className="text-gray-400">@{sm.username}</span>
                  <button type="button" onClick={() => removeSocial(idx)} className="text-red-400 hover:text-red-300">
                    <X className="w-3 h-3" />
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="flex gap-4 pt-4 border-t border-gray-800">
          <button type="submit" className="px-6 py-3 bg-amber-600 hover:bg-amber-700 text-white rounded-lg font-medium flex items-center gap-2">
            <Save className="w-4 h-4" /> Save Executive
          </button>
          <button type="button" onClick={onCancel} className="px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium flex items-center gap-2">
            <X className="w-4 h-4" /> Cancel
          </button>
        </div>
      </form>
    );
  };

  const ExecEditForm = ({ executive, onCancel, onSuccess }: { executive: any; onCancel: () => void; onSuccess: () => void }) => {
    const [form, setForm] = useState({
      documentId: executive.documentId,
      phone: executive.phone,
      emailCorporate: executive.emailCorporate,
      emailPersonal: executive.emailPersonal,
      socialMedia: executive.socialMedia || [],
      address: executive.address,
      location: executive.location,
    });
    const [newSocial, setNewSocial] = useState({ platform: '', url: '', username: '' });

    const handleSubmit = async (e: React.FormEvent) => {
      e.preventDefault();
      try {
        const res = await fetch('/api/osint/exec-protection', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: executive.id, ...form, socialMedia: form.socialMedia })
        });
        const data = await res.json();
        if (data.success) {
          showFeedback('Executive updated successfully', 'success');
          onSuccess();
        } else {
          showFeedback(data.error || 'Failed to update executive', 'error');
        }
      } catch {
        showFeedback('Failed to update executive', 'error');
      }
    };

    const addSocial = () => {
      if (newSocial.platform && newSocial.username) {
        setForm(prev => ({ ...prev, socialMedia: [...prev.socialMedia, newSocial] }));
        setNewSocial({ platform: '', url: '', username: '' });
      }
    };

    const removeSocial = (idx: number) => {
      setForm(prev => ({ ...prev, socialMedia: prev.socialMedia.filter((_, i) => i !== idx) }));
    };

    return (
      <form onSubmit={handleSubmit} className="space-y-4 max-w-4xl mx-auto">
        <div className="flex items-center gap-3 mb-4">
          <h3 className="text-lg font-semibold">Editing: {executive.documentId}</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">ID / Document *</label>
            <input
              value={form.documentId}
              onChange={e => setForm({ ...form, documentId: e.target.value })}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">Phone</label>
            <input
              value={form.phone}
              onChange={e => setForm({ ...form, phone: e.target.value })}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">Email Corporate</label>
            <input
              value={form.emailCorporate}
              onChange={e => setForm({ ...form, emailCorporate: e.target.value })}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-blue-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">Email Personal</label>
            <input
              value={form.emailPersonal}
              onChange={e => setForm({ ...form, emailPersonal: e.target.value })}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-green-500 focus:outline-none"
            />
          </div>
          <div className="md:col-span-2">
            <label className="block text-xs font-medium text-gray-400 mb-1">Address</label>
            <input
              value={form.address}
              onChange={e => setForm({ ...form, address: e.target.value })}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none"
            />
          </div>
          <div className="md:col-span-2">
            <label className="block text-xs font-medium text-gray-400 mb-1">Location (City, Country)</label>
            <input
              value={form.location}
              onChange={e => setForm({ ...form, location: e.target.value })}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none"
            />
          </div>
        </div>

        <div className="border-t border-gray-800 pt-4">
          <div className="flex items-center justify-between mb-3">
            <h4 className="font-medium">Social Media Profiles</h4>
            <button type="button" onClick={addSocial} className="px-3 py-1.5 bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 border border-amber-500/30 rounded text-sm font-medium flex items-center gap-1">
              <Plus className="w-3 h-3" /> Add
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
            <input
              value={newSocial.platform}
              onChange={e => setNewSocial({ ...newSocial, platform: e.target.value })}
              placeholder="Platform (e.g., LinkedIn, Facebook, Twitter, Instagram, TikTok, YouTube, GitHub, Custom)"
              className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none"
            />
            <input
              value={newSocial.url}
              onChange={e => setNewSocial({ ...newSocial, url: e.target.value })}
              placeholder="URL (optional)"
              className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none"
            />
            <input
              value={newSocial.username}
              onChange={e => setNewSocial({ ...newSocial, username: e.target.value })}
              placeholder="Username / Handle *"
              className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none"
            />
          </div>
          {form.socialMedia.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {form.socialMedia.map((sm, idx) => (
                <span key={idx} className="px-3 py-1 bg-gray-700 border border-gray-600 rounded flex items-center gap-2 text-sm">
                  <span className="font-medium">{sm.platform}</span>
                  <span className="text-gray-400">@{sm.username}</span>
                  <button type="button" onClick={() => removeSocial(idx)} className="text-red-400 hover:text-red-300">
                    <X className="w-3 h-3" />
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="flex gap-4 pt-4 border-t border-gray-800">
          <button type="submit" className="px-6 py-3 bg-amber-600 hover:bg-amber-700 text-white rounded-lg font-medium flex items-center gap-2">
            <Save className="w-4 h-4" /> Save Changes
          </button>
          <button type="button" onClick={onCancel} className="px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium flex items-center gap-2">
            <X className="w-4 h-4" /> Cancel
          </button>
        </div>
      </form>
    );
  };

  const ExecDetailView = ({ executive, onClose, onEdit }: { executive: any; onClose: () => void; onEdit: () => void }) => {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">Executive Details</h3>
          <div className="flex gap-2">
            <button onClick={onEdit} className="px-4 py-2 bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 border border-amber-500/30 rounded-lg font-medium flex items-center gap-2">
              <Edit3 className="w-4 h-4" /> Edit
            </button>
            <button onClick={onClose} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium flex items-center gap-2">
              <X className="w-4 h-4" /> Close
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-gray-800/60 border border-gray-700 rounded-xl p-4">
            <p className="text-xs text-gray-400 mb-1">ID / Document</p>
            <p className="font-mono text-amber-300 text-lg">{executive.documentId}</p>
          </div>
          <div className="bg-gray-800/60 border border-gray-700 rounded-xl p-4">
            <p className="text-xs text-gray-400 mb-1">Phone</p>
            <p className="font-mono text-sm">{executive.phone || 'Not set'}</p>
          </div>
          <div className="bg-gray-800/60 border border-gray-700 rounded-xl p-4">
            <p className="text-xs text-gray-400 mb-1">Email Corporate</p>
            <p className="text-blue-400 text-sm break-all">{executive.emailCorporate || 'Not set'}</p>
          </div>
          <div className="bg-gray-800/60 border border-gray-700 rounded-xl p-4">
            <p className="text-xs text-gray-400 mb-1">Email Personal</p>
            <p className="text-green-400 text-sm break-all">{executive.emailPersonal || 'Not set'}</p>
          </div>
          <div className="md:col-span-2 lg:col-span-2 bg-gray-800/60 border border-gray-700 rounded-xl p-4">
            <p className="text-xs text-gray-400 mb-1">Address</p>
            <p className="text-sm text-gray-300">{executive.address || 'Not set'}</p>
          </div>
          <div className="md:col-span-2 lg:col-span-2 bg-gray-800/60 border border-gray-700 rounded-xl p-4">
            <p className="text-xs text-gray-400 mb-1">Location</p>
            <p className="text-sm text-gray-300 flex items-center gap-2">
              <MapPin className="w-3 h-3 text-gray-500" />
              {executive.location || 'Not set'}
            </p>
          </div>
        </div>

        {executive.socialMedia?.length > 0 && (
          <div className="bg-gray-800/60 border border-gray-700 rounded-xl p-4">
            <h4 className="font-medium mb-3 flex items-center gap-2">
              <Users className="w-5 h-5 text-purple-400" /> Social Media Profiles ({executive.socialMedia.length})
            </h4>
            <div className="flex flex-wrap gap-3">
              {executive.socialMedia.map((sm: any, idx: number) => (
                <div key={idx} className="flex items-center gap-2 px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg">
                  <span className="font-medium text-purple-300">{sm.platform}</span>
                  {sm.url && (
                    <a href={sm.url} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-400 hover:text-blue-300 font-mono break-all max-w-xs">
                      {sm.url}
                    </a>
                  )}
                  <span className="text-gray-400">@{sm.username}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  // ==================== RENDER ====================
  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Feedback Toast */}
      {actionFeedback && (
        <div className={`fixed top-4 right-4 z-[100] px-4 py-3 rounded-lg shadow-lg flex items-center gap-2 animate-pulse ${
          actionFeedback.includes('ERROR') ? 'bg-red-600 text-white' :
          actionFeedback.includes('SUCCESS') ? 'bg-green-600 text-white' :
          'bg-blue-600 text-white'
        }`}>
          {actionFeedback.includes('ERROR') ? <XCircle className="w-4 h-4" /> :
           actionFeedback.includes('SUCCESS') ? <CheckCircle className="w-4 h-4" /> :
           <Loader2 className="w-4 h-4 animate-spin" />}
          <span className="text-sm font-medium">{actionFeedback}</span>
        </div>
      )}

      {/* Header */}
      <header className="bg-gray-900 border-b border-gray-800 sticky top-0 z-50">
        <div className="max-w-[1920px] mx-auto px-4 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Radar className="w-8 h-8 text-red-500 animate-pulse" />
              <div>
                <h1 className="text-xl font-bold bg-gradient-to-r from-red-500 via-orange-500 to-yellow-500 bg-clip-text text-transparent">
                  MONITOR-THREAT-v2
                </h1>
                <p className="text-xs text-gray-400">Brand Protection • URL Sandbox • Social Monitoring • Executive OSINT</p>
              </div>
            </div>
            
            {/* Global Search */}
            <div className="flex-1 max-w-lg mx-8">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search IOCs, IPs, domains, hashes, CVEs..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && searchIOCs()}
                  className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm focus:border-red-500 focus:outline-none focus:ring-1 focus:ring-red-500"
                />
              </div>
            </div>

            <div className="flex items-center gap-4">
              <button 
                onClick={() => { loadIOCs(); showFeedback('Data refreshed', 'success'); }} 
                className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
              >
                <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </button>
              <div className="text-right">
                <div className="text-xs text-gray-400">Indexed</div>
                <div className="text-sm font-bold text-green-400">{iocs.length} IOCs</div>
              </div>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-[1920px] mx-auto flex">
        {/* Sidebar Navigation */}
        <nav className="w-64 min-h-screen bg-gray-900 border-r border-gray-800 p-4 sticky top-[65px] h-[calc(100vh-65px)] overflow-y-auto">
          <div className="space-y-1">
            {/* Dashboard — always visible */}
            <button
              onClick={() => { setActiveTab('dashboard'); showFeedback('Loaded Dashboard'); }}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all relative ${
                activeTab === 'dashboard'
                  ? 'bg-gradient-to-r from-red-600/20 to-orange-600/20 border border-red-500/50 text-white'
                  : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              }`}
            >
              <BarChart3 className={`w-4 h-4 ${activeTab === 'dashboard' ? '' : 'text-blue-400'}`} />
              <span>Dashboard</span>
            </button>

            {/* Category groups (collapsible) */}
            {NAV_CATEGORIES.map((cat) => {
              const collapsed = isCatCollapsed(cat);
              return (
                <div key={cat.name}>
                  <button
                    onClick={() => toggleCat(cat)}
                    className="w-full flex items-center gap-2 px-3 py-2 mt-2 rounded-lg text-[11px] font-bold uppercase tracking-wider text-gray-500 hover:text-gray-300 hover:bg-gray-800/60 transition-all"
                  >
                    <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${collapsed ? '-rotate-90' : ''}`} />
                    <span>{cat.emoji}</span>
                    <span>{cat.name}</span>
                  </button>
                  <div className={`overflow-hidden transition-all duration-300 ease-in-out ${collapsed ? 'max-h-0 opacity-0' : 'max-h-[600px] opacity-100 mt-1'}`}>
                    {cat.items.map(({ id, icon: Icon, label, color, badge }) => (
                      <button
                        key={id}
                        onClick={() => { setActiveTab(id); showFeedback(`Loaded ${label}`); }}
                        className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all relative ${
                          activeTab === id
                            ? 'bg-gradient-to-r from-red-600/20 to-orange-600/20 border border-red-500/50 text-white'
                            : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                        }`}
                      >
                        <Icon className={`w-4 h-4 ${activeTab === id ? '' : color}`} />
                        <span>{label}</span>
                        {badge && (
                          <span className="ml-auto px-1.5 py-0.5 text-[10px] font-bold bg-red-500 text-white rounded">
                            {badge}
                          </span>
                        )}
                      </button>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Quick Stats */}
          <div className="mt-6 p-4 bg-gray-800 rounded-xl border border-gray-700">
            <h3 className="text-xs font-semibold mb-3 flex items-center gap-2 text-gray-400">
              <Activity className="w-3 h-3" /> LIVE STATS
            </h3>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Critical</span>
                <span className="font-bold text-red-400 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" />
                  {iocs.filter(i => i.severity === 'CRITICAL').length}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Malicious</span>
                <span className="font-bold text-red-500">{iocs.filter(i => i.status === 'MALICIOUS').length}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Timeline Events</span>
                <span className="font-bold text-blue-400">{timelineData.length}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Status</span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                  LIVE
                </span>
              </div>
            </div>
          </div>
        </nav>

        {/* Main Content */}
        <main className="flex-1 p-6 overflow-y-auto h-[calc(100vh-65px)]">
          
          {/* ==================== DASHBOARD TAB ==================== */}
          {activeTab === 'dashboard' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <BarChart3 className="w-7 h-7 text-blue-400" /> Command Dashboard
                </h2>
                <button onClick={() => { loadIOCs(); setTimelineData(generateTimelineData()); }} className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
                  <RefreshCw className="w-4 h-4" /> Refresh All
                </button>
              </div>

              {/* Stats Cards - Clickable (2x2 split) */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {[
                  { label: 'Total IOCs', value: iocs.length, icon: Database, color: 'blue', onClick: () => setActiveTab('iocs') },
                  { label: 'Critical Threats', value: iocs.filter(i => i.severity === 'CRITICAL').length, icon: AlertTriangle, color: 'red', onClick: () => setActiveTab('iocs') },
                  { label: 'Malicious', value: iocs.filter(i => i.status === 'MALICIOUS').length, icon: ShieldAlert, color: 'red', onClick: () => setActiveTab('iocs') },
                  { label: 'Live Events', value: timelineData.length, icon: Activity, color: 'green', onClick: () => {} },
                ].map(({ label, value, icon: Icon, color, onClick }) => (
                  <button
                    key={label}
                    onClick={onClick}
                    className={`p-4 bg-gray-900 border border-gray-800 rounded-xl hover:border-${color}-500/50 transition-all group cursor-pointer`}
                  >
                    <div className="flex items-center justify-between">
                      <Icon className={`w-8 h-8 text-${color}-400 group-hover:scale-110 transition-transform`} />
                      <span className="text-3xl font-bold text-white">{value}</span>
                    </div>
                    <p className="text-sm text-gray-400 mt-2">{label}</p>
                  </button>
                ))}
              </div>

              {/* Live Threat Timeline - INTERACTIVE */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-semibold flex items-center gap-2">
                    <Clock className="w-5 h-5 text-red-400 animate-pulse" />
                    Live Threat Timeline
                    <span className="px-2 py-0.5 text-xs bg-red-500/20 text-red-400 rounded">LIVE</span>
                  </h3>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setTimelineRunning(!timelineRunning)}
                      className={`p-2 rounded-lg ${timelineRunning ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}
                    >
                      {timelineRunning ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                    </button>
                    <button
                      onClick={() => setTimelineData(generateTimelineData())}
                      className="p-2 bg-gray-800 hover:bg-gray-700 rounded-lg"
                      title="Reset Timeline"
                    >
                      <RefreshCw className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                
                <div className="space-y-2 max-h-[400px] overflow-y-auto">
                  {timelineData.map((event, idx) => (
                    <div
                      key={idx}
                      onClick={() => {
                        if (event.type === 'threat') setActiveTab('threats');
                        else if (event.type === 'ioc') setActiveTab('iocs');
                        showFeedback(`Viewing: ${event.event}`);
                      }}
                      className={`flex items-start gap-3 p-3 rounded-lg cursor-pointer hover:bg-gray-800 transition-colors ${
                        event.severity === 'CRITICAL' ? 'bg-red-500/10 border-l-2 border-red-500' :
                        event.severity === 'HIGH' ? 'bg-orange-500/10 border-l-2 border-orange-500' :
                        event.severity === 'MEDIUM' ? 'bg-yellow-500/10 border-l-2 border-yellow-500' :
                        'bg-gray-800/50'
                      }`}
                    >
                      <span className="text-xs text-gray-500 min-w-[70px]">{event.time}</span>
                      {event.type === 'threat' && <Skull className="w-4 h-4 text-red-400 mt-0.5" />}
                      {event.type === 'ioc' && <Database className="w-4 h-4 text-blue-400 mt-0.5" />}
                      {event.type === 'analysis' && <Search className="w-4 h-4 text-purple-400 mt-0.5" />}
                      {event.type === 'alert' && <AlertTriangle className="w-4 h-4 text-yellow-400 mt-0.5" />}
                      {event.type === 'system' && <Activity className="w-4 h-4 text-green-400 mt-0.5" />}
                      <span className="text-sm flex-1">{event.event}</span>
                      {event.severity && (
                        <span className={`text-xs px-2 py-0.5 rounded ${
                          event.severity === 'CRITICAL' ? 'bg-red-500 text-white' :
                          event.severity === 'HIGH' ? 'bg-orange-500 text-black' :
                          'bg-gray-700'
                        }`}>
                          {event.severity}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Charts Row */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                  <h3 className="font-semibold mb-4 flex items-center gap-2">
                    <PieChartIcon className="w-5 h-5 text-purple-400" /> Severity Distribution
                  </h3>
                  {severityChartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={250}>
                      <PieChart>
                        <Pie data={severityChartData} innerRadius={60} outerRadius={100} paddingAngle={5} dataKey="value">
                          {severityChartData.map((entry, index) => (
                            <Cell key={index} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-[250px] flex items-center justify-center text-gray-500">
                      No data yet - run some analyses!
                    </div>
                  )}
                </div>

                <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                  <h3 className="font-semibold mb-4 flex items-center gap-2">
                    <BarChart3 className="w-5 h-5 text-cyan-400" /> Type Distribution
                  </h3>
                  {typeChartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={250}>
                      <BarChart data={typeChartData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                        <XAxis stroke="#9ca3af" dataKey="name" />
                        <YAxis stroke="#9ca3af" />
                        <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
                        <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-[250px] flex items-center justify-center text-gray-500">
                      No data yet
                    </div>
                  )}
                </div>
              </div>

              {/* Recent IOCs Table - Clickable rows */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-semibold">Recent IOCs</h3>
                  <button onClick={() => setActiveTab('iocs')} className="text-sm text-red-400 hover:text-red-300 flex items-center gap-1">
                    View All <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-gray-800">
                        <th className="text-left py-3 px-3 text-gray-400">Type</th>
                        <th className="text-left py-3 px-3 text-gray-400">Value</th>
                        <th className="text-left py-3 px-3 text-gray-400">Severity</th>
                        <th className="text-left py-3 px-3 text-gray-400">Status</th>
                        <th className="text-left py-3 px-3 text-gray-400">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {iocs.slice(0, 8).map((ioc) => (
                        <tr 
                          key={ioc.id} 
                          onClick={() => openDetailModal(ioc)}
                          className="border-b border-gray-800 hover:bg-gray-800 cursor-pointer transition-colors"
                        >
                          <td className="py-3 px-3">
                            <span className="px-2 py-1 bg-gray-700 rounded text-xs">{ioc.type}</span>
                          </td>
                          <td className="py-3 px-3 font-mono text-sm">{ioc.value}</td>
                          <td className="py-3 px-3">
                            <span style={{ color: SEVERITY_COLORS[ioc.severity] }} className="font-medium">
                              {ioc.severity}
                            </span>
                          </td>
                          <td className="py-3 px-3">
                            <span style={{ color: STATUS_COLORS[ioc.status] }} className="font-medium">
                              {ioc.status}
                            </span>
                          </td>
                          <td className="py-3 px-3">
                            <button onClick={(e) => { e.stopPropagation(); openDetailModal(ioc); }} className="p-1 hover:bg-gray-700 rounded">
                              <Eye className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {iocs.length === 0 && (
                    <div className="text-center py-8 text-gray-500">
                      No IOCs yet. Go to IP Intel or other modules to add some!
                    </div>
                  )}
                </div>
              </div>

              {/* Quick Actions Grid */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <h3 className="font-semibold mb-4 flex items-center gap-2">
                  <Zap className="w-5 h-5 text-yellow-400" /> Quick Actions
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {[
                    { label: 'IP Recon', icon: Globe, tab: 'ip' as TabType },
                    { label: 'Domain Scan', icon: Server, tab: 'domain' as TabType },
                    { label: 'URL Analysis', icon: ExternalLink, tab: 'url' as TabType },
                    { label: 'Hash Lookup', icon: Fingerprint, tab: 'hash' as TabType },
                    { label: 'CVE Search', icon: Shield, tab: 'cve' as TabType },
                    { label: 'AI Analysis', icon: Cpu, tab: 'ai' as TabType },
                    { label: 'Dark Web', icon: Skull, tab: 'darkweb' as TabType },
                    { label: 'Mobile Scan', icon: Smartphone, tab: 'mobile' as TabType },
                  ].map(({ label, icon: Icon, tab }) => (
                    <button
                      key={label}
                      onClick={() => { setActiveTab(tab); showFeedback(`Opening ${label}...`); }}
                      className="flex items-center gap-2 p-3 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
                    >
                      <Icon className="w-4 h-4 text-blue-400" />
                      <span className="text-sm">{label}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ==================== IP INTEL TAB ==================== */}
          {activeTab === 'ip' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Globe className="w-7 h-7 text-green-400" /> IP Intelligence
                </h2>
                <button
                  onClick={() => openPrintReport('ip', apiData, inputValue)}
                  className="px-4 py-2 bg-green-600/20 hover:bg-green-600/30 text-green-300 border border-green-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter IP address (e.g., 8.8.8.8, 1.1.1.1)"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleIPRecon()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-green-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleIPRecon}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-green-600 hover:bg-green-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    Analyze IP
                  </button>
                </div>
              </div>

              {/* IP Analysis Queue (FIFO, persistent) */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
                  <h3 className="font-semibold flex items-center gap-2">
                    <Database className="w-5 h-5 text-cyan-400" /> IP Analysis Queue
                    <span className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded">{ipQueue.length}/{QUEUE_MAX}</span>
                  </h3>
                  <div className="flex flex-wrap gap-2 text-xs">
                    <button onClick={() => exportIpQueue('csv')} className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded flex items-center gap-1"><Download className="w-3 h-3" /> CSV</button>
                    <button onClick={() => exportIpQueue('json')} className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded flex items-center gap-1"><Download className="w-3 h-3" /> JSON</button>
                    {ipQueue.length > 0 && (
                      <>
                        <button onClick={selectAllQueue} className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded flex items-center gap-1"><Check className="w-3 h-3" /> Select all</button>
                        <button onClick={deleteSelectedFromQueue} className="px-2 py-1 bg-red-600/20 hover:bg-red-600/40 text-red-300 rounded flex items-center gap-1"><Trash2 className="w-3 h-3" /> Delete selected ({selectedQueue.size})</button>
                        <button onClick={clearIpQueue} className="px-2 py-1 bg-red-600/20 hover:bg-red-600/40 text-red-300 rounded flex items-center gap-1"><Ban className="w-3 h-3" /> Clear all</button>
                      </>
                    )}
                  </div>
                </div>
                {ipQueue.length === 0 ? (
                  <p className="text-xs text-gray-500">
                    No IPs analyzed yet. Click <span className="text-blue-400">+ Add to IOC</span> on an IP result to keep it in this persistent FIFO queue (max {QUEUE_MAX}).
                  </p>
                ) : (
                  <div className="space-y-2">
                    {(() => {
                      const top = [...ipQueue].sort((a, b) => b.riskScore - a.riskScore)[0];
                      const sevClass = (s: string) => s === 'CRITICAL' ? 'text-red-300 bg-red-500/20 border-red-500/40' : s === 'HIGH' ? 'text-orange-300 bg-orange-500/15 border-orange-500/40' : s === 'MEDIUM' ? 'text-yellow-300 bg-yellow-500/10 border-yellow-500/40' : 'text-green-300 bg-green-500/10 border-green-500/40';
                      return (
                        <>
                          {top && (
                            <div className="p-3 rounded-lg border-2 border-red-500/40 bg-red-500/10">
                              <div className="flex flex-wrap items-center gap-2 text-xs">
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-600 text-white font-bold uppercase tracking-wide">Top Risk</span>
                                <span className="font-mono font-bold text-red-200">{top.ip}</span>
                                <span className={`px-2 py-0.5 rounded border text-[10px] font-medium uppercase ${sevClass(top.severity)}`}>{top.severity}</span>
                                <span className="text-gray-400">{top.flag} {top.country}</span>
                                <span className="text-gray-500">Risk {top.riskScore}/100</span>
                              </div>
                              <div className="mt-1 h-1.5 bg-gray-700 rounded overflow-hidden">
                                <div className="h-1.5 rounded" style={{ width: `${top.riskScore}%`, backgroundColor: abuseScoreColor(top.riskScore) }} />
                              </div>
                              <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-gray-400">
                                <span><span className="text-gray-300 font-medium">{top.abuseScore}%</span> abuse</span>
                                <span>{top.blacklistCount} blacklisted{top.blockedCount ? ` · ${top.blockedCount} blocked` : ''}</span>
                                <span>{top.torExit ? 'Tor exit' : 'No Tor'}</span>
                                <span>URLhaus: {top.urlhausCount}</span>
                                {top.malware && <span className="text-red-300">{top.malware}</span>}
                              </div>
                            </div>
                          )}
                          {ipQueue.map((e) => (
                            <div key={e.id} className={`px-2.5 py-2 rounded border ${selectedQueue.has(e.id) ? 'bg-cyan-500/10 border-cyan-500/40' : 'bg-gray-800/50 border-gray-700'}`}>
                              <div className="flex flex-wrap items-center gap-2 text-xs">
                                <input type="checkbox" checked={selectedQueue.has(e.id)} onChange={() => toggleQueueSelect(e.id)} className="accent-cyan-500" />
                                <span className="font-mono font-bold">{e.ip}</span>
                                <span className={`px-1.5 py-0.5 rounded border text-[10px] font-medium uppercase ${sevClass(e.severity)}`}>{e.severity}</span>
                                <span className="text-gray-400">{e.flag} {e.country}</span>
                                <span className="text-gray-500 ml-auto shrink-0">{timeAgo(e.addedAt)}</span>
                              </div>
                              <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-gray-400 pl-6">
                                <span><span className="text-gray-200 font-medium">{e.abuseScore}%</span> abuse</span>
                                <span>{e.blacklistCount} listed</span>
                                <span>{e.category}</span>
                                <span>URLhaus: {e.urlhausCount}</span>
                                {e.openPorts.length > 0 && <span className="font-mono text-red-300">Ports: {e.openPorts.join(', ')}</span>}
                                {e.malware && <span className="text-red-300">{e.malware}</span>}
                              </div>
                            </div>
                          ))}
                        </>
                      );
                    })()}
                  </div>
                )}
              </div>

              {/* Results Display */}
              {apiData && apiData.data && (
                <div className="space-y-4">
                  <div className="bg-gradient-to-r from-green-500/10 to-emerald-500/10 border border-green-500/30 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2">
                      <CheckCircle className="w-5 h-5 text-green-400" /> Live Results
                      {apiData.fetchedLive && <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded">LIVE DATA</span>}
                    </h3>
                    
                    {/* Status cards: threat level / blacklists / network category */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 mb-4">
                      <div className={`px-3 py-2 rounded-lg border flex items-center gap-2 ${threatBadgeClass(apiData)}`}>
                        <AlertTriangle className="w-4 h-4 shrink-0" />
                        <div className="min-w-0">
                          <div className="text-[10px] uppercase tracking-wide opacity-80">Threat Level</div>
                          <div className="font-bold truncate">{apiData.analysis?.threatLevel || 'NORMAL'}</div>
                        </div>
                      </div>
                      <button
                        onClick={() => setShowDnsblDetail((v) => !v)}
                        className={`px-3 py-2 rounded-lg border flex items-center gap-2 text-left ${(apiData.reputation?.dnsbl?.filter((d: any) => d.listed)?.length || 0) > 0 ? 'bg-red-500/20 text-red-300 border-red-500/40' : 'bg-green-500/10 text-green-300 border-green-500/40'}`}
                      >
                        <Ban className="w-4 h-4 shrink-0" />
                        <div className="min-w-0 flex-1">
                          <div className="text-[10px] uppercase tracking-wide opacity-80">Blacklists</div>
                          <div className="font-bold truncate">
                            {(apiData.reputation?.dnsbl?.filter((d: any) => d.listed)?.length || 0) > 0
                              ? `Blacklisted (${apiData.reputation.dnsbl.filter((d: any) => d.listed).length} lists)`
                              : 'Not blacklisted'}
                          </div>
                        </div>
                        <ChevronDown className={`w-3 h-3 shrink-0 transition-transform ${showDnsblDetail ? 'rotate-180' : ''}`} />
                      </button>
                      <div className="px-3 py-2 rounded-lg border border-gray-700 bg-gray-800/50 flex items-center gap-2">
                        <Wifi className="w-4 h-4 shrink-0 text-blue-400" />
                        <div className="min-w-0">
                          <div className="text-[10px] uppercase tracking-wide text-gray-500">Network</div>
                          <div className="font-bold text-gray-200 truncate">{networkCategory(apiData)}</div>
                        </div>
                      </div>
                    </div>

                    {/* DNSBL detail (toggled from the Blacklists card) */}
                    {showDnsblDetail && apiData.reputation && (
                      <div className="mb-4 p-3 bg-gray-900/60 rounded-lg border border-gray-700">
                        <div className="flex items-center justify-between mb-2">
                          <p className="text-xs text-gray-400 font-medium">DNSBL detail — {apiData.reputation.dnsbl.length} zones checked</p>
                          <button onClick={() => setShowDnsblDetail(false)} className="text-gray-500 hover:text-gray-300"><X className="w-4 h-4" /></button>
                        </div>
                        {(() => {
                          const listed = (apiData.reputation.dnsbl || []).filter((d: any) => d.listed);
                          const blocked = (apiData.reputation.dnsbl || []).filter((d: any) => d.blocked);
                          const flagged = [...listed, ...blocked];
                          return flagged.length === 0 ? (
                            <p className="text-xs text-green-400">No blacklist hits across {apiData.reputation.dnsbl.length} DNSBL zones.</p>
                          ) : (
                            <ul className="space-y-1">
                              {flagged.map((d: any) => (
                                <li key={d.zone} className={`flex flex-col text-xs px-2 py-1 rounded ${d.listed ? 'bg-red-500/20 text-red-300 border border-red-500/30' : 'bg-yellow-500/10 text-yellow-300 border border-yellow-500/30'}`}>
                                  <span className="flex items-center justify-between gap-2">
                                    <span className="font-medium">{d.name} <span className="text-gray-500 font-normal">[{d.group}]</span></span>
                                    <span className="font-mono shrink-0">{d.listed ? `LISTED ${d.records.join(',')}` : 'BLOCKED (resolver)'}</span>
                                  </span>
                                  {d.listed && d.message && (
                                    <span className="text-[10px] text-gray-400 break-all mt-0.5">{d.message}</span>
                                  )}
                                </li>
                              ))}
                            </ul>
                          );
                        })()}
                      </div>
                    )}

                    <div className="grid grid-cols-2 gap-3">
                      {(apiData.data.query || apiData.data.ip) && (
                        <>
                          <InfoCard label="IP Address" value={apiData.data.query || apiData.data.ip} icon={<Globe className="w-4 h-4" />} />
                          <InfoCard label="Hostname (reverse DNS)" value={apiData.data.reverse || 'N/A'} icon={<Network className="w-4 h-4" />} />
                          <InfoCard label="Country" value={`${apiData.data.country || 'N/A'} (${apiData.data.countryCode || ''})`} icon={<MapPin className="w-4 h-4" />} />
                          <InfoCard label="Region" value={apiData.data.regionName || 'N/A'} icon={<MapPin className="w-4 h-4" />} />
                          <InfoCard label="City" value={apiData.data.city || 'N/A'} icon={<Server className="w-4 h-4" />} />
                          <InfoCard label="District" value={apiData.data.district || 'N/A'} icon={<MapPin className="w-4 h-4" />} />
                          <InfoCard label="Postal Code" value={apiData.data.zip || 'N/A'} icon={<FileCode className="w-4 h-4" />} />
                          <InfoCard label="Continent" value={`${apiData.data.continent || 'N/A'} (${apiData.data.continentCode || ''})`} icon={<Globe2 className="w-4 h-4" />} />
                          <InfoCard label="ISP" value={apiData.data.isp || 'N/A'} icon={<Wifi className="w-4 h-4" />} />
                          <InfoCard label="Organization" value={apiData.data.org || 'N/A'} icon={<Database className="w-4 h-4" />} />
                          <InfoCard label="ASN" value={`${apiData.data.as || 'N/A'}${apiData.data.asname ? ` — ${apiData.data.asname}` : ''}`} icon={<Radar className="w-4 h-4" />} />
                          <InfoCard label="Latitude" value={apiData.data.lat || 'N/A'} icon={<Target className="w-4 h-4" />} />
                          <InfoCard label="Longitude" value={apiData.data.lon || 'N/A'} icon={<Target className="w-4 h-4" />} />
                          <InfoCard label="Timezone" value={apiData.data.timezone || 'N/A'} icon={<Clock className="w-4 h-4" />} />
                          <InfoCard label="Local Time" value={apiData.data.timezone ? new Intl.DateTimeFormat('en-GB', { timeZone: apiData.data.timezone, dateStyle: 'medium', timeStyle: 'medium' }).format(new Date()) : 'N/A'} icon={<Clock className="w-4 h-4" />} />
                          <InfoCard label="Currency" value={apiData.data.currency || 'N/A'} icon={<Database className="w-4 h-4" />} />
                        </>
                      )}
                    </div>

                    {/* Map */}
                    {apiData.data.lat && apiData.data.lon && (
                      <div className="mt-4 rounded-lg overflow-hidden border border-gray-700">
                        <iframe
                          title="IP Location Map"
                          src={`https://www.openstreetmap.org/export/embed.html?bbox=${Number(apiData.data.lon) - 0.1}%2C${Number(apiData.data.lat) - 0.1}%2C${Number(apiData.data.lon) + 0.1}%2C${Number(apiData.data.lat) + 0.1}&layer=mapnik&marker=${apiData.data.lat}%2C${apiData.data.lon}`}
                          className="w-full h-64"
                          loading="lazy"
                        />
                      </div>
                    )}

                    {apiData.data.location && (
                      <div className="mt-4 p-4 bg-gray-800/50 rounded-lg">
                        <h4 className="text-sm font-medium mb-2">Location Details</h4>
                        <p className="text-sm text-gray-300">{apiData.data.location}</p>
                      </div>
                    )}

                    {/* RDAP / WHOIS ownership */}
                    {apiData.data.rdap && (
                      <div className="mt-4 p-4 bg-gray-800/50 rounded-lg border border-gray-700">
                        <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                          <Shield className="w-4 h-4 text-green-400" /> Network Ownership (RDAP)
                        </h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                          {apiData.data.rdap.name && <div><span className="text-gray-400">Network:</span> <span className="font-mono">{apiData.data.rdap.name}</span></div>}
                          {apiData.data.rdap.startAddress && apiData.data.rdap.endAddress && <div><span className="text-gray-400">Range:</span> <span className="font-mono">{apiData.data.rdap.startAddress} — {apiData.data.rdap.endAddress}</span></div>}
                          {apiData.data.rdap.entities?.length > 0 && <div><span className="text-gray-400">Registrant:</span> <span>{apiData.data.rdap.entities.join(', ')}</span></div>}
                          {apiData.data.rdap.country && <div><span className="text-gray-400">Registry Country:</span> <span>{apiData.data.rdap.country}</span></div>}
                          {apiData.data.rdap.status?.length > 0 && <div><span className="text-gray-400">Status:</span> <span>{apiData.data.rdap.status.join(', ')}</span></div>}
                          {apiData.data.rdap.abuseContacts?.length > 0 && <div><span className="text-gray-400">Abuse Contact:</span> <a href={`mailto:${apiData.data.rdap.abuseContacts[0]}`} className="text-red-400 underline break-all">{apiData.data.rdap.abuseContacts.join(', ')}</a></div>}
                        </div>
                      </div>
                    )}

                    {/* Reputation & Threat Intelligence */}
                    {apiData.reputation && (
                      <div id="ip-reputation" className="mt-4 p-4 bg-gray-800/50 rounded-lg border border-gray-700 scroll-mt-4">
                        <h4 className="text-sm font-medium mb-3 flex items-center gap-2">
                          <ShieldAlert className="w-4 h-4 text-red-400" /> Reputation & Threat Intelligence
                        </h4>
                        {/* VirusTotal Classification */}
                        {apiData.reputation?.virusTotal && apiData.reputation.virusTotal.analyzed && (
                          <div className="mt-4 p-3 bg-gray-900/50 rounded-lg border border-gray-700">
                            <h5 className="text-xs font-medium text-gray-400 mb-2 flex items-center gap-2">
                              <Shield className="w-3.5 h-3.5 text-orange-400" /> VirusTotal Classification
                            </h5>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                              <div className="p-2 bg-gray-900/50 rounded border border-gray-700">
                                <div className="text-xs text-gray-500 mb-1">Verdict</div>
                                <div className="font-bold text-lg flex items-center gap-2">
                                  <span className={`px-2 py-0.5 rounded text-xs ${
                                    apiData.reputation.virusTotal.verdict === 'MALICIOUS' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                                    apiData.reputation.virusTotal.verdict === 'SUSPICIOUS' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40' :
                                    apiData.reputation.virusTotal.verdict === 'CLEAN' ? 'bg-green-500/20 text-green-400 border border-green-500/40' :
                                    'bg-gray-700 text-gray-300 border border-gray-600'
                                  }`}>
                                    {apiData.reputation.virusTotal.verdict}
                                  </span>
                                </div>
                              </div>
                              <div className="p-2 bg-gray-900/50 rounded border border-gray-700">
                                <div className="text-xs text-gray-500 mb-1">Detection</div>
                                <div className="font-bold text-lg">
                                  {apiData.reputation.virusTotal.lastAnalysisStats?.malicious || 0} / {apiData.reputation.virusTotal.totalEngines || 0} engines
                                </div>
                              </div>
                            </div>
                            <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-3">
                              <div className="p-2 bg-gray-900/50 rounded border border-gray-700">
                                <div className="text-xs text-gray-500 mb-1">Reputation Score</div>
                                <div className="font-bold text-lg">{apiData.reputation.virusTotal.reputation || 0}</div>
                              </div>
                              <div className="p-2 bg-gray-900/50 rounded border border-gray-700">
                                <div className="text-xs text-gray-500 mb-1">Last Analysis</div>
                                <div className="font-bold text-lg">
                                  {apiData.reputation.virusTotal.lastAnalysisDate ? new Date(apiData.reputation.virusTotal.lastAnalysisDate).toLocaleDateString('es-ES', {year: 'numeric', month: 'short', day: 'numeric'}) : 'N/A'}
                                </div>
                              </div>
                            </div>
                            <div className="mt-2">
                              <a href={apiData.reputation.virusTotal.url} target="_blank" rel="noopener noreferrer" className="text-xs text-orange-400 hover:text-orange-300 flex items-center gap-1">
                                <ExternalLink className="w-3 h-3" />
                                View on VirusTotal
                              </a>
                            </div>
                          </div>
                        )}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <p className="text-xs text-gray-400 mb-1">DNS Blacklists (DNSBL)</p>
                            {(() => {
                                const dnsbl: any[] = apiData.reputation.dnsbl || [];
                                const listed = dnsbl.filter((d: any) => d.listed);
                                const blocked = dnsbl.filter((d: any) => d.blocked);
                                const clean = dnsbl.filter((d: any) => !d.listed && !d.blocked);
                                const groups: string[] = Array.from(new Set(clean.map((d: any) => d.group))).sort();
                                return (
                                  <div className="space-y-2">
                                    <div className="flex flex-wrap gap-1 text-[11px]">
                                      <span className={`px-2 py-0.5 rounded border ${listed.length ? 'bg-red-500/20 text-red-300 border-red-500/40' : 'bg-gray-900 text-gray-500 border-gray-700'}`}>{listed.length} listed</span>
                                      <span className={`px-2 py-0.5 rounded border ${blocked.length ? 'bg-yellow-500/10 text-yellow-300 border-yellow-500/40' : 'bg-gray-900 text-gray-500 border-gray-700'}`}>{blocked.length} blocked</span>
                                      <span className="px-2 py-0.5 rounded bg-gray-900 text-gray-400 border border-gray-700">{dnsbl.length} lists checked</span>
                                    </div>
                                    {listed.length === 0 && blocked.length === 0 && (
                                      <p className="text-xs text-green-400">No blacklist hits across {dnsbl.length} DNSBL zones.</p>
                                    )}
                                    {(listed.length > 0 || blocked.length > 0) && (
                                      <ul className="space-y-1">
                                        {[...listed, ...blocked].map((d: any) => (
                                          <li key={d.zone} className={`flex flex-col text-xs px-2 py-1 rounded ${d.listed ? 'bg-red-500/20 text-red-300 border border-red-500/30' : 'bg-yellow-500/10 text-yellow-300 border border-yellow-500/30'}`}>
                                            <span className="flex items-center justify-between gap-2">
                                              <span className="font-medium">{d.name} <span className="text-gray-500 font-normal">[{d.group}]</span></span>
                                              <span className="font-mono shrink-0">{d.listed ? `LISTED ${d.records.join(',')}` : 'BLOCKED (resolver)'}</span>
                                            </span>
                                            {d.listed && d.message && (
                                              <span className="text-[10px] text-gray-400 break-all mt-0.5">{d.message}</span>
                                            )}
                                          </li>
                                        ))}
                                      </ul>
                                    )}
                                    <details className="text-xs">
                                      <summary className="cursor-pointer text-gray-400 hover:text-gray-300">Show all clean lists ({clean.length})</summary>
                                      <div className="mt-1.5 space-y-1.5">
                                        {groups.map((g: string) => (
                                          <div key={g}>
                                            <p className="text-[10px] uppercase tracking-wide text-gray-500">{g}</p>
                                            <div className="flex flex-wrap gap-1">
                                              {clean.filter((d: any) => d.group === g).map((d: any) => (
                                                <span key={d.zone} className="px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 text-[11px]">{d.name}</span>
                                              ))}
                                            </div>
                                          </div>
                                        ))}
                                      </div>
                                    </details>
                                  </div>
                                );
                              })()
                            }
                          </div>
                          {/* VirusTotal Classification */}
                          {apiData.reputation?.virusTotal && apiData.reputation.virusTotal.analyzed && (
                            <div className="mt-4 p-3 bg-gray-900/50 rounded-lg border border-gray-700">
                              <h5 className="text-xs font-medium text-gray-400 mb-2 flex items-center gap-2">
                                <Shield className="w-3.5 h-3.5 text-orange-400" /> VirusTotal Classification
                              </h5>
                              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                <div className="p-2 bg-gray-900/50 rounded border border-gray-700">
                                  <div className="text-xs text-gray-500 mb-1">Verdict</div>
                                  <div className="font-bold text-lg flex items-center gap-2">
                                    <span className={`px-2 py-0.5 rounded text-xs ${
                                      apiData.reputation.virusTotal.verdict === 'MALICIOUS' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                                      apiData.reputation.virusTotal.verdict === 'SUSPICIOUS' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40' :
                                      apiData.reputation.virusTotal.verdict === 'CLEAN' ? 'bg-green-500/20 text-green-400 border border-green-500/40' :
                                      'bg-gray-700 text-gray-300 border border-gray-600'
                                    }`}>
                                      {apiData.reputation.virusTotal.verdict}
                                    </span>
                                  </div>
                                </div>
                                <div className="p-2 bg-gray-900/50 rounded border border-gray-700">
                                  <div className="text-xs text-gray-500 mb-1">Detection</div>
                                  <div className="font-bold text-lg">
                                    {apiData.reputation.virusTotal.lastAnalysisStats?.malicious || 0} / {apiData.reputation.virusTotal.totalEngines || 0} engines
                                  </div>
                                </div>
                              </div>
                              <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-3">
                                <div className="p-2 bg-gray-900/50 rounded border border-gray-700">
                                  <div className="text-xs text-gray-500 mb-1">Reputation Score</div>
                                  <div className="font-bold text-lg">{apiData.reputation.virusTotal.reputation || 0}</div>
                                </div>
                                <div className="p-2 bg-gray-900/50 rounded border border-gray-700">
                                  <div className="text-xs text-gray-500 mb-1">Last Analysis</div>
                                  <div className="font-bold text-lg">
                                    {apiData.reputation.virusTotal.lastAnalysisDate ? new Date(apiData.reputation.virusTotal.lastAnalysisDate).toLocaleDateString('es-ES', {year: 'numeric', month: 'short', day: 'numeric'}) : 'N/A'}
                                  </div>
                                </div>
                              </div>
                              <div className="mt-2">
                                <a href={apiData.reputation.virusTotal.url} target="_blank" rel="noopener noreferrer" className="text-xs text-orange-400 hover:text-orange-300 flex items-center gap-1">
                                  <ExternalLink className="w-3 h-3" />
                                  View on VirusTotal
                                </a>
                              </div>
                            </div>
                          )}
                        </div>
                          </div>
                        )}
                        {/* VirusTotal Classification */}
                        {apiData.reputation?.virusTotal && apiData.reputation.virusTotal.analyzed && (
                          <div className="mt-4 p-3 bg-gray-900/50 rounded-lg border border-gray-700">
                            <h5 className="text-xs font-medium text-gray-400 mb-2 flex items-center gap-2">
                              <Shield className="w-3.5 h-3.5 text-orange-400" /> VirusTotal Classification
                            </h5>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                              <div className="p-2 bg-gray-900/50 rounded border border-gray-700">
                                <div className="text-xs text-gray-500 mb-1">Verdict</div>
                                <div className="font-bold text-lg flex items-center gap-2">
                                  <span className={`px-2 py-0.5 rounded text-xs ${
                                    apiData.reputation.virusTotal.verdict === 'MALICIOUS' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                                    apiData.reputation.virusTotal.verdict === 'SUSPICIOUS' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40' :
                                    apiData.reputation.virusTotal.verdict === 'CLEAN' ? 'bg-green-500/20 text-green-400 border border-green-500/40' :
                                    'bg-gray-700 text-gray-300 border border-gray-600'
                                  }`}>
                                    {apiData.reputation.virusTotal.verdict}
                                  </span>
                                </div>
                              </div>
                              <div className="p-2 bg-gray-900/50 rounded border border-gray-700">
                                <div className="text-xs text-gray-500 mb-1">Detection</div>
                                <div className="font-bold text-lg">
                                  {apiData.reputation.virusTotal.lastAnalysisStats?.malicious || 0} / {apiData.reputation.virusTotal.totalEngines || 0} engines
                                </div>
                              </div>
                            </div>
                            <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-3">
                              <div className="p-2 bg-gray-900/50 rounded border border-gray-700">
                                <div className="text-xs text-gray-500 mb-1">Reputation Score</div>
                                <div className="font-bold text-lg">{apiData.reputation.virusTotal.reputation || 0}</div>
                              </div>
                              <div className="p-2 bg-gray-900/50 rounded border border-gray-700">
                                <div className="text-xs text-gray-500 mb-1">Last Analysis</div>
                                <div className="font-bold text-lg">
                                  {apiData.reputation.virusTotal.lastAnalysisDate ? new Date(apiData.reputation.virusTotal.lastAnalysisDate).toLocaleDateString('es-ES', {year: 'numeric', month: 'short', day: 'numeric'}) : 'N/A'}
                                </div>
                              </div>
                            </div>
                            <div className="mt-2">
                              <a href={apiData.reputation.virusTotal.url} target="_blank" rel="noopener noreferrer" className="text-xs text-orange-400 hover:text-orange-300 flex items-center gap-1">
                                <ExternalLink className="w-3 h-3" />
                                View on VirusTotal
                              </a>
                            </div>
                          </div>
                        )}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <p className="text-xs text-gray-400 mb-1">DNS Blacklists (DNSBL)</p>
                            {(() => {
                                const dnsbl: any[] = apiData.reputation.dnsbl || [];
                                const listed = dnsbl.filter((d: any) => d.listed);
                                const blocked = dnsbl.filter((d: any) => d.blocked);
                                const clean = dnsbl.filter((d: any) => !d.listed && !d.blocked);
                                const groups: string[] = Array.from(new Set(clean.map((d: any) => d.group))).sort();
                                return (
                                  <div className="space-y-2">
                                    <div className="flex flex-wrap gap-1 text-[11px]">
                                      <span className={`px-2 py-0.5 rounded border ${listed.length ? 'bg-red-500/20 text-red-300 border-red-500/40' : 'bg-gray-900 text-gray-500 border-gray-700'}`}>{listed.length} listed</span>
                                      <span className={`px-2 py-0.5 rounded border ${blocked.length ? 'bg-yellow-500/10 text-yellow-300 border-yellow-500/40' : 'bg-gray-900 text-gray-500 border-gray-700'}`}>{blocked.length} blocked</span>
                                      <span className="px-2 py-0.5 rounded bg-gray-900 text-gray-400 border border-gray-700">{dnsbl.length} lists checked</span>
                                    </div>
                                    {listed.length === 0 && blocked.length === 0 && (
                                      <p className="text-xs text-green-400">No blacklist hits across {dnsbl.length} DNSBL zones.</p>
                                    )}
                                    {(listed.length > 0 || blocked.length > 0) && (
                                      <ul className="space-y-1">
                                        {[...listed, ...blocked].map((d: any) => (
                                          <li key={d.zone} className={`flex flex-col text-xs px-2 py-1 rounded ${d.listed ? 'bg-red-500/20 text-red-300 border border-red-500/30' : 'bg-yellow-500/10 text-yellow-300 border border-yellow-500/30'}`}>
                                            <span className="flex items-center justify-between gap-2">
                                              <span className="font-medium">{d.name} <span className="text-gray-500 font-normal">[{d.group}]</span></span>
                                              <span className="font-mono shrink-0">{d.listed ? `LISTED ${d.records.join(',')}` : 'BLOCKED (resolver)'}</span>
                                            </span>
                                            {d.listed && d.message && (
                                              <span className="text-[10px] text-gray-400 break-all mt-0.5">{d.message}</span>
                                            )}
                                          </li>
                                        ))}
                                      </ul>
                                    )}
                                    <details className="text-xs">
                                      <summary className="cursor-pointer text-gray-400 hover:text-gray-300">Show all clean lists ({clean.length})</summary>
                                      <div className="mt-1.5 space-y-1.5">
                                        {groups.map((g: string) => (
                                          <div key={g}>
                                            <p className="text-[10px] uppercase tracking-wide text-gray-500">{g}</p>
                                            <div className="flex flex-wrap gap-1">
                                              {clean.filter((d: any) => d.group === g).map((d: any) => (
                                                <span key={d.zone} className="px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 text-[11px]">{d.name}</span>
                                              ))}
                                            </div>
                                          </div>
                                        ))}
                                      </div>
                                    </details>
                                  </div>
                                );
                              })()
                          </div>
                          <div>
                            <p className="text-xs text-gray-400 mb-1">Malicious URL History (URLhaus)</p>
                            {apiData.reputation.urlhaus?.urlCount > 0 ? (
                              <>
                                <p className="text-sm text-red-400 font-medium mb-2">{apiData.reputation.urlhaus.urlCount} malicious URL(s) associated</p>
                                <ul className="space-y-1 max-h-32 overflow-y-auto">
                                  {apiData.reputation.urlhaus.urls.slice(0, 10).map((u: any, i: number) => (
                                    <li key={i} className="text-xs font-mono text-red-300 bg-gray-900 rounded px-2 py-1 break-all">
                                      {u.url} <span className="text-gray-500">[{u.threat} · {u.dateAdded}]</span>
                                    </li>
                                  ))}
                                </ul>
                              </>
                            ) : (
                              <p className="text-xs text-green-400">No malicious URLs found on URLhaus</p>
                            )}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Certificates / pivoting */}
                    {apiData.pivot?.certificates?.length > 0 && (
                      <div className="mt-4 p-4 bg-gray-800/50 rounded-lg border border-gray-700">
                        <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                          <Lock className="w-4 h-4 text-blue-400" /> SSL/TLS Certificates & Linked Domains (crt.sh)
                        </h4>
                        <ul className="space-y-1 max-h-48 overflow-y-auto">
                          {apiData.pivot.certificates.slice(0, 25).map((c: any, i: number) => (
                            <li key={i} className="text-xs px-2 py-1 bg-gray-900 rounded">
                              <span className="font-mono text-blue-300">{c.nameValue}</span>
                              {c.issuerName && <span className="text-gray-500"> · {c.issuerName}</span>}
                              {c.notBefore && <span className="text-gray-600"> · valid from {c.notBefore.slice(0, 10)}</span>}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Active scan */}
                    {apiData.scan?.ports?.length > 0 && (
                      <div id="ip-scan" className="mt-4 p-4 bg-gray-800/50 rounded-lg border border-gray-700 scroll-mt-4">
                        <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                          <Terminal className="w-4 h-4 text-purple-400" /> Active Scan — Exposed Services
                        </h4>
                        <p className="text-xs text-gray-400 mb-2">Estimated OS: <span className="text-purple-300 font-medium">{apiData.scan.os}</span></p>
                        {(() => {
                          const ports = apiData.scan.ports || [];
                          const open = ports.filter((p: any) => p.state === 'open');
                          const closed = ports.filter((p: any) => p.state === 'closed');
                          const filtered = ports.filter((p: any) => p.state === 'filtered');
                          return (
                            <div className="space-y-3">
                              <div className="flex flex-wrap gap-1 text-[11px]">
                                <span className="px-2 py-0.5 rounded bg-gray-900 text-gray-400 border border-gray-700">Scanned {ports.length} ports (yougetsignal-style)</span>
                                <span className={`px-2 py-0.5 rounded border ${open.length ? 'bg-red-500/20 text-red-300 border-red-500/40' : 'bg-gray-900 text-gray-500 border-gray-700'}`}>{open.length} open</span>
                                <span className={`px-2 py-0.5 rounded border ${closed.length ? 'bg-green-500/10 text-green-400 border-green-500/40' : 'bg-gray-900 text-gray-500 border-gray-700'}`}>{closed.length} closed</span>
                                <span className={`px-2 py-0.5 rounded border ${filtered.length ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/40' : 'bg-gray-900 text-gray-500 border-gray-700'}`}>{filtered.length} filtered/timeout</span>
                              </div>
                              {open.length === 0 ? (
                                <p className="text-xs text-green-400">No open ports detected on the 20-port probe list. Filtered/closed ports are omitted below.</p>
                              ) : (
                                <>
                                  <div className="flex flex-wrap gap-1">
                                    {open.map((p: any) => (
                                      <span key={p.port} className="px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/40 text-xs font-mono">{p.port} {p.service}</span>
                                    ))}
                                  </div>
                                  <div className="space-y-2">
                                    {open.map((p: any) => {
                                      const profile = VULNERABLE_SERVICES[Number(p.port)];
                                      return profile ? (
                                        <div key={p.port} className="p-3 rounded-lg border border-red-500/30 bg-red-500/10">
                                          <div className="flex flex-wrap items-center gap-2 text-sm">
                                            <span className="font-mono font-bold text-red-300">port {p.port}</span>
                                            <span className="text-gray-300 font-medium">{p.service}</span>
                                            <span className={`text-[10px] px-2 py-0.5 rounded border font-medium uppercase tracking-wide ${VULN_RISK_COLORS[profile.risk] || VULN_RISK_COLORS.MEDIUM}`}>Risk {profile.risk}</span>
                                          </div>
                                          <p className="text-xs text-red-200 font-medium mt-1">{profile.title}</p>
                                          <p className="text-xs text-gray-300 mt-1">{profile.desc}</p>
                                          {profile.cves.length > 0 && (
                                            <div className="flex flex-wrap gap-1 mt-2">
                                              {profile.cves.map((cve) => (
                                                <span key={cve} className="text-[10px] px-1.5 py-0.5 rounded bg-gray-900 text-purple-300 border border-purple-500/30 font-mono">{cve}</span>
                                              ))}
                                            </div>
                                          )}
                                          <div className="mt-2 text-xs">
                                            <p className="text-gray-400 font-medium flex items-center gap-1"><Target className="w-3 h-3" /> Attack vector</p>
                                            <p className="text-gray-300 mt-0.5">{profile.vector}</p>
                                          </div>
                                          <div className="mt-2 text-xs">
                                            <p className="text-gray-400 font-medium flex items-center gap-1"><Terminal className="w-3 h-3" /> Verification / exploitation steps</p>
                                            <ol className="list-decimal list-inside mt-0.5 space-y-0.5 text-gray-300">
                                              {profile.steps.map((s, i) => (
                                                <li key={i}>{s}</li>
                                              ))}
                                            </ol>
                                          </div>
                                          {p.banner && <p className="text-[10px] text-gray-500 font-mono mt-2 break-all">Banner: {p.banner}</p>}
                                        </div>
                                      ) : (
                                        <div key={p.port} className="flex items-center gap-2 text-xs px-2 py-1 rounded bg-orange-500/10 text-orange-300 border border-orange-500/30">
                                          <span className="font-mono w-14 font-bold">{p.port}</span>
                                          <span className="w-20">{p.service}</span>
                                          <span className="font-medium text-orange-300">OPEN — no known vuln profile in this build</span>
                                          {p.banner && <span className="text-gray-400 truncate flex-1" title={p.banner}>{p.banner}</span>}
                                        </div>
                                      );
                                    })}
                                  </div>
                                </>
                              )}
                            </div>
                          );
                        })()}
                      </div>
                    )}

                    {/* Forensic artifacts guidance — interactive */}
                    <div className="mt-4 p-4 bg-gray-800/50 rounded-lg border border-gray-700">
                      <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                        <h4 className="text-sm font-medium flex items-center gap-2">
                          <Fingerprint className="w-4 h-4 text-green-400" /> Forensic Artifacts to Extract from Logs
                        </h4>
                        <div className="flex flex-wrap gap-2 text-xs">
                          <button onClick={copyAllArtifactQueries} className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded flex items-center gap-1"><Copy className="w-3 h-3" /> Copy all queries</button>
                          <button onClick={downloadForensicChecklist} className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded flex items-center gap-1"><DownloadCloud className="w-3 h-3" /> Checklist CSV</button>
                          <button onClick={downloadTimelineTemplate} className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded flex items-center gap-1"><FileText className="w-3 h-3" /> Timeline template</button>
                        </div>
                      </div>
                      <p className="text-xs text-gray-400 mb-3">
                        Click any artifact to expand where to extract it, the fields to collect and ready-to-copy SIEM / CLI queries for{' '}
                        <span className="font-mono text-green-300">{apiData.data.query || apiData.data.ip || '<IP>'}</span>.
                      </p>
                      <div className="space-y-2">
                        {FORENSIC_ARTIFACTS.map((a) => {
                          const active = openArtifact === a.id;
                          return (
                            <div key={a.id} className={`rounded-lg border overflow-hidden ${active ? 'border-green-500/40 bg-gray-900/60' : 'border-gray-700 bg-gray-800/40'}`}>
                              <button onClick={() => setOpenArtifact(active ? null : a.id)} className="w-full flex items-center gap-2 px-3 py-2 text-left text-sm">
                                <span className={`flex-1 font-medium ${active ? 'text-green-300' : 'text-gray-200'}`}>{a.title}</span>
                                <span className="text-xs text-gray-500 hidden sm:inline truncate max-w-[40%]">{a.purpose}</span>
                                <ChevronDown className={`w-4 h-4 shrink-0 text-gray-500 transition-transform ${active ? 'rotate-180' : ''}`} />
                              </button>
                              {active && (
                                <div className="px-3 pb-3 space-y-3 text-xs">
                                  <div>
                                    <p className="text-gray-400 font-medium mb-1">Purpose</p>
                                    <p className="text-gray-300">{a.purpose}</p>
                                  </div>
                                  <div>
                                    <p className="text-gray-400 font-medium mb-1">Where to extract it</p>
                                    <div className="flex flex-wrap gap-1">
                                      {a.sources.map((s) => <span key={s} className="px-1.5 py-0.5 rounded bg-gray-800 text-gray-300 border border-gray-700">{s}</span>)}
                                    </div>
                                  </div>
                                  <div>
                                    <p className="text-gray-400 font-medium mb-1">Fields to collect</p>
                                    <div className="flex flex-wrap gap-1">
                                      {a.fields.map((f) => <code key={f} className="px-1.5 py-0.5 rounded bg-gray-900 text-cyan-300 font-mono">{f}</code>)}
                                    </div>
                                  </div>
                                  <div>
                                    <p className="text-gray-400 font-medium mb-1">Ready-to-copy queries</p>
                                    <div className="space-y-1.5">
                                      {a.queries.map((q) => (
                                        <div key={q.label} className="flex items-start gap-2">
                                          <span className="w-24 shrink-0 text-gray-500 pt-1">{q.label}</span>
                                          <code className="flex-1 px-2 py-1 rounded bg-gray-900 text-gray-300 font-mono text-[11px] break-all">{q.query}</code>
                                          <button onClick={() => copyText(q.query, `${q.label} query`)} className="p-1 hover:bg-gray-700 rounded text-gray-400" title="Copy query">
                                            <Copy className="w-3 h-3" />
                                          </button>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Threat Assessment — summarized, click to expand */}
                    {apiData.data && (
                      <div className="mt-4 p-4 bg-gray-800/50 rounded-lg border border-gray-700">
                        {(() => {
                          const severity = riskSeverityFrom(apiData);
                          const abuseScore = computeAbuseScore(apiData);
                          const factors = computeAbuseBreakdown(apiData);
                          const lastDate = (apiData.reputation?.urlhaus?.urls || []).map((u: any) => u.dateAdded).filter(Boolean).sort().slice(-1)[0];
                          const threats = (apiData.reputation?.urlhaus?.urls || []).map((u: any) => u.threat).filter(Boolean);
                          const malware = threats.length > 0 ? [...new Set(threats)].slice(0, 2).join(', ') : apiData.reputation?.torExit ? 'Tor exit (anonymization)' : null;
                          const open = (apiData.scan?.ports || []).filter((p: any) => p.state === 'open');
                          const sevClass = severity === 'CRITICAL' ? 'bg-red-600/30 text-red-300 border-red-500/60' : severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border-orange-500/40' : severity === 'MEDIUM' ? 'bg-yellow-500/15 text-yellow-300 border-yellow-500/40' : 'bg-green-500/15 text-green-300 border-green-500/40';
                          const summaryText = [
                            `Threat Assessment — ${apiData.data.query || apiData.data.ip}`,
                            `Risk: ${severity} · Abuse confidence: ${abuseScore}%`,
                            factors.length ? `Signals: ${factors.map((f) => `${f.label} (+${f.points})`).join(', ')}` : 'Signals: none',
                            `Geolocation: ${getFlagEmoji(apiData.data.countryCode)} ${apiData.data.country || 'N/A'}${apiData.data.city ? ` (${apiData.data.city})` : ''}`,
                            `ASN & ISP: ${apiData.data.as ? `AS${apiData.data.as}` : 'AS?'}${apiData.data.asname ? ` (${apiData.data.asname})` : ''} — ${apiData.data.isp || apiData.data.org || 'N/A'}`,
                            `Open ports: ${open.length ? open.map((p: any) => `${p.port} ${p.service}`).join(', ') : 'none'}`,
                            `Malware/C2: ${malware || 'none'}`,
                            `Last seen: ${lastDate ? timeAgo(lastDate) : 'no recent malicious activity'}`,
                          ].join('\n');
                          return (
                            <>
                              <button onClick={() => setShowEnrichment((v) => !v)} className="w-full flex flex-wrap items-center gap-2 text-left">
                                <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
                                <span className="text-sm font-medium flex-1">Threat Assessment</span>
                                <span className={`px-2 py-0.5 rounded border text-[10px] font-bold uppercase ${sevClass}`}>{severity}</span>
                                <span className="text-xs font-mono text-gray-300">{abuseScore}% abuse</span>
                                <ChevronDown className={`w-4 h-4 text-gray-500 shrink-0 transition-transform ${showEnrichment ? 'rotate-180' : ''}`} />
                              </button>
                              <div className="mt-2 flex flex-wrap gap-1 text-[11px]">
                                {factors.length === 0 ? (
                                  <span className="px-2 py-0.5 rounded bg-green-500/10 text-green-400 border border-green-500/40">No negative signals detected</span>
                                ) : factors.map((f) => (
                                  <span key={f.key} className={`px-2 py-0.5 rounded border ${f.points >= 15 ? 'bg-red-500/15 text-red-300 border-red-500/40' : 'bg-yellow-500/10 text-yellow-300 border-yellow-500/40'}`}>{f.label} +{f.points}</span>
                                ))}
                              </div>
                              {showEnrichment && (
                                <div className="mt-3 space-y-3">
                                  <div>
                                    <div className="flex items-center justify-between text-xs mb-1">
                                      <span className="text-gray-400">Abuse confidence</span>
                                      <span className="font-mono font-bold">{abuseScore}%</span>
                                    </div>
                                    <div className="h-2 bg-gray-700 rounded overflow-hidden">
                                      <div className="h-2 rounded" style={{ width: `${abuseScore}%`, backgroundColor: abuseScoreColor(abuseScore) }} />
                                    </div>
                                    <p className="mt-2 text-xs text-gray-300">{riskVerdict(severity)}</p>
                                  </div>
                                  <div>
                                    <p className="text-gray-400 text-xs font-medium mb-1">What drives the score</p>
                                    {factors.length === 0 ? (
                                      <p className="text-xs text-green-400">Clean on all checked sources — score stays low.</p>
                                    ) : (
                                      <ul className="space-y-1">
                                        {factors.map((f) => {
                                          const section = f.section;
                                          return (
                                            <li key={f.key} className="flex flex-wrap items-center gap-2 text-xs px-2 py-1.5 rounded bg-gray-900/60 border border-gray-700">
                                              <span className="font-mono w-14 text-right font-bold" style={{ color: abuseScoreColor(f.points) }}>+{f.points}</span>
                                              <span className="font-medium">{f.label}</span>
                                              <span className="text-gray-400 truncate flex-1 min-w-0">{f.detail}</span>
                                              {section && (
                                                <button onClick={() => scrollToSection(section)} className="px-1.5 py-0.5 rounded bg-gray-800 hover:bg-gray-700 text-blue-300 text-[10px] shrink-0">View detail ▸</button>
                                              )}
                                            </li>
                                          );
                                        })}
                                      </ul>
                                    )}
                                  </div>
                                  <div>
                                    <p className="text-gray-400 text-xs font-medium mb-1">Additional context</p>
                                    <ul className="space-y-1 text-xs text-gray-300">
                                      <li><span className="text-gray-400">ASN & ISP:</span> {apiData.data.as ? `AS${apiData.data.as}` : 'AS?'}{apiData.data.asname ? ` (${apiData.data.asname})` : ''} — {apiData.data.isp || apiData.data.org || 'N/A'}</li>
                                      <li><span className="text-gray-400">Geolocation:</span> {getFlagEmoji(apiData.data.countryCode)} {apiData.data.country || 'N/A'}{apiData.data.city ? ` (${apiData.data.city})` : ''}</li>
                                      <li><span className="text-gray-400">Malware / C2:</span> {malware || 'No known association'}</li>
                                      <li><span className="text-gray-400">Last seen:</span> {lastDate ? `${timeAgo(lastDate)} via URLhaus (${lastDate.slice(0, 10)})` : 'No recent malicious activity'}</li>
                                    </ul>
                                  </div>
                                  <div className="flex flex-wrap gap-2 text-xs">
                                    <button onClick={() => copyText(summaryText, 'threat summary')} className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded flex items-center gap-1"><Copy className="w-3 h-3" /> Copy summary</button>
                                    <button onClick={() => handleAddIOCFromResult()} className="px-2 py-1 bg-blue-600 hover:bg-blue-700 rounded flex items-center gap-1"><Plus className="w-3 h-3" /> + Add to IOC</button>
                                  </div>
                                </div>
                              )}
                            </>
                          );
                        })()}
                      </div>
                    )}

                    {/* Action Buttons on Result */}
                    <div className="mt-4 flex flex-wrap gap-2">
                      <button onClick={() => copyToClipboard(apiData.data.query || apiData.data.ip)} className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm flex items-center gap-2">
                        <Copy className="w-4 h-4" /> Copy IP
                      </button>
                      <button onClick={() => handleAddIOCFromResult()} className="px-3 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm flex items-center gap-2">
                        <Plus className="w-4 h-4" /> + Add to IOC
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Globe className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Ready for IP Analysis</h3>
                  <p className="text-gray-400 mb-4">Enter an IP address above to get real-time geolocation and intelligence data.</p>
                  <p className="text-xs text-gray-500">Powered by ip-api.com with live data</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== DOMAIN INTEL TAB ==================== */}
          {activeTab === 'domain' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Server className="w-7 h-7 text-purple-400" /> Domain Intel
                  <span className="text-sm font-normal text-gray-400">passive recon · DNS · WHOIS · subdomains · infra graph</span>
                </h2>
                <button
                  onClick={() => openPrintReport('domain', apiData?.domainIntel || apiData, inputValue)}
                  className="px-4 py-2 bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 border border-purple-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <DomainIntelPanel
                intel={apiData?.domainIntel || null}
                virusTotal={apiData?.virusTotal || null}
                loading={loading}
                inputValue={inputValue}
                setInputValue={setInputValue}
                onAnalyze={handleDomainRecon}
                onCopy={copyToClipboard}
                onGoForensics={(domain) => {
                  setActiveTab('forensics');
                  setInputValue(domain);
                  showFeedback(`Launching full web forensics for ${domain}...`, 'info');
                  setTimeout(() => handleForensicAnalysis(domain), 250);
                }}
              />
            </div>
          )}

          {/* ==================== FORENSICS TAB (Advanced Web Forensic Module) ==================== */}
          {activeTab === 'forensics' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Camera className="w-7 h-7 text-red-400" /> Web Forensic Analysis
                  <span className="text-sm font-normal text-gray-400">DNS recon · fuzzing tree · phishing kits · databases · attribution</span>
                </h2>
                <button
                  onClick={() => openPrintReport('forensics', apiData?.forensics || apiData, inputValue)}
                  className="px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>

              <div className="bg-gray-900 border border-red-500/30 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter URL or domain for advanced forensic analysis..."
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleForensicAnalysis()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-red-500 focus:outline-none font-mono"
                    />
                  </div>
                  <button
                    onClick={() => handleForensicAnalysis()}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Camera className="w-4 h-4" />}
                    Start Forensics
                  </button>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  <span className="text-xs text-gray-500">Includes:</span>
                  {['DNS Recon', 'Subdomain Enumeration', 'Directory Fuzzing', 'Phishing Kit Detection', 'DB Exposure Scan', 'Source Attribution', 'VirusTotal'].map(item => (
                    <span key={item} className="px-2 py-1 bg-red-500/10 text-red-400 rounded text-xs">{item}</span>
                  ))}
                </div>
              </div>

              {/* Previous Analyses / Resource History */}
              {forensicsHistory.length > 0 && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                  <div className="flex items-center justify-between mb-3">
                      <h3 className="font-semibold flex items-center gap-2">
                        <FolderOpen className="w-5 h-5 text-yellow-400" /> Analyzed Resources ({forensicsHistory.length})
                      </h3>
                      <div className="flex items-center gap-2">
                        {storageHealth && (
                          <button
                            onClick={getStorageHealth}
                            title={storageHealth.backend === 'vercel-kv'
                              ? (storageHealth.message || 'Vercel KV conectado')
                              : 'Historial del servidor en memoria efímera (se reinicia por invocación). Para persistencia real: Vercel → Storage → Create Database → KV → Redeploy. El historial igual funciona vía localStorage del navegador.'}
                            className={`text-[10px] px-2 py-0.5 rounded flex items-center gap-1 ${
                              storageHealth.backend === 'vercel-kv' ? 'bg-green-500/20 text-green-400' : 'bg-amber-500/20 text-amber-400'
                            }`}
                          >
                            ● {storageHealth.backend === 'vercel-kv' ? 'KV conectado' : 'Memoria efímera'}
                          </button>
                        )}
                        <button onClick={loadForensicsHistory} className="text-xs text-gray-400 hover:text-gray-200 flex items-center gap-1">
                          <RefreshCw className="w-3 h-3" /> Refresh
                        </button>
                      </div>
                    </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left text-xs text-gray-500 border-b border-gray-800">
                          <th className="py-2 pr-3">Site</th>
                          <th className="py-2 pr-3">IP</th>
                          <th className="py-2 pr-3">Date</th>
                          <th className="py-2 pr-3">Risk</th>
                          <th className="py-2 pr-3">Kits</th>
                          <th className="py-2 pr-3">DBs</th>
                          <th className="py-2 pr-3">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {forensicsHistory.slice(0, 10).map((analysis: any, idx: number) => {
                          const isCurrentlyLoaded = selectedForensics?.id === analysis.id || selectedForensics?.name === analysis.name;
                          const displayName = analysis.domain || analysis.name?.split('_')[1] || '—';
                          return (
                            <tr key={idx} className={`border-b border-gray-800/50 ${isCurrentlyLoaded ? 'bg-blue-500/10' : 'hover:bg-gray-800/40'}`}>
                              <td className="py-2 pr-3 font-mono text-red-300">{displayName}</td>
                              <td className="py-2 pr-3 font-mono text-xs text-gray-400">{analysis.ip || '—'}</td>
                              <td className="py-2 pr-3 text-xs text-gray-400">{new Date(analysis.created).toLocaleString()}</td>
                              <td className="py-2 pr-3">
                                <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                                  analysis.riskLevel === 'CRITICAL' ? 'bg-red-500 text-white' :
                                  analysis.riskLevel === 'HIGH' ? 'bg-orange-500 text-black' :
                                  analysis.riskLevel === 'MEDIUM' ? 'bg-yellow-500 text-black' : 'bg-green-500/20 text-green-400'
                                }`}>{analysis.riskLevel} ({analysis.score})</span>
                              </td>
                              <td className="py-2 pr-3 text-xs">
                                {analysis.kits > 0 ? <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded text-[10px] font-bold">{analysis.kits}</span> : <span className="text-gray-600">0</span>}
                              </td>
                              <td className="py-2 pr-3 text-xs">
                                {analysis.databases > 0 ? <span className="px-1.5 py-0.5 bg-orange-500/20 text-orange-400 rounded text-[10px] font-bold">{analysis.databases}</span> : <span className="text-gray-600">0</span>}
                              </td>
                              <td className="py-2 pr-3 text-right">
                                <div className="flex items-center justify-end gap-1">
                                  {isCurrentlyLoaded ? (
                                    <span className="text-xs px-2 py-1 bg-blue-600/20 text-blue-400 rounded flex items-center gap-1">
                                      <CheckCircle className="w-3 h-3" /> Loaded
                                    </span>
                                  ) : (
                                    <button
                                      onClick={() => setLoadConfirm({ id: analysis.name, name: displayName })}
                                      className="text-xs px-2 py-1 bg-red-600/20 hover:bg-red-600/40 text-red-400 rounded"
                                    >Open</button>
                                  )}
                                    <button
                                      onClick={() => setDeleteConfirm({ id: analysis.name, name: displayName })}
                                      className="text-xs px-2 py-1 bg-gray-600/20 hover:bg-gray-600/40 text-gray-400 rounded"
                                      title="Delete this analysis"
                                    >
                                      <Trash2 className="w-3 h-3" />
                                    </button>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Load Confirmation Modal */}
              {loadConfirm && (
                <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setLoadConfirm(null)}>
                  <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-md w-full p-6" onClick={(e) => e.stopPropagation()}>
                    <h3 className="font-bold text-lg mb-4 flex items-center gap-2"><FolderOpen className="w-5 h-5 text-yellow-400" /> Load Analysis</h3>
                    <p className="text-gray-300 mb-4">Load forensic analysis for <span className="font-mono text-red-300">{loadConfirm.name}</span>?</p>
                    <p className="text-xs text-gray-500 mb-6">This will replace the current view with the stored results.</p>
                    <div className="flex justify-end gap-2">
                      <button onClick={() => setLoadConfirm(null)} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg">Cancel</button>
                      <button
                        onClick={async () => {
                          const id = loadConfirm.id;
                          setLoadConfirm(null);
                          const localItem = localHistoryLoad().find((i: any) => i.name === id);
                          if (localItem) {
                            setApiData({ success: true, data: localItem });
                            setSelectedForensics(localItem);
                            showFeedback('Recurso cargado (local)', 'success');
                            return;
                          }
                          showFeedback('Cargando recurso forense...', 'info');
                          const res = await fetch(`/api/osint/forensics?action=get&id=${encodeURIComponent(id)}&module=forensics`);
                          const data = await res.json();
                          if (data.success) { setApiData({ success: true, data: data.data }); setSelectedForensics(data.data); }
                          else showFeedback(`Error: ${data.error || 'not found'}`, 'error');
                        }}
                        className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg"
                      >Load</button>
                    </div>
                  </div>
                </div>
              )}

              {/* Delete Confirmation Modal */}
              {deleteConfirm && (
                <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setDeleteConfirm(null)}>
                  <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-md w-full p-6" onClick={(e) => e.stopPropagation()}>
                    <h3 className="font-bold text-lg mb-4 flex items-center gap-2"><Trash2 className="w-5 h-5 text-red-400" /> Delete Analysis</h3>
                    <p className="text-gray-300 mb-4">Delete forensic analysis for <span className="font-mono text-red-300">{deleteConfirm.name}</span>?</p>
                    <p className="text-xs text-gray-500 mb-6">This action cannot be undone. The resource will be removed from history.</p>
                    <div className="flex justify-end gap-2">
                      <button onClick={() => setDeleteConfirm(null)} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg">Cancel</button>
                      <button
                        onClick={async () => {
                          const id = deleteConfirm.id;
                          setDeleteConfirm(null);
                          showFeedback('Eliminando recurso forense...', 'info');
                          localHistoryRemove(id);
                          try {
                            await fetch(`/api/osint/forensics?action=delete&id=${encodeURIComponent(id)}&module=forensics`, { method: 'DELETE' });
                          } catch {}
                          loadForensicsHistory();
                          if (selectedForensics?.id === id || selectedForensics?.name === id) { setApiData(null); setSelectedForensics(null); }
                          showFeedback('Recurso eliminado', 'success');
                        }}
                        className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg"
                      >Delete</button>
                    </div>
                  </div>
                </div>
              )}

               {/* Forensics Results */}
               {apiData?.data && activeTab === 'forensics' && (
                 <div className="space-y-4">
                   {/* Risk Assessment */}
                   {apiData.data.risk && (
                     <div className={`rounded-xl p-5 border ${
                       apiData.data.risk.level === 'CRITICAL' ? 'bg-red-500/10 border-red-500/50' :
                       apiData.data.risk.level === 'HIGH' ? 'bg-orange-500/10 border-orange-500/50' :
                       apiData.data.risk.level === 'MEDIUM' ? 'bg-yellow-500/10 border-yellow-500/50' :
                       'bg-green-500/10 border-green-500/50'
                     }`}>
                        <div className="flex items-center justify-between flex-wrap gap-3">
                          <div>
                            <h3 className="font-semibold flex items-center gap-2">
                              <ShieldAlert className="w-5 h-5" /> Forensic Risk Assessment
                              <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                                apiData.data.risk.level === 'CRITICAL' ? 'bg-red-500 text-white' :
                                apiData.data.risk.level === 'HIGH' ? 'bg-orange-500 text-black' :
                                apiData.data.risk.level === 'MEDIUM' ? 'bg-yellow-500 text-black' : 'bg-green-500 text-black'
                              }`}>
                                {apiData.data.risk.level} ({apiData.data.risk.score}/100)
                              </span>
                            </h3>
                            <p className="text-sm font-mono text-red-300 mt-1 break-all">{apiData.data.domain}</p>
                            <p className="text-sm text-gray-400 mt-1">{apiData.data.verdict || 'No critical indicators found'}</p>
                          </div>
                          <div className="flex flex-col items-end gap-2">
                            <button
                              onClick={handleForensicReport}
                              className="text-xs px-2.5 py-1 bg-purple-600 hover:bg-purple-700 rounded text-white flex items-center gap-1.5"
                            >
                              <Download className="w-3 h-3" /> Informe imprimible (HTML)
                            </button>
                            <div className="text-right text-xs text-gray-400">
                              <div>IP: <span className="font-mono">{apiData.data.ip || '—'}</span></div>
                              <div className="mt-1">ASN: <span className="font-mono">{apiData.data.asn || '—'}</span></div>
                              <div className="mt-1">ISP: <span className="font-mono">{apiData.data.isp || '—'}</span></div>
                              <div className="mt-1">Resource: <span className="font-mono">{apiData.data.name}</span></div>
                              <div className="mt-1">{new Date(apiData.data.timestamp).toLocaleString()}</div>
                            </div>
                          </div>
                        </div>
                       <div className="mt-3 h-2 rounded-full bg-gray-900 overflow-hidden">
                         <div className={`h-full ${apiData.data.risk.level === 'CRITICAL' ? 'bg-red-500' : apiData.data.risk.level === 'HIGH' ? 'bg-orange-500' : apiData.data.risk.level === 'MEDIUM' ? 'bg-yellow-500' : 'bg-green-500'}`}
                           style={{ width: `${Math.max(apiData.data.risk.score, 2)}%` }} />
                       </div>

                       {/* Evidencias completas del Web Forensic Analysis */}
                       <details className="mt-4">
                         <summary className="text-xs text-gray-400 cursor-pointer hover:text-gray-200 flex items-center gap-1.5 select-none">
                           <ChevronDown className="w-3.5 h-3.5" /> Análisis completo — todas las evidencias del módulo (clic para desplegar)
                         </summary>
                         <div className="mt-4 space-y-5">

                           {/* Infraestructura / Geo / SSL / HTTP */}
                           <div>
                             <div className="text-xs uppercase text-gray-500 mb-2">Infraestructura, Geo, SSL y HTTP</div>
                             <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                               <div className="p-2 bg-gray-900 rounded-lg">
                                 <div className="text-[10px] uppercase text-gray-500">IP</div>
                                 <div className="text-xs font-mono break-all">{apiData.data.ip || '—'}</div>
                               </div>
                               <div className="p-2 bg-gray-900 rounded-lg">
                                 <div className="text-[10px] uppercase text-gray-500">ASN</div>
                                 <div className="text-xs font-mono">{apiData.data.asn || '—'}</div>
                               </div>
                               <div className="p-2 bg-gray-900 rounded-lg">
                                 <div className="text-[10px] uppercase text-gray-500">ISP</div>
                                 <div className="text-xs">{apiData.data.isp || '—'}</div>
                               </div>
                               <div className="p-2 bg-gray-900 rounded-lg">
                                 <div className="text-[10px] uppercase text-gray-500">Geo</div>
                                 <div className="text-xs">{apiData.data.geo ? `${apiData.data.geo.country || ''}${apiData.data.geo.city ? ' / ' + apiData.data.geo.city : ''}` : '—'}</div>
                               </div>
                               <div className="p-2 bg-gray-900 rounded-lg">
                                 <div className="text-[10px] uppercase text-gray-500">SSL/TLS</div>
                                 <div className="text-xs flex items-center gap-1">
                                   {apiData.data.ssl?.secure === true ? <CheckCircle className="w-3.5 h-3.5 text-green-400" /> : <XCircle className="w-3.5 h-3.5 text-red-400" />}
                                   {apiData.data.ssl?.secure === true ? 'Verificado' : 'No verificado'}
                                 </div>
                               </div>
                               <div className="p-2 bg-gray-900 rounded-lg">
                                 <div className="text-[10px] uppercase text-gray-500">Protocolo SSL</div>
                                 <div className="text-xs">{apiData.data.ssl?.protocol || '—'}</div>
                               </div>
                               <div className="p-2 bg-gray-900 rounded-lg">
                                 <div className="text-[10px] uppercase text-gray-500">Servidor</div>
                                 <div className="text-xs break-all">{apiData.data.httpHeaders?.server || '—'}</div>
                               </div>
                               <div className="p-2 bg-gray-900 rounded-lg">
                                 <div className="text-[10px] uppercase text-gray-500">HTTP Status</div>
                                 <div className="text-xs">{apiData.data.httpHeaders?.statusCode ?? '—'}</div>
                               </div>
                             </div>
                           </div>

                           {/* Security headers */}
                           {apiData.data.httpHeaders?.securityHeaders && (
                             <div>
                               <div className="text-xs uppercase text-gray-500 mb-2">Security Headers ({apiData.data.httpHeaders.securityScore})</div>
                               <div className="grid grid-cols-1 md:grid-cols-3 gap-1.5">
                                 {Object.entries(apiData.data.httpHeaders.securityHeaders).map(([h, present]) => (
                                   <div key={h} className="flex items-center gap-1.5 text-xs">
                                     {present ? <CheckCircle className="w-3.5 h-3.5 text-green-400" /> : <XCircle className="w-3.5 h-3.5 text-red-400" />}
                                     <span className={present ? '' : 'text-gray-500 line-through'}>{h}</span>
                                   </div>
                                 ))}
                               </div>
                             </div>
                           )}

                           {/* Todos los headers */}
                           {apiData.data.httpHeaders?.headers && (
                             <div>
                               <div className="text-xs uppercase text-gray-500 mb-2">Todos los headers HTTP ({Object.keys(apiData.data.httpHeaders.headers).length})</div>
                               <div className="max-h-48 overflow-auto bg-gray-900 rounded-lg p-2">
                                 {Object.entries(apiData.data.httpHeaders.headers).map(([k, v]) => (
                                   <div key={k} className="text-[11px] font-mono py-0.5 border-b border-gray-800 last:border-0 break-all">
                                     <span className="text-cyan-400">{k}:</span> <span className="text-gray-300">{String(v)}</span>
                                   </div>
                                 ))}
                               </div>
                             </div>
                           )}

                           {/* DNS */}
                           {apiData.data.dns && (
                             <div>
                               <div className="text-xs uppercase text-gray-500 mb-2">DNS (Google DoH)</div>
                               <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                                 {Object.entries(apiData.data.dns).map(([type, records]: [string, any]) => (
                                   <div key={type} className="p-2 bg-gray-900 rounded-lg">
                                     <div className="text-[10px] font-medium text-gray-500 mb-1">{type} ({records?.Answer?.length || 0})</div>
                                     {(records?.Answer || []).slice(0, 4).map((r: any, i: number) => (
                                       <div key={i} className="text-[11px] font-mono text-green-400 truncate">{r.data || r.exchange || r.nsdname || '—'}</div>
                                     ))}
                                   </div>
                                 ))}
                               </div>
                             </div>
                           )}

                           {/* Subdominios */}
                           {apiData.data.subdomains?.length > 0 && (
                             <div>
                               <div className="text-xs uppercase text-gray-500 mb-2">Subdominios ({apiData.data.subdomains.length})</div>
                               <div className="flex flex-wrap gap-1.5">
                                 {apiData.data.subdomains.map((s: string, i: number) => (
                                   <span key={i} className="px-2 py-0.5 bg-gray-900 rounded font-mono text-[11px]">{s}</span>
                                 ))}
                               </div>
                             </div>
                           )}

                           {/* Fuzzing */}
                           {apiData.data.fuzzingSummary && (
                             <div>
                               <div className="text-xs uppercase text-gray-500 mb-2">Fuzzing de directorios</div>
                               <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                                 <div className="p-2 bg-gray-900 rounded-lg">
                                   <div className="text-[10px] uppercase text-gray-500">Rutas probadas</div>
                                   <div className="text-xs">{apiData.data.fuzzingSummary.totalProbed ?? 0}</div>
                                 </div>
                                 <div className="p-2 bg-gray-900 rounded-lg">
                                   <div className="text-[10px] uppercase text-gray-500">Expuestas</div>
                                   <div className="text-xs">{apiData.data.fuzzingSummary.exposed ?? 0}</div>
                                 </div>
                                 <div className="p-2 bg-gray-900 rounded-lg">
                                   <div className="text-[10px] uppercase text-gray-500">Archivos en kits</div>
                                   <div className="text-xs">{apiData.data.fuzzingSummary.archiveEntries ?? 0}</div>
                                 </div>
                                 <div className="p-2 bg-gray-900 rounded-lg">
                                   <div className="text-[10px] uppercase text-gray-500">Tablas BD</div>
                                   <div className="text-xs">{apiData.data.fuzzingSummary.dbTables ?? 0}</div>
                                 </div>
                               </div>
                               <div className="mt-2 grid grid-cols-1 md:grid-cols-2 gap-2">
                                 <div className="p-2 bg-gray-900 rounded-lg">
                                   <div className="text-[10px] uppercase text-gray-500">Por status</div>
                                   <div className="text-[11px] font-mono break-all">{Object.entries(apiData.data.fuzzingSummary.byStatus || {}).map(([k, v]) => `${k}:${v}`).join(' · ') || '—'}</div>
                                 </div>
                                 <div className="p-2 bg-gray-900 rounded-lg">
                                   <div className="text-[10px] uppercase text-gray-500">Por categoría</div>
                                   <div className="text-[11px] font-mono break-all">{Object.entries(apiData.data.fuzzingSummary.byCategory || {}).map(([k, v]) => `${k}:${v}`).join(' · ') || '—'}</div>
                                 </div>
                               </div>
                             </div>
                           )}

                           {/* Atribución */}
                           {apiData.data.attribution && (
                             <div>
                               <div className="text-xs uppercase text-gray-500 mb-2">Atribución de actor</div>
                               <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                 <div className="p-2 bg-gray-900 rounded-lg">
                                   <div className="text-[10px] uppercase text-gray-500">Emails ({apiData.data.attribution.emails?.length || 0})</div>
                                   <div className="flex flex-wrap gap-1 mt-1">
                                     {apiData.data.attribution.emails?.length ? apiData.data.attribution.emails.map((e: string, i: number) => (
                                       <span key={i} className="px-1.5 py-0.5 bg-gray-800 rounded text-[10px] font-mono">{e}</span>
                                     )) : <span className="text-[11px] text-gray-500">ninguno</span>}
                                   </div>
                                 </div>
                                 <div className="p-2 bg-gray-900 rounded-lg">
                                   <div className="text-[10px] uppercase text-gray-500">Telegram ({apiData.data.attribution.telegramIds?.length || 0})</div>
                                   <div className="flex flex-wrap gap-1 mt-1">
                                     {apiData.data.attribution.telegramIds?.length ? apiData.data.attribution.telegramIds.map((t: string, i: number) => (
                                       <span key={i} className="px-1.5 py-0.5 bg-gray-800 rounded text-[10px] font-mono">{t}</span>
                                     )) : <span className="text-[11px] text-gray-500">ninguno</span>}
                                   </div>
                                 </div>
                                 <div className="p-2 bg-gray-900 rounded-lg">
                                   <div className="text-[10px] uppercase text-gray-500">API Keys / Secrets ({apiData.data.attribution.apiKeys?.length || 0})</div>
                                   <div className="flex flex-wrap gap-1 mt-1">
                                     {apiData.data.attribution.apiKeys?.length ? apiData.data.attribution.apiKeys.map((k: string, i: number) => (
                                       <span key={i} className="px-1.5 py-0.5 bg-gray-800 rounded text-[10px] font-mono break-all">{k.slice(0, 60)}</span>
                                     )) : <span className="text-[11px] text-gray-500">ninguno</span>}
                                   </div>
                                 </div>
                                 <div className="p-2 bg-gray-900 rounded-lg">
                                   <div className="text-[10px] uppercase text-gray-500">Tracking IDs ({apiData.data.attribution.trackingIds?.length || 0})</div>
                                   <div className="flex flex-wrap gap-1 mt-1">
                                     {apiData.data.attribution.trackingIds?.length ? apiData.data.attribution.trackingIds.map((t: string, i: number) => (
                                       <span key={i} className="px-1.5 py-0.5 bg-gray-800 rounded text-[10px] font-mono">{t}</span>
                                     )) : <span className="text-[11px] text-gray-500">ninguno</span>}
                                   </div>
                                 </div>
                               </div>
                               {(apiData.data.attribution.toolSignatures?.length > 0 || apiData.data.attribution.links?.length > 0) && (
                                 <div className="mt-2 grid grid-cols-1 md:grid-cols-2 gap-2">
                                   <div className="p-2 bg-gray-900 rounded-lg">
                                     <div className="text-[10px] uppercase text-gray-500">Firmas de herramienta</div>
                                     <div className="flex flex-wrap gap-1 mt-1">
                                       {apiData.data.attribution.toolSignatures?.length ? apiData.data.attribution.toolSignatures.map((s: string, i: number) => (
                                         <span key={i} className="px-1.5 py-0.5 bg-gray-800 rounded text-[10px]">{s}</span>
                                       )) : <span className="text-[11px] text-gray-500">ninguna</span>}
                                     </div>
                                   </div>
                                   <div className="p-2 bg-gray-900 rounded-lg">
                                     <div className="text-[10px] uppercase text-gray-500">Links externos</div>
                                     <div className="max-h-24 overflow-auto mt-1">
                                       {apiData.data.attribution.links?.length ? apiData.data.attribution.links.map((l: string, i: number) => (
                                         <div key={i} className="text-[10px] font-mono text-gray-400 truncate">{l}</div>
                                       )) : <div className="text-[11px] text-gray-500">ninguno</div>}
                                     </div>
                                   </div>
                                 </div>
                               )}
                             </div>
                           )}

                           {/* VirusTotal */}
                           {apiData.data.virusTotal && (
                             <div>
                               <div className="text-xs uppercase text-gray-500 mb-2">VirusTotal</div>
                               <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                                 <div className="p-2 bg-gray-900 rounded-lg">
                                   <div className="text-[10px] uppercase text-gray-500">Veredicto</div>
                                   <div className="text-xs">{apiData.data.virusTotal.verdict || '—'}</div>
                                 </div>
                                 <div className="p-2 bg-gray-900 rounded-lg">
                                   <div className="text-[10px] uppercase text-gray-500">Malicious</div>
                                   <div className="text-xs text-red-400">{apiData.data.virusTotal.lastAnalysisStats?.malicious ?? 0}</div>
                                 </div>
                                 <div className="p-2 bg-gray-900 rounded-lg">
                                   <div className="text-[10px] uppercase text-gray-500">Suspicious</div>
                                   <div className="text-xs text-orange-400">{apiData.data.virusTotal.lastAnalysisStats?.suspicious ?? 0}</div>
                                 </div>
                                 <div className="p-2 bg-gray-900 rounded-lg">
                                   <div className="text-[10px] uppercase text-gray-500">Harmless</div>
                                   <div className="text-xs text-green-400">{apiData.data.virusTotal.lastAnalysisStats?.harmless ?? 0}</div>
                                 </div>
                               </div>
                             </div>
                           )}

                           {/* Artefactos */}
                           {apiData.data.artifacts?.length > 0 && (
                             <div>
                               <div className="text-xs uppercase text-gray-500 mb-2">Artefactos descargados ({apiData.data.artifacts.length})</div>
                               <div className="max-h-48 overflow-auto space-y-1.5">
                                 {apiData.data.artifacts.map((a: any, i: number) => (
                                   <div key={i} className="p-2 bg-gray-900 rounded-lg text-[11px]">
                                     <div className="flex items-center gap-2">
                                       <span className="uppercase text-[10px] px-1.5 py-0.5 rounded bg-gray-800">{a.category || 'other'}</span>
                                       <span className="font-mono break-all flex-1">{a.url}</span>
                                       {a.downloaded && <CheckCircle className="w-3.5 h-3.5 text-green-400 shrink-0" />}
                                     </div>
                                     {(a.hash || a.size) && (
                                       <div className="text-[10px] text-gray-500 mt-1 truncate">
                                         {a.hash ? `SHA-256: ${a.hash}` : ''}{a.size ? ` · ${(a.size / 1024).toFixed(1)} KB` : ''}
                                       </div>
                                     )}
                                   </div>
                                 ))}
                               </div>
                             </div>
                           )}

                           {/* Redirects / cadenas */}
                           {(() => {
                             const redirects: string[] = [];
                             const walkRedirects = (n: any) => {
                               if (n?.redirectChain?.length) {
                                 let prev = '';
                                 n.redirectChain.forEach((r: string) => {
                                   if (r !== prev) redirects.push(r);
                                   prev = r;
                                 });
                               }
                               (n?.children || []).forEach(walkRedirects);
                             };
                             walkRedirects(apiData.data.resourceTree);
                             return redirects.length ? (
                               <div>
                                 <div className="text-xs uppercase text-gray-500 mb-2">Cadenas de redirección</div>
                                 <div className="max-h-32 overflow-auto space-y-1">
                                   {Array.from(new Set(redirects)).slice(0, 40).map((r: string, i: number) => (
                                     <div key={i} className="text-[10px] font-mono text-gray-400 truncate">{r}</div>
                                   ))}
                                 </div>
                               </div>
                             ) : null;
                           })()}

                           {/* Resource Tree stats */}
                           {apiData.data.resourceTree && (
                             <div>
                               <div className="text-xs uppercase text-gray-500 mb-2">Resource Tree (Live Crawl)</div>
                               <div className="p-2 bg-gray-900 rounded-lg text-[11px] text-gray-400">
                                 El árbol completo de recursos (páginas, scripts, redirecciones, fuzz) se muestra en la sección "Resource Tree — Live Crawl" de esta pestaña y en el informe imprimible.
                               </div>
                             </div>
                           )}

                         </div>
                       </details>
</div>
                    )}

                    {/* Live Screenshot */}
                    {apiData.data && (
                      <div className="bg-gray-900 border border-yellow-500/30 rounded-xl p-5">
                        <h3 className="font-semibold mb-3 flex items-center gap-2">
                          <Camera className="w-5 h-5 text-yellow-400" /> Live Screenshot
                          <span className="text-xs bg-yellow-500/20 text-yellow-400 px-2 py-0.5 rounded">
                            Captured: {(() => { const d = new Date(); const utc5 = new Date(d.getTime() - 5 * 60 * 60 * 1000); return utc5.toISOString().slice(0, 19).replace('T', ' ') + ' UTC-5'; })()}
                          </span>
                        </h3>
                        <div className="relative aspect-video bg-gray-950 rounded-lg border border-gray-800 overflow-hidden">
                          {(() => {
                            const domain = apiData.data.domain;
                            const screenshotUrl = `https://s0.wp.com/mshots/v1/${encodeURIComponent('https://' + domain)}?w=1280&h=720`;
                            return (
                              <a href={screenshotUrl} target="_blank" rel="noopener noreferrer" className="block">
                                <img
                                  src={screenshotUrl}
                                  alt={`Screenshot of ${domain}`}
                                  className="w-full h-full object-cover"
                                  loading="lazy"
                                />
                              </a>
                            );
                          })()}
                        </div>
                        <p className="text-xs text-gray-500 mt-2 text-center">
                          Captured via WordPress mshots (UTC-5). Click to open full-size in new tab.
                        </p>
                      </div>
                    )}

                    {/* VirusTotal indicators */}
                    {apiData.data.virusTotal && (
                     <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                       <div className="flex items-center gap-3 mb-3 flex-wrap">
                         <h3 className="font-semibold flex items-center gap-2">
                           <Shield className="w-5 h-5 text-orange-400" /> VirusTotal Indicators
                         </h3>
                         <span className={`px-2.5 py-1 rounded-lg text-xs font-semibold border ${
                           apiData.data.virusTotal.verdict === 'MALICIOUS' ? 'bg-red-500/20 text-red-400 border-red-500/40'
                           : apiData.data.virusTotal.verdict === 'SUSPICIOUS' ? 'bg-orange-500/20 text-orange-400 border-orange-500/40'
                           : apiData.data.virusTotal.verdict === 'CLEAN' ? 'bg-green-500/20 text-green-400 border-green-500/40'
                           : 'bg-gray-700 text-gray-300 border-gray-600'
                         }`}>{apiData.data.virusTotal.verdict}</span>
                         <a href={apiData.data.virusTotal.url} target="_blank" rel="noreferrer" className="text-xs text-orange-400 hover:text-orange-300 flex items-center gap-1 ml-auto">
                           <ExternalLink className="w-3.5 h-3.5" /> View on VirusTotal
                         </a>
                       </div>
                       <div className="flex flex-wrap items-center gap-6">
                         {[
                           { label: 'malicious', v: apiData.data.virusTotal.lastAnalysisStats?.malicious || 0, c: 'text-red-400' },
                           { label: 'suspicious', v: apiData.data.virusTotal.lastAnalysisStats?.suspicious || 0, c: 'text-orange-400' },
                           { label: 'harmless', v: apiData.data.virusTotal.lastAnalysisStats?.harmless || 0, c: 'text-green-400' },
                           { label: 'engines', v: apiData.data.virusTotal.totalEngines || 0, c: 'text-gray-300' },
                         ].map((s) => (
                           <div key={s.label} className="text-center">
                             <div className={`text-2xl font-bold ${s.c}`}>{s.v}</div>
                             <div className="text-[10px] text-gray-500">{s.label}</div>
                           </div>
                         ))}
                         <div className="text-xs text-gray-400">
                           <div>Reputation: <span className="font-bold">{apiData.data.virusTotal.reputation}</span></div>
                           {apiData.data.virusTotal.lastAnalysisDate && <div>Last: {new Date(apiData.data.virusTotal.lastAnalysisDate).toISOString().slice(0, 10)}</div>}
                         </div>
                       </div>
                     </div>
                   )}

                    {/* Resource Tree (Live Crawl) - Interactive + Downloadable */}
                    {apiData.data.resourceTree && (
                      <div className="bg-gray-900 border border-blue-500/30 rounded-xl p-5">
                        <h3 className="font-semibold mb-3 flex items-center gap-2 flex-wrap">
                          <FileCode className="w-5 h-5 text-blue-400" /> Resource Tree — Live Crawl (gospider-style)
                          <span className="text-xs bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded">
                            {(() => { let c=0; const count=(n:any)=>{c++; n.children?.forEach(count); }; count(apiData.data.resourceTree); return c; })()} nodes
                          </span>
                          <button
                            onClick={handleWgetZip}
                            disabled={wgetZipLoading}
                            className="ml-auto text-xs px-2.5 py-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded text-white flex items-center gap-1.5"
                          >
                            <Download className="w-3 h-3" /> {wgetZipLoading ? 'Descargando rutas...' : 'Descargar todas las rutas (.zip)'}
                          </button>
                        </h3>
                        <p className="text-xs text-gray-500 mb-3">Click para expandir. Usa <Download className="w-3 h-3 inline" /> en un nodo para descargar su contenido real (wget/curl-style), o descarga todas las rutas en un solo .zip.</p>
                        <div className="max-h-[400px] overflow-auto space-y-1">
                          <TreeNode node={apiData.data.resourceTree} indent={0} onDownload={downloadNodeContent} />
                        </div>
                      </div>
                    )}

                   {/* Evidence Download Section */}
                   {apiData.data.artifacts?.length > 0 && (
                     <div className="bg-gray-900 border border-red-500/30 rounded-xl p-5">
                       <h3 className="font-semibold mb-3 flex items-center gap-2">
                         <Download className="w-5 h-5 text-red-400" /> Evidence — Downloaded Artifacts
                         <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs">{apiData.data.artifacts.filter((a: any) => a.category === 'phishing_kit' && a.downloaded).length} kit(s)</span>
                         <span className="px-2 py-0.5 bg-orange-500/20 text-orange-400 rounded text-xs">{apiData.data.artifacts.filter((a: any) => a.category === 'database' && a.downloaded).length} db(s)</span>
                         <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-400 rounded text-xs">{apiData.data.artifacts.filter((a: any) => a.category === 'config' && a.downloaded).length} config(s)</span>
                         <span className="px-2 py-0.5 bg-gray-500/20 text-gray-400 rounded text-xs">{apiData.data.artifacts.filter((a: any) => a.category === 'backup' && a.downloaded).length} backup(s)</span>
                       </h3>
                        <div className="space-y-2">
                          {apiData.data.artifacts.filter((a: any) => a.downloaded).map((a: any, i: number) => (
                            <details key={i} className="p-3 bg-gray-800/50 border border-gray-700 rounded-lg group">
                              <summary className="flex items-center gap-3 cursor-pointer list-none">
                                <span className={`w-2 h-2 rounded-full shrink-0 ${
                                  a.category === 'phishing_kit' ? 'bg-red-400' : a.category === 'database' ? 'bg-orange-400' : a.category === 'config' ? 'bg-yellow-400' : 'bg-gray-400'
                                }`} />
                                <span className="font-mono text-xs text-gray-300 flex-1 truncate">{a.url}</span>
                                {a.structure?.note && <span className="text-[10px] px-2 py-0.5 bg-blue-500/10 text-blue-300 rounded shrink-0 hidden sm:inline">{a.structure.note}</span>}
                                {a.structure?.sensitive && <span className="text-[10px] px-2 py-0.5 bg-red-500/20 text-red-400 rounded shrink-0">sensitive</span>}
                                <span className="text-xs text-gray-500 shrink-0">{(a.size / 1024).toFixed(1)} KB</span>
                                {a.hash && <span className="text-[10px] font-mono text-gray-500 hidden md:inline shrink-0">SHA256: {a.hash}</span>}
                                <a href={a.url} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()} className="text-xs px-2 py-1 bg-red-600 hover:bg-red-700 rounded text-white flex items-center gap-1 shrink-0">
                                  <Download className="w-3 h-3" /> Download
                                </a>
                                <ChevronDown className="w-4 h-4 text-gray-500 transition-transform shrink-0 group-open:rotate-180" />
                              </summary>
                              <div className="mt-3 pt-3 border-t border-gray-700 space-y-3 text-xs">
                                {a.structure?.entries && a.structure.entries.length > 0 && (
                                  <div>
                                    <p className="text-gray-400 mb-1.5 font-medium">Internal structure ({a.structure.entries.length} items)</p>
                                    <div className="max-h-56 overflow-auto bg-gray-900/60 rounded-lg p-2 font-mono text-[11px] space-y-0.5">
                                      {a.structure.entries.map((e: any, j: number) => (
                                        <div key={j} className="flex items-center gap-2">
                                          <span className={`shrink-0 ${e.type === 'dir' ? 'text-yellow-400' : 'text-gray-400'}`}>{e.type === 'dir' ? '📁' : '📄'}</span>
                                          <span className="text-gray-300 truncate flex-1">{e.name}</span>
                                          {e.size > 0 && <span className="text-gray-500 shrink-0">{(e.size / 1024).toFixed(1)} KB</span>}
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {a.structure?.tables && a.structure.tables.length > 0 && (
                                  <div>
                                    <p className="text-gray-400 mb-1.5 font-medium">Database schema ({a.structure.tables.length} tables)</p>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                      {a.structure.tables.map((t: any, j: number) => (
                                        <div key={j} className="bg-gray-900/60 rounded-lg p-2">
                                          <p className="text-orange-300 font-mono truncate">{t.name} <span className="text-gray-500">({t.rows} rows)</span></p>
                                          {t.columns.length > 0 && <p className="text-[10px] text-gray-500 font-mono truncate">{t.columns.join(', ')}</p>}
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {a.structure?.keys && a.structure.keys.length > 0 && (
                                  <div>
                                    <p className="text-gray-400 mb-1.5 font-medium">Config keys ({a.structure.keys.length})</p>
                                    <div className="max-h-40 overflow-auto bg-gray-900/60 rounded-lg p-2 font-mono text-[11px] space-y-0.5">
                                      {a.structure.keys.map((k: any, j: number) => (
                                        <div key={j} className="flex gap-2">
                                          <span className="text-yellow-300 shrink-0">{k.key}</span>
                                          <span className="text-gray-400 truncate">= {k.value}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {a.structure?.emails && a.structure.emails.length > 0 && (
                                  <div>
                                    <p className="text-gray-400 mb-1.5 font-medium">Emails found ({a.structure.emails.length})</p>
                                    <div className="flex flex-wrap gap-1">
                                      {a.structure.emails.map((e: string, j: number) => (
                                        <span key={j} className="px-2 py-0.5 bg-gray-900/60 rounded font-mono text-[10px] text-blue-300">{e}</span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {a.structure?.urls && a.structure.urls.length > 0 && (
                                  <div>
                                    <p className="text-gray-400 mb-1.5 font-medium">URLs found ({a.structure.urls.length})</p>
                                    <div className="flex flex-wrap gap-1">
                                      {a.structure.urls.map((u: string, j: number) => (
                                        <span key={j} className="px-2 py-0.5 bg-gray-900/60 rounded font-mono text-[10px] text-sky-300">{u}</span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {a.structure?.note && !a.structure?.entries && !a.structure?.tables && !a.structure?.keys && (
                                  <p className="text-gray-500">{a.structure.note}</p>
                                )}
                              </div>
                            </details>
                          ))}
                         {apiData.data.artifacts.filter((a: any) => !a.downloaded).length > 0 && (
                           <div className="text-xs text-gray-500 text-center py-2">
                             {apiData.data.artifacts.filter((a: any) => !a.downloaded).length} artifact(s) detected but not downloaded (size limit / timeout)
                           </div>
                         )}
                       </div>
                     </div>
                   )}

                   {/* Attribution (Collapsible) */}
                   {apiData.data.attribution && (
                     <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                       <button 
                         onClick={() => setAttributionExpanded(!attributionExpanded)}
                         className="w-full flex items-center justify-between gap-2 mb-3"
                       >
                         <h3 className="font-semibold flex items-center gap-2">
                           <Users className="w-5 h-5 text-purple-400" /> Threat Actor Attribution
                         </h3>
                         <ChevronDown className={`w-4 h-4 text-gray-500 transition-transform ${attributionExpanded ? 'rotate-180' : ''}`} />
                       </button>
                       {attributionExpanded && (
                         <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
                           <div>
                             <p className="text-gray-500 mb-1">Emails ({apiData.data.attribution.emails?.length || 0})</p>
                             <div className="flex flex-wrap gap-1">
                               {apiData.data.attribution.emails?.length > 0 ? apiData.data.attribution.emails.map((e: string, i: number) => (
                                 <span key={i} className="px-2 py-1 bg-gray-800 rounded font-mono text-blue-300">{e}</span>
                               )) : <span className="text-gray-600">none</span>}
                             </div>
                           </div>
                           <div>
                             <p className="text-gray-500 mb-1">Telegram IDs ({apiData.data.attribution.telegramIds?.length || 0})</p>
                             <div className="flex flex-wrap gap-1">
                               {apiData.data.attribution.telegramIds?.length > 0 ? apiData.data.attribution.telegramIds.map((e: string, i: number) => (
                                 <span key={i} className="px-2 py-1 bg-gray-800 rounded font-mono text-sky-300">{e}</span>
                               )) : <span className="text-gray-600">none</span>}
                             </div>
                           </div>
                           <div>
                             <p className="text-gray-500 mb-1">Tracking IDs ({apiData.data.attribution.trackingIds?.length || 0})</p>
                             <div className="flex flex-wrap gap-1">
                               {apiData.data.attribution.trackingIds?.length > 0 ? apiData.data.attribution.trackingIds.map((e: string, i: number) => (
                                 <span key={i} className="px-2 py-1 bg-gray-800 rounded font-mono text-yellow-300">{e}</span>
                               )) : <span className="text-gray-600">none</span>}
                             </div>
                           </div>
                           <div>
                             <p className="text-gray-500 mb-1">API Keys / Secrets ({apiData.data.attribution.apiKeys?.length || 0})</p>
                             <div className="flex flex-wrap gap-1">
                               {apiData.data.attribution.apiKeys?.length > 0 ? apiData.data.attribution.apiKeys.map((e: string, i: number) => (
                                 <span key={i} className="px-2 py-1 bg-red-500/10 border border-red-500/30 rounded font-mono text-red-300">{e}</span>
                               )) : <span className="text-gray-600">none</span>}
                             </div>
                           </div>
                           <div>
                             <p className="text-gray-500 mb-1">Tool / Hosting Signatures ({apiData.data.attribution.toolSignatures?.length || 0})</p>
                             <div className="flex flex-wrap gap-1">
                               {apiData.data.attribution.toolSignatures?.length > 0 ? apiData.data.attribution.toolSignatures.map((e: string, i: number) => (
                                 <span key={i} className="px-2 py-1 bg-gray-800 rounded font-mono text-gray-300">{e}</span>
                               )) : <span className="text-gray-600">none</span>}
                             </div>
                           </div>
                           <div>
                             <p className="text-gray-500 mb-1">HTML Comments ({apiData.data.attribution.comments?.length || 0})</p>
                             <div className="space-y-1">
                               {apiData.data.attribution.comments?.length > 0 ? apiData.data.attribution.comments.slice(0, 4).map((e: string, i: number) => (
                                 <div key={i} className="px-2 py-1 bg-gray-800/60 rounded font-mono text-gray-400 truncate">{e.replace(/<!--|-->/g, '').trim()}</div>
                               )) : <span className="text-gray-600">none</span>}
                             </div>
                           </div>
                         </div>
                       )}
                     </div>
                   )}

                   {/* Fuzzing Summary (Collapsible) */}
                   {apiData.data.fuzzingSummary && (
                     <div className="bg-gray-900 border border-yellow-500/30 rounded-xl p-5">
                       <button
                         onClick={() => setFuzzingExpanded(!fuzzingExpanded)}
                         className="w-full flex items-center justify-between gap-2 mb-3"
                       >
                         <div className="flex items-center gap-2">
                           <h3 className="font-semibold flex items-center gap-2">
                             <FolderOpen className="w-5 h-5 text-yellow-400" /> Directory Fuzzing (ffuf/dirb-style)
                             <span className="text-xs text-gray-500 font-normal">{apiData.data.fuzzingSummary.totalProbed} paths probed</span>
                           </h3>
                         </div>
                         <ChevronDown className={`w-4 h-4 text-gray-500 transition-transform ${fuzzingExpanded ? 'rotate-180' : ''}`} />
                       </button>
                       <div className="flex flex-wrap gap-4 mb-4 text-xs">
                         {(() => {
                           const s = apiData.data.fuzzingSummary;
                           return (
                             <>
                               <span className="px-2 py-1 bg-gray-800 rounded border border-gray-700"><span className="text-green-400 font-bold">{s.byStatus[200] || 0}</span> 200 OK</span>
                               <span className="px-2 py-1 bg-gray-800 rounded border border-gray-700"><span className="text-red-400 font-bold">{s.byStatus[403] || 0}</span> 403 Forbidden</span>
                               <span className="px-2 py-1 bg-gray-800 rounded border border-gray-700"><span className="text-yellow-400 font-bold">{(s.byStatus[301] || 0) + (s.byStatus[302] || 0)}</span> Redirect</span>
                               <span className="px-2 py-1 bg-gray-800 rounded border border-gray-700"><span className="text-gray-500 font-bold">{s.byStatus[404] || 0}</span> 404</span>
                               {s.exposed > 0 && <span className="px-2 py-1 bg-red-500/20 rounded border border-red-500/40"><span className="text-red-400 font-bold">{s.exposed}</span> EXPOSED</span>}
                             </>
                           );
                         })()}
                       </div>
                       <div className="text-xs text-gray-500 mb-4">By category: {Object.entries(apiData.data.fuzzingSummary.byCategory).map(([k,v]) => `${k}: ${v}`).join(', ')}</div>
                       {fuzzingExpanded && (
                         <div className="overflow-x-auto">
                           <p className="text-xs text-gray-500 mb-2">Full fuzz results are embedded in the Resource Tree above (type: fuzz). Expand nodes with 🔴 folder icons.</p>
                         </div>
                       )}
                     </div>
                   )}

{/* Infrastructure Graph - Interactive (Lookyloo-style) */}
                    {apiData.data.dns && (
                      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                        <h3 className="font-semibold mb-3 flex items-center gap-2">
                          <Network className="w-5 h-5 text-blue-400" /> Infrastructure Graph
                        </h3>
                        <p className="text-xs text-gray-500 mb-3">Interactive graph: DNS · MX · NS · Subdomains · IP/ASN/Geo. Click nodes to expand.</p>
                        <InfrastructureGraph data={apiData.data} />
                      </div>
                    )}

                    {/* DNS Records */}
                    {apiData.data.dns && (
                     <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                       <h3 className="font-semibold mb-3 flex items-center gap-2">
                         <Server className="w-5 h-5 text-blue-400" /> DNS Enumeration (Google DoH)
                       </h3>
                       <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                         {Object.entries(apiData.data.dns).map(([type, records]: [string, any]) => (
                           <div key={type} className="p-3 bg-gray-800 rounded-lg">
                             <div className="text-xs font-medium text-gray-400 mb-1">{type} Records (Status: {records.Status || '?'})</div>
                             {records?.Answer?.length > 0 ? (
                               <div className="space-y-1">
                                 {records.Answer.slice(0, 6).map((r: any, i: number) => (
                                   <div key={i} className="text-xs font-mono text-green-400 truncate">{r.data || r.exchange || r.nsdname || r.name || JSON.stringify(r).slice(0, 80)}</div>
                                 ))}
                                 {records.Answer.length > 6 && <div className="text-xs text-gray-500">+{records.Answer.length - 6} more</div>}
                               </div>
                             ) : (
                               <div className="text-xs text-gray-500">No records</div>
                             )}
                           </div>
                         ))}
                       </div>
                     </div>
                   )}

                   {/* HTTP Headers */}
                   {apiData.data.httpHeaders?.securityHeaders && (
                     <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                       <h3 className="font-semibold mb-3 flex items-center gap-2">
                         <FileCode className="w-5 h-5 text-cyan-400" /> HTTP Headers & Security
                         <span className="ml-auto text-xs text-gray-400">{apiData.data.httpHeaders.securityScore} security headers</span>
                       </h3>
                       <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                         <div className="space-y-1">
                           <div className="flex justify-between"><span className="text-gray-400">Status Code:</span><span>{apiData.data.httpHeaders.statusCode}</span></div>
                           <div className="flex justify-between"><span className="text-gray-400">Server:</span><span>{apiData.data.httpHeaders.server}</span></div>
                           {apiData.data.httpHeaders.headers?.['x-powered-by'] && (
                             <div className="flex justify-between"><span className="text-gray-400">Powered By:</span><span>{apiData.data.httpHeaders.headers['x-powered-by']}</span></div>
                           )}
                           <div className="flex justify-between"><span className="text-gray-400">Content-Type:</span><span>{apiData.data.httpHeaders.headers?.['content-type'] || '—'}</span></div>
                         </div>
                         <div className="space-y-1">
                           {Object.entries(apiData.data.httpHeaders.securityHeaders || {}).map(([header, present]: [string, any]) => (
                             <div key={header} className="flex items-center gap-2">
                               {present ? <CheckCircle className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                               <span className={present ? '' : 'text-gray-500 line-through'}>{header}</span>
                             </div>
                           ))}
                         </div>
                       </div>
                     </div>
                   )}

                   {/* Subdomains */}
                   {apiData.data.subdomains?.length > 0 && (
                     <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                       <h3 className="font-semibold mb-3 flex items-center gap-2">
                         <Globe2 className="w-5 h-5 text-indigo-400" /> Discovered Subdomains
                         <span className="text-xs bg-indigo-500/20 text-indigo-400 px-2 py-0.5 rounded">{apiData.data.subdomains.length} found</span>
                       </h3>
                       <div className="flex flex-wrap gap-2">
                         {apiData.data.subdomains.map((sub: string, idx: number) => (
                           <span key={idx} className="px-3 py-1 bg-gray-800 rounded-lg font-mono text-sm hover:bg-gray-700 cursor-pointer">{sub}</span>
                         ))}
                       </div>
                     </div>
                   )}
                 </div>
               )}

              {!apiData?.data && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Camera className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Advanced Web Forensic Lab</h3>
                  <p className="text-gray-400">Real-time analysis: DNS recon, directory fuzzing, phishing kit & database discovery, and threat actor attribution. Results are stored as per-site resource containers.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== URL SCANNER TAB ==================== */}
          {activeTab === 'url' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <ExternalLink className="w-7 h-7 text-yellow-400" /> URL Scanner
                  <span className="text-sm font-normal text-gray-400">attack-surface · kit fingerprint · attribution</span>
                </h2>
                <button
                  onClick={() => openPrintReport('url', apiData?.data, inputValue)}
                  className="px-4 py-2 bg-yellow-600/20 hover:bg-yellow-600/30 text-yellow-300 border border-yellow-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <ModuleErrorBoundary module="URL Scanner">
                <UrlScannerPanel
                  data={apiData?.data || null}
                  virusTotal={apiData?.virusTotal || null}
                  loading={loading}
                  inputValue={inputValue}
                  setInputValue={setInputValue}
                  onScan={handleURLAnalysis}
                  onCopy={copyToClipboard}
                  onReport={handleUrlScanReport}
                />
              </ModuleErrorBoundary>
            </div>
          )}

{/* ==================== HASH LOOKUP TAB ==================== */}
          {activeTab === 'hash' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Fingerprint className="w-7 h-7 text-cyan-400" /> Hash Lookup
                </h2>
                <button
                  onClick={() => openPrintReport('hash', apiData?.data, inputValue)}
                  className="px-4 py-2 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter hash (MD5, SHA-1, SHA-256)"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleHashLookup()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-cyan-500 focus:outline-none font-mono"
                    />
                  </div>
                  <button
                    onClick={handleHashLookup}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    Lookup Hash
                  </button>
                </div>
              </div>

              {apiData?.success && (
                <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-xl p-5">
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-cyan-400" /> Hash Analysis Results
                  </h3>
                  {apiData.data ? (
                    <>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        <InfoCard label="Hash Type" value={apiData.hashType || apiData.data.hashType || 'Detected'} icon={<Hash className="w-4 h-4" />} />
                        <InfoCard label="First Seen" value={apiData.data.firstSeen || 'Unknown'} icon={<Clock className="w-4 h-4" />} />
                        <InfoCard label="Last Seen" value={apiData.data.lastSeen || 'Unknown'} icon={<Clock className="w-4 h-4" />} />
                        <InfoCard label="File Type" value={apiData.data.fileType || 'Unknown'} icon={<FileText className="w-4 h-4" />} />
                        <InfoCard label="Signature" value={apiData.data.signature || 'Not found'} icon={<Bug className="w-4 h-4" />} alert={apiData.data.signature !== 'Not found'} />
                        <InfoCard label="Detection Ratio" value={apiData.data.detectionRatio || `${apiData.data.signature ? 1 : 0}/1`} icon={<Shield className="w-4 h-4" />} />
                      </div>
                      
                      {apiData.data.tags && (
                        <div className="mt-4 flex flex-wrap gap-2">
                          {apiData.data.tags.map((tag: string, idx: number) => (
                            <span key={idx} className="px-2 py-1 bg-gray-800 rounded text-xs">{tag}</span>
                          ))}
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="space-y-2">
                      <p className="text-sm text-gray-300">{apiData.message || 'Hash not found in malware databases. This could indicate a clean file or an unknown sample.'}</p>
                      {apiData.suggestions?.map((s: string, idx: number) => (
                        <p key={idx} className="text-xs text-gray-500">- {s}</p>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Fingerprint className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Hash Lookup Ready</h3>
                  <p className="text-gray-400">Look up file hashes against malware databases.</p>
                </div>
              )}
            </div>
          )}

{/* ==================== CVE DATABASE TAB ==================== */}
          {activeTab === 'cve' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Shield className="w-7 h-7 text-orange-400" /> CVE Database (NIST NVD)
                </h2>
                <button
                  onClick={() => openPrintReport('cve', apiData?.data, inputValue)}
                  className="px-4 py-2 bg-orange-600/20 hover:bg-orange-600/30 text-orange-300 border border-orange-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter CVE ID (e.g., CVE-2024-2334) or keyword"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleCVESearch()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-orange-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleCVESearch}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-orange-600 hover:bg-orange-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    Search CVE
                  </button>
                </div>

                <div className="mt-4 flex flex-wrap gap-2">
                  <span className="text-xs text-gray-500">Recent Critical:</span>
                  {['CVE-2024-3400', 'CVE-2024-21887', 'CVE-2023-44428'].map(cve => (
                    <button
                      key={cve}
                      onClick={() => { setInputValue(cve); handleCVESearch(); }}
                      className="px-2 py-1 bg-red-500/10 text-red-400 rounded text-xs font-mono hover:bg-red-500/20"
                    >
                      {cve}
                    </button>
                  ))}
                </div>
              </div>

              {apiData?.vulnerabilities && (
                <div className="bg-gradient-to-r from-orange-500/10 to-red-500/10 border border-orange-500/30 rounded-xl p-5">
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-orange-400" /> Vulnerability Details
                  </h3>
                  
                  {apiData.vulnerabilities.map((vuln: any, idx: number) => (
                    <div key={idx} className="mb-4 p-4 bg-gray-800/50 rounded-lg">
                      <div className="flex items-start justify-between mb-2">
                        <h4 className="font-mono font-bold text-lg">{vuln.id || vuln.cveId}</h4>
                        <span className={`px-2 py-1 rounded text-xs font-bold ${
                          (vuln.cvssScore || vuln.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore) >= 9 ? 'bg-red-500 text-white' :
                          (vuln.cvssScore || vuln.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore) >= 7 ? 'bg-orange-500 text-black' :
                          (vuln.cvssScore || vuln.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore) >= 4 ? 'bg-yellow-500 text-black' :
                          'bg-green-500 text-black'
                        }`}>
                          CVSS: {vuln.cvssScore || vuln.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || 'N/A'}
                        </span>
                      </div>
                      <p className="text-sm text-gray-300 mb-2">{vuln.description || vuln.descriptions?.[0]?.value || vuln.shortDescription}</p>
                      <div className="flex flex-wrap gap-2 text-xs">
                        {(vuln.weaknesses || vuln.cwes || []).map((cwe: any, i: number) => (
                          <span key={i} className="px-2 py-1 bg-gray-700 rounded">{cwe}</span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Shield className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">CVE Database Ready</h3>
                  <p className="text-gray-400">Search the NIST National Vulnerability Database for known vulnerabilities.</p>
                </div>
              )}
            </div>
          )}

{/* ==================== AI ANALYST TAB ==================== */}
          {activeTab === 'ai' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Cpu className="w-7 h-7 text-pink-400" /> AI Threat Analyst
                </h2>
                <button
                  onClick={() => openPrintReport('ai', apiData?.analysis || apiData, inputValue)}
                  className="px-4 py-2 bg-pink-600/20 hover:bg-pink-600/30 text-pink-300 border border-pink-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter target for AI analysis (IP, domain, hash, etc.)"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleAIAnalysis()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-pink-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleAIAnalysis}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-pink-600 hover:bg-pink-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Cpu className="w-4 h-4" />}
                    Run AI Analysis
                  </button>
                </div>
              </div>

              {apiData?.analysis && (
                <div className="bg-gradient-to-r from-pink-500/10 to-purple-500/10 border border-pink-500/30 rounded-xl p-5">
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <Cpu className="w-5 h-5 text-pink-400" /> AI Analysis Results
                  </h3>
                  
                  <div className="prose prose-invert max-w-none">
                    <p className="text-sm text-gray-300 whitespace-pre-wrap">{apiData.analysis.summary || apiData.analysis.analysis}</p>
                    
                    {apiData.analysis.recommendation && (
                      <div className="mt-4 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                        <h4 className="font-medium text-blue-400 mb-2">Recommendation</h4>
                        <p className="text-sm">{apiData.analysis.recommendation}</p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Cpu className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">AI Analyst Ready</h3>
                  <p className="text-gray-400">Enter any indicator for AI-powered threat analysis and recommendations.</p>
                </div>
              )}
            </div>
          )}

{/* ==================== DARK WEB INTEL TAB ==================== */}
          {activeTab === 'darkweb' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Skull className="w-7 h-7 text-red-500" /> Dark Web Intelligence Engine
                  <span className="text-sm font-normal text-gray-400">(Deep/Dark Web Search)</span>
                </h2>
                <button
                  onClick={() => openPrintReport('darkweb', apiData?.data, inputValue)}
                  className="px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <div className="bg-gray-900 border border-red-500/30 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Search dark web (e.g., 'breaches', 'malware', 'credentials')"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleDarkWebSearch()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-red-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleDarkWebSearch}
                    disabled={loading}
                    className="px-6 py-3 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <EyeOff className="w-4 h-4" />}
                    Search Dark Web
                  </button>
                </div>

                <div className="mt-4 flex flex-wrap gap-2">
                  <span className="text-xs text-gray-500">Selectores rápidos (domino · email · IP · BTC):</span>
                  {['bitcoin.com', 'test@example.com', '8.8.8.8', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'].map(q => (
                    <button
                      key={q}
                      onClick={() => { setInputValue(q); handleDarkWebSearch(); }}
                      className="px-2 py-1 bg-red-500/10 text-red-400 rounded text-xs hover:bg-red-500/20 capitalize"
                    >
                      {q}
                    </button>
                  ))}
                </div>
              </div>

              {/* Dark Web Overview */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl">
                  <div className="flex items-center gap-2 text-red-400 mb-2">
                    <Skull className="w-5 h-5" /> Marketplaces
                  </div>
                  <div className="text-2xl font-bold">4+</div>
                  <div className="text-xs text-gray-500">Active markets tracked</div>
                </div>
                <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl">
                  <div className="flex items-center gap-2 text-orange-400 mb-2">
                    <AlertTriangle className="w-5 h-5" /> Breaches
                  </div>
                  <div className="text-2xl font-bold">4</div>
                  <div className="text-xs text-gray-500">Recent major breaches</div>
                </div>
                <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl">
                  <div className="flex items-center gap-2 text-purple-400 mb-2">
                    <Bug className="w-5 h-5" /> Malware
                  </div>
                  <div className="text-2xl font-bold">4</div>
                  <div className="text-xs text-gray-500">Trending families</div>
                </div>
                <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl">
                  <div className="flex items-center gap-2 text-yellow-400 mb-2">
                    <Users className="w-5 h-5" /> Forums
                  </div>
                  <div className="text-2xl font-bold">4</div>
                  <div className="text-xs text-gray-500">Monitored forums</div>
                </div>
              </div>

              {/* Search Results */}
              {apiData?.liveMode && apiData.results && (
                <div className="space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="font-semibold">
                      Resultados combinados ({apiData.results.length}) — IntelX + DuckDuckGo + Bing
                    </h3>
                    <div className="flex flex-wrap gap-1.5 text-[10px]">
                      {(apiData.engines || []).map((e: any, i: number) => (
                        <span key={i} className={`px-1.5 py-0.5 rounded font-mono border ${
                          e.ok ? 'bg-green-500/10 border-green-500/40 text-green-400' : 'bg-gray-800 border-gray-700 text-gray-500'
                        }`} title={e.ok ? `${e.count} resultados` : e.error}>
                          {e.engine}: {e.ok ? e.count : 'err'}
                        </span>
                      ))}
                    </div>
                  </div>

                  {apiData.results.length === 0 && (
                    <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl text-xs text-gray-400">
                      {apiData.note ? apiData.note : 'Sin resultados para este término. Prueba con un dominio, email, IP o dirección Bitcoin.'}
                    </div>
                  )}

                  {apiData.results.map((r: any, idx: number) => (
                    <div key={idx} className="p-4 rounded-lg border bg-gray-900 border-gray-800">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <h4 className="font-medium text-sm break-all">{r.title}</h4>
                          <p className="mt-1 font-mono text-[11px] text-purple-300 break-all">{r.url}</p>
                          {r.snippet && <p className="mt-1.5 text-xs text-gray-400 break-all">{r.snippet}</p>}
                        </div>
                        <div className="flex flex-col items-end gap-1.5 shrink-0">
                          <span className="px-2 py-1 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300">
                            {r.engines?.join(' + ')}
                          </span>
                          <button
                            onClick={() => copyToClipboard(r.url)}
                            className="px-2 py-1 rounded text-[10px] bg-gray-800 hover:bg-gray-700 text-gray-300"
                          >
                            {r.url.includes('.onion') ? 'Copiar .onion' : 'Copiar enlace'}
                          </button>
                        </div>
                      </div>
                      {r.url.includes('.onion') && (
                        <div className="mt-2 text-[10px] text-yellow-500/80">
                          ⚠ Abre esta URL solo dentro de Tor Browser — la red clara no puede resolver .onion.
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {apiData?.matches && !apiData?.liveMode && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="font-semibold">Search Results ({apiData.matches.length})</h3>
                    {apiData.riskLevel && (
                      <div className="flex gap-2 text-xs">
                        <span className={`px-2 py-1 rounded ${
                          apiData.riskLevel === 'HIGH' ? 'bg-red-500/20 text-red-400' :
                          apiData.riskLevel === 'MEDIUM' ? 'bg-orange-500/20 text-orange-400' :
                          'bg-green-500/20 text-green-400'
                        }`}>
                          Risk: {apiData.riskLevel}
                        </span>
                      </div>
                    )}
                  </div>
                  
                  {apiData.matches.map((result: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-4 rounded-lg border bg-gray-900 border-gray-800"
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <h4 className="font-medium flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 text-red-400" />
                            {result.source}
                          </h4>
                          <p className="text-sm text-gray-400 mt-1">{result.found}</p>
                        </div>
                        <span className={`px-2 py-1 rounded text-xs font-bold ${
                          result.relevance === 'HIGH' ? 'bg-red-500 text-white' :
                          result.relevance === 'MEDIUM' ? 'bg-orange-500 text-black' :
                          'bg-gray-700'
                        }`}>
                          {result.relevance}
                        </span>
                      </div>
                      <div className="mt-2 flex items-center gap-4 text-xs text-gray-500">
                        <span>Source: {result.source}</span>
                        <span>Date: {result.date}</span>
                      </div>
                    </div>
                  ))}

                  {/* Recommendations */}
                  {apiData.recommendations && (
                    <div className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Shield className="w-5 h-5 text-purple-400" /> Recommended Actions
                      </h3>
                      <ul className="space-y-1">
                        {apiData.recommendations.map((action: string, idx: number) => (
                          <li key={idx} className="text-sm flex items-start gap-2">
                            <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 shrink-0" />
                            {action}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Skull className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Dark Web Search Engine</h3>
                  <p className="text-gray-400 mb-4">Search for threats, breaches, malware, and intelligence from dark web sources.</p>
                  <button onClick={() => handleDarkWebSearch()} className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg">
                    Show Latest Intelligence
                  </button>
                </div>
              )}
            </div>
          )}

{/* ==================== MOBILE SECURITY TAB ==================== */}
          {activeTab === 'mobile' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Smartphone className="w-7 h-7 text-indigo-400" /> Mobile Security Analysis
                  <span className="text-sm font-normal text-gray-400">(MobSF-style)</span>
                </h2>
                <button
                  onClick={() => openPrintReport('mobile', apiData?.data, inputValue)}
                  className="px-4 py-2 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter APK/IPA filename (e.g., app.apk, app.ipa)"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleMobileAnalysis()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-indigo-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleMobileAnalysis}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Smartphone className="w-4 h-4" />}
                    Analyze App
                  </button>
                </div>

                <div className="mt-4 flex flex-wrap gap-2">
                  <span className="text-xs text-gray-500">Supported:</span>
                  {['APK (Android)', 'IPA (iOS)', 'APPX (Windows)'].map(fmt => (
                    <span key={fmt} className="px-2 py-1 bg-indigo-500/10 text-indigo-400 rounded text-xs">{fmt}</span>
                  ))}
                </div>
              </div>

              {/* Mobile Analysis Results */}
              {apiData?.data && (
                <div className="space-y-4">
                  {/* Risk Score Card */}
                  <div className={`rounded-xl p-5 border ${
                    apiData.data.securityAnalysis?.riskLevel === 'MALICIOUS' ? 'bg-red-500/10 border-red-500/50' :
                    apiData.data.securityAnalysis?.riskLevel === 'HIGH' ? 'bg-orange-500/10 border-orange-500/50' :
                    apiData.data.securityAnalysis?.riskLevel === 'MEDIUM' ? 'bg-yellow-500/10 border-yellow-500/50' :
                    'bg-green-500/10 border-green-500/50'
                  }`}>
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-semibold">Security Risk Assessment</h3>
                        <p className="text-sm text-gray-400 mt-1">{apiData.data.fileName}</p>
                      </div>
                      <div className="text-right">
                        <div className="text-3xl font-bold">
                          {apiData.data.securityAnalysis?.malwareScore || 0}/100
                        </div>
                        <div className={`text-sm font-bold ${
                          apiData.data.securityAnalysis?.riskLevel === 'SAFE' ? 'text-green-400' :
                          apiData.data.securityAnalysis?.riskLevel === 'LOW_RISK' ? 'text-blue-400' :
                          apiData.data.securityAnalysis?.riskLevel === 'MEDIUM' ? 'text-yellow-400' :
                          apiData.data.securityAnalysis?.riskLevel === 'HIGH' ? 'text-orange-400' :
                          'text-red-400'
                        }`}>
                          {apiData.data.securityAnalysis?.riskLevel}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* App Info Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    <InfoCard label="Package/Bundle" value={apiData.data.basicInfo?.packageName || apiData.data.basicInfo?.bundleId || 'N/A'} icon={<Package className="w-4 h-4" />} />
                    <InfoCard label="Version" value={apiData.data.basicInfo?.versionName || apiData.data.basicInfo?.platformVersion || 'N/A'} icon={<Tag className="w-4 h-4" />} />
                    <InfoCard label="File Size" value={apiData.data.fileSize || 'N/A'} icon={<Database className="w-4 h-4" />} />
                    <InfoCard label="SHA256" value={apiData.data.sha256?.substring(0, 16) + '...' || 'N/A'} icon={<Hash className="w-4 h-4" />} />
                  </div>

                  {/* Permissions */}
                  {apiData.data.permissions && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Lock className="w-5 h-5 text-yellow-400" /> Permissions Analysis
                        <span className="text-xs bg-yellow-500/20 text-yellow-400 px-2 py-0.5 rounded">
                          {apiData.data.permissions.total} total
                        </span>
                      </h3>
                      
                      {apiData.data.permissions.dangerous?.length > 0 && (
                        <div className="mb-3">
                          <h4 className="text-sm font-medium text-red-400 mb-2">Dangerous ({apiData.data.permissions.dangerous.length})</h4>
                          <div className="flex flex-wrap gap-1">
                            {apiData.data.permissions.dangerous.map((perm: string, idx: number) => (
                              <span key={idx} className="px-2 py-1 bg-red-500/10 text-red-400 rounded text-xs font-mono">
                                {perm.split('.').pop()}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Security Findings */}
                  {apiData.data.securityAnalysis?.findings && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <ShieldAlert className="w-5 h-5 text-orange-400" /> Security Findings
                      </h3>
                      <div className="space-y-2">
                        {apiData.data.securityAnalysis.findings.map((finding: any, idx: number) => (
                          <div
                            key={idx}
                            className={`p-3 rounded-lg ${
                              finding.severity === 'CRITICAL' ? 'bg-red-500/10 border-l-2 border-red-500' :
                              finding.severity === 'HIGH' ? 'bg-orange-500/10 border-l-2 border-orange-500' :
                              finding.severity === 'MEDIUM' ? 'bg-yellow-500/10 border-l-2 border-yellow-500' :
                              'bg-gray-800'
                            }`}
                          >
                            <div className="flex items-start justify-between">
                              <div>
                                <span className={`text-xs font-bold uppercase ${
                                  finding.severity === 'CRITICAL' ? 'text-red-400' :
                                  finding.severity === 'HIGH' ? 'text-orange-400' :
                                  finding.severity === 'MEDIUM' ? 'text-yellow-400' :
                                  'text-gray-400'
                                }`}>
                                  {finding.severity}
                                </span>
                                <span className="text-sm ml-2">{finding.description}</span>
                              </div>
                            </div>
                            <p className="text-xs text-gray-400 mt-1">{finding.recommendation}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Network Analysis */}
                  {apiData.data.networkAnalysis && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Wifi className="w-5 h-5 text-cyan-400" /> Network Endpoints
                      </h3>
                      <div className="flex flex-wrap gap-2">
                        {apiData.data.networkAnalysis.domains?.map((domain: string, idx: number) => (
                          <span key={idx} className="px-2 py-1 bg-gray-800 rounded text-xs font-mono">{domain}</span>
                        ))}
                      </div>
                      {apiData.data.networkAnalysis.hasHttpTraffic && (
                        <div className="mt-2 p-2 bg-red-500/10 rounded text-xs text-red-400">
                          Warning: App sends data over unencrypted HTTP
                        </div>
                      )}
                    </div>
                  )}

                  {/* AI Assessment */}
                  {apiData.data.aiAssessment && (
                    <div className="bg-gradient-to-r from-indigo-500/10 to-purple-500/10 border border-indigo-500/30 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Cpu className="w-5 h-5 text-indigo-400" /> AI Assessment
                      </h3>
                      <p className="text-sm text-gray-300 mb-2">{apiData.data.aiAssessment.summary}</p>
                      <div className="inline-block px-3 py-1 bg-indigo-500/20 text-indigo-400 rounded-full text-sm font-bold">
                        Verdict: {apiData.data.aiAssessment.verdict}
                      </div>
                      <div className="mt-3">
                        <h4 className="text-sm font-medium text-green-400 mb-1">Recommendations:</h4>
                        <ul className="space-y-1">
                          {apiData.data.aiAssessment.recommendations?.map((rec: string, idx: number) => (
                            <li key={idx} className="text-sm flex items-start gap-2">
                              <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 shrink-0" />
                              {rec}
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Smartphone className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Mobile Security Analyzer</h3>
                  <p className="text-gray-400 mb-4">Analyze Android APKs and iOS IPA files for security issues. Similar to MobSF.</p>
                  <div className="flex justify-center gap-2">
                    {['malicious.apk', 'banking.app', 'game.apk'].map(app => (
                      <button
                        key={app}
                        onClick={() => { setInputValue(app); handleMobileAnalysis(); }}
                        className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded text-xs"
                      >
                        Try {app}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

{/* ==================== THREAT FEEDS TAB ==================== */}
          {activeTab === 'threats' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <AlertTriangle className="w-7 h-7 text-amber-400" /> Live Threat Feeds
                </h2>
                <button
                  onClick={() => openPrintReport('threats', apiData?.feeds || apiData, inputValue)}
                  className="px-4 py-2 bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex flex-wrap gap-3">
                  <button
                    onClick={() => handleThreatFeedLoad()}
                    disabled={loading}
                    className="px-4 py-2 bg-amber-600 hover:bg-amber-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                    Load All Feeds
                  </button>
                  <button onClick={() => handleThreatFeedLoad('cisa')} disabled={loading} className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm">
                    CISA KEV
                  </button>
                  <button onClick={() => handleThreatFeedLoad('malwaredl')} disabled={loading} className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm">
                    MalwareBazaar
                  </button>
                  <button onClick={() => handleThreatFeedLoad('abusech')} disabled={loading} className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm">
                    AbuseCH SSLBL
                  </button>
                </div>
              </div>

              {apiData?.feeds && (
                <div className="space-y-4">
                  {apiData.feeds.map((feed: any, idx: number) => (
                    <div key={idx} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="font-semibold flex items-center gap-2">
                          <AlertTriangle className="w-5 h-5 text-amber-400" />
                          {feed.source}
                          <span className="text-xs bg-amber-500/20 text-amber-400 px-2 py-0.5 rounded">
                            {feed.count} items
                          </span>
                        </h3>
                        <span className={`text-xs px-2 py-0.5 rounded ${
                          feed.status === 'active' ? 'bg-green-500/20 text-green-400' : 'bg-gray-700'
                        }`}>
                          {feed.status}
                        </span>
                      </div>
                      
                      {feed.entries && (
                        <div className="overflow-x-auto">
                          <table className="w-full text-sm">
                            <thead>
                              <tr className="border-b border-gray-800">
                                <th className="text-left py-2 px-2 text-gray-400">ID/Name</th>
                                <th className="text-left py-2 px-2 text-gray-400">Details</th>
                                <th className="text-left py-2 px-2 text-gray-400">Date</th>
                              </tr>
                            </thead>
                            <tbody>
                              {feed.entries.slice(0, 5).map((entry: any, eIdx: number) => (
                                <tr key={eIdx} className="border-b border-gray-800 hover:bg-gray-800">
                                  <td className="py-2 px-2 font-mono text-xs">
                                    {entry.cveID || entry.sha256_hash || entry.sha256_fingerprint || entry.name || '-'}
                                  </td>
                                  <td className="py-2 px-2 text-xs">{entry.shortDescription || entry.signature || entry.listing_reason || '-'}</td>
                                  <td className="py-2 px-2 text-xs text-gray-500">{entry.dateAdded || entry.first_seen || '-'}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <AlertTriangle className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Threat Feeds</h3>
                  <p className="text-gray-400">Click a button above to load threat intelligence from various sources.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== IOC MANAGER TAB ==================== */}
          {activeTab === 'iocs' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Database className="w-7 h-7 text-emerald-400" /> IOC Manager
                </h2>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => openPrintReport('iocs', { iocs, iocStats }, inputValue)}
                    className="px-4 py-2 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                    title="Generar informe imprimible HTML"
                  >
                    <Printer className="w-4 h-4" />
                    Informe Imprimible
                  </button>
                  <button
                    onClick={() => { setModalType('add'); setFormData({ type: 'IP', value: '', description: '', severity: 'MEDIUM', status: 'UNKNOWN', tags: [] }); setShowModal(true); }}
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 rounded-lg font-medium flex items-center gap-2"
                  >
                    <Plus className="w-4 h-4" /> Add IOC
                  </button>
                </div>
              </div>

              {/* Filters */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <div className="flex flex-wrap gap-4">
                  <div className="flex-1 min-w-[200px]">
                    <input
                      type="text"
                      placeholder="Search IOCs..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm"
                    />
                  </div>
                  <select className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm">
                    <option>All Types</option>
                    <option>IP</option>
                    <option>DOMAIN</option>
                    <option>URL</option>
                    <option>HASH</option>
                  </select>
                  <select className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm">
                    <option>All Severities</option>
                    <option>CRITICAL</option>
                    <option>HIGH</option>
                    <option>MEDIUM</option>
                  </select>
                  <button onClick={searchIOCs} className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm">
                    <Search className="w-4 h-4 inline mr-1" /> Search
                  </button>
                </div>
              </div>

              {/* IOC Table */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-gray-800">
                    <tr>
                      <th className="text-left py-3 px-4 text-gray-400">Type</th>
                      <th className="text-left py-3 px-4 text-gray-400">Value</th>
                      <th className="text-left py-3 px-4 text-gray-400">Severity</th>
                      <th className="text-left py-3 px-4 text-gray-400">Status</th>
                      <th className="text-left py-3 px-4 text-gray-400">Source</th>
                      <th className="text-right py-3 px-4 text-gray-400">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {iocs.map((ioc) => (
                      <tr key={ioc.id} className="border-t border-gray-800 hover:bg-gray-800/50">
                        <td className="py-3 px-4">
                          <span className="px-2 py-1 bg-gray-700 rounded text-xs">{ioc.type}</span>
                        </td>
                        <td className="py-3 px-4 font-mono text-sm">{ioc.value}</td>
                        <td className="py-3 px-4">
                          <span style={{ color: SEVERITY_COLORS[ioc.severity] }} className="font-medium">
                            {ioc.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span style={{ color: STATUS_COLORS[ioc.status] }} className="font-medium">
                            {ioc.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-gray-400 text-xs">{ioc.source || '-'}</td>
                        <td className="py-3 px-4 text-right">
                          <button onClick={() => openDetailModal(ioc)} className="p-1 hover:bg-gray-700 rounded mr-1">
                            <Eye className="w-4 h-4" />
                          </button>
                          <button onClick={() => openEditModal(ioc)} className="p-1 hover:bg-gray-700 rounded mr-1">
                            <Edit3 className="w-4 h-4" />
                          </button>
                          <button onClick={() => handleDeleteIOC(ioc.id)} className="p-1 hover:bg-gray-700 rounded text-red-400">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                
                {iocs.length === 0 && (
                  <div className="text-center py-12 text-gray-500">
                    <Database className="w-12 h-12 mx-auto mb-2 opacity-50" />
                    <p>No IOCs found. Add your first IOC or analyze an IP/domain!</p>
                  </div>
                )}
              </div>
            </div>
          )}

{/* ==================== EXPORT TAB ==================== */}
          {activeTab === 'export' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Download className="w-7 h-7 text-teal-400" /> Export Data
                </h2>
                <button
                  onClick={() => openPrintReport('export', { exports: [] }, inputValue)}
                  className="px-4 py-2 bg-teal-600/20 hover:bg-teal-600/30 text-teal-300 border border-teal-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h3 className="font-semibold mb-3">Export Format</h3>
                    <div className="space-y-2">
                      <button
                        onClick={() => handleExport('json')}
                        className="w-full p-4 bg-gray-800 hover:bg-gray-700 rounded-lg flex items-center gap-3 transition-colors"
                      >
                        <FileCode className="w-6 h-6 text-blue-400" />
                        <div className="text-left">
                          <div className="font-medium">JSON Export</div>
                          <div className="text-xs text-gray-400">Full data with metadata</div>
                        </div>
                      </button>
                      <button
                        onClick={() => handleExport('csv')}
                        className="w-full p-4 bg-gray-800 hover:bg-gray-700 rounded-lg flex items-center gap-3 transition-colors"
                      >
                        <DownloadCloud className="w-6 h-6 text-green-400" />
                        <div className="text-left">
                          <div className="font-medium">CSV Export</div>
                          <div className="text-xs text-gray-400">Spreadsheet compatible</div>
                        </div>
                      </button>
                    </div>
                  </div>
                  
                  <div>
                    <h3 className="font-semibold mb-3">Export Summary</h3>
                    <div className="p-4 bg-gray-800 rounded-lg">
                      <p className="text-sm text-gray-400">
                        Total IOCs: <strong className="text-white">{iocs.length}</strong>
                      </p>
                      <p className="text-sm text-gray-400 mt-2">
                        Formats available: JSON, CSV, STIX, TAXII
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ==================== INTELLIGENCE SOURCES TAB ==================== */}
          {activeTab === 'sources' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Wifi className="w-7 h-7 text-sky-400" /> Intelligence Sources
                </h2>
                <button
                  onClick={() => openPrintReport('sources', { sources }, inputValue)}
                  className="px-4 py-2 bg-sky-600/20 hover:bg-sky-600/30 text-sky-300 border border-sky-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>

              {/* Add Source Form */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <h3 className="font-semibold mb-3">Add Custom Intelligence Source</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  <input
                    type="text"
                    placeholder="Source name (e.g., My Threat Feed)"
                    value={newSource.name}
                    onChange={(e) => setNewSource(prev => ({ ...prev, name: e.target.value }))}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                  />
                  <select
                    value={newSource.type}
                    onChange={(e) => setNewSource(prev => ({ ...prev, type: e.target.value }))}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                  >
                    {['THREAT_FEED', 'GEO_IP', 'DNS', 'CVE', 'REPUTATION', 'BREACH', 'AI', 'CUSTOM'].map(t => (
                      <option key={t} value={t}>{t.replace('_', ' ')}</option>
                    ))}
                  </select>
                  <select
                    value={newSource.method}
                    onChange={(e) => setNewSource(prev => ({ ...prev, method: e.target.value }))}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                  >
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                  </select>
                  <input
                    type="text"
                    placeholder="Endpoint URL"
                    value={newSource.endpoint}
                    onChange={(e) => setNewSource(prev => ({ ...prev, endpoint: e.target.value }))}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg lg:col-span-2"
                  />
                  <input
                    type="text"
                    placeholder="API key env var (optional)"
                    value={newSource.apiKeyEnv}
                    onChange={(e) => setNewSource(prev => ({ ...prev, apiKeyEnv: e.target.value }))}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                  />
                  <input
                    type="text"
                    placeholder="Description"
                    value={newSource.description}
                    onChange={(e) => setNewSource(prev => ({ ...prev, description: e.target.value }))}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg lg:col-span-2"
                  />
                  <button
                    onClick={handleAddSource}
                    className="px-4 py-2 bg-sky-600 hover:bg-sky-700 rounded-lg font-medium flex items-center justify-center gap-2"
                  >
                    <Plus className="w-4 h-4" /> Add Source
                  </button>
                </div>
              </div>

              {/* Sources List */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-semibold">Registered Sources ({sources.length})</h3>
                  <button onClick={loadSources} className="p-2 hover:bg-gray-800 rounded-lg" title="Refresh">
                    <RefreshCw className="w-4 h-4" />
                  </button>
                </div>

                {sources.length === 0 ? (
                  <p className="text-sm text-gray-500">No sources found.</p>
                ) : (
                  <div className="space-y-2">
                    {sources.map((source: any) => {
                      const health = sourceHealth.find((h: any) => h.id === source.id);
                      return (
                        <div key={source.id} className="flex items-center gap-3 p-3 bg-gray-800/60 rounded-lg">
                          <span className={`w-2 h-2 rounded-full shrink-0 ${source.enabled ? 'bg-green-500' : 'bg-gray-500'}`}></span>
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-medium truncate">{source.name}</div>
                            <div className="text-xs text-gray-500">
                              {source.type} • {source.method} {source.endpoint}
                            </div>
                            {health && (
                              <div className={`text-xs mt-0.5 ${health.ok ? 'text-green-500' : 'text-red-500'}`}>
                                {health.ok ? `Healthy (HTTP ${health.status || 200})` : health.message}
                              </div>
                            )}
                          </div>
                          <div className="flex gap-1">
                            <button onClick={() => handleTestSource(source.id)} className="p-2 hover:bg-gray-700 rounded-lg" title="Test connectivity">
                              <Zap className="w-4 h-4" />
                            </button>
                            <button onClick={() => handleToggleSource(source)} className="p-2 hover:bg-gray-700 rounded-lg" title={source.enabled ? 'Disable' : 'Enable'}>
                              {source.enabled ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ==================== REPORTS TAB ==================== */}
          {activeTab === 'reports' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <FileText className="w-7 h-7 text-violet-400" /> Report Generator
                </h2>
                <button
                  onClick={() => openPrintReport('reports', { reports: reportsList || [] }, inputValue)}
                  className="px-4 py-2 bg-violet-600/20 hover:bg-violet-600/30 text-violet-300 border border-violet-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Report Configuration */}
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
                  <h3 className="font-semibold">Configuration</h3>
                  
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Report Title *</label>
                    <input
                      type="text"
                      placeholder="Enter report title..."
                      value={reportConfig.title}
                      onChange={(e) => setReportConfig(prev => ({ ...prev, title: e.target.value }))}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                    />
                  </div>

                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Format</label>
                    <select
                      value={reportConfig.format}
                      onChange={(e) => setReportConfig(prev => ({ ...prev, format: e.target.value }))}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                    >
                      <option value="PDF">PDF Report</option>
                      <option value="JSON">JSON Data</option>
                      <option value="CSV">CSV Spreadsheet</option>
                      <option value="HTML">HTML Interactive</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm text-gray-400 mb-2">Select Modules to Include</label>
                    <div className="grid grid-cols-2 gap-2">
                      {[
                        { id: 'dashboard', label: 'Dashboard Stats' },
                        { id: 'ip', label: 'IP Intelligence' },
                        { id: 'domain', label: 'Domain Intel' },
                        { id: 'forensics', label: 'Forensics Data' },
                        { id: 'cve', label: 'CVE Database' },
                        { id: 'darkweb', label: 'Dark Web Intel' },
                        { id: 'mobile', label: 'Mobile Security' },
                        { id: 'threats', label: 'Threat Feeds' },
                        { id: 'iocs', label: 'IOC List' },
                        { id: 'ai', label: 'AI Analysis' },
                      ].map(mod => (
                        <label key={mod.id} className="flex items-center gap-2 p-2 bg-gray-800 rounded cursor-pointer hover:bg-gray-700">
                          <input
                            type="checkbox"
                            checked={reportConfig.modules.includes(mod.id)}
                            onChange={() => toggleReportModule(mod.id)}
                            className="rounded"
                          />
                          <span className="text-sm">{mod.label}</span>
                        </label>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={reportConfig.executiveSummary}
                        onChange={(e) => setReportConfig(prev => ({ ...prev, executiveSummary: e.target.checked }))}
                        className="rounded"
                      />
                      <span className="text-sm">Include Executive Summary</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={reportConfig.recommendations}
                        onChange={(e) => setReportConfig(prev => ({ ...prev, recommendations: e.target.checked }))}
                        className="rounded"
                      />
                      <span className="text-sm">Include Recommendations</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={reportConfig.includeTimeline}
                        onChange={(e) => setReportConfig(prev => ({ ...prev, includeTimeline: e.target.checked }))}
                        className="rounded"
                      />
                      <span className="text-sm">Include Timeline</span>
                    </label>
                  </div>

                  <button
                    onClick={handleGenerateReport}
                    disabled={loading || !reportConfig.title || reportConfig.modules.length === 0}
                    className="w-full py-3 bg-violet-600 hover:bg-violet-700 disabled:opacity-50 rounded-lg font-medium flex items-center justify-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileText className="w-4 h-4" />}
                    Generate Report
                  </button>
                </div>

                {/* Report Preview / Templates */}
                <div className="space-y-4">
                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                    <h3 className="font-semibold mb-3">Quick Templates</h3>
                    <div className="space-y-2">
                      {[
                        { name: 'Executive Summary', desc: 'For leadership', modules: ['dashboard', 'iocs', 'threats'] },
                        { name: 'Technical Analysis', desc: 'For analysts', modules: ['ip', 'domain', 'url', 'hash', 'cve'] },
                        { name: 'Threat Hunt', desc: 'For hunters', modules: ['darkweb', 'threats', 'ai'] },
                        { name: 'Comprehensive', desc: 'Full audit', modules: ['dashboard', 'ip', 'domain', 'forensics', 'cve', 'darkweb', 'threats', 'iocs', 'mobile'] },
                      ].map(template => (
                        <button
                          key={template.name}
                          onClick={() => setReportConfig(prev => ({
                            ...prev,
                            title: template.name + ' Report',
                            modules: template.modules
                          }))}
                          className="w-full p-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-left transition-colors"
                        >
                          <div className="font-medium text-sm">{template.name}</div>
                          <div className="text-xs text-gray-400">{template.desc} • {template.modules.length} modules</div>
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Generated Report Display */}
                  {apiData?.content && (
                    <div className="bg-gradient-to-r from-violet-500/10 to-purple-500/10 border border-violet-500/30 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <CheckCircle className="w-5 h-5 text-violet-400" /> Report Generated
                      </h3>
                      
                      {apiData.content.executiveSummary && (
                        <div className="mb-4 p-4 bg-gray-800/50 rounded-lg">
                          <h4 className="text-sm font-medium text-violet-400 mb-2">Executive Summary</h4>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
                            <div>
                              <div className="text-2xl font-bold">{apiData.content.executiveSummary.totalIndicators || 0}</div>
                              <div className="text-xs text-gray-400">Total IOCs</div>
                            </div>
                            <div>
                              <div className="text-2xl font-bold text-red-400">{apiData.content.executiveSummary.criticalItems || 0}</div>
                              <div className="text-xs text-gray-400">Critical</div>
                            </div>
                            <div>
                              <div className="text-2xl font-bold text-orange-400">{apiData.content.executiveSummary.highRiskItems || 0}</div>
                              <div className="text-xs text-gray-400">High Risk</div>
                            </div>
                            <div>
                              <div className="text-2xl font-bold text-violet-400">{apiData.content.statistics?.modulesIncluded || 0}</div>
                              <div className="text-xs text-gray-400">Modules</div>
                            </div>
                          </div>
                        </div>
                      )}

                      {apiData.content.recommendations && (
                        <div>
                          <h4 className="text-sm font-medium text-green-400 mb-2">Recommendations</h4>
                          <ul className="space-y-1">
                            {apiData.content.recommendations.slice(0, 5).map((rec: string, idx: number) => (
                              <li key={idx} className="text-sm flex items-start gap-2">
                                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 shrink-0" />
                                {rec}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>

              {/* Generated Reports History */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <h3 className="font-semibold mb-4 flex items-center gap-2">
                  <FolderOpen className="w-4 h-4 text-violet-400" /> Generated Reports
                  <span className="text-xs text-gray-500 ml-auto">{reports.length} saved</span>
                </h3>
                {reports.length === 0 ? (
                  <p className="text-sm text-gray-500">No reports generated yet. Configure a report above and click Generate.</p>
                ) : (
                  <div className="space-y-2">
                    {reports.map((report: any) => (
                      <div key={report.id} className="flex items-center gap-3 p-3 bg-gray-800/60 rounded-lg">
                        <FileText className="w-4 h-4 text-violet-400 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-medium truncate">{report.title}</div>
                          <div className="text-xs text-gray-500">
                            {new Date(report.createdAt || report.timestamp).toLocaleString()} • {report.modules?.length || 0} modules
                          </div>
                        </div>
                        <div className="flex gap-1">
                          <a href={`/api/osint/reports?action=download&id=${report.id}&format=pdf`} target="_blank" rel="noreferrer" className="p-2 hover:bg-gray-700 rounded-lg" title="Download PDF">
                            <FileText className="w-4 h-4 text-red-400" />
                          </a>
                          <a href={`/api/osint/reports?action=download&id=${report.id}&format=docx`} target="_blank" rel="noreferrer" className="p-2 hover:bg-gray-700 rounded-lg" title="Download DOCX">
                            <FileText className="w-4 h-4 text-blue-400" />
                          </a>
                          <a href={`/api/osint/reports?action=download&id=${report.id}&format=pptx`} target="_blank" rel="noreferrer" className="p-2 hover:bg-gray-700 rounded-lg" title="Download PPTX">
                            <Presentation className="w-4 h-4 text-orange-400" />
                          </a>
                          <a href={`/api/osint/reports?action=download&id=${report.id}&format=json`} target="_blank" rel="noreferrer" className="p-2 hover:bg-gray-700 rounded-lg" title="Download JSON">
                            <DownloadCloud className="w-4 h-4" />
                          </a>
                          <a href={`/api/osint/reports?action=download&id=${report.id}&format=csv`} target="_blank" rel="noreferrer" className="p-2 hover:bg-gray-700 rounded-lg" title="Download CSV">
                            <FileCode className="w-4 h-4" />
                          </a>
                          <a href={`/api/osint/reports?action=download&id=${report.id}&format=html`} target="_blank" rel="noreferrer" className="p-2 hover:bg-gray-700 rounded-lg" title="Open HTML report">
                            <ExternalLink className="w-4 h-4" />
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ==================== BRAND PROTECTION TAB ==================== */}
          {activeTab === 'brand' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Shield className="w-7 h-7 text-rose-400" /> Brand Protection
                  <span className="text-sm font-normal text-gray-400">(Phishing & impersonation monitoring)</span>
                </h2>
                <button
                  onClick={() => openPrintReport('brand', apiData?.data, inputValue)}
                  className="px-4 py-2 bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input type="text" placeholder="Suspicious URL or domain (e.g., paypal-secure-login.top)"
                      value={inputValue} onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleBrandScan()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-rose-500 focus:outline-none" />
                  </div>
                  <button onClick={handleBrandScan} disabled={loading} className="px-6 py-3 bg-rose-600 hover:bg-rose-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2">
                    <Search className="w-4 h-4" /> Scan Candidate
                  </button>
                  <button onClick={handleBrandWatchlist} disabled={loading} className="px-4 py-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm flex items-center gap-2">
                    <Plus className="w-4 h-4" /> Add Brand
                  </button>
                </div>
              </div>

              {apiData?.data?.phishing && (
                <div className="space-y-4">
                  <div className={`rounded-xl p-5 border ${
                    apiData.data.phishing.verdict === 'HIGH' ? 'bg-red-500/10 border-red-500/50' :
                    apiData.data.phishing.verdict === 'MEDIUM' ? 'bg-yellow-500/10 border-yellow-500/50' : 'bg-green-500/10 border-green-500/50'
                  }`}>
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-semibold">Phishing Risk Assessment</h3>
                        <p className="text-sm text-gray-400 mt-1">{apiData.data.candidate} vs brand "{apiData.data.brand}"</p>
                      </div>
                      <div className="text-right">
                        <div className="text-3xl font-bold">{apiData.data.phishing.score}/15</div>
                        <div className="text-sm font-bold">{apiData.data.phishing.verdict}</div>
                      </div>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {apiData.data.phishing.reasons.map((r: string, i: number) => (
                        <span key={i} className="px-2 py-1 bg-gray-800 rounded text-xs">{r}</span>
                      ))}
                    </div>
                  </div>

                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2"><AlertTriangle className="w-5 h-5 text-red-400" /> Lookalike Domains</h3>
                    <div className="flex flex-wrap gap-2">
                      {(apiData.lookalikes || []).map((d: string, i: number) => (
                        <button key={i} onClick={() => setInputValue(d)} className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded text-xs font-mono">{d}</button>
                      ))}
                    </div>
                  </div>

                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2"><Skull className="w-5 h-5 text-red-500" /> Suspected Phishing Kits</h3>
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead><tr className="border-b border-gray-800 text-left text-gray-400">
                          <th className="py-2 px-2">Name</th><th className="py-2 px-2">Platform</th><th className="py-2 px-2">IOC</th>
                        </tr></thead>
                        <tbody>
                          {(apiData.kits || []).map((k: any, i: number) => (
                            <tr key={i} className="border-b border-gray-800">
                              <td className="py-2 px-2 font-medium">{k.name}</td>
                              <td className="py-2 px-2 text-xs">{k.platform}</td>
                              <td className="py-2 px-2 font-mono text-xs text-red-400">{k.ioc}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}
              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Shield className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Brand Protection Ready</h3>
                  <p className="text-gray-400">Scan suspected phishing URLs and domains, discover lookalikes and phishing kits targeting your brand.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== URL SANDBOX TAB ==================== */}
          {activeTab === 'sandbox' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Zap className="w-7 h-7 text-lime-400" /> URL Sandbox
                  <span className="text-sm font-normal text-gray-400">real detonation · HTTP/TLS · content · reputation</span>
                </h2>
                <button
                  onClick={() => openPrintReport('sandbox', apiData?.data, inputValue)}
                  className="px-4 py-2 bg-lime-600/20 hover:bg-lime-600/30 text-lime-300 border border-lime-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <ModuleErrorBoundary module="URL Sandbox">
                <UrlSandboxPanel
                  data={apiData?.data || null}
                  loading={loading}
                  inputValue={inputValue}
                  setInputValue={setInputValue}
                  onDetonate={handleSandbox}
                  onCopy={copyToClipboard}
                  onReport={handleSandboxReport}
                />
              </ModuleErrorBoundary>
            </div>
          )}

          {/* ==================== TAKE DOWN URL TAB ==================== */}
          {activeTab === 'takedown' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Send className="w-7 h-7 text-orange-400" /> TakeDown URL
                  <span className="text-sm font-normal text-gray-400">Cargue URLs maliciosas y repórtelas a servicios de seguridad</span>
                </h2>
                <button
                  onClick={() => openPrintReport('takedown', apiData?.data, inputValue)}
                  className="px-4 py-2 bg-orange-600/20 hover:bg-orange-600/30 text-orange-300 border border-orange-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <TakeDownPanel />
            </div>
          )}

          {/* ==================== DNS DUMP TAB ==================== */}
          {activeTab === 'dnsdump' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Network className="w-7 h-7 text-teal-400" /> DNS Dump
                  <span className="text-sm font-normal text-gray-400">(dnsdumpster.com style enumeration)</span>
                </h2>
                <button
                  onClick={() => openPrintReport('dnsdump', apiData?.data, inputValue)}
                  className="px-4 py-2 bg-teal-600/20 hover:bg-teal-600/30 text-teal-300 border border-teal-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input type="text" placeholder="Domain to enumerate (e.g., example.com)"
                      value={inputValue} onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleDnsDump()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-teal-500 focus:outline-none" />
                  </div>
                  <button onClick={handleDnsDump} disabled={loading} className="px-6 py-3 bg-teal-600 hover:bg-teal-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2">
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} Enumerate
                  </button>
                </div>
              </div>

              {apiData?.data?.records && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
                    {Object.entries(apiData.data.records).map(([type, recs]: [string, any]) => (
                      <div key={type} className="p-3 bg-gray-900 border border-gray-800 rounded-xl">
                        <div className="text-sm font-bold text-teal-400">{type}</div>
                        <div className="text-2xl font-bold">{recs?.length || 0}</div>
                        <div className="text-xs text-gray-500">records</div>
                      </div>
                    ))}
                  </div>

                  {/* Toolbar: fuentes + export CSV */}
                  <div className="flex flex-wrap items-center gap-3">
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <span className="px-2.5 py-1 bg-purple-500/20 border border-purple-500/40 text-purple-300 rounded-lg font-mono">
                        CT (crt.sh): {apiData.data.sourceBreakdown?.ct ?? 0}
                      </span>
                      <span className="px-2.5 py-1 bg-pink-500/20 border border-pink-500/40 text-pink-300 rounded-lg font-mono">
                        OTX: {apiData.data.sourceBreakdown?.otx ?? 0}
                      </span>
                      <span className="px-2.5 py-1 bg-orange-500/20 border border-orange-500/40 text-orange-300 rounded-lg font-mono">
                        BufferOver: {apiData.data.sourceBreakdown?.buffer ?? 0}
                      </span>
                      <span className="px-2.5 py-1 bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded-lg font-mono">
                        Hackertarget: {apiData.data.sourceBreakdown?.hackertarget ?? 0}
                      </span>
                      <span className="px-2.5 py-1 bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 rounded-lg font-mono">
                        Brute-force: {apiData.data.sourceBreakdown?.brute ?? 0}
                      </span>
                      {(apiData.data.takeovers || []).filter((t: any) => t.status !== 'SAFE').length > 0 && (
                        <span className="px-2.5 py-1 bg-red-500/20 border border-red-500/40 text-red-300 rounded-lg font-mono">
                          {apiData.data.takeovers.filter((t: any) => t.status !== 'SAFE').length} takeovers posibles
                        </span>
                      )}
                    </div>
                    <button onClick={handleDnsDumpReport} className="ml-auto text-xs px-3 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-lg text-white flex items-center gap-1.5">
                      <Printer className="w-3.5 h-3.5" /> Informe Imprimible HTML
                    </button>
                    <button onClick={exportDnsCsv} className="text-xs px-3 py-2 bg-emerald-600 hover:bg-emerald-700 rounded-lg text-white flex items-center gap-1.5">
                      <Download className="w-3.5 h-3.5" /> Exportar CSV (lista completa)
                    </button>
                  </div>

                  {/* Tabla filtrable de registros DNS */}
                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2"><Server className="w-5 h-5 text-purple-400" /> Registros DNS — tabla filtrable ({apiData.data.allRecords?.length || 0})</h3>
                    <div className="flex flex-wrap items-center gap-2 mb-3">
                      <button onClick={() => setDnsdumpType('ALL')} className={`px-2.5 py-1 rounded-lg text-xs font-medium border ${dnsdumpType === 'ALL' ? 'bg-teal-600 border-teal-500 text-white' : 'bg-gray-800 border-gray-700 text-gray-400 hover:bg-gray-700'}`}>TODOS</button>
                      {Object.entries(apiData.data.records).map(([type, recs]: [string, any]) => (
                        <button key={type} onClick={() => setDnsdumpType(type)} className={`px-2.5 py-1 rounded-lg text-xs font-mono border ${dnsdumpType === type ? 'bg-teal-600 border-teal-500 text-white' : 'bg-gray-800 border-gray-700 text-gray-400 hover:bg-gray-700'}`}>
                          {type} ({recs?.length || 0})
                        </button>
                      ))}
                      <input
                        type="text"
                        placeholder="Filtrar por nombre o valor..."
                        value={dnsdumpFilter}
                        onChange={(e) => setDnsdumpFilter(e.target.value)}
                        className="ml-auto w-64 px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-xs focus:border-teal-500 focus:outline-none"
                      />
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead>
                          <tr className="text-gray-500 border-b border-gray-800">
                            <th className="py-2 pr-3">Tipo</th>
                            <th className="py-2 pr-3">Nombre</th>
                            <th className="py-2 pr-3">TTL</th>
                            <th className="py-2">Dato</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(apiData.data.allRecords || [])
                            .filter((r: any) => dnsdumpType === 'ALL' || r.type === dnsdumpType)
                            .filter((r: any) => {
                              const q = dnsdumpFilter.toLowerCase();
                              return !q || String(r.name).toLowerCase().includes(q) || String(r.data).toLowerCase().includes(q);
                            })
                            .map((r: any, i: number) => (
                              <tr key={i} className="border-b border-gray-800/60 hover:bg-gray-800/40">
                                <td className="py-1.5 pr-3"><span className="px-1.5 py-0.5 rounded bg-gray-800 font-mono text-teal-300">{r.type}</span></td>
                                <td className="py-1.5 pr-3 font-mono text-gray-300">{r.name}</td>
                                <td className="py-1.5 pr-3 text-gray-500">{r.ttl}</td>
                                <td className="py-1.5 font-mono text-gray-400 break-all">{r.data}</td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Grafo visual de subdominios */}
                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2">
                      <Network className="w-5 h-5 text-teal-400" /> Grafo visual — subdominios descubiertos ({apiData.data.subdomains?.length || 0})
                    </h3>
                    <p className="text-xs text-gray-500 mb-3">
                      Fuentes: certificate transparency (crt.sh) + brute-force DNS. Nodos: dominio → subdominio → IP. Clic en un nodo para ver detalles.
                    </p>
                    <SubdomainGraph data={apiData.data} />
                  </div>

                  {/* Mapeo dominio -> IP -> proveedor de hosting */}
                  {apiData.data.ipMap?.length > 0 && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Globe2 className="w-5 h-5 text-indigo-400" /> Mapeo Dominio → IP → Proveedor de Hosting ({apiData.data.ipMap.length})</h3>
                      <div className="overflow-x-auto max-h-96 overflow-y-auto">
                        <table className="w-full text-left text-xs">
                          <thead>
                            <tr className="text-gray-500 border-b border-gray-800 sticky top-0 bg-gray-900">
                              <th className="py-2 pr-3">Host</th>
                              <th className="py-2 pr-3">IP</th>
                              <th className="py-2 pr-3">ASN</th>
                              <th className="py-2 pr-3">Proveedor</th>
                              <th className="py-2">País</th>
                            </tr>
                          </thead>
                          <tbody>
                            {apiData.data.ipMap.map((m: any, i: number) => (
                              <tr key={i} className="border-b border-gray-800/60 hover:bg-gray-800/40">
                                <td className="py-1.5 pr-3 font-mono text-gray-300">{m.host}</td>
                                <td className="py-1.5 pr-3 font-mono text-cyan-300">{m.ip}</td>
                                <td className="py-1.5 pr-3 font-mono text-pink-300">{m.asn}</td>
                                <td className="py-1.5 pr-3 text-gray-300">{m.provider}</td>
                                <td className="py-1.5 text-gray-400">{m.country}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* DNS histórico (passive DNS) con línea de tiempo */}
                  {(apiData.data.passiveDns?.length > 0 || true) && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Clock className="w-5 h-5 text-yellow-400" /> DNS Histórico — Passive DNS con línea de tiempo (CT)</h3>
                      <p className="text-xs text-gray-500 mb-4">Línea de tiempo basada en emisiones de certificados (certificate transparency) y registros passive DNS. Primera y última aparición observada por subdominio.</p>
                      {apiData.data.passiveDns?.length > 0 ? (
                        <div className="relative pl-6">
                          <div className="absolute left-2 top-1 bottom-1 w-px bg-gradient-to-b from-yellow-400/60 via-gray-700 to-transparent"></div>
                          {apiData.data.passiveDns.map((p: any, i: number) => (
                            <div key={i} className="relative pb-4 pl-4">
                              <div className="absolute left-0 top-1 w-3 h-3 rounded-full bg-yellow-400/80 border-2 border-gray-900 -translate-x-1/2"></div>
                              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
                                <span className="font-mono text-gray-200">{p.name}</span>
                                <span className="text-gray-500">visto: <span className="text-yellow-300 font-mono">{p.firstSeen}</span> → <span className="text-yellow-300 font-mono">{p.lastSeen}</span></span>
                                <span className="px-1.5 py-0.5 bg-gray-800 rounded text-[10px] text-gray-400">{p.daysKnown} días activo</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="p-3 bg-gray-800/50 border border-yellow-500/20 rounded-lg text-xs text-gray-400">
                          Sin datos históricos disponibles: las fuentes passive DNS (crt.sh / OTX AlienVault) no respondieron en este momento. Reintenta en unos minutos para ver la línea de tiempo.
                        </div>
                      )}
                    </div>
                  )}

                  {/* Posibles tomas de control (subdomain takeover) */}
                  {apiData.data.takeovers?.length > 0 && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <div className="flex flex-wrap items-center gap-2 mb-3">
                        <h3 className="font-semibold flex items-center gap-2"><ShieldAlert className="w-5 h-5 text-orange-400" /> Posibles Subdomain Takeovers ({apiData.data.takeovers.filter((t: any) => t.status !== 'SAFE').length})</h3>
                        <button onClick={() => setDnsdumpShowSafe(!dnsdumpShowSafe)} className="ml-auto text-xs px-2.5 py-1 bg-gray-800 hover:bg-gray-700 rounded-lg text-gray-400">
                          {dnsdumpShowSafe ? 'Ocultar seguros' : 'Mostrar seguros'}
                        </button>
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs">
                          <thead>
                            <tr className="text-gray-500 border-b border-gray-800">
                              <th className="py-2 pr-3">Subdominio</th>
                              <th className="py-2 pr-3">CNAME</th>
                              <th className="py-2 pr-3">Servicio</th>
                              <th className="py-2 pr-3">Estado</th>
                              <th className="py-2">Razón</th>
                            </tr>
                          </thead>
                          <tbody>
                            {apiData.data.takeovers
                              .filter((t: any) => dnsdumpShowSafe || t.status !== 'SAFE')
                              .map((t: any, i: number) => (
                                <tr key={i} className="border-b border-gray-800/60 hover:bg-gray-800/40 align-top">
                                  <td className="py-2 pr-3 font-mono text-gray-200">{t.subdomain}</td>
                                  <td className="py-2 pr-3 font-mono text-cyan-300 break-all">{t.cname}</td>
                                  <td className="py-2 pr-3 text-gray-300">{t.service}</td>
                                  <td className="py-2 pr-3">
                                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                      t.status === 'CANDIDATE' ? 'bg-red-500/20 text-red-400' :
                                      t.status === 'DANGLING' ? 'bg-yellow-500/20 text-yellow-400' :
                                      'bg-green-500/20 text-green-400'
                                    }`}>{t.status}</span>
                                  </td>
                                  <td className="py-2 text-gray-400">{t.reason}</td>
                                </tr>
                              ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* WHOIS integrado */}
                  {apiData.data.whois && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Key className="w-5 h-5 text-green-400" /> WHOIS integrado (RDAP)</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                        <div className="p-3 bg-gray-800 rounded-lg">
                          <div className="text-[10px] uppercase text-gray-500 mb-1">Registrar</div>
                          <div className="text-sm font-mono break-all">{apiData.data.whois.registrar || '—'}</div>
                        </div>
                        <div className="p-3 bg-gray-800 rounded-lg">
                          <div className="text-[10px] uppercase text-gray-500 mb-1">Registrado</div>
                          <div className="text-sm font-mono">{apiData.data.whois.created ? apiData.data.whois.created.slice(0, 10) : '—'}</div>
                        </div>
                        <div className="p-3 bg-gray-800 rounded-lg">
                          <div className="text-[10px] uppercase text-gray-500 mb-1">Expira</div>
                          <div className="text-sm font-mono">{apiData.data.whois.expires ? apiData.data.whois.expires.slice(0, 10) : '—'}</div>
                        </div>
                        <div className="p-3 bg-gray-800 rounded-lg">
                          <div className="text-[10px] uppercase text-gray-500 mb-1">Nameservers</div>
                          <div className="text-sm font-mono truncate">{apiData.data.whois.nameservers?.join(', ') || '—'}</div>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2"><ExternalLink className="w-5 h-5 text-cyan-400" /> Related Hosts</h3>
                    <div className="flex flex-wrap gap-2">
                      {(apiData.data.relatedHosts || []).slice(0, 20).map((h: string, i: number) => (
                        <span key={i} className="px-2 py-1 bg-gray-800 rounded text-xs font-mono text-cyan-300">{h}</span>
                      ))}
                    </div>
                  </div>

                  {(apiData.data.security?.findings?.length > 0) && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><ShieldAlert className="w-5 h-5 text-orange-400" /> Security Findings</h3>
                      <ul className="space-y-1">
                        {apiData.data.security.findings.map((f: string, i: number) => (
                          <li key={i} className="text-sm text-gray-300 flex items-start gap-2"><CheckCircle className="w-4 h-4 text-orange-400 mt-0.5" /> {f}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Network className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">DNS Dump Ready</h3>
                  <p className="text-gray-400">Enumerate A, AAAA, MX, TXT, NS, CNAME, SOA, CAA records, subdomains (crt.sh + brute-force), passive DNS timeline y subdomain takeover detection.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== SOCIAL MONITOR TAB ==================== */}
          {activeTab === 'social' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <MessageSquare className="w-7 h-7 text-blue-400" /> Telegram & Discord Monitor
                  <span className="text-sm font-normal text-gray-400">(keyword intelligence across channels)</span>
                </h2>
                <button
                  onClick={() => openPrintReport('social', apiData?.stats || apiData, inputValue)}
                  className="px-4 py-2 bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex flex-wrap gap-3">
                  <input type="text" placeholder="Search captured messages..." value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleSocialLoad(inputValue)}
                    className="flex-1 min-w-[200px] px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm focus:border-blue-500 focus:outline-none" />
                  <button onClick={() => handleSocialLoad(inputValue)} disabled={loading} className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm flex items-center gap-2">
                    <Search className="w-4 h-4" /> Search
                  </button>
                  <button onClick={() => handleSocialLoad()} disabled={loading} className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm">All</button>
                  <button onClick={handleSocialKeywords} disabled={loading} className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg text-sm flex items-center gap-2">
                    <Key className="w-4 h-4" /> Keywords
                  </button>
                </div>
                {apiData?.configured === false && (
                  <div className="mt-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-xs text-yellow-300">
                    Demo mode — set TELEGRAM_BOT_TOKEN and DISCORD_BOT_TOKEN (Settings → Environment Variables) for live capture.
                  </div>
                )}
              </div>

              {apiData?.stats && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl"><div className="text-2xl font-bold text-blue-400">{apiData.stats.total}</div><div className="text-xs text-gray-500">Total Captured</div></div>
                  <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl"><div className="text-2xl font-bold text-red-400">{apiData.stats.critical}</div><div className="text-xs text-gray-500">Critical</div></div>
                  <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl"><div className="text-2xl font-bold text-orange-400">{apiData.stats.high}</div><div className="text-xs text-gray-500">High</div></div>
                  <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl"><div className="text-2xl font-bold text-green-400">{apiData.stats.activeChannels}</div><div className="text-xs text-gray-500">Active Channels</div></div>
                </div>
              )}

              {apiData?.stats?.topKeywords?.length > 0 && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                  <h3 className="font-semibold mb-3 flex items-center gap-2"><Key className="w-5 h-5 text-purple-400" /> Top Keywords</h3>
                  <div className="flex flex-wrap gap-2">
                    {apiData?.stats?.topKeywords?.map((k: any, i: number) => (
                      <span key={i} className="px-2 py-1 bg-gray-800 rounded text-xs">{k.keyword} <strong className="text-purple-400">{k.count}</strong></span>
                    ))}
                  </div>
                </div>
              )}

              {apiData?.data?.length > 0 && (
                <div className="space-y-2">
                  {(apiData?.data as any[] | undefined)?.slice(0, 50).map((m: any, i: number) => (
                    <div key={i} className={`p-4 rounded-lg border ${m.severity === 'CRITICAL' ? 'bg-red-500/10 border-red-500/30' : m.severity === 'HIGH' ? 'bg-orange-500/10 border-orange-500/30' : 'bg-gray-900 border-gray-800'}`}>
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${m.platform === 'telegram' ? 'bg-blue-500/20 text-blue-400' : 'bg-indigo-500/20 text-indigo-400'}`}>{m.platform}</span>
                          <span className="text-sm font-semibold">{m.channel}</span>
                          <span className="text-xs text-gray-500">@{m.author}</span>
                        </div>
                        <span className={`text-xs font-bold ${m.severity === 'CRITICAL' ? 'text-red-400' : m.severity === 'HIGH' ? 'text-orange-400' : 'text-gray-400'}`}>{m.severity}</span>
                      </div>
                      <p className="text-sm text-gray-300">{m.text}</p>
                      <div className="mt-2 flex flex-wrap gap-2 text-xs">
                        {(m.keywords || []).map((k: string, j: number) => <span key={j} className="px-1.5 py-0.5 bg-purple-500/10 text-purple-300 rounded">#{k}</span>)}
                        {(m.links || []).slice(0, 3).map((l: string, j: number) => <span key={j} className="px-1.5 py-0.5 bg-gray-800 text-cyan-300 rounded font-mono">{l}</span>)}
                      </div>
                      <div className="mt-1 text-[10px] text-gray-600">{new Date(m.ts).toLocaleString()}</div>
                    </div>
                  ))}
                </div>
              )}
              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <MessageSquare className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Channel Monitor Ready</h3>
                  <p className="text-gray-400">Search keywords across Telegram and Discord channels. Connect bots for live capture.</p>
                </div>
              )}
</div>
            )}

          {/* ==================== EXECUTIVE PROTECTION TAB ==================== */}
          {activeTab === 'exec-protection' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <ShieldUser className="w-7 h-7 text-amber-400" /> Executive Protection
                  <span className="text-sm font-normal text-gray-400">(CRUD + OSINT Dork Research)</span>
                </h2>
              </div>

              {/* Executive List / Add Form */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-lg font-semibold">Executives</h3>
                  <button
                    onClick={() => setExecMode('add')}
                    className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg font-medium flex items-center gap-2"
                  >
                    <Plus className="w-4 h-4" /> Add Executive
                  </button>
                </div>

                {execMode === 'add' && (
                  <ExecAddForm onCancel={() => setExecMode('list')} onSuccess={() => { setExecMode('list'); loadExecutives(); }} />
                )}

                {execMode === 'edit' && editingExec && (
                  <ExecEditForm executive={editingExec} onCancel={() => { setExecMode('list'); setEditingExec(null); }} onSuccess={() => { setExecMode('list'); loadExecutives(); }} />
                )}

                {execMode === 'detail' && selectedExec && (
                  <ExecDetailView executive={selectedExec} onClose={() => { setExecMode('list'); setSelectedExec(null); }} onEdit={() => { setEditingExec(selectedExec); setExecMode('edit'); }} />
                )}

                {execMode === 'list' && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-gray-800 text-left text-gray-400">
                          <th className="py-3 px-4">ID/Document</th>
                          <th className="py-3 px-4">Phone</th>
                          <th className="py-3 px-4">Emails</th>
                          <th className="py-3 px-4">Social Media</th>
                          <th className="py-3 px-4">Address / Location</th>
                          <th className="py-3 px-4">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {executives.length === 0 ? (
                          <tr>
                            <td colSpan={6} className="py-12 text-center text-gray-500">
                              <ShieldUser className="w-12 h-12 mx-auto mb-3 text-gray-600" />
                              <p>No executives registered. Click "Add Executive" to start.</p>
                            </td>
                          </tr>
                        ) : (
                          executives.map((exec: any) => (
                            <tr key={exec.id} className="border-b border-gray-800 hover:bg-gray-800/50">
                              <td className="py-3 px-4 font-mono text-amber-300">{exec.documentId}</td>
                              <td className="py-3 px-4 font-mono text-xs">{exec.phone || '-'}</td>
                              <td className="py-3 px-4 text-xs">
                                {exec.emailCorporate && <div className="text-blue-400">{exec.emailCorporate}</div>}
                                {exec.emailPersonal && <div className="text-green-400">{exec.emailPersonal}</div>}
                                {!exec.emailCorporate && !exec.emailPersonal && <span className="text-gray-500">-</span>}
                              </td>
                              <td className="py-3 px-4 text-xs">
                                {exec.socialMedia?.length > 0 ? (
                                  <div className="flex flex-wrap gap-1">
                                    {exec.socialMedia.map((sm: any) => (
                                      <span key={sm.platform} className="px-2 py-0.5 bg-gray-700 rounded text-xs">{sm.platform}</span>
                                    ))}
                                  </div>
                                ) : (
                                  <span className="text-gray-500">-</span>
                                )}
                              </td>
                              <td className="py-3 px-4 text-xs text-gray-400 max-w-xs truncate">
                                {exec.address || exec.location || '-'}
                              </td>
                              <td className="py-3 px-4">
                                <div className="flex gap-2">
                                  <button
                                    onClick={() => { setSelectedExec(exec); setExecMode('detail'); }}
                                    className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded text-xs font-medium"
                                  >
                                    View
                                  </button>
                                  <button
                                    onClick={() => { setEditingExec(exec); setExecMode('edit'); }}
                                    className="px-3 py-1.5 bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 border border-amber-500/30 rounded text-xs font-medium"
                                  >
                                    Edit
                                  </button>
                                  <button
                                    onClick={() => deleteExecutive(exec.id)}
                                    className="px-3 py-1.5 bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 rounded text-xs font-medium"
                                  >
                                    Delete
                                  </button>
                                </div>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Dork Research Section */}
              {selectedExec && execMode === 'detail' && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Search className="w-5 h-5 text-purple-400" />
                    OSINT Dork Research for: <span className="text-amber-300">{selectedExec.documentId}</span>
                  </h3>
                  <div className="flex gap-4 mb-6 flex-wrap">
                    <button
                      onClick={() => searchAllDorks(selectedExec.id)}
                      disabled={dorkLoading}
                      className="px-6 py-3 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                    >
                      {dorkLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                      Run All Dork Searches
                    </button>
                    <button
                      onClick={() => openPrintReport('exec-protection', { executive: selectedExec, dorkResults: dorkResults }, selectedExec.documentId)}
                      className="px-6 py-3 bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/30 rounded-lg font-medium flex items-center gap-2 no-print"
                    >
                      <Printer className="w-4 h-4" />
                      Print HTML Report
                    </button>
                  </div>

                  {dorkResults && dorkResults.queries.length > 0 && (
                    <div className="space-y-4">
                      {dorkResults.queries.map((q: any, idx: number) => (
                        <div key={idx} className="bg-gray-800/60 border border-gray-700 rounded-lg p-4">
                          <div className="flex items-start justify-between mb-3">
                            <div>
                              <h4 className="font-semibold text-purple-300">{q.category}</h4>
                              <p className="text-xs text-gray-500">{q.description}</p>
                            </div>
                            <span className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs font-mono">
                              {q.isImageSearch ? 'Images' : 'Web'}
                            </span>
                          </div>
                          <div className="font-mono text-xs text-gray-300 bg-gray-900 p-3 rounded break-all">
                            {q.query}
                          </div>
                          <div className="flex gap-3 mt-3 flex-wrap">
                            {q.sources.map((source: string) => (
                              <span key={source} className="px-2 py-1 bg-gray-700 text-gray-300 rounded text-xs">{source}</span>
                            ))}
                          </div>
                          <div className="mt-3 flex gap-2">
                            <button
                              onClick={() => copyToClipboard(q.query)}
                              className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs font-medium flex items-center gap-1"
                            >
                              <Copy className="w-3 h-3" /> Copy Query
                            </button>
                            <a
                              href={`https://www.google.com/search?q=${encodeURIComponent(q.query)}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="px-3 py-1.5 bg-green-600/20 hover:bg-green-600/30 text-green-400 border border-green-500/30 rounded text-xs font-medium flex items-center gap-1"
                            >
                              <ExternalLink className="w-3 h-3" /> Search Google
                            </a>
                            {q.isImageSearch && (
                              <a
                                href={`https://www.google.com/search?tbm=isch&q=${encodeURIComponent(q.query)}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded text-xs font-medium flex items-center gap-1"
                              >
                                <Image className="w-3 h-3" /> Search Images
                              </a>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ==================== FAKE APP SCANNER TAB ==================== */}
          {activeTab === 'fakeapp' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Smartphone className="w-7 h-7 text-fuchsia-400" /> Fake App Scanner
                  <span className="text-sm font-normal text-gray-400">(MOBSF-style + CVE matching)</span>
                </h2>
                <button
                  onClick={() => openPrintReport('fakeapp', apiData?.data, inputValue)}
                  className="px-4 py-2 bg-fuchsia-600/20 hover:bg-fuchsia-600/30 text-fuchsia-300 border border-fuchsia-500/30 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors no-print"
                  title="Generar informe imprimible HTML"
                >
                  <Printer className="w-4 h-4" />
                  Informe Imprimible
                </button>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
                <div>
                  <p className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wide flex items-center gap-2"><UploadCloud className="w-4 h-4 text-fuchsia-400" /> Upload file (analyzed in your browser)</p>
                  <div className="flex gap-4 items-center">
                    <div className="flex-1">
                      <input ref={fakeAppFileRef} type="file" accept=".apk,.xapk,.aab,.apks,.ipa,.appx,.zip,application/vnd.android.package-archive" onChange={handleFakeAppFile}
                        className="w-full text-sm text-gray-400 file:mr-4 file:px-4 file:py-2.5 file:rounded-lg file:border-0 file:bg-fuchsia-600 file:text-white file:font-medium file:cursor-pointer hover:file:bg-fuchsia-700" />
                    </div>
                    <button onClick={handleFakeAppUpload} disabled={fakeAppAnalyzing || loading || !fakeAppFile}
                      className="px-6 py-3 bg-fuchsia-600 hover:bg-fuchsia-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg font-medium flex items-center gap-2 shrink-0">
                      {fakeAppAnalyzing ? <Loader2 className="w-4 h-4 animate-spin" /> : <UploadCloud className="w-4 h-4" />} {fakeAppAnalyzing ? 'Analyzing...' : 'Analizar archivo'}
                    </button>
                  </div>
                  {fakeAppFileName && <p className="text-xs text-fuchsia-300 mt-2 font-mono">Selected: {fakeAppFileName}</p>}
                  <p className="text-xs text-gray-500 mt-1">Choose the file and click <span className="text-fuchsia-400 font-semibold">Analizar archivo</span>. APK / XAPK / AAB / APKS / APPX / ZIP are scanned fully client-side — nothing but the report leaves your browser.</p>
                </div>
                <div className="border-t border-gray-800 pt-4">
                  <p className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wide flex items-center gap-2"><Globe className="w-4 h-4 text-fuchsia-400" /> ...or analyze a download URL</p>
                  <div className="flex gap-4">
                    <div className="flex-1">
                      <input type="text" placeholder="Direct APK download URL (e.g., https://cdn.example.com/bankapp.apk)"
                        value={inputValue} onChange={(e) => setInputValue(e.target.value)}
                        onKeyPress={(e) => e.key === 'Enter' && handleFakeApp()}
                        className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-fuchsia-500 focus:outline-none" />
                    </div>
                    <button onClick={handleFakeApp} disabled={loading} className="px-6 py-3 bg-fuchsia-600 hover:bg-fuchsia-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2">
                      {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Smartphone className="w-4 h-4" />} Analyze
                    </button>
                  </div>
                </div>
                <p className="text-xs text-gray-500">Statically analyzes the app — manifest (AXML), signing certificate, permissions, dex secrets &amp; URLs. Like MobSF.</p>
              </div>

              {apiData?.data?.verdict && (
                <div className="space-y-4">
                  <div className={`rounded-xl p-5 border ${apiData.data.verdict === 'FAKE' ? 'bg-red-500/10 border-red-500/50' : apiData.data.verdict === 'SUSPICIOUS' ? 'bg-orange-500/10 border-orange-500/50' : 'bg-emerald-500/10 border-emerald-500/50'}`}>
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-semibold">Verdict: <span className={apiData.data.verdict === 'FAKE' ? 'text-red-400' : apiData.data.verdict === 'SUSPICIOUS' ? 'text-orange-400' : 'text-emerald-400'}>{apiData.data.verdict}</span></h3>
                        <p className="text-sm text-gray-400 mt-1 font-mono break-all">{apiData.data.fileName}</p>
                        <p className="text-xs text-gray-500 mt-1 font-mono break-all">{apiData.data.appInfo?.package} · v{apiData.data.appInfo?.versionName || '?'} · {apiData.data.sha256?.substring(0, 20)}...</p>
                      </div>
                      <div className="text-right">
                        <div className="text-3xl font-bold">{apiData.data.score || 0}<span className="text-sm text-gray-500">/100</span></div>
                        <div className="text-sm font-bold text-gray-400">risk score</div>
                        <div className="text-xs mt-1"><span className={`px-2 py-0.5 rounded font-bold ${apiData.data.confidence >= 75 ? 'bg-red-500/20 text-red-400' : apiData.data.confidence >= 50 ? 'bg-orange-500/20 text-orange-400' : 'bg-gray-700'}`}>{apiData.data.confidence}% conf</span></div>
                      </div>
                    </div>
                    <div className="mt-3 h-2 bg-gray-800 rounded-full overflow-hidden">
                      <div className={`h-full ${apiData.data.score >= 60 ? 'bg-red-500' : apiData.data.score >= 30 ? 'bg-orange-500' : 'bg-emerald-500'}`} style={{ width: `${Math.min(100, apiData.data.score || 0)}%` }} />
                    </div>
                  </div>

                  {(apiData.data.appInfo?.package || apiData.data.permissions) && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Info className="w-5 h-5 text-sky-400" /> App Info</h3>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                        <div><span className="text-gray-500 block">Package</span><span className="font-mono break-all">{apiData.data.appInfo?.package}</span></div>
                        <div><span className="text-gray-500 block">Version</span><span>{apiData.data.appInfo?.versionName} ({apiData.data.appInfo?.versionCode})</span></div>
                        <div><span className="text-gray-500 block">SDK</span><span>min {apiData.data.appInfo?.minSdk || '?'} / target {apiData.data.appInfo?.targetSdk || '?'}</span></div>
                        <div><span className="text-gray-500 block">Size</span><span>{(apiData.data.sizeBytes / 1048576).toFixed(1)} MB · {apiData.data.fileType}</span></div>
                      </div>
                      <div className="mt-3 grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
                        <div className="bg-gray-800/60 rounded-lg p-2"><span className="text-gray-500 block">Activities</span><span className="font-bold">{apiData.data.components?.activities?.length ?? 0}</span></div>
                        <div className="bg-gray-800/60 rounded-lg p-2"><span className="text-gray-500 block">Services</span><span className="font-bold">{apiData.data.components?.services?.length ?? 0}</span></div>
                        <div className="bg-gray-800/60 rounded-lg p-2"><span className="text-gray-500 block">Receivers</span><span className="font-bold">{apiData.data.components?.receivers?.length ?? 0}</span></div>
                        <div className="bg-gray-800/60 rounded-lg p-2"><span className="text-gray-500 block">Providers</span><span className="font-bold">{apiData.data.components?.providers?.length ?? 0}</span></div>
                        <div className="bg-gray-800/60 rounded-lg p-2"><span className="text-gray-500 block">Exported</span><span className={`font-bold ${apiData.data.manifest?.exportedCount > 0 ? 'text-orange-400' : 'text-emerald-400'}`}>{apiData.data.manifest?.exportedCount ?? 0}</span></div>
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2 text-xs">
                        <span className={`px-2 py-1 rounded ${apiData.data.manifest?.allowBackup ? 'bg-orange-500/20 text-orange-400' : 'bg-gray-800 text-gray-400'}`}>allowBackup: {String(apiData.data.manifest?.allowBackup)}</span>
                        <span className={`px-2 py-1 rounded ${apiData.data.manifest?.debuggable ? 'bg-red-500/20 text-red-400' : 'bg-gray-800 text-gray-400'}`}>debuggable: {String(apiData.data.manifest?.debuggable)}</span>
                        <span className={`px-2 py-1 rounded ${apiData.data.manifest?.usesCleartextTraffic ? 'bg-red-500/20 text-red-400' : 'bg-gray-800 text-gray-400'}`}>cleartext: {String(apiData.data.manifest?.usesCleartextTraffic)}</span>
                        <span className={`px-2 py-1 rounded ${apiData.data.certificate?.selfSigned ? 'bg-red-500/20 text-red-400' : 'bg-gray-800 text-gray-400'}`}>self-signed: {String(apiData.data.certificate?.selfSigned)}</span>
                      </div>
                    </div>
                  )}

                  {apiData.data.permissions?.dangerous?.length > 0 && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Lock className="w-5 h-5 text-amber-400" /> Dangerous Permissions ({apiData.data.permissions.dangerous.length})</h3>
                      <div className="flex flex-wrap gap-2">
                        {apiData.data.permissions.dangerous.map((p: string, i: number) => (
                          <span key={i} className="px-2 py-1 bg-red-500/10 border border-red-500/30 rounded text-xs font-mono">{p.replace('android.permission.', '')}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2"><AlertTriangle className="w-5 h-5 text-red-400" /> Risk Objects ({apiData.data.riskObjects?.length || 0})</h3>
                    <div className="space-y-2">
                      {(apiData.data.riskObjects || []).map((r: any, i: number) => (
                        <div key={i} className={`p-3 rounded-lg ${r.severity === 'CRITICAL' ? 'bg-red-500/10 border-l-2 border-red-500' : r.severity === 'HIGH' ? 'bg-orange-500/10 border-l-2 border-orange-500' : r.severity === 'MEDIUM' ? 'bg-yellow-500/10 border-l-2 border-yellow-500' : 'bg-gray-800/60 border-l-2 border-gray-600'}`}>
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-bold">{r.id} · {r.type}</span>
                            <span className="text-xs font-bold text-red-400">{r.severity}</span>
                          </div>
                          <p className="text-xs text-gray-400 mt-1">{r.description}</p>
                          <p className="text-xs text-gray-500 mt-1">→ {r.recommendation}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {apiData.data.certificate && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Shield className="w-5 h-5 text-emerald-400" /> Signing Certificate</h3>
                      <div className="grid grid-cols-2 gap-3 text-xs">
                        <div className="col-span-2"><span className="text-gray-500 block">Subject</span><span className="font-mono break-all">{apiData.data.certificate.subject}</span></div>
                        <div className="col-span-2"><span className="text-gray-500 block">Issuer</span><span className="font-mono break-all">{apiData.data.certificate.issuer}</span></div>
                        <div><span className="text-gray-500 block">Valid from</span><span>{apiData.data.certificate.validFrom?.substring(0, 10)}</span></div>
                        <div><span className="text-gray-500 block">Valid to</span><span className={apiData.data.certificate.expired ? 'text-red-400 font-bold' : ''}>{apiData.data.certificate.validTo?.substring(0, 10)}{apiData.data.certificate.expired ? ' (EXPIRED)' : ''}</span></div>
                        <div className="col-span-2"><span className="text-gray-500 block">Serial</span><span className="font-mono break-all text-gray-400">{apiData.data.certificate.serialNumber}</span></div>
                      </div>
                    </div>
                  )}

                  {(apiData.data.secrets?.length > 0 || apiData.data.network?.suspiciousDomains?.length > 0) && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Key className="w-5 h-5 text-orange-400" /> Binary Findings</h3>
                      {apiData.data.secrets?.length > 0 && (
                        <div className="mb-3">
                          <p className="text-xs text-gray-500 mb-2">Hardcoded secrets ({apiData.data.secrets.length})</p>
                          <div className="flex flex-wrap gap-2">
                            {apiData.data.secrets.slice(0, 10).map((s: any, i: number) => (
                              <span key={i} className={`px-2 py-1 rounded text-xs font-mono ${s.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' : s.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' : 'bg-yellow-500/20 text-yellow-400'}`}>{s.type}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      {apiData.data.network?.suspiciousDomains?.length > 0 && (
                        <div>
                          <p className="text-xs text-gray-500 mb-2">Suspicious domains</p>
                          <div className="flex flex-wrap gap-2">
                            {apiData.data.network.suspiciousDomains.slice(0, 10).map((d: string, i: number) => (
                              <span key={i} className="px-2 py-1 bg-red-500/10 border border-red-500/30 rounded text-xs font-mono">{d}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      {apiData.data.code?.riskyCalls?.length > 0 && (
                        <div className="mt-3">
                          <p className="text-xs text-gray-500 mb-2">Risky APIs ({apiData.data.code.riskyCalls.length})</p>
                          <div className="flex flex-wrap gap-2">
                            {apiData.data.code.riskyCalls.map((c: string, i: number) => (
                              <span key={i} className="px-2 py-1 bg-gray-800 rounded text-xs font-mono text-gray-300">{c}</span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {apiData.data.cvEs?.length > 0 && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Shield className="w-5 h-5 text-orange-400" /> CVE Impact Matches</h3>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead><tr className="border-b border-gray-800 text-left text-gray-400">
                            <th className="py-2 px-2">CVE</th><th className="py-2 px-2">CVSS</th><th className="py-2 px-2">Relevance</th>
                          </tr></thead>
                          <tbody>
                            {(apiData.data.cvEs as any[]).map((c: any, i: number) => (
                              <tr key={i} className="border-b border-gray-800">
                                <td className="py-2 px-2 font-mono text-xs">{c.cveId}</td>
                                <td className="py-2 px-2"><span className={`px-2 py-0.5 rounded text-xs font-bold ${(c.cvssScore || 0) >= 9 ? 'bg-red-500 text-white' : (c.cvssScore || 0) >= 7 ? 'bg-orange-500 text-black' : 'bg-gray-700'}`}>{c.cvssScore}</span></td>
                                <td className="py-2 px-2 text-xs text-gray-400">{c.relevance}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {apiData.data.actors?.length > 0 && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Users className="w-5 h-5 text-purple-400" /> Suspected Actors</h3>
                      <div className="space-y-2">
                        {(apiData.data.actors as any[]).map((a: any, i: number) => (
                          <div key={i} className="p-3 bg-gray-800/60 rounded-lg flex flex-wrap gap-3 text-xs">
                            <span className="font-bold text-purple-300">{a.handle}</span>
                            <span className="text-gray-400">{a.role}</span>
                            <span className="font-mono text-gray-500">{a.ip}</span>
                            <span className="font-mono text-red-400">{a.domains?.join(', ')}</span>
                            <span className={`px-2 py-0.5 rounded font-bold ${a.confidence === 'HIGH' ? 'bg-red-500/20 text-red-400' : 'bg-gray-700'}`}>{a.confidence}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Smartphone className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Fake App Scanner Ready</h3>
                  <p className="text-gray-400">Analyze suspicious APK/IPA files for risk objects, CVE impact and fraud actors.</p>
                </div>
              )}
            </div>
          )}
        </main>
      </div>

      {/* ==================== MODALS ==================== */}
      {/* Detail Modal */}
      {showModal && selectedIOC && modalType === 'detail' && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setShowModal(false)}>
          <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-3xl w-full max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="sticky top-0 bg-gray-900 border-b border-gray-800 p-4 flex items-center justify-between">
              <h3 className="font-bold text-lg">IOC Details</h3>
              <button onClick={() => setShowModal(false)} className="p-2 hover:bg-gray-800 rounded-lg"><X className="w-5 h-5" /></button>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div><span className="text-gray-400 text-sm">ID:</span><p className="font-mono text-sm">{selectedIOC.id}</p></div>
                <div><span className="text-gray-400 text-sm">Type:</span><p><span className="px-2 py-1 bg-gray-700 rounded text-xs">{selectedIOC.type}</span></p></div>
                <div className="col-span-2"><span className="text-gray-400 text-sm">Value:</span><p className="font-mono break-all">{selectedIOC.value}</p></div>
                <div><span className="text-gray-400 text-sm">Severity:</span><p style={{ color: SEVERITY_COLORS[selectedIOC.severity] }} className="font-bold">{selectedIOC.severity}</p></div>
                <div><span className="text-gray-400 text-sm">Status:</span><p style={{ color: STATUS_COLORS[selectedIOC.status] }} className="font-bold">{selectedIOC.status}</p></div>
                <div><span className="text-gray-400 text-sm">Confidence:</span><p>{selectedIOC.confidence}%</p></div>
                <div><span className="text-gray-400 text-sm">Source:</span><p>{selectedIOC.source || '-'}</p></div>
                <div className="col-span-2"><span className="text-gray-400 text-sm">Description:</span><p>{selectedIOC.description || '-'}</p></div>
              </div>
              {selectedIOC.tags?.length > 0 && (
                <div className="flex flex-wrap gap-2 pt-4 border-t border-gray-800">
                  {selectedIOC.tags.map((tag, idx) => (<span key={idx} className="px-2 py-1 bg-gray-700 rounded text-xs">{tag}</span>))}
                </div>
              )}
            </div>
            <div className="sticky bottom-0 bg-gray-900 border-t border-gray-800 p-4 flex justify-end gap-3">
              <button onClick={() => setModalType('edit')} className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm"><Edit3 className="w-4 h-4 inline mr-1" /> Edit</button>
              <button onClick={() => { handleDeleteIOC(selectedIOC.id); setShowModal(false); }} className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-sm"><Trash2 className="w-4 h-4 inline mr-1" /> Delete</button>
            </div>
          </div>
        </div>
      )}

      {/* Add/Edit Modal */}
      {showModal && (modalType === 'add' || modalType === 'edit') && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setShowModal(false)}>
          <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-lg w-full" onClick={(e) => e.stopPropagation()}>
            <div className="border-b border-gray-800 p-4 flex items-center justify-between">
              <h3 className="font-bold text-lg">{modalType === 'add' ? 'Add New IOC' : 'Edit IOC'}</h3>
              <button onClick={() => setShowModal(false)} className="p-2 hover:bg-gray-800 rounded-lg"><X className="w-5 h-5" /></button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Type *</label>
                <select value={formData.type} onChange={(e) => setFormData({...formData, type: e.target.value})} className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg" disabled={modalType === 'edit'}>
                  <option value="IP">IP Address</option>
                  <option value="DOMAIN">Domain</option>
                  <option value="URL">URL</option>
                  <option value="HASH">Hash</option>
                  <option value="CVE">CVE ID</option>
                  <option value="EMAIL">Email</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Value *</label>
                <input type="text" value={formData.value} onChange={(e) => setFormData({...formData, value: e.target.value})} className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg font-mono" placeholder={modalType === 'add' ? 'Enter indicator value...' : ''} disabled={modalType === 'edit'} />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Description</label>
                <textarea value={formData.description} onChange={(e) => setFormData({...formData, description: e.target.value})} rows={3} className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg resize-none" placeholder="Add context..." />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Severity</label>
                  <select value={formData.severity} onChange={(e) => setFormData({...formData, severity: e.target.value})} className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg">
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                    <option value="INFO">Info</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Tags (comma separated)</label>
                  <input type="text" value={formData.tags.join(', ')} onChange={(e) => setFormData({...formData, tags: e.target.value.split(',').map(t => t.trim()).filter(Boolean)})} className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg" placeholder="tag1, tag2..." />
                </div>
              </div>
            </div>
            <div className="border-t border-gray-800 p-4 flex justify-end gap-3">
              <button onClick={() => setShowModal(false)} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg">Cancel</button>
              <button onClick={modalType === 'add' ? handleAddIOC : handleUpdateIOC} disabled={!formData.value} className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 rounded-lg">
                {modalType === 'add' ? <Plus className="w-4 h-4 inline mr-1" /> : <Save className="w-4 h-4 inline mr-1" />}
                {modalType === 'add' ? 'Add IOC' : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ==================== SUB-COMPONENTS ====================
function InfoCard({ label, value, icon, alert }: { label: string; value: string | React.ReactNode; icon: React.ReactNode; alert?: boolean }) {
  return (
    <div className={`p-3 bg-gray-800/50 rounded-lg min-w-0 ${alert ? 'border border-red-500/30' : ''}`}>
      <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">{icon}{label}</div>
      <div className={`font-medium text-sm break-words ${alert ? 'text-red-400' : ''}`}>{value}</div>
    </div>
  );
}

// Missing icons - create simple components
function LinkIcon({ className }: { className?: string }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>;
}

function Tag({ className }: { className?: string }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" /></svg>;
}

function Package({ className }: { className?: string }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" /></svg>;
}

function ShoppingCart({ className }: { className?: string }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293 2.293c-.63.63-.184 1.707.707 1.707H17m0 0a2 2 0 100 4 2 2 0 000-4zm-8 2a2 2 0 11-4 0 2 2 0 014 0z" /></svg>;
}

function TreeNode({ node, indent = 0, onDownload }: { node: any; indent?: number; onDownload?: (url: string) => void }) {
  const [expanded, setExpanded] = React.useState(false);
  const typeIcon = {
    page: <Globe2 className="w-3.5 h-3.5 text-blue-400" />,
    script: <FileCode className="w-3.5 h-3.5 text-yellow-400" />,
    style: <FileCode className="w-3.5 h-3.5 text-pink-400" />,
    image: <Camera className="w-3.5 h-3.5 text-green-400" />,
    font: <FileCode className="w-3.5 h-3.5 text-purple-400" />,
    document: <FileText className="w-3.5 h-3.5 text-orange-400" />,
    redirect: <ArrowRight className="w-3.5 h-3.5 text-yellow-400" />,
    fuzz: <FolderOpen className="w-3.5 h-3.5 text-red-400" />,
    other: <FileText className="w-3.5 h-3.5 text-gray-400" />,
  };
  const statusColor = node.status === 200 ? 'text-green-400' : node.status === 403 ? 'text-red-400' : node.status >= 300 && node.status < 400 ? 'text-yellow-400' : node.status === 404 ? 'text-gray-500' : 'text-gray-400';
  const secrets = node.meta?.secrets?.length || 0;
  const hasChildren = node.children && node.children.length > 0;
  const downloadable = node.status && node.status >= 200 && node.status < 400 && node.type !== 'redirect';
  return (
    <div key={node.id} style={{ marginLeft: `${indent * 16}px` }}>
      <div className="flex items-center gap-2 py-1 text-xs" onClick={() => setExpanded(!expanded)}>
        {hasChildren && <ChevronRight className={`w-3.5 h-3.5 text-gray-500 transition-transform ${expanded ? 'rotate-90' : ''}`} />}
        {typeIcon[node.type as keyof typeof typeIcon] || typeIcon.other}
        <span className="font-mono truncate flex-1 min-w-0">{node.name}</span>
        <span className={`font-mono ${statusColor}`}>{node.status || '—'}</span>
        {node.size && <span className="text-gray-500">{(node.size / 1024).toFixed(1)} KB</span>}
        {secrets > 0 && <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded text-[10px] font-bold">{secrets} secrets</span>}
        {node.meta?.forms > 0 && <span className="px-1.5 py-0.5 bg-blue-500/20 text-blue-400 rounded text-[10px] font-bold">{node.meta.forms} forms</span>}
        {downloadable && onDownload && (
          <button
            onClick={(e) => { e.stopPropagation(); onDownload(node.url); }}
            className="text-gray-400 hover:text-blue-400 transition-colors shrink-0"
            title={`Download content: ${node.url}`}
          >
            <Download className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
      {expanded && node.children && (
        <div className="border-l border-gray-800 pl-2 mt-1 space-y-1">
          {node.children.map((child: any) => <TreeNode key={child.id} node={child} indent={indent + 1} onDownload={onDownload} />)}
        </div>
      )}
    </div>
  );
}

// Infrastructure Graph Component (Lookyloo-style interactive graph)
function InfrastructureGraph({ data }: { data: any }) {
  const [nodes, setNodes] = React.useState<any[]>([]);
  const [edges, setEdges] = React.useState<any[]>([]);
  const [selectedNode, setSelectedNode] = React.useState<any>(null);
  const [pan, setPan] = React.useState({ x: 0, y: 0 });
  const [zoom, setZoom] = React.useState(1);

  React.useEffect(() => {
    if (!data.dns) return;
    
    const newNodes: any[] = [];
    const newEdges: any[] = [];
    const nodeId = (prefix: string, label: string) => `${prefix}-${label.replace(/[^a-zA-Z0-9]/g, '-')}`;
    
    // Primary domain (center)
    const domainId = nodeId('domain', data.domain);
    newNodes.push({
      id: domainId,
      label: data.domain,
      type: 'domain',
      x: 400,
      y: 200,
      data: { domain: data.domain, ip: data.ip, asn: data.asn, isp: data.isp, geo: data.geo }
    });

    // IP node
    if (data.ip) {
      const ipId = nodeId('ip', data.ip);
      newNodes.push({ id: ipId, label: data.ip, type: 'ip', x: 200, y: 200, data: { ip: data.ip, asn: data.asn, isp: data.isp, geo: data.geo } });
      newEdges.push({ from: domainId, to: ipId, label: 'A', color: '#a855f7' });
    }

    // ASN
    if (data.asn) {
      const asnId = nodeId('asn', data.asn);
      newNodes.push({ id: asnId, label: `AS${data.asn}`, type: 'asn', x: 200, y: 300, data: { asn: data.asn } });
      if (data.ip) newEdges.push({ from: nodeId('ip', data.ip), to: asnId, label: 'ASN', color: '#ec4899' });
    }

    // ISP
    if (data.isp) {
      const ispId = nodeId('isp', data.isp);
      newNodes.push({ id: ispId, label: data.isp, type: 'isp', x: 200, y: 400, data: { isp: data.isp } });
      if (data.asn) newEdges.push({ from: nodeId('asn', data.asn), to: ispId, label: 'ISP', color: '#ec4899' });
    }

    // Geo
    if (data.geo) {
      const geoId = nodeId('geo', data.geo.country);
      newNodes.push({ id: geoId, label: `${data.geo.country}, ${data.geo.city}`, type: 'geo', x: 200, y: 500, data: data.geo });
      if (data.isp) newEdges.push({ from: nodeId('isp', data.isp), to: geoId, label: 'Geo', color: '#22d3ee' });
    }

    // MX Records
    data.dns.MX?.Answer?.slice(0, 5).forEach((m: any, i: number) => {
      const mxLabel = m.data || m.exchange;
      if (!mxLabel) return;
      const mxId = nodeId('mx', mxLabel);
      newNodes.push({ id: mxId, label: `MX ${m.preference || i}: ${mxLabel}`, type: 'mx', x: 600, y: 100 + i * 80, data: m });
      newEdges.push({ from: domainId, to: mxId, label: 'MX', color: '#f97316' });
    });

    // Nameservers
    data.dns.NS?.Answer?.slice(0, 4).forEach((n: any, i: number) => {
      const nsLabel = n.data || n.nsdname;
      if (!nsLabel) return;
      const nsId = nodeId('ns', nsLabel);
      newNodes.push({ id: nsId, label: nsLabel, type: 'ns', x: 600, y: 500 + i * 80, data: n });
      newEdges.push({ from: domainId, to: nsId, label: 'NS', color: '#84cc16' });
    });

    // Subdomains
    data.subdomains?.slice(0, 12).forEach((s: string, i: number) => {
      const subId = nodeId('sub', s);
      newNodes.push({ id: subId, label: s, type: 'subdomain', x: 800, y: 100 + i * 50, data: { subdomain: s } });
      newEdges.push({ from: domainId, to: subId, label: 'sub', color: '#6366f1' });
    });

    setNodes(newNodes);
    setEdges(newEdges);
  }, [data]);

  const getNodeColor = (type: string) => {
    const colors: Record<string, string> = {
      domain: '#f97316', ip: '#a855f7', asn: '#ec4899', isp: '#ec4899',
      geo: '#22d3ee', mx: '#f97316', ns: '#84cc16', subdomain: '#6366f1',
    };
    return colors[type] || '#6b7280';
  };

  const getNodeIcon = (type: string) => {
    const icons: Record<string, string> = {
      domain: '🌐', ip: '📍', asn: '🔢', isp: '🏢', geo: '🌍',
      mx: '📧', ns: '📛', subdomain: '🌿',
    };
    return icons[type] || '🔗';
  };

  if (!data.dns) return <div className="text-gray-500 text-center py-8">No DNS data available</div>;

  return (
    <div className="relative w-full h-[500px] bg-gray-950 rounded-lg border border-gray-800 overflow-hidden">
      <svg viewBox="0 0 800 500" className="w-full h-full" style={{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`, transformOrigin: '0 0' }}>
        <defs>
          <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="#6b7280" />
          </marker>
        </defs>
        {/* Edges */}
        {edges.map((edge, i) => (
          <line
            key={i}
            x1={nodes.find(n => n.id === edge.from)?.x || 0}
            y1={nodes.find(n => n.id === edge.from)?.y || 0}
            x2={nodes.find(n => n.id === edge.to)?.x || 0}
            y2={nodes.find(n => n.id === edge.to)?.y || 0}
            stroke={edge.color}
            strokeWidth="1.5"
            markerEnd="url(#arrowhead)"
            strokeDasharray="5,5"
            opacity="0.7"
          />
        ))}
        {/* Nodes */}
        {nodes.map((node) => (
          <g key={node.id} onClick={() => setSelectedNode(node)}>
            <circle
              cx={node.x}
              cy={node.y}
              r={selectedNode?.id === node.id ? 22 : 18}
              fill="url(#node-gradient)"
              stroke={getNodeColor(node.type)}
              strokeWidth={selectedNode?.id === node.id ? 3 : 2}
              filter="drop-shadow(0 0 8px currentColor)"
            />
            <text x={node.x} y={node.y + 4} textAnchor="middle" fontSize="14" fill="white" fontWeight="bold">
              {getNodeIcon(node.type)}
            </text>
            <text x={node.x} y={node.y - 28} textAnchor="middle" fontSize="10" fill="#9ca3af" fontFamily="monospace">
              {node.label.length > 20 ? node.label.slice(0, 18) + '...' : node.label}
            </text>
          </g>
        ))}
        {/* Edge labels */}
        {edges.map((edge, i) => {
          const from = nodes.find(n => n.id === edge.from);
          const to = nodes.find(n => n.id === edge.to);
          if (!from || !to) return null;
          const mx = (from.x + to.x) / 2;
          const my = (from.y + to.y) / 2;
          return (
            <text key={i} x={mx} y={my - 5} textAnchor="middle" fontSize="8" fill="#9ca3af" fontFamily="monospace">
              {edge.label}
            </text>
          );
        })}
      </svg>
      
      {/* Pan/Zoom Controls */}
      <div className="absolute bottom-4 right-4 flex flex-col gap-1">
        <button onClick={() => setZoom(Math.min(zoom + 0.2, 3))} className="p-2 bg-gray-800 border border-gray-700 rounded hover:bg-gray-700">+</button>
        <button onClick={() => setZoom(Math.max(zoom - 0.2, 0.3))} className="p-2 bg-gray-800 border border-gray-700 rounded hover:bg-gray-700">−</button>
        <button onClick={() => { setPan({ x: 0, y: 0 }); setZoom(1); }} className="p-2 bg-gray-800 border border-gray-700 rounded hover:bg-gray-700">⌂</button>
      </div>

      {/* Node Detail Panel */}
      {selectedNode && (
        <div className="absolute top-4 left-4 w-72 bg-gray-900 border border-gray-700 rounded-lg p-4 shadow-lg z-10">
          <div className="flex items-center justify-between mb-3">
            <h4 className="font-semibold">{selectedNode.label}</h4>
            <button onClick={() => setSelectedNode(null)} className="text-gray-400 hover:text-white">×</button>
          </div>
          <div className="space-y-2 text-xs">
            <div><span className="text-gray-500">Type:</span> <span className="font-mono ml-2 capitalize">{selectedNode.type}</span></div>
            {selectedNode.data.ip && <div><span className="text-gray-500">IP:</span> <span className="font-mono ml-2">{selectedNode.data.ip}</span></div>}
            {selectedNode.data.asn && <div><span className="text-gray-500">ASN:</span> <span className="font-mono ml-2">{selectedNode.data.asn}</span></div>}
            {selectedNode.data.isp && <div><span className="text-gray-500">ISP:</span> <span className="font-mono ml-2">{selectedNode.data.isp}</span></div>}
            {selectedNode.data.geo && <div><span className="text-gray-500">Geo:</span> <span className="font-mono ml-2">{selectedNode.data.geo.country}, {selectedNode.data.geo.city}</span></div>}
            {selectedNode.data.mx && <div><span className="text-gray-500">MX:</span> <span className="font-mono ml-2">{selectedNode.data.mx}</span></div>}
            <button onClick={() => setSelectedNode(null)} className="mt-3 w-full px-2 py-1 bg-gray-700 hover:bg-gray-600 rounded text-xs">Close</button>
          </div>
        </div>
      )}
      
      <style jsx>{`
        @keyframes gradient {
          0% { background-position: 0% 50%; }
          50% { background-position: 100% 50%; }
          100% { background-position: 0% 50%; }
        }
        #node-gradient {
          background: linear-gradient(135deg, #1f2937, #374151);
          background-size: 200% 200%;
          animation: gradient 3s ease infinite;
        }
      `}
      </style>
    </div>
  );
}

// Subdomain Graph Component — DNS Dump (dominio → subdominios → IPs, fuentes CT/brute)
function SubdomainGraph({ data }: { data: any }) {
  const [selected, setSelected] = React.useState<any>(null);
  const infoMap = React.useMemo(() => {
    const m = new Map<string, any>();
    (data?.subdomainInfo || []).forEach((s: any) => m.set(s.name, s));
    return m;
  }, [data]);
  const tbMap = React.useMemo(() => {
    const m = new Map<string, any>();
    (data?.takeovers || []).forEach((t: any) => m.set(t.subdomain, t));
    return m;
  }, [data]);
  const ipRows = React.useMemo(() => (data?.ipMap || []).slice(), [data]);

  const providerFor = (host: string, ip: string) => {
    const row = ipRows.find((r: any) => r.host === host && r.ip === ip);
    if (!row) return '';
    const parts = [row.provider, row.asn && row.asn !== '—' ? row.asn : '', row.country && row.country !== '—' ? row.country : ''].filter(Boolean);
    return parts.join(' · ');
  };

  const subs = (data?.subdomains || []).slice(0, 30);
  const W = Math.max(840, subs.length * 150 + 80);
  const H = 320;
  const rootX = Math.min(W / 2, 640);
  const subX = (i: number) => (subs.length === 1 ? W / 2 : 60 + (i * (W - 120)) / Math.max(subs.length - 1, 1));
  const colorFor = (info: any) => {
    const src = info?.source || '';
    if (src.includes('brute-force') && (src.includes('crt.sh') || src.includes('OTX') || src.includes('bufferover') || src.includes('hackertarget'))) return '#2dd4bf';
    if (src.includes('crt.sh')) return '#a855f7';
    if (src.includes('OTX')) return '#ec4899';
    if (src.includes('bufferover')) return '#fb923c';
    if (src.includes('hackertarget')) return '#60a5fa';
    if (src.includes('brute-force')) return '#22d3ee';
    return '#6b7280';
  };

  return (
    <div className="relative w-full max-h-[380px] overflow-auto bg-gray-950 rounded-lg border border-gray-800">
      <svg width={W} height={H} className="min-w-full">
        <defs>
          <marker id="subarrow" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <polygon points="0 0, 8 3, 0 6" fill="#4b5563" />
          </marker>
        </defs>
        {subs.map((s: string, i: number) => (
          <line key={`e${i}`} x1={rootX} y1={48} x2={subX(i)} y2={118} stroke="#4b5563" strokeWidth="1" strokeDasharray="4,4" opacity="0.6" markerEnd="url(#subarrow)" />
        ))}
        {subs.map((s: string, i: number) => {
          const info = infoMap.get(s);
          const ips = info?.ips || [];
          return ips.map((ip: string, j: number) => (
            <line key={`ei${i}-${j}`} x1={subX(i)} y1={140} x2={subX(i) + (j - (ips.length - 1) / 2) * 14} y2={210} stroke="#3b82f6" strokeWidth="1" strokeDasharray="2,3" opacity="0.5" />
          ));
        })}
        <g onClick={() => setSelected({ kind: 'root' })} style={{ cursor: 'pointer' }}>
          <circle cx={rootX} cy={36} r={22} fill="#134e4a" stroke="#2dd4bf" strokeWidth={2.5} />
          <text x={rootX} y={41} textAnchor="middle" fontSize="10" fill="#e2e8f0" fontFamily="monospace" fontWeight="bold">
            {data?.domain?.length > 16 ? data.domain.slice(0, 14) + '…' : data?.domain || 'domain'}
          </text>
          <text x={rootX} y={72} textAnchor="middle" fontSize="9" fill="#64748b" fontFamily="monospace">dominio</text>
        </g>
        {subs.map((s: string, i: number) => {
          const info = infoMap.get(s);
          const tb = tbMap.get(s);
          const stroke = tb && tb.status !== 'SAFE' ? (tb.status === 'CANDIDATE' ? '#ef4444' : '#f59e0b') : colorFor(info);
          const color = colorFor(info);
          const label = s.split('.')[0];
          return (
            <g key={s} onClick={() => setSelected({ kind: 'sub', name: s })} style={{ cursor: 'pointer' }}>
              <circle cx={subX(i)} cy={128} r={15} fill="#111827" stroke={stroke} strokeWidth={selected?.name === s ? 3 : 2} />
              <text x={subX(i)} y={132} textAnchor="middle" fontSize="8" fill="#cbd5e1" fontFamily="monospace">{label.length > 9 ? label.slice(0, 8) + '…' : label}</text>
              <text x={subX(i)} y={158} textAnchor="middle" fontSize="8" fill={color} fontFamily="monospace">{info?.ips?.length || 0} IP</text>
            </g>
          );
        })}
        {subs.map((s: string, i: number) => {
          const info = infoMap.get(s);
          const ips = info?.ips || [];
          return ips.map((ip: string, j: number) => (
            <g key={s + ip} onClick={() => setSelected({ kind: 'ip', host: s, ip })} style={{ cursor: 'pointer' }}>
              <rect x={subX(i) + (j - (ips.length - 1) / 2) * 14 - 18} y={203} width={36} height={20} rx={4} fill="#0f172a" stroke="#3b82f6" strokeWidth={1} opacity={0.9} />
              <text x={subX(i) + (j - (ips.length - 1) / 2) * 14} y={216} textAnchor="middle" fontSize="7" fill="#60a5fa" fontFamily="monospace">{ip}</text>
            </g>
          ));
        })}
      </svg>

      {selected && (
        <div className="absolute top-3 left-3 w-80 bg-gray-900 border border-gray-700 rounded-lg p-4 shadow-lg z-10 max-h-[92%] overflow-auto">
          {selected.kind === 'root' && (
            <>
              <div className="flex items-center justify-between mb-3">
                <h4 className="font-semibold text-sm break-all">{data?.domain}</h4>
                <button onClick={() => setSelected(null)} className="text-gray-400 hover:text-white">×</button>
              </div>
              <div className="space-y-2 text-xs">
                <div><span className="text-gray-500">Subdominios:</span> <span className="font-mono ml-2">{data?.subdomains?.length || 0}</span></div>
                <div><span className="text-gray-500">Registros DNS:</span> <span className="font-mono ml-2">{data?.allRecords?.length || 0}</span></div>
                <div><span className="text-gray-500">Takeovers:</span> <span className="font-mono ml-2">{(data?.takeovers || []).filter((t: any) => t.status !== 'SAFE').length}</span></div>
              </div>
            </>
          )}
          {selected.kind === 'sub' && (() => {
            const info = infoMap.get(selected.name);
            const tb = tbMap.get(selected.name);
            return (
              <>
                <div className="flex items-center justify-between mb-3">
                  <h4 className="font-semibold text-sm break-all font-mono">{selected.name}</h4>
                  <button onClick={() => setSelected(null)} className="text-gray-400 hover:text-white">×</button>
                </div>
                <div className="space-y-2 text-xs">
                  {info?.source && <div><span className="text-gray-500">Fuente:</span> <span className="ml-2">{info.source}</span></div>}
                  {info?.firstSeen && <div><span className="text-gray-500">Primera vista:</span> <span className="font-mono ml-2">{info.firstSeen}</span></div>}
                  {info?.lastSeen && <div><span className="text-gray-500">Última vista:</span> <span className="font-mono ml-2">{info.lastSeen}</span></div>}
                  {info?.cname && <div><span className="text-gray-500">CNAME:</span> <span className="font-mono ml-2 break-all">{info.cname}</span></div>}
                  {tb && tb.status !== 'SAFE' && (
                    <div className={`p-2 rounded ${tb.status === 'CANDIDATE' ? 'bg-red-500/20 text-red-300' : 'bg-yellow-500/20 text-yellow-300'}`}>
                      <b>{tb.status}</b> — {tb.reason}
                    </div>
                  )}
                  <div><span className="text-gray-500">IPs resolvidas:</span></div>
                  {(info?.ips || []).map((ip: string, i: number) => (
                    <div key={i} className="font-mono text-cyan-300">{ip} <span className="text-gray-500">{providerFor(selected.name, ip)}</span></div>
                  ))}
                </div>
              </>
            );
          })()}
          {selected.kind === 'ip' && (
            <>
              <div className="flex items-center justify-between mb-3">
                <h4 className="font-semibold text-sm break-all font-mono">{selected.ip}</h4>
                <button onClick={() => setSelected(null)} className="text-gray-400 hover:text-white">×</button>
              </div>
              <div className="space-y-2 text-xs">
                <div><span className="text-gray-500">Host:</span> <span className="font-mono ml-2">{selected.host}</span></div>
                <div><span className="text-gray-500">Proveedor:</span> <span className="ml-2">{providerFor(selected.host, selected.ip) || '—'}</span></div>
              </div>
            </>
          )}
        </div>
      )}
      <div className="absolute bottom-2 left-3 flex flex-wrap gap-2 text-[10px] text-gray-400">
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full inline-block" style={{ background: '#a855f7' }} /> crt.sh</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full inline-block" style={{ background: '#ec4899' }} /> OTX passive DNS</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full inline-block" style={{ background: '#fb923c' }} /> bufferover</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full inline-block" style={{ background: '#60a5fa' }} /> hackertarget</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full inline-block" style={{ background: '#22d3ee' }} /> brute-force</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full inline-block" style={{ background: '#2dd4bf' }} /> múltiples fuentes</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full inline-block" style={{ background: '#ef4444' }} /> takeover candidato</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full inline-block" style={{ background: '#f59e0b' }} /> CNAME colgante</span>
      </div>
      <button onClick={() => setSelected(null)} className="absolute top-2 right-2 p-1.5 bg-gray-800 border border-gray-700 rounded hover:bg-gray-700 text-xs text-gray-400">Limpiar selección</button>
    </div>
  );
}

// force rebuild 08/20/2026 09:06:46
// force rebuild 08/20/2026 09:32:28
