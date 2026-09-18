// Printable IP intelligence report (HTML, self-contained, print-optimized).

import { NextRequest, NextResponse } from 'next/server';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

function esc(v: unknown): string {
  return String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { error: moduleError } = resolveModuleScope(request, body);
    if (moduleError) {
      return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
    }
    const d = body?.data || body;
    const ip = String(body?.ip || d?.ip || d?.data?.query || d?.data?.ip || 'target');
    if (!d) {
      return NextResponse.json({ success: false, error: 'Analysis data required' }, { status: 400 });
    }

    const riskColor = d.risk?.level === 'CRITICAL' ? '#ef4444' : d.risk?.level === 'HIGH' ? '#f97316' : d.risk?.level === 'MEDIUM' ? '#eab308' : '#22c55e';
    const riskScore = d.risk?.score ?? 0;
    const timestamp = new Date().toISOString();

    const formatDate = (iso: string | null) => {
      if (!iso) return '—';
      const dt = new Date(iso);
      return Number.isNaN(dt.getTime()) ? iso : dt.toISOString().slice(0, 10);
    };

    const getRiskClass = (level: string) => {
      switch (level.toUpperCase()) {
        case 'CRITICAL': return 'badge-critical';
        case 'HIGH': return 'badge-elevated';
        default: return 'badge-normal';
      }
    };

    const vt = d.reputation?.virusTotal || d.virusTotal || null;
    const reputation = d.reputation || {};
    const scan = d.scan || {};
    const rdap = d.data?.rdap || null;
    const http = d.data?.http || null;
    const tls = d.data?.tls || null;
    const content = d.data?.content || null;
    const redirects = d.data?.redirects || [];
    const staticFlags = d.data?.staticFlags || [];
    const verdict = d.analysis?.threatLevel || 'NORMAL';
    const recommendations = d.analysis?.recommendations || [];

    const buildVT = () => {
      if (!vt || !vt.analyzed) return '';
      const stats = vt.lastAnalysisStats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 };
      const total = vt.totalEngines || Object.values(stats).reduce((a: number, b: number) => a + b, 0);
      return `<div class="section"><div class="section-title">🛡️ VirusTotal Analysis</div>
        <div class="data-grid">
          <div class="data-card"><div class="data-label">Verdict</div><div class="data-value"><span class="badge ${getRiskClass(vt.verdict)}">${esc(vt.verdict)}</span></div></div>
          <div class="data-card"><div class="data-label">Detection</div><div class="data-value">${stats.malicious}/${total} engines</div></div>
          <div class="data-card"><div class="data-label">Reputation</div><div class="data-value">${vt.reputation}</div></div>
          <div class="data-card"><div class="data-label">Last Analysis</div><div class="data-value">${vt.lastAnalysisDate ? formatDate(vt.lastAnalysisDate) : 'N/A'}</div></div>
        </div></div>`;
    };

    const buildReputation = () => {
      if (!reputation || Object.keys(reputation).length === 0) return '';
      return `<div class="section"><div class="section-title">🎯 Reputation & Infrastructure</div>
        <div class="data-grid">
          <div class="data-card"><div class="data-label">IP</div><div class="data-value">${esc(reputation.ip || '—')}</div></div>
          <div class="data-card"><div class="data-label">Geo</div><div class="data-value">${esc(reputation.geo || '—')}</div></div>
          <div class="data-card"><div class="data-label">ASN</div><div class="data-value">${esc(reputation.asn || '—')}</div></div>
          <div class="data-card"><div class="data-label">ISP</div><div class="data-value">${esc(reputation.isp || '—')}</div></div>
          <div class="data-card"><div class="data-label">DNSBL Listed</div><div class="data-value">${reputation.dnsblListed || 0}</div></div>
          <div class="data-card"><div class="data-label">Tor Exit</div><div class="data-value">${reputation.torExit ? 'Yes' : 'No'}</div></div>
          <div class="data-card"><div class="data-label">URLhaus Count</div><div class="data-value">${reputation.urlhausCount || 0}</div></div>
          <div class="data-card"><div class="data-label">Hosting</div><div class="data-value">${reputation.hosting ? 'Yes' : 'No'}</div></div>
          <div class="data-card"><div class="data-label">Proxy</div><div class="data-value">${reputation.proxy ? 'Yes' : 'No'}</div></div>
        </div></div>`;
    };

    const buildScan = () => {
      if (!scan || Object.keys(scan).length === 0) return '';
      const openPorts = scan.ports?.filter((p: any) => p.state === 'open') || [];
      return `<div class="section"><div class="section-title">🔍 Port Scan Results</div>
        <div class="data-grid">
          <div class="data-card"><div class="data-label">OS Fingerprint</div><div class="data-value">${esc(scan.os || 'Unknown')}</div></div>
          <div class="data-card"><div class="data-label">Open Ports</div><div class="data-value">${openPorts.length}</div></div>
        </div>
        ${openPorts.length > 0 ? `<div class="section">${openPorts.map((p: any) => `<div class="data-card"><div class="data-label">Port ${p.port}</div><div class="data-value">${p.service} (${p.state})</div><div class="data-label">Banner: ${esc(p.banner || '—')}</div></div>`).join('')}</div>` : ''}
      </div>`;
    };

    const buildRdap = () => {
      if (!rdap) return '';
      return `<div class="section"><div class="section-title">📋 RDAP / WHOIS</div>
        <div class="data-grid">
          <div class="data-card"><div class="data-label">Handle</div><div class="data-value">${esc(rdap.handle || '—')}</div></div>
          <div class="data-card"><div class="data-label">Name</div><div class="data-value">${esc(rdap.name || '—')}</div></div>
          <div class="data-card"><div class="data-label">Country</div><div class="data-value">${esc(rdap.country || '—')}</div></div>
          <div class="data-card"><div class="data-label">Entities</div><div class="data-value">${rdap.entities?.join(', ') || 'N/A'}</div></div>
        </div></div>`;
    };

    const buildHttp = () => {
      if (!http) return '';
      return `<div class="section"><div class="section-title">🌐 HTTP Fingerprint</div>
        <div class="data-grid">
          <div class="data-card"><div class="data-label">Final URL</div><div class="data-value">${esc(http.finalUrl || '—')}</div></div>
          <div class="data-card"><div class="data-label">Status</div><div class="data-value">${http.status} ${http.statusText}</div></div>
          <div class="data-card"><div class="data-label">Protocol</div><div class="data-value">${esc(http.protocol)}</div></div>
          <div class="data-card"><div class="data-label">Server</div><div class="data-value">${esc(http.server || '—')}</div></div>
          <div class="data-card"><div class="data-label">TTFB</div><div class="data-value">${http.timings?.ttfbMs} ms</div></div>
          <div class="data-card"><div class="data-label">Total</div><div class="data-value">${http.timings?.totalMs} ms</div></div>
        </div></div>`;
    };

    const buildTls = () => {
      if (!tls) return '';
      return `<div class="section"><div class="section-title">🔒 TLS Certificate</div>
        <div class="data-grid">
          <div class="data-card"><div class="data-label">Protocol</div><div class="data-value">${esc(tls.protocol)}</div></div>
          <div class="data-card"><div class="data-label">Cipher</div><div class="data-value">${esc(tls.cipher)}</div></div>
          <div class="data-card"><div class="data-label">Subject CN</div><div class="data-value">${esc(tls.subjectCn || 'N/A')}</div></div>
          <div class="data-card"><div class="data-label">Issuer CN</div><div class="data-value">${esc(tls.issuerCn || 'N/A')}</div></div>
          <div class="data-card"><div class="data-label">Valid From</div><div class="data-value">${formatDate(tls.validFrom)}</div></div>
          <div class="data-card"><div class="data-label">Valid To</div><div class="data-value">${formatDate(tls.validTo)}</div></div>
          <div class="data-card"><div class="data-label">Status</div><div class="data-value">${tls.expired ? 'EXPIRED' : tls.selfSigned ? 'SELF-SIGNED' : tls.hostnameMismatch ? 'MISMATCH' : 'VALID'}</div></div>
        </div></div>`;
    };

    const buildStaticFlags = () => {
      if (!staticFlags || staticFlags.length === 0) return '';
      return `<div class="section"><div class="section-title">🚩 Static Flags</div>
        <div class="data-grid">${staticFlags.map((f: any) => `<div class="data-card"><div class="data-label">${esc(f.label)}</div><div class="data-value">Weight: ${f.weight} · Category: ${esc(f.category)}</div></div>`).join('')}</div></div>`;
    };

    const buildRecommendations = () => {
      if (!recommendations || recommendations.length === 0) return '';
      return `<div class="section"><div class="section-title">🛡️ Recommendations</div><ol>${recommendations.map(r => `<li>${esc(r)}</li>`).join('')}</ol></div>`;
    };

    const html = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Informe de Inteligencia IP — ${esc(ip)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; margin: 0; padding: 24px; background: #fff; color: #1f2937; line-height: 1.6; font-size: 12px; }
  .report { max-width: 900px; margin: 0 auto; }
  .header { border-bottom: 3px solid #059669; padding-bottom: 20px; margin-bottom: 30px; text-align: center; }
  .logo { font-size: 24px; font-weight: 800; color: #059669; margin-bottom: 8px; }
  .title { font-size: 26px; font-weight: 700; color: #111827; margin-bottom: 4px; }
  .subtitle { color: #6b7280; font-size: 13px; margin-bottom: 16px; }
  .meta { display: flex; justify-content: center; gap: 20px; flex-wrap: wrap; font-size: 12px; color: #6b7280; }
  .risk-banner { display: inline-block; padding: 8px 20px; border-radius: 8px; color: #fff; font-weight: 700; font-size: 13px; margin: 12px 0; background: ${riskColor}; }
  .scorebar { height: 10px; background: #e5e7eb; border-radius: 5px; overflow: hidden; margin: 8px 0; max-width: 300px; margin-left: auto; margin-right: auto; }
  .scorebar > div { height: 100%; background: ${riskColor}; width: ${Math.max(riskScore, 2)}%; }
  .section { margin-bottom: 28px; page-break-inside: avoid; }
  .section-title { font-size: 16px; font-weight: 700; color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; margin-bottom: 16px; }
  .data-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px; }
  .data-card { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px 16px; page-break-inside: avoid; }
  .data-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: #6b7280; margin-bottom: 4px; font-weight: 600; }
  .data-value { font-weight: 600; color: #111827; word-break: break-word; font-size: 12px; }
  .mono { font-family: 'Cascadia Code', Consolas, monospace; font-size: 11px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
  .badge-normal { background: #dcfce7; color: #166534; }
  .badge-elevated { background: #fef3c7; color: #92400e; }
  .badge-critical { background: #fee2e2; color: #991b1b; }
  .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; text-align: center; font-size: 10px; color: #9ca3af; }
  .print-btn { position: fixed; top: 20px; right: 20px; background: #1f2937; color: #fff; border: 0; border-radius: 6px; padding: 10px 18px; font-size: 13px; cursor: pointer; z-index: 1000; }
  .print-btn:hover { background: #374151; }
  @media print { .print-btn { display: none; } body { padding: 0; } }
  @page { size: A4; margin: 15mm; }
</style>
</head>
<body>
<div class="report">
  <button class="print-btn" onclick="window.print()">🖨️ Imprimir / Guardar como PDF</button>

  <div class="header">
    <div class="logo">🛡️ NEXUS-INTEL</div>
    <div class="title">Informe de Inteligencia IP: ${esc(ip)}</div>
    <div class="subtitle">Plataforma de Inteligencia de Amenazas y Protección Ejecutiva</div>
    <div class="meta">
      <span>📅 Generado: ${new Date(timestamp).toLocaleString('es-ES', { dateStyle: 'full', timeStyle: 'short' })}</span>
      <span>🎯 Objetivo: ${esc(ip)}</span>
      <span>🔍 Módulo: IP Intel</span>
    </div>
  </div>

  <div class="risk-banner">${esc(verdict)} (${riskScore}/100)</div>
  <div class="scorebar"><div></div></div>

  <div class="section">
    <div class="section-title">📋 Resumen Ejecutivo</div>
    <div class="data-grid">
      <div class="data-card"><div class="data-label">Módulo</div><div class="data-value">IP Intel</div></div>
      <div class="data-card"><div class="data-label">Fecha/Hora (UTC)</div><div class="data-value">${timestamp}</div></div>
      <div class="data-card"><div class="data-label">Objetivo Analizado</div><div class="data-value mono">${esc(ip)}</div></div>
      <div class="data-card"><div class="data-label">Fuente</div><div class="data-value">${esc(d.source || 'NEXUS-INTEL OSINT Platform')}</div></div>
      <div class="data-card"><div class="data-label">Live</div><div class="data-value">${d.fetchedLive ? 'Yes' : 'No'}</div></div>
    </div>
  </div>

  ${buildReputation()}
  ${buildScan()}
  ${buildVT()}
  ${buildRdap()}
  ${buildHttp()}
  ${buildTls()}
  ${buildStaticFlags()}
  ${buildRecommendations()}

  <div class="footer">
    <p>Generado por NEXUS-INTEL — Plataforma de Inteligencia de Amenazas y Protección Ejecutiva</p>
    <p>Este informe se generó automáticamente. Verifique los datos antes de tomar decisiones operacionales.</p>
    <p>Fuente: ${esc(d.source || 'NEXUS-INTEL')} · Clasificación: CLASIFICADO</p>
  </div>
</div>
<script>window.onload = () => { window.print(); }</script>
</body>
</html>`;

    const safeIp = ip.replace(/[^a-zA-Z0-9._:]/g, '_');
    return new NextResponse(html, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `attachment; filename="informe_ip_${safeIp}.html"`,
      },
    });
  } catch (error) {
    return NextResponse.json({ success: false, error: error instanceof Error ? error.message : 'Report failed' }, { status: 500 });
  }
}
