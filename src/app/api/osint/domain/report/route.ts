// Printable domain intelligence report (HTML, self-contained, print-optimized).
// Uses the same architecture as the forensics report route.

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
    const domain = String(body?.domain || d?.domain || 'target');
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

    const buildDnsRecords = (records: any) => {
      if (!records) return '';
      const types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];
      return types.map(type => {
        const recs = records[type as keyof typeof records] || [];
        if (recs.length === 0) return '';
        return `<div class="data-card"><div class="data-label">${type} Records (${recs.length})</div><div class="data-value">${recs.slice(0, 5).map(r => esc(r.data || r.value || '')).join('<br>')}${recs.length > 5 ? `<br>... and ${recs.length - 5} more` : ''}</div></div>`;
      }).join('');
    };

    const buildSubdomains = (subs: any[]) => {
      if (!subs || subs.length === 0) return '';
      return subs.slice(0, 20).map(s =>
        `<div class="data-card"><div class="data-label">${esc(s.name)}</div><div class="data-value">${s.ips.length > 0 ? s.ips.join(', ') : (s.cname ? `CNAME: ${s.cname}` : 'No A record')}</div></div>`
      ).join('');
    };

    const buildIpAsn = (ips: any[]) => {
      if (!ips || ips.length === 0) return '';
      return ips.slice(0, 15).map(ip =>
        `<div class="data-card"><div class="data-label">${ip.ip}</div><div class="data-value">Geo: ${ip.country} ${ip.city ? `(${ip.city})` : ''}</div><div class="data-label">ASN: ${ip.asn || '—'}</div><div class="data-value">${ip.asname || ''}</div></div>`
      ).join('');
    };

    const buildEmailSecurity = (es: any) => {
      if (!es) return '';
      return `<div class="data-grid"><div class="data-card"><div class="data-label">SPF</div><div class="data-value">${es.hasSPF ? 'Present' : 'Missing'}</div></div><div class="data-card"><div class="data-label">DMARC</div><div class="data-value">${es.hasDMARC ? 'Present' : 'Missing'}</div></div><div class="data-card"><div class="data-label">DKIM</div><div class="data-value">${es.hasDKIM ? 'Present' : 'Missing'}</div></div><div class="data-card"><div class="data-label">Risk Level</div><div class="data-value">${es.riskLevel}</div></div></div>`;
    };

    const buildWhois = (whois: any) => {
      if (!whois) return '';
      return `<div class="data-grid"><div class="data-card"><div class="data-label">Registrar</div><div class="data-value">${esc(whois.registrar || '—')}</div></div><div class="data-card"><div class="data-label">Created</div><div class="data-value">${formatDate(whois.created)}</div></div><div class="data-card"><div class="data-label">Expires</div><div class="data-value">${formatDate(whois.expires)}</div></div><div class="data-card"><div class="data-label">Registrant</div><div class="data-value">${esc(whois.registrantOrg || '—')}</div></div><div class="data-card"><div class="data-label">Country</div><div class="data-value">${esc(whois.registrantCountry || '—')}</div></div></div>`;
    };

    const vtSection = d.virusTotal ? `
      <div class="section"><div class="section-title">🛡️ VirusTotal Analysis</div>
        <div class="data-grid">
          <div class="data-card"><div class="data-label">Verdict</div><div class="data-value"><span class="badge ${getRiskClass(d.virusTotal.verdict)}">${esc(d.virusTotal.verdict)}</span></div></div>
          <div class="data-card"><div class="data-label">Reputation</div><div class="data-value">${d.virusTotal.reputation}</div></div>
          <div class="data-card"><div class="data-label">Malicious</div><div class="data-value">${d.virusTotal.lastAnalysisStats?.malicious || 0}</div></div>
          <div class="data-card"><div class="data-label">Suspicious</div><div class="data-value">${d.virusTotal.lastAnalysisStats?.suspicious || 0}</div></div>
        </div>
      </div>` : '';

    const html = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Informe de Inteligencia de Dominio — ${esc(domain)}</title>
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
    <div class="title">Informe de Inteligencia de Dominio: ${esc(domain)}</div>
    <div class="subtitle">Plataforma de Inteligencia de Amenazas y Protección Ejecutiva</div>
    <div class="meta">
      <span>📅 Generado: ${new Date(timestamp).toLocaleString('es-ES', { dateStyle: 'full', timeStyle: 'short' })}</span>
      <span>🎯 Objetivo: ${esc(domain)}</span>
      <span>🔍 Módulo: Domain Intel</span>
    </div>
  </div>

  <div class="risk-banner">${esc(d.risk?.level || 'N/A')} (${riskScore}/100)</div>
  <div class="scorebar"><div></div></div>

  <div class="section">
    <div class="section-title">📋 Resumen Ejecutivo</div>
    <div class="data-grid">
      <div class="data-card"><div class="data-label">Módulo</div><div class="data-value">Domain Intel</div></div>
      <div class="data-card"><div class="data-label">Fecha/Hora (UTC)</div><div class="data-value">${timestamp}</div></div>
      <div class="data-card"><div class="data-label">Objetivo Analizado</div><div class="data-value mono">${esc(domain)}</div></div>
      <div class="data-card"><div class="data-label">Fuente</div><div class="data-value">${esc(d.source || 'NEXUS-INTEL OSINT Platform')}</div></div>
      <div class="data-card"><div class="data-label">VirusTotal</div><div class="data-value">${d.virusTotal?.analyzed ? 'Analyzed' : 'Not analyzed'}</div></div>
    </div>
  </div>

  ${d.records ? `<div class="section"><div class="section-title">📡 DNS Records</div>${buildDnsRecords(d.records)}</div>` : ''}
  ${d.subdomains?.length ? `<div class="section"><div class="section-title">🌐 Subdominios (${d.subdomains.length})</div>${buildSubdomains(d.subdomains)}</div>` : ''}
  ${d.ips?.length ? `<div class="section"><div class="section-title">📍 IP & ASN Infrastructure</div>${buildIpAsn(d.ips)}</div>` : ''}
  ${d.emailSecurity ? `<div class="section"><div class="section-title">📧 Email Security</div>${buildEmailSecurity(d.emailSecurity)}</div>` : ''}
  ${d.whois ? `<div class="section"><div class="section-title">🔍 WHOIS / Registration</div>${buildWhois(d.whois)}</div>` : ''}
  ${vtSection}

  <div class="footer">
    <p>Generado por NEXUS-INTEL — Plataforma de Inteligencia de Amenazas y Protección Ejecutiva</p>
    <p>Este informe se generó automáticamente. Verifique los datos antes de tomar decisiones operacionales.</p>
    <p>Fuente: ${esc(d.source || 'NEXUS-INTEL')} · Clasificación: CLASIFICADO</p>
  </div>
</div>
<script>window.onload = () => { window.print(); }</script>
</body>
</html>`;

    const safeDomain = domain.replace(/[^a-zA-Z0-9._-]/g, '_');
    return new NextResponse(html, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `attachment; filename="informe_domain_${safeDomain}.html"`,
      },
    });
  } catch (error) {
    return NextResponse.json({ success: false, error: error instanceof Error ? error.message : 'Report failed' }, { status: 500 });
  }
}
