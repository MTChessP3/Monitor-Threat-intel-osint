// Printable DNS Dump report (HTML, self-contained, print-optimized).
// Client posts the full DNS dump JSON (always available, KV-independent).

import { NextRequest, NextResponse } from 'next/server';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

function esc(v: unknown): string {
  return String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const TAKEOVER_COLOR: Record<string, string> = {
  CANDIDATE: '#dc2626',
  DANGLING: '#f59e0b',
  SAFE: '#16a34a',
};

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { error: moduleError } = resolveModuleScope(request, body);
    if (moduleError) {
      return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
    }
    const d = body?.data;
    const domain = String(body?.domain || d?.domain || 'target');
    if (!d) {
      return NextResponse.json({ success: false, error: 'DNS dump data required' }, { status: 400 });
    }

    const records = Array.isArray(d.allRecords) ? d.allRecords : [];
    const byType = d.records && typeof d.records === 'object' ? d.records : {};
    const subInfo = Array.isArray(d.subdomainInfo) ? d.subdomainInfo : [];
    const ipMap = Array.isArray(d.ipMap) ? d.ipMap : [];
    const passiveDns = Array.isArray(d.passiveDns) ? d.passiveDns : [];
    const takeovers = Array.isArray(d.takeovers) ? d.takeovers : [];
    const sourceBreakdown = d.sourceBreakdown || {};
    const sb = (d.sourceBreakdown || {}) as Record<string, any>;
    const recordsByType = Object.entries(byType)
      .map(([type, recs]) => ({ type, recs: (recs as any[]) || [] }))
      .filter((t) => t.recs.length > 0)
      .sort((a, b) => b.recs.length - a.recs.length);
    const uniqueIps = Array.from(new Set(ipMap.map((m: any) => m.ip))).length;
    const providers = Array.from(new Set(ipMap.map((m: any) => m.isp || m.provider || '—').filter((p: string) => p !== '—'))).length;
    const candidates = takeovers.filter((t: any) => t.status === 'CANDIDATE' || t.status === 'DANGLING').length;
    const whois = d.whois || null;
    const security = d.security || null;
    const secRows = security && typeof security === 'object' ? Object.entries(security) : [];
    const sourceChips = [
      ['CT (crt.sh)', sb.ct],
      ['OTX passive DNS', sb.otx],
      ['BufferOver', sb.buffer],
      ['Hackertarget', sb.hackertarget],
      ['Brute-force', sb.brute],
    ].filter(([, n]) => Number(n) > 0);

    const html = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<title>DNS Dump — ${esc(domain)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Roboto, Arial, sans-serif; background: #fff; color: #111; margin: 0; padding: 24px; font-size: 12px; }
  .report { max-width: 900px; margin: 0 auto; }
  h1 { margin: 0 0 4px; font-size: 22px; }
  h2 { font-size: 15px; margin: 24px 0 8px; padding-bottom: 4px; border-bottom: 2px solid #e5e7eb; color: #111827; }
  h3 { font-size: 13px; margin: 12px 0 6px; color: #1f2937; }
  .meta { color: #6b7280; font-size: 11px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 8px; }
  .card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 8px 10px; }
  .card b { display: block; color: #6b7280; font-size: 10px; text-transform: uppercase; letter-spacing: .04em; }
  .card span { font-size: 12px; word-break: break-all; }
  table.tbl { width: 100%; border-collapse: collapse; margin: 4px 0 8px; }
  .tbl th, .tbl td { border: 1px solid #e5e7eb; padding: 4px 8px; text-align: left; font-size: 11px; }
  .tbl th { background: #f9fafb; }
  .mono { font-family: 'Cascadia Code', Consolas, monospace; }
  .small { font-size: 10px; color: #4b5563; }
  .chrome { display: flex; justify-content: space-between; align-items: center; }
  .print-btn { background: #1f2937; color: #fff; border: 0; border-radius: 6px; padding: 8px 14px; font-size: 12px; cursor: pointer; }
  .chips { display: flex; flex-wrap: wrap; gap: 4px; }
  .chip { background: #eff6ff; border: 1px solid #bfdbfe; color: #1d4ed8; border-radius: 999px; padding: 2px 8px; font-size: 10px; font-family: Consolas, monospace; word-break: break-all; }
  .chip.gray { background: #f3f4f6; border-color: #e5e7eb; color: #6b7280; }
  .chip.red { background: #fee2e2; border-color: #fecaca; color: #b91c1c; }
  .chip.green { background: #dcfce7; border-color: #bbf7d0; color: #15803d; }
  .take { border: 1px solid #e5e7eb; border-left: 4px solid #6b7280; border-radius: 6px; padding: 8px 12px; margin-bottom: 8px; page-break-inside: avoid; }
  .badge { display: inline-block; border-radius: 4px; padding: 0 6px; font-size: 10px; font-weight: 700; color: #fff; }
  .note { color: #6b7280; font-style: italic; margin: 2px 0; }
  .footer { margin-top: 28px; padding-top: 8px; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 10px; text-align: center; }
  @media print { .print-btn { display: none; } body { padding: 8px; } tr, .take { break-inside: avoid; } }
  @page { size: A4 landscape; margin: 10mm; }
</style>
</head>
<body><div class="report">
  <div class="chrome">
    <div>
      <h1>🌐 DNS Dump — <span class="mono">${esc(domain)}</span></h1>
      <div class="meta">Monitor-Threat DNS Dumpster (Google DoH + crt.sh + RDAP) · Generado ${esc(d.timestamp || new Date().toISOString())}</div>
    </div>
    <button class="print-btn" onclick="window.print()">🖨️ Imprimir / Guardar PDF</button>
  </div>

  <h2>Resumen</h2>
  <div class="grid">
    <div class="card"><b>Registros DNS</b><span>${esc(records.length)}</span></div>
    <div class="card"><b>Subdominios</b><span>${esc(subInfo.length)}</span></div>
    <div class="card"><b>IPs únicas</b><span>${esc(uniqueIps)}</span></div>
    <div class="card"><b>Proveedores</b><span>${esc(providers)}</span></div>
    <div class="card"><b>Takeovers</b><span>${esc(candidates)}</span></div>
    <div class="card"><b>Eventos passive DNS</b><span>${esc(passiveDns.length)}</span></div>
  </div>
  ${sourceChips.length ? `<h3>Subdominios por fuente</h3><div class="chips">${sourceChips.map(([label, n]) => `<span class="chip">${esc(label)}: ${esc(n)}</span>`).join('')}</div>` : ''}

  <h2>Registros DNS (${esc(records.length)})</h2>
  ${recordsByType.map(({ type, recs }) => `
    <h3>${esc(type)} (${esc(recs.length)})</h3>
    <table class="tbl"><thead><tr><th>Nombre</th><th>TTL</th><th>Datos</th></tr></thead><tbody>${recs.map((r: any) => `
      <tr><td class="mono">${esc(r.name)}</td><td>${esc(r.ttl ?? 0)}</td><td class="mono small">${esc(r.data)}</td></tr>`).join('')}</tbody></table>`).join('') || '<p class="note">Sin registros DNS encontrados.</p>'}

  <h2>Mapa IP → Proveedor (${esc(ipMap.length)})</h2>
  ${ipMap.length ? `<table class="tbl"><thead><tr><th>Host</th><th>IP</th><th>ASN</th><th>ISP</th><th>Organización</th><th>País</th></tr></thead><tbody>${ipMap.map((m: any) => `
    <tr><td class="mono">${esc(m.host)}</td><td class="mono">${esc(m.ip)}</td><td class="mono">${esc(m.asn || '—')}</td><td>${esc(m.isp || '—')}</td><td>${esc(m.org || '—')}</td><td>${esc(m.country || '—')}</td></tr>`).join('')}</tbody></table>` : '<p class="note">Sin IPs resueltas.</p>'}

  <h2>Subdominios (${esc(subInfo.length)})</h2>
  ${subInfo.length ? `<table class="tbl"><thead><tr><th>Subdominio</th><th>Fuente</th><th>IPs</th><th>CNAME</th><th>Primera vez</th><th>Última vez</th></tr></thead><tbody>${subInfo.map((s: any) => `
    <tr><td class="mono">${esc(s.name)}</td><td class="small">${esc(s.source || '')}</td><td class="mono small">${esc((s.ips || []).join(', ') || '—')}</td><td class="mono small">${esc(s.cname || '—')}</td><td>${esc((s.firstSeen || '').slice(0, 10) || '—')}</td><td>${esc((s.lastSeen || '').slice(0, 10) || '—')}</td></tr>`).join('')}</tbody></table>` : '<p class="note">Sin subdominios descubiertos.</p>'}

  <h2>Línea temporal Passive DNS (${esc(passiveDns.length)})</h2>
  ${passiveDns.length ? `<table class="tbl"><thead><tr><th>Host</th><th>Primera vez</th><th>Última vez</th><th>Días conocido</th></tr></thead><tbody>${passiveDns.map((p: any) => `
    <tr><td class="mono">${esc(p.name)}</td><td>${esc((p.firstSeen || '').slice(0, 10))}</td><td>${esc((p.lastSeen || '').slice(0, 10))}</td><td>${esc(p.daysKnown ?? '—')}</td></tr>`).join('')}</tbody></table>` : '<p class="note">Sin historial passive DNS.</p>'}

  <h2>Subdomain Takeover (${esc(takeovers.length)})</h2>
  ${takeovers.length ? takeovers.map((t: any) => `
    <div class="take" style="border-left-color:${TAKEOVER_COLOR[t.status] || '#6b7280'}">
      <b>${esc(t.subdomain)}</b> <span class="badge" style="background:${TAKEOVER_COLOR[t.status] || '#6b7280'}">${esc(t.status)}</span>
      ${t.service ? ` · <span class="mono small">${esc(t.service)}</span>` : ''}
      <div class="mono small">CNAME: ${esc(t.cname) || '—'}</div>
      <div class="small">${esc(t.reason || '')}</div>
    </div>`).join('') : '<p class="note">No se detectaron candidatos a subdomain takeover.</p>'}

  ${whois && (whois.registrar || whois.created || whois.expires || (whois.nameservers || []).length) ? `
  <h2>WHOIS</h2>
  <div class="grid">
    <div class="card"><b>Registrador</b><span>${esc(whois.registrar || '—')}</span></div>
    <div class="card"><b>Creado</b><span>${esc((whois.created || '—').slice(0, 10))}</span></div>
    <div class="card"><b>Expira</b><span>${esc((whois.expires || '—').slice(0, 10))}</span></div>
    <div class="card"><b>Nameservers (${esc((whois.nameservers || []).length)})</b><div class="chips" style="margin-top:4px">${(whois.nameservers || []).map((n: string) => `<span class="chip gray">${esc(n)}</span>`).join('') || '<span class="note">—</span>'}</div></div>
    ${(whois.status || []).length ? `<div class="card"><b>Estado</b><div class="chips" style="margin-top:4px">${whois.status.map((s: string) => `<span class="chip gray">${esc(s)}</span>`).join('')}</div></div>` : ''}
  </div>` : ''}

  ${secRows.length ? `
  <h2>Seguridad de email/DNS (${esc(secRows.length)})</h2>
  <table class="tbl"><thead><tr><th>Chequeo</th><th>Resultado</th></tr></thead><tbody>${secRows.map(([k, v]: any) => `
    <tr><td class="mono">${esc(k)}</td><td>${typeof v === 'boolean' ? (v ? '<span class="chip green">OK</span>' : '<span class="chip red">FALLO</span>') : esc(v)}</td></tr>`).join('')}</tbody></table>` : ''}

  ${Array.isArray(d.relatedHosts) && d.relatedHosts.length ? `
  <h2>Hosts relacionados (${esc(d.relatedHosts.length)})</h2>
  <div class="chips">${d.relatedHosts.map((h: string) => `<span class="chip">${esc(h)}</span>`).join('')}</div>` : ''}

  <div class="footer">NEXUS OSINT — Monitor-Threat DNS Dumpster · Generado ${esc(new Date().toISOString())} · Informe automatizado de enumeración DNS</div>
</div></body>
</html>`;

    const safeDomain = String(domain).replace(/[^a-zA-Z0-9._-]/g, '_');
    return new NextResponse(html, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `attachment; filename="informe_dnsdump_${safeDomain}.html"`,
      },
    });
  } catch (error) {
    return NextResponse.json({ success: false, error: error instanceof Error ? error.message : 'Report failed' }, { status: 500 });
  }
}