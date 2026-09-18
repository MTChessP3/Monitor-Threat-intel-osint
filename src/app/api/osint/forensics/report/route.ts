// Printable forensic report (HTML, self-contained, print-optimized).
// Client posts the full analysis JSON (always available, KV-independent).

import { NextRequest, NextResponse } from 'next/server';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

function esc(v: unknown): string {
  return String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function renderTree(node: any, depth: number): string {
  if (!node) return '';
  const kids = Array.isArray(node.children) ? node.children.map((c: any) => renderTree(c, depth + 1)).join('') : '';
  const statusClass =
    node.status === 200 ? 's200' : node.status === 403 ? 's403' : node.status >= 300 && node.status < 400 ? 's3xx' : 's404';
  const badges = [
    node.meta?.secrets?.length ? `<span class="badge">${esc(node.meta.secrets.length)} secrets</span>` : '',
    node.meta?.forms > 0 ? `<span class="badge">${esc(node.meta.forms)} forms</span>` : '',
    node.meta?.endpoints?.length ? `<span class="badge">${esc(node.meta.endpoints.length)} endpoints</span>` : '',
    typeof node.meta?.title === 'string' ? `<span class="badge gray">${esc(node.meta.title.slice(0, 60))}</span>` : '',
  ].join('');
  return `<div class="tnode"><details${depth === 0 ? ' open' : ''}><summary>
      <span class="tname">${esc(node.name)}</span>
      <span class="status ${statusClass}">${esc(node.status ?? '—')}</span>
      ${node.size ? `<span class="tsize">${(node.size / 1024).toFixed(1)} KB</span>` : ''}
      ${badges}
    </summary>${kids ? `<div class="tchildren">${kids}</div>` : ''}${node.type === 'script' && node.meta?.secrets?.length ? `<div class="tsecrets">${node.meta.secrets.map((s: string) => `<div>🔑 ${esc(s)}</div>`).join('')}</div>` : ''}
  </details></div>`;
}

function renderStructure(s: any): string {
  if (!s) return '';
  const parts: string[] = [];
  if (s.entries?.length) {
    parts.push(`<h4>📁 Contenido interno (${esc(s.entries.length)} archivos)</h4><div class="filetree">${s.entries.map((e: any) =>
      `<div class="frow"><span>${e.type === 'dir' ? '📁' : '📄'}</span><span class="fname">${esc(e.name)}</span><span class="fsize">${e.size ? (e.size / 1024).toFixed(1) + ' KB' : ''}</span></div>`).join('')}</div>`);
  }
  if (s.tables?.length) {
    parts.push(`<h4>🗄️ Esquema de base de datos (${esc(s.tables.length)} tablas)</h4>`);
    parts.push(`<table class="tbl"><thead><tr><th>Tabla</th><th>Filas</th><th>Columnas</th></tr></thead><tbody>${s.tables.map((t: any) =>
      `<tr><td>${esc(t.name)}</td><td>${esc(t.rows)}</td><td class="mono small">${esc((t.columns || []).join(', '))}</td></tr>`).join('')}</tbody></table>`);
  }
  if (s.keys?.length) {
    parts.push(`<h4>🔐 Claves de configuración (${esc(s.keys.length)})</h4><table class="tbl"><thead><tr><th>Clave</th><th>Valor</th></tr></thead><tbody>${s.keys.map((k: any) =>
      `<tr><td class="mono">${esc(k.key)}</td><td class="mono small">${esc(k.value)}</td></tr>`).join('')}</tbody></table>`);
  }
  if (s.emails?.length) {
    parts.push(`<h4>✉️ Emails encontrados (${esc(s.emails.length)})</h4><div class="chips">${s.emails.map((e: string) => `<span class="chip">${esc(e)}</span>`).join('')}</div>`);
  }
  if (s.urls?.length) {
    parts.push(`<h4>🔗 URLs encontradas (${esc(s.urls.length)})</h4><div class="chips">${s.urls.map((u: string) => `<span class="chip">${esc(u)}</span>`).join('')}</div>`);
  }
  if (s.note && !parts.length) parts.push(`<p class="note">${esc(s.note)}</p>`);
  if (s.note && parts.length) parts.unshift(`<p class="note">${esc(s.note)}</p>`);
  return parts.join('');
}

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
      return NextResponse.json({ success: false, error: 'Analysis data required' }, { status: 400 });
    }

    const riskColor = d.risk?.level === 'CRITICAL' ? '#ef4444' : d.risk?.level === 'HIGH' ? '#f97316' : d.risk?.level === 'MEDIUM' ? '#eab308' : '#22c55e';
    const catColor: Record<string, string> = { phishing_kit: '#ef4444', database: '#f97316', config: '#eab308', backup: '#94a3b8', other: '#6b7280' };
    const fz = d.fuzzingSummary || {};
    const artifacts = Array.isArray(d.artifacts) ? d.artifacts.filter((a: any) => a.downloaded) : [];
    const fuzzRows = (Array.isArray(d.resourceTree?.children) ? d.resourceTree.children : []).filter((n: any) => n.type === 'fuzz' && (n.status === 200 || n.status === 403)).slice(0, 80);
    const att = d.attribution || {};

    const html = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<title>Informe Forense — ${esc(domain)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Roboto, Arial, sans-serif; background: #fff; color: #111; margin: 0; padding: 24px; font-size: 12px; }
  .report { max-width: 900px; margin: 0 auto; }
  h1 { margin: 0 0 4px; font-size: 22px; }
  h2 { font-size: 15px; margin: 24px 0 8px; padding-bottom: 4px; border-bottom: 2px solid #e5e7eb; color: #111827; }
  h3 { font-size: 13px; margin: 12px 0 6px; color: #1f2937; }
  h4 { font-size: 12px; margin: 10px 0 4px; color: #374151; }
  .meta { color: #6b7280; font-size: 11px; }
  .risk { display: inline-block; padding: 4px 12px; border-radius: 6px; color: #fff; font-weight: 700; margin: 8px 0; }
  .scorebar { height: 8px; background: #e5e7eb; border-radius: 4px; overflow: hidden; margin: 6px 0 2px; }
  .scorebar > div { height: 100%; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px; }
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
  .tnode details { margin: 1px 0; }
  .tnode summary { cursor: pointer; display: flex; align-items: center; gap: 8px; padding: 1px 0; font-family: Consolas, monospace; font-size: 11px; }
  .tchildren { border-left: 1px solid #d1d5db; margin-left: 6px; padding-left: 10px; }
  .status { font-weight: 700; }
  .s200 { color: #16a34a; } .s403 { color: #dc2626; } .s3xx { color: #ca8a04; } .s404 { color: #9ca3af; }
  .tsize, .tname { color: #374151; }
  .tsecrets { margin: 2px 0 6px 14px; font-size: 11px; color: #b91c1c; }
  .badge { display: inline-block; background: #fee2e2; color: #b91c1c; border-radius: 4px; padding: 0 5px; font-size: 9px; font-weight: 700; font-family: Arial, sans-serif; }
  .badge.gray { background: #f3f4f6; color: #6b7280; }
  .filetree { border: 1px solid #e5e7eb; border-radius: 6px; padding: 6px 8px; max-height: 260px; overflow: auto; font-family: Consolas, monospace; font-size: 11px; }
  .frow { display: flex; gap: 6px; }
  .fname { flex: 1; color: #374151; } .fsize { color: #9ca3af; }
  .chips { display: flex; flex-wrap: wrap; gap: 4px; }
  .chip { background: #eff6ff; border: 1px solid #bfdbfe; color: #1d4ed8; border-radius: 999px; padding: 2px 8px; font-size: 10px; font-family: Consolas, monospace; }
  .note { color: #6b7280; font-style: italic; margin: 2px 0; }
  .verdict { background: #f9fafb; border-left: 4px solid ${riskColor}; padding: 8px 12px; border-radius: 4px; }
  .footer { margin-top: 28px; padding-top: 8px; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 10px; text-align: center; }
  @media print { .print-btn { display: none; } body { padding: 8px; } .tnode details { break-inside: avoid; } }
  @page { size: A4; margin: 12mm; }
</style>
</head>
<body><div class="report">
  <div class="chrome">
    <div>
      <h1>🔍 Informe Forense — <span class="mono">${esc(domain)}</span></h1>
      <div class="meta">Motor: Advanced Web Forensic Engine v5.2 · ${esc(d.timestamp || '')} · Recurso: ${esc(d.name || '')}</div>
    </div>
    <button class="print-btn" onclick="window.print()">🖨️ Imprimir / Guardar PDF</button>
  </div>

  <div class="risk" style="background:${riskColor}">${esc(d.risk?.level || '—')} (${esc(d.risk?.score ?? 0)}/100)</div>
  <div class="scorebar"><div style="width:${Math.max((d.risk?.score ?? 0), 2)}%; background:${riskColor}"></div></div>
  <div class="verdict"><b>Veredicto:</b> ${esc(d.verdict || 'Sin indicadores críticos')}</div>

  <h2>Captura de pantalla (Live)</h2>
  <div style="text-align:center;padding:8px;border:1px solid #e5e7eb;border-radius:8px;">
    <img src="https://s0.wp.com/mshots/v1/${encodeURIComponent('https://' + domain)}?w=1280&h=720" alt="Live screenshot" style="max-width:100%;border-radius:6px;"/>
    <div class="meta">Fuente: WordPress mshots · Hora local UTC-5</div>
  </div>

  <h2>Infraestructura</h2>
  <div class="grid">
    <div class="card"><b>IP</b><span class="mono">${esc(d.ip || '—')}</span></div>
    <div class="card"><b>ASN</b><span>${esc(d.asn || '—')}</span></div>
    <div class="card"><b>ISP</b><span>${esc(d.isp || '—')}</span></div>
    <div class="card"><b>Geo</b><span>${esc(d.geo ? [d.geo.country, d.geo.region, d.geo.city].filter(Boolean).join(' · ') : '—')}</span></div>
    <div class="card"><b>Servidor</b><span>${esc(d.httpHeaders?.server || '—')}</span></div>
    <div class="card"><b>HTTP</b><span>${esc(d.httpHeaders?.statusCode ?? '—')} · Seg. ${esc(d.httpHeaders?.securityScore ?? '—')}</span></div>
    <div class="card"><b>SSL/TLS</b><span>${esc(d.ssl?.secure ? 'Verificado' : 'No verificado')}</span></div>
    <div class="card"><b>Protocolo SSL</b><span>${esc(d.ssl?.protocol || '—')}</span></div>
    <div class="card"><b>Subdominios</b><span>${esc((d.subdomains || []).length)}</span></div>
    <div class="card"><b>Análisis</b><span>${esc(d.name || '—')}</span></div>
  </div>
  ${d.subdomains?.length ? `<h3>Subdominios</h3><div class="chips">${d.subdomains.slice(0, 50).map((s: string) => `<span class="chip">${esc(s)}</span>`).join('')}</div>` : ''}
  ${d.dns ? `<h3>DNS</h3>` +
    ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'].filter((t) => d.dns[t]?.Answer?.length).map((t) =>
      `<div class="card" style="margin-bottom:4px"><b>${esc(t)}</b><div class="mono small">${d.dns[t].Answer.slice(0, 8).map((a: any) => esc(String(a.data || ''))).join(' · ')}</div></div>`).join('') : ''}

  <h2>HTTP Headers & Seguridad</h2>
  <div class="grid">
    <div class="card"><b>Status Code</b><span>${esc(d.httpHeaders?.statusCode ?? '—')}</span></div>
    <div class="card"><b>Server</b><span>${esc(d.httpHeaders?.server || '—')}</span></div>
    <div class="card"><b>Content-Type</b><span>${esc(d.httpHeaders?.headers?.['content-type'] || '—')}</span></div>
    <div class="card"><b>Powered By</b><span>${esc(d.httpHeaders?.headers?.['x-powered-by'] || '—')}</span></div>
    <div class="card"><b>Security Score</b><span>${esc(d.httpHeaders?.securityScore ?? '—')}</span></div>
  </div>
  ${d.httpHeaders?.securityHeaders ? `<h3>Checklist de security headers</h3><table class="tbl"><thead><tr><th>Header</th><th>Estado</th></tr></thead><tbody>${Object.entries(d.httpHeaders.securityHeaders).map(([h, present]) =>
    `<tr><td class="mono">${esc(h)}</td><td>${present ? '✓ Presente' : '✗ Ausente'}</td></tr>`).join('')}</tbody></table>` : ''}
  ${d.httpHeaders?.headers && Object.keys(d.httpHeaders.headers).length ? `<h3>Headers completos (${esc(Object.keys(d.httpHeaders.headers).length)})</h3><table class="tbl"><thead><tr><th>Header</th><th>Valor</th></tr></thead><tbody>${Object.entries(d.httpHeaders.headers).map(([k, v]) =>
    `<tr><td class="mono">${esc(k)}</td><td class="mono small">${esc(v)}</td></tr>`).join('')}</tbody></table>` : ''}

  ${(() => {
    const redirects: string[] = [];
    const walk = (n: any) => {
      if (n?.redirectChain?.length) {
        let prev = '';
        n.redirectChain.forEach((r: string) => { if (r !== prev) redirects.push(r); prev = r; });
      }
      (n?.children || []).forEach(walk);
    };
    walk(d.resourceTree);
    const uniq = Array.from(new Set(redirects));
    return uniq.length ? `<h2>Cadenas de Redirección</h2><table class="tbl"><thead><tr><th>#</th><th>URL</th></tr></thead><tbody>${uniq.slice(0, 80).map((r: string, i: number) =>
      `<tr><td>${esc(i + 1)}</td><td class="mono small">${esc(r)}</td></tr>`).join('')}</tbody></table>` : '';
  })()}

  <h2>Fuzzing de Directorios (${esc(fz.totalProbed ?? 0)} rutas)</h2>
  <div class="grid">
    <div class="card"><b>Rutas probadas</b><span>${esc(fz.totalProbed ?? 0)}</span></div>
    <div class="card"><b>Expuestas</b><span>${esc(fz.exposed ?? 0)}</span></div>
    <div class="card"><b>Archivos en kits</b><span>${esc(fz.archiveEntries ?? 0)}</span></div>
    <div class="card"><b>Tablas de BD</b><span>${esc(fz.dbTables ?? 0)}</span></div>
    <div class="card"><b>Estado</b><span class="mono small">${Object.entries(fz.byStatus || {}).map(([k, v]) => `${k}:${v}`).join(' · ')}</span></div>
    <div class="card"><b>Categorías</b><span class="mono small">${Object.entries(fz.byCategory || {}).map(([k, v]) => `${k}:${v}`).join(' · ')}</span></div>
  </div>
  ${fuzzRows.length ? `<h3>Rutas sensibles con respuesta (${fuzzRows.length})</h3><table class="tbl"><thead><tr><th>Ruta</th><th>Estado</th><th>Categoría</th><th>Tamaño</th></tr></thead><tbody>${fuzzRows.map((n: any) =>
    `<tr><td class="mono">${esc(n.url || n.name)}</td><td>${esc(n.status)}</td><td>${esc(n.meta?.category || '')}</td><td>${n.size ? (n.size / 1024).toFixed(1) + ' KB' : ''}</td></tr>`).join('')}</tbody></table>` : ''}

  <h2>Evidencia — Artefactos Descargados (${artifacts.length})</h2>
  ${artifacts.length ? artifacts.map((a: any, i: number) => `
    <div style="border:1px solid #e5e7eb;border-left:4px solid ${catColor[a.category] || '#6b7280'};border-radius:6px;padding:8px 12px;margin-bottom:10px;page-break-inside:avoid;">
      <b>${esc(a.category)}</b> · <span class="mono">${esc(a.url)}</span>
      <div class="meta">Tamaño: ${(a.size / 1024).toFixed(1)} KB · SHA-256: ${esc(a.hash || '—')} · ${esc(a.structure?.note || a.kind || '')}</div>
      ${renderStructure(a.structure)}
    </div>`).join('') : '<p class="note">No se descargaron artefactos.</p>'}

  <h2>Resource Tree — Live Crawl</h2>
  <div class="tnode">${renderTree(d.resourceTree, 0)}</div>

  <h2>Atribución de Actor</h2>
  <div class="grid">
    <div class="card"><b>Emails (${esc((att.emails || []).length)})</b><div class="chips">${(att.emails || []).map((e: string) => `<span class="chip">${esc(e)}</span>`).join('') || '<span class="note">ninguno</span>'}</div></div>
    <div class="card"><b>Telegram (${esc((att.telegramIds || []).length)})</b><div class="chips">${(att.telegramIds || []).map((e: string) => `<span class="chip">${esc(e)}</span>`).join('') || '<span class="note">ninguno</span>'}</div></div>
    <div class="card"><b>API Keys / Secrets</b><div class="chips">${(att.apiKeys || []).map((e: string) => `<span class="chip">${esc(e.slice(0, 60))}</span>`).join('') || '<span class="note">ninguno</span>'}</div></div>
    <div class="card"><b>Tracking IDs</b><div class="chips">${(att.trackingIds || []).map((e: string) => `<span class="chip">${esc(e)}</span>`).join('') || '<span class="note">ninguno</span>'}</div></div>
    <div class="card"><b>Firmas de herramienta</b><div class="chips">${(att.toolSignatures || []).map((e: string) => `<span class="chip">${esc(e)}</span>`).join('') || '<span class="note">ninguna</span>'}</div></div>
    <div class="card"><b>Comentarios / strings</b><div class="mono small">${(att.comments || []).map((e: string) => `${esc(e.slice(0, 80))}<br/>`).join('') || '<span class="note">ninguno</span>'}</div></div>
  </div>
  ${(att.links || []).length ? `<h3>Links externos detectados (${esc(att.links.length)})</h3><table class="tbl"><thead><tr><th>URL</th></tr></thead><tbody>${att.links.slice(0, 50).map((l: string) => `<tr><td class="mono small">${esc(l)}</td></tr>`).join('')}</tbody></table>` : ''}
  ${d.virusTotal ? `<h2>VirusTotal</h2><div class="grid"><div class="card"><b>Reputación</b><span>${esc(d.virusTotal.reputation ?? '—')}</span></div><div class="card"><b>Veredicto</b><span>${esc(d.virusTotal.verdict || '—')}</span></div><div class="card"><b>Malicious</b><span>${esc(d.virusTotal.lastAnalysisStats?.malicious ?? 0)}</span></div><div class="card"><b>Suspicious</b><span>${esc(d.virusTotal.lastAnalysisStats?.suspicious ?? 0)}</span></div><div class="card"><b>Harmless</b><span>${esc(d.virusTotal.lastAnalysisStats?.harmless ?? 0)}</span></div><div class="card"><b>Engines</b><span>${esc(d.virusTotal.totalEngines ?? 0)}</span></div></div>` : ''}

  <div class="footer">NEXUS OSINT — Advanced Web Forensic Engine v5.2 · Generado ${esc(new Date().toISOString())} · Informe forense automatizado</div>
</div></body>
</html>`;

    const safeDomain = String(domain).replace(/[^a-zA-Z0-9._-]/g, '_');
    return new NextResponse(html, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `attachment; filename="informe_forense_${safeDomain}.html"`,
      },
    });
  } catch (error) {
    return NextResponse.json({ success: false, error: error instanceof Error ? error.message : 'Report failed' }, { status: 500 });
  }
}