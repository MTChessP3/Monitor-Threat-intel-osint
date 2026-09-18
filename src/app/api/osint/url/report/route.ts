// Printable URL Scanner report (HTML, self-contained, print-optimized).
// Client posts the full URL scan JSON (always available, KV-independent).

import { NextRequest, NextResponse } from 'next/server';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

function esc(v: unknown): string {
  return String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const LEVEL_COLOR: Record<string, string> = {
  MALICIOUS: '#dc2626',
  SUSPICIOUS: '#d97706',
  BENIGN: '#16a34a',
};

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { error: moduleError } = resolveModuleScope(request, body);
    if (moduleError) {
      return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
    }
    const d = body?.data;
    const virusTotal = body?.virusTotal || null;
    const url = String(body?.url || d?.url || 'target');
    if (!d) {
      return NextResponse.json({ success: false, error: 'URL scan data required' }, { status: 400 });
    }

    const verdict = d.verdict || {};
    const level = verdict.level || '—';
    const reasons = Array.isArray(verdict.reasons) ? verdict.reasons : [];
    const fuzz = Array.isArray(d.fuzz) ? d.fuzz : [];
    const exposed = fuzz.filter((f: any) => f.status !== null && f.status < 400 && f.status >= 200);
    const kitFiles = Array.isArray(d.kitFiles) ? d.kitFiles : [];
    const exfil = Array.isArray(d.exfil) ? d.exfil : [];
    const artifacts = Array.isArray(d.artifacts) ? d.artifacts : [];
    const redirects = Array.isArray(d.redirects) ? d.redirects : [];
    const content = d.content || null;
    const tls = d.tls || null;
    const http = d.http || null;
    const indicators = content && Array.isArray(content.indicators) ? content.indicators : [];
    const host = String(d.host || '');
    const screenshotUrl = d.screenshotUrl ? encodeURIComponent('https://' + (host || url)) : '';

    const html = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<title>URL Scan — ${esc(url)}</title>
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
  .row { display: flex; align-items: center; gap: 8px; padding: 3px 0; border-bottom: 1px solid #f3f4f6; }
  .row:last-child { border-bottom: 0; }
  .row b { width: 140px; color: #6b7280; font-size: 11px; font-weight: 600; flex-shrink: 0; }
  .verdict { background: #f9fafb; border-left: 4px solid ${LEVEL_COLOR[level] || '#6b7280'}; padding: 8px 12px; border-radius: 4px; }
  .badge { display: inline-block; border-radius: 4px; padding: 0 8px; font-size: 11px; font-weight: 700; color: #fff; }
  .take { border: 1px solid #e5e7eb; border-left: 4px solid #6b7280; border-radius: 6px; padding: 6px 10px; margin-bottom: 6px; page-break-inside: avoid; }
  .note { color: #6b7280; font-style: italic; margin: 2px 0; }
  .footer { margin-top: 28px; padding-top: 8px; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 10px; text-align: center; }
  @media print { .print-btn { display: none; } body { padding: 8px; } tr, .take { break-inside: avoid; } }
  @page { size: A4 landscape; margin: 10mm; }
</style>
</head>
<body><div class="report">
  <div class="chrome">
    <div>
      <h1>🎯 URL Scanner — <span class="mono">${esc(url)}</span></h1>
      <div class="meta">NEXUS URL Scanner (attack-surface · kit fingerprint · attribution) · ${esc(d.timestamp || '')}</div>
    </div>
    <button class="print-btn" onclick="window.print()">🖨️ Imprimir / Guardar PDF</button>
  </div>

  <h2>Veredicto</h2>
  <div class="verdict">
    <span class="badge" style="background:${LEVEL_COLOR[level] || '#6b7280'}">${esc(level)}</span>
    <b style="margin-left:8px">${esc(verdict.score ?? 0)}/100</b>
    <div style="margin-top:6px">${esc(verdict.verdict || '')}</div>
  </div>
  ${reasons.length ? `<h3>Señales detectadas (${esc(reasons.length)})</h3><div class="chips">${reasons.map((r: string) => `<span class="chip red">${esc(r)}</span>`).join('')}</div>` : ''}

  <h2>Resumen</h2>
  <div class="grid">
    <div class="card"><b>HTTP Status</b><span>${http ? esc(http.status + ' ' + http.statusText) : 'unreachable'}</span></div>
    <div class="card"><b>Final URL</b><span class="mono">${esc(http?.finalUrl || '—')}</span></div>
    <div class="card"><b>Servidor</b><span>${esc(http?.server || '—')}</span></div>
    <div class="card"><b>Redirecciones</b><span>${esc(redirects.length)}</span></div>
    <div class="card"><b>Rutas probadas</b><span>${esc(fuzz.length)}</span></div>
    <div class="card"><b>Expuestos</b><span>${esc(exposed.length)}</span></div>
    <div class="card"><b>Kit files</b><span>${esc(kitFiles.length)}</span></div>
    <div class="card"><b>Exfil endpoints</b><span>${esc(exfil.length)}</span></div>
    <div class="card"><b>Artefactos / IoCs</b><span>${esc(artifacts.length)}</span></div>
    <div class="card"><b>Indicadores de contenido</b><span>${esc(indicators.length)}</span></div>
  </div>
  ${Array.isArray(d.staticFlags) && d.staticFlags.length ? `<h3>Heurísticas de URL</h3><div class="chips">${d.staticFlags.map((f: any) => `<span class="chip ${f.weight >= 3 ? 'red' : ''}">+${esc(f.weight)} · ${esc(f.label)}</span>`).join('')}</div>` : ''}

  ${screenshotUrl ? `<h2>Captura de pantalla (Live)</h2>
  <div style="text-align:center;padding:8px;border:1px solid #e5e7eb;border-radius:8px;">
    <img src="https://s0.wp.com/mshots/v1/${esc(screenshotUrl)}?w=1280&h=720" alt="Live screenshot" style="max-width:100%;border-radius:6px;"/>
    <div class="meta">Fuente: WordPress mshots · Hora local UTC-5</div>
  </div>` : ''}

  ${http ? `<h2>HTTP Fingerprint</h2>
  <div class="row"><b>Final URL</b><span class="mono">${esc(http.finalUrl)}</span></div>
  <div class="row"><b>Status</b><span>${esc(http.status)} ${esc(http.statusText)}</span></div>
  <div class="row"><b>Protocolo</b><span>${esc(http.protocol || '—')}</span></div>
  <div class="row"><b>Servidor</b><span>${esc(http.server || '—')}</span></div>
  <div class="row"><b>Content-Type</b><span>${esc(http.contentType || '—')}</span></div>
  <div class="row"><b>Content-Length</b><span>${esc(http.contentLength ?? '—')}</span></div>
  <div class="row"><b>TTFB</b><span>${http.timings ? esc(`${http.timings.ttfbMs} ms`) : '—'}</span></div>
  <div class="row"><b>Total</b><span>${http.timings ? esc(`${http.timings.totalMs} ms`) : '—'}</span></div>
  ${Object.keys(http.headers || {}).length ? `<h3>Response headers (${esc(Object.keys(http.headers).length)})</h3><table class="tbl"><thead><tr><th>Header</th><th>Valor</th></tr></thead><tbody>${Object.entries(http.headers).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td class="mono small">${esc(v)}</td></tr>`).join('')}</tbody></table>` : ''}` : ''}

  ${redirects.length ? `<h2>Cadena de Redirección (${esc(redirects.length)})</h2>
  <table class="tbl"><thead><tr><th>#</th><th>Status</th><th>URL</th></tr></thead><tbody>${redirects.map((r: any, i: number) => `<tr><td>${esc(i + 1)}</td><td>${esc(r.status ?? '—')}</td><td class="mono small">${esc(r.url)}</td></tr>`).join('')}</tbody></table>` : ''}

  ${tls ? `<h2>Certificado TLS</h2>
  <div class="row"><b>Protocolo</b><span>${esc(tls.protocol || '—')}</span></div>
  <div class="row"><b>Cipher</b><span>${esc(tls.cipher || '—')}</span></div>
  <div class="row"><b>Subject CN</b><span>${esc(tls.subjectCn || '—')}</span></div>
  <div class="row"><b>Subject Org</b><span>${esc(tls.subjectOrg || '—')}</span></div>
  <div class="row"><b>Issuer CN</b><span>${esc(tls.issuerCn || '—')}</span></div>
  <div class="row"><b>Issuer Org</b><span>${esc(tls.issuerOrg || '—')}</span></div>
  <div class="row"><b>Validez</b><span>${esc((tls.validFrom || '').slice(0, 10))} → ${esc((tls.validTo || '').slice(0, 10))}</span></div>
  <div class="row"><b>Estado</b><span>${tls.expired ? 'EXPIRADO' : tls.selfSigned ? 'SELF-SIGNED' : tls.hostnameMismatch ? 'MISMATCH HOSTNAME' : 'VÁLIDO'}</span></div>
  ${Array.isArray(tls.san) && tls.san.length ? `<h3>SAN (${esc(tls.san.length)})</h3><div class="chips">${tls.san.map((s: string) => `<span class="chip gray">${esc(s)}</span>`).join('')}</div>` : ''}` : ''}

  ${content ? `<h2>Análisis de contenido</h2>
  <div class="row"><b>Título</b><span>${esc(content.title || '—')}</span></div>
  <div class="row"><b>Idioma</b><span>${esc(content.lang || '—')}</span></div>
  <div class="row"><b>JS ofuscado</b><span>${content.obfuscatedJs ? 'SÍ' : 'no'}</span></div>
  <div class="row"><b>JS inline</b><span>${esc(content.inlineJsBytes ?? 0)} bytes</span></div>
  <div class="row"><b>Meta refresh</b><span>${content.metaRefresh ? 'SÍ' : 'no'}</span></div>
  ${content.forms && content.forms.length ? `<h3>Formularios (${esc(content.forms.length)})</h3>${content.forms.map((f: any) => `<div class="take"><span class="mono small">${esc(f.method)}</span> · <span class="mono small">${esc(f.action || '(self)')}</span>${f.external ? ' · <b class="small">EXTERNO</b>' : ''}</div>`).join('')}` : ''}
  ${content.iframes && content.iframes.length ? `<h3>Iframes (${esc(content.iframes.length)})</h3>${content.iframes.map((f: any) => `<div class="take mono small">${esc(f.src || '(no src)')}</div>`).join('')}` : ''}
  ${content.telegramTokens && content.telegramTokens.length ? `<h3>Bots de Telegram (${esc(content.telegramTokens.length)})</h3><div class="chips">${content.telegramTokens.map((t: string) => `<span class="chip red">bot:${esc(t)}</span>`).join('')}</div>` : ''}
  ${content.telegramChatIds && content.telegramChatIds.length ? `<h3>Chat IDs (${esc(content.telegramChatIds.length)})</h3><div class="chips">${content.telegramChatIds.map((c: string) => `<span class="chip red">${esc(c)}</span>`).join('')}</div>` : ''}
  ${content.emails && content.emails.length ? `<h3>Emails (${esc(content.emails.length)})</h3><div class="chips">${content.emails.map((e: string) => `<span class="chip">${esc(e)}</span>`).join('')}</div>` : ''}
  ${indicators.length ? `<h3>Indicadores (${esc(indicators.length)})</h3>${indicators.map((ind: any) => `<div class="take"><b>${esc(ind.label)}</b> <span class="badge" style="background:${ind.severity === 'CRITICAL' || ind.severity === 'HIGH' ? '#dc2626' : ind.severity === 'MEDIUM' ? '#d97706' : '#6b7280'}">${esc(ind.severity)}</span><span class="small"> · ${esc(ind.category)}</span><div class="small">${esc(ind.detail)}</div></div>`).join('')}` : ''}` : ''}

  <h2>Path Fuzzing (${esc(fuzz.length)} rutas)</h2>
  ${fuzz.length ? `<table class="tbl"><thead><tr><th>Ruta</th><th>Status</th><th>Contenido</th><th>Tamaño</th><th>Nota</th></tr></thead><tbody>${fuzz.map((f: any) => `<tr><td class="mono">${esc(f.path)}</td><td>${esc(f.status ?? 'ERR')}</td><td>${esc(f.contentType || '—')}</td><td>${f.size ? esc(f.size + ' B') : '—'}</td><td class="small">${f.sensitive ? '<b>SENSITIVE</b> ' : ''}${esc(f.note || '')}</td></tr>`).join('')}</tbody></table>` : '<p class="note">No se probaron rutas.</p>'}

  <h2>Phishing Kit Fingerprint</h2>
  ${d.kit && d.kit.detected ? `<div class="verdict" style="border-left-color:#dc2626"><b>KIT SIGNATURES</b></div>${(d.kit.matches || []).map((m: any) => `<div class="take"><b>${esc(m.family)}</b> <span class="small">${esc(Math.round(m.confidence * 100))}% confidence</span><div class="small">${esc((m.indicators || []).join(' · '))}</div></div>`).join('')}` : '<p class="note">Sin firmas de kit de phishing.</p>'}
  ${kitFiles.length ? `<h3>Archivos de kit (${esc(kitFiles.length)})</h3><table class="tbl"><thead><tr><th>Tipo</th><th>Status</th><th>Tamaño</th><th>URL</th><th>SHA-256</th></tr></thead><tbody>${kitFiles.map((f: any) => `<tr><td class="small">${esc(f.kind || '')}</td><td>${esc(f.status ?? 'ERR')}</td><td>${esc(f.size ?? '—')}</td><td class="mono small">${esc(f.url)}</td><td class="mono small">${esc(f.sha256 || '—')}</td></tr>`).join('')}</tbody></table>` : ''}

  <h2>Exfiltración (${esc(exfil.length)})</h2>
  ${exfil.length ? exfil.map((e: any) => `<div class="take"><div class="small">${esc(e.kind)}</div><span class="mono">${esc(e.url)}</span><div class="small">${esc(e.detail || '')}</div></div>`).join('') : '<p class="note">Sin canales de exfiltración detectados.</p>'}

  <h2>Artefactos / IoCs (${esc(artifacts.length)})</h2>
  ${artifacts.length ? `<table class="tbl"><thead><tr><th>Tipo</th><th>Valor</th><th>Fuente</th><th>Severidad</th></tr></thead><tbody>${artifacts.map((a: any) => `<tr><td class="small">${esc(a.type)}</td><td class="mono small">${esc(a.value)}</td><td class="small">${esc(a.source || '')}</td><td>${esc(a.severity || '')}</td></tr>`).join('')}</tbody></table>` : '<p class="note">No se recolectaron artefactos.</p>'}

  ${virusTotal ? `<h2>VirusTotal</h2>
  <div class="grid">
    <div class="card"><b>Veredicto</b><span>${esc(virusTotal.verdict || '—')}</span></div>
    <div class="card"><b>Malicious</b><span>${esc(virusTotal.lastAnalysisStats?.malicious ?? 0)}/${esc(virusTotal.totalEngines ?? 0)}</span></div>
    <div class="card"><b>Suspicious</b><span>${esc(virusTotal.lastAnalysisStats?.suspicious ?? 0)}</span></div>
    <div class="card"><b>Harmless</b><span>${esc(virusTotal.lastAnalysisStats?.harmless ?? 0)}</span></div>
    <div class="card"><b>Reputación</b><span>${esc(virusTotal.reputation ?? '—')}</span></div>
    <div class="card"><b>Último análisis</b><span>${esc((virusTotal.lastAnalysisDate || '').slice(0, 10) || '—')}</span></div>
  </div>
  ${Array.isArray(virusTotal.categories) && virusTotal.categories.length ? `<h3>Categorías</h3><div class="chips">${virusTotal.categories.map((c: string) => `<span class="chip gray">${esc(c)}</span>`).join('')}</div>` : ''}
  ${Array.isArray(virusTotal.tags) && virusTotal.tags.length ? `<h3>Tags</h3><div class="chips">${virusTotal.tags.map((t: string) => `<span class="chip gray">#${esc(t)}</span>`).join('')}</div>` : ''}` : ''}

  <div class="footer">NEXUS OSINT — URL Scanner · Generado ${esc(new Date().toISOString())} · Informe automatizado de análisis de URL</div>
</div></body>
</html>`;

    const safeName = String(host || url).replace(/[^a-zA-Z0-9._-]/g, '_');
    return new NextResponse(html, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `attachment; filename="informe_urlscan_${safeName}.html"`,
      },
    });
  } catch (error) {
    return NextResponse.json({ success: false, error: error instanceof Error ? error.message : 'Report failed' }, { status: 500 });
  }
}