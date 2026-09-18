import { NextResponse } from 'next/server';
import { createHash } from 'crypto';

interface HTMLReportRequest {
  reportId: string;
  timestamp: string;
  urls: string[];
  services: string[];
  notes?: string;
  results: Array<{
    service: string;
    url: string;
    status: 'success' | 'failed' | 'pending' | 'manual';
    message: string;
    timestamp: string;
    referenceId?: string;
  }>;
  fingerprint: string;
  summary: {
    total: number;
    success: number;
    failed: number;
    pending: number;
    manual: number;
  };
}

function generateHTMLReport(data: HTMLReportRequest): string {
  const { reportId, timestamp, urls, services, notes, results, fingerprint, summary } = data;
  const date = new Date(timestamp).toLocaleString('es-ES', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  const statusColors: Record<string, string> = {
    success: '#10b981',
    failed: '#ef4444',
    pending: '#f59e0b',
    manual: '#3b82f6',
  };

  const statusLabels: Record<string, string> = {
    success: 'ÉXITO',
    failed: 'FALLIDO',
    pending: 'PENDIENTE',
    manual: 'MANUAL',
  };

  const serviceIcons: Record<string, string> = {
    'Google Safe Browsing': '🛡️',
    'Microsoft SmartScreen': '🔷',
    'APWG (Anti-Phishing Working Group)': '📧',
    'CISA / US-CERT': '🇺🇸',
    'VirusTotal': '🦠',
  };

  const resultsByUrl = urls.map(url => ({
    url,
    results: results.filter(r => r.url === url),
  }));

  const resultsTableRows = results.map(r => `
    <tr>
      <td style="padding: 12px; border: 1px solid #e5e7eb; font-family: monospace; font-size: 12px;">${r.service}</td>
      <td style="padding: 12px; border: 1px solid #e5e7eb; font-family: monospace; font-size: 11px; word-break: break-all;">${r.url}</td>
      <td style="padding: 12px; border: 1px solid #e5e7eb; text-align: center;">
        <span style="display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 11px; font-weight: 600; background-color: ${statusColors[r.status]}20; color: ${statusColors[r.status]}; border: 1px solid ${statusColors[r.status]}40;">
          ${statusLabels[r.status]}
        </span>
      </td>
      <td style="padding: 12px; border: 1px solid #e5e7eb; font-size: 13px; color: #374151;">${r.message}</td>
      <td style="padding: 12px; border: 1px solid #e5e7eb; font-family: monospace; font-size: 11px; color: #6b7280;">${new Date(r.timestamp).toLocaleString('es-ES')}</td>
      <td style="padding: 12px; border: 1px solid #e5e7eb; font-family: monospace; font-size: 11px; color: #6b7280;">${r.referenceId || '-'}</td>
    </tr>
  `).join('');

  const urlDetailSections = resultsByUrl.map(({ url, results: urlResults }) => `
    <div style="margin-bottom: 32px; padding: 24px; background: #f9fafb; border-radius: 12px; border: 1px solid #e5e7eb;">
      <h3 style="margin: 0 0 16px 0; font-size: 18px; color: #111827; font-family: 'Segoe UI', system-ui, sans-serif; word-break: break-all;">
        ${url}
      </h3>
      <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
        <thead>
          <tr style="background: #f3f4f6;">
            <th style="padding: 10px; border: 1px solid #e5e7eb; text-align: left; font-weight: 600; color: #374151;">Servicio</th>
            <th style="padding: 10px; border: 1px solid #e5e7eb; text-align: center; font-weight: 600; color: #374151;">Estado</th>
            <th style="padding: 10px; border: 1px solid #e5e7eb; text-align: left; font-weight: 600; color: #374151;">Mensaje</th>
            <th style="padding: 10px; border: 1px solid #e5e7eb; text-align: left; font-weight: 600; color: #374151;">Timestamp</th>
            <th style="padding: 10px; border: 1px solid #e5e7eb; text-align: left; font-weight: 600; color: #374151;">Ref. ID</th>
          </tr>
        </thead>
        <tbody>
          ${urlResults.map(r => `
            <tr>
              <td style="padding: 10px; border: 1px solid #e5e7eb; font-weight: 500; color: #374151;">${serviceIcons[r.service] || '•'} ${r.service}</td>
              <td style="padding: 10px; border: 1px solid #e5e7eb; text-align: center;">
                <span style="display: inline-block; padding: 3px 10px; border-radius: 9999px; font-size: 10px; font-weight: 600; background-color: ${statusColors[r.status]}20; color: ${statusColors[r.status]}; border: 1px solid ${statusColors[r.status]}40;">
                  ${statusLabels[r.status]}
                </span>
              </td>
              <td style="padding: 10px; border: 1px solid #e5e7eb; color: #4b5563;">${r.message}</td>
              <td style="padding: 10px; border: 1px solid #e5e7eb; font-family: monospace; font-size: 11px; color: #6b7280;">${new Date(r.timestamp).toLocaleString('es-ES')}</td>
              <td style="padding: 10px; border: 1px solid #e5e7eb; font-family: monospace; font-size: 11px; color: #6b7280;">${r.referenceId || '-'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `).join('');

  const summaryCards = `
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 24px;">
      <div style="padding: 20px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 12px; text-align: center;">
        <div style="font-size: 32px; font-weight: 700; color: #166534;">${summary.total}</div>
        <div style="font-size: 13px; color: #166534; font-weight: 500; margin-top: 4px;">Total Reportes</div>
      </div>
      <div style="padding: 20px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 12px; text-align: center;">
        <div style="font-size: 32px; font-weight: 700; color: #166534;">${summary.success}</div>
        <div style="font-size: 13px; color: #166534; font-weight: 500; margin-top: 4px;">Éxitos</div>
      </div>
      <div style="padding: 20px; background: #fef2f2; border: 1px solid #fecaca; border-radius: 12px; text-align: center;">
        <div style="font-size: 32px; font-weight: 700; color: #991b1b;">${summary.failed}</div>
        <div style="font-size: 13px; color: #991b1b; font-weight: 500; margin-top: 4px;">Fallidos</div>
      </div>
      <div style="padding: 20px; background: #fffbeb; border: 1px solid #fde68a; border-radius: 12px; text-align: center;">
        <div style="font-size: 32px; font-weight: 700; color: #92400e;">${summary.pending}</div>
        <div style="font-size: 13px; color: #92400e; font-weight: 500; margin-top: 4px;">Pendientes</div>
      </div>
      <div style="padding: 20px; background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 12px; text-align: center;">
        <div style="font-size: 32px; font-weight: 700; color: #1e40af;">${summary.manual}</div>
        <div style="font-size: 13px; color: #1e40af; font-weight: 500; margin-top: 4px;">Manuales</div>
      </div>
    </div>
  `;

  const servicesList = services.map(s => {
    const names: Record<string, string> = {
      google: 'Google Safe Browsing',
      microsoft: 'Microsoft SmartScreen',
      apwg: 'APWG (Anti-Phishing Working Group)',
      cisa: 'CISA / US-CERT',
      virustotal: 'VirusTotal',
    };
    return names[s] || s;
  }).join(', ');

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Informe TakeDown URL - ${reportId}</title>
  <style>
    @page { margin: 20mm; size: A4; }
    @media print {
      .no-print { display: none !important; }
      body { margin: 0; padding: 0; }
      .page-break { page-break-before: always; }
    }
    body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; line-height: 1.6; color: #1f2937; background: white; margin: 0; padding: 40px; }
    .container { max-width: 800px; margin: 0 auto; }
    .header { text-align: center; padding: 32px 0; border-bottom: 3px solid #1e3a8a; margin-bottom: 32px; }
    .logo { font-size: 28px; font-weight: 800; color: #1e3a8a; margin-bottom: 8px; letter-spacing: -0.5px; }
    .subtitle { font-size: 16px; color: #6b7280; margin-bottom: 24px; }
    .report-id { font-family: monospace; font-size: 14px; background: #f3f4f6; padding: 8px 16px; border-radius: 8px; display: inline-block; color: #374151; }
    .section { margin-bottom: 32px; }
    .section-title { font-size: 20px; font-weight: 700; color: #111827; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb; display: flex; align-items: center; gap: 10px; }
    .info-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
    .info-item { padding: 16px; background: #f9fafb; border-radius: 8px; border: 1px solid #e5e7eb; }
    .info-label { font-size: 12px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
    .info-value { font-size: 14px; color: #111827; font-weight: 500; word-break: break-word; }
    .fingerprint-box { background: #111827; color: #10b981; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 12px; word-break: break-all; border: 2px solid #10b981; }
    .fingerprint-label { color: #9ca3af; font-size: 11px; margin-bottom: 8px; display: block; }
    .print-btn { position: fixed; top: 20px; right: 20px; padding: 12px 24px; background: #1e3a8a; color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 14px; box-shadow: 0 4px 12px rgba(30, 58, 138, 0.3); z-index: 1000; }
    .print-btn:hover { background: #1e40af; }
    .footer { margin-top: 48px; padding-top: 24px; border-top: 1px solid #e5e7eb; text-align: center; font-size: 12px; color: #9ca3af; }
    .watermark { position: fixed; bottom: 50px; right: 50px; font-size: 80px; color: #e5e7eb; font-weight: 800; transform: rotate(-15deg); z-index: -1; pointer-events: none; }
  </style>
</head>
<body>
  <button class="print-btn no-print" onclick="window.print()">🖨️ Imprimir / Guardar PDF</button>
  <div class="watermark">TAKEDOWN</div>
  
  <div class="container">
    <header class="header">
      <div class="logo">🛡️ INFORME TAKEDOWN URL</div>
      <div class="subtitle">Reporte de envío de URLs maliciosas a servicios de seguridad</div>
      <div class="report-id">ID: ${reportId}</div>
    </header>

    <section class="section">
      <h2 class="section-title">📋 Información General</h2>
      <div class="info-grid">
        <div class="info-item">
          <div class="info-label">Fecha y Hora</div>
          <div class="info-value">${date}</div>
        </div>
        <div class="info-item">
          <div class="info-label">Total URLs Procesadas</div>
          <div class="info-value">${urls.length}</div>
        </div>
        <div class="info-item">
          <div class="info-label">Servicios Seleccionados</div>
          <div class="info-value">${servicesList}</div>
        </div>
        <div class="info-item">
          <div class="info-label">Huella Digital (SHA-256)</div>
          <div class="info-value fingerprint-box">
            <span class="fingerprint-label">FINGERPRINT</span>
            ${fingerprint}
          </div>
        </div>
      </div>
      ${notes ? `
        <div style="margin-top: 16px; padding: 16px; background: #fef3c7; border: 1px solid #fde68a; border-radius: 8px;">
          <div class="info-label">Notas Adicionales</div>
          <div class="info-value" style="white-space: pre-wrap;">${notes}</div>
        </div>
      ` : ''}
    </section>

    <section class="section">
      <h2 class="section-title">📊 Resumen de Resultados</h2>
      ${summaryCards}
    </section>

    <section class="section page-break">
      <h2 class="section-title">📋 Detalle por URL</h2>
      ${urlDetailSections}
    </section>

    <section class="section page-break">
      <h2 class="section-title">📋 Tabla Consolidada de Resultados</h2>
      <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
        <thead>
          <tr style="background: #1e3a8a; color: white;">
            <th style="padding: 12px; border: 1px solid #e5e7eb; text-align: left; font-weight: 600;">Servicio</th>
            <th style="padding: 12px; border: 1px solid #e5e7eb; text-align: left; font-weight: 600;">URL</th>
            <th style="padding: 12px; border: 1px solid #e5e7eb; text-align: center; font-weight: 600;">Estado</th>
            <th style="padding: 12px; border: 1px solid #e5e7eb; text-align: left; font-weight: 600;">Mensaje</th>
            <th style="padding: 12px; border: 1px solid #e5e7eb; text-align: left; font-weight: 600;">Timestamp</th>
            <th style="padding: 12px; border: 1px solid #e5e7eb; text-align: left; font-weight: 600;">Ref. ID</th>
          </tr>
        </thead>
        <tbody>
          ${resultsTableRows}
        </tbody>
      </table>
    </section>

    <section class="section">
      <h2 class="section-title">🔗 Guía de Reportes Manuales</h2>
      <div style="display: grid; gap: 12px;">
        ${urls.map(url => `
          <div style="padding: 16px; background: #f9fafb; border-radius: 8px; border: 1px solid #e5e7eb;">
            <div style="font-family: monospace; font-size: 13px; color: #1e3a8a; margin-bottom: 12px; word-break: break-all;">${url}</div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
              <a href="https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(url)}" target="_blank" rel="noopener noreferrer" style="padding: 8px 16px; background: #1e3a8a; color: white; text-decoration: none; border-radius: 6px; font-size: 12px; font-weight: 500;">🛡️ Google Safe Browsing</a>
              <a href="https://www.microsoft.com/wdsi/support/report-unsafe-site" target="_blank" rel="noopener noreferrer" style="padding: 8px 16px; background: #0067b8; color: white; text-decoration: none; border-radius: 6px; font-size: 12px; font-weight: 500;">🔷 Microsoft SmartScreen</a>
              <a href="mailto:reportphishing@apwg.org?subject=Phishing%20Report&body=${encodeURIComponent(`URL: ${url}\n\n${notes || ''}`)}" style="padding: 8px 16px; background: #dc2626; color: white; text-decoration: none; border-radius: 6px; font-size: 12px; font-weight: 500;">📧 APWG</a>
              <a href="mailto:phishing-report@us-cert.gov?subject=Phishing%20Report&body=${encodeURIComponent(`URL: ${url}\n\n${notes || ''}`)}" style="padding: 8px 16px; background: #002b5c; color: white; text-decoration: none; border-radius: 6px; font-size: 12px; font-weight: 500;">🇺🇸 CISA/US-CERT</a>
              <a href="https://www.virustotal.com/gui/url/${Buffer.from(url).toString('base64').replace(/=+$/, '')}" target="_blank" rel="noopener noreferrer" style="padding: 8px 16px; background: #7c3aed; color: white; text-decoration: none; border-radius: 6px; font-size: 12px; font-weight: 500;">🦠 VirusTotal</a>
            </div>
          </div>
        `).join('')}
      </div>
    </section>

    <footer class="footer">
      <p><strong>Informe generado por TakeDown URL Module</strong> - Sistema de Inteligencia de Amenazas</p>
      <p>ID de Reporte: ${reportId} | Huella Digital: ${fingerprint.substring(0, 16)}... | Generado: ${date}</p>
      <p style="margin-top: 12px;">Este documento contiene información confidencial. Su integridad puede verificarse mediante la huella digital SHA-256.</p>
    </footer>
  </div>

  <script>
    window.onload = function() {
      document.querySelector('.print-btn')?.focus();
    };
  </script>
</body>
</html>`;
}

export async function POST(request: Request) {
  try {
    const data: HTMLReportRequest = await request.json();
    const html = generateHTMLReport(data);
    return new NextResponse(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `inline; filename="takedown-report-${data.reportId}.html"`,
      },
    });
  } catch (error: unknown) {
    console.error('Error generating HTML report:', error);
    const errorMessage = error instanceof Error ? error.message : 'Error al generar reporte HTML';
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}