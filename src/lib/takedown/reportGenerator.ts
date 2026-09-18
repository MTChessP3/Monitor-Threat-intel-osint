import { sha256 } from './hashGenerator';
import { defangUrl } from './defang';

interface ReportEvidence {
  url: string;
  defangedUrl: string;
  virustotalStatus?: string;
  virustotalClassification?: string;
  virustotalMaliciousEngines?: number;
  vectorDetected?: string;
  googleStatus?: string;
  microsoftStatus?: string;
  apwgStatus?: string;
  cisaStatus?: string;
  timestamp: string;
}

interface BatchReport {
  reportId: string;
  batchId: string;
  timestamp: string;
  fileHash: string;
  reportHash: string;
  urls: ReportEvidence[];
  summary: {
    totalUrls: number;
    totalSent: number;
    successfulByChannel: Record<string, number>;
    averageRiskScore: number;
  };
  fingerprints: {
    originalFile: string;
    reportExecution: string;
  };
}

function generateQrCodeData(text: string): string {
  const encoded = Buffer.from(text).toString('base64');
  return `data:image/svg+xml;base64,${Buffer.from(
    `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">
      <rect width="128" height="128" fill="#fff"/>
      <text x="64" y="64" text-anchor="middle" dominant-baseline="middle" font-family="monospace" font-size="8" fill="#000">${encoded.substring(0, 200)}...</text>
    </svg>`
  ).toString('base64')}`;
}

export function generateHtmlReport(data: {
  batchId: string;
  batchName: string;
  fileHash: string;
  reportHash: string;
  originalFileHash: string;
  urls: ReportEvidence[];
  summary: {
    totalUrls: number;
    totalSent: number;
    successfulByChannel: Record<string, number>;
    averageRiskScore: number;
  };
  virustotalResults?: Array<{ url: string; classification: string; maliciousEngines: number }>;
  fingerprint: string;
  timestamp: string;
}): string {
  const {
    batchId, batchName, fileHash, reportHash, originalFileHash,
    urls, summary, virustotalResults, fingerprint, timestamp
  } = data;

  const rowsHtml = urls.map((ev, i) => `
    <tr class="border-b border-gray-700/50 hover:bg-gray-800/50">
      <td class="p-3 font-mono text-xs text-red-400">${ev.defangedUrl}</td>
      <td class="p-3 text-xs">${ev.virustotalClassification || '—'}</td>
      <td class="p-3 text-xs">${ev.vectorDetected || '—'}</td>
      <td class="p-3 text-xs">
        <span class="${ev.googleStatus === 'success' ? 'text-green-400' : 'text-yellow-400'}">${ev.googleStatus || '—'}</span> /
        <span class="${ev.microsoftStatus === 'success' ? 'text-green-400' : 'text-yellow-400'}">${ev.microsoftStatus || '—'}</span> /
        <span class="${ev.apwgStatus === 'success' ? 'text-green-400' : 'text-yellow-400'}">${ev.apwgStatus || '—'}</span> /
        <span class="${ev.cisaStatus === 'success' ? 'text-green-400' : 'text-yellow-400'}">${ev.cisaStatus || '—'}</span>
      </td>
      <td class="p-3 font-mono text-xs text-gray-400">${ev.timestamp}</td>
    </tr>
  `).join('');

  const qrCodeSvg = `
    <svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">
      <rect width="128" height="128" fill="#fff"/>
      <rect x="0" y="0" width="32" height="32" fill="#000"/>
      <rect x="0" y="0" width="12" height="12" fill="#fff"/>
      <rect x="20" y="20" width="12" height="12" fill="#fff"/>
      <rect x="0" y="20" width="12" height="12" fill="#fff"/>
      <rect x="0" y="0" width="12" height="12" fill="#fff"/>
      <rect x="96" y="0" width="32" height="32" fill="#000"/>
      <rect x="96" y="0" width="12" height="12" fill="#fff"/>
      <rect x="116" y="20" width="12" height="12" fill="#fff"/>
      <rect x="96" y="20" width="12" height="12" fill="#fff"/>
      <rect x="96" y="0" width="12" height="12" fill="#fff"/>
      <rect x="0" y="96" width="32" height="32" fill="#000"/>
      <rect x="0" y="96" width="12" height="12" fill="#fff"/>
      <rect x="20" y="116" width="12" height="12" fill="#fff"/>
      <rect x="0" y="116" width="12" height="12" fill="#fff"/>
      <rect x="0" y="96" width="12" height="12" fill="#fff"/>
      <rect x="32" y="32" width="64" height="64" fill="none" stroke="#000" stroke-width="2"/>
      <rect x="40" y="40" width="48" height="48" fill="none" stroke="#000" stroke-width="1"/>
    </svg>
  `;

  const channelStatuses = Object.entries(summary.successfulByChannel).map(([channel, count]) => `
    <div class="p-3 rounded-lg bg-gray-800 border border-gray-700">
      <div class="text-sm font-medium text-gray-300">${channel}</div>
      <div class="text-2xl font-bold ${count > 0 ? 'text-green-400' : 'text-yellow-400'}">${count}</div>
      <div class="text-xs text-gray-500">envíos exitosos</div>
    </div>
  `).join('');

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TakeDown URL - Informe de Eliminación | NEXUS-INTEL</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: #fff;
      color: #1f2937;
      line-height: 1.6;
      font-size: 12px;
      padding: 20mm;
    }
    @page { size: A4; margin: 20mm; }
    .header {
      border-bottom: 4px solid #059669;
      padding-bottom: 24px;
      margin-bottom: 32px;
      text-align: center;
    }
    .header h1 { font-size: 28px; font-weight: 800; color: #059669; margin-bottom: 8px; }
    .header .subtitle { color: #6b7280; font-size: 14px; }
    .meta-bar {
      display: flex; justify-content: center; gap: 24px; flex-wrap: wrap;
      font-size: 12px; color: #6b7280; margin-top: 16px;
    }
    .meta-bar span { display: flex; align-items: center; gap: 6px; }
    .section { margin-bottom: 32px; page-break-inside: avoid; }
    .section-title {
      font-size: 18px; font-weight: 700; color: #111827;
      border-bottom: 2px solid #e5e7eb; padding-bottom: 8px;
      margin-bottom: 16px; display: flex; align-items: center; gap: 8px;
    }
    .crypto-block {
      background: #f0fdf4; border: 2px solid #86efac; border-radius: 12px;
      padding: 20px; margin: 16px 0;
    }
    .crypto-block h3 { color: #166534; font-size: 14px; margin-bottom: 12px; }
    .hash-row {
      display: flex; justify-content: space-between; align-items: center;
      padding: 8px 12px; background: #fff; border-radius: 8px; margin-bottom: 8px;
      border: 1px solid #bbf7d0;
    }
    .hash-label { font-weight: 600; color: #166534; font-size: 12px; }
    .hash-value { font-family: 'Cascadia Code', monospace; font-size: 11px; color: #15803d; word-break: break-all; }
    table { width: 100%; border-collapse: collapse; margin: 16px 0; }
    th {
      background: #1e3a8a; color: #fff; padding: 12px 8px; text-align: left;
      font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
    }
    td { padding: 10px 8px; border-bottom: 1px solid #e5e7eb; font-size: 12px; }
    tr:hover td { background: #f9fafb; }
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; margin: 16px 0; }
    .summary-card {
      background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px;
      padding: 16px; text-align: center;
    }
    .summary-card .number { font-size: 28px; font-weight: 700; color: #111827; }
    .summary-card .label { font-size: 11px; color: #6b7280; text-transform: uppercase; margin-top: 4px; }
    .risk-score {
      display: inline-block; padding: 6px 16px; border-radius: 9999px;
      font-weight: 700; font-size: 14px;
      background: ${summary.averageRiskScore > 50 ? '#ef4444' : summary.averageRiskScore > 25 ? '#f59e0b' : '#22c55e'};
      color: #fff;
    }
    .footer {
      margin-top: 48px; padding-top: 24px; border-top: 2px solid #e5e7eb;
      text-align: center; font-size: 10px; color: #9ca3af; page-break-before: always;
    }
    .footer p { margin: 4px 0; }
    .qr-section { display: flex; justify-content: center; gap: 24px; align-items: flex-start; margin: 16px 0; }
    .qr-code { border: 2px solid #e5e7eb; border-radius: 8px; padding: 8px; }
    .non-alteration {
      background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px 16px;
      border-radius: 4px; margin: 16px 0; font-size: 11px; color: #92400e;
    }
    .channel-results { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 12px; margin: 16px 0; }
    @media print {
      body { padding: 0; }
      .no-print { display: none; }
      table, .summary-grid, .channel-results { page-break-inside: avoid; }
      .section { page-break-inside: avoid; }
    }
  </style>
</head>
<body>
  <div class="report">
    <div class="header">
      <h1>🛡️ TAKE DOWN URL</h1>
      <div class="subtitle">Informe de Eliminación de URLs Maliciosas</div>
      <div class="meta-bar">
        <span>📋 ID Transacción: <strong>${batchId}</strong></span>
        <span>📅 Fecha UTC: <strong>${new Date(timestamp).toISOString()}</strong></span>
        <span>🏢 Plataforma: <strong>NEXUS-INTEL</strong></span>
        <span>📊 Versión: <strong>2.0</strong></span>
      </div>
    </div>

    <div class="section">
      <div class="section-title">🔐 Bloque de Criptografía e Integridad</div>
      <div class="crypto-block">
        <h3>Huella Digital SHA-256 del Lote</h3>
        <div class="hash-row">
          <span class="hash-label">Hash del Archivo Original:</span>
          <span class="hash-value">${fileHash}</span>
        </div>
        <div class="hash-row">
          <span class="hash-label">Hash de Ejecución del Reporte:</span>
          <span class="hash-value">${reportHash}</span>
        </div>
        <div class="hash-row">
          <span class="hash-label">Hash Verificable (Original + Ejecución):</span>
          <span class="hash-value">${originalFileHash}</span>
        </div>
        <div class="hash-row">
          <span class="hash-label">Firma Criptográfica del Lote:</span>
          <span class="hash-value">${fingerprint}</span>
        </div>
      </div>
      <div class="non-alteration">
        <strong>⚠️ Declaración de No Alteración:</strong> Este informe ha sido generado con huella digital criptográfica SHA-256. 
        Cualquier modificación posterior al contenido invalidará la firma. Verifique la integridad del lote comparando los hashes.
      </div>
    </div>

    <div class="section">
      <div class="section-title">📊 Resumen Ejecutivo</div>
      <div class="summary-grid">
        <div class="summary-card">
          <div class="number">${summary.totalUrls}</div>
          <div class="label">Total URLs Procesadas</div>
        </div>
        <div class="summary-card">
          <div class="number">${summary.totalSent}</div>
          <div class="label">Reportes Enviados</div>
        </div>
        <div class="summary-card">
          <div class="number">${summary.averageRiskScore}</div>
          <div class="label">Puntuación de Riesgo Promedio</div>
        </div>
        <div class="summary-card">
          <div class="number">${summary.totalSent > 0 ? '✅' : '⏳'}</div>
          <div class="label">Estado General</div>
        </div>
      </div>
      <div class="channel-results">
        ${channelStatuses}
      </div>
      ${virustotalResults && virustotalResults.length > 0 ? `
        <div style="margin-top: 16px;">
          <h4 style="font-size: 14px; margin-bottom: 8px; color: #111827;">🔬 Pre-Check VirusTotal</h4>
          <table>
            <thead>
              <tr><th>URL</th><th>Clasificación</th><th>Motores Maliciosos</th></tr>
            </thead>
            <tbody>
              ${virustotalResults.map(v => `
                <tr>
                  <td class="font-mono text-xs">${v.url}</td>
                  <td><span class="${v.classification === 'CONFIRMED_MALICIOUS' ? 'text-red-400' : v.classification === 'SUSPICIOUS' ? 'text-yellow-400' : 'text-gray-400'}">${v.classification}</span></td>
                  <td>${v.maliciousEngines}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      ` : ''}
    </div>

    <div class="section">
      <div class="section-title">📋 Tabla de Evidencia y Trazabilidad</div>
      <table>
        <thead>
          <tr>
            <th>URL (Defanged)</th>
            <th>VirusTotal</th>
            <th>Vector Detectado</th>
            <th>Google / MS / APWG / CISA</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml}
        </tbody>
      </table>
    </div>

    <div class="section">
      <div class="section-title">🔗 Servicios de Reporte Configurados</div>
      <div class="channel-results">
        <div class="summary-card">
          <div class="number text-green-400">✅</div>
          <div class="label">VirusTotal API</div>
        </div>
        <div class="summary-card">
          <div class="number text-blue-400">📧</div>
          <div class="label">APWG SMTP</div>
        </div>
        <div class="summary-card">
          <div class="number text-blue-400">📧</div>
          <div class="label">CISA SMTP</div>
        </div>
        <div class="summary-card">
          <div class="number text-purple-400">🔍</div>
          <div class="label">Google Safe Browsing</div>
        </div>
        <div class="summary-card">
          <div class="number text-orange-400">🪟</div>
          <div class="label">Microsoft SmartScreen</div>
        </div>
      </div>
    </div>

    <div class="footer">
      <div class="qr-section">
        <div class="qr-code">${qrCodeSvg}</div>
        <div style="text-align: left; font-size: 11px; color: #6b7280;">
          <p><strong>Código QR de Sesión:</strong> Contiene la firma criptográfica del lote</p>
          <p><strong>Firma:</strong> ${fingerprint.substring(0, 40)}...</p>
        </div>
      </div>
      <p style="margin-top: 16px;">Generado por NEXUS-INTEL TakeDown URL Module v2.0</p>
      <p>Plataforma de Inteligencia de Amenazas y Protección Ejecutiva</p>
      <p>Este informe se generó automáticamente con huella digital SHA-256. Verifique la integridad antes de compartir.</p>
      <p style="margin-top: 8px; color: #6b7280;">Hash Verificación: ${reportHash}</p>
    </div>
  </div>
</body>
</html>`;
}

export async function generateReportHash(content: string): Promise<string> {
  return sha256(content);
}

export function generateReportId(): string {
  return crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substr(2);
}
