// ============================================================================
// Executive Digital Protection - Printable HTML Module Generator
// ============================================================================
// Generates printable HTML modules for each dork category with PDF download

import { ExecutiveDorkCategory, EXECUTIVE_DORK_CATEGORIES, SEVERITY_LABELS } from './executive-dork-categories';

export interface PrintableModuleOptions {
  category: ExecutiveDorkCategory;
  targetName: string;
  executiveEmail?: string;
  executivePhone?: string;
  executiveOrg?: string;
  results: DorkResult[];
  timestamp: string;
  riskLevel?: 'bajo' | 'medio' | 'alto' | 'critico';
  totalQueries: number;
  totalResults: number;
}

export interface DorkResult {
  title: string;
  url: string;
  snippet: string;
  source: string;
  position: number;
  classification: 'validated' | 'potential' | 'discarded';
}

function escapeHtml(text: string): string {
  return String(text ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatDate(dateString: string): string {
  const d = new Date(dateString);
  return d.toLocaleString('es-ES', { dateStyle: 'full', timeStyle: 'short' });
}

function getSeverityInfo(severity: string) {
  return SEVERITY_LABELS[severity] || SEVERITY_LABELS.LOW;
}

function renderResultsTable(results: DorkResult[]): string {
  if (results.length === 0) {
    return `
      <div class="no-results">
        <p>No se encontraron resultados para esta categoría.</p>
      </div>
    `;
  }

  return `
    <table class="results-table">
      <thead>
        <tr>
          <th>#</th>
          <th>Título</th>
          <th>URL</th>
          <th>Fuente</th>
          <th>Clasificación</th>
        </tr>
      </thead>
      <tbody>
        ${results.map(r => `
          <tr>
            <td>${r.position}</td>
            <td>${escapeHtml(r.title)}</td>
            <td><a href="${escapeHtml(r.url)}" target="_blank">${escapeHtml(r.url)}</a></td>
            <td>${escapeHtml(r.source)}</td>
            <td><span class="badge badge-${r.classification}">${r.classification.toUpperCase()}</span></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

function renderDorkQuery(dorkTemplate: string, targetName: string): string {
  return dorkTemplate.replace(/\{TARGET\}/g, targetName);
}

export function generatePrintableModuleHTML(options: PrintableModuleOptions): string {
  const { category, targetName, results, timestamp, riskLevel, totalQueries, totalResults } = options;
  const severityInfo = getSeverityInfo(category.severity);
  const dorkQuery = renderDorkQuery(category.dorkTemplate, targetName);

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${category.name} - ${escapeHtml(targetName)} | Executive Digital Protection</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { 
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; 
      background: #ffffff; 
      color: #1f2937; 
      line-height: 1.6; 
      font-size: 11px; 
      padding: 20px; 
    }
    .container { max-width: 1000px; margin: 0 auto; }
    
    .header { 
      border-bottom: 3px solid #059669; 
      padding-bottom: 16px; 
      margin-bottom: 20px; 
      text-align: center; 
    }
    .logo { 
      font-size: 20px; 
      font-weight: 800; 
      color: #059669; 
      margin-bottom: 6px; 
    }
    .title { 
      font-size: 22px; 
      font-weight: 700; 
      color: #111827; 
      margin-bottom: 4px; 
    }
    .subtitle { 
      color: #6b7280; 
      font-size: 12px; 
    }
    
    .meta-bar { 
      display: flex; 
      justify-content: center; 
      gap: 16px; 
      flex-wrap: wrap; 
      font-size: 11px; 
      color: #6b7280; 
      margin-bottom: 16px; 
      padding: 10px; 
      background: #f9fafb; 
      border-radius: 8px; 
    }
    .meta-item { display: flex; align-items: center; gap: 4px; }
    
    .severity-banner { 
      display: inline-block; 
      padding: 6px 16px; 
      border-radius: 6px; 
      color: #fff; 
      font-weight: 700; 
      font-size: 12px; 
      margin: 8px 0; 
      background: ${severityInfo.color === 'text-red-400' ? '#dc2626' : severityInfo.color === 'text-orange-400' ? '#f97316' : severityInfo.color === 'text-yellow-500' ? '#eab308' : '#22c55e'};
    }
    
    .section { margin-bottom: 20px; page-break-inside: avoid; }
    .section-title { 
      font-size: 14px; 
      font-weight: 700; 
      color: #111827; 
      border-bottom: 2px solid #e5e7eb; 
      padding-bottom: 6px; 
      margin-bottom: 12px; 
      display: flex; 
      align-items: center; 
      gap: 8px; 
    }
    
    .dork-box { 
      background: #1f2937; 
      color: #10b981; 
      padding: 12px 16px; 
      border-radius: 8px; 
      font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace; 
      font-size: 11px; 
      word-break: break-all; 
      margin-bottom: 12px; 
      border-left: 4px solid #10b981; 
    }
    .dork-label { 
      font-size: 10px; 
      text-transform: uppercase; 
      letter-spacing: 0.5px; 
      color: #6b7280; 
      margin-bottom: 4px; 
      font-weight: 600; 
    }
    
    .results-table { 
      width: 100%; 
      border-collapse: collapse; 
      margin-top: 8px; 
    }
    .results-table th { 
      background: #f3f4f6; 
      padding: 8px 10px; 
      text-align: left; 
      font-size: 10px; 
      text-transform: uppercase; 
      letter-spacing: 0.5px; 
      color: #374151; 
      border-bottom: 2px solid #e5e7eb; 
      font-weight: 700; 
    }
    .results-table td { 
      padding: 8px 10px; 
      border-bottom: 1px solid #e5e7eb; 
      font-size: 11px; 
      vertical-align: top; 
    }
    .results-table tr:hover { background: #f9fafb; }
    .results-table a { color: #059669; text-decoration: none; word-break: break-all; font-size: 10px; }
    .results-table a:hover { text-decoration: underline; }
    
    .badge { 
      display: inline-block; 
      padding: 2px 6px; 
      border-radius: 4px; 
      font-size: 9px; 
      font-weight: 700; 
      text-transform: uppercase; 
    }
    .badge-validated { background: #dcfce7; color: #166534; }
    .badge-potential { background: #fef3c7; color: #92400e; }
    .badge-discarded { background: #fee2e2; color: #991b1b; }
    
    .stats-grid { 
      display: grid; 
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
      gap: 10px; 
      margin-bottom: 16px; 
    }
    .stat-card { 
      background: #f9fafb; 
      border: 1px solid #e5e7eb; 
      border-radius: 8px; 
      padding: 12px; 
      text-align: center; 
    }
    .stat-value { 
      font-size: 24px; 
      font-weight: 700; 
      color: #111827; 
    }
    .stat-label { 
      font-size: 10px; 
      text-transform: uppercase; 
      letter-spacing: 0.5px; 
      color: #6b7280; 
      margin-top: 4px; 
    }
    
    .no-results { 
      text-align: center; 
      padding: 24px; 
      color: #9ca3af; 
      font-style: italic; 
    }
    
    .footer { 
      margin-top: 30px; 
      padding-top: 16px; 
      border-top: 1px solid #e5e7eb; 
      text-align: center; 
      font-size: 9px; 
      color: #9ca3af; 
    }
    .footer p { margin: 2px 0; }
    
    .print-btn { 
      position: fixed; 
      top: 20px; 
      right: 20px; 
      background: #1f2937; 
      color: #fff; 
      border: 0; 
      border-radius: 6px; 
      padding: 10px 18px; 
      font-size: 13px; 
      cursor: pointer; 
      z-index: 1000; 
      box-shadow: 0 4px 12px rgba(0,0,0,0.15); 
    }
    .print-btn:hover { background: #374151; }
    
    .category-info { 
      background: #f0fdf4; 
      border: 1px solid #bbf7d0; 
      border-radius: 8px; 
      padding: 12px 16px; 
      margin-bottom: 16px; 
    }
    .category-info p { font-size: 11px; color: #374151; }
    
    .export-bar { 
      display: flex; 
      gap: 8px; 
      margin-bottom: 16px; 
      flex-wrap: wrap; 
    }
    .export-btn { 
      padding: 6px 14px; 
      border-radius: 6px; 
      font-size: 11px; 
      font-weight: 600; 
      cursor: pointer; 
      border: 1px solid #e5e7eb; 
      background: #fff; 
      color: #374151; 
      transition: all 0.2s; 
    }
    .export-btn:hover { background: #f3f4f6; border-color: #059669; color: #059669; }
    
    @media print { 
      .print-btn { display: none; } 
      body { padding: 0; } 
      .results-table { page-break-inside: avoid; }
      .section { page-break-inside: avoid; }
      .export-bar { display: none; }
    }
    @page { size: A4; margin: 15mm; }
  </style>
</head>
<body>
  <button class="print-btn" onclick="window.print()">🖨️ Imprimir / Guardar como PDF</button>
  
  <div class="container">
    <div class="header">
      <div class="logo">🛡️ EXECUTIVE DIGITAL PROTECTION</div>
      <div class="title">${escapeHtml(category.icon)} ${escapeHtml(category.name)}</div>
      <div class="subtitle">Módulo de Inteligencia OSINT - Protección Ejecutiva</div>
    </div>
    
    <div class="meta-bar">
      <span class="meta-item">📅 ${formatDate(timestamp)}</span>
      <span class="meta-item">🎯 Objetivo: <strong>${escapeHtml(targetName)}</strong></span>
      <span class="meta-item">📋 Categoría: ${escapeHtml(category.name)}</span>
      <span class="meta-item">🔍 Severidad: <span class="severity-banner">${severityInfo.label}</span></span>
      <span class="meta-item">📊 ${totalResults} resultados</span>
      <span class="meta-item">⚡ ${totalQueries} consultas</span>
    </div>
    
    <div class="category-info">
      <p><strong>${escapeHtml(category.description)}</strong></p>
    </div>
    
    <div class="section">
      <div class="dork-label">Consulta Dork</div>
      <div class="dork-box">${escapeHtml(dorkQuery)}</div>
    </div>
    
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">${totalResults}</div>
        <div class="stat-label">Resultados Totales</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${totalQueries}</div>
        <div class="stat-label">Consultas Ejecutadas</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${severityInfo.label}</div>
        <div class="stat-label">Nivel de Riesgo</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${results.length}</div>
        <div class="stat-label">Resultados Encontrados</div>
      </div>
    </div>
    
    <div class="section">
      <div class="section-title">
        <span>${category.icon}</span>
        Resultados de Búsqueda
      </div>
      ${renderResultsTable(results)}
    </div>
    
    <div class="section">
      <div class="section-title">📋 Resumen de la Búsqueda</div>
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value">${escapeHtml(targetName)}</div>
          <div class="stat-label">Objetivo</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${escapeHtml(category.id)}</div>
          <div class="stat-label">ID de Categoría</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${formatDate(timestamp)}</div>
          <div class="stat-label">Fecha/Hora</div>
        </div>
      </div>
    </div>
    
    <div class="footer">
      <p>Generado por Executive Digital Protection — NEXUS-INTEL OSINT Platform</p>
      <p>Este informe se generó automáticamente. Verifique los datos antes de tomar decisiones operacionales.</p>
      <p>Fuente: NEXUS-INTEL · Clasificación: CONFIDENCIAL</p>
    </div>
  </div>
  
  <script>
    window.onload = () => { window.print(); }
  </script>
</body>
</html>`;
}

export function openPrintableModule(options: PrintableModuleOptions): void {
  const html = generatePrintableModuleHTML(options);
  const win = window.open('', '_blank');
  if (win) {
    win.document.write(html);
    win.document.close();
  } else {
    alert('Permita ventanas emergentes para generar el informe imprimible.');
  }
}

export function downloadModuleAsHTML(options: PrintableModuleOptions): void {
  const html = generatePrintableModuleHTML(options);
  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `EDP_${options.category.id}_${options.targetName.replace(/[^a-zA-Z0-9]/g, '_')}.html`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function downloadModuleAsJSON(options: PrintableModuleOptions): void {
  const payload = {
    metadata: {
      exportedAt: options.timestamp,
      agent: 'Executive Digital Protection v1.0',
      category: options.category.name,
      categoryId: options.category.id,
      severity: options.category.severity,
    },
    target: {
      name: options.targetName,
      email: options.executiveEmail,
      phone: options.executivePhone,
      organization: options.executiveOrg,
    },
    dorkQuery: renderDorkQuery(options.category.dorkTemplate, options.targetName),
    results: options.results,
    totalResults: options.totalResults,
    totalQueries: options.totalQueries,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `EDP_${options.category.id}_${options.targetName.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
