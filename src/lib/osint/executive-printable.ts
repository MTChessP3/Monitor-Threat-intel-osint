// ============================================================================
// Executive Digital Protection - Printable HTML Module Generator
// ============================================================================
// Generates printable HTML modules for each dork category with PDF download
// and consolidated full report generation

import { ExecutiveDorkCategory, EXECUTIVE_DORK_CATEGORIES, SEVERITY_LABELS } from './executive-dork-categories';

export interface SocialMediaEntry {
  platform: string;
  url: string;
  handle: string;
  type: string;
}

export interface ExecutiveProfileData {
  name: string;
  email: string;
  phone: string;
  organization: string;
  address: string;
  location: string;
  socialMedia: SocialMediaEntry[];
  emailType: string;
  identificationNum: string;
  position: string;
}

export interface PrintableModuleOptions {
  category: ExecutiveDorkCategory;
  targetName: string;
  executiveEmail?: string;
  executivePhone?: string;
  executiveOrg?: string;
  executiveAddress?: string;
  executiveLocation?: string;
  executiveSocialMedia?: SocialMediaEntry[];
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

export interface FullReportData {
  executive: ExecutiveProfileData;
  modules: Array<{
    category: ExecutiveDorkCategory;
    moduleStatus: { executed: boolean; results: DorkResult[]; timestamp: string; totalResults: number } | undefined;
  }>;
  allResults: DorkResult[];
  timestamp: string;
  totalQueries: number;
  totalResults: number;
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

function renderSocialMedia(socialMedia: SocialMediaEntry[]): string {
  if (!socialMedia || socialMedia.length === 0) return '<p>No registradas</p>';
  return `
    <div class="social-grid">
      ${socialMedia.map(s => `
        <div class="social-item">
          <span class="social-platform">${escapeHtml(s.platform)}</span>
          <a href="${escapeHtml(s.url)}" target="_blank" class="social-url">${escapeHtml(s.url)}</a>
          <span class="social-handle">@${escapeHtml(s.handle)}</span>
        </div>
      `).join('')}
    </div>
  `;
}

// ============================================================================
// Individual Module HTML Generator
// ============================================================================
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
    body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #ffffff; color: #1f2937; line-height: 1.6; font-size: 11px; padding: 20px; }
    .container { max-width: 1000px; margin: 0 auto; }
    .header { border-bottom: 3px solid #059669; padding-bottom: 16px; margin-bottom: 20px; text-align: center; }
    .logo { font-size: 20px; font-weight: 800; color: #059669; margin-bottom: 6px; }
    .title { font-size: 22px; font-weight: 700; color: #111827; margin-bottom: 4px; }
    .subtitle { color: #6b7280; font-size: 12px; }
    .meta-bar { display: flex; justify-content: center; gap: 16px; flex-wrap: wrap; font-size: 11px; color: #6b7280; margin-bottom: 16px; padding: 10px; background: #f9fafb; border-radius: 8px; }
    .meta-item { display: flex; align-items: center; gap: 4px; }
    .severity-banner { display: inline-block; padding: 6px 16px; border-radius: 6px; color: #fff; font-weight: 700; font-size: 12px; margin: 8px 0; background: ${severityInfo.color === 'text-red-400' ? '#dc2626' : severityInfo.color === 'text-orange-400' ? '#f97316' : severityInfo.color === 'text-yellow-500' ? '#eab308' : '#22c55e'}; }
    .section { margin-bottom: 20px; page-break-inside: avoid; }
    .section-title { font-size: 14px; font-weight: 700; color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 6px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
    .dork-box { background: #1f2937; color: #10b981; padding: 12px 16px; border-radius: 8px; font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace; font-size: 11px; word-break: break-all; margin-bottom: 12px; border-left: 4px solid #10b981; }
    .dork-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: #6b7280; margin-bottom: 4px; font-weight: 600; }
    .results-table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    .results-table th { background: #f3f4f6; padding: 8px 10px; text-align: left; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: #374151; border-bottom: 2px solid #e5e7eb; font-weight: 700; }
    .results-table td { padding: 8px 10px; border-bottom: 1px solid #e5e7eb; font-size: 11px; vertical-align: top; }
    .results-table tr:hover { background: #f9fafb; }
    .results-table a { color: #059669; text-decoration: none; word-break: break-all; font-size: 10px; }
    .results-table a:hover { text-decoration: underline; }
    .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: 700; text-transform: uppercase; }
    .badge-validated { background: #dcfce7; color: #166534; }
    .badge-potential { background: #fef3c7; color: #92400e; }
    .badge-discarded { background: #fee2e2; color: #991b1b; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 16px; }
    .stat-card { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; text-align: center; }
    .stat-value { font-size: 24px; font-weight: 700; color: #111827; }
    .stat-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: #6b7280; margin-top: 4px; }
    .no-results { text-align: center; padding: 24px; color: #9ca3af; font-style: italic; }
    .footer { margin-top: 30px; padding-top: 16px; border-top: 1px solid #e5e7eb; text-align: center; font-size: 9px; color: #9ca3af; }
    .footer p { margin: 2px 0; }
    .print-btn { position: fixed; top: 20px; right: 20px; background: #1f2937; color: #fff; border: 0; border-radius: 6px; padding: 10px 18px; font-size: 13px; cursor: pointer; z-index: 1000; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
    .print-btn:hover { background: #374151; }
    .category-info { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; }
    .category-info p { font-size: 11px; color: #374151; }
    .export-bar { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
    .export-btn { padding: 6px 14px; border-radius: 6px; font-size: 11px; font-weight: 600; cursor: pointer; border: 1px solid #e5e7eb; background: #fff; color: #374151; transition: all 0.2s; }
    .export-btn:hover { background: #f3f4f6; border-color: #059669; color: #059669; }
    .social-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px; }
    .social-item { padding: 8px; background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px; }
    .social-platform { font-weight: 700; font-size: 11px; color: #111827; }
    .social-url { display: block; font-size: 10px; color: #059669; word-break: break-all; }
    .social-handle { display: block; font-size: 9px; color: #6b7280; }
    .executive-info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-bottom: 16px; }
    .executive-info-item { padding: 10px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; }
    .executive-info-label { font-size: 9px; text-transform: uppercase; color: #6b7280; font-weight: 600; }
    .executive-info-value { font-size: 12px; font-weight: 700; color: #111827; word-break: break-all; }
    @media print { .print-btn { display: none; } body { padding: 0; } .results-table { page-break-inside: avoid; } .section { page-break-inside: avoid; } .export-bar { display: none; } }
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
    
    ${options.executiveAddress || options.executiveLocation || options.executiveSocialMedia ? `
    <div class="executive-info-grid">
      ${options.executiveAddress ? `<div class="executive-info-item"><div class="executive-info-label">📍 Dirección</div><div class="executive-info-value">${escapeHtml(options.executiveAddress)}</div></div>` : ''}
      ${options.executiveLocation ? `<div class="executive-info-item"><div class="executive-info-label">🌐 Ubicación</div><div class="executive-info-value">${escapeHtml(options.executiveLocation)}</div></div>` : ''}
      ${options.executiveSocialMedia && options.executiveSocialMedia.length > 0 ? `<div class="executive-info-item" style="grid-column: span 2;"><div class="executive-info-label">📱 Redes Sociales (${options.executiveSocialMedia.length})</div>${renderSocialMedia(options.executiveSocialMedia)}</div>` : ''}
    </div>
    ` : ''}
    
    <div class="category-info">
      <p><strong>${escapeHtml(category.description)}</strong></p>
    </div>
    
    <div class="section">
      <div class="dork-label">Consulta Dork</div>
      <div class="dork-box">${escapeHtml(dorkQuery)}</div>
    </div>
    
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-value">${totalResults}</div><div class="stat-label">Resultados Totales</div></div>
      <div class="stat-card"><div class="stat-value">${totalQueries}</div><div class="stat-label">Consultas Ejecutadas</div></div>
      <div class="stat-card"><div class="stat-value">${severityInfo.label}</div><div class="stat-label">Nivel de Riesgo</div></div>
      <div class="stat-card"><div class="stat-value">${results.length}</div><div class="stat-label">Resultados Encontrados</div></div>
    </div>
    
    <div class="section">
      <div class="section-title"><span>${category.icon}</span> Resultados de Búsqueda</div>
      ${renderResultsTable(results)}
    </div>
    
    <div class="section">
      <div class="section-title">📋 Resumen de la Búsqueda</div>
      <div class="stats-grid">
        <div class="stat-card"><div class="stat-value">${escapeHtml(targetName)}</div><div class="stat-label">Objetivo</div></div>
        <div class="stat-card"><div class="stat-value">${escapeHtml(category.id)}</div><div class="stat-label">ID de Categoría</div></div>
        <div class="stat-card"><div class="stat-value">${formatDate(timestamp)}</div><div class="stat-label">Fecha/Hora</div></div>
      </div>
    </div>
    
    <div class="footer">
      <p>Generado por Executive Digital Protection — NEXUS-INTEL OSINT Platform</p>
      <p>Este informe se generó automáticamente. Verifique los datos antes de tomar decisiones operacionales.</p>
      <p>Fuente: NEXUS-INTEL · Clasificación: CONFIDENCIAL</p>
    </div>
  </div>
  
  <script>window.onload = () => { window.print(); }</script>
</body>
</html>`;
}

// ============================================================================
// Full Consolidated Report Generator
// ============================================================================
export function generateFullReportHTML(reportData: FullReportData): string {
  const { executive, modules, allResults, timestamp, totalQueries, totalResults } = reportData;
  const severityInfo = getSeverityInfo('MEDIUM');

  const executedModules = modules.filter(m => m.moduleStatus?.executed);

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Informe Completo - ${escapeHtml(executive.name)} | Executive Digital Protection</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #ffffff; color: #1f2937; line-height: 1.6; font-size: 11px; padding: 20px; }
    .container { max-width: 1200px; margin: 0 auto; }
    .header { border-bottom: 4px solid #059669; padding-bottom: 20px; margin-bottom: 24px; text-align: center; }
    .logo { font-size: 24px; font-weight: 800; color: #059669; margin-bottom: 8px; }
    .title { font-size: 28px; font-weight: 700; color: #111827; margin-bottom: 4px; }
    .subtitle { color: #6b7280; font-size: 14px; }
    .meta-bar { display: flex; justify-content: center; gap: 20px; flex-wrap: wrap; font-size: 12px; color: #6b7280; margin-bottom: 20px; padding: 14px; background: #f9fafb; border-radius: 8px; }
    .meta-item { display: flex; align-items: center; gap: 6px; }
    .severity-banner { display: inline-block; padding: 8px 20px; border-radius: 6px; color: #fff; font-weight: 700; font-size: 14px; margin: 8px 0; background: #d97706; }
    .section { margin-bottom: 28px; page-break-inside: avoid; }
    .section-title { font-size: 16px; font-weight: 700; color: #111827; border-bottom: 3px solid #e5e7eb; padding-bottom: 8px; margin-bottom: 16px; display: flex; align-items: center; gap: 10px; }
    .dork-box { background: #1f2937; color: #10b981; padding: 14px 18px; border-radius: 8px; font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace; font-size: 12px; word-break: break-all; margin-bottom: 14px; border-left: 4px solid #10b981; }
    .dork-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #6b7280; margin-bottom: 6px; font-weight: 600; }
    .results-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    .results-table th { background: #f3f4f6; padding: 10px 12px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #374151; border-bottom: 2px solid #e5e7eb; font-weight: 700; }
    .results-table td { padding: 10px 12px; border-bottom: 1px solid #e5e7eb; font-size: 12px; vertical-align: top; }
    .results-table tr:hover { background: #f9fafb; }
    .results-table a { color: #059669; text-decoration: none; word-break: break-all; font-size: 11px; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
    .badge-validated { background: #dcfce7; color: #166534; }
    .badge-potential { background: #fef3c7; color: #92400e; }
    .badge-discarded { background: #fee2e2; color: #991b1b; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }
    .stat-card { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 14px; text-align: center; }
    .stat-value { font-size: 28px; font-weight: 700; color: #111827; }
    .stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #6b7280; margin-top: 4px; }
    .no-results { text-align: center; padding: 24px; color: #9ca3af; font-style: italic; }
    .footer { margin-top: 30px; padding-top: 20px; border-top: 2px solid #e5e7eb; text-align: center; font-size: 10px; color: #9ca3af; }
    .footer p { margin: 2px 0; }
    .print-btn { position: fixed; top: 20px; right: 20px; background: #1f2937; color: #fff; border: 0; border-radius: 6px; padding: 12px 20px; font-size: 14px; cursor: pointer; z-index: 1000; box-shadow: 0 4px 12px rgba(0,0,0,0.15); font-weight: 700; }
    .print-btn:hover { background: #374151; }
    .category-info { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 14px 18px; margin-bottom: 16px; }
    .category-info p { font-size: 12px; color: #374151; }
    .export-bar { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
    .export-btn { padding: 8px 16px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; border: 1px solid #e5e7eb; background: #fff; color: #374151; }
    .export-btn:hover { background: #f3f4f6; border-color: #059669; color: #059669; }
    .social-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; }
    .social-item { padding: 10px; background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; }
    .social-platform { font-weight: 700; font-size: 12px; color: #111827; }
    .social-url { display: block; font-size: 11px; color: #059669; word-break: break-all; }
    .social-handle { display: block; font-size: 10px; color: #6b7280; }
    .executive-profile-card { background: linear-gradient(135deg, #f0fdf4 0%, #ecfdf5 100%); border: 2px solid #86efac; border-radius: 12px; padding: 20px; margin-bottom: 24px; }
    .executive-profile-card h3 { font-size: 18px; color: #065f46; margin-bottom: 12px; }
    .executive-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; }
    .executive-detail { padding: 10px; }
    .executive-detail-label { font-size: 10px; text-transform: uppercase; color: #065f46; font-weight: 700; margin-bottom: 4px; }
    .executive-detail-value { font-size: 13px; font-weight: 600; color: #111827; word-break: break-all; }
    .progress-bar-container { height: 8px; background: #e5e7eb; border-radius: 4px; overflow: hidden; margin: 8px 0; }
    .progress-bar { height: 100%; background: #059669; border-radius: 4px; transition: width 0.5s; }
    .module-card { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    .module-card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
    .module-card-title { font-size: 14px; font-weight: 700; color: #111827; }
    .module-card-body { font-size: 11px; color: #6b7280; }
    @media print { .print-btn { display: none; } body { padding: 0; } .results-table { page-break-inside: avoid; } .section { page-break-inside: avoid; } .export-bar { display: none; } }
    @page { size: A4; margin: 15mm; }
  </style>
</head>
<body>
  <button class="print-btn" onclick="window.print()">🖨️ Imprimir Informe Completo</button>
  
  <div class="container">
    <div class="header">
      <div class="logo">🛡️ EXECUTIVE DIGITAL PROTECTION</div>
      <div class="title">Informe Completo de Protección Ejecutiva</div>
      <div class="subtitle">Módulo de Inteligencia OSINT — Reporte Consolidado</div>
    </div>
    
    <div class="meta-bar">
      <span class="meta-item">📅 ${formatDate(timestamp)}</span>
      <span class="meta-item">🎯 Objetivo: <strong>${escapeHtml(executive.name)}</strong></span>
      <span class="meta-item">📊 ${totalResults} resultados totales</span>
      <span class="meta-item">⚡ ${totalQueries} consultas</span>
      <span class="meta-item">✅ ${executedModules.length}/${modules.length} módulos ejecutados</span>
    </div>
    
    <!-- Executive Profile Section -->
    <div class="executive-profile-card">
      <h3>👤 Perfil del Ejecutivo</h3>
      <div class="executive-grid">
        <div class="executive-detail">
          <div class="executive-detail-label">Nombre Completo</div>
          <div class="executive-detail-value">${escapeHtml(executive.name)}</div>
        </div>
        ${executive.identificationNum ? `<div class="executive-detail"><div class="executive-detail-label">ID / Documento</div><div class="executive-detail-value">${escapeHtml(executive.identificationNum)}</div></div>` : ''}
        <div class="executive-detail">
          <div class="executive-detail-label">Email</div>
          <div class="executive-detail-value">${escapeHtml(executive.email) || 'No registrado'}</div>
          <div class="executive-detail-label" style="margin-top:4px">Tipo: ${escapeHtml(executive.emailType)}</div>
        </div>
        <div class="executive-detail">
          <div class="executive-detail-label">Teléfono</div>
          <div class="executive-detail-value">${escapeHtml(executive.phone) || 'No registrado'}</div>
        </div>
        <div class="executive-detail">
          <div class="executive-detail-label">Organización</div>
          <div class="executive-detail-value">${escapeHtml(executive.organization) || 'No registrado'}</div>
        </div>
        <div class="executive-detail">
          <div class="executive-detail-label">Dirección</div>
          <div class="executive-detail-value">${escapeHtml(executive.address) || 'No registrado'}</div>
        </div>
        <div class="executive-detail">
          <div class="executive-detail-label">Ubicación</div>
          <div class="executive-detail-value">${escapeHtml(executive.location) || 'No registrado'}</div>
        </div>
        <div class="executive-detail" style="grid-column: span 2;">
          <div class="executive-detail-label">Redes Sociales (${executive.socialMedia.length})</div>
          <div class="social-grid">
            ${executive.socialMedia.map(s => `
              <div class="social-item">
                <span class="social-platform">${escapeHtml(s.platform)}</span>
                <a href="${escapeHtml(s.url)}" target="_blank" class="social-url">${escapeHtml(s.url)}</a>
                <span class="social-handle">@${escapeHtml(s.handle)}</span>
              </div>
            `).join('')}
            ${executive.socialMedia.length === 0 ? '<span style="color:#9ca3af;font-size:11px">No registradas</span>' : ''}
          </div>
        </div>
      </div>
    </div>
    
    <!-- Progress Overview -->
    <div class="section">
      <div class="section-title">📊 Progreso de Búsqueda</div>
      <div class="stats-grid">
        <div class="stat-card"><div class="stat-value">${executedModules.length}</div><div class="stat-label">Módulos Completados</div></div>
        <div class="stat-card"><div class="stat-value">${modules.length - executedModules.length}</div><div class="stat-label">Pendientes</div></div>
        <div class="stat-card"><div class="stat-value">${totalQueries}</div><div class="stat-label">Consultas Totales</div></div>
        <div class="stat-card"><div class="stat-value">${totalResults}</div><div class="stat-label">Resultados</div></div>
      </div>
      <div class="progress-bar-container">
        <div class="progress-bar" style="width: ${(executedModules.length / modules.length) * 100}%"></div>
      </div>
    </div>
    
    <!-- Modules Section — One per category -->
    <div class="section">
      <div class="section-title">📋 Secciones de Búsqueda por Categoría</div>
      ${modules.map(({ category, moduleStatus }) => {
        if (!moduleStatus?.executed) return '';
        const severityInfo = getSeverityInfo(category.severity);
        return `
          <div class="module-card">
            <div class="module-card-header">
              <span class="module-card-title">${category.icon} ${escapeHtml(category.name)}</span>
              <span class="severity-banner">${severityInfo.label}</span>
            </div>
            <div class="module-card-body">
              <div class="dork-box">${escapeHtml(renderDorkQuery(category.dorkTemplate, executive.name))}</div>
              <p>Resultados: ${moduleStatus.totalResults} | Ejecutado: ${formatDate(moduleStatus.timestamp)}</p>
              <div class="results-table">
                <thead>
                  <tr><th>#</th><th>Título</th><th>URL</th><th>Fuente</th><th>Clasificación</th></tr>
                </thead>
                <tbody>
                  ${moduleStatus.results.map(r => `
                    <tr>
                      <td>${r.position}</td>
                      <td>${escapeHtml(r.title)}</td>
                      <td><a href="${escapeHtml(r.url)}" target="_blank">${escapeHtml(r.url)}</a></td>
                      <td>${escapeHtml(r.source)}</td>
                      <td><span class="badge badge-${r.classification}">${r.classification.toUpperCase()}</span></td>
                    </tr>
                  `).join('')}
                  ${moduleStatus.results.length === 0 ? '<tr><td colspan="5" class="no-results">Sin resultados</td></tr>' : ''}
                </tbody>
              </div>
            </div>
          </div>
        `;
      }).join('')}
    </div>
    
    <!-- Summary Results -->
    <div class="section">
      <div class="section-title">📈 Resumen Global de Resultados</div>
      <div class="stats-grid">
        <div class="stat-card"><div class="stat-value">${allResults.length}</div><div class="stat-label">Total Resultados</div></div>
        <div class="stat-card"><div class="stat-value">${modules.length}</div><div class="stat-label">Categorías</div></div>
        <div class="stat-card"><div class="stat-value">${executedModules.filter(m => m.moduleStatus?.results.some(r => r.classification === 'validated')).length}</div><div class="stat-label">Con Resultados Validados</div></div>
        <div class="stat-card"><div class="stat-value">${executedModules.filter(m => m.moduleStatus?.results.some(r => r.classification === 'potential')).length}</div><div class="stat-label">Con Resultados Potenciales</div></div>
      </div>
      <div class="category-info">
        <p><strong>Este informe fue generado automáticamente por Executive Digital Protection.</strong> Todas las búsquedas Dork OSINT se han ejecutado por categoría. El informe está estructurado por sección para facilitar la revisión y la exportación a PDF.</p>
      </div>
    </div>
    
    <div class="footer">
      <p>Generado por Executive Digital Protection — NEXUS-INTEL OSINT Platform</p>
      <p>Informe Completo · Clasificación: CONFIDENCIAL</p>
      <p>Fecha de generación: ${formatDate(timestamp)}</p>
      <p>Este informe se generó automáticamente. Verifique los datos antes de tomar decisiones operacionales.</p>
    </div>
  </div>
  
  <script>window.onload = () => { window.print(); }</script>
</body>
</html>`;
}

// ============================================================================
// Export functions
// ============================================================================
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

export function openFullReport(reportData: FullReportData): void {
  const html = generateFullReportHTML(reportData);
  const win = window.open('', '_blank');
  if (win) {
    win.document.write(html);
    win.document.close();
  } else {
    alert('Permita ventanas emergentes para generar el informe completo.');
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

export function downloadFullReportAsHTML(reportData: FullReportData): void {
  const html = generateFullReportHTML(reportData);
  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `Informe_Completo_${reportData.executive.name.replace(/[^a-zA-Z0-9]/g, '_')}.html`;
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
      address: options.executiveAddress,
      location: options.executiveLocation,
    },
    socialMedia: options.executiveSocialMedia,
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
