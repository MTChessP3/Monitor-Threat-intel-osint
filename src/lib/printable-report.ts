'use client';

export interface PrintableReportOptions {
  moduleName: string;
  moduleIcon?: string;
  targetValue: string;
  data: Record<string, unknown>;
  timestamp?: string;
  riskLevel?: 'bajo' | 'medio' | 'alto' | 'critico' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  riskScore?: number;
  verdict?: string;
  sections?: ReportSection[];
  metadata?: ReportMetadata;
}

export interface ReportSection {
  title: string;
  icon?: string;
  content: ReportContentItem[];
}

export interface ReportContentItem {
  label: string;
  value: string | number | boolean | null | undefined;
  type?: 'text' | 'json' | 'list' | 'badge' | 'monospace';
  badgeClass?: 'normal' | 'elevated' | 'critical';
}

export interface ReportMetadata {
  source?: string;
  analysisDate?: string;
  analyst?: string;
  classification?: string;
  version?: string;
}

const RISK_LEVEL_MAP: Record<string, { label: string; color: string; dot: string }> = {
  'critico': { label: 'CRÍTICO', color: '#ef4444', dot: 'bg-red-500' },
  'CRITICAL': { label: 'CRÍTICO', color: '#ef4444', dot: 'bg-red-500' },
  'alto': { label: 'ALTO', color: '#f97316', dot: 'bg-orange-500' },
  'HIGH': { label: 'ALTO', color: '#f97316', dot: 'bg-orange-500' },
  'medio': { label: 'MEDIO', color: '#eab308', dot: 'bg-yellow-500' },
  'MEDIUM': { label: 'MEDIO', color: '#eab308', dot: 'bg-yellow-500' },
  'bajo': { label: 'BAJO', color: '#22c55e', dot: 'bg-emerald-500' },
  'LOW': { label: 'BAJO', color: '#22c55e', dot: 'bg-emerald-500' },
};

const BADGE_STYLES: Record<string, string> = {
  normal: 'background: #dcfce7; color: #166534;',
  elevated: 'background: #fef3c7; color: #92400e;',
  critical: 'background: #fee2e2; color: #991b1b;',
};

function escapeHtml(text: string): string {
  return String(text ?? '')
    .replace(/&/g, '&')
    .replace(/</g, '<')
    .replace(/>/g, '>')
    .replace(/"/g, '"')
    .replace(/'/g, '&#039;');
}

function formatDate(dateString?: string): string {
  if (!dateString) return new Date().toLocaleString('es-ES', { dateStyle: 'full', timeStyle: 'short' });
  const d = new Date(dateString);
  return Number.isNaN(d.getTime()) ? dateString : d.toLocaleString('es-ES', { dateStyle: 'full', timeStyle: 'short' });
}

function getRiskInfo(riskLevel?: string) {
  const info = RISK_LEVEL_MAP[riskLevel?.toUpperCase() || ''] || RISK_LEVEL_MAP['medio'];
  return info;
}

function renderBadge(value: string, badgeClass: string): string {
  const style = BADGE_STYLES[badgeClass] || BADGE_STYLES.normal;
  return `<span class="badge" style="${style} padding: 2px 8px; border-radius: 9999px; font-size: 10px; font-weight: 700; text-transform: uppercase;">${escapeHtml(value)}</span>`;
}

function renderDataGrid(items: ReportContentItem[]): string {
  return `
    <div class="data-grid">
      ${items.map(item => {
        let valueHtml = '';
        const label = escapeHtml(item.label);
        
        switch (item.type) {
          case 'badge':
            valueHtml = renderBadge(String(item.value), item.badgeClass || 'normal');
            break;
          case 'json':
            valueHtml = `<div class="json-block">${escapeHtml(JSON.stringify(item.value, null, 2))}</div>`;
            break;
          case 'list':
            const listItems = Array.isArray(item.value) ? item.value : [item.value];
            valueHtml = `<ul>${listItems.map(v => `<li>${escapeHtml(String(v))}</li>`).join('')}</ul>`;
            break;
          case 'monospace':
            valueHtml = `<span class="mono">${escapeHtml(String(item.value))}</span>`;
            break;
          default:
            valueHtml = escapeHtml(String(item.value ?? '—'));
        }
        
        return `
          <div class="data-card">
            <div class="data-label">${label}</div>
            <div class="data-value">${valueHtml}</div>
          </div>
        `;
      }).join('')}
    </div>
  `;
}

function renderSection(section: ReportSection): string {
  const icon = section.icon ? `<span>${section.icon}</span>` : '';
  const contentHtml = renderDataGrid(section.content);
  return `
    <div class="section">
      <div class="section-title">${icon} ${escapeHtml(section.title)}</div>
      ${contentHtml}
    </div>
  `;
}

function renderFullDataJson(data: Record<string, unknown>): string {
  return `
    <div class="section">
      <div class="section-title">📊 Datos Completos del Análisis</div>
      <div class="json-block">${escapeHtml(JSON.stringify(data, null, 2)).slice(0, 50000)}</div>
    </div>
  `;
}

export function generatePrintableReport(options: PrintableReportOptions): string {
  const {
    moduleName,
    moduleIcon = '🛡️',
    targetValue,
    data,
    timestamp,
    riskLevel,
    riskScore,
    verdict,
    sections = [],
    metadata = {},
  } = options;

  const generatedAt = timestamp || new Date().toISOString();
  const formattedTimestamp = formatDate(generatedAt);
  const riskInfo = getRiskInfo(riskLevel);
  const riskColor = riskInfo.color;
  const riskLabel = riskInfo.label;
  const score = riskScore ?? 0;

  const classification = metadata.classification || 'CLASIFICADO';
  const source = metadata.source || 'NEXUS-INTEL OSINT Platform';
  const version = metadata.version || '1.0';

  const sectionsHtml = sections.length > 0
    ? sections.map(renderSection).join('\n')
    : renderFullDataJson(data);

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${moduleName} - Informe Imprimible | NEXUS-INTEL</title>
  <style>
    * { box-sizing: border-box; }
    body { 
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; 
      margin: 0; 
      padding: 24px; 
      background: #fff; 
      color: #1f2937; 
      line-height: 1.6; 
      font-size: 12px; 
    }
    .report { max-width: 900px; margin: 0 auto; }
    .header { 
      border-bottom: 3px solid #059669; 
      padding-bottom: 20px; 
      margin-bottom: 30px; 
      text-align: center; 
    }
    .logo { 
      font-size: 24px; 
      font-weight: 800; 
      color: #059669; 
      margin-bottom: 8px; 
    }
    .title { 
      font-size: 26px; 
      font-weight: 700; 
      color: #111827; 
      margin-bottom: 4px; 
    }
    .subtitle { 
      color: #6b7280; 
      font-size: 13px; 
      margin-bottom: 16px;
    }
    .meta { 
      display: flex; 
      justify-content: center; 
      gap: 20px; 
      flex-wrap: wrap; 
      font-size: 12px; 
      color: #6b7280; 
    }
    .meta-item { display: flex; align-items: center; gap: 6px; }
    
    .risk-banner { 
      display: inline-block; 
      padding: 8px 20px; 
      border-radius: 8px; 
      color: #fff; 
      font-weight: 700; 
      font-size: 13px; 
      margin: 12px 0; 
      background: ${riskColor};
    }
    .scorebar { 
      height: 10px; 
      background: #e5e7eb; 
      border-radius: 5px; 
      overflow: hidden; 
      margin: 8px 0 4px; 
      max-width: 300px;
      margin-left: auto;
      margin-right: auto;
    }
    .scorebar > div { 
      height: 100%; 
      background: ${riskColor};
      width: ${Math.max(score, 2)}%; 
      transition: width 0.3s ease;
    }
    .verdict-box { 
      background: #f9fafb; 
      border-left: 4px solid ${riskColor}; 
      padding: 12px 16px; 
      border-radius: 4px; 
      margin: 16px 0;
      font-size: 13px;
    }
    .verdict-box strong { color: #111827; }
    
    .section { margin-bottom: 28px; page-break-inside: avoid; }
    .section-title { 
      font-size: 16px; 
      font-weight: 700; 
      color: #111827; 
      border-bottom: 2px solid #e5e7eb; 
      padding-bottom: 8px; 
      margin-bottom: 16px; 
      display: flex; 
      align-items: center; 
      gap: 8px; 
    }
    .data-grid { 
      display: grid; 
      grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); 
      gap: 12px; 
    }
    .data-card { 
      background: #f9fafb; 
      border: 1px solid #e5e7eb; 
      border-radius: 8px; 
      padding: 12px 16px; 
      page-break-inside: avoid;
    }
    .data-label { 
      font-size: 10px; 
      text-transform: uppercase; 
      letter-spacing: 0.5px; 
      color: #6b7280; 
      margin-bottom: 4px; 
      font-weight: 600;
    }
    .data-value { 
      font-weight: 600; 
      color: #111827; 
      word-break: break-word; 
      font-size: 12px; 
    }
    .mono { 
      font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace; 
      font-size: 11px; 
      background: #f3f4f6; 
      padding: 2px 6px; 
      border-radius: 4px;
    }
    .json-block { 
      background: #111827; 
      color: #10b981; 
      padding: 16px; 
      border-radius: 8px; 
      font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace; 
      font-size: 10px; 
      overflow-x: auto; 
      white-space: pre-wrap; 
      max-height: 400px; 
      overflow-y: auto; 
      line-height: 1.5;
    }
    .badge { 
      display: inline-block; 
      padding: 2px 8px; 
      border-radius: 9999px; 
      font-size: 10px; 
      font-weight: 700; 
      text-transform: uppercase; 
    }
    ul { margin: 4px 0; padding-left: 20px; }
    li { margin: 2px 0; font-size: 11px; }
    a { color: #059669; text-decoration: none; }
    a:hover { text-decoration: underline; }
    
    .footer { 
      margin-top: 40px; 
      padding-top: 20px; 
      border-top: 1px solid #e5e7eb; 
      text-align: center; 
      font-size: 10px; 
      color: #9ca3af; 
    }
    .footer p { margin: 4px 0; }
    
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
    
    @media print { 
      .print-btn { display: none; } 
      body { padding: 0; } 
      .data-card { break-inside: avoid; }
      .section { break-inside: avoid; }
    }
    @page { size: A4; margin: 15mm; }
  </style>
</head>
<body>
  <div class="report">
    <button class="print-btn" onclick="window.print()">🖨️ Imprimir / Guardar como PDF</button>
    
    <div class="header">
      <div class="logo">${moduleIcon} NEXUS-INTEL</div>
      <div class="title">Informe de Inteligencia: ${escapeHtml(moduleName)}</div>
      <div class="subtitle">Plataforma de Inteligencia de Amenazas y Protección Ejecutiva</div>
      <div class="meta">
        <span class="meta-item">📅 Generado: ${formattedTimestamp}</span>
        <span class="meta-item">🎯 Objetivo: ${escapeHtml(targetValue)}</span>
        <span class="meta-item">🔍 Módulo: ${escapeHtml(moduleName)}</span>
        <span class="meta-item">📋 Clasificación: ${escapeHtml(classification)}</span>
        <span class="meta-item">🔖 Versión: ${escapeHtml(version)}</span>
      </div>
    </div>

    <div class="risk-banner">${riskLabel} (${score}/100)</div>
    <div class="scorebar"><div></div></div>
    <div class="verdict-box"><strong>Veredicto:</strong> ${escapeHtml(verdict || 'Análisis completado sin hallazgos críticos')}</div>

    <div class="section">
      <div class="section-title">📋 Resumen Ejecutivo</div>
      <div class="data-grid">
        <div class="data-card"><div class="data-label">Módulo</div><div class="data-value">${escapeHtml(moduleName)}</div></div>
        <div class="data-card"><div class="data-label">Fecha/Hora (UTC)</div><div class="data-value">${new Date(generatedAt).toISOString()}</div></div>
        <div class="data-card"><div class="data-label">Objetivo Analizado</div><div class="data-value mono">${escapeHtml(targetValue)}</div></div>
        <div class="data-card"><div class="data-label">Nivel de Riesgo</div><div class="data-value">${renderBadge(riskLabel, riskLevel?.toLowerCase().includes('crit') || riskLevel?.toUpperCase() === 'CRITICAL' ? 'critical' : riskLevel?.toLowerCase().includes('alto') || riskLevel?.toUpperCase() === 'HIGH' ? 'elevated' : 'normal')}</div></div>
        <div class="data-card"><div class="data-label">Puntuación</div><div class="data-value mono">${score}/100</div></div>
        <div class="data-card"><div class="data-label">Fuente</div><div class="data-value">${escapeHtml(source)}</div></div>
      </div>
    </div>

    ${sectionsHtml}

    <div class="footer">
      <p>Generado por NEXUS-INTEL — Plataforma de Inteligencia de Amenazas y Protección Ejecutiva v${version}</p>
      <p>Este informe se generó automáticamente. Verifique los datos antes de tomar decisiones operacionales.</p>
      <p>Fuente: ${escapeHtml(source)} · Clasificación: ${escapeHtml(classification)}</p>
    </div>
  </div>
  
  <script>
    window.onload = () => { window.print(); }
  </script>
</body>
</html>`;
}

export function openPrintReport(options: PrintableReportOptions): void {
  const html = generatePrintableReport(options);
  const win = window.open('', '_blank');
  if (win) {
    win.document.write(html);
    win.document.close();
  } else {
    alert('Permita ventanas emergentes para generar el informe imprimible.');
  }
}

export function createReportSectionsFromData(data: Record<string, unknown>, sectionMapping: Record<string, { title: string; icon?: string; fields: string[] }>): ReportSection[] {
  return Object.entries(sectionMapping)
    .map(([key, config]) => {
      const sectionData = data[key];
      if (!sectionData) return null;
      
      const items: ReportContentItem[] = config.fields
        .map(field => {
          const value = (sectionData as Record<string, unknown>)[field];
          if (value === undefined || value === null) return null;
          
          let type: ReportContentItem['type'] = 'text';
          let badgeClass: ReportContentItem['badgeClass'] = 'normal';
          
          if (field.toLowerCase().includes('risk') || field.toLowerCase().includes('level') || field.toLowerCase().includes('severity')) {
            type = 'badge';
            const strVal = String(value).toLowerCase();
            if (strVal.includes('crit') || strVal.includes('high') || strVal === 'alto' || strVal === 'critico') badgeClass = 'critical';
            else if (strVal.includes('medium') || strVal.includes('medio')) badgeClass = 'elevated';
            else badgeClass = 'normal';
          } else if (typeof value === 'object') {
            type = 'json';
          } else if (Array.isArray(value)) {
            type = 'list';
          } else if (typeof value === 'string' && (value.includes('.') || value.includes(':') || /^[A-Fa-f0-9]{32,64}$/.test(value))) {
            type = 'monospace';
          }
          
          return { label: field, value, type, badgeClass };
        })
        .filter((item): item is ReportContentItem => item !== null);
      
      if (items.length === 0) return null;
      
      return { title: config.title, icon: config.icon, content: items };
    })
    .filter((section): section is ReportSection => section !== null);
}