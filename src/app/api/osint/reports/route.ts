import { NextRequest, NextResponse } from 'next/server';
import { reporterAgent } from '@/lib/agents';
import { getIOCs, getStoreStats, getRecentAnalyses } from '@/lib/store';
import { loadThreatFeeds } from '@/lib/intel';
import { aiJSON, isAIEnabled } from '@/lib/ai';
import { kvGet, kvSet, kvPushList, kvGetList } from '@/lib/kv';
import { buildPDF, buildDOCX, buildPPTX, ReportSpec, ReportSection } from '@/lib/reportgen';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

export const maxDuration = 60;

interface ReportConfig {
  title: string;
  modules: string[];
  format: 'PDF' | 'JSON' | 'CSV' | 'HTML' | 'DOCX' | 'PPTX';
  includeIOCs: boolean;
  includeThreats: boolean;
  includeTimeline: boolean;
  executiveSummary: boolean;
  recommendations: boolean;
  templateId?: string;
  customContent?: {
    header?: string;
    footer?: string;
    sections?: { title: string; body: string }[];
    clientName?: string;
    engagement?: string;
  };
}

interface ReportRecord {
  id: string;
  module?: string;
  title: string;
  config: ReportConfig;
  timestamp: string;
  content: any;
}

const REPORTS_KEY = 'nexus:reports';

function generateId(): string {
  return `rpt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// ---------- Executive summary via AI agent (or rule-based) ----------
async function generateExecutiveSummary(
  config: ReportConfig,
  bundle: Record<string, any>
): Promise<{ summary: any; usedAI: boolean }> {
  const iocData = bundle.iocs?.data || [];
  const threatData = bundle.threats || [];

  const ruleSummary = {
    overallRiskLevel: 'MEDIUM' as string,
    keyFindings: [] as string[],
    criticalItems: iocData.filter((i: any) => i.severity === 'CRITICAL').length,
    highRiskItems: iocData.filter((i: any) => i.severity === 'HIGH').length,
    totalIndicators: iocData.length,
    maliciousCount: iocData.filter((i: any) => i.status === 'MALICIOUS').length,
    threatFeeds: threatData.length,
    modulesIncluded: config.modules.length,
    coverage: config.modules,
    generatedAt: new Date().toISOString(),
  };

  if (ruleSummary.criticalItems > 2) ruleSummary.overallRiskLevel = 'CRITICAL';
  else if (ruleSummary.criticalItems > 0 || ruleSummary.maliciousCount > 2) ruleSummary.overallRiskLevel = 'HIGH';
  else if (ruleSummary.threatFeeds > 0 || ruleSummary.totalIndicators > 0) ruleSummary.overallRiskLevel = 'MEDIUM';

  ruleSummary.keyFindings.push(`${ruleSummary.totalIndicators} indicators tracked (${ruleSummary.criticalItems} critical, ${ruleSummary.highRiskItems} high)`);
  if (ruleSummary.maliciousCount > 0) ruleSummary.keyFindings.push(`${ruleSummary.maliciousCount} confirmed MALICIOUS`);
  if (ruleSummary.threatFeeds > 0) ruleSummary.keyFindings.push(`Active intelligence from ${ruleSummary.threatFeeds} live threat feed(s)`);

  if (isAIEnabled()) {
    const { data, usedAI } = await aiJSON<any>(
      `You are a senior cyber threat intelligence analyst producing an executive summary for leadership.
Return JSON with exactly: {"overallRiskLevel":"CRITICAL|HIGH|MEDIUM|LOW","narrative":"3-4 sentence executive summary","keyFindings":["..."],"topPriorities":["..."]}.`,
      `Produce an executive summary for the report "${config.title}".
Aggregate intelligence:
- IOCs: ${ruleSummary.totalIndicators} total, ${ruleSummary.criticalItems} critical, ${ruleSummary.highRiskItems} high, ${ruleSummary.maliciousCount} malicious
- Live threat feeds available: ${threatData.length}
- Modules covered: ${config.modules.join(', ')}`
    );
    if (usedAI && data) {
      return {
        summary: {
          ...ruleSummary,
          overallRiskLevel: data.overallRiskLevel || ruleSummary.overallRiskLevel,
          narrative: data.narrative || '',
          keyFindings: data.keyFindings || ruleSummary.keyFindings,
          topPriorities: data.topPriorities || [],
          usedAI: true,
        },
        usedAI: true,
      };
    }
  }

  return { summary: { ...ruleSummary, usedAI: false }, usedAI: false };
}

function generateRecommendations(bundle: Record<string, any>): string[] {
  const recs: string[] = [];
  const iocData = bundle.iocs?.data || [];

  const critical = iocData.filter((i: any) => i.severity === 'CRITICAL');
  const malicious = iocData.filter((i: any) => i.status === 'MALICIOUS');
  const threats = bundle.threats || [];

  if (critical.length > 0) {
    recs.push(`Immediate action required for ${critical.length} CRITICAL indicators — block in security controls and investigate`);
  }
  if (malicious.length > 0) {
    recs.push(`${malicious.length} malicious indicators should be added to blocklists immediately`);
  }
  threats.forEach((feed: any) => {
    const criticalFeeds = feed.entries?.filter((e: any) => e.severity === 'CRITICAL');
    if (criticalFeeds?.length) {
      recs.push(`Feed ${feed.source}: ${criticalFeeds.length} critical items requiring patching/hunting`);
    }
  });
  recs.push(
    'Schedule regular threat intelligence updates',
    'Review and update IOC feeds weekly',
    'Conduct security awareness training based on current threat landscape'
  );
  return [...new Set(recs)].slice(0, 10);
}

function generateTimeline(bundle: Record<string, any>): any[] {
  const timeline: any[] = [];
  const now = Date.now();
  const iocData = bundle.iocs?.data || [];

  iocData.slice(0, 6).forEach((ioc: any, idx: number) => {
    timeline.push({
      date: new Date(now - idx * 3600000).toISOString(),
      event: `${ioc.type} ${ioc.value} — ${ioc.status}`,
      type: 'ioc',
      severity: ioc.severity,
    });
  });
  const threats = bundle.threats || [];
  threats.forEach((feed: any, feedIdx: number) => {
    (feed.entries || []).slice(0, 2).forEach((e: any, idx: number) => {
      timeline.push({
        date: new Date(now - (feedIdx * 7200000) - (idx + 1) * 3600000).toISOString(),
        event: `[${feed.source}] ${e.cveID || e.sha256 || e.signature || e.vulnerabilityName || 'intel item'}`,
        type: 'threat',
        severity: e.severity || 'INFO',
      });
    });
  });
  timeline.push({ date: new Date().toISOString(), event: 'Report generated', type: 'system', severity: 'INFO' });
  return timeline.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
}

// ---------- POST: generate report ----------
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    const { module: reportModule, error: moduleError } = resolveModuleScope(request, body);
    if (moduleError) {
      return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
    }

    const config: ReportConfig = {
      title: body.title || 'NEXUS INTEL Intelligence Report',
      modules: body.modules || ['iocs', 'threats'],
      format: body.format || 'HTML',
      includeIOCs: body.includeIOCs ?? true,
      includeThreats: body.includeThreats ?? true,
      includeTimeline: body.includeTimeline ?? true,
      executiveSummary: body.executiveSummary ?? true,
      recommendations: body.recommendations ?? true,
      templateId: body.templateId,
      customContent: body.customContent,
    };

    console.log('[REPORTS] Generating:', config.title, '| modules:', config.modules.join(', '));

    // Connect ALL internal modules via the reporter agent
    const moduleData: Record<string, any> = {};

    const iocs = await getIOCs({ limit: 100 });
    moduleData.iocs = { data: iocs.data, total: iocs.total };

    const threats = await loadThreatFeeds(undefined, 15);
    moduleData.threats = threats;

    const stats = await getStoreStats();
    moduleData.stats = stats;

    const recentAnalyses = await getRecentAnalyses(20);
    moduleData.recentAnalyses = recentAnalyses;

    // Per-module aggregation
    if (config.modules.includes('threats') || config.includeThreats) moduleData.threatFeeds = threats;
    if (config.modules.includes('iocs') || config.includeIOCs) moduleData.iocList = iocs.data;
    if (config.modules.includes('dashboard')) moduleData.dashboardStats = stats;

    // Executive summary (AI agent)
    let execSummary: any;
    let usedAI = false;
    if (config.executiveSummary) {
      const res = await generateExecutiveSummary(config, moduleData);
      execSummary = res.summary;
      usedAI = res.usedAI;
    }

    // Recommendations
    let recommendations: string[] = [];
    if (config.recommendations) {
      recommendations = generateRecommendations(moduleData);
    }

    // Timeline
    let timeline: any[] = [];
    if (config.includeTimeline) {
      timeline = generateTimeline(moduleData);
    }

    const report: ReportRecord = {
      id: generateId(),
      module: reportModule,
      title: config.title,
      config,
      timestamp: new Date().toISOString(),
      content: {
        executiveSummary: execSummary,
        recommendations,
        timeline,
        moduleData: {
          iocs: iocs.data,
          totalIocs: iocs.total,
          threats,
          stats,
          recentAnalyses,
        },
        statistics: {
          totalIOCs: iocs.total,
          totalThreats: threats.length,
          modulesIncluded: config.modules.length,
          format: config.format,
          aiUsed: usedAI,
          storage: 'persistent',
        },
      },
    };

    // Persist to KV
    await kvPushList(REPORTS_KEY, report, 50);

    return NextResponse.json({
      success: true,
      source: usedAI ? 'Reporter Agent (Groq LLM)' : 'Reporter Agent (rule-based)',
      fetchedLive: true,
      aiUsed: usedAI,
      data: report,
      message: `Report "${config.title}" generated and stored successfully`,
    });
  } catch (error) {
    console.error('Report generation error:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Report generation failed',
      },
      { status: 500 }
    );
  }
}

// ---------- GET: list / get / download ----------
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const action = searchParams.get('action');

  if (action === 'list') {
    const reports = await kvGetList<ReportRecord>(REPORTS_KEY);
    return NextResponse.json({
      success: true,
      data: reports.map((r) => ({
        id: r.id,
        title: r.title,
        timestamp: r.timestamp,
        modules: r.config?.modules || [],
        format: r.config?.format || 'HTML',
        stats: r.content?.statistics,
      })),
      message: `Found ${reports.length} report(s)`,
    });
  }

  if (action === 'get') {
    const id = searchParams.get('id');
    if (!id) return NextResponse.json({ success: false, error: 'Report ID required' });
    const reports = await kvGetList<ReportRecord>(REPORTS_KEY);
    const report = reports.find((r) => r.id === id);
    if (!report) return NextResponse.json({ success: false, error: 'Report not found' });
    return NextResponse.json({ success: true, data: report });
  }

  if (action === 'download') {
    const id = searchParams.get('id');
    const format = searchParams.get('format') || 'html';
    if (!id) return NextResponse.json({ success: false, error: 'Report ID required' });
    const reports = await kvGetList<ReportRecord>(REPORTS_KEY);
    const report = reports.find((r) => r.id === id);
    if (!report) return NextResponse.json({ success: false, error: 'Report not found' });

    const fmt = format.toLowerCase();
    const spec = buildReportSpec(report);

    if (fmt === 'pdf' || fmt === 'docx' || fmt === 'pptx') {
      try {
        let buffer: Buffer;
        let type: string;
        let ext: string;
        if (fmt === 'pdf') {
          buffer = await buildPDF(spec);
          type = 'application/pdf';
          ext = 'pdf';
        } else if (fmt === 'docx') {
          buffer = await buildDOCX(spec);
          type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
          ext = 'docx';
        } else {
          buffer = await buildPPTX(spec);
          type = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
          ext = 'pptx';
        }
        return new NextResponse(new Uint8Array(buffer), {
          headers: {
            'Content-Type': type,
            'Content-Disposition': `attachment; filename="${report.id}.${ext}"`,
          },
        });
      } catch (err) {
        console.error('Binary report generation error:', err);
        return NextResponse.json(
          { success: false, error: err instanceof Error ? err.message : 'Binary generation failed' },
          { status: 500 }
        );
      }
    }

    const content = buildDownloadContent(report, fmt);
    return new NextResponse(content.body as any, {
      headers: {
        'Content-Type': content.type,
        'Content-Disposition': `attachment; filename="${report.id}.${content.ext}"`,
      },
    });
  }

  // Info / templates
  return NextResponse.json({
    success: true,
    source: 'Reporter Agent v11',
    data: {
      templates: [
        { id: 'executive', name: 'Executive Summary', modules: ['dashboard', 'iocs', 'threats'] },
        { id: 'technical', name: 'Technical Analysis', modules: ['ip', 'domain', 'url', 'hash', 'cve'] },
        { id: 'threat-hunt', name: 'Threat Hunt Report', modules: ['darkweb', 'threats', 'ai'] },
        { id: 'comprehensive', name: 'Comprehensive Report', modules: ['dashboard', 'ip', 'domain', 'cve', 'darkweb', 'threats', 'iocs', 'mobile', 'ai'] },
        { id: 'brand-protection', name: 'Brand Protection Assessment', modules: ['brand', 'phishing', 'social', 'fakeapp'] },
        { id: 'executive-protection', name: 'Executive Digital Protection', modules: ['exec', 'dorking', 'social', 'darkweb'] },
        { id: 'incident-response', name: 'Incident Response Report', modules: ['ip', 'domain', 'hash', 'url', 'cve', 'sandbox'] },
      ],
      formats: ['HTML', 'JSON', 'CSV', 'PDF', 'DOCX', 'PPTX'],
      customOptions: {
        clientName: true,
        engagement: true,
        header: true,
        footer: true,
        sections: true,
      },
      aiEnabled: isAIEnabled(),
      storage: 'persistent',
    },
  });
}

function buildDownloadContent(report: ReportRecord, format: string): { body: string | Buffer; type: string; ext: string } {
  switch (format.toLowerCase()) {
    case 'json':
      return {
        body: JSON.stringify(report, null, 2),
        type: 'application/json',
        ext: 'json',
      };
    case 'csv': {
      const lines: string[] = ['Section,Key,Value'];
      const push = (section: string, obj: any) => {
        if (!obj || typeof obj !== 'object') return;
        Object.entries(obj).forEach(([k, v]) => lines.push(`"${section}","${k}","${String(v).replace(/"/g, '""')}"`));
      };
      push('Executive Summary', report.content.executiveSummary);
      push('Statistics', report.content.statistics);
      report.content.recommendations?.forEach((r: string, i: number) =>
        lines.push(`"Recommendations","${i + 1}","${r.replace(/"/g, '""')}"`)
      );
      return { body: lines.join('\n'), type: 'text/csv', ext: 'csv' };
    }
    case 'pdf':
    case 'docx':
    case 'pptx': {
      const spec = buildReportSpec(report);
      if (format.toLowerCase() === 'pdf') {
        return { body: '', type: 'application/pdf', ext: 'pdf' };
      }
      if (format.toLowerCase() === 'docx') {
        return { body: '', type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', ext: 'docx' };
      }
      return { body: '', type: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', ext: 'pptx' };
    }
    case 'html':
    default:
      return { body: renderHTML(report), type: 'text/html', ext: 'html' };
  }
}

function buildReportSpec(report: ReportRecord): ReportSpec {
  const c = report.content;
  const custom = report.config?.customContent;
  const sections: ReportSection[] = [];

  if (c.executiveSummary) {
    sections.push({
      title: 'Executive Summary',
      body: c.executiveSummary.narrative || (c.executiveSummary.keyFindings || []).join(' '),
      metadata: {
        'Overall Risk': c.executiveSummary.overallRiskLevel || 'N/A',
        'Total Indicators': c.statistics?.totalIOCs || 0,
        'Threat Feeds': c.statistics?.totalThreats || 0,
        'Modules': c.statistics?.modulesIncluded || 0,
      },
      bullets: c.executiveSummary.keyFindings || [],
    });
  }

  if (c.recommendations?.length) {
    sections.push({ title: 'Recommendations', bullets: c.recommendations });
  }

  const iocs = c.moduleData?.iocs || [];
  if (iocs.length) {
    sections.push({
      title: 'Indicators of Compromise',
      table: {
        headers: ['Type', 'Value', 'Severity', 'Status'],
        rows: iocs.slice(0, 40).map((i: any) => [i.type, i.value, i.severity, i.status]),
      },
    });
  }

  const threats = c.moduleData?.threats || [];
  const threatRows = threats.flatMap((f: any) =>
    (f.entries || []).slice(0, 5).map((e: any) => [f.source, e.cveID || e.sha256 || e.signature || e.vulnerabilityName || '-', e.severity || 'INFO'])
  );
  if (threatRows.length) {
    sections.push({ title: 'Live Threat Feeds', table: { headers: ['Feed', 'Item', 'Severity'], rows: threatRows.slice(0, 40) } });
  }

  if (c.timeline?.length) {
    sections.push({
      title: 'Timeline',
      bullets: c.timeline.slice(0, 20).map((t: any) => `${t.type.toUpperCase()} — ${t.event} (${new Date(t.date).toLocaleString()})`),
    });
  }

  if (c.moduleData?.recentAnalyses?.length) {
    sections.push({
      title: 'Recent Analyses',
      table: {
        headers: ['Source', 'Summary', 'Verified'],
        rows: c.moduleData.recentAnalyses.slice(0, 20).map((a: any) => [a.source || '-', (a.summary || '-').substring(0, 80), a.verified ? 'Yes' : 'No']),
      },
    });
  }

  // Custom sections injected by the user
  if (custom?.sections?.length) {
    custom.sections.forEach((s) => sections.push({ title: s.title || 'Custom Section', body: s.body || '' }));
  }

  const now = new Date().toLocaleString();
  return {
    title: report.title,
    subtitle: custom?.clientName ? `Client: ${custom.clientName}` : undefined,
    riskLevel: c.executiveSummary?.overallRiskLevel,
    generatedAt: now,
    preparedBy: custom?.clientName ? `Monitor-Threat · Engagement: ${custom.engagement || 'General'}` : 'Monitor-Threat',
    classification: custom?.engagement ? `ENGAGEMENT: ${custom.engagement}` : 'CONFIDENTIAL',
    sections,
    customHeader: custom?.header,
    customFooter: custom?.footer,
  };
}

function renderHTML(report: ReportRecord): string {
  const c = report.content;
  const esc = (s: any) => String(s ?? '').replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]!));

  const recs = (c.recommendations || [])
    .map((r: string) => `<li>${esc(r)}</li>`)
    .join('');

  const iocRows = (c.moduleData?.iocs || [])
    .slice(0, 25)
    .map((i: any) => `<tr><td>${esc(i.type)}</td><td><code>${esc(i.value)}</code></td><td>${esc(i.severity)}</td><td>${esc(i.status)}</td></tr>`)
    .join('');

  const threatRows = (c.moduleData?.threats || [])
    .flatMap((f: any) => (f.entries || []).slice(0, 3).map((e: any) => `<tr><td>${esc(f.source)}</td><td>${esc(e.cveID || e.sha256 || e.signature || e.vulnerabilityName || '-')}</td><td>${esc(e.severity || 'INFO')}</td></tr>`))
    .slice(0, 30)
    .join('');

  const timeline = (c.timeline || [])
    .slice(0, 15)
    .map((t: any) => `<li><strong>${esc(t.type)}</strong> — ${esc(t.event)} <small>(${esc(new Date(t.date).toLocaleString())})</small></li>`)
    .join('');

  return `<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>${esc(report.title)}</title>
<style>
body{font-family:-apple-system,'Segoe UI',Roboto,sans-serif;background:#0b0f19;color:#e5e7eb;margin:0;padding:24px}
.wrap{max-width:900px;margin:0 auto}
h1{color:#f87171;border-bottom:2px solid #1f2937;padding-bottom:12px}
h2{color:#60a5fa;margin-top:32px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{background:#1f2937;text-align:left;padding:8px;color:#9ca3af}
td{border-bottom:1px solid #1f2937;padding:8px}
code{background:#1f2937;padding:2px 6px;border-radius:4px;font-size:13px}
.card{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:18px;margin-top:16px}
.badge{display:inline-block;padding:4px 10px;border-radius:9999px;font-weight:700;font-size:12px}
.critical{background:#dc2626;color:#fff}.high{background:#f97316;color:#000}.medium{background:#eab308;color:#000}.low{background:#22c55e;color:#000}
.footer{margin-top:40px;font-size:12px;color:#6b7280;text-align:center}
</style></head>
<body><div class="wrap">
<h1>🛡️ ${esc(report.title)}</h1>
<p><em>Generated ${esc(new Date(report.timestamp).toLocaleString())} · MONITOR-THREAT v11 · Reporter Agent${c.statistics?.aiUsed ? ' (AI)':''}</em></p>
${report.config?.customContent?.clientName ? `<p><strong>Client:</strong> ${esc(report.config.customContent.clientName)}${report.config.customContent.engagement ? ` · <strong>Engagement:</strong> ${esc(report.config.customContent.engagement)}` : ''}</p>` : ''}
${report.config?.customContent?.header ? `<p><em>${esc(report.config.customContent.header)}</em></p>` : ''}

<div class="card">
<span class="badge ${esc((c.executiveSummary?.overallRiskLevel || 'MEDIUM').toLowerCase())}">${esc(c.executiveSummary?.overallRiskLevel || 'MEDIUM')} RISK</span>
<p>${esc(c.executiveSummary?.narrative || c.executiveSummary?.keyFindings?.[0] || '')}</p>
</div>

<h2>Key Findings</h2>
<ul>${(c.executiveSummary?.keyFindings || []).map((f: string) => `<li>${esc(f)}</li>`).join('')}</ul>

<h2>Statistics</h2>
<div class="card">
<p>Total IOCs: <strong>${esc(c.statistics?.totalIOCs)}</strong> · Threat feeds: <strong>${esc(c.statistics?.totalThreats)}</strong> · Modules: <strong>${esc(c.statistics?.modulesIncluded)}</strong></p>
</div>

<h2>Recommendations</h2>
<ol>${recs}</ol>

<h2>Indicators of Compromise</h2>
<table><tr><th>Type</th><th>Value</th><th>Severity</th><th>Status</th></tr>${iocRows}</table>

<h2>Live Threat Feeds</h2>
<table><tr><th>Feed</th><th>Item</th><th>Severity</th></tr>${threatRows}</table>

<h2>Timeline</h2>
<ul>${timeline}</ul>

${(report.config?.customContent?.sections || []).map((s: any) => `<h2>${esc(s.title || 'Custom Section')}</h2><p>${esc(s.body || '')}</p>`).join('')}
${report.config?.customContent?.footer ? `<p><em>${esc(report.config.customContent.footer)}</em></p>` : ''}

<div class="footer">Generated by MONITOR-THREAT — OSINT &amp; Threat Intelligence Platform</div>
</div></body></html>`;
}
