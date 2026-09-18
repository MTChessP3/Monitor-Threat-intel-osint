import { NextRequest, NextResponse } from 'next/server';
import { getIOCs } from '@/lib/store';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

// Export functionality — JSON, CSV, STIX 2.1 (backed by the persistent store)
export async function GET(request: NextRequest) {
  const { module: exportModule, error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }
  const searchParams = request.nextUrl.searchParams;
  const format = searchParams.get('format') || 'json'; // json, csv, stix
  const type = searchParams.get('type') || undefined;
  const status = searchParams.get('status') || undefined;
  const severity = searchParams.get('severity') || undefined;

  try {
    const { data: iocs } = await getIOCs({ type, status, severity, limit: 1000 });
    const timestamp = new Date().toISOString();

    switch (format.toLowerCase()) {
      case 'csv':
        return exportCSV(iocs, timestamp);
      case 'stix':
        return exportSTIX(iocs, timestamp);
      case 'json':
      default:
        return exportJSON(iocs, timestamp);
    }
  } catch (error) {
    console.error('Export Error:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Export failed',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

function exportJSON(iocs: any[], timestamp: string) {
  const report = {
    metadata: {
      title: 'NEXUS INTEL Export',
      generatedAt: timestamp,
      platform: 'NEXUS-INTEL v10',
      totalIOCs: iocs.length,
      sources: [...new Set(iocs.map((i) => i.source).filter(Boolean))],
    },
    summary: {
      byType: countBy(iocs, 'type'),
      bySeverity: countBy(iocs, 'severity'),
      byStatus: countBy(iocs, 'status'),
    },
    data: iocs.map((ioc) => ({
      id: ioc.id,
      type: ioc.type,
      value: ioc.value,
      description: ioc.description,
      severity: ioc.severity,
      confidence: ioc.confidence,
      status: ioc.status,
      source: ioc.source,
      tags: ioc.tags || [],
      firstSeen: ioc.firstSeen,
      lastUpdated: ioc.lastUpdated,
    })),
  };

  return new NextResponse(JSON.stringify(report, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="nexus-export-${timestamp.split('T')[0]}.json"`,
    },
  });
}

function exportCSV(iocs: any[], timestamp: string) {
  const headers = [
    'ID', 'Type', 'Value', 'Description', 'Severity',
    'Confidence', 'Status', 'Source', 'Tags', 'First Seen', 'Last Updated',
  ];

  const rows = iocs.map((ioc) => [
    ioc.id,
    ioc.type,
    `"${(ioc.value || '').replace(/"/g, '""')}"`,
    `"${(ioc.description || '').replace(/"/g, '""')}"`,
    ioc.severity,
    ioc.confidence,
    ioc.status,
    ioc.source || '',
    `"${(ioc.tags || []).join('; ').replace(/"/g, '""')}"`,
    ioc.firstSeen,
    ioc.lastUpdated,
  ]);

  const csvContent = [
    '# NEXUS INTEL Export',
    `# Generated: ${timestamp}`,
    `# Total IOCs: ${iocs.length}`,
    '',
    headers.join(','),
    ...rows.map((r) => r.join(',')),
  ].join('\n');

  return new NextResponse(csvContent, {
    headers: {
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="nexus-export-${timestamp.split('T')[0]}.csv"`,
    },
  });
}

// STIX 2.1 indicators bundle
function exportSTIX(iocs: any[], timestamp: string) {
  const objects = iocs.map((ioc) => ({
    type: 'indicator',
    id: `indicator--${ioc.id.replace(/[^a-zA-Z0-9]/g, '') || cryptoUUID()}`,
    created: ioc.firstSeen || timestamp,
    modified: ioc.lastUpdated || timestamp,
    name: ioc.value,
    description: ioc.description || `${ioc.type} indicator`,
    pattern: stixPattern(ioc.type, ioc.value),
    valid_from: ioc.firstSeen || timestamp,
    labels: [stixLabel(ioc.status)],
    confidence: ioc.confidence,
    source: ioc.source,
  }));

  const bundle = {
    type: 'bundle',
    id: `bundle--${cryptoUUID()}`,
    spec_version: '2.1',
    created: timestamp,
    modified: timestamp,
    objects,
  };

  return new NextResponse(JSON.stringify(bundle, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="nexus-iocs-${timestamp.split('T')[0]}.stix2.json"`,
    },
  });
}

function stixPattern(type: string, value: string): string {
  const v = value.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  switch (type.toUpperCase()) {
    case 'IP':
      return `[ipv4-addr:value = '${v}']`;
    case 'DOMAIN':
      return `[domain-name:value = '${v}']`;
    case 'URL':
      return `[url:value = '${v}']`;
    case 'HASH':
      return `[file:hashes.'SHA-256' = '${v}']`;
    case 'EMAIL':
      return `[email-addr:value = '${v}']`;
    default:
      return `[indicator:pattern = '${v}']`;
  }
}

function stixLabel(status: string): string {
  const mapping: Record<string, string> = {
    MALICIOUS: 'malicious-activity',
    SUSPICIOUS: 'suspicious-activity',
    BENIGN: 'benign',
    UNKNOWN: 'unknown',
  };
  return mapping[status?.toUpperCase() || ''] || 'unknown';
}

function countBy(arr: any[], field: string): Record<string, number> {
  return arr.reduce((acc, item) => {
    const key = item[field] || 'unknown';
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
}

function cryptoUUID(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 12)}`;
}
