import { NextRequest, NextResponse } from 'next/server';
import { loadThreatFeeds } from '@/lib/intel';
import { createAlert, upsertIOC } from '@/lib/store';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

// Live threat feeds — real CISA KEV, MalwareBazaar, Abuse.ch SSLBL
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const feed = searchParams.get('feed') || 'all';
  const limit = parseInt(searchParams.get('limit') || '20');

  const { module: threatsModule, error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }

  try {
    const feeds = await loadThreatFeeds(feed === 'all' ? undefined : feed, limit);

    // Create alerts for critical items
    const criticalCount = feeds.reduce(
      (acc: number, f) => acc + f.entries.filter((e: any) => e.severity === 'CRITICAL').length,
      0
    );
    if (criticalCount > 2) {
      try {
        await createAlert({
          title: `Threat Feed Alert: ${criticalCount} Critical Items`,
          description: `Current threat feeds contain ${criticalCount} items requiring immediate attention`,
          severity: 'CRITICAL',
          type: 'THREAT_FEED_MATCH',
        });
      } catch (e) {
        /* non-critical */
      }
    }

    // Persist a representative IOC when feeds are live
    for (const f of feeds) {
      const entry = f.entries?.[0];
      if (entry?.cveID) {
        try {
          await upsertIOC({
            type: 'CVE',
            value: entry.cveID,
            description: `${f.source}: ${entry.vulnerabilityName || entry.cveID}`,
            severity: entry.severity || 'HIGH',
            confidence: 95,
            source: f.source,
            tags: ['threat-feed'],
          });
        } catch (e) {
          /* non-critical */
        }
        break;
      }
    }

    return NextResponse.json({
      success: true,
      module: threatsModule,
      timestamp: new Date().toISOString(),
      fetchedLive: true,
      totalFeeds: feeds.length,
      feeds,
      summary: {
        totalEntries: feeds.reduce((acc: number, f) => acc + f.entries.length, 0),
        criticalCount: feeds.reduce((acc: number, f) => acc + f.entries.filter((e: any) => e.severity === 'CRITICAL').length, 0),
        highCount: feeds.reduce((acc: number, f) => acc + f.entries.filter((e: any) => e.severity === 'HIGH').length, 0),
      },
      message: `Loaded ${feeds.length} threat intelligence feed(s)`,
    });
  } catch (error) {
    console.error('Threat Feed Error:', error);
    return NextResponse.json({
      success: true,
      module: threatsModule,
      timestamp: new Date().toISOString(),
      fetchedLive: false,
      totalFeeds: 0,
      feeds: [],
      message: 'Threat feeds unavailable at the moment',
    });
  }
}
