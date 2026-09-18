import { NextRequest, NextResponse } from 'next/server';
import { lookupIP, validateIP, IPValidationResult } from '@/lib/intel';
import { enrichIP } from '@/lib/intel/ipenrich';
import { upsertIOC, createAnalysis, createAlert } from '@/lib/store';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

async function fetchRdap(ip: string): Promise<any> {
  let rdap: any = null;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);
    const rdapRes = await fetch(`https://rdap.org/ip/${encodeURIComponent(ip)}`, {
      headers: { Accept: 'application/rdap+json', 'User-Agent': 'NEXUS-INTEL/1.0' },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    if (rdapRes.ok) {
      const rd = await rdapRes.json();
      const entities = (rd.entities || []).flatMap((e: any) => {
        const vcard = e.vcardArray?.[1] || [];
        const fn = vcard.find((line: any) => line[0] === 'fn')?.[3];
        const org = vcard.find((line: any) => line[0] === 'org')?.[3];
        return [fn || org].filter(Boolean);
      });
      const abuseContacts = (rd.entities || [])
        .filter((e: any) => (e.roles || []).includes('abuse'))
        .flatMap((e: any) => {
          const vcard = e.vcardArray?.[1] || [];
          return vcard
            .filter((line: any) => line[0] === 'email')
            .map((line: any) => line[3])
            .filter(Boolean);
        });
      rdap = {
        handle: rd.handle,
        name: rd.name,
        type: rd.type,
        startAddress: rd.startAddress,
        endAddress: rd.endAddress,
        country: rd.country,
        parent: rd.parent,
        entities: [...new Set(entities)],
        abuseContacts: [...new Set(abuseContacts)],
        status: rd.status,
      };
    }
  } catch (rdapError) {
    console.log('[INTEL] RDAP lookup failed:', rdapError instanceof Error ? rdapError.message : rdapError);
  }
  return rdap;
}

// IP Intelligence — real ip-api.com lookup + free OSINT enrichment + active fingerprinting
export async function GET(request: NextRequest) {
  const { error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }
  const searchParams = request.nextUrl.searchParams;
  const ip = searchParams.get('ip');
  const scan = searchParams.get('scan') !== '0';

  if (!ip) {
    return NextResponse.json(
      {
        success: false,
        error: 'IP address is required',
        suggestion: 'Enter a valid IP address (e.g., 8.8.8.8 or 2001:db8::1)',
      },
      { status: 400 }
    );
  }

  // Validate IP using new robust validator
  const validation: IPValidationResult = validateIP(ip);
  if (!validation.valid) {
    return NextResponse.json(
      {
        success: false,
        error: validation.error || 'Invalid IP address',
        suggestion: 'Enter a valid IPv4 (e.g., 8.8.8.8) or IPv6 (e.g., 2001:db8::1)',
        provided: ip,
      },
      { status: 400 }
    );
  }

  try {
    const { live, source, data } = await lookupIP(validation.normalized);

    const [rdap, enrichment] = await Promise.all([fetchRdap(ip), enrichIP(ip, { scan })]);

    try {
      const ioc = await upsertIOC({
        type: 'IP',
        value: ip,
        description: `IP Geolocation: ${data.city || 'Unknown'}, ${data.country || 'Unknown'}`,
        severity: data.proxy || data.hosting ? 'HIGH' : data.mobile ? 'LOW' : 'MEDIUM',
        confidence: live ? 90 : 75,
        status: data.proxy || data.hosting ? 'SUSPICIOUS' : 'UNKNOWN',
        source: live ? source : 'cached',
        rawResponse: JSON.stringify(data),
        tags: [data.proxy && 'proxy', data.hosting && 'hosting', data.mobile && 'mobile', `ISP: ${data.isp || 'Unknown'}`].filter(Boolean),
      });

      await createAnalysis({
        iocId: ioc.id,
        source,
        sourceType: 'GEO_IP',
        rawData: JSON.stringify(data),
        summary: `Location: ${data.city}, ${data.regionName}, ${data.country}. ISP: ${data.org || data.isp}`,
        verified: live,
      });

      if (data.proxy || data.hosting) {
        await createAlert({
          iocId: ioc.id,
          title: `Suspicious IP Detected: ${ip}`,
          description: `IP has proxy/hosting flags. Location: ${data.city}, ${data.country}`,
          severity: 'HIGH',
          type: 'ANOMALY_DETECTED',
        });
      }
    } catch (storeError) {
      console.error('Store save error (non-critical):', storeError);
    }

    const dnsblHits = enrichment.reputation.dnsbl.filter((d) => d.listed);
    const malicious = data.proxy || data.hosting || enrichment.reputation.torExit || dnsblHits.length > 0 || enrichment.reputation.urlhaus.urlCount > 0;
    const threatLevel = malicious ? 'ELEVATED' : 'NORMAL';

    const recommendations: string[] = [];
    if (enrichment.reputation.torExit) recommendations.push('IP is a known Tor exit node — highly anonymized, treat with extreme caution');
    if (dnsblHits.length > 0) recommendations.push(`Listed on ${dnsblHits.length} DNS blacklist(s): ${dnsblHits.map((d) => d.name).join(', ')}`);
    if (enrichment.reputation.urlhaus.urlCount > 0) recommendations.push(`Associated with ${enrichment.reputation.urlhaus.urlCount} malicious URL(s) on URLhaus`);
    if (data.proxy) recommendations.push('Known proxy/VPN — additional verification recommended');
    if (data.hosting) recommendations.push('Hosting provider network — could be server/shared hosting, monitor activity');
    const openPorts = enrichment.scan.ports.filter((p) => p.state === 'open');
    if (openPorts.length > 0) recommendations.push(`Exposed services: ${openPorts.map((p) => `${p.port}/${p.service}`).join(', ')}`);
    if (recommendations.length === 0) recommendations.push('Standard residential/business IP — no immediate threats detected');

    return NextResponse.json({
      success: true,
      source,
      timestamp: new Date().toISOString(),
      fetchedLive: live,
      data: { ...data, rdap },
      reputation: enrichment.reputation,
      pivot: enrichment.pivot,
      scan: enrichment.scan,
      analysis: {
        threatLevel,
        recommendations,
      },
    });
  } catch (error) {
    console.error('IP Lookup Error:', error);
    const { data } = await lookupIP(ip);
    return NextResponse.json({
      success: true,
      source: 'fallback-data',
      timestamp: new Date().toISOString(),
      fetchedLive: false,
      data,
      error: 'Primary lookup failed, showing cached data',
      details: error instanceof Error ? error.message : 'Unknown error',
    });
  }
}

// POST: manually add an IP IOC
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { error: moduleError } = resolveModuleScope(request, body);
    if (moduleError) {
      return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
    }
    const { ip, description, tags, severity } = body;

    if (!ip) {
      return NextResponse.json({ success: false, error: 'IP address is required' }, { status: 400 });
    }

    const ioc = await upsertIOC({
      type: 'IP',
      value: ip,
      description: description || `Manually added IP: ${ip}`,
      severity: severity || 'MEDIUM',
      confidence: 70,
      status: 'UNKNOWN',
      source: 'manual',
      tags: tags || [],
    });

    return NextResponse.json({
      success: true,
      ioc,
      message: `IP ${ip} added successfully`,
    });
  } catch (error: any) {
    console.error('Create IOC Error:', error);
    return NextResponse.json(
      { success: false, error: error.message || 'Failed to create IOC', details: error.message },
      { status: 500 }
    );
  }
}
