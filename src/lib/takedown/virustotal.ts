function base64Url(url: string): string {
  try {
    return btoa(url).replace(/=+$/, '');
  } catch {
    return Buffer.from(url).toString('base64').replace(/=+$/, '');
  }
}

interface VirusTotalPreCheckResult {
  url: string;
  urlId: string;
  classification: 'CONFIRMED_MALICIOUS' | 'SUSPICIOUS' | 'NO_RECORD';
  maliciousEngines: number;
  suspiciousEngines: number;
  harmlessEngines: number;
  totalEngines: number;
  lastAnalysisDate: string;
  permalink: string;
  country?: string;
  asn?: string;
  ipAddress?: string;
}

interface VirustotalUrlResponse {
  data?: {
    id: string;
    attributes: {
      last_analysis_stats: Record<string, number>;
      last_analysis_date: number;
      permalink: string;
      tags?: string[];
      type_description?: string;
      reputations?: Array<{ date: number; result: string }>;
    };
  };
  error?: { code: number; message: string };
}

export async function virustotalPreCheck(
  url: string,
  apiKey: string
): Promise<VirusTotalPreCheckResult> {
  const urlId = base64Url(url);
  const apiUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;

  const response = await fetch(apiUrl, {
    method: 'GET',
    headers: {
      'x-apikey': apiKey,
      'Content-Type': 'application/json',
    },
    next: { revalidate: 300 },
  });

  if (!response.ok) {
    if (response.status === 404) {
      return {
        url,
        urlId,
        classification: 'NO_RECORD',
        maliciousEngines: 0,
        suspiciousEngines: 0,
        harmlessEngines: 0,
        totalEngines: 0,
        lastAnalysisDate: '',
        permalink: `https://www.virustotal.com/gui/url/${urlId}`,
      };
    }
    if (response.status === 429) {
      throw new Error('VirusTotal rate limit exceeded');
    }
    throw new Error(`VirusTotal API error: HTTP ${response.status}`);
  }

  const data: VirustotalUrlResponse = await response.json();

  if (!data.data) {
    return {
      url,
      urlId,
      classification: 'NO_RECORD',
      maliciousEngines: 0,
      suspiciousEngines: 0,
      harmlessEngines: 0,
      totalEngines: 0,
      lastAnalysisDate: '',
      permalink: `https://www.virustotal.com/gui/url/${urlId}`,
    };
  }

  const attrs = data.data.attributes;
  const stats = attrs.last_analysis_stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;
  const totalEngines = malicious + suspicious + harmless + undetected;

  let classification: VirusTotalPreCheckResult['classification'] = 'NO_RECORD';
  if (malicious > 0) {
    classification = 'CONFIRMED_MALICIOUS';
  } else if (suspicious > 0) {
    classification = 'SUSPICIOUS';
  }

  return {
    url,
    urlId,
    classification,
    maliciousEngines: malicious,
    suspiciousEngines: suspicious,
    harmlessEngines: harmless,
    totalEngines,
    lastAnalysisDate: new Date(attrs.last_analysis_date * 1000).toISOString(),
    permalink: attrs.permalink || `https://www.virustotal.com/gui/url/${urlId}`,
  };
}

export async function virustotalPreCheckBatch(
  urls: string[],
  apiKey: string
): Promise<VirusTotalPreCheckResult[]> {
  const results: VirusTotalPreCheckResult[] = [];

  for (const url of urls) {
    try {
      const result = await virustotalPreCheck(url, apiKey);
      results.push(result);
    } catch (error) {
      results.push({
        url,
        urlId: Buffer.from(url).toString('base64').replace(/=+$/, ''),
        classification: 'NO_RECORD',
        maliciousEngines: 0,
        suspiciousEngines: 0,
        harmlessEngines: 0,
        totalEngines: 0,
        lastAnalysisDate: '',
        permalink: '',
      });
    }
  }

  return results;
}

export async function virustotalSubmitUrl(url: string, apiKey: string): Promise<{
  submitted: boolean;
  urlId: string;
  message: string;
}> {
  const apiUrl = 'https://www.virustotal.com/api/v3/urls';
  const response = await fetch(apiUrl, {
    method: 'POST',
    headers: {
      'x-apikey': apiKey,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ url }),
  });

  if (response.ok) {
    const data = await response.json();
    return {
      submitted: true,
      urlId: data.data?.id || Buffer.from(url).toString('base64').replace(/=+$/, ''),
      message: 'URL enviada para análisis en VirusTotal',
    };
  }

  return {
    submitted: false,
    urlId: Buffer.from(url).toString('base64').replace(/=+$/, ''),
    message: `Error al enviar: HTTP ${response.status}`,
  };
}
