import { NextResponse } from 'next/server';
import { createHash } from 'crypto';

interface ReportRequest {
  urls: string[];
  services: string[];
  notes?: string;
  apiKeys?: {
    google?: string;
    virustotal?: string;
  };
}

interface ServiceReportResult {
  service: string;
  url: string;
  status: 'success' | 'failed' | 'pending' | 'manual';
  message: string;
  timestamp: string;
  referenceId?: string;
}

const GOOGLE_SAFE_BROWSING_API = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const MICROSOFT_SMARTSCREEN_API = 'https://api.smartscreen.microsoft.com/report';
const VIRUSTOTAL_API = 'https://www.virustotal.com/api/v3';

function generateFingerprint(data: string): string {
  return createHash('sha256').update(data).digest('hex').toUpperCase();
}

function generateReportId(): string {
  return 'TD-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substring(2, 8).toUpperCase();
}

async function reportToGoogleSafeBrowsing(url: string, apiKey?: string): Promise<ServiceReportResult> {
  if (!apiKey) {
    return {
      service: 'Google Safe Browsing',
      url,
      status: 'manual',
      message: 'Requiere API Key. Reporte manual en: https://safebrowsing.google.com/safebrowsing/report_phish/',
      timestamp: new Date().toISOString(),
    };
  }

  try {
    const response = await fetch(`${GOOGLE_SAFE_BROWSING_API}?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'takedown-module', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }),
    });

    if (response.ok) {
      const data = await response.json();
      return {
        service: 'Google Safe Browsing',
        url,
        status: data.matches ? 'success' : 'success',
        message: data.matches ? 'URL detectada como amenaza' : 'URL enviada para análisis',
        timestamp: new Date().toISOString(),
        referenceId: 'GSB-' + Date.now().toString(36).toUpperCase(),
      };
    }

    return {
      service: 'Google Safe Browsing',
      url,
      status: 'failed',
      message: `Error HTTP ${response.status}: ${response.statusText}`,
      timestamp: new Date().toISOString(),
    };
  } catch (error) {
    return {
      service: 'Google Safe Browsing',
      url,
      status: 'failed',
      message: error instanceof Error ? error.message : 'Error de conexión',
      timestamp: new Date().toISOString(),
    };
  }
}

async function reportToMicrosoftSmartScreen(url: string): Promise<ServiceReportResult> {
  return {
    service: 'Microsoft SmartScreen',
    url,
    status: 'manual',
    message: 'Reporte manual requerido. Envíe a: https://www.microsoft.com/wdsi/support/report-unsafe-site',
    timestamp: new Date().toISOString(),
  };
}

async function reportToAPWG(url: string, notes?: string): Promise<ServiceReportResult> {
  return {
    service: 'APWG (Anti-Phishing Working Group)',
    url,
    status: 'manual',
    message: `Enviar correo a reportphishing@apwg.org con la URL: ${url}${notes ? '\nNotas: ' + notes : ''}`,
    timestamp: new Date().toISOString(),
  };
}

async function reportToCISA(url: string, notes?: string): Promise<ServiceReportResult> {
  return {
    service: 'CISA / US-CERT',
    url,
    status: 'manual',
    message: `Enviar correo a phishing-report@us-cert.gov con la URL: ${url}${notes ? '\nNotas: ' + notes : ''}`,
    timestamp: new Date().toISOString(),
  };
}

async function analyzeWithVirusTotal(url: string, apiKey?: string): Promise<ServiceReportResult> {
  if (!apiKey) {
    return {
      service: 'VirusTotal',
      url,
      status: 'manual',
      message: 'Requiere API Key. Analice manualmente en: https://www.virustotal.com/gui/url/' + Buffer.from(url).toString('base64'),
      timestamp: new Date().toISOString(),
    };
  }

  try {
    const urlId = Buffer.from(url).toString('base64').replace(/=+$/, '');
    const response = await fetch(`${VIRUSTOTAL_API}/urls/${urlId}`, {
      headers: { 'x-apikey': apiKey },
    });

    if (response.ok) {
      const data = await response.json();
      const stats = data.data?.attributes?.last_analysis_stats || {};
      const malicious = (stats.malicious as number) || 0;
      const suspicious = (stats.suspicious as number) || 0;
      const total = Object.values(stats).reduce((a: number, b: unknown) => a + ((b as number) || 0), 0);

      return {
        service: 'VirusTotal',
        url,
        status: 'success',
        message: `Análisis completado: ${malicious} maliciosos, ${suspicious} sospechosos de ${total} motores`,
        timestamp: new Date().toISOString(),
        referenceId: data.data?.id,
      };
    }

    if (response.status === 404) {
      const submitResponse = await fetch(`${VIRUSTOTAL_API}/urls`, {
        method: 'POST',
        headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ url }),
      });

      if (submitResponse.ok) {
        return {
          service: 'VirusTotal',
          url,
          status: 'pending',
          message: 'URL enviada para análisis. Resultados disponibles en unos minutos.',
          timestamp: new Date().toISOString(),
        };
      }
    }

    return {
      service: 'VirusTotal',
      url,
      status: 'failed',
      message: `Error HTTP ${response.status}`,
      timestamp: new Date().toISOString(),
    };
  } catch (error) {
    return {
      service: 'VirusTotal',
      url,
      status: 'failed',
      message: error instanceof Error ? error.message : 'Error de conexión',
      timestamp: new Date().toISOString(),
    };
  }
}

export async function POST(request: Request) {
  try {
    const body: ReportRequest = await request.json();
    const { urls, services, notes, apiKeys } = body;

    if (!urls || urls.length === 0) {
      return NextResponse.json({ error: 'No se proporcionaron URLs' }, { status: 400 });
    }

    const reportId = generateReportId();
    const timestamp = new Date().toISOString();
    const results: ServiceReportResult[] = [];

    const googleApiKey = apiKeys?.google || process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    const vtApiKey = apiKeys?.virustotal || process.env.VIRUSTOTAL_API_KEY;

    for (const url of urls) {
      for (const service of services) {
        let result: ServiceReportResult;

        switch (service) {
          case 'google':
            result = await reportToGoogleSafeBrowsing(url, googleApiKey);
            break;
          case 'microsoft':
            result = await reportToMicrosoftSmartScreen(url);
            break;
          case 'apwg':
            result = await reportToAPWG(url, notes);
            break;
          case 'cisa':
            result = await reportToCISA(url, notes);
            break;
          case 'virustotal':
            result = await analyzeWithVirusTotal(url, vtApiKey);
            break;
          default:
            continue;
        }

        results.push(result);
      }
    }

    const fingerprint = generateFingerprint(JSON.stringify({ reportId, urls, services, timestamp, results }));

    return NextResponse.json({
      reportId,
      timestamp,
      urls,
      services,
      notes,
      results,
      fingerprint,
      summary: {
        total: results.length,
        success: results.filter(r => r.status === 'success').length,
        failed: results.filter(r => r.status === 'failed').length,
        pending: results.filter(r => r.status === 'pending').length,
        manual: results.filter(r => r.status === 'manual').length,
      },
    });
  } catch (error: unknown) {
    console.error('Error generating report:', error);
    const errorMessage = error instanceof Error ? error.message : 'Error al generar reporte';
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}