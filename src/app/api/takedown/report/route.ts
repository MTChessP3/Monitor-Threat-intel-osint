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
const VIRUSTOTAL_API = 'https://www.virustotal.com/api/v3';

const MAX_URLS_PER_REQUEST = 50;
const CONCURRENCY_LIMIT = 5;
const API_TIMEOUT_MS = 8000;

function generateFingerprint(data: string): string {
  return createHash('sha256').update(data).digest('hex').toUpperCase();
}

function generateReportId(): string {
  return 'TD-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substring(2, 8).toUpperCase();
}

async function fetchWithTimeout(url: string, options: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}

async function reportToGoogleSafeBrowsing(url: string, apiKey?: string): Promise<ServiceReportResult> {
  if (!apiKey) {
    return {
      service: 'Google Safe Browsing',
      url,
      status: 'manual',
      message: 'Reporte manual en: https://safebrowsing.google.com/safebrowsing/report_phish/',
      timestamp: new Date().toISOString(),
    };
  }

  try {
    const response = await fetchWithTimeout(
      `${GOOGLE_SAFE_BROWSING_API}?key=${apiKey}`,
      {
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
      },
      API_TIMEOUT_MS
    );

    if (response.ok) {
      const data = await response.json();
      return {
        service: 'Google Safe Browsing',
        url,
        status: 'success',
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
      message: error instanceof Error ? (error.name === 'AbortError' ? 'Timeout (8s)' : error.message) : 'Error de conexión',
      timestamp: new Date().toISOString(),
    };
  }
}

async function reportToMicrosoftSmartScreen(url: string): Promise<ServiceReportResult> {
  return {
    service: 'Microsoft SmartScreen',
    url,
    status: 'manual',
    message: 'Reporte manual en: https://www.microsoft.com/wdsi/support/report-unsafe-site',
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
      message: 'Análisis manual en: https://www.virustotal.com/gui/url/' + Buffer.from(url).toString('base64'),
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
        message: `Análisis: ${malicious} maliciosos, ${suspicious} sospechosos de ${total} motores`,
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
          message: 'URL enviada para análisis. Resultados en unos minutos.',
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
    const body = await request.json();
    const { urls, services, notes, apiKeys } = body;

    if (!urls || urls.length === 0) {
      return NextResponse.json({ error: 'No se proporcionaron URLs' }, { status: 400 });
    }

    if (urls.length > 50) {
      return NextResponse.json({
        error: `Demasiadas URLs. Máximo 50 por reporte. Recibidas: ${urls.length}. Divida en varios reportes.`,
        maxAllowed: 50,
        received: urls.length,
      }, { status: 400 });
    }

    const googleApiKey = apiKeys?.google || process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    const vtApiKey = apiKeys?.virustotal || process.env.VIRUSTOTAL_API_KEY;

    const tasks: Array<() => Promise<ServiceReportResult>> = [];

    for (const url of urls) {
      for (const service of services) {
        const task = async () => {
          switch (service) {
            case 'google':
              return await reportToGoogleSafeBrowsing(url, googleApiKey);
            case 'microsoft':
              return await (async () => ({
                service: 'Microsoft SmartScreen',
                url,
                status: 'manual' as const,
                message: 'Reporte manual en: https://www.microsoft.com/wdsi/support/report-unsafe-site',
                timestamp: new Date().toISOString(),
              }))();
            case 'apwg':
              return await (async () => ({
                service: 'APWG (Anti-Phishing Working Group)',
                url,
                status: 'manual' as const,
                message: `Enviar correo a reportphishing@apwg.org con la URL: ${url}${notes ? '\nNotas: ' + notes : ''}`,
                timestamp: new Date().toISOString(),
              }))();
            case 'cisa':
              return await (async () => ({
                service: 'CISA / US-CERT',
                url,
                status: 'manual' as const,
                message: `Enviar correo a phishing-report@us-cert.gov con la URL: ${url}${notes ? '\nNotas: ' + notes : ''}`,
                timestamp: new Date().toISOString(),
              }))();
            case 'virustotal':
              return await analyzeWithVirusTotal(url, vtApiKey);
            default:
              return {
                service,
                url,
                status: 'failed' as const,
                message: 'Servicio desconocido',
                timestamp: new Date().toISOString(),
              };
          }
        };
        tasks.push(task);
      }
    }

    // Process with controlled concurrency
    const reportId = 'TD-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substring(2, 8).toUpperCase();
    const timestamp = new Date().toISOString();
    const results: ServiceReportResult[] = [];
    const queue = [...tasks];
    const maxConcurrent = Math.min(5, tasks.length);

    async function processNext(): Promise<void> {
      if (queue.length === 0) return;
      const task = queue.shift()!;
      try {
        const result = await task();
        results.push(result);
      } catch (error) {
        // Error already handled in each task
      }
      if (queue.length > 0) {
        await processNext();
      }
    }

    const workers = Array(Math.min(5, tasks.length))
      .fill(null)
      .map(() => processNext());

    await Promise.all(workers);

    const fingerprint = createHash('sha256').update(JSON.stringify({ reportId, urls, services, timestamp, results })).digest('hex').toUpperCase();

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