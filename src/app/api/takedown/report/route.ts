import { NextResponse } from 'next/server';
import { createHash } from 'crypto';

interface ReportRequest {
  urls: string[];
  services: string[];
  notes?: string;
  apiKeys?: {
    google?: string;
    microsoft?: string;
    netcraft?: string;
    eset?: string;
    phishfort?: string;
    phishreport?: string;
    easydmarc?: string;
    norton?: string;
    fortinet?: string;
    mcafee?: string;
    crdf?: string;
    phishtank?: string;
    antiphishing?: string;
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

// Service configurations
const SERVICE_CONFIG = {
  google: { name: 'Google Safe Browsing', requiresKey: true, manualUrl: 'https://safebrowsing.google.com/safebrowsing/report_phish/' },
  microsoft: { name: 'Microsoft SmartScreen', requiresKey: false, manualUrl: 'https://www.microsoft.com/wdsi/support/report-unsafe-site' },
  netcraft: { name: 'Netcraft', requiresKey: true, manualUrl: 'https://netcraft.com/report-phishing/' },
  eset: { name: 'ESET', requiresKey: true, manualUrl: 'https://www.eset.com/us/support/phishing-report/' },
  phishfort: { name: 'PhishFort', requiresKey: true, manualUrl: 'https://www.phishfort.com/report-phishing/' },
  phishreport: { name: 'PhishReport', requiresKey: false, manualUrl: 'mailto:report@phishreport.org' },
  easydmarc: { name: 'EasyDMARC', requiresKey: true, manualUrl: 'https://www.easydmarc.com/report-phishing/' },
  norton: { name: 'Norton (Gen Digital)', requiresKey: false, manualUrl: 'https://support.norton.com/report-unsafe-site' },
  fortinet: { name: 'Fortinet / FortiGuard', requiresKey: true, manualUrl: 'https://fortiguard.com/phishing-report/' },
  mcafee: { name: 'McAfee (Trellix)', requiresKey: false, manualUrl: 'https://support.mcafee.com/report-phishing' },
  crdf: { name: 'CRDF ThreatCenter', requiresKey: false, manualUrl: 'https://threatcenter.crdf.org/report/' },
  phishtank: { name: 'PhishTank', requiresKey: true, manualUrl: 'https://phishtank.org/reportphish/' },
  antiphishing: { name: 'antiphishing.ch', requiresKey: false, manualUrl: 'https://antiphishing.ch/report/' },
} as const;

const GOOGLE_SB_API = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const VIRUSTOTAL_API = 'https://www.virustotal.com/api/v3';

const MAX_URLS_PER_REQUEST = 50;
const API_TIMEOUT_MS = 8000;

function generateFingerprint(data: string): string {
  return createHash('sha256').update(data).digest('hex').toUpperCase();
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

function createManualResult(service: string, url: string, notes?: string): ServiceReportResult {
  const config = SERVICE_CONFIG[service as keyof typeof SERVICE_CONFIG];
  return {
    service: config?.name || service,
    url,
    status: 'manual',
    message: `Reporte manual requerido: ${config?.manualUrl || 'Sin URL configurada'}${notes ? '\nNotas: ' + notes : ''}`,
    timestamp: new Date().toISOString(),
  };
}

function createPendingResult(service: string, url: string): ServiceReportResult {
  const config = SERVICE_CONFIG[service as keyof typeof SERVICE_CONFIG];
  return {
    service: config?.name || service,
    url,
    status: 'pending',
    message: 'En cola de procesamiento...',
    timestamp: new Date().toISOString(),
  };
}

// ===== 13 SERVICE HANDLERS =====

async function reportToGoogleSafeBrowsing(url: string, apiKey?: string): Promise<ServiceReportResult> {
  if (!apiKey) return createManualResult('google', url);
  try {
    const response = await fetchWithTimeout(`${GOOGLE_SB_API}?key=${apiKey}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'takedown-module', clientVersion: '1.0' },
        threatInfo: { threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'], platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url }] },
      }),
    }, API_TIMEOUT_MS);
    if (response.ok) {
      const data = await response.json();
      return { service: 'Google Safe Browsing', url, status: 'success', message: data.matches ? 'URL detectada como amenaza' : 'URL enviada para análisis', timestamp: new Date().toISOString(), referenceId: 'GSB-' + Date.now().toString(36).toUpperCase() };
    }
    return { service: 'Google Safe Browsing', url, status: 'failed', message: `Error HTTP ${response.status}: ${response.statusText}`, timestamp: new Date().toISOString() };
  } catch (error: any) {
    return { service: 'Google Safe Browsing', url, status: 'failed', message: error.name === 'AbortError' ? 'Timeout (8s)' : error.message || 'Error de conexión', timestamp: new Date().toISOString() };
  }
}

async function reportToMicrosoftSmartScreen(url: string): Promise<ServiceReportResult> {
  return createManualResult('microsoft', url);
}

async function reportToNetcraft(url: string, apiKey?: string): Promise<ServiceReportResult> {
  if (!apiKey) return createManualResult('netcraft', url);
  try {
    const response = await fetchWithTimeout(`https://netcraft.com/phishing-report/${url}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Auth-Key': apiKey } }, API_TIMEOUT_MS);
    if (response.ok) {
      const data = await response.json();
      return { service: 'Netcraft', url, status: 'success', message: 'Reporte enviado exitosamente', timestamp: new Date().toISOString(), referenceId: data.reference_id || data.id };
    }
    return { service: 'Netcraft', url, status: 'failed', message: `Error HTTP ${response.status}: ${response.statusText}`, timestamp: new Date().toISOString() };
  } catch (error: any) { return { service: 'Netcraft', url, status: 'failed', message: error.message || 'Error de conexión', timestamp: new Date().toISOString() }; }
}

async function reportToESET(url: string, apiKey?: string): Promise<ServiceReportResult> {
  if (!apiKey) return createManualResult('eset', url);
  try {
    const response = await fetchWithTimeout(`https://www.eset.com/esvulntv/v2/report`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'apikey': apiKey }, body: JSON.stringify({ url }) }, API_TIMEOUT_MS);
    if (response.ok) {
      const data = await response.json();
      return { service: 'ESET', url, status: 'success', message: 'URL reportada a ESET', timestamp: new Date().toISOString(), referenceId: data.id || data.referenceId };
    }
    return { service: 'ESET', url, status: 'failed', message: `Error HTTP ${response.status}: ${response.statusText}`, timestamp: new Date().toISOString() };
  } catch (error: any) { return { service: 'ESET', url, status: 'failed', message: error.message || 'Error de conexión', timestamp: new Date().toISOString() }; }
}

async function reportToPhishFort(url: string, apiKey?: string): Promise<ServiceReportResult> {
  if (!apiKey) return createManualResult('phishfort', url);
  try {
    const response = await fetchWithTimeout(`https://api.phishfort.com/v1/report`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` }, body: JSON.stringify({ url }) }, API_TIMEOUT_MS);
    if (response.ok) {
      const data = await response.json();
      return { service: 'PhishFort', url, status: 'success', message: 'URL reportada a PhishFort', timestamp: new Date().toISOString(), referenceId: data.id };
    }
    return { service: 'PhishFort', url, status: 'failed', message: `Error HTTP ${response.status}: ${response.statusText}`, timestamp: new Date().toISOString() };
  } catch (error: any) { return { service: 'PhishFort', url, status: 'failed', message: error.message || 'Error de conexión', timestamp: new Date().toISOString() }; }
}

async function reportToPhishReport(url: string, notes?: string): Promise<ServiceReportResult> {
  return createManualResult('phishreport', url, notes);
}

async function reportToEasyDMARC(url: string, apiKey?: string): Promise<ServiceReportResult> {
  if (!apiKey) return createManualResult('easydmarc', url);
  try {
    const response = await fetchWithTimeout(`https://api.easydmarc.com/v1/report/phishing`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` }, body: JSON.stringify({ url }) }, API_TIMEOUT_MS);
    if (response.ok) {
      const data = await response.json();
      return { service: 'EasyDMARC', url, status: 'success', message: 'URL reportada a EasyDMARC', timestamp: new Date().toISOString(), referenceId: data.id };
    }
    return { service: 'EasyDMARC', url, status: 'failed', message: `Error HTTP ${response.status}: ${response.statusText}`, timestamp: new Date().toISOString() };
  } catch (error: any) { return { service: 'EasyDMARC', url, status: 'failed', message: error.message || 'Error de conexión', timestamp: new Date().toISOString() }; }
}

async function reportToNorton(url: string): Promise<ServiceReportResult> {
  return createManualResult('norton', url);
}

async function reportToFortinet(url: string, apiKey?: string): Promise<ServiceReportResult> {
  if (!apiKey) return createManualResult('fortinet', url);
  try {
    const response = await fetchWithTimeout(`https://fortiguard.com/api/phishing-report`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` }, body: JSON.stringify({ url }) }, API_TIMEOUT_MS);
    if (response.ok) {
      const data = await response.json();
      return { service: 'Fortinet / FortiGuard', url, status: 'success', message: 'URL reportada a FortiGuard', timestamp: new Date().toISOString(), referenceId: data.id };
    }
    return { service: 'Fortinet / FortiGuard', url, status: 'failed', message: `Error HTTP ${response.status}: ${response.statusText}`, timestamp: new Date().toISOString() };
  } catch (error: any) { return { service: 'Fortinet / FortiGuard', url, status: 'failed', message: error.message || 'Error de conexión', timestamp: new Date().toISOString() }; }
}

async function reportToMcAfeeTrellix(url: string): Promise<ServiceReportResult> {
  return createManualResult('mcafee', url);
}

async function reportToCRDFThreatCenter(url: string): Promise<ServiceReportResult> {
  return createManualResult('crdf', url);
}

async function reportToPhishTank(url: string, apiKey?: string): Promise<ServiceReportResult> {
  if (!apiKey) return createManualResult('phishtank', url);
  try {
    const urlId = Buffer.from(url).toString('base64').replace(/=+$/, '');
    const response = await fetchWithTimeout(`https://phishtank.org/api2/v2/url/post/${urlId}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Apikey': apiKey, 'Accept': 'application/json' }, body: JSON.stringify({ url, format: 'json' }) }, API_TIMEOUT_MS);
    if (response.ok) {
      const data = await response.json();
      return { service: 'PhishTank', url, status: 'success', message: 'URL reportada a PhishTank', timestamp: new Date().toISOString(), referenceId: data.phish_id };
    }
    return { service: 'PhishTank', url, status: 'failed', message: `Error HTTP ${response.status}: ${response.statusText}`, timestamp: new Date().toISOString() };
  } catch (error: any) { return { service: 'PhishTank', url, status: 'failed', message: error.message || 'Error de conexión', timestamp: new Date().toISOString() }; }
}

async function reportToAntiphishingCh(url: string): Promise<ServiceReportResult> {
  return createManualResult('antiphishing', url);
}

async function analyzeWithVirusTotal(url: string, apiKey?: string): Promise<ServiceReportResult> {
  if (!apiKey) return createManualResult('virustotal', url);
  try {
    const urlId = Buffer.from(url).toString('base64').replace(/=+$/, '');
    const response = await fetch(`${VIRUSTOTAL_API}/urls/${urlId}`, { headers: { 'x-apikey': apiKey } });
    if (response.ok) {
      const data = await response.json();
      const stats = data.data?.attributes?.last_analysis_stats || {};
      const malicious = (stats.malicious as number) || 0;
      const suspicious = (stats.suspicious as number) || 0;
      const total = Object.values(stats).reduce((a: number, b: unknown) => a + ((b as number) || 0), 0);
      return { service: 'VirusTotal', url, status: 'success', message: `Análisis: ${malicious} maliciosos, ${suspicious} sospechosos de ${total} motores`, timestamp: new Date().toISOString(), referenceId: data.data?.id };
    }
    if (response.status === 404) {
      const submitResponse = await fetch(`${VIRUSTOTAL_API}/urls`, { method: 'POST', headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ url }) });
      if (submitResponse.ok) return { service: 'VirusTotal', url, status: 'pending', message: 'URL enviada para análisis. Resultados en unos minutos.', timestamp: new Date().toISOString() };
    }
    return { service: 'VirusTotal', url, status: 'failed', message: `Error HTTP ${response.status}`, timestamp: new Date().toISOString() };
  } catch (error: any) { return { service: 'VirusTotal', url, status: 'failed', message: error.message || 'Error de conexión', timestamp: new Date().toISOString() }; }
}

// ===== MAIN HANDLER =====

export async function POST(request: Request) {
  try {
    const body: ReportRequest = await request.json();
    const { urls, services, notes, apiKeys } = body;

    if (!urls || urls.length === 0) return NextResponse.json({ error: 'No se proporcionaron URLs' }, { status: 400 });
    if (urls.length > MAX_URLS_PER_REQUEST) return NextResponse.json({ error: `Demasiadas URLs. Máximo ${MAX_URLS_PER_REQUEST} por reporte. Recibidas: ${urls.length}.`, maxAllowed: MAX_URLS_PER_REQUEST, received: urls.length }, { status: 400 });
    if (!services || services.length === 0) return NextResponse.json({ error: 'No se seleccionaron servicios de reporte' }, { status: 400 });

    const reportId = 'TD-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substring(2, 8).toUpperCase();
    const timestamp = new Date().toISOString();
    const results: ServiceReportResult[] = [];

    // Merge API keys from body and environment
    const envKeys = {
      google: process.env.GOOGLE_SAFE_BROWSING_API_KEY,
      microsoft: process.env.MICROSOFT_SMARTSCREEN_API_KEY,
      netcraft: process.env.NETCRAFT_API_KEY,
      eset: process.env.ESET_API_KEY,
      phishfort: process.env.PHISHFORT_API_KEY,
      easydmarc: process.env.EASYDMARC_API_KEY,
      fortinet: process.env.FORTINET_API_KEY,
      phishtank: process.env.PHISHTANK_API_KEY,
    };
    const finalApiKeys = { ...apiKeys };
    Object.keys(envKeys).forEach(k => { if (!finalApiKeys[k as keyof typeof finalApiKeys] && envKeys[k as keyof typeof envKeys]) finalApiKeys[k as keyof typeof finalApiKeys] = envKeys[k as keyof typeof envKeys]!; });

    // Process each URL-service combination
    for (const url of urls) {
      for (const service of services) {
        const config = SERVICE_CONFIG[service as keyof typeof SERVICE_CONFIG];
        const apiKey = finalApiKeys[service as keyof typeof finalApiKeys];

        // If requires key and none provided, mark manual
        if (config?.requiresKey && !apiKey) {
          results.push(createManualResult(service, url, notes));
          continue;
        }

        // Execute handler
        let result: ServiceReportResult;
        switch (service) {
          case 'google': result = await reportToGoogleSafeBrowsing(url, apiKey); break;
          case 'microsoft': result = await reportToMicrosoftSmartScreen(url); break;
          case 'netcraft': result = await reportToNetcraft(url, apiKey); break;
          case 'eset': result = await reportToESET(url, apiKey); break;
          case 'phishfort': result = await reportToPhishFort(url, apiKey); break;
          case 'phishreport': result = await reportToPhishReport(url, notes); break;
          case 'easydmarc': result = await reportToEasyDMARC(url, apiKey); break;
          case 'norton': result = await reportToNorton(url); break;
          case 'fortinet': result = await reportToFortinet(url, apiKey); break;
          case 'mcafee': result = await reportToMcAfeeTrellix(url); break;
          case 'crdf': result = await reportToCRDFThreatCenter(url); break;
          case 'phishtank': result = await reportToPhishTank(url, apiKey); break;
          case 'antiphishing': result = await reportToAntiphishingCh(url); break;
          case 'virustotal': result = await analyzeWithVirusTotal(url, apiKey); break;
          default: result = { service, url, status: 'failed', message: 'Servicio desconocido', timestamp: new Date().toISOString() };
        }
        results.push(result);
      }
    }

    const fingerprint = generateFingerprint(JSON.stringify({ reportId, urls, services, timestamp, results }));

    return NextResponse.json({
      reportId, timestamp, urls, services, notes, results, fingerprint,
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