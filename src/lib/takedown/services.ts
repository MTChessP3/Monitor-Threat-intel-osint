import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export interface ServiceConfig {
  service: string;
  serviceName: string;
  enabled: boolean;
  apiEndpoint?: string;
  apiKey?: string;
  config?: Record<string, unknown>;
  rateLimit?: number;
  timeout: number;
  retryPolicy?: Record<string, unknown>;
  isManual: boolean;
  manualUrl?: string;
  manualInstructions?: string;
}

export interface ServiceResultData {
  service: string;
  serviceName: string;
  url: string;
  status: 'pending' | 'sent' | 'success' | 'failed' | 'manual' | 'rate_limited';
  message?: string;
  referenceId?: string;
  requestPayload?: Record<string, unknown>;
  responsePayload?: Record<string, unknown>;
  errorDetails?: string;
}

export interface ReportUrlParams {
  url: string;
  notes?: string;
  apiKeys?: Record<string, string>;
  batchId: string;
  reportId?: string;
  userId: string;
}

const SERVICE_CONFIGS: Record<string, ServiceConfig> = {
  google: {
    service: 'google',
    serviceName: 'Google Safe Browsing',
    enabled: true,
    apiEndpoint: 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
    timeout: 30000,
    isManual: false,
    manualUrl: 'https://safebrowsing.google.com/safebrowsing/report_phish/',
    manualInstructions: 'Submit URL manually at safebrowsing.google.com',
    retryPolicy: { maxRetries: 3, backoffMs: 5000 },
  },
  microsoft: {
    service: 'microsoft',
    serviceName: 'Microsoft SmartScreen',
    enabled: true,
    apiEndpoint: 'https://api.smartscreen.microsoft.com/report',
    timeout: 30000,
    isManual: true,
    manualUrl: 'https://www.microsoft.com/wdsi/support/report-unsafe-site',
    manualInstructions: 'Submit via Microsoft WDSI portal',
  },
  netcraft: {
    service: 'netcraft',
    serviceName: 'Netcraft',
    enabled: true,
    apiEndpoint: 'https://report.netcraft.com/api/v2/report',
    timeout: 30000,
    isManual: false,
    manualUrl: 'https://report.netcraft.com/',
    manualInstructions: 'Submit URL via Netcraft report page',
    retryPolicy: { maxRetries: 3, backoffMs: 5000 },
  },
  eset: {
    service: 'eset',
    serviceName: 'ESET',
    enabled: true,
    apiEndpoint: 'https://www.eset.com/us/home/security-report/',
    timeout: 30000,
    isManual: true,
    manualUrl: 'https://www.eset.com/us/home/security-report/',
    manualInstructions: 'Submit via ESET threat report form',
  },
  phishfort: {
    service: 'phishfort',
    serviceName: 'PhishFort',
    enabled: true,
    apiEndpoint: 'https://phishfort.com/report/',
    timeout: 30000,
    isManual: true,
    manualUrl: 'https://phishfort.com/report/',
    manualInstructions: 'Submit via PhishFort report page',
  },
  phishreport: {
    service: 'phishreport',
    serviceName: 'PhishReport',
    enabled: true,
    apiEndpoint: 'https://phish.report/api/v1/report',
    timeout: 30000,
    isManual: false,
    manualUrl: 'https://phish.report/',
    manualInstructions: 'Submit via PhishReport',
    retryPolicy: { maxRetries: 3, backoffMs: 5000 },
  },
  easydmarc: {
    service: 'easydmarc',
    serviceName: 'EasyDMARC',
    enabled: true,
    apiEndpoint: 'https://api.easydmarc.com/v1/phishing/report',
    timeout: 30000,
    isManual: false,
    manualUrl: 'https://easydmarc.com/tools/phishing-report/',
    manualInstructions: 'Submit via EasyDMARC phishing report tool',
    retryPolicy: { maxRetries: 3, backoffMs: 5000 },
  },
  norton: {
    service: 'norton',
    serviceName: 'Norton (Gen Digital)',
    enabled: true,
    apiEndpoint: 'https://submit.symantec.com/submit-url/',
    timeout: 30000,
    isManual: true,
    manualUrl: 'https://submit.symantec.com/url/',
    manualInstructions: 'Submit via Norton Safe Web submission',
  },
  fortinet: {
    service: 'fortinet',
    serviceName: 'Fortinet / FortiGuard',
    enabled: true,
    apiEndpoint: 'https://www.fortiguard.com/url-submission',
    timeout: 30000,
    isManual: true,
    manualUrl: 'https://www.fortiguard.com/url-submission',
    manualInstructions: 'Submit URL via FortiGuard URL submission',
  },
  mcafee: {
    service: 'mcafee',
    serviceName: 'McAfee (Trellix)',
    enabled: true,
    apiEndpoint: 'https://www.mcafee.com/enterprise/en-us/assets/submit-url.html',
    timeout: 30000,
    isManual: true,
    manualUrl: 'https://www.mcafee.com/enterprise/en-us/assets/submit-url.html',
    manualInstructions: 'Submit via McAfee/Trellix URL submission',
  },
  crdf: {
    service: 'crdf',
    serviceName: 'CRDF ThreatCenter',
    enabled: true,
    apiEndpoint: 'https://threatcenter.crdf.ru/api/report',
    timeout: 30000,
    isManual: false,
    manualUrl: 'https://threatcenter.crdf.ru/',
    manualInstructions: 'Submit via CRDF ThreatCenter',
    retryPolicy: { maxRetries: 3, backoffMs: 5000 },
  },
  phishtank: {
    service: 'phishtank',
    serviceName: 'PhishTank',
    enabled: true,
    apiEndpoint: 'https://phishtank.org/phish_detail.php',
    timeout: 30000,
    isManual: true,
    manualUrl: 'https://phishtank.org/phish_detail.php',
    manualInstructions: 'Submit via PhishTank submission form',
  },
  antiphishing_ch: {
    service: 'antiphishing_ch',
    serviceName: 'antiphishing.ch',
    enabled: true,
    apiEndpoint: 'https://antiphishing.ch/report/',
    timeout: 30000,
    isManual: true,
    manualUrl: 'https://antiphishing.ch/report/',
    manualInstructions: 'Submit via antiphishing.ch report form',
  },
};

function getConfig(service: string): ServiceConfig {
  return SERVICE_CONFIGS[service] || {
    service,
    serviceName: service,
    enabled: false,
    timeout: 30000,
    isManual: true,
  };
}

async function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function fetchWithTimeout(url: string, options: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    return response;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  maxRetries: number,
  baseDelayMs: number
): Promise<T> {
  let lastError: Error | undefined;
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      
      if (attempt < maxRetries) {
        const delay = baseDelayMs * Math.pow(2, attempt) + Math.random() * 1000;
        await sleep(delay);
      }
    }
  }
  
  throw lastError;
}

export async function reportToGoogleSafeBrowsing(
  url: string,
  apiKey?: string
): Promise<ServiceResultData> {
  const config = getConfig('google');
  
  if (!apiKey && !config.apiKey) {
    return {
      service: 'google',
      serviceName: config.serviceName,
      url,
      status: 'manual',
      message: `Requiere API Key. Reporte manual en: ${config.manualUrl}`,
      referenceId: undefined,
    };
  }

  const key = apiKey || config.apiKey;
  
  try {
    const response = await fetchWithTimeout(
      `${config.apiEndpoint}?key=${key}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'nexus-takedown', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }],
          },
        }),
      },
      config.timeout
    );

    const requestPayload = { url, threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'] };
    
    if (response.ok) {
      const data = await response.json();
      return {
        service: 'google',
        serviceName: config.serviceName,
        url,
        status: 'success',
        message: data.matches ? 'URL detectada como amenaza conocida' : 'URL enviada para análisis',
        referenceId: 'GSB-' + Date.now().toString(36).toUpperCase(),
        requestPayload,
        responsePayload: data,
      };
    }

    const errorText = await response.text();
    return {
      service: 'google',
      serviceName: config.serviceName,
      url,
      status: response.status === 429 ? 'rate_limited' : 'failed',
      message: `Error HTTP ${response.status}: ${errorText}`,
      requestPayload,
      errorDetails: errorText,
    };
  } catch (error) {
    return {
      service: 'google',
      serviceName: config.serviceName,
      url,
      status: 'failed',
      message: error instanceof Error ? error.message : 'Error de conexión',
      errorDetails: error instanceof Error ? error.stack : String(error),
    };
  }
}

export async function reportToMicrosoftSmartScreen(url: string): Promise<ServiceResultData> {
  const config = getConfig('microsoft');
  
  return {
    service: 'microsoft',
    serviceName: config.serviceName,
    url,
    status: 'manual',
    message: `Reporte manual requerido. Envíe a: ${config.manualUrl}`,
    referenceId: undefined,
  };
}

export async function reportToNetcraft(
  url: string,
  apiKey?: string
): Promise<ServiceResultData> {
  const config = getConfig('netcraft');
  
  if (!apiKey && !config.apiKey) {
    return {
      service: 'netcraft',
      serviceName: config.serviceName,
      url,
      status: 'manual',
      message: `Requiere API Key. Reporte manual en: ${config.manualUrl}`,
    };
  }

  try {
    const response = await fetchWithTimeout(
      config.apiEndpoint!,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey || config.apiKey}`,
        },
        body: JSON.stringify({ url, category: 'phishing' }),
      },
      config.timeout
    );

    if (response.ok) {
      const data = await response.json();
      return {
        service: 'netcraft',
        serviceName: config.serviceName,
        url,
        status: 'success',
        message: 'URL reportada a Netcraft exitosamente',
        referenceId: data.reportId || 'NC-' + Date.now().toString(36).toUpperCase(),
      };
    }

    return {
      service: 'netcraft',
      serviceName: config.serviceName,
      url,
      status: response.status === 429 ? 'rate_limited' : 'failed',
      message: `Error HTTP ${response.status}`,
    };
  } catch (error) {
    return {
      service: 'netcraft',
      serviceName: config.serviceName,
      url,
      status: 'failed',
      message: error instanceof Error ? error.message : 'Error de conexión',
    };
  }
}

export async function reportToESET(url: string, notes?: string): Promise<ServiceResultData> {
  const config = getConfig('eset');
  
  return {
    service: 'eset',
    serviceName: config.serviceName,
    url,
    status: 'manual',
    message: `Enviar formulario en ${config.manualUrl} con URL: ${url}${notes ? '\nNotas: ' + notes : ''}`,
  };
}

export async function reportToPhishFort(url: string, notes?: string): Promise<ServiceResultData> {
  const config = getConfig('phishfort');
  
  return {
    service: 'phishfort',
    serviceName: config.serviceName,
    url,
    status: 'manual',
    message: `Enviar reporte en ${config.manualUrl} con URL: ${url}${notes ? '\nNotas: ' + notes : ''}`,
  };
}

export async function reportToPhishReport(
  url: string,
  apiKey?: string
): Promise<ServiceResultData> {
  const config = getConfig('phishreport');
  
  if (!apiKey && !config.apiKey) {
    return {
      service: 'phishreport',
      serviceName: config.serviceName,
      url,
      status: 'manual',
      message: `Requiere API Key. Reporte manual en: ${config.manualUrl}`,
    };
  }

  try {
    const response = await fetchWithTimeout(
      config.apiEndpoint!,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey || config.apiKey}`,
        },
        body: JSON.stringify({ url }),
      },
      config.timeout
    );

    if (response.ok) {
      const data = await response.json();
      return {
        service: 'phishreport',
        serviceName: config.serviceName,
        url,
        status: 'success',
        message: 'URL reportada a PhishReport exitosamente',
        referenceId: data.id || 'PR-' + Date.now().toString(36).toUpperCase(),
      };
    }

    return {
      service: 'phishreport',
      serviceName: config.serviceName,
      url,
      status: response.status === 429 ? 'rate_limited' : 'failed',
      message: `Error HTTP ${response.status}`,
    };
  } catch (error) {
    return {
      service: 'phishreport',
      serviceName: config.serviceName,
      url,
      status: 'failed',
      message: error instanceof Error ? error.message : 'Error de conexión',
    };
  }
}

export async function reportToEasyDMARC(
  url: string,
  apiKey?: string
): Promise<ServiceResultData> {
  const config = getConfig('easydmarc');
  
  if (!apiKey && !config.apiKey) {
    return {
      service: 'easydmarc',
      serviceName: config.serviceName,
      url,
      status: 'manual',
      message: `Requiere API Key. Reporte manual en: ${config.manualUrl}`,
    };
  }

  try {
    const response = await fetchWithTimeout(
      config.apiEndpoint!,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey || config.apiKey}`,
        },
        body: JSON.stringify({ url, type: 'phishing' }),
      },
      config.timeout
    );

    if (response.ok) {
      const data = await response.json();
      return {
        service: 'easydmarc',
        serviceName: config.serviceName,
        url,
        status: 'success',
        message: 'URL reportada a EasyDMARC exitosamente',
        referenceId: data.report_id || 'ED-' + Date.now().toString(36).toUpperCase(),
      };
    }

    return {
      service: 'easydmarc',
      serviceName: config.serviceName,
      url,
      status: response.status === 429 ? 'rate_limited' : 'failed',
      message: `Error HTTP ${response.status}`,
    };
  } catch (error) {
    return {
      service: 'easydmarc',
      serviceName: config.serviceName,
      url,
      status: 'failed',
      message: error instanceof Error ? error.message : 'Error de conexión',
    };
  }
}

export async function reportToNorton(url: string, notes?: string): Promise<ServiceResultData> {
  const config = getConfig('norton');
  
  return {
    service: 'norton',
    serviceName: config.serviceName,
    url,
    status: 'manual',
    message: `Enviar a ${config.manualUrl} con URL: ${url}${notes ? '\nNotas: ' + notes : ''}`,
  };
}

export async function reportToFortinet(url: string, notes?: string): Promise<ServiceResultData> {
  const config = getConfig('fortinet');
  
  return {
    service: 'fortinet',
    serviceName: config.serviceName,
    url,
    status: 'manual',
    message: `Enviar a ${config.manualUrl} con URL: ${url}${notes ? '\nNotas: ' + notes : ''}`,
  };
}

export async function reportToMcAfee(url: string, notes?: string): Promise<ServiceResultData> {
  const config = getConfig('mcafee');
  
  return {
    service: 'mcafee',
    serviceName: config.serviceName,
    url,
    status: 'manual',
    message: `Enviar a ${config.manualUrl} con URL: ${url}${notes ? '\nNotas: ' + notes : ''}`,
  };
}

export async function reportToCRDF(
  url: string,
  apiKey?: string
): Promise<ServiceResultData> {
  const config = getConfig('crdf');
  
  if (!apiKey && !config.apiKey) {
    return {
      service: 'crdf',
      serviceName: config.serviceName,
      url,
      status: 'manual',
      message: `Requiere API Key. Reporte manual en: ${config.manualUrl}`,
    };
  }

  try {
    const response = await fetchWithTimeout(
      config.apiEndpoint!,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey || config.apiKey}`,
        },
        body: JSON.stringify({ url, type: 'phishing' }),
      },
      config.timeout
    );

    if (response.ok) {
      const data = await response.json();
      return {
        service: 'crdf',
        serviceName: config.serviceName,
        url,
        status: 'success',
        message: 'URL reportada a CRDF ThreatCenter exitosamente',
        referenceId: data.id || 'CRDF-' + Date.now().toString(36).toUpperCase(),
      };
    }

    return {
      service: 'crdf',
      serviceName: config.serviceName,
      url,
      status: response.status === 429 ? 'rate_limited' : 'failed',
      message: `Error HTTP ${response.status}`,
    };
  } catch (error) {
    return {
      service: 'crdf',
      serviceName: config.serviceName,
      url,
      status: 'failed',
      message: error instanceof Error ? error.message : 'Error de conexión',
    };
  }
}

export async function reportToPhishTank(url: string, notes?: string): Promise<ServiceResultData> {
  const config = getConfig('phishtank');
  
  return {
    service: 'phishtank',
    serviceName: config.serviceName,
    url,
    status: 'manual',
    message: `Enviar formulario en ${config.manualUrl} con URL: ${url}${notes ? '\nNotas: ' + notes : ''}`,
  };
}

export async function reportToAntiPhishingCH(url: string, notes?: string): Promise<ServiceResultData> {
  const config = getConfig('antiphishing_ch');
  
  return {
    service: 'antiphishing_ch',
    serviceName: config.serviceName,
    url,
    status: 'manual',
    message: `Enviar reporte en ${config.manualUrl} con URL: ${url}${notes ? '\nNotas: ' + notes : ''}`,
  };
}

export async function reportToVirusTotal(
  url: string,
  apiKey?: string
): Promise<ServiceResultData> {
  const config = { ...getConfig('virustotal'), apiEndpoint: 'https://www.virustotal.com/api/v3' };
  
  if (!apiKey && !config.apiKey) {
    const urlId = Buffer.from(url).toString('base64').replace(/=+$/, '');
    return {
      service: 'virustotal',
      serviceName: 'VirusTotal',
      url,
      status: 'manual',
      message: `Requiere API Key. Analice manualmente en: https://www.virustotal.com/gui/url/${urlId}`,
    };
  }

  try {
    const urlId = Buffer.from(url).toString('base64').replace(/=+$/, '');
    const response = await fetchWithTimeout(
      `${config.apiEndpoint}/urls/${urlId}`,
      {
        headers: { 'x-apikey': apiKey || config.apiKey! },
      },
      config.timeout
    );

    if (response.ok) {
      const data = await response.json();
      const stats = data.data?.attributes?.last_analysis_stats || {};
      const malicious = (stats.malicious as number) || 0;
      const suspicious = (stats.suspicious as number) || 0;
      const total = Object.values(stats).reduce((a: number, b: unknown) => a + ((b as number) || 0), 0);

      return {
        service: 'virustotal',
        serviceName: 'VirusTotal',
        url,
        status: 'success',
        message: `Análisis: ${malicious} maliciosos, ${suspicious} sospechosos de ${total} motores`,
        referenceId: data.data?.id,
      };
    }

    if (response.status === 404) {
      const submitResponse = await fetchWithTimeout(
        `${config.apiEndpoint}/urls`,
        {
          method: 'POST',
          headers: {
            'x-apikey': apiKey || config.apiKey!,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({ url }),
        },
        config.timeout
      );

      if (submitResponse.ok) {
        return {
          service: 'virustotal',
          serviceName: 'VirusTotal',
          url,
          status: 'pending',
          message: 'URL enviada para análisis. Resultados en unos minutos.',
        };
      }
    }

    return {
      service: 'virustotal',
      serviceName: 'VirusTotal',
      url,
      status: response.status === 429 ? 'rate_limited' : 'failed',
      message: `Error HTTP ${response.status}`,
    };
  } catch (error) {
    return {
      service: 'virustotal',
      serviceName: 'VirusTotal',
      url,
      status: 'failed',
      message: error instanceof Error ? error.message : 'Error de conexión',
    };
  }
}

export async function reportToAPWG(url: string, notes?: string): Promise<ServiceResultData> {
  return {
    service: 'apwg',
    serviceName: 'APWG (Anti-Phishing Working Group)',
    url,
    status: 'manual',
    message: `Enviar correo a reportphishing@apwg.org con la URL: ${url}${notes ? '\nNotas: ' + notes : ''}`,
  };
}

export async function reportToCISA(url: string, notes?: string): Promise<ServiceResultData> {
  return {
    service: 'cisa',
    serviceName: 'CISA / US-CERT',
    url,
    status: 'manual',
    message: `Enviar correo a phishing-report@us-cert.gov con la URL: ${url}${notes ? '\nNotas: ' + notes : ''}`,
  };
}

type ServiceReportFn = (url: string, apiKey?: string, notes?: string) => Promise<ServiceResultData>;

const SERVICE_REPORT_FNS: Record<string, ServiceReportFn> = {
  google: reportToGoogleSafeBrowsing,
  microsoft: reportToMicrosoftSmartScreen,
  netcraft: reportToNetcraft,
  eset: reportToESET,
  phishfort: reportToPhishFort,
  phishreport: reportToPhishReport,
  easydmarc: reportToEasyDMARC,
  norton: reportToNorton,
  fortinet: reportToFortinet,
  mcafee: reportToMcAfee,
  crdf: reportToCRDF,
  phishtank: reportToPhishTank,
  antiphishing_ch: reportToAntiPhishingCH,
  virustotal: reportToVirusTotal,
  apwg: reportToAPWG,
  cisa: reportToCISA,
};

export async function reportUrlToService(
  service: string,
  url: string,
  apiKeys?: Record<string, string>,
  notes?: string
): Promise<ServiceResultData> {
  const fn = SERVICE_REPORT_FNS[service];
  if (!fn) {
    return {
      service,
      serviceName: service,
      url,
      status: 'failed',
      message: `Servicio desconocido: ${service}`,
    };
  }

  const apiKey = apiKeys?.[service];
  return fn(url, apiKey, notes);
}

export function getAllServices(): ServiceConfig[] {
  return Object.values(SERVICE_CONFIGS);
}

export function getEnabledServices(): string[] {
  return Object.values(SERVICE_CONFIGS)
    .filter(c => c.enabled)
    .map(c => c.service);
}

export function isManualService(service: string): boolean {
  return SERVICE_CONFIGS[service]?.isManual ?? true;
}

export async function storeServiceResult(
  batchId: string,
  reportId: string | undefined,
  result: ServiceResultData
): Promise<void> {
  await prisma.serviceResult.create({
    data: {
      batchId,
      reportId,
      service: result.service,
      serviceName: result.serviceName,
      url: result.url,
      status: result.status,
      message: result.message,
      referenceId: result.referenceId,
      requestPayload: result.requestPayload ? JSON.stringify(result.requestPayload) : null,
      responsePayload: result.responsePayload ? JSON.stringify(result.responsePayload) : null,
      errorDetails: result.errorDetails,
    },
  });
}

export async function createAuditLog(
  userId: string,
  action: string,
  entityType: string,
  entityId: string,
  details?: Record<string, unknown>,
  ipAddress?: string,
  userAgent?: string
): Promise<void> {
  await prisma.auditLog.create({
    data: {
      userId,
      action,
      entityType,
      entityId,
      details: details ? JSON.stringify(details) : null,
      ipAddress,
      userAgent,
    },
  });
}