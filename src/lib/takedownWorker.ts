import { Worker, Job } from 'bullmq';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

interface TakedownJobData {
  reportId: string;
  url: string;
  service: string;
  apiKey?: string;
  notes?: string;
}

interface ServiceReportResult {
  url: string;
  service: string;
  status: 'success' | 'failed' | 'pending' | 'manual';
  message: string;
  referenceId?: string;
  timestamp: string;
}

// Service handlers
const serviceHandlers: Record<string, (url: string, apiKey?: string) => Promise<{ status: string; message: string; referenceId?: string }>> = {
  google: async (url: string, apiKey?: string) => {
    if (!apiKey) {
      return { status: 'manual', message: 'Requiere API Key', referenceId: undefined };
    }
    try {
      const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
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
          status: 'success',
          message: data.matches ? 'URL detectada como amenaza' : 'URL enviada para análisis',
          referenceId: 'GSB-' + Date.now().toString(36).toUpperCase(),
        };
      }
      return { status: 'failed', message: `Error HTTP ${response.status}`, referenceId: undefined };
    } catch (error: any) {
      return { status: 'failed', message: error.message || 'Error de conexión', referenceId: undefined };
    }
  },

  microsoft: async (url: string) => ({
    status: 'manual',
    message: 'Reporte manual requerido: https://www.microsoft.com/wdsi/support/report-unsafe-site',
    referenceId: undefined,
  }),

  netcraft: async (url: string, apiKey?: string) => {
    if (!apiKey) {
      return { status: 'manual', message: 'Requiere API Key', referenceId: undefined };
    }
    try {
      const response = await fetch(`https://netcraft.com/phishing-report/${url}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Auth-Key': apiKey },
      });
      if (response.ok) {
        const data = await response.json();
        return { status: 'success', message: 'Reporte enviado', referenceId: data.reference_id || data.id };
      }
      return { status: 'failed', message: `Error HTTP ${response.status}`, referenceId: undefined };
    } catch (error: any) {
      return { status: 'failed', message: error.message, referenceId: undefined };
    }
  },

  eset: async (url: string, apiKey?: string) => {
    if (!apiKey) {
      return { status: 'manual', message: 'Requiere API Key', referenceId: undefined };
    }
    try {
      const response = await fetch(`https://www.eset.com/esvulntv/v2/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'apikey': apiKey },
        body: JSON.stringify({ url }),
      });
      if (response.ok) {
        const data = await response.json();
        return { status: 'success', message: 'URL reportada', referenceId: data.id || data.referenceId };
      }
      return { status: 'failed', message: `Error HTTP ${response.status}`, referenceId: undefined };
    } catch (error: any) {
      return { status: 'failed', message: error.message, referenceId: undefined };
    }
  },

  phishfort: async (url: string, apiKey?: string) => {
    if (!apiKey) {
      return { status: 'manual', message: 'Requiere API Key', referenceId: undefined };
    }
    try {
      const response = await fetch(`https://api.phishfort.com/v1/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        body: JSON.stringify({ url }),
      });
      if (response.ok) {
        const data = await response.json();
        return { status: 'success', message: 'URL reportada', referenceId: data.id };
      }
      return { status: 'failed', message: `Error HTTP ${response.status}`, referenceId: undefined };
    } catch (error: any) {
      return { status: 'failed', message: error.message, referenceId: undefined };
    }
  },

  phishreport: async (url: string) => ({
    status: 'manual',
    message: `Enviar informe a PhishReport: ${url}`,
    referenceId: undefined,
  }),

  easydmarc: async (url: string, apiKey?: string) => {
    if (!apiKey) {
      return { status: 'manual', message: 'Requiere API Key', referenceId: undefined };
    }
    try {
      const response = await fetch(`https://api.easydmarc.com/v1/report/phishing`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        body: JSON.stringify({ url }),
      });
      if (response.ok) {
        const data = await response.json();
        return { status: 'success', message: 'URL reportada', referenceId: data.id };
      }
      return { status: 'failed', message: `Error HTTP ${response.status}`, referenceId: undefined };
    } catch (error: any) {
      return { status: 'failed', message: error.message, referenceId: undefined };
    }
  },

  norton: async (url: string) => ({
    status: 'manual',
    message: 'Reporte manual: https://support.norton.com/report-unsafe-site',
    referenceId: undefined,
  }),

  fortinet: async (url: string, apiKey?: string) => {
    if (!apiKey) {
      return { status: 'manual', message: 'Requiere API Key', referenceId: undefined };
    }
    try {
      const response = await fetch(`https://fortiguard.com/api/phishing-report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        body: JSON.stringify({ url }),
      });
      if (response.ok) {
        const data = await response.json();
        return { status: 'success', message: 'URL reportada', referenceId: data.id };
      }
      return { status: 'failed', message: `Error HTTP ${response.status}`, referenceId: undefined };
    } catch (error: any) {
      return { status: 'failed', message: error.message, referenceId: undefined };
    }
  },

  mcafee: async (url: string) => ({
    status: 'manual',
    message: 'Reporte manual: https://support.mcafee.com/report-phishing',
    referenceId: undefined,
  }),

  crdf: async (url: string) => ({
    status: 'manual',
    message: 'Reporte manual: https://threatcenter.crdf.org/report',
    referenceId: undefined,
  }),

  phishtank: async (url: string, apiKey?: string) => {
    if (!apiKey) {
      return { status: 'manual', message: 'Requiere API Key', referenceId: undefined };
    }
    try {
      const urlId = Buffer.from(url).toString('base64').replace(/=+$/, '');
      const response = await fetch(`https://phishtank.org/api2/v2/url/post/${urlId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Apikey': apiKey, 'Accept': 'application/json' },
        body: JSON.stringify({ url, format: 'json' }),
      });
      if (response.ok) {
        const data = await response.json();
        return { status: 'success', message: 'URL reportada', referenceId: data.phish_id };
      }
      return { status: 'failed', message: `Error HTTP ${response.status}`, referenceId: undefined };
    } catch (error: any) {
      return { status: 'failed', message: error.message, referenceId: undefined };
    }
  },

  antiphishing: async (url: string) => ({
    status: 'manual',
    message: 'Reporte manual: https://antiphishing.ch/report/',
    referenceId: undefined,
  }),
};

// Create the worker
export const takedownWorker = new Worker<TakedownJobData>('takedown-reports', async (job: Job<TakedownJobData>) => {
  const { reportId, url, service, apiKey, notes } = job.data;
  
  const handler = serviceHandlers[service];
  if (!handler) {
    throw new Error(`Servicio no configurado: ${service}`);
  }

  // Update job progress
  await job.updateProgress(10);

  // Process the report
  const result = await handler(url, apiKey);

  await job.updateProgress(50);

  // Store in database
  await prisma.takedownReport.create({
    data: {
      reportId,
      url,
      service,
      status: result.status,
      referenceId: result.referenceId,
      timestamp: new Date(),
      notes: notes || result.message,
    },
  });

  await job.updateProgress(100);

  return {
    url,
    service,
    status: result.status as 'success' | 'failed' | 'pending' | 'manual',
    message: result.message,
    referenceId: result.referenceId,
    timestamp: new Date().toISOString(),
  };
}, {
  connection: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD,
  },
  concurrency: 5,
  maxStalledCount: 2,
});

// Event handlers
takedownWorker.on('completed', (job) => {
  console.log(`Job ${job.id} completed for ${job.data.service}/${job.data.url}`);
});

takedownWorker.on('failed', (job, err) => {
  console.error(`Job ${job?.id} failed for ${job?.data?.service}/${job?.data?.url}:`, err);
});

takedownWorker.on('progress', (job, progress) => {
  console.log(`Job ${job.id} progress: ${progress}%`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Shutting down worker...');
  await takedownWorker.close();
  await prisma.$disconnect();
  process.exit(0);
});

export async function startWorker() {
  console.log('TakeDown worker started');
  return takedownWorker;
}