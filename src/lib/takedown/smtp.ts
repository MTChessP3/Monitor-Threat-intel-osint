import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

interface EmailRecipient {
  to: string;
  name: string;
  organization?: string;
}

interface EmailConfig {
  smtpHost: string;
  smtpPort: number;
  smtpUser: string;
  smtpPass: string;
  fromEmail: string;
  fromName: string;
  useSES: boolean;
  region?: string;
}

const DEFAULT_CONFIG: EmailConfig = {
  smtpHost: process.env.SMTP_HOST || 'localhost',
  smtpPort: parseInt(process.env.SMTP_PORT || '587'),
  smtpUser: process.env.SMTP_USER || '',
  smtpPass: process.env.SMTP_PASS || '',
  fromEmail: process.env.NOTIFICATION_FROM_EMAIL || 'noreply@nexus-intel.local',
  fromName: 'NEXUS-INTEL TakeDown Module',
  useSES: process.env.USE_SES === 'true',
  region: process.env.AWS_REGION,
};

const APWG_EMAIL = 'reportphishing@apwg.org';
const CISA_EMAIL = 'phishing-report@us-cert.gov';

interface TakedownEmailData {
  batchId: string;
  batchName: string;
  urls: Array<{ originalUrl: string; defangedUrl: string; status: string }>;
  virustotalResults?: Array<{
    url: string;
    classification: string;
    maliciousEngines: number;
  }>;
  notes?: string;
  fingerprint: string;
  timestamp: string;
}

function generateEmailHeaders(structuredData: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = {
    'From': `${DEFAULT_CONFIG.fromName} <${DEFAULT_CONFIG.fromEmail}>`,
    'To': '',
    'Subject': '',
    'Message-ID': `<takedown-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@nexus-intel.local>`,
    'X-Mailer': 'NEXUS-INTEL TakeDown Module v1.0',
    'X-Takedown-Batch': structuredData.batchId,
    'X-Cryptographic-Fingerprint': structuredData.fingerprint,
    'Content-Type': 'application/json; charset="utf-8"',
    'MIME-Version': '1.0',
  };
  return headers;
}

function generateRfc822StructuredPayload(data: TakedownEmailData): string {
  const payload = {
    '_type': 'TakeDown-Report',
    'version': '1.0',
    'timestamp': data.timestamp,
    'batch_id': data.batchId,
    'fingerprint': data.fingerprint,
    'entity': {
      'type': 'url_batch',
      'count': data.urls.length,
      'urls': data.urls.map(u => ({
        'original': u.originalUrl,
        'defanged': u.defangedUrl,
        'status': u.status,
      })),
    },
    'analysis': {
      'virustotal': data.virustotalResults?.map(v => ({
        'url': v.url,
        'classification': v.classification,
        'malicious_engines': v.maliciousEngines,
      })) || [],
    },
    'reporting_instructions': {
      'apwg': 'Send this JSON attachment to reportphishing@apwg.org',
      'cisa': 'Send this JSON attachment to phishing-report@us-cert.gov',
    },
    'notes': data.notes || '',
  };

  return JSON.stringify(payload, null, 2);
}

export async function sendApwgEmail(data: TakedownEmailData): Promise<{
  success: boolean;
  message: string;
  referenceId?: string;
  error?: string;
}> {
  const referenceId = `APWG-${Date.now().toString(36).toUpperCase()}`;
  const structuredData = generateRfc822StructuredPayload(data);
  const headers = generateEmailHeaders({
    batchId: data.batchId,
    fingerprint: data.fingerprint,
  });
  headers['To'] = APWG_EMAIL;
  headers['Subject'] = `[PHISHING REPORT] NEXUS-INTEL Batch ${data.batchId} - ${data.urls.length} URLs`;

  try {
    if (DEFAULT_CONFIG.useSES) {
      const ses = require('@aws-sdk/client-ses');
      const client = new ses.SES({ region: DEFAULT_CONFIG.region || 'us-east-1' });

      await client.sendEmail({
        Source: `${DEFAULT_CONFIG.fromName} <${DEFAULT_CONFIG.fromEmail}>`,
        Destination: {
          ToAddresses: [APWG_EMAIL],
        },
        Message: {
          Subject: { Data: headers['Subject'], Charset: 'UTF-8' },
          Body: {
            Text: { Data: structuredData, Charset: 'UTF-8' },
          },
        },
      });
    } else {
      const nodemailer = require('nodemailer');
      const transporter = nodemailer.createTransport({
        host: DEFAULT_CONFIG.smtpHost,
        port: DEFAULT_CONFIG.smtpPort,
        secure: DEFAULT_CONFIG.smtpPort === 465,
        auth: {
          user: DEFAULT_CONFIG.smtpUser,
          pass: DEFAULT_CONFIG.smtpPass,
        },
      });

      await transporter.sendMail({
        from: `${DEFAULT_CONFIG.fromName} <${DEFAULT_CONFIG.fromEmail}>`,
        to: APWG_EMAIL,
        subject: headers['Subject'],
        text: structuredData,
        headers: {
          'X-Takedown-Batch': data.batchId,
          'X-Cryptographic-Fingerprint': data.fingerprint,
        },
      });
    }

    await prisma.emailLog.create({
      data: {
        type: 'APWG',
        recipient: APWG_EMAIL,
        batchId: data.batchId,
        referenceId,
        status: 'sent',
        payload: structuredData,
      },
    });

    return { success: true, message: `Reporte enviado a APWG (${APWG_EMAIL})`, referenceId };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    await prisma.emailLog.create({
      data: {
        type: 'APWG',
        recipient: APWG_EMAIL,
        batchId: data.batchId,
        referenceId,
        status: 'failed',
        errorDetails: errorMessage,
      },
    });
    return { success: false, message: 'Failed to send to APWG', error: errorMessage };
  }
}

export async function sendCisaEmail(data: TakedownEmailData): Promise<{
  success: boolean;
  message: string;
  referenceId?: string;
  error?: string;
}> {
  const referenceId = `CISA-${Date.now().toString(36).toUpperCase()}`;
  const structuredData = generateRfc822StructuredPayload(data);
  const headers = generateEmailHeaders({
    batchId: data.batchId,
    fingerprint: data.fingerprint,
  });
  headers['To'] = CISA_EMAIL;
  headers['Subject'] = `[PHISHING REPORT] NEXUS-INTEL Batch ${data.batchId} - ${data.urls.length} URLs Maliciousas`;

  try {
    if (DEFAULT_CONFIG.useSES) {
      const ses = require('@aws-sdk/client-ses');
      const client = new ses.SES({ region: DEFAULT_CONFIG.region || 'us-east-1' });

      await client.sendEmail({
        Source: `${DEFAULT_CONFIG.fromName} <${DEFAULT_CONFIG.fromEmail}>`,
        Destination: {
          ToAddresses: [CISA_EMAIL],
        },
        Message: {
          Subject: { Data: headers['Subject'], Charset: 'UTF-8' },
          Body: {
            Text: { Data: structuredData, Charset: 'UTF-8' },
          },
        },
      });
    } else {
      const nodemailer = require('nodemailer');
      const transporter = nodemailer.createTransport({
        host: DEFAULT_CONFIG.smtpHost,
        port: DEFAULT_CONFIG.smtpPort,
        secure: DEFAULT_CONFIG.smtpPort === 465,
        auth: {
          user: DEFAULT_CONFIG.smtpUser,
          pass: DEFAULT_CONFIG.smtpPass,
        },
      });

      await transporter.sendMail({
        from: `${DEFAULT_CONFIG.fromName} <${DEFAULT_CONFIG.fromEmail}>`,
        to: CISA_EMAIL,
        subject: headers['Subject'],
        text: structuredData,
        headers: {
          'X-Takedown-Batch': data.batchId,
          'X-Cryptographic-Fingerprint': data.fingerprint,
        },
      });
    }

    await prisma.emailLog.create({
      data: {
        type: 'CISA',
        recipient: CISA_EMAIL,
        batchId: data.batchId,
        referenceId,
        status: 'sent',
        payload: structuredData,
      },
    });

    return { success: true, message: `Reporte enviado a CISA (${CISA_EMAIL})`, referenceId };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    await prisma.emailLog.create({
      data: {
        type: 'CISA',
        recipient: CISA_EMAIL,
        batchId: data.batchId,
        referenceId,
        status: 'failed',
        errorDetails: errorMessage,
      },
    });
    return { success: false, message: 'Failed to send to CISA', error: errorMessage };
  }
}

export async function sendBulkEmailReports(
  data: TakedownEmailData,
  recipients: EmailRecipient[]
): Promise<Array<{ recipient: string; success: boolean; referenceId: string }>> {
  const results = [];
  for (const recipient of recipients) {
    const emailData: TakedownEmailData = { ...data };
    const result = await sendApwgEmail(emailData);
    results.push({
      recipient: recipient.to,
      success: result.success,
      referenceId: result.referenceId || '',
    });
  }
  return results;
}

export async function logEmailDelivery(
  type: string,
  recipient: string,
  batchId: string,
  referenceId: string,
  status: 'sent' | 'failed',
  payload: string,
  errorDetails?: string
): Promise<void> {
  await prisma.emailLog.create({
    data: { type, recipient, batchId, referenceId, status, payload, errorDetails },
  });
}

export function getEmailConfig(): EmailConfig {
  return DEFAULT_CONFIG;
}

export { APWG_EMAIL, CISA_EMAIL };
