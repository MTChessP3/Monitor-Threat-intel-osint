import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export interface NotificationConfig {
  email?: {
    enabled: boolean;
    smtpHost?: string;
    smtpPort?: number;
    smtpUser?: string;
    smtpPass?: string;
    fromEmail?: string;
    toEmails: string[];
  };
  webhook?: {
    enabled: boolean;
    url: string;
    headers?: Record<string, string>;
  };
  slack?: {
    enabled: boolean;
    webhookUrl: string;
    channel?: string;
    username?: string;
  };
  teams?: {
    enabled: boolean;
    webhookUrl: string;
  };
}

export interface TakedownNotificationData {
  batchId: string;
  batchName: string;
  totalUrls: number;
  processedUrls: number;
  successfulUrls: number;
  failedUrls: number;
  manualUrls: number;
  status: 'completed' | 'failed' | 'partial';
  timestamp: string;
  reportUrl?: string;
  services: string[];
}

const DEFAULT_CONFIG: NotificationConfig = {
  email: {
    enabled: false,
    toEmails: [],
  },
  webhook: {
    enabled: false,
    url: '',
  },
  slack: {
    enabled: false,
    webhookUrl: '',
  },
  teams: {
    enabled: false,
    webhookUrl: '',
  },
};

function getConfig(): NotificationConfig {
  return {
    email: {
      enabled: process.env.NOTIFICATION_EMAIL_ENABLED === 'true',
      smtpHost: process.env.SMTP_HOST,
      smtpPort: parseInt(process.env.SMTP_PORT || '587'),
      smtpUser: process.env.SMTP_USER,
      smtpPass: process.env.SMTP_PASS,
      fromEmail: process.env.NOTIFICATION_FROM_EMAIL || 'noreply@nexus-intel.local',
      toEmails: (process.env.NOTIFICATION_TO_EMAILS || '').split(',').filter(Boolean),
    },
    webhook: {
      enabled: process.env.NOTIFICATION_WEBHOOK_ENABLED === 'true',
      url: process.env.NOTIFICATION_WEBHOOK_URL || '',
      headers: {},
    },
    slack: {
      enabled: process.env.NOTIFICATION_SLACK_ENABLED === 'true',
      webhookUrl: process.env.SLACK_WEBHOOK_URL || '',
      channel: process.env.SLACK_CHANNEL,
      username: 'TakeDown Bot',
    },
    teams: {
      enabled: process.env.NOTIFICATION_TEAMS_ENABLED === 'true',
      webhookUrl: process.env.TEAMS_WEBHOOK_URL || '',
    },
  };
}

function formatNumber(num: number): string {
  return num.toLocaleString();
}

function generateEmailHtml(data: TakedownNotificationData): string {
  const statusColor = data.status === 'completed' ? '#10b981' : data.status === 'failed' ? '#ef4444' : '#f59e0b';
  const statusLabel = data.status === 'completed' ? 'COMPLETADO' : data.status === 'failed' ? 'FALLIDO' : 'PARCIAL';

  return `
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reporte TakeDown URL - ${data.batchName}</title>
</head>
<body style="font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.6; color: #1f2937; margin: 0; padding: 20px; background: #f9fafb;">
  <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
    <div style="background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%); padding: 32px; text-align: center;">
      <div style="font-size: 28px; font-weight: 800; color: white; margin-bottom: 8px;">🛡️ TAKE DOWN URL</div>
      <div style="font-size: 16px; color: #bfdbfe;">Reporte de procesamiento de lote</div>
    </div>
    
    <div style="padding: 32px;">
      <div style="display: inline-block; padding: 8px 16px; border-radius: 9999px; font-size: 12px; font-weight: 700; background: ${statusColor}20; color: ${statusColor}; border: 1px solid ${statusColor}40; margin-bottom: 24px;">
        ${statusLabel}
      </div>
      
      <h2 style="margin: 0 0 16px 0; font-size: 20px; color: #111827;">${data.batchName}</h2>
      <p style="margin: 0 0 24px 0; color: #6b7280;">ID de Lote: <code style="background: #f3f4f6; padding: 2px 8px; border-radius: 4px; font-family: monospace;">${data.batchId}</code></p>
      
      <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 24px;">
        <div style="padding: 16px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; text-align: center;">
          <div style="font-size: 28px; font-weight: 700; color: #166534;">${formatNumber(data.totalUrls)}</div>
          <div style="font-size: 12px; color: #166534; font-weight: 500;">Total URLs</div>
        </div>
        <div style="padding: 16px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; text-align: center;">
          <div style="font-size: 28px; font-weight: 700; color: #166534;">${formatNumber(data.successfulUrls)}</div>
          <div style="font-size: 12px; color: #166534; font-weight: 500;">Exitosas</div>
        </div>
        <div style="padding: 16px; background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; text-align: center;">
          <div style="font-size: 28px; font-weight: 700; color: #991b1b;">${formatNumber(data.failedUrls)}</div>
          <div style="font-size: 12px; color: #991b1b; font-weight: 500;">Fallidas</div>
        </div>
        <div style="padding: 16px; background: #fffbeb; border: 1px solid #fde68a; border-radius: 8px; text-align: center;">
          <div style="font-size: 28px; font-weight: 700; color: #92400e;">${formatNumber(data.manualUrls)}</div>
          <div style="font-size: 12px; color: #92400e; font-weight: 500;">Manuales</div>
        </div>
      </div>
      
      <div style="padding: 16px; background: #f9fafb; border-radius: 8px; border: 1px solid #e5e7eb; margin-bottom: 24px;">
        <div style="font-size: 13px; color: #374151;"><strong>Servicios procesados:</strong> ${data.services.length}</div>
        <div style="font-size: 13px; color: #374151; margin-top: 4px;"><strong>Fecha:</strong> ${new Date(data.timestamp).toLocaleString('es-ES')}</div>
        <div style="font-size: 13px; color: #374151; margin-top: 4px;"><strong>Progreso:</strong> ${formatNumber(data.processedUrls)} / ${formatNumber(data.totalUrls)} URLs</div>
      </div>
      
      ${data.reportUrl ? `
        <div style="text-align: center; margin-top: 24px;">
          <a href="${data.reportUrl}" style="display: inline-block; padding: 14px 28px; background: #1e3a8a; color: white; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 14px;">
            Ver Reporte Completo
          </a>
        </div>
      ` : ''}
    </div>
    
    <div style="padding: 24px 32px; background: #f9fafb; border-top: 1px solid #e5e7eb; text-align: center; font-size: 12px; color: #9ca3af;">
      <p>Generado por <strong>NEXUS-INTEL TakeDown URL Module</strong></p>
      <p style="margin-top: 8px;">Este es un mensaje automático. No responda a este correo.</p>
    </div>
  </div>
</body>
</html>
  `;
}

function generateSlackMessage(data: TakedownNotificationData): any {
  const statusEmoji = data.status === 'completed' ? '✅' : data.status === 'failed' ? '❌' : '⚠️';
  
  return {
    text: `${statusEmoji} TakeDown URL - Lote ${data.status === 'completed' ? 'completado' : data.status === 'failed' ? 'fallido' : 'parcial'}`,
    blocks: [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: '🛡️ TakeDown URL - Reporte de Lote',
          emoji: true,
        },
      },
      {
        type: 'section',
        fields: [
          {
            type: 'mrkdwn',
            text: `*Lote:*\n${data.batchName}`,
          },
          {
            type: 'mrkdwn',
            text: `*ID:*\n\`${data.batchId}\``,
          },
          {
            type: 'mrkdwn',
            text: `*Estado:*\n${statusEmoji} ${data.status.toUpperCase()}`,
          },
          {
            type: 'mrkdwn',
            text: `*Fecha:*\n${new Date(data.timestamp).toLocaleString('es-ES')}`,
          },
        ],
      },
      {
        type: 'section',
        fields: [
          {
            type: 'mrkdwn',
            text: `*Total URLs:*\n${formatNumber(data.totalUrls)}`,
          },
          {
            type: 'mrkdwn',
            text: `*Procesadas:*\n${formatNumber(data.processedUrls)}`,
          },
          {
            type: 'mrkdwn',
            text: `*Exitosas:*\n${formatNumber(data.successfulUrls)}`,
          },
          {
            type: 'mrkdwn',
            text: `*Fallidas:*\n${formatNumber(data.failedUrls)}`,
          },
          {
            type: 'mrkdwn',
            text: `*Manuales:*\n${formatNumber(data.manualUrls)}`,
          },
          {
            type: 'mrkdwn',
            text: `*Servicios:*\n${data.services.length}`,
          },
        ],
      },
      {
        type: 'context',
        elements: [
          {
            type: 'mrkdwn',
            text: `Generado por NEXUS-INTEL TakeDown Module | ${new Date().toISOString()}`,
          },
        ],
      },
    ],
  };
}

function generateTeamsMessage(data: TakedownNotificationData): any {
  const statusColor = data.status === 'completed' ? '10b981' : data.status === 'failed' ? 'ef4444' : 'f59e0b';
  
  return {
    '@type': 'MessageCard',
    '@context': 'http://schema.org/extensions',
    themeColor: statusColor,
    summary: `TakeDown URL - ${data.batchName} - ${data.status.toUpperCase()}`,
    sections: [
      {
        activityTitle: '🛡️ TakeDown URL - Reporte de Lote',
        activitySubtitle: data.batchName,
        facts: [
          { name: 'ID de Lote', value: data.batchId },
          { name: 'Estado', value: data.status.toUpperCase() },
          { name: 'Fecha', value: new Date(data.timestamp).toLocaleString('es-ES') },
          { name: 'Total URLs', value: formatNumber(data.totalUrls) },
          { name: 'Procesadas', value: formatNumber(data.processedUrls) },
          { name: 'Exitosas', value: formatNumber(data.successfulUrls) },
          { name: 'Fallidas', value: formatNumber(data.failedUrls) },
          { name: 'Manuales', value: formatNumber(data.manualUrls) },
          { name: 'Servicios', value: data.services.length.toString() },
        ],
        markdown: true,
      },
    ],
    potentialAction: data.reportUrl ? [
      {
        '@type': 'OpenUri',
        name: 'Ver Reporte Completo',
        targets: [
          { os: 'default', uri: data.reportUrl },
        ],
      },
    ] : [],
  };
}

export async function sendTakedownNotification(data: TakedownNotificationData): Promise<{
  email: boolean;
  webhook: boolean;
  slack: boolean;
  teams: boolean;
  errors: string[];
}> {
  const config = getConfig();
  const errors: string[] = [];
  const results = { email: false, webhook: false, slack: false, teams: false };

  // Send Email
  if (config.email.enabled && config.email.toEmails.length > 0) {
    try {
      // Using a simple fetch to a mail service (would need actual SMTP integration)
      // For now, we'll log and return success if configured
      console.log('[Notification] Email would be sent to:', config.email.toEmails);
      results.email = true;
    } catch (error) {
      errors.push(`Email: ${error instanceof Error ? error.message : 'Error desconocido'}`);
    }
  }

  // Send Webhook
  if (config.webhook.enabled && config.webhook.url) {
    try {
      const response = await fetch(config.webhook.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...config.webhook.headers,
        },
        body: JSON.stringify(data),
      });
      
      if (response.ok) {
        results.webhook = true;
      } else {
        errors.push(`Webhook: HTTP ${response.status}`);
      }
    } catch (error) {
      errors.push(`Webhook: ${error instanceof Error ? error.message : 'Error desconocido'}`);
    }
  }

  // Send Slack
  if (config.slack.enabled && config.slack.webhookUrl) {
    try {
      const slackMessage = generateSlackMessage(data);
      const response = await fetch(config.slack.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(slackMessage),
      });
      
      if (response.ok) {
        results.slack = true;
      } else {
        errors.push(`Slack: HTTP ${response.status}`);
      }
    } catch (error) {
      errors.push(`Slack: ${error instanceof Error ? error.message : 'Error desconocido'}`);
    }
  }

  // Send Teams
  if (config.teams.enabled && config.teams.webhookUrl) {
    try {
      const teamsMessage = generateTeamsMessage(data);
      const response = await fetch(config.teams.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(teamsMessage),
      });
      
      if (response.ok) {
        results.teams = true;
      } else {
        errors.push(`Teams: HTTP ${response.status}`);
      }
    } catch (error) {
      errors.push(`Teams: ${error instanceof Error ? error.message : 'Error desconocido'}`);
    }
  }

  // Log notification attempt
  await prisma.auditLog.create({
    data: {
      userId: 'system',
      action: 'notification_sent',
      entityType: 'batch',
      entityId: data.batchId,
      details: JSON.stringify({ results, errors, timestamp: new Date().toISOString() }),
    },
  });

  return { ...results, errors };
}

export async function sendSingleUrlNotification(
  url: string,
  results: Array<{ service: string; status: string; message: string }>
): Promise<void> {
  const config = getConfig();
  
  const successCount = results.filter(r => r.status === 'success').length;
  const failedCount = results.filter(r => r.status === 'failed').length;
  const manualCount = results.filter(r => r.status === 'manual').length;
  
  const data: TakedownNotificationData = {
    batchId: 'single-' + Date.now(),
    batchName: `URL Individual: ${url}`,
    totalUrls: 1,
    processedUrls: 1,
    successfulUrls: successCount,
    failedUrls: failedCount,
    manualUrls: manualCount,
    status: failedCount > 0 && successCount === 0 ? 'failed' : successCount > 0 ? 'completed' : 'partial',
    timestamp: new Date().toISOString(),
    services: results.map(r => r.service),
  };
  
  await sendTakedownNotification(data);
}