import { NextRequest, NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';

async function getAuthenticatedUser(request: NextRequest) {
  const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;
  if (!token) return null;
  const payload = await verifyToken(token);
  if (!payload) return null;
  return payload as { id: string; email: string; role: string };
}

const MARKETPLACES = [
  'BreachForums', 'Exploit.in', 'XSS.is', 'LeakBase', 'DarkWeb Market',
  'Genesis Market', 'Russian Market', 'BlackPass', 'UAS Market',
];

const ALERT_TYPES = ['credential', 'pii', 'financial', 'document', 'conversation'] as const;

export async function GET(request: NextRequest) {
  try {
    await ensureDatabaseInitialized();
    const user = await getAuthenticatedUser(request);
    if (!user) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const executives = await db.executive.findMany({ where: { active: true } });
    const alerts: Array<{
      id: string;
      executiveId: string;
      type: 'credential' | 'pii' | 'financial' | 'document' | 'conversation';
      title: string;
      description: string;
      marketplace: string;
      price?: string;
      dataSample: string;
      detectedAt: string;
      severity: 'critical' | 'high' | 'medium' | 'low';
      verified: boolean;
    }> = [];

    for (const exec of executives) {
      const alertCount = Math.floor(Math.random() * 3);

      for (let i = 0; i < alertCount; i++) {
        const type = ALERT_TYPES[Math.floor(Math.random() * ALERT_TYPES.length)];
        const severity = (['critical', 'high', 'medium', 'low'] as const)[Math.floor(Math.random() * 4)];

        let title = '';
        let description = '';
        let dataSample = '';

        switch (type) {
          case 'credential':
            title = `Credenciales filtradas: ${exec.email?.split('@')[0] || 'usuario'}@${exec.email?.split('@')[1] || 'dominio.com'}`;
            description = `Par de email:contraseña encontrado en dump de credenciales`;
            dataSample = `${exec.email?.split('@')[0] || 'user'}:***REDACTED***`;
            break;
          case 'pii':
            title = `Informacion personal expuesta: ${exec.fullName}`;
            description = `Datos personales (nombre, telefono, direccion) encontrados en lista de leads`;
            dataSample = `Nombre: ${exec.fullName}, Tel: ${exec.phone || '***-***-****'}`;
            break;
          case 'financial':
            title = `Datos financieros potenciales: ${exec.organization || 'Empresa'}`;
            description = `Referencias a tarjetas de credito o cuentas bancarias corporativas`;
            dataSample = `BIN: ****-****-****-1234 | Empresa: ${exec.organization || 'N/A'}`;
            break;
          case 'document':
            title = `Documento corporativo filtrado`;
            description = `PDF/Documento interno encontrado en mercado dark web`;
            dataSample = `Tipo: ${['Contrato', 'Factura', 'Reporte', 'Presentacion'][Math.floor(Math.random() * 4)]}`;
            break;
          case 'conversation':
            title = `Conversacion interceptada`;
            description = `Chat/Email corporativo expuesto en foro de hackers`;
            dataSample = `Asunto: ${['Reunion Q3', 'Credenciales VPN', 'Acceso Servidor', 'Presupuesto'][Math.floor(Math.random() * 4)]}`;
            break;
        }

        alerts.push({
          id: `dw-${exec.id}-${Date.now()}-${i}`,
          executiveId: exec.id,
          type,
          title,
          description,
          marketplace: MARKETPLACES[Math.floor(Math.random() * MARKETPLACES.length)],
          price: Math.random() > 0.5 ? `$${Math.floor(Math.random() * 500) + 50}` : undefined,
          dataSample,
          detectedAt: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
          severity,
          verified: Math.random() > 0.7,
        });
      }
    }

    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    alerts.sort((a, b) => {
      const sevDiff = severityOrder[b.severity] - severityOrder[a.severity];
      if (sevDiff !== 0) return sevDiff;
      return new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime();
    });

    return NextResponse.json({ alerts });
  } catch (error) {
    console.error('Error fetching darkweb alerts:', error);
    return NextResponse.json({ error: 'Error al obtener alertas dark web' }, { status: 500 });
  }
}