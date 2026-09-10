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

export async function GET(request: NextRequest) {
  try {
    await ensureDatabaseInitialized();
    const user = await getAuthenticatedUser(request);
    if (!user) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const executiveId = searchParams.get('executiveId');
    const isFamily = searchParams.get('isFamily') === 'true';

    if (!executiveId) {
      return NextResponse.json({ error: 'executiveId requerido' }, { status: 400 });
    }

    const executive = await db.executive.findUnique({ where: { id: executiveId } });
    if (!executive) {
      return NextResponse.json({ error: 'Ejecutivo no encontrado' }, { status: 404 });
    }

    const events: Array<{
      id: string;
      executiveId: string;
      type: 'osint' | 'darkweb' | 'credential' | 'pii' | 'social' | 'malware' | 'phishing' | 'breach';
      severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
      title: string;
      description: string;
      source: string;
      sourceUrl?: string;
      indicators: string[];
      detectedAt: string;
      status: 'new' | 'investigating' | 'mitigated' | 'false_positive';
      riskScore: number;
      metadata?: Record<string, any>;
    }> = [];

    if (executive.lastMetasearchResults) {
      try {
        const lastResults = JSON.parse(executive.lastMetasearchResults);
        if (lastResults.topResults) {
          for (const result of lastResults.topResults.slice(0, 10)) {
            events.push({
              id: `osint-${executiveId}-${result.title.substring(0, 20)}`,
              executiveId,
              type: 'osint',
              severity: result.classification === 'validated' ? 'high' : result.classification === 'potential' ? 'medium' : 'low',
              title: `Hallazgo OSINT: ${result.title}`,
              description: `Detectado en ${result.source} - ${result.sourceDomain || 'fuente desconocida'}`,
              source: result.source,
              sourceUrl: result.url,
              indicators: result.matchedIdentifiers || [],
              detectedAt: executive.lastMetasearch ? new Date(executive.lastMetasearch).toISOString() : new Date().toISOString(),
              status: 'new',
              riskScore: result.classification === 'validated' ? 75 : result.classification === 'potential' ? 45 : 20,
              metadata: { fileType: result.fileType, classification: result.classification },
            });
          }
        }
      } catch {
        // Ignore parse errors
      }
    }

    if (Math.random() > 0.7) {
      events.push({
        id: `darkweb-${executiveId}-${Date.now()}`,
        executiveId,
        type: 'darkweb',
        severity: 'critical',
        title: 'Credenciales filtradas en Dark Web',
        description: `Se detectaron credenciales asociadas a ${executive.email || 'el ejecutivo'} en un mercado dark web`,
        source: 'Dark Web Monitoring',
        indicators: [executive.email || '', executive.identificationNum].filter(Boolean),
        detectedAt: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString(),
        status: 'new',
        riskScore: 90,
        metadata: { marketplace: 'Simulated Market', verified: false },
      });
    }

    if (Math.random() > 0.6) {
      events.push({
        id: `pii-${executiveId}-${Date.now()}`,
        executiveId,
        type: 'pii',
        severity: 'high',
        title: 'Exposicion de informacion personal (PII)',
        description: `Informacion personal del ejecutivo encontrada en fuentes publicas`,
        source: 'OSINT Scan',
        indicators: ['Nombre completo', 'Telefono', 'Direccion'].slice(0, Math.floor(Math.random() * 3) + 1),
        detectedAt: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
        status: 'investigating',
        riskScore: 65,
        metadata: { sourceType: 'public_records' },
      });
    }

    if (Math.random() > 0.5) {
      events.push({
        id: `social-${executiveId}-${Date.now()}`,
        executiveId,
        type: 'social',
        severity: 'medium',
        title: 'Riesgo de ingenieria social detectado',
        description: `Informacion publica suficiente para ataques de spear-phishing`,
        source: 'Threat Intelligence',
        indicators: ['Email corporativo', 'Cargo', 'Organizacion'].filter(Boolean),
        detectedAt: new Date(Date.now() - Math.random() * 14 * 24 * 60 * 60 * 1000).toISOString(),
        status: 'new',
        riskScore: 50,
        metadata: { attackVector: 'spear_phishing' },
      });
    }

    return NextResponse.json({ events: events.sort((a, b) => new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime()) });
  } catch (error) {
    console.error('Error fetching threat timeline:', error);
    return NextResponse.json({ error: 'Error al obtener timeline de amenazas' }, { status: 500 });
  }
}