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

    if (!executiveId) {
      return NextResponse.json({ error: 'executiveId requerido' }, { status: 400 });
    }

    const executive = await db.executive.findUnique({ where: { id: executiveId } });
    if (!executive) {
      return NextResponse.json({ error: 'Ejecutivo no encontrado' }, { status: 404 });
    }

    let digitalFootprint = 30;
    let credentialExposure = 20;
    let piiExposure = 25;
    let darkwebPresence = 15;
    let socialEngineering = 35;
    let malwareAssociation = 10;

    let criticalFindings = 0;

    if (executive.lastMetasearchResults) {
      try {
        const results = JSON.parse(executive.lastMetasearchResults);
        const validated = results.validated || 0;
        const potential = results.potential || 0;
        const total = validated + potential;

        digitalFootprint = Math.min(100, 30 + total * 3);
        credentialExposure = Math.min(100, 20 + darkwebPresence + Math.floor(Math.random() * 20));
        piiExposure = Math.min(100, 25 + potential * 2);
        darkwebPresence = Math.min(100, 15 + Math.floor(Math.random() * 25));
        socialEngineering = Math.min(100, 35 + validated * 2);
        malwareAssociation = Math.min(100, 10 + Math.floor(Math.random() * 15));

        criticalFindings = validated;
      } catch {
        // Use defaults
      }
    }

    const familyCount = await db.familyMember.count({ where: { executiveId } });
    socialEngineering = Math.min(100, socialEngineering + familyCount * 5);
    piiExposure = Math.min(100, piiExposure + familyCount * 3);

    const overallRiskScore = Math.round(
      (digitalFootprint * 0.2 +
        credentialExposure * 0.2 +
        piiExposure * 0.15 +
        darkwebPresence * 0.2 +
        socialEngineering * 0.15 +
        malwareAssociation * 0.1)
    );

    const trends: ('increasing' | 'stable' | 'decreasing')[] = ['increasing', 'stable', 'decreasing'];
    const riskTrend = trends[Math.floor(Math.random() * trends.length)];

    const recommendations = [
      'Implementar monitoreo continuo de huella digital',
      'Configurar alertas de credenciales filtradas',
      'Revisar y minimizar exposicion de PII en fuentes publicas',
      'Capacitar al ejecutivo y familiares en ingenieria social',
      'Implementar autenticacion multifactor en todas las cuentas',
      'Monitorear dominios similares y typosquatting',
    ];

    const selectedRecommendations = recommendations.slice(0, 3 + Math.floor(overallRiskScore / 25));

    const profile = {
      executiveId,
      overallRiskScore,
      riskTrend,
      categories: {
        digitalFootprint,
        credentialExposure,
        piiExposure,
        darkwebPresence,
        socialEngineering,
        malwareAssociation,
      },
      lastAssessment: new Date().toISOString(),
      criticalFindings,
      recommendations: selectedRecommendations,
    };

    return NextResponse.json({ profile });
  } catch (error) {
    console.error('Error fetching risk profile:', error);
    return NextResponse.json({ error: 'Error al obtener perfil de riesgo' }, { status: 500 });
  }
}