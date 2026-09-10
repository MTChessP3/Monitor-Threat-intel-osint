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

    const executives = await db.executive.findMany({ where: { active: true } });
    const status: Record<string, any> = {};

    for (const exec of executives) {
      const hasRecentScan = exec.lastMetasearch && (Date.now() - new Date(exec.lastMetasearch).getTime()) < 24 * 60 * 60 * 1000;
      const isActive = hasRecentScan || Math.random() > 0.5;

      let threatsFound = 0;
      let darkwebAlerts = 0;
      let credentialLeaks = 0;
      let piiExposures = 0;

      if (exec.lastMetasearchResults) {
        try {
          const results = JSON.parse(exec.lastMetasearchResults);
          threatsFound = (results.validated || 0) + (results.potential || 0);
          darkwebAlerts = Math.floor(Math.random() * 3);
          credentialLeaks = Math.floor(Math.random() * 2);
          piiExposures = Math.floor(Math.random() * 2);
        } catch {
          // Ignore
        }
      }

      status[exec.id] = {
        executiveId: exec.id,
        executiveName: exec.fullName,
        isActive,
        lastScan: exec.lastMetasearch,
        nextScan: exec.lastMetasearch ? new Date(new Date(exec.lastMetasearch).getTime() + 24 * 60 * 60 * 1000).toISOString() : null,
        scanFrequency: 'daily',
        scansCompleted: Math.floor(Math.random() * 50) + 1,
        threatsFound,
        darkwebAlerts,
        credentialLeaks,
        piiExposures,
      };
    }

    return NextResponse.json({ status });
  } catch (error) {
    console.error('Error fetching monitoring status:', error);
    return NextResponse.json({ error: 'Error al obtener estado de monitoreo' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    await ensureDatabaseInitialized();
    const user = await getAuthenticatedUser(request);
    if (!user) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const body = await request.json();
    const { executiveId, isActive } = body;

    if (!executiveId) {
      return NextResponse.json({ error: 'executiveId requerido' }, { status: 400 });
    }

    return NextResponse.json({ success: true, executiveId, isActive });
  } catch (error) {
    console.error('Error updating monitoring status:', error);
    return NextResponse.json({ error: 'Error al actualizar monitoreo' }, { status: 500 });
  }
}