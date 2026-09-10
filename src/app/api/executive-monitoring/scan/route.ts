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

export async function POST(request: NextRequest) {
  try {
    await ensureDatabaseInitialized();
    const user = await getAuthenticatedUser(request);
    if (!user) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const body = await request.json();
    const { executiveId } = body;

    if (!executiveId) {
      return NextResponse.json({ error: 'executiveId requerido' }, { status: 400 });
    }

    const executive = await db.executive.findUnique({ where: { id: executiveId } });
    if (!executive) {
      return NextResponse.json({ error: 'Ejecutivo no encontrado' }, { status: 404 });
    }

    const metasearchRes = await fetch(`${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/api/metasearch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        executiveId: executive.id,
        downloadFiles: true,
        targetType: 'executive',
        targetName: executive.fullName,
        targetEmail: executive.email,
        targetPhone: executive.phone,
        targetOrg: executive.organization,
      }),
    });

    if (!metasearchRes.ok) {
      const errorData = await metasearchRes.json().catch(() => ({ error: 'Error en metabusqueda' }));
      throw new Error(errorData.error || 'Error en metabusqueda');
    }

    const metasearchData = await metasearchRes.json();

    return NextResponse.json({
      success: true,
      executiveId,
      scanId: `scan-${Date.now()}`,
      results: {
        validated: metasearchData.validatedResults?.length || 0,
        potential: metasearchData.potentialResults?.length || 0,
        discarded: metasearchData.discardedResults?.length || 0,
      },
    });
  } catch (error) {
    console.error('Error running manual scan:', error);
    return NextResponse.json({ error: 'Error al ejecutar escaneo' }, { status: 500 });
  }
}