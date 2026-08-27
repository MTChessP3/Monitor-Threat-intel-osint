import { NextRequest, NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';

// Helper to authenticate requests
async function getAuthenticatedUser(request: NextRequest) {
  const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;
  if (!token) return null;
  const payload = await verifyToken(token);
  if (!payload) return null;
  return payload as { id: string; email: string; role: string };
}

// GET /api/executives - List all executives
export async function GET(request: NextRequest) {
  try {
    await ensureDatabaseInitialized();
    const user = await getAuthenticatedUser(request);
    if (!user) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const search = searchParams.get('search') || '';
    const riskLevel = searchParams.get('riskLevel') || '';
    const active = searchParams.get('active');

    const where: any = {};

    if (search) {
      where.OR = [
        { fullName: { contains: search } },
        { identificationNum: { contains: search } },
        { email: { contains: search } },
        { organization: { contains: search } },
      ];
    }

    if (riskLevel) {
      where.riskLevel = riskLevel;
    }

    if (active !== null && active !== undefined && active !== '') {
      where.active = active === 'true';
    }

    const executives = await db.executive.findMany({
      where,
      orderBy: { updatedAt: 'desc' },
    });

    return NextResponse.json({ executives });
  } catch (error) {
    console.error('Error fetching executives:', error);
    return NextResponse.json(
      { error: 'Error al obtener ejecutivos' },
      { status: 500 }
    );
  }
}

// POST /api/executives - Create a new executive
export async function POST(request: NextRequest) {
  try {
    await ensureDatabaseInitialized();
    const user = await getAuthenticatedUser(request);
    if (!user) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const body = await request.json();
    const { identificationNum, fullName, email, phone, position, organization, riskLevel, notes } = body;

    if (!identificationNum || !fullName) {
      return NextResponse.json(
        { error: 'Número de identificación y nombre completo son requeridos' },
        { status: 400 }
      );
    }

    // Check total executives limit (300)
    const totalExecutives = await db.executive.count();
    if (totalExecutives >= 300) {
      return NextResponse.json(
        { error: 'Máximo 300 ejecutivos permitidos' },
        { status: 400 }
      );
    }

    // Check for duplicate identification number
    const existing = await db.executive.findUnique({
      where: { identificationNum },
    });

    if (existing) {
      return NextResponse.json(
        { error: 'Ya existe un ejecutivo con este número de identificación' },
        { status: 409 }
      );
    }

    const executive = await db.executive.create({
      data: {
        identificationNum,
        fullName,
        email: email || null,
        phone: phone || null,
        position: position || null,
        organization: organization || null,
        riskLevel: riskLevel || 'bajo',
        notes: notes || null,
      },
    });

    return NextResponse.json({ executive }, { status: 201 });
  } catch (error) {
    console.error('Error creating executive:', error);
    return NextResponse.json(
      { error: 'Error al crear ejecutivo' },
      { status: 500 }
    );
  }
}

// PUT /api/executives - Update an executive
export async function PUT(request: NextRequest) {
  try {
    await ensureDatabaseInitialized();
    const user = await getAuthenticatedUser(request);
    if (!user) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const body = await request.json();
    const { id, identificationNum, fullName, email, phone, position, organization, riskLevel, notes, active } = body;

    if (!id) {
      return NextResponse.json({ error: 'ID requerido' }, { status: 400 });
    }

    const existing = await db.executive.findUnique({ where: { id } });
    if (!existing) {
      return NextResponse.json({ error: 'Ejecutivo no encontrado' }, { status: 404 });
    }

    // If changing identificationNum, check for duplicates
    if (identificationNum && identificationNum !== existing.identificationNum) {
      const dup = await db.executive.findUnique({ where: { identificationNum } });
      if (dup) {
        return NextResponse.json(
          { error: 'Ya existe un ejecutivo con este número de identificación' },
          { status: 409 }
        );
      }
    }

    const executive = await db.executive.update({
      where: { id },
      data: {
        ...(identificationNum !== undefined && { identificationNum }),
        ...(fullName !== undefined && { fullName }),
        ...(email !== undefined && { email: email || null }),
        ...(phone !== undefined && { phone: phone || null }),
        ...(position !== undefined && { position }),
        ...(organization !== undefined && { organization }),
        ...(riskLevel !== undefined && { riskLevel }),
        ...(notes !== undefined && { notes }),
        ...(active !== undefined && { active }),
      },
    });

    return NextResponse.json({ executive });
  } catch (error) {
    console.error('Error updating executive:', error);
    return NextResponse.json(
      { error: 'Error al actualizar ejecutivo' },
      { status: 500 }
    );
  }
}

// DELETE /api/executives - Delete an executive
export async function DELETE(request: NextRequest) {
  try {
    await ensureDatabaseInitialized();
    const user = await getAuthenticatedUser(request);
    if (!user) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const id = searchParams.get('id');

    if (!id) {
      return NextResponse.json({ error: 'ID requerido' }, { status: 400 });
    }

    const existing = await db.executive.findUnique({ where: { id } });
    if (!existing) {
      return NextResponse.json({ error: 'Ejecutivo no encontrado' }, { status: 404 });
    }

    await db.executive.delete({ where: { id } });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error deleting executive:', error);
    return NextResponse.json(
      { error: 'Error al eliminar ejecutivo' },
      { status: 500 }
    );
  }
}
