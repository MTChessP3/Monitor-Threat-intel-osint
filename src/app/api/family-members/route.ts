import { NextRequest, NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';

const MAX_FAMILY_MEMBERS_PER_EXECUTIVE = 3;
const MAX_EXECUTIVES = 300;

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

    const familyMembers = await db.familyMember.findMany({
      where: { executiveId },
      orderBy: { createdAt: 'desc' },
    });

    return NextResponse.json({ familyMembers });
  } catch (error) {
    console.error('Error fetching family members:', error);
    return NextResponse.json(
      { error: 'Error al obtener familiares' },
      { status: 500 }
    );
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
    const { executiveId, fullName, relationship, identificationNum, email, phone, riskLevel, notes } = body;

    if (!executiveId || !fullName || !relationship) {
      return NextResponse.json(
        { error: 'executiveId, nombre completo y relación son requeridos' },
        { status: 400 }
      );
    }

    // Check executive exists
    const executive = await db.executive.findUnique({ where: { id: executiveId } });
    if (!executive) {
      return NextResponse.json({ error: 'Ejecutivo no encontrado' }, { status: 404 });
    }

    // Check limit of 3 family members per executive
    const existingCount = await db.familyMember.count({ where: { executiveId } });
    if (existingCount >= MAX_FAMILY_MEMBERS_PER_EXECUTIVE) {
      return NextResponse.json(
        { error: `Máximo ${MAX_FAMILY_MEMBERS_PER_EXECUTIVE} familiares por ejecutivo` },
        { status: 400 }
      );
    }

    // Check total executives limit
    const totalExecutives = await db.executive.count();
    if (totalExecutives >= MAX_EXECUTIVES) {
      return NextResponse.json(
        { error: `Máximo ${MAX_EXECUTIVES} ejecutivos permitidos` },
        { status: 400 }
      );
    }

    const familyMember = await db.familyMember.create({
      data: {
        executiveId,
        fullName,
        relationship,
        identificationNum: identificationNum || null,
        email: email || null,
        phone: phone || null,
        riskLevel: riskLevel || 'bajo',
        notes: notes || null,
      },
    });

    return NextResponse.json({ familyMember }, { status: 201 });
  } catch (error) {
    console.error('Error creating family member:', error);
    return NextResponse.json(
      { error: 'Error al crear familiar' },
      { status: 500 }
    );
  }
}

export async function PUT(request: NextRequest) {
  try {
    await ensureDatabaseInitialized();
    const user = await getAuthenticatedUser(request);
    if (!user) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const body = await request.json();
    const { id, executiveId, fullName, relationship, identificationNum, email, phone, riskLevel, notes, active } = body;

    if (!id) {
      return NextResponse.json({ error: 'ID requerido' }, { status: 400 });
    }

    const existing = await db.familyMember.findUnique({ where: { id } });
    if (!existing) {
      return NextResponse.json({ error: 'Familiar no encontrado' }, { status: 404 });
    }

    // If changing executiveId, verify new executive exists and check limit
    if (executiveId && executiveId !== existing.executiveId) {
      const newExecutive = await db.executive.findUnique({ where: { id: executiveId } });
      if (!newExecutive) {
        return NextResponse.json({ error: 'Ejecutivo no encontrado' }, { status: 404 });
      }
      const existingCount = await db.familyMember.count({ where: { executiveId } });
      if (existingCount >= MAX_FAMILY_MEMBERS_PER_EXECUTIVE) {
        return NextResponse.json(
          { error: `Máximo ${MAX_FAMILY_MEMBERS_PER_EXECUTIVE} familiares por ejecutivo` },
          { status: 400 }
        );
      }
    }

    const familyMember = await db.familyMember.update({
      where: { id },
      data: {
        ...(executiveId !== undefined && { executiveId }),
        ...(fullName !== undefined && { fullName }),
        ...(relationship !== undefined && { relationship }),
        ...(identificationNum !== undefined && { identificationNum: identificationNum || null }),
        ...(email !== undefined && { email: email || null }),
        ...(phone !== undefined && { phone: phone || null }),
        ...(riskLevel !== undefined && { riskLevel }),
        ...(notes !== undefined && { notes }),
        ...(active !== undefined && { active }),
      },
    });

    return NextResponse.json({ familyMember });
  } catch (error) {
    console.error('Error updating family member:', error);
    return NextResponse.json(
      { error: 'Error al actualizar familiar' },
      { status: 500 }
    );
  }
}

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

    const existing = await db.familyMember.findUnique({ where: { id } });
    if (!existing) {
      return NextResponse.json({ error: 'Familiar no encontrado' }, { status: 404 });
    }

    await db.familyMember.delete({ where: { id } });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error deleting family member:', error);
    return NextResponse.json(
      { error: 'Error al eliminar familiar' },
      { status: 500 }
    );
  }
}