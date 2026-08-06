import { NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';

export async function GET(request: Request) {
  try {
    await ensureDatabaseInitialized();
    const { searchParams } = new URL(request.url);
    const limit = parseInt(searchParams.get('limit') || '10');
    const offset = parseInt(searchParams.get('offset') || '0');

    const [reports, total] = await Promise.all([
      db.report.findMany({
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
        include: {
          template: {
            select: { name: true },
          },
        },
      }),
      db.report.count(),
    ]);

    return NextResponse.json({ reports, total });
  } catch (error) {
    console.error('Error fetching reports:', error);
    return NextResponse.json({ error: 'Error al obtener informes' }, { status: 500 });
  }
}

export async function DELETE(request: Request) {
  try {
    await ensureDatabaseInitialized();
    const body = await request.json();
    const { id } = body;

    if (!id) {
      return NextResponse.json({ error: 'ID es requerido' }, { status: 400 });
    }

    await db.report.delete({
      where: { id },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error deleting report:', error);
    return NextResponse.json({ error: 'Error al eliminar informe' }, { status: 500 });
  }
}

export async function PUT(request: Request) {
  try {
    await ensureDatabaseInitialized();
    const body = await request.json();
    const { id, content, title, summary, threatLevel } = body;

    if (!id) {
      return NextResponse.json({ error: 'ID es requerido' }, { status: 400 });
    }

    const report = await db.report.update({
      where: { id },
      data: {
        ...(content !== undefined && { content }),
        ...(title !== undefined && { title }),
        ...(summary !== undefined && { summary }),
        ...(threatLevel !== undefined && { threatLevel }),
      },
    });

    return NextResponse.json(report);
  } catch (error) {
    console.error('Error updating report:', error);
    return NextResponse.json({ error: 'Error al actualizar informe' }, { status: 500 });
  }
}
