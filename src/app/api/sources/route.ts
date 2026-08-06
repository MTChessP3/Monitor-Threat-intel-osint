import { NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';

export async function GET() {
  try {
    await ensureDatabaseInitialized();
    const sources = await db.newsSource.findMany({
      orderBy: { createdAt: 'desc' },
    });
    return NextResponse.json(sources);
  } catch (error) {
    console.error('Error fetching sources:', error);
    return NextResponse.json({ error: 'Error al obtener fuentes' }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    await ensureDatabaseInitialized();
    const body = await request.json();
    const { name, url, type, category } = body;

    if (!name || !url) {
      return NextResponse.json({ error: 'Nombre y URL son requeridos' }, { status: 400 });
    }

    const source = await db.newsSource.create({
      data: {
        name,
        url,
        type: type || 'web',
        category: category || 'seguridad',
        active: true,
      },
    });

    return NextResponse.json(source);
  } catch (error) {
    console.error('Error creating source:', error);
    return NextResponse.json({ error: 'Error al crear fuente' }, { status: 500 });
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

    await db.newsSource.delete({
      where: { id },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error deleting source:', error);
    return NextResponse.json({ error: 'Error al eliminar fuente' }, { status: 500 });
  }
}
