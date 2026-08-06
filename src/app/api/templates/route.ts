import { NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';

export async function GET() {
  try {
    await ensureDatabaseInitialized();
    const templates = await db.reportTemplate.findMany({
      orderBy: { createdAt: 'desc' },
    });
    return NextResponse.json(templates);
  } catch (error) {
    console.error('Error fetching templates:', error);
    return NextResponse.json({ error: 'Error al obtener plantillas' }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    await ensureDatabaseInitialized();
    const body = await request.json();
    const { name, content, isDefault } = body;

    if (!name || !content) {
      return NextResponse.json({ error: 'Nombre y contenido son requeridos' }, { status: 400 });
    }

    // If setting as default, unset any existing default
    if (isDefault) {
      await db.reportTemplate.updateMany({
        where: { isDefault: true },
        data: { isDefault: false },
      });
    }

    const template = await db.reportTemplate.create({
      data: {
        name,
        content,
        isDefault: isDefault || false,
      },
    });

    return NextResponse.json(template);
  } catch (error) {
    console.error('Error creating template:', error);
    return NextResponse.json({ error: 'Error al crear plantilla' }, { status: 500 });
  }
}
