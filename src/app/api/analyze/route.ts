import { NextResponse } from 'next/server';
import { analyzeIntelligence } from '@/lib/ai';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { urls, searchQueries } = body;

    if ((!urls || urls.length === 0) && (!searchQueries || searchQueries.length === 0)) {
      return NextResponse.json(
        { error: 'Se requiere al menos una URL o consulta de búsqueda' },
        { status: 400 }
      );
    }

    const analysis = await analyzeIntelligence(
      urls || [],
      searchQueries || []
    );

    return NextResponse.json(analysis);
  } catch (error: unknown) {
    console.error('Error in analysis:', error);
    const errorMessage = error instanceof Error ? error.message : 'Error al realizar el análisis de inteligencia';
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}
