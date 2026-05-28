import { NextResponse } from 'next/server';

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

    // This endpoint is deprecated - use /api/ai-operation with operation: 'analyze' instead
    // Redirect to the inlined AI operation
    return NextResponse.json({ 
      error: 'Este endpoint ha sido reemplazado. Use /api/ai-operation con operation: "analyze".' 
    }, { status: 410 });
  } catch (error: unknown) {
    console.error('Error in analysis:', error);
    const errorMessage = error instanceof Error ? error.message : 'Error al realizar el análisis';
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}
