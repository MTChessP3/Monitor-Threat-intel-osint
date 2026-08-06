import { NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';

export async function POST(request: Request) {
  try {
    await ensureDatabaseInitialized();
    const body = await request.json();
    const { templateId, analysis, title, reportContent } = body;

    const content = reportContent || '';
    if (!content) {
      return NextResponse.json({ error: 'No hay contenido para el informe' }, { status: 400 });
    }

    // Small delay to let resources recover from previous AI operation
    await new Promise(r => setTimeout(r, 500));

    const report = await db.report.create({
      data: {
        title: title || `Informe de Inteligencia - ${new Date().toLocaleDateString('es-ES')}`,
        summary: analysis?.summary || '',
        threatLevel: analysis?.overallRiskLevel || 'bajo',
        content,
        templateId: templateId || null,
        sourcesUsed: JSON.stringify(analysis?.sources?.map((s: { url: string }) => s.url) || []),
        generationMode: 'automatic',
        abuseTypes: '[]',
        severity: analysis?.overallRiskLevel || 'bajo',
        tlpLevel: 'AMBER',
        inputUrls: '[]',
        inputText: '',
      },
    });

    return NextResponse.json(report);
  } catch (error) {
    console.error('Error generating report:', error);
    return NextResponse.json({ error: 'Error al generar el informe' }, { status: 500 });
  }
}
