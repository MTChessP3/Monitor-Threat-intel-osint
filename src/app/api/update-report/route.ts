import { NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';

export async function POST(request: Request) {
  try {
    await ensureDatabaseInitialized();
    const body = await request.json();
    const { reportId, updatedContent, additionalUrls, additionalNews, additionalContext } = body;

    if (!reportId) {
      return NextResponse.json({ error: 'ID del informe es requerido' }, { status: 400 });
    }

    const report = await db.report.findUnique({ where: { id: reportId } });
    if (!report) {
      return NextResponse.json({ error: 'Informe no encontrado' }, { status: 404 });
    }

    let content = updatedContent || '';

    // If no pre-generated content, check if additional info was provided
    if (!content) {
      const urls = additionalUrls
        ? additionalUrls.split(',').map((u: string) => u.trim()).filter((u: string) => u.length > 0)
        : [];
      const news = additionalNews || '';
      const context = additionalContext || '';

      if (urls.length === 0 && !news.trim() && !context.trim()) {
        return NextResponse.json({ error: 'Debe proporcionar información adicional' }, { status: 400 });
      }

      // Content should be pre-generated via /api/ai-operation before saving
      return NextResponse.json({ error: 'Contenido actualizado es requerido. Use /api/ai-operation primero.' }, { status: 400 });
    }

    const summaryMatch = content.match(/##?\s*(?:Resumen Ejecutivo|Resumen|Summary)\s*\n([\s\S]*?)(?=\n##?\s|\n*$)/i);
    const newSummary = summaryMatch ? summaryMatch[1].trim().substring(0, 300) : report.summary;

    const threatKeywords: Record<string, RegExp> = {
      critico: /cr[ií]tico|cr[ií]tica|extremo|grave/i,
      alto: /alto|alta|severo|severa|urgente/i,
      medio: /medio|media|moderado|moderada/i,
      bajo: /bajo|baja|m[ií]nimo|m[ií]nima/i,
    };
    let newThreatLevel = report.threatLevel;
    for (const [level, regex] of Object.entries(threatKeywords)) {
      if (regex.test(content)) { newThreatLevel = level; break; }
    }

    const updatedReport = await db.report.update({
      where: { id: reportId },
      data: { content, summary: newSummary, threatLevel: newThreatLevel },
    });

    return NextResponse.json(updatedReport);
  } catch (error) {
    console.error('Error updating report:', error);
    return NextResponse.json({ error: 'Error al actualizar el informe' }, { status: 500 });
  }
}
