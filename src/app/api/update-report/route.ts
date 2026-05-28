import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { updateReport } from '@/lib/ai';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { reportId, additionalUrls, additionalNews, additionalContext } = body;

    if (!reportId) {
      return NextResponse.json({ error: 'ID del informe es requerido' }, { status: 400 });
    }

    // Fetch existing report
    const report = await db.report.findUnique({
      where: { id: reportId },
    });

    if (!report) {
      return NextResponse.json({ error: 'Informe no encontrado' }, { status: 404 });
    }

    // Parse additional URLs
    const urls = additionalUrls
      ? additionalUrls.split(',').map((u: string) => u.trim()).filter((u: string) => u.length > 0)
      : [];

    const news = additionalNews || '';
    const context = additionalContext || '';

    if (urls.length === 0 && !news.trim() && !context.trim()) {
      return NextResponse.json({ error: 'Debe proporcionar al menos una URL, noticias adicionales o contexto adicional' }, { status: 400 });
    }

    // Update the report using AI
    const updatedContent = await updateReport(
      report.content,
      report.title,
      urls,
      news,
      context
    );

    // Generate new summary from updated content
    const summaryMatch = updatedContent.match(/##?\s*(?:Resumen Ejecutivo|Resumen|Summary)\s*\n([\s\S]*?)(?=\n##?\s|\n*$)/i);
    const newSummary = summaryMatch ? summaryMatch[1].trim().substring(0, 300) : report.summary;

    // Detect threat level from content
    const threatKeywords: Record<string, string> = {
      critico: /cr[ií]tico|cr[ií]tica|extremo|grave/i,
      alto: /alto|alta|severo|severa|urgente/i,
      medio: /medio|media|moderado|moderada/i,
      bajo: /bajo|baja|m[ií]nimo|m[ií]nima/i,
    };
    let newThreatLevel = report.threatLevel;
    for (const [level, regex] of Object.entries(threatKeywords)) {
      if (regex.test(updatedContent)) {
        newThreatLevel = level;
        break;
      }
    }

    // Update the report in database
    const updatedReport = await db.report.update({
      where: { id: reportId },
      data: {
        content: updatedContent,
        summary: newSummary,
        threatLevel: newThreatLevel,
      },
    });

    return NextResponse.json(updatedReport);
  } catch (error) {
    console.error('Error updating report:', error);
    return NextResponse.json({ error: 'Error al actualizar el informe' }, { status: 500 });
  }
}
