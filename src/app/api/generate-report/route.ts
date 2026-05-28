import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { generateReport, type AnalysisResult } from '@/lib/ai';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { templateId, analysis, title } = body;

    if (!analysis) {
      return NextResponse.json(
        { error: 'Datos de análisis son requeridos' },
        { status: 400 }
      );
    }

    // Get template content
    let templateContent = '';
    if (templateId) {
      const template = await db.reportTemplate.findUnique({
        where: { id: templateId },
      });
      if (template) {
        templateContent = template.content;
      }
    }

    // If no template, use default structure
    if (!templateContent) {
      templateContent = `# INFORME EJECUTIVO DE PROTECCIÓN VIP

## Resumen Ejecutivo
[Resumen de la situación actual de seguridad]

## Amenazas Detectadas
[Listado de amenazas identificadas con su nivel de severidad]

## Nivel de Riesgo
[Evaluación del nivel de riesgo general]

## Recomendaciones
[Recomendaciones de seguridad y protección]

## Conclusiones
[Conclusiones finales y próximos pasos]`;
    }

    // Generate the report using AI
    const reportContent = await generateReport(
      templateContent,
      analysis as AnalysisResult
    );

    // Save to database
    const report = await db.report.create({
      data: {
        title: title || `Informe de Inteligencia - ${new Date().toLocaleDateString('es-ES')}`,
        summary: analysis.summary || '',
        threatLevel: analysis.overallRiskLevel || 'bajo',
        content: reportContent,
        templateId: templateId || null,
        sourcesUsed: JSON.stringify(analysis.sources?.map((s: { url: string }) => s.url) || []),
      },
    });

    return NextResponse.json(report);
  } catch (error) {
    console.error('Error generating report:', error);
    return NextResponse.json(
      { error: 'Error al generar el informe' },
      { status: 500 }
    );
  }
}
