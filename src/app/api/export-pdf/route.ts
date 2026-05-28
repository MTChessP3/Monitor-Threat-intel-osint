import { NextResponse } from 'next/server';
import PDFDocument from 'pdfkit';
import { db } from '@/lib/db';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { reportId, content, title: inputTitle, threatLevel: inputThreatLevel, date: inputDate } = body;

    let reportContent = content || '';
    let reportTitle = inputTitle || 'Informe de Inteligencia';
    let reportThreatLevel = inputThreatLevel || 'medio';
    let reportDate = inputDate || new Date().toLocaleDateString('es-ES');

    // If reportId provided, fetch from DB
    if (reportId) {
      const report = await db.report.findUnique({
        where: { id: reportId },
      });
      if (report) {
        reportContent = report.content;
        reportTitle = report.title;
        reportThreatLevel = report.threatLevel;
        reportDate = new Date(report.createdAt).toLocaleDateString('es-ES', {
          year: 'numeric',
          month: 'long',
          day: 'numeric',
        });
      } else {
        return NextResponse.json({ error: 'Informe no encontrado' }, { status: 404 });
      }
    }

    if (!reportContent) {
      return NextResponse.json({ error: 'No hay contenido para exportar' }, { status: 400 });
    }

    // Create PDF document
    const doc = new PDFDocument({
      size: 'A4',
      margins: { top: 60, bottom: 60, left: 60, right: 60 },
      info: {
        Title: reportTitle,
        Author: 'VIP_Protection Report',
        Subject: 'Informe de Inteligencia Ejecutiva',
      },
    });

    const chunks: Buffer[] = [];
    doc.on('data', (chunk: Buffer) => chunks.push(chunk));

    // Helper: parse markdown content to PDF
    const lines = reportContent.split('\n');

    // Header section
    doc.fontSize(8).fillColor('#888888')
      .text('VIP_Protection Report', 60, 30, { align: 'center' });
    doc.fontSize(8).fillColor('#d4a017')
      .text('Executive Intelligence', 60, 42, { align: 'center' });

    // Separator line
    doc.moveTo(60, 58).lineTo(535, 58).strokeColor('#d4a017').lineWidth(1).stroke();

    // Title
    doc.moveDown(1);
    doc.fontSize(18).fillColor('#1a1a1a')
      .text(reportTitle, { align: 'center' });

    // Date and threat level
    doc.moveDown(0.5);
    doc.fontSize(10).fillColor('#555555')
      .text(`Fecha: ${reportDate}`, { align: 'center' });

    const threatLabels: Record<string, string> = {
      bajo: 'BAJO - Verde',
      medio: 'MEDIO - Amarillo',
      alto: 'ALTO - Naranja',
      critico: 'CRITICO - Rojo',
    };
    doc.fontSize(10).fillColor('#d4a017')
      .text(`Nivel de Amenaza: ${threatLabels[reportThreatLevel] || reportThreatLevel.toUpperCase()}`, { align: 'center' });

    // Separator
    doc.moveDown(0.5);
    doc.moveTo(60, doc.y).lineTo(535, doc.y).strokeColor('#cccccc').lineWidth(0.5).stroke();
    doc.moveDown(1);

    // Parse and render content
    for (const line of lines) {
      if (doc.y > 720) {
        doc.addPage();
        // Header on new page
        doc.fontSize(8).fillColor('#888888')
          .text('VIP_Protection Report - Documento Clasificado', 60, 30, { align: 'center' });
        doc.moveTo(60, 45).lineTo(535, 45).strokeColor('#d4a017').lineWidth(0.5).stroke();
        doc.moveDown(2);
      }

      if (line.startsWith('# ')) {
        // H1
        doc.fontSize(16).fillColor('#1a1a1a')
          .text(line.replace('# ', '').trim(), { align: 'left' });
        doc.moveDown(0.3);
      } else if (line.startsWith('## ')) {
        // H2
        doc.moveDown(0.5);
        doc.fontSize(14).fillColor('#2a2a2a')
          .text(line.replace('## ', '').trim(), { align: 'left' });
        doc.moveTo(60, doc.y + 2).lineTo(535, doc.y + 2).strokeColor('#d4a017').lineWidth(0.5).stroke();
        doc.moveDown(0.5);
      } else if (line.startsWith('### ')) {
        // H3
        doc.moveDown(0.3);
        doc.fontSize(12).fillColor('#333333')
          .text(line.replace('### ', '').trim(), { align: 'left' });
        doc.moveDown(0.3);
      } else if (line.startsWith('- ') || line.startsWith('* ')) {
        // Bullet point
        doc.fontSize(10).fillColor('#333333')
          .text(`  \u2022 ${line.replace(/^[-*]\s/, '').trim()}`, { indent: 20 });
      } else if (line.startsWith('**') && line.endsWith('**')) {
        // Bold text
        doc.fontSize(10).fillColor('#1a1a1a')
          .text(line.replace(/\*\*/g, '').trim(), { align: 'left' });
      } else if (line.trim() === '') {
        doc.moveDown(0.3);
      } else {
        // Regular text
        doc.fontSize(10).fillColor('#333333')
          .text(line, { align: 'left', lineGap: 2 });
      }
    }

    // Footer on last page
    doc.moveTo(60, 760).lineTo(535, 760).strokeColor('#d4a017').lineWidth(0.5).stroke();
    doc.fontSize(8).fillColor('#888888')
      .text('Documento Clasificado - VIP_Protection Report', 60, 770, { align: 'center' });

    doc.end();

    // Wait for the PDF to be generated
    const pdfBuffer = await new Promise<Buffer>((resolve) => {
      doc.on('end', () => {
        resolve(Buffer.concat(chunks));
      });
    });

    const safeTitle = reportTitle.replace(/[^a-zA-Z0-9áéíóúñÁÉÍÓÚÑ ]/g, '');

    return new NextResponse(pdfBuffer, {
      status: 200,
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="${safeTitle}.pdf"`,
      },
    });
  } catch (error) {
    console.error('Error generating PDF:', error);
    return NextResponse.json({ error: 'Error al generar PDF' }, { status: 500 });
  }
}
