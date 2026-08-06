import { NextResponse } from 'next/server';
import {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  BorderStyle, TabStopPosition, TabStopType,
} from 'docx';
import { db, ensureDatabaseInitialized } from '@/lib/db';

export async function POST(request: Request) {
  try {
    await ensureDatabaseInitialized();
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

    // Parse markdown content to docx paragraphs
    const lines = reportContent.split('\n');
    const children: Paragraph[] = [];

    // Header section
    children.push(
      new Paragraph({
        children: [
          new TextRun({
            text: 'VIP_Protection Report',
            bold: true,
            size: 16,
            color: '888888',
            font: 'Calibri',
          }),
          new TextRun({
            text: '  |  Executive Intelligence',
            size: 14,
            color: 'D4A017',
            font: 'Calibri',
          }),
        ],
        alignment: AlignmentType.CENTER,
        spacing: { after: 100 },
        border: {
          bottom: { style: BorderStyle.SINGLE, size: 1, color: 'D4A017' },
        },
      })
    );

    // Title
    children.push(
      new Paragraph({
        children: [
          new TextRun({
            text: reportTitle,
            bold: true,
            size: 28,
            color: '1A1A1A',
            font: 'Calibri',
          }),
        ],
        alignment: AlignmentType.CENTER,
        heading: HeadingLevel.TITLE,
        spacing: { before: 200, after: 100 },
      })
    );

    // Date and threat level
    const threatLabels: Record<string, string> = {
      bajo: 'BAJO',
      medio: 'MEDIO',
      alto: 'ALTO',
      critico: 'CRITICO',
    };

    children.push(
      new Paragraph({
        children: [
          new TextRun({
            text: `Fecha: ${reportDate}`,
            size: 20,
            color: '555555',
            font: 'Calibri',
          }),
        ],
        alignment: AlignmentType.CENTER,
        spacing: { after: 50 },
      })
    );

    children.push(
      new Paragraph({
        children: [
          new TextRun({
            text: `Nivel de Amenaza: `,
            size: 20,
            color: '555555',
            font: 'Calibri',
          }),
          new TextRun({
            text: threatLabels[reportThreatLevel] || reportThreatLevel.toUpperCase(),
            bold: true,
            size: 20,
            color: 'D4A017',
            font: 'Calibri',
          }),
        ],
        alignment: AlignmentType.CENTER,
        spacing: { after: 200 },
        border: {
          bottom: { style: BorderStyle.SINGLE, size: 1, color: 'CCCCCC' },
        },
      })
    );

    // Parse markdown lines
    for (const line of lines) {
      if (line.startsWith('# ')) {
        children.push(
          new Paragraph({
            children: [
              new TextRun({
                text: line.replace('# ', '').trim(),
                bold: true,
                size: 26,
                color: '1A1A1A',
                font: 'Calibri',
              }),
            ],
            heading: HeadingLevel.HEADING_1,
            spacing: { before: 300, after: 100 },
          })
        );
      } else if (line.startsWith('## ')) {
        children.push(
          new Paragraph({
            children: [
              new TextRun({
                text: line.replace('## ', '').trim(),
                bold: true,
                size: 22,
                color: '2A2A2A',
                font: 'Calibri',
              }),
            ],
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 250, after: 80 },
            border: {
              bottom: { style: BorderStyle.SINGLE, size: 1, color: 'D4A017' },
            },
          })
        );
      } else if (line.startsWith('### ')) {
        children.push(
          new Paragraph({
            children: [
              new TextRun({
                text: line.replace('### ', '').trim(),
                bold: true,
                size: 20,
                color: '333333',
                font: 'Calibri',
              }),
            ],
            heading: HeadingLevel.HEADING_3,
            spacing: { before: 200, after: 60 },
          })
        );
      } else if (line.startsWith('- ') || line.startsWith('* ')) {
        const bulletText = line.replace(/^[-*]\s/, '').trim();
        // Parse bold within bullet
        const runs = parseInlineFormatting(bulletText, 20);
        children.push(
          new Paragraph({
            children: runs,
            bullet: { level: 0 },
            spacing: { after: 40 },
          })
        );
      } else if (line.startsWith('**') && line.endsWith('**')) {
        children.push(
          new Paragraph({
            children: [
              new TextRun({
                text: line.replace(/\*\*/g, '').trim(),
                bold: true,
                size: 20,
                color: '1A1A1A',
                font: 'Calibri',
              }),
            ],
            spacing: { after: 60 },
          })
        );
      } else if (line.trim() === '') {
        children.push(
          new Paragraph({
            children: [],
            spacing: { after: 60 },
          })
        );
      } else {
        const runs = parseInlineFormatting(line, 20);
        children.push(
          new Paragraph({
            children: runs,
            spacing: { after: 60 },
          })
        );
      }
    }

    // Footer
    children.push(
      new Paragraph({
        children: [
          new TextRun({
            text: 'Documento Clasificado - VIP_Protection Report',
            size: 14,
            color: '888888',
            font: 'Calibri',
          }),
        ],
        alignment: AlignmentType.CENTER,
        spacing: { before: 400 },
        border: {
          top: { style: BorderStyle.SINGLE, size: 1, color: 'D4A017' },
        },
      })
    );

    const doc = new Document({
      sections: [{
        properties: {
          page: {
            margin: {
              top: 1200,
              right: 1200,
              bottom: 1200,
              left: 1200,
            },
          },
        },
        children,
      }],
    });

    const buffer = await Packer.toBuffer(doc);

    const safeTitle = reportTitle.replace(/[^a-zA-Z0-9áéíóúñÁÉÍÓÚÑ ]/g, '');

    return new NextResponse(buffer, {
      status: 200,
      headers: {
        'Content-Type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'Content-Disposition': `attachment; filename="${safeTitle}.docx"`,
      },
    });
  } catch (error) {
    console.error('Error generating DOCX:', error);
    return NextResponse.json({ error: 'Error al generar DOCX' }, { status: 500 });
  }
}

// Helper to parse inline bold/italic formatting
function parseInlineFormatting(text: string, baseSize: number): TextRun[] {
  const runs: TextRun[] = [];
  // Split by **bold** patterns
  const boldRegex = /\*\*(.+?)\*\*/g;
  let lastIndex = 0;
  let match;

  while ((match = boldRegex.exec(text)) !== null) {
    // Text before bold
    if (match.index > lastIndex) {
      runs.push(new TextRun({
        text: text.slice(lastIndex, match.index),
        size: baseSize,
        color: '333333',
        font: 'Calibri',
      }));
    }
    // Bold text
    runs.push(new TextRun({
      text: match[1],
      bold: true,
      size: baseSize,
      color: '1A1A1A',
      font: 'Calibri',
    }));
    lastIndex = match.index + match[0].length;
  }

  // Remaining text
  if (lastIndex < text.length) {
    runs.push(new TextRun({
      text: text.slice(lastIndex),
      size: baseSize,
      color: '333333',
      font: 'Calibri',
    }));
  }

  // If no formatting found, return simple text
  if (runs.length === 0) {
    runs.push(new TextRun({
      text: text,
      size: baseSize,
      color: '333333',
      font: 'Calibri',
    }));
  }

  return runs;
}
