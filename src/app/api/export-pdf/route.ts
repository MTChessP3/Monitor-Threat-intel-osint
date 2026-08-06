import { NextResponse } from 'next/server';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
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

    // Create PDF document using pdf-lib
    const pdfDoc = await PDFDocument.create();
    const fontRegular = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
    const fontItalic = await pdfDoc.embedFont(StandardFonts.HelveticaOblique);

    const pageWidth = 595.28; // A4 width
    const pageHeight = 841.89; // A4 height
    const margin = 60;
    const contentWidth = pageWidth - (margin * 2);
    let currentPage = pdfDoc.addPage([pageWidth, pageHeight]);
    let y = pageHeight - margin;

    const threatLabels: Record<string, string> = {
      bajo: 'BAJO - Verde',
      medio: 'MEDIO - Amarillo',
      alto: 'ALTO - Naranja',
      critico: 'CRITICO - Rojo',
    };

    // Color constants
    const gold = rgb(0.83, 0.63, 0.09);
    const gray = rgb(0.53, 0.53, 0.53);
    const darkGray = rgb(0.33, 0.33, 0.33);
    const lightGray = rgb(0.8, 0.8, 0.8);
    const black = rgb(0.1, 0.1, 0.1);
    const text = rgb(0.2, 0.2, 0.2);
    const subtext = rgb(0.27, 0.27, 0.27);

    // Helper: add new page
    function addNewPage() {
      currentPage = pdfDoc.addPage([pageWidth, pageHeight]);
      y = pageHeight - margin;
      currentPage.drawText('VIP_Protection Report - Documento Clasificado', {
        x: margin, y: pageHeight - 30, size: 7, font: fontRegular, color: gray,
      });
      currentPage.drawLine({
        start: { x: margin, y: pageHeight - 38 },
        end: { x: pageWidth - margin, y: pageHeight - 38 },
        thickness: 0.5, color: gold,
      });
      y = pageHeight - 55;
    }

    // Helper: wrap text
    function wrapText(text: string, font: typeof fontRegular, size: number, maxWidth: number): string[] {
      // Remove characters that can't be encoded in WinAnsi
      const cleanText = text
        .replace(/[^\x00-\x7F]/g, (ch) => {
          // Common Spanish character replacements
          const map: Record<string, string> = {
            'á': 'a', 'é': 'e', 'í': 'i', 'ó': 'o', 'ú': 'u',
            'Á': 'A', 'É': 'E', 'Í': 'I', 'Ó': 'O', 'Ú': 'U',
            'ñ': 'n', 'Ñ': 'N', 'ü': 'u', 'Ü': 'U',
            '—': '-', '–': '-', '"': '"', '"': '"',
            '\u2019': "'", '\u2018': "'", '\u2022': '*', '\u25BA': '>',
            '«': '"', '»': '"', '¡': '!', '¿': '?',
          };
          return map[ch] || '';
        });
      
      const words = cleanText.split(' ');
      const lines: string[] = [];
      let currentLine = '';

      for (const word of words) {
        const testLine = currentLine ? `${currentLine} ${word}` : word;
        try {
          const testWidth = font.widthOfTextAtSize(testLine, size);
          if (testWidth > maxWidth && currentLine) {
            lines.push(currentLine);
            currentLine = word;
          } else {
            currentLine = testLine;
          }
        } catch {
          // If text measurement fails, just push the line
          if (currentLine) lines.push(currentLine);
          currentLine = word;
        }
      }
      if (currentLine) lines.push(currentLine);
      return lines.length > 0 ? lines : [''];
    }

    // Helper: draw text with page management
    function drawWrappedText(text: string, x: number, fontSize: number, font: typeof fontRegular, colorVal: ReturnType<typeof rgb>, lineHeight?: number) {
      const lh = lineHeight || fontSize + 3;
      const lines = wrapText(text, font, fontSize, contentWidth - (x - margin));
      for (const line of lines) {
        if (y < margin + 30) addNewPage();
        try {
          currentPage.drawText(line, { x, y, size: fontSize, font, color: colorVal });
        } catch {
          // Skip lines that can't be rendered
        }
        y -= lh;
      }
    }

    // ===== HEADER =====
    currentPage.drawLine({
      start: { x: margin, y: pageHeight - 30 },
      end: { x: pageWidth - margin, y: pageHeight - 30 },
      thickness: 1, color: gold,
    });

    y = pageHeight - 50;
    drawWrappedText('VIP_Protection Report', margin, 8, fontRegular, gray);
    drawWrappedText('Executive Intelligence', margin, 7, fontItalic, gold);

    // Separator
    y -= 5;
    currentPage.drawLine({
      start: { x: margin, y },
      end: { x: pageWidth - margin, y },
      thickness: 0.5, color: gold,
    });
    y -= 20;

    // Classification
    drawWrappedText(`CLASIFICACION: ${threatLabels[reportThreatLevel] || reportThreatLevel.toUpperCase()}`, margin, 9, fontBold, gold);

    // Title
    y -= 10;
    drawWrappedText(reportTitle, margin, 16, fontBold, black, 22);

    // Date
    y -= 5;
    drawWrappedText(`Fecha: ${reportDate}`, margin, 10, fontRegular, darkGray);

    // Separator
    y -= 10;
    currentPage.drawLine({
      start: { x: margin, y },
      end: { x: pageWidth - margin, y },
      thickness: 0.5, color: lightGray,
    });
    y -= 20;

    // ===== CONTENT =====
    const cleanContent = reportContent.replace(/```markdown\n?/g, '').replace(/```\n?/g, '');
    const lines = cleanContent.split('\n');

    for (const line of lines) {
      if (y < margin + 50) addNewPage();

      const trimmedLine = line.trim();

      if (trimmedLine.startsWith('# ')) {
        y -= 10;
        const heading = trimmedLine.replace('# ', '').replace(/\*\*/g, '');
        drawWrappedText(heading, margin, 15, fontBold, black, 20);
        y -= 5;
      } else if (trimmedLine.startsWith('## ')) {
        y -= 8;
        const heading = trimmedLine.replace('## ', '').replace(/\*\*/g, '');
        drawWrappedText(heading, margin, 13, fontBold, rgb(0.16, 0.16, 0.16), 18);
        currentPage.drawLine({
          start: { x: margin, y: y + 3 },
          end: { x: pageWidth - margin, y: y + 3 },
          thickness: 0.5, color: gold,
        });
        y -= 5;
      } else if (trimmedLine.startsWith('### ')) {
        y -= 5;
        const heading = trimmedLine.replace('### ', '').replace(/\*\*/g, '');
        drawWrappedText(heading, margin, 11, fontBold, rgb(0.2, 0.2, 0.2), 16);
        y -= 3;
      } else if (trimmedLine.startsWith('#### ')) {
        y -= 3;
        const heading = trimmedLine.replace('#### ', '').replace(/\*\*/g, '');
        drawWrappedText(heading, margin, 10, fontBold, subtext, 14);
      } else if (trimmedLine.startsWith('- ') || trimmedLine.startsWith('* ')) {
        const bulletText = trimmedLine.replace(/^[-*]\s/, '').replace(/\*\*/g, '');
        if (y < margin + 50) addNewPage();
        try {
          currentPage.drawText('*', { x: margin + 10, y, size: 10, font: fontRegular, color: text });
        } catch { /* skip */ }
        drawWrappedText(bulletText, margin + 25, 10, fontRegular, text);
      } else if (trimmedLine.startsWith('---') || trimmedLine.startsWith('***')) {
        y -= 5;
        currentPage.drawLine({
          start: { x: margin, y },
          end: { x: pageWidth - margin, y },
          thickness: 0.5, color: gold,
        });
        y -= 10;
      } else if (trimmedLine === '') {
        y -= 8;
      } else if (trimmedLine.startsWith('|')) {
        const cells = trimmedLine.split('|').filter(c => c.trim() && !c.match(/^[-:]+$/));
        if (cells.length > 0) {
          const rowText = cells.map(c => c.trim().replace(/\*\*/g, '')).join(' | ');
          drawWrappedText(rowText, margin, 9, fontRegular, subtext);
        }
      } else if (trimmedLine.match(/^\d+\.\s/)) {
        const numText = trimmedLine.replace(/\*\*/g, '');
        drawWrappedText(numText, margin + 10, 10, fontRegular, text);
      } else {
        const cleanLine = trimmedLine
          .replace(/\*\*(.*?)\*\*/g, '$1')
          .replace(/\*(.*?)\*/g, '$1');
        drawWrappedText(cleanLine, margin, 10, fontRegular, text);
      }
    }

    // Footer on last page
    if (y > margin + 30) {
      currentPage.drawLine({
        start: { x: margin, y: margin + 20 },
        end: { x: pageWidth - margin, y: margin + 20 },
        thickness: 0.5, color: gold,
      });
      currentPage.drawText('Documento Clasificado - VIP_Protection Report', {
        x: margin, y: margin + 5, size: 7, font: fontRegular, color: gray,
      });
    }

    const pdfBytes = await pdfDoc.save();
    const pdfBuffer = Buffer.from(pdfBytes);

    const safeTitle = reportTitle.replace(/[^a-zA-Z0-9 ]/g, '');

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
