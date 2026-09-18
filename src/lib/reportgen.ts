// Professional report generation engine: PDF (pdfkit), DOCX (docx), PPTX (pptxgenjs).
// Supports custom templates and injected custom content for executive/technical audiences.

import PDFDocument from 'pdfkit';
import { Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell, WidthType, AlignmentType, BorderStyle } from 'docx';
import pptxgen from 'pptxgenjs';

export interface ReportSection {
  title: string;
  body?: string;
  bullets?: string[];
  table?: { headers: string[]; rows: (string | number)[][] };
  metadata?: Record<string, string | number | boolean>;
}

export interface ReportSpec {
  title: string;
  subtitle?: string;
  riskLevel?: string;
  generatedAt?: string;
  preparedBy?: string;
  classification?: string;
  sections: ReportSection[];
  customHeader?: string;
  customFooter?: string;
}

const esc = (s: any) => String(s ?? '');

function riskColor(risk?: string): string {
  switch ((risk || '').toUpperCase()) {
    case 'CRITICAL': return '#dc2626';
    case 'HIGH': return '#f97316';
    case 'MEDIUM': return '#eab308';
    case 'LOW': return '#22c55e';
    default: return '#3b82f6';
  }
}

// ==================== PDF ====================
export async function buildPDF(spec: ReportSpec): Promise<Buffer> {
  const doc = new PDFDocument({ size: 'A4', margin: 48, bufferPages: true });
  const chunks: Buffer[] = [];
  doc.on('data', (c: Buffer) => chunks.push(c));

  const finish = new Promise<Buffer>((resolve) => {
    doc.on('end', () => resolve(Buffer.concat(chunks)));
  });

  // Header band
  doc.rect(0, 0, doc.page.width, 90).fill('#0f172a');
  doc.fillColor('#f87171').fontSize(20).font('Helvetica-Bold')
    .text('MONITOR-THREAT', 48, 24);
  doc.fillColor('#94a3b8').fontSize(10).font('Helvetica')
    .text('Professional Threat Intelligence Report', 48, 50);
  doc.fillColor(riskColor(spec.riskLevel)).fontSize(11).font('Helvetica-Bold')
    .text(`Risk Level: ${esc(spec.riskLevel || 'N/A')}`, 48, 68);

  doc.fillColor('#111827');
  doc.y = 120;
  doc.fillColor('#0f172a').fontSize(16).font('Helvetica-Bold').text(esc(spec.title), { continued: false });
  doc.fillColor('#475569').fontSize(9).font('Helvetica')
    .text(`Generated: ${esc(spec.generatedAt || new Date().toLocaleString())}  ·  Prepared by: ${esc(spec.preparedBy || 'Monitor-Threat')}  ·  ${esc(spec.classification || 'UNCLASSIFIED')}`, 48, doc.y + 4);

  if (spec.customHeader) {
    doc.moveDown(0.5).fillColor('#64748b').fontSize(9).font('Helvetica-Oblique').text(esc(spec.customHeader));
  }

  for (const sec of spec.sections) {
    doc.moveDown(1);
    doc.fillColor('#f87171').fontSize(13).font('Helvetica-Bold').text(esc(sec.title));
    doc.fillColor('#334155');
    if (sec.body) {
      doc.moveDown(0.25).font('Helvetica').fontSize(10).text(esc(sec.body));
    }
    if (sec.metadata) {
      doc.moveDown(0.25);
      Object.entries(sec.metadata).forEach(([k, v]) => {
        doc.font('Helvetica').fontSize(9).fillColor('#475569').text(`${k}: `, { continued: true });
        doc.fillColor('#0f172a').font('Helvetica-Bold').text(esc(v));
      });
    }
    if (sec.bullets && sec.bullets.length) {
      doc.moveDown(0.25).font('Helvetica').fontSize(10).fillColor('#334155');
      sec.bullets.forEach((b) => doc.text('• ' + esc(b)));
    }
    if (sec.table && sec.table.headers.length) {
      doc.moveDown(0.3);
      const colW = (doc.page.width - 96) / sec.table.headers.length;
      const drawRow = (cells: string[], bold: boolean, bg?: string) => {
        const y0 = doc.y;
        let maxH = 14;
        doc.font(bold ? 'Helvetica-Bold' : 'Helvetica').fontSize(8);
        cells.forEach((c, i) => {
          if (bg) doc.rect(48 + i * colW, y0, colW, 14).fill(bg);
          doc.fillColor(bold ? '#ffffff' : '#1e293b').text(esc(c).substring(0, 60), 48 + i * colW + 3, y0 + 3, { width: colW - 6 });
        });
        maxH = Math.max(maxH, doc.y - y0);
        doc.y = y0 + maxH + 2;
      };
      drawRow(sec.table.headers, true, '#0f172a');
      sec.table.rows.slice(0, 40).forEach((r) => drawRow(r.map((x) => String(x)), false));
    }
  }

  if (spec.customFooter) {
    doc.moveDown(1).fillColor('#64748b').fontSize(9).font('Helvetica-Oblique').text(esc(spec.customFooter));
  }

  // Footer on every page
  const pages = doc.bufferedPageRange();
  for (let i = pages.start; i < pages.start + pages.count; i++) {
    doc.switchToPage(i);
    doc.fontSize(8).fillColor('#94a3b8').font('Helvetica')
      .text('MONITOR-THREAT · Confidential — For authorized use only', 48, doc.page.height - 40, { align: 'center' });
  }

  doc.end();
  return finish;
}

// ==================== DOCX ====================
export async function buildDOCX(spec: ReportSpec): Promise<Buffer> {
  const children: any[] = [];
  const pushP = (text: string, opts: any = {}) =>
    children.push(new Paragraph({ children: [new TextRun({ text, ...opts })], spacing: { after: 120 } }));

  children.push(
    new Paragraph({
      children: [new TextRun({ text: 'MONITOR-THREAT', bold: true, size: 52, color: 'f87171' })],
    }),
    new Paragraph({
      children: [new TextRun({ text: spec.title, bold: true, size: 32 })],
      spacing: { before: 240, after: 120 },
    }),
    new Paragraph({
      children: [new TextRun({ text: `Risk Level: ${esc(spec.riskLevel || 'N/A')}`, color: riskColor(spec.riskLevel).replace('#', ''), bold: true })],
    }),
    new Paragraph({
      children: [new TextRun({ text: `Generated: ${esc(spec.generatedAt || new Date().toLocaleString())}  ·  ${esc(spec.classification || 'UNCLASSIFIED')}`, size: 18, color: '64748b' })],
    })
  );

  if (spec.customHeader) {
    children.push(new Paragraph({ children: [new TextRun({ text: esc(spec.customHeader), italics: true, color: '64748b', size: 18 })] }));
  }

  for (const sec of spec.sections) {
    children.push(
      new Paragraph({
        heading: HeadingLevel.HEADING_2,
        children: [new TextRun({ text: sec.title, bold: true, color: 'f87171' })],
        spacing: { before: 300, after: 120 },
      })
    );
    if (sec.body) children.push(new Paragraph({ children: [new TextRun({ text: esc(sec.body) })], spacing: { after: 120 } }));
    if (sec.metadata) {
      Object.entries(sec.metadata).forEach(([k, v]) =>
        children.push(new Paragraph({ children: [new TextRun({ text: `${k}: `, bold: true }), new TextRun({ text: esc(v) })] }))
      );
    }
    if (sec.bullets && sec.bullets.length) {
      sec.bullets.forEach((b) =>
        children.push(new Paragraph({ children: [new TextRun({ text: '• ' + esc(b) })] }))
      );
    }
    if (sec.table && sec.table.headers.length) {
      const rows: TableRow[] = [
        new TableRow({
          tableHeader: true,
          children: sec.table.headers.map(
            (h) =>
              new TableCell({
                shading: { fill: '0f172a' },
                children: [new Paragraph({ children: [new TextRun({ text: esc(h), bold: true, color: 'ffffff' })] })],
              })
          ),
        }),
      ];
      sec.table.rows.slice(0, 50).forEach((r) =>
        rows.push(
          new TableRow({
            children: r.map(
              (c) =>
                new TableCell({
                  borders: { top: { style: BorderStyle.SINGLE, size: 1, color: 'e2e8f0' }, bottom: { style: BorderStyle.SINGLE, size: 1, color: 'e2e8f0' } },
                  children: [new Paragraph({ children: [new TextRun({ text: esc(c) })] })],
                })
            ),
          })
        )
      );
      children.push(
        new Table({
          width: { size: 100, type: WidthType.PERCENTAGE },
          rows,
        })
      );
    }
  }

  if (spec.customFooter) {
    children.push(new Paragraph({ children: [new TextRun({ text: esc(spec.customFooter), italics: true, color: '64748b' })] }));
  }

  const doc = new Document({
    styles: { default: { document: { run: { font: 'Calibri', size: 22 } } } },
    sections: [{ properties: {}, children }],
  });
  return Packer.toBuffer(doc);
}

// ==================== PPTX ====================
export async function buildPPTX(spec: ReportSpec): Promise<Buffer> {
  const pptx = new pptxgen();
  pptx.author = spec.preparedBy || 'Monitor-Threat';
  pptx.title = spec.title;
  pptx.layout = 'LAYOUT_16x9';

  const bg = pptx.ShapeType.rect;
  const slideHeader = (slide: any, title: string, subtitle?: string) => {
    slide.background = { color: '0B0F19' };
    slide.addText('MONITOR-THREAT', { x: 0.5, y: 0.25, w: 5, h: 0.4, color: 'F87171', bold: true, fontSize: 20 });
    slide.addText(title, { x: 0.5, y: 0.75, w: 9, h: 0.7, color: 'FFFFFF', bold: true, fontSize: 28 });
    if (subtitle) slide.addText(subtitle, { x: 0.5, y: 1.45, w: 9, h: 0.4, color: '94A3B8', fontSize: 12 });
    slide.addShape(bg, { x: 0, y: 5.0, w: 10, h: 0.1, fill: { color: '1F2937' } });
  };

  // Title slide
  let s = pptx.addSlide();
  s.background = { color: '0B0F19' };
  s.addShape(bg, { x: 0, y: 0, w: 10, h: 0.15, fill: { color: 'F87171' } });
  s.addText('MONITOR-THREAT', { x: 0.5, y: 1.8, w: 9, h: 0.5, color: 'F87171', bold: true, fontSize: 30 });
  s.addText(spec.title, { x: 0.5, y: 2.4, w: 9, h: 1.2, color: 'FFFFFF', bold: true, fontSize: 40 });
  s.addText(`Risk Level: ${esc(spec.riskLevel || 'N/A')}`, { x: 0.5, y: 3.6, w: 9, h: 0.5, color: riskColor(spec.riskLevel), bold: true, fontSize: 18 });
  s.addText(`Generated: ${esc(spec.generatedAt || new Date().toLocaleString())}`, { x: 0.5, y: 4.2, w: 9, h: 0.4, color: '94A3B8', fontSize: 12 });
  if (spec.customHeader) s.addText(esc(spec.customHeader), { x: 0.5, y: 4.6, w: 9, h: 0.4, color: '94A3B8', fontSize: 11 });

  // Section slides
  for (const sec of spec.sections) {
    s = pptx.addSlide();
    slideHeader(s, sec.title);
    let y = 2.0;
    if (sec.body) {
      s.addText(esc(sec.body), { x: 0.5, y, w: 9, h: 1.5, color: 'E5E7EB', fontSize: 13, valign: 'top' });
      y += 1.6;
    }
    if (sec.metadata) {
      const meta = Object.entries(sec.metadata).map(([k, v]) => `${k}: ${esc(v)}`).join('   ·   ');
      s.addText(meta, { x: 0.5, y, w: 9, h: 0.5, color: '60A5FA', fontSize: 12 });
      y += 0.6;
    }
    if (sec.bullets && sec.bullets.length) {
      s.addText(
        sec.bullets.map((b) => ({ text: `•  ${esc(b)}`, options: { bullet: false } })),
        { x: 0.5, y, w: 9, h: Math.min(2.8, 0.35 * sec.bullets.length), color: 'D1D5DB', fontSize: 12, valign: 'top' }
      );
    }
    if (sec.table && sec.table.headers.length) {
      const rows: string[][] = sec.table.rows.slice(0, 12).map((r) => r.map((c) => String(c)));
      const headers: string[] = sec.table.headers.map((h) => String(h));
      s.addTable([headers, ...rows] as any, {
        x: 0.4, y: y + 0.2, w: 9.2,
        fontSize: 9,
        border: { pt: 0.5, color: '334155' },
        fill: { color: '111827' },
        color: 'E5E7EB',
        rowH: 0.28,
      }) as any;
    }
  }

  if (spec.customFooter) {
    s = pptx.addSlide();
    slideHeader(s, 'Closing');
    s.addText(esc(spec.customFooter), { x: 0.5, y: 2.2, w: 9, h: 1.2, color: '94A3B8', fontSize: 13 });
  }

  const b64 = await pptx.write({ outputType: 'base64' });
  return Buffer.from(b64 as string, 'base64');
}
