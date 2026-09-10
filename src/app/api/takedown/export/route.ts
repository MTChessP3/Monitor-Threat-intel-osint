import { NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';
import { PDFDocument, rgb, StandardFonts } from 'pdf-lib';
import * as XLSX from 'xlsx';

const prisma = new PrismaClient();

interface ExportRequest {
  batchId?: string;
  reportId?: string;
  format: 'pdf' | 'csv' | 'json' | 'xlsx';
  includeDetails?: boolean;
}

async function getReportData(batchId?: string, reportId?: string) {
  if (reportId) {
    const report = await prisma.takeDownReport.findUnique({
      where: { id: reportId },
      include: {
        serviceResults: { orderBy: { createdAt: 'asc' } },
        batch: true,
      },
    });
    return report ? [report] : [];
  }

  if (batchId) {
    const batch = await prisma.takeDownBatch.findUnique({
      where: { id: batchId },
      include: {
        reports: {
          include: { serviceResults: { orderBy: { createdAt: 'asc' } } },
          orderBy: { createdAt: 'asc' },
        },
      },
    });
    return batch?.reports || [];
  }

  return [];
}

function generateCSV(reports: Awaited<ReturnType<typeof getReportData>>, includeDetails: boolean): string {
  const headers = [
    'Report ID',
    'Batch ID',
    'URL',
    'Report Status',
    'Report Created',
    'Report Completed',
    'Fingerprint',
  ];

  if (includeDetails) {
    headers.push(
      'Service',
      'Service Name',
      'Service Status',
      'Message',
      'Reference ID',
      'Service Timestamp',
      'Retry Count'
    );
  }

  const rows = [headers.join(',')];

  for (const report of reports) {
    const baseRow = [
      `"${report.id}"`,
      `"${report.batchId}"`,
      `"${report.url}"`,
      `"${report.status}"`,
      `"${report.createdAt.toISOString()}"`,
      `"${report.completedAt?.toISOString() || ''}"`,
      `"${report.fingerprint || ''}"`,
    ];

    if (includeDetails && report.serviceResults.length > 0) {
      for (const sr of report.serviceResults) {
        const detailRow = [
          ...baseRow,
          `"${sr.service}"`,
          `"${sr.serviceName}"`,
          `"${sr.status}"`,
          `"${sr.message?.replace(/"/g, '""') || ''}"`,
          `"${sr.referenceId || ''}"`,
          `"${sr.createdAt.toISOString()}"`,
          `"${sr.retryCount}"`,
        ];
        rows.push(detailRow.join(','));
      }
    } else {
      rows.push(baseRow.join(','));
    }
  }

  return rows.join('\n');
}

function generateXLSX(reports: Awaited<ReturnType<typeof getReportData>>, includeDetails: boolean): Buffer {
  const wb = XLSX.utils.book_new();

  // Summary sheet
  const summaryData = [
    ['TakeDown URL - Export Report'],
    ['Generated', new Date().toLocaleString()],
    ['Total Reports', reports.length],
    [''],
    ['Report ID', 'Batch ID', 'URL', 'Status', 'Created', 'Completed', 'Fingerprint'],
  ];

  for (const report of reports) {
    summaryData.push([
      report.id,
      report.batchId,
      report.url,
      report.status,
      report.createdAt.toISOString(),
      report.completedAt?.toISOString() || '',
      report.fingerprint || '',
    ]);
  }

  const wsSummary = XLSX.utils.aoa_to_sheet(summaryData);
  XLSX.utils.book_append_sheet(wb, wsSummary, 'Resumen');

  if (includeDetails) {
    const detailData = [
      ['Report ID', 'Batch ID', 'URL', 'Report Status', 'Service', 'Service Name', 'Service Status', 'Message', 'Reference ID', 'Timestamp', 'Retries'],
    ];

    for (const report of reports) {
      for (const sr of report.serviceResults) {
        detailData.push([
          report.id,
          report.batchId,
          report.url,
          report.status,
          sr.service,
          sr.serviceName,
          sr.status,
          sr.message || '',
          sr.referenceId || '',
          sr.createdAt.toISOString(),
          sr.retryCount,
        ]);
      }
    }

    const wsDetails = XLSX.utils.aoa_to_sheet(detailData);
    XLSX.utils.book_append_sheet(wb, wsDetails, 'Detalle por Servicio');
  }

  return Buffer.from(XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' }));
}

async function generatePDF(reports: Awaited<ReturnType<typeof getReportData>>, includeDetails: boolean): Promise<Buffer> {
  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const pageWidth = 595.28; // A4 width
  const pageHeight = 841.89; // A4 height
  const margin = 50;
  let y = pageHeight - margin;

  const addPage = () => {
    const page = pdfDoc.addPage([pageWidth, pageHeight]);
    y = pageHeight - margin;
    return page;
  };

  let page = addPage();

  const drawText = (text: string, x: number, yPos: number, size = 10, fontRef = font, color = rgb(0, 0, 0)) => {
    page.drawText(text, { x, y: yPos, size, font: fontRef, color });
  };

  const checkSpace = (needed: number) => {
    if (y < margin + needed) {
      page = addPage();
    }
  };

  // Title
  drawText('INFORME TAKEDOWN URL', margin, y, 20, fontBold, rgb(0.1, 0.2, 0.5));
  y -= 30;
  drawText(`Generado: ${new Date().toLocaleString()}`, margin, y, 10, font);
  drawText(`Total Reportes: ${reports.length}`, margin, y - 15, 10, font);
  y -= 40;

  for (const report of reports) {
    checkSpace(120);

    drawText(`Reporte: ${report.id}`, margin, y, 12, fontBold);
    y -= 20;

    const fields = [
      ['Batch ID:', report.batchId],
      ['URL:', report.url],
      ['Estado:', report.status],
      ['Creado:', report.createdAt.toLocaleString()],
      ['Completado:', report.completedAt?.toLocaleString() || 'Pendiente'],
      ['Fingerprint:', report.fingerprint || 'N/A'],
    ];

    for (const [label, value] of fields) {
      checkSpace(15);
      drawText(label, margin, y, 10, fontBold);
      drawText(String(value), margin + 100, y, 10, font);
      y -= 15;
    }

    if (includeDetails && report.serviceResults.length > 0) {
      checkSpace(20);
      drawText('Resultados por Servicio:', margin, y, 11, fontBold);
      y -= 18;

      const svcHeaders = ['Servicio', 'Estado', 'Mensaje', 'Ref. ID', 'Timestamp'];
      const colWidths = [120, 70, 180, 70, 90];
      let x = margin;

      for (let i = 0; i < svcHeaders.length; i++) {
        drawText(svcHeaders[i], x, y, 9, fontBold);
        x += colWidths[i];
      }
      y -= 15;

      for (const sr of report.serviceResults) {
        checkSpace(15);
        x = margin;
        const values = [
          sr.serviceName,
          sr.status,
          sr.message?.substring(0, 50) || '',
          sr.referenceId || '',
          sr.createdAt.toLocaleString(),
        ];

        for (let i = 0; i < values.length; i++) {
          drawText(String(values[i]), x, y, 8, font);
          x += colWidths[i];
        }
        y -= 14;
      }
    }

    y -= 20;
  }

  const pdfBytes = await pdfDoc.save();
  return Buffer.from(pdfBytes);
}

export async function POST(request: Request) {
  try {
    const body: ExportRequest = await request.json();
    const { batchId, reportId, format, includeDetails = true } = body;

    if (!batchId && !reportId) {
      return NextResponse.json({ error: 'Se requiere batchId o reportId' }, { status: 400 });
    }

    if (!['pdf', 'csv', 'json', 'xlsx'].includes(format)) {
      return NextResponse.json({ error: 'Formato no soportado. Use: pdf, csv, json, xlsx' }, { status: 400 });
    }

    const reports = await getReportData(batchId, reportId);

    if (reports.length === 0) {
      return NextResponse.json({ error: 'No se encontraron datos para exportar' }, { status: 404 });
    }

    let content: Buffer | string;
    let contentType: string;
    let filename: string;

    switch (format) {
      case 'csv':
        content = generateCSV(reports, includeDetails);
        contentType = 'text/csv; charset=utf-8';
        filename = `takedown-export-${batchId || reportId}-${Date.now()}.csv`;
        break;
      case 'json':
        content = JSON.stringify(reports, null, 2);
        contentType = 'application/json; charset=utf-8';
        filename = `takedown-export-${batchId || reportId}-${Date.now()}.json`;
        break;
      case 'xlsx':
        content = generateXLSX(reports, includeDetails);
        contentType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
        filename = `takedown-export-${batchId || reportId}-${Date.now()}.xlsx`;
        break;
      case 'pdf':
      default:
        content = await generatePDF(reports, includeDetails);
        contentType = 'application/pdf';
        filename = `takedown-export-${batchId || reportId}-${Date.now()}.pdf`;
        break;
    }

    return new NextResponse(content, {
      headers: {
        'Content-Type': contentType,
        'Content-Disposition': `attachment; filename="${filename}"`,
      },
    });
  } catch (error: unknown) {
    console.error('Error exporting report:', error);
    const errorMessage = error instanceof Error ? error.message : 'Error al exportar reporte';
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}