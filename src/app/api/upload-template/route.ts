import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  try {
    const formData = await request.formData();
    const file = formData.get('file') as File | null;

    if (!file) {
      return NextResponse.json(
        { error: 'No se proporcionó ningún archivo' },
        { status: 400 }
      );
    }

    const fileName = file.name.toLowerCase();
    const buffer = Buffer.from(await file.arrayBuffer());
    let extractedText = '';

    if (fileName.endsWith('.txt') || fileName.endsWith('.md')) {
      // Plain text or markdown
      extractedText = buffer.toString('utf-8');
    } else if (fileName.endsWith('.docx')) {
      // DOCX file - use mammoth
      try {
        const mammoth = await import('mammoth');
        const result = await mammoth.extractRawText({ buffer });
        extractedText = result.value;
      } catch {
        return NextResponse.json(
          { error: 'Error al procesar el archivo DOCX. Verifique que el archivo sea válido.' },
          { status: 400 }
        );
      }
    } else if (fileName.endsWith('.pdf')) {
      // PDF file - use pdf-parse
      try {
        const pdfParse = (await import('pdf-parse')).default;
        const pdfData = await pdfParse(buffer);
        extractedText = pdfData.text;
      } catch {
        return NextResponse.json(
          { error: 'Error al procesar el archivo PDF. Verifique que el archivo sea válido.' },
          { status: 400 }
        );
      }
    } else {
      return NextResponse.json(
        { error: 'Formato no soportado. Use PDF, DOCX, TXT o MD.' },
        { status: 400 }
      );
    }

    if (!extractedText.trim()) {
      return NextResponse.json(
        { error: 'No se pudo extraer texto del archivo. Puede estar vacío o protegido.' },
        { status: 400 }
      );
    }

    return NextResponse.json({
      text: extractedText,
      fileName: file.name,
      fileSize: file.size,
    });
  } catch (error) {
    console.error('Error uploading template:', error);
    return NextResponse.json(
      { error: 'Error al procesar el archivo' },
      { status: 500 }
    );
  }
}
