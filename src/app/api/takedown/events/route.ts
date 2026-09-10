import { NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const batchId = searchParams.get('batchId');

  if (!batchId) {
    return NextResponse.json({ error: 'batchId requerido' }, { status: 400 });
  }

  const encoder = new TextEncoder();
  let intervalId: NodeJS.Timeout | null = null;

  const stream = new ReadableStream({
    start(controller) {
      const sendEvent = (data: unknown) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
      };

      const fetchAndSend = async () => {
        try {
          const batch = await prisma.takeDownBatch.findUnique({
            where: { id: batchId },
            include: {
              reports: {
                include: { serviceResults: true },
              },
              serviceResults: true,
            },
          });

          if (batch) {
            sendEvent({ type: 'progress', batch });
            
            if (batch.status === 'completed' || batch.status === 'failed') {
              sendEvent({ type: 'complete', batch });
              if (intervalId) clearInterval(intervalId);
              controller.close();
            }
          }
        } catch (error) {
          console.error('SSE fetch error:', error);
        }
      };

      fetchAndSend();
      intervalId = setInterval(fetchAndSend, 2000);
    },
    cancel() {
      if (intervalId) clearInterval(intervalId);
    },
  });

  return new NextResponse(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    },
  });
}