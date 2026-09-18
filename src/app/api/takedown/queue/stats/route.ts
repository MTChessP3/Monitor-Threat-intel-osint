import { NextResponse } from 'next/server';
import { getQueueStats } from '@/lib/takedownQueue';

export const runtime = 'edge';

export async function GET() {
  try {
    const stats = await getQueueStats();
    return NextResponse.json(stats);
  } catch (error) {
    console.error('Queue stats error:', error);
    return NextResponse.json({
      waiting: 0, active: 0, completed: 0, failed: 0, delayed: 0,
    });
  }
}
