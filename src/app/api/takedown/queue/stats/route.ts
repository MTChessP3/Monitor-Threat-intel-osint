import { NextResponse } from 'next/server';
import { getQueueStats } from '@/lib/takedown/queue';

export async function GET() {
  try {
    const stats = await getQueueStats();
    return NextResponse.json(stats);
  } catch (error) {
    console.error('Error getting queue stats:', error);
    return NextResponse.json({ 
      waiting: 0, 
      active: 0, 
      completed: 0, 
      failed: 0, 
      delayed: 0 
    });
  }
}