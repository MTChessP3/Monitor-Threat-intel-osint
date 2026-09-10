import { Queue } from 'bullmq';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

interface TakedownJobData {
  reportId: string;
  url: string;
  service: string;
  apiKey?: string;
  notes?: string;
}

interface TakedownResult {
  url: string;
  service: string;
  status: 'success' | 'failed' | 'pending' | 'manual';
  message: string;
  referenceId?: string;
  timestamp: string;
}

// Create queue - will connect to Redis on process.env.REDIS_URL
export const takedownQueue = new Queue('takedown-reports', {
  connection: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD,
  },
  // Optional: failed retry queue
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 5000,
    },
    removeOnComplete: 50,
    removeOnFail: 100
  }
});

/**
 * Enqueue a takedown job for a single URL-service combination
 */
export async function enqueueTakedownJob(
  data: TakedownJobData
): Promise<string> {
  const job = await takedownQueue.add('process-takedown', data);
  return job.id!;
}

/**
 * Enqueue multiple takedown jobs in batch
 */
export async function enqueueTakedownBatch(
  jobs: TakedownJobData[]
): Promise<string[]> {
  const jobPromises = jobs.map(job => takedownQueue.add('process-takedown', job));
  const results = await Promise.all(jobPromises);
  return results.map(job => job.id!);
}

/**
 * Get queue statistics
 */
export async function getQueueStats() {
  const [waiting, active, completed, failed, delayed] = await Promise.all([
    takedownQueue.getWaitingCount(),
    takedownQueue.getActiveCount(),
    takedownQueue.getCompletedCount(),
    takedownQueue.getFailedCount(),
    takedownQueue.getDelayedCount(),
  ]);

  return { waiting, active, completed, failed, delayed };
}

/**
 * Pause the queue
 */
export async function pauseQueue() {
  await takedownQueue.pause();
}

/**
 * Resume the queue
 */
export async function resumeQueue() {
  await takedownQueue.resume();
}

/**
 * Clean completed/failed jobs
 */
export async function cleanQueue() {
  await takedownQueue.clean(0, 100, 'completed');
  await takedownQueue.clean(0, 100, 'failed');
}

/**
 * Close queue connection
 */
export async function closeQueue() {
  await takedownQueue.close();
}