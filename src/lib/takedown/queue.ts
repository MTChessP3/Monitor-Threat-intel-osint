import { Queue, Worker, Job, QueueEvents } from 'bullmq';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

export const takedownQueue = new Queue('takedown-processing', {
  connection: {
    url: REDIS_URL,
  },
  defaultJobOptions: {
    removeOnComplete: 100,
    removeOnFail: 50,
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 5000,
    },
  },
});

export interface TakedownJobData {
  batchId: string;
  reportId?: string;
  url: string;
  services: string[];
  notes?: string;
  apiKeys?: Record<string, string>;
  userId: string;
  priority?: number;
}

export interface BatchProcessJobData {
  batchId: string;
  userId: string;
}

const queueEvents = new QueueEvents('takedown-processing', {
  connection: { url: REDIS_URL },
});

queueEvents.on('completed', async ({ jobId, returnvalue }) => {
  console.log(`Job ${jobId} completed:`, returnvalue);
});

queueEvents.on('failed', async ({ jobId, failedReason }) => {
  console.error(`Job ${jobId} failed:`, failedReason);
});

export async function addTakedownJob(data: TakedownJobData): Promise<void> {
  await takedownQueue.add('process-url', data, {
    priority: data.priority || 0,
  });
}

export async function addBatchProcessJob(data: BatchProcessJobData): Promise<void> {
  await takedownQueue.add('process-batch', data, {
    priority: 10,
  });
}

export async function getQueueStats(): Promise<{
  waiting: number;
  active: number;
  completed: number;
  failed: number;
  delayed: number;
}> {
  const [waiting, active, completed, failed, delayed] = await Promise.all([
    takedownQueue.getWaitingCount(),
    takedownQueue.getActiveCount(),
    takedownQueue.getCompletedCount(),
    takedownQueue.getFailedCount(),
    takedownQueue.getDelayedCount(),
  ]);
  
  return { waiting, active, completed, failed, delayed };
}

export async function pauseQueue(): Promise<void> {
  await takedownQueue.pause();
}

export async function resumeQueue(): Promise<void> {
  await takedownQueue.resume();
}

export async function cleanQueue(): Promise<void> {
  await takedownQueue.clean(0, 1000, 'completed');
  await takedownQueue.clean(0, 1000, 'failed');
}

export async function retryFailedJobs(): Promise<void> {
  const failedJobs = await takedownQueue.getFailed();
  for (const job of failedJobs) {
    await job.retry();
  }
}

function createWorker(): Worker<TakedownJobData | BatchProcessJobData> {
  return new Worker(
    'takedown-processing',
    async (job: Job<TakedownJobData | BatchProcessJobData>) => {
      const { name, data } = job;
      
      if (name === 'process-url') {
        return await processUrlJob(data as TakedownJobData, job);
      } else if (name === 'process-batch') {
        return await processBatchJob(data as BatchProcessJobData, job);
      }
      
      throw new Error(`Unknown job type: ${name}`);
    },
    {
      connection: { url: REDIS_URL },
      concurrency: 5,
      limiter: {
        max: 10,
        duration: 60000,
      },
    }
  );
}

async function processUrlJob(data: TakedownJobData, job: Job): Promise<{ success: boolean; results: unknown[] }> {
  const { batchId, reportId, url, services, notes, apiKeys, userId } = data;
  
  await prisma.auditLog.create({
    data: {
      userId,
      action: 'process_url_start',
      entityType: 'report',
      entityId: reportId || batchId,
      details: JSON.stringify({ url, services }),
    },
  });

  const { reportUrlToService, storeServiceResult } = await import('./services');
  
  const results = [];
  
  for (const service of services) {
    await job.updateProgress({ 
      current: results.length + 1, 
      total: services.length, 
      service 
    });

    try {
      const result = await reportUrlToService(service, url, apiKeys, notes);
      
      await storeServiceResult(batchId, reportId, result);
      
      results.push(result);
      
      await prisma.auditLog.create({
        data: {
          userId,
          action: 'service_result',
          entityType: 'service_result',
          entityId: `${batchId}-${service}`,
          details: JSON.stringify({ service, status: result.status, message: result.message }),
        },
      });
    } catch (error) {
      const errorResult = {
        service,
        serviceName: service,
        url,
        status: 'failed' as const,
        message: error instanceof Error ? error.message : 'Error desconocido',
        errorDetails: error instanceof Error ? error.stack : String(error),
      };
      
      await storeServiceResult(batchId, reportId, errorResult);
      results.push(errorResult);
    }
  }

  const successCount = results.filter(r => r.status === 'success').length;
  const failedCount = results.filter(r => r.status === 'failed').length;
  const manualCount = results.filter(r => r.status === 'manual').length;
  const pendingCount = results.filter(r => r.status === 'pending').length;

  await prisma.takeDownReport.updateMany({
    where: { batchId, url },
    data: {
      status: failedCount === services.length ? 'failed' : 'completed',
      completedAt: new Date(),
    },
  });

  await prisma.takeDownBatch.update({
    where: { id: batchId },
    data: {
      processedUrls: { increment: 1 },
      successfulUrls: { increment: successCount > 0 ? 1 : 0 },
      failedUrls: { increment: failedCount > 0 ? 1 : 0 },
    },
  });

  await prisma.auditLog.create({
    data: {
      userId,
      action: 'process_url_complete',
      entityType: 'report',
      entityId: reportId || batchId,
      details: JSON.stringify({ 
        url, 
        total: services.length, 
        success: successCount, 
        failed: failedCount, 
        manual: manualCount,
        pending: pendingCount 
      }),
    },
  });

  return { success: failedCount !== services.length, results };
}

async function processBatchJob(data: BatchProcessJobData, job: Job): Promise<{ success: boolean; processed: number }> {
  const { batchId, userId } = data;
  
  const batch = await prisma.takeDownBatch.findUnique({
    where: { id: batchId },
    include: { reports: true },
  });

  if (!batch) {
    throw new Error(`Batch ${batchId} not found`);
  }

  await prisma.takeDownBatch.update({
    where: { id: batchId },
    data: { status: 'processing' },
  });

  await prisma.auditLog.create({
    data: {
      userId,
      action: 'batch_process_start',
      entityType: 'batch',
      entityId: batchId,
      details: JSON.stringify({ totalUrls: batch.reports.length }),
    },
  });

  let processed = 0;
  const totalReports = batch.reports.length;

  for (const report of batch.reports) {
    await job.updateProgress({ 
      current: processed + 1, 
      total: totalReports, 
      url: report.url 
    });

    await addTakedownJob({
      batchId,
      reportId: report.id,
      url: report.url,
      services: batch.reports.flatMap(r => r.serviceResults.map(sr => sr.service)),
      notes: report.notes,
      userId,
    });

    processed++;
  }

  await prisma.takeDownBatch.update({
    where: { id: batchId },
    data: { 
      status: 'completed',
      completedAt: new Date(),
    },
  });

  await prisma.auditLog.create({
    data: {
      userId,
      action: 'batch_process_complete',
      entityType: 'batch',
      entityId: batchId,
      details: JSON.stringify({ processed }),
    },
  });

  return { success: true, processed };
}

let workerInstance: Worker | null = null;

export function getWorker(): Worker {
  if (!workerInstance) {
    workerInstance = createWorker();
    
    workerInstance.on('completed', (job) => {
      console.log(`Job ${job.id} completed`);
    });
    
    workerInstance.on('failed', (job, err) => {
      console.error(`Job ${job?.id} failed:`, err);
    });
    
    workerInstance.on('error', (err) => {
      console.error('Worker error:', err);
    });
  }
  
  return workerInstance;
}

export async function shutdownWorker(): Promise<void> {
  if (workerInstance) {
    await workerInstance.close();
    workerInstance = null;
  }
  await takedownQueue.close();
  await queueEvents.close();
}