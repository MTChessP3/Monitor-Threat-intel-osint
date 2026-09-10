#!/usr/bin/env node

/**
 * TakeDown Worker - Procesa trabajos de reporte de URLs en segundo plano
 * 
 * Uso:
 *   npx tsx src/scripts/runTakedownWorker.ts
 * 
 * Variables de entorno requeridas:
 *   REDIS_HOST=localhost
 *   REDIS_PORT=6379
 *   REDIS_PASSWORD= (opcional)
 * 
 * API Keys para servicios:
 *   GOOGLE_SAFE_BROWSING_API_KEY=
 *   NETCRAFT_API_KEY=
 *   ESET_API_KEY=
 *   PHISHFORT_API_KEY=
 *   EASYDMARC_API_KEY=
 *   FORTINET_API_KEY=
 *   PHISHTANK_API_KEY=
 */

import { startWorker } from '@/lib/takedownWorker';

async function main() {
  console.log('🚀 Iniciando TakeDown Worker...');
  console.log('📋 Configuración:');
  console.log(`   Redis Host: ${process.env.REDIS_HOST || 'localhost'}`);
  console.log(`   Redis Port: ${process.env.REDIS_PORT || '6379'}`);
  console.log(`   Redis Password: ${process.env.REDIS_PASSWORD ? '***' : 'none'}`);
  console.log('');

  try {
    await startWorker();
    console.log('✅ Worker iniciado correctamente');
    console.log('👂 Escuchando trabajos en la cola "takedown-reports"...');
    console.log('⏹️  Presiona Ctrl+C para detener');
  } catch (error) {
    console.error('❌ Error iniciando worker:', error);
    process.exit(1);
  }
}

main();