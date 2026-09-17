import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  // 1. Upsert default template
  await prisma.reportTemplate.upsert({
    where: { id: 'default-template-vip' },
    update: {},
    create: {
      id: 'default-template-vip',
      name: 'Plantilla Predeterminada - Informe VIP',
      content: `# INFORME EJECUTIVO DE PROTECCIÓN VIP

## Resumen Ejecutivo
Breve resumen de la situación actual de seguridad y las principales amenazas identificadas para la protección VIP.

## Amenazas Detectadas
Listado detallado de todas las amenazas identificadas, clasificadas por nivel de severidad:
- **Crítico**: Amenazas que requieren acción inmediata
- **Alto**: Amenazas significativas que necesitan atención prioritaria
- **Medio**: Amenazas moderadas que deben ser monitoreadas
- **Bajo**: Amenazas menores que requieren seguimiento

## Nivel de Riesgo
Evaluación integral del nivel de riesgo general basada en el análisis de todas las amenazas detectadas y factores contextuales.

## Análisis de Contexto
Información contextual relevante incluyendo:
- Situación política y social
- Indicadores económicos
- Eventos de seguridad recientes
- Tendencias de amenazas

## Recomendaciones
Recomendaciones específicas y accionables para la protección VIP:
1. Medidas de seguridad inmediatas
2. Ajustes al protocolo de protección
3. Recomendaciones de viaje y movilidad
4. Medidas de ciberseguridad
5. Coordinación con autoridades locales

## Fuentes de Inteligencia
Listado de fuentes consultadas para la elaboración de este informe.

## Conclusiones
Conclusiones finales, evaluación general y próximos pasos recomendados.`,
      isDefault: true,
    },
  });
  console.log('Default template upserted');

  // 2. Seed the 16 intelligence sources with upsert
  const sources = [
    { id: 'src-eltiempo', name: 'El Tiempo', url: 'https://www.eltiempo.com', type: 'web', category: 'seguridad', active: true },
    { id: 'src-elespectador', name: 'El Espectador', url: 'https://www.elespectador.com', type: 'web', category: 'seguridad', active: true },
    { id: 'src-semana', name: 'Semana', url: 'https://www.semana.com', type: 'web', category: 'politica', active: true },
    { id: 'src-portafolio', name: 'Portafolio', url: 'https://www.portafolio.co', type: 'web', category: 'economia', active: true },
    { id: 'src-bluradio', name: 'Blu Radio', url: 'https://www.bluradio.com', type: 'web', category: 'seguridad', active: true },
    { id: 'src-caracol', name: 'Caracol Radio', url: 'https://caracol.com.co', type: 'web', category: 'seguridad', active: true },
    { id: 'src-kaspersky', name: 'Kaspersky', url: 'https://www.kaspersky.com', type: 'web', category: 'ciberseguridad', active: true },
    { id: 'src-thehackernews', name: 'The Hacker News', url: 'https://thehackernews.com', type: 'web', category: 'ciberseguridad', active: true },
    { id: 'src-bleepingcomputer', name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com', type: 'web', category: 'ciberseguridad', active: true },
    { id: 'src-darkreading', name: 'Dark Reading', url: 'https://www.darkreading.com', type: 'web', category: 'ciberseguridad', active: true },
    { id: 'src-cnnespanol', name: 'CNN Espanol', url: 'https://cnnespanol.cnn.com', type: 'web', category: 'politica', active: true },
    { id: 'src-bbcmundo', name: 'BBC Mundo', url: 'https://www.bbc.com/mundo', type: 'web', category: 'politica', active: true },
    { id: 'src-infosecurity', name: 'Infosecurity Magazine', url: 'https://www.infosecurity-magazine.com', type: 'web', category: 'ciberseguridad', active: true },
    { id: 'src-insightcrime', name: 'InSight Crime', url: 'https://insightcrime.org', type: 'web', category: 'seguridad', active: true },
    { id: 'src-bancolombia', name: 'Bancolombia', url: 'https://www.grupobancolombia.com', type: 'web', category: 'economia', active: true },
    { id: 'src-redalert', name: 'Red Alert Colombia', url: 'https://redalert.col', type: 'web', category: 'seguridad', active: true },
  ];

  for (const source of sources) {
    await prisma.newsSource.upsert({
      where: { id: source.id },
      update: {},
      create: source,
    });
  }
  console.log(`${sources.length} intelligence sources upserted`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
