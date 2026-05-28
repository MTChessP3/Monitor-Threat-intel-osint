import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  // Check if default template already exists
  const existing = await prisma.reportTemplate.findFirst({
    where: { isDefault: true },
  });

  if (!existing) {
    await prisma.reportTemplate.create({
      data: {
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
    console.log('Default template created');
  } else {
    console.log('Default template already exists');
  }

  // Add some default news sources
  const sourceCount = await prisma.newsSource.count();
  if (sourceCount === 0) {
    await prisma.newsSource.createMany({
      data: [
        {
          name: 'BBC Mundo - Seguridad',
          url: 'https://www.bbc.com/mundo',
          type: 'web',
          category: 'seguridad',
          active: true,
        },
        {
          name: 'El País - Internacional',
          url: 'https://elpais.com/internacional/',
          type: 'web',
          category: 'politica',
          active: true,
        },
        {
          name: 'Reuters - Security',
          url: 'https://www.reuters.com/world/',
          type: 'web',
          category: 'seguridad',
          active: true,
        },
      ],
    });
    console.log('Default sources created');
  } else {
    console.log('Sources already exist');
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
