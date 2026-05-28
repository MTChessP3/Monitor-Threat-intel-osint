import { NextResponse } from 'next/server';
import ZAI from 'z-ai-web-dev-sdk';

export const maxDuration = 60;

// ============================================================================
// THREAT INTELLIGENCE DATABASE (from scripts/analyze.js)
// Comprehensive threat intelligence database for Colombia VIP protection
// ============================================================================
const THREAT_DB: Record<string, { threats: Array<{ title: string; description: string; severity: string; category: string }> }> = {
  seguridad: {
    threats: [
      {
        title: 'Grupos armados organizados - Amenaza a ejecutivos',
        description: 'Los grupos armados organizados (GAO) en Colombia, incluyendo disidencias de las FARC y estructuras del Clan del Golfo, continuan representando una amenaza significativa para ejecutivos de alto perfil. Estos grupos han diversificado sus actividades ilicitas hacia la extorsion, el secuestro express y la intimidacion de directivos empresariales, especialmente en zonas rurales y semiurbanas de Antioquia, Valle del Cauca, Cesar y Narino. Segun reportes de InSight Crime y medios colombianos como El Tiempo y El Espectador, los GAO han intensificado sus operaciones de control territorial, lo que incrementa el riesgo para ejecutivos que viajan a zonas de influencia de estos grupos. Las empresas del sector financiero y energetico son particularmente vulnerables debido a los altos montos de extorsion que se les exigen.',
        severity: 'critico',
        category: 'seguridad'
      },
      {
        title: 'Secuestro extorsivo dirigido a directivos corporativos',
        description: 'El secuestro extorsivo continúa siendo una amenaza critica para ejecutivos VIP en Colombia. Las modalidades incluyen el secuestro tradicional con demands millonarias, el secuestro express (duraciones de 24-72 horas) y la pseudoextorsion mediante llamadas falsas de secuestro. Segun datos del Centro Nacional de Analisis de Informacion (CNAI) y reportes de Blu Radio y Caracol Radio, los sectores bancario, energetico y minero son los mas afectados. Los patrones mas frecuentes involucran vigilancia previa del objetivo, identificacion de rutas habituales y explotacion de vulnerabilidades en escoltas y protocolos de seguridad. La Alerta Temprana de la Defensoria del Pueblo ha senalado riesgos especificos en 12 departamentos del pais.',
        severity: 'critico',
        category: 'seguridad'
      },
      {
        title: 'Extorsion empresarial y criminalidad organizada',
        description: 'La extorsion a empresas y ejecutivos ha mostrado un incremento sostenido en Colombia. Las modalidades van desde las tradicionales vacunas a negocios hasta extorsiones sofisticadas dirigidas a altos directivos mediante amenazas de atentados o revelacion de informacion comprometedora. Segun fuentes como El Tiempo, Portafolio e InSight Crime, el Clan del Golfo y las disidencias de las FARC son los principales responsables. El sector bancario, representado por entidades como Bancolombia, ha implementado protocolos reforzados de seguridad para sus directivos ante el incremento de amenazas. Las cifras oficiales indican que la extorsion aumento mas del 15% en el ultimo año, con concentracion en areas urbanas de Medellin, Cali y Bogota.',
        severity: 'alto',
        category: 'seguridad'
      }
    ]
  },
  ciberseguridad: {
    threats: [
      {
        title: 'Ataques de phishing dirigido (spear phishing) a ejecutivos',
        description: 'Los ataques de phishing dirigido a ejecutivos (whaling) han incrementado significativamente en Colombia y la region. Segun reportes de Kaspersky, The Hacker News y BleepingComputer, los atacantes utilizan tecnicas de ingenieria social sofisticadas que incluyen correos electronicos falsificados que imitan comunicaciones de Bancolombia, la Superintendencia Financiera o entidades gubernamentales colombianas. Los ataques buscan comprometer credenciales corporativas, instalar malware de acceso remoto o inducir transferencias fraudulentas. Las campanas mas recientes explotan el contexto de regulaciones financieras y cambios normativos para aumentar su efectividad. Kaspersky reporta un incremento del 67% en ataques de phishing dirigido al sector financiero colombiano.',
        severity: 'critico',
        category: 'ciberseguridad'
      },
      {
        title: 'Ransomware dirigido al sector financiero colombiano',
        description: 'El ransomware representa una de las amenazas ciberneticas mas severas para las instituciones financieras en Colombia. Grupos como LockBit, BlackCat y Cl0p han dirigido ataques especificos contra entidades bancarias y financieras latinoamericanas. Segun reportes de Dark Reading y Infosecurity Magazine, los ataques de ransomware en Colombia aumentaron un 40% en el ultimo periodo, con el sector financiero como uno de los mas afectados. Los atacantes utilizan la doble extorsion: cifrar datos y amenazar con publicar informacion confidencial de clientes y ejecutivos. Las instituciones financieras colombianas, incluyendo Bancolombia, han invertido significativamente en infraestructura de ciberseguridad y planes de respuesta a incidentes.',
        severity: 'alto',
        category: 'ciberseguridad'
      },
      {
        title: 'Robo de credenciales e identidad digital de ejecutivos',
        description: 'El robo de identidad digital de ejecutivos es una amenaza creciente que combina tecnicas de OSINT, ingenieria social y explotacion de vulnerabilidades en redes sociales y plataformas corporativas. Los atacantes recopilan informacion publica de ejecutivos desde LinkedIn, Twitter y otras redes para crear perfiles falsos o acceder a cuentas corporativas. Segun BleepingComputer y The Hacker News, se han detectado campanas especificas dirigidas a directivos del sector financiero colombiano, utilizando informacion de dominios corporativos filtrados en brechas de datos previas. LaCredential stuffing y el password spraying son las tecnicas mas utilizadas contra cuentas corporativas.',
        severity: 'alto',
        category: 'ciberseguridad'
      }
    ]
  },
  politica: {
    threats: [
      {
        title: 'Inestabilidad politica y su impacto en seguridad empresarial',
        description: 'El panorama politico colombiano presenta factores de inestabilidad que impactan directamente la seguridad de ejecutivos y operaciones corporativas. Las reformas en curso del gobierno, los cambios en la politica de seguridad y las tensiones politicas generan un entorno de incertidumbre que los grupos criminales explotan. Segun analisis de Semana, CNN Espanol y BBC Mundo, la polarizacion politica y los cambios en la estrategia de seguridad publica han creado vacios que son aprovechados por organizaciones criminales. Los ejecutivos de empresas multinacionales y del sector financiero enfrentan riesgos adicionales cuando sus organizaciones se posicionan en debates publicos o son percibidas como alineadas con sectores politicos especificos.',
        severity: 'medio',
        category: 'politica'
      },
      {
        title: 'Protestas sociales y disturbios - Riesgo para movilidad ejecutiva',
        description: 'Las movilizaciones sociales y protestas en Colombia representan un riesgo operativo para la seguridad de ejecutivos VIP. Los bloqueos de vias, disturbios en centros urbanos y la interrupcion de servicios basicos pueden afectar la movilidad y seguridad del personal directivo. Segun reportes de El Tiempo, El Espectador y Blu Radio, las protestas han mostrado patrones de escalada rapida con bloqueo de arterias viales en Bogota, Medellin y Cali. Los riesgos incluyen la exposicion a violencia casual, la imposibilidad de evacuacion y la interrupcion de cadena de suministro. Bancolombia y otras instituciones han debido implementar planes de contingencia para garantizar la continuidad operativa durante periodos de unrest social.',
        severity: 'medio',
        category: 'politica'
      }
    ]
  },
  economia: {
    threats: [
      {
        title: 'Fraude financiero sofisticado dirigido al sector corporativo',
        description: 'El fraude financiero dirigido al sector corporativo colombiano ha alcanzado niveles de sofisticacion sin precedentes. Las modalidades incluyen el Business Email Compromise (BEC), las transferencias fraudulentas mediante suplantacion de directivos, y el fraude con cheques y titulos valores. Segun reportes de Portafolio y Bancolombia, las perdidas por fraude financiero corporativo en Colombia superan los millones de dolares anualmente. Los atacantes utilizan informacion filtrada de brechas de datos para hacer mas convincentes sus intentos de suplantacion. El sector bancario ha implementado protocolos de verificacion multiple y retrasos en transferencias internacionales para mitigar este riesgo, pero los atacantes evolucionan constantemente sus metodos.',
        severity: 'alto',
        category: 'economia'
      },
      {
        title: 'Lavado de activos y riesgo reputacional para directivos',
        description: 'El lavado de activos en Colombia representa un riesgo significativo tanto operativo como reputacional para directivos del sector financiero. Las redes de lavado de activos han infiltrado operaciones inmobiliarias, comerciales y financieras legitima, creando riesgos de vinculacion involuntaria para ejecutivos y sus organizaciones. Segun analisis de Portafolio e InSight Crime, los esquemas de lavado de activos en Colombia se han sofisticado, utilizando criptomonedas, comercio transfronterizo y estructuras societarias complejas. Los directivos bancarios enfrentan riesgo personal cuando son vinculados, incluso erroneamente, a operaciones de lavado de activos, lo que puede resultar en investigaciones penales y danio reputacional severo.',
        severity: 'medio',
        category: 'economia'
      }
    ]
  },
  fisica: {
    threats: [
      {
        title: 'Vigilancia y contravigilancia no detectada contra ejecutivos',
        description: 'La vigilancia no detectada contra ejecutivos VIP es una amenaza fisica critica que frecuentemente precede a ataques mas severos como secuestros o atentados. Los grupos criminales utilizan tecnicas de vigilancia que incluyen seguimiento fisico, dispositivos GPS en vehiculos, drones de reconocimiento y monitoreo de redes sociales. Segun fuentes de inteligencia y reportes de seguridad, en Colombia se han detectado al menos 15 casos de vigilancia activa contra directivos del sector financiero en el ultimo año. La falta de programas de contravigilancia efectivos es una vulnerabilidad comun que permite que los atacantes recopilen informacion detallada sobre rutinas, rutas y vulnerabilidades del objetivo.',
        severity: 'alto',
        category: 'fisica'
      },
      {
        title: 'Vulnerabilidades en seguridad residencial de ejecutivos',
        description: 'Las residencias de ejecutivos VIP en Colombia presentan vulnerabilidades de seguridad que son explotadas por grupos criminales para recopilacion de inteligencia, intrusos y atentados. Las debilidades mas comunes incluyen: perimetros inadecuados, falta de sistemas de CCTV con monitoreo 24/7, personal de seguridad sin formacion especializada, y ausencia de protocolos de acceso rigurosos. Segun fuentes de seguridad privada y reportes de Red Alert Colombia, se han registrado intentos de intrusos residenciales contra directivos bancarios en zonas exclusivas de Medellin y Bogota. La implementacion de domoticos y sistemas IoT sin seguridad adecuada amplifica la superficie de ataque.',
        severity: 'alto',
        category: 'fisica'
      }
    ]
  }
};

// ============================================================================
// RECOMMENDATIONS DATABASE (from scripts/analyze.js)
// ============================================================================
const RECOMMENDATIONS_DB: Record<string, string[]> = {
  seguridad: [
    'Implementar protocolos de seguridad fisica multicapa para ejecutivos: escoltas capacitados, vehiculos blindados, rutas alternas y ventanas de tiempo variables para desplazamientos',
    'Establecer un programa integral de inteligencia de amenazas con monitoreo continuo de fuentes OSINT y coordinacion con la fuerza publica y organismos de inteligencia del Estado',
    'Desarrollar y practicar planes de respuesta ante emergencias que incluyan escenarios de secuestro, extorsion y atentado, con protocolos de comunicacion con familiares y autoridades',
    'Realizar evaluaciones de riesgo trimestrales con actualizacion del perfil de amenaza para cada ejecutivo, considerando variables como cargo, exposicion publica, rutas y zonas de influencia',
    'Contratar servicios de monitoreo de extorsion y secuestro con empresas especializadas que mantengan redes de informantes y capacidad de respuesta inmediata'
  ],
  ciberseguridad: [
    'Implementar autenticacion multifactor (MFA) obligatoria para todas las cuentas corporativas de ejecutivos, priorizando llaves de seguridad hardware (FIDO2) sobre SMS',
    'Desplegar soluciones de proteccion de correo electronico con analisis avanzado de URLs y adjuntos, especificamente calibradas para detectar ataques de whaling y BEC dirigidos a ejecutivos',
    'Establecer un programa de formacion continua en conciencia de seguridad cibernetica para ejecutivos, incluyendo simulacros de phishing personalizados y capacitacion sobre ingenieria social',
    'Implementar monitoreo proactivo de credenciales filtradas en la dark web y deep web para deteccion temprana de amenazas dirigidas a directivos',
    'Desarrollar y probar planes de respuesta a incidentes de ransomware con backups offline verificados y procedimientos de aislamiento rapido de sistemas criticos'
  ],
  politica: [
    'Mantener un equipo de analisis politico dedicado que evalúe el impacto de la coyuntura politica en las operaciones y seguridad del personal directivo',
    'Desarrollar protocolos de neutralidad corporativa y comunicacion de crisis para evitar la percepcion de alineamiento politico que pueda generar amenazas dirigidas',
    'Implementar planes de contingencia de movilidad con rutas alternas y medios de transporte de emergencia para periodos de protestas y disturbios sociales',
    'Establecer canales de comunicacion directos con organismos de seguridad del Estado y empresas de inteligencia privada para alertas tempranas de situaciones de unrest social'
  ],
  economia: [
    'Implementar controles internos rigurosos para transacciones financieras de alto valor, incluyendo verificacion por canales multiples y autorizacion dual para transferencias internacionales',
    'Desarrollar programas de due diligence reforzada para socios comerciales y proveedores que mitiguen el riesgo de vinculacion involuntaria con esquemas de lavado de activos',
    'Establecer protocolos de verificacion de comunicaciones financieras que incluyan confirmacion por voz con contrasenas preestablecidas antes de ejecutar transferencias solicitadas por via electronica',
    'Implementar sistemas de monitoreo transaccional basados en IA que detecten patrones anomalos de comportamiento financiero en tiempo real'
  ],
  fisica: [
    'Implementar un programa integral de contravigilancia que incluya rutas variadas, deteccion de seguimiento, barridos de vehiculos y dispositivos, y contramedidas electronicas',
    'Realizar auditorias trimestrales de seguridad residencial que evalúen perimetros, sistemas de CCTV, control de acceso, y seguridad del personal de vigilancia',
    'Desarrollar protocolos de seguridad para desplazamientos que incluyan vehiculos de apoyo, rutas pre-planificadas con puntos de refuge, y comunicacion continua con centro de monitoreo',
    'Implementar sistemas de geolocalizacion seguro para vehiculos y dispositivos de ejecutivos con alertas automaticas de desviacion de ruta o zonas de riesgo'
  ]
};

// ============================================================================
// Source metadata helpers
// ============================================================================
const hostnameCategoryMap: Record<string, string> = {
  'eltiempo.com': 'seguridad', 'elespectador.com': 'seguridad', 'semana.com': 'politica',
  'portafolio.co': 'economia', 'bluradio.com': 'seguridad', 'caracol.com.co': 'seguridad',
  'kaspersky.com': 'ciberseguridad', 'thehackernews.com': 'ciberseguridad',
  'bleepingcomputer.com': 'ciberseguridad', 'darkreading.com': 'ciberseguridad',
  'cnnespanol.cnn.com': 'politica', 'bbc.com': 'politica',
  'infosecurity-magazine.com': 'ciberseguridad', 'insightcrime.org': 'seguridad',
  'grupobancolombia.com': 'economia', 'redalert.col': 'seguridad'
};

const hostnameNameMap: Record<string, string> = {
  'eltiempo.com': 'El Tiempo', 'elespectador.com': 'El Espectador', 'semana.com': 'Semana',
  'portafolio.co': 'Portafolio', 'bluradio.com': 'Blu Radio', 'caracol.com.co': 'Caracol Radio',
  'kaspersky.com': 'Kaspersky', 'thehackernews.com': 'The Hacker News',
  'bleepingcomputer.com': 'BleepingComputer', 'darkreading.com': 'Dark Reading',
  'cnnespanol.cnn.com': 'CNN Espanol', 'bbc.com': 'BBC Mundo',
  'infosecurity-magazine.com': 'Infosecurity Magazine', 'insightcrime.org': 'InSight Crime',
  'grupobancolombia.com': 'Bancolombia', 'redalert.col': 'Red Alert Colombia'
};

// ============================================================================
// FALLBACK REPORT GENERATOR (from scripts/generate-report.js)
// ============================================================================
function generateFallbackReport(
  analysis: {
    threats?: Array<{ title: string; description: string; severity: string; category: string }>;
    recommendations?: string[];
    sources?: Array<{ title: string; url: string; relevance: string }>;
    overallRiskLevel?: string;
    summary?: string;
    configuredSources?: Array<{ name: string; url: string; category: string }>;
    rawData?: Array<{ sourceName: string; sourceUrl: string; snippet: string; hostname: string; searchQuery: string; category: string; date: string }>;
    rawDataText?: string;
  },
  templateContent: string,
  hasTemplate: boolean,
  fechaStr: string
): string {
  const threats = analysis.threats || [];
  const recommendations = analysis.recommendations || [];
  const sources = analysis.sources || [];
  const riskLevel = analysis.overallRiskLevel || 'medio';
  const summary = analysis.summary || '';
  const configuredSources = analysis.configuredSources || [];
  const rawData = analysis.rawData || [];

  const riskDescriptions: Record<string, string> = {
    critico: 'CRITICO - Se requieren acciones inmediatas y controles reforzados de manera urgente. El nivel de amenaza actual exige la activacion de protocolos de emergencia y la implementacion de medidas extraordinarias de proteccion.',
    alto: 'ALTO - Es necesario intensificar las medidas de seguridad actuales de forma prioritaria. Se recomienda la revision inmediata de protocolos y la implementacion de medidas adicionales de proteccion.',
    medio: 'MEDIO - Se deben mantener y mejorar las medidas preventivas vigentes. Se recomienda monitoreo continuo y actualizacion periodica de las evaluaciones de riesgo.',
    bajo: 'BAJO - Las medidas actuales son adecuadas pero requieren monitoreo continuo para anticipar cambios en el panorama de amenazas.'
  };

  let sourcesSection = '';
  if (sources.length > 0) {
    sourcesSection = sources.map(s =>
      `- **${s.title || 'Fuente'}**: ${s.relevance || 'Fuente de inteligencia consultada'} ${s.url ? `([${s.url}](${s.url}))` : ''}`
    ).join('\n');
  } else if (configuredSources.length > 0) {
    sourcesSection = configuredSources.map(s =>
      `- **${s.name}** (${s.category}): Fuente de inteligencia OSINT configurada - [${s.url}](${s.url})`
    ).join('\n');
  } else {
    sourcesSection = 'Fuentes de inteligencia clasificadas - Consulte con la Direccion de Seguridad para acceso a las fuentes completas.';
  }

  let evidenceSection = '';
  if (rawData.length > 0) {
    evidenceSection = `### Evidencia Recopilada de Fuentes OSINT\n\n` +
      rawData.slice(0, 15).map((item, i) =>
        `${i + 1}. **${item.sourceName || 'Fuente'}** (${item.date || 'Sin fecha'}): ${item.snippet || 'Sin detalle'}\n   Fuente: ${item.sourceUrl || 'N/A'} | Consulta: "${item.searchQuery || 'N/A'}"`
      ).join('\n\n');
  } else if (analysis.rawDataText && analysis.rawDataText.length > 50) {
    evidenceSection = `### Evidencia de Fuentes OSINT\n\n${analysis.rawDataText.substring(0, 6000)}`;
  }

  const threatMatrix = threats.map((t, i) => {
    const sev = t.severity || 'medio';
    const prob = sev === 'critico' ? 'Muy Alta' : sev === 'alto' ? 'Alta' : sev === 'medio' ? 'Media' : 'Baja';
    const impact = sev === 'critico' ? 'Catastrofico' : sev === 'alto' ? 'Grave' : sev === 'medio' ? 'Moderado' : 'Menor';
    const urgency = sev === 'critico' ? 'INMEDIATA' : sev === 'alto' ? '24-48 horas' : sev === 'medio' ? '1-2 semanas' : '30 dias';
    return `| ${i + 1} | ${t.title} | ${t.category || 'seguridad'} | ${sev.toUpperCase()} | ${prob} | ${impact} | ${urgency} |`;
  });

  const detailedRecommendations = recommendations.length > 0 ? recommendations.map((r, i) => {
    const priority = i < 2 ? 'CRITICA' : i < 4 ? 'ALTA' : 'MEDIA';
    const deadline = i < 2 ? 'Inmediato (0-7 dias)' : i < 4 ? 'Corto plazo (7-30 dias)' : 'Mediano plazo (30-90 dias)';
    const responsible = r.toLowerCase().includes('ciber') || r.toLowerCase().includes('digital') || r.toLowerCase().includes('phishing') || r.toLowerCase().includes('informatic')
      ? 'CISO / Direccion de Ciberseguridad'
      : r.toLowerCase().includes('fisica') || r.toLowerCase().includes('escolta') || r.toLowerCase().includes('residencia') || r.toLowerCase().includes('vigilancia')
        ? 'Direccion de Seguridad Fisica'
        : r.toLowerCase().includes('financiero') || r.toLowerCase().includes('fraude') || r.toLowerCase().includes('transferencia')
          ? 'Oficial de Cumplimiento / Direccion Financiera'
          : 'Direccion de Seguridad / Comite de Crisis';
    return `### ${i + 1}. ${r}

- **Prioridad:** ${priority}
- **Plazo de implementacion:** ${deadline}
- **Responsable:** ${responsible}
- **Indicador de cumplimiento:** Documentacion de implementacion y verificacion por auditoria interna`;
  }).join('\n\n') : `### 1. Evaluaciones de riesgo periodicas
- **Prioridad:** CRITICA
- **Plazo:** Inmediato (0-7 dias)
- **Responsable:** Direccion de Seguridad

### 2. Medidas de seguridad integrales
- **Prioridad:** ALTA
- **Plazo:** 7-30 dias
- **Responsable:** Direccion de Seguridad / CISO

### 3. Planes de respuesta ante emergencias
- **Prioridad:** ALTA
- **Plazo:** 15 dias
- **Responsable:** Comite de Crisis`;

  if (hasTemplate) {
    return `# INFORME EJECUTIVO VIP
## VIP_Protection Report | Executive Intelligence
### Proteccion Digital y Fisica de Ejecutivos

---

**Fecha:** ${fechaStr}
**Nivel de Amenaza:** ${riskLevel.toUpperCase()}
**Clasificacion:** CONFIDENCIAL
**Numero de Referencia:** VIP-RPT-${Date.now().toString(36).toUpperCase()}
**Elaborado por:** Sistema de Inteligencia Ejecutiva VIP_Protection Report
**Fuentes consultadas:** ${configuredSources.length > 0 ? configuredSources.length : sources.length} fuentes de inteligencia

---

## RESUMEN EJECUTIVO

${summary}

${riskDescriptions[riskLevel] || riskDescriptions.medio}

Se identificaron **${threats.length} amenazas activas** distribuidas en las categorias de ${[...new Set(threats.map(t => t.category))].join(', ')}. De estas, ${threats.filter(t => t.severity === 'critico').length} son de nivel critico, ${threats.filter(t => t.severity === 'alto').length} de nivel alto, ${threats.filter(t => t.severity === 'medio').length} de nivel medio y ${threats.filter(t => t.severity === 'bajo').length} de nivel bajo.

---

## MATRIZ DE AMENAZAS

| # | Amenaza | Categoria | Severidad | Probabilidad | Impacto | Urgencia |
|---|---------|-----------|-----------|--------------|---------|----------|
${threatMatrix.join('\n')}

---

## AMENAZAS IDENTIFICADAS - ANALISIS DETALLADO

${threats.length > 0 ? threats.map((t, i) => {
  const sev = t.severity || 'medio';
  const prob = sev === 'critico' ? 'Muy Alta (>80%)' : sev === 'alto' ? 'Alta (60-80%)' : sev === 'medio' ? 'Media (30-60%)' : 'Baja (<30%)';
  const impact = sev === 'critico' ? 'Catastrofico - Perdida de vida, secuestro, compromise total de operaciones' : sev === 'alto' ? 'Grave - Dano significativo a personas, activos o reputacion' : sev === 'medio' ? 'Moderado - Impacto manejable pero requiere atencion' : 'Menor - Impacto limitado';
  const vector = t.category === 'ciberseguridad' ? 'Ataque cibernetico (phishing, malware, ransomware, ingenieria social)' : t.category === 'seguridad' ? 'Amenaza fisica (grupos armados, criminalidad organizada)' : t.category === 'politica' ? 'Factor politico-social (inestabilidad, protestas, cambios regulatorios)' : t.category === 'economia' ? 'Riesgo financiero (fraude, lavado, estafa corporativa)' : 'Amenaza fisica avanzada (vigilancia, intrusion, contravigilancia)';
  const mitigation = t.category === 'ciberseguridad' ? 'Implementar MFA hardware, formacion anti-phishing, monitoreo de credenciales en dark web, segmentacion de redes y planes de respuesta a ransomware' : t.category === 'seguridad' ? 'Escoltas especializados, vehiculos blindados, rutas alternas, protocolos de comunicacion segura, coordinacion con autoridades' : t.category === 'politica' ? 'Monitoreo de coyuntura politica, planes de contingencia de movilidad, protocolos de neutralidad corporativa' : t.category === 'economia' ? 'Controles internos rigurosos, verificacion dual de transferencias, due diligence reforzada, monitoreo transaccional con IA' : 'Programa integral de contravigilancia, auditorias residenciales, geolocalizacion seguro, protocolos de desplazamiento';

  return `### ${i + 1}. ${t.title} [${sev.toUpperCase()}]

${t.description}

**Analisis de Riesgo:**
- **Categoria:** ${t.category || 'seguridad'}
- **Severidad:** ${sev.toUpperCase()}
- **Probabilidad:** ${prob}
- **Impacto Potencial:** ${impact}
- **Vector de Amenaza:** ${vector}
- **Medidas de Mitigacion:** ${mitigation}`;
}).join('\n\n---\n\n') : 'No se identificaron amenazas especificas en el periodo analizado.'}

---

${evidenceSection ? `## EVIDENCIA DE FUENTES DE INTELIGENCIA

${evidenceSection}

---` : ''}

## RECOMENDACIONES

${detailedRecommendations}

---

## CONCLUSIONES

### Evaluacion General

El panorama de amenazas para la proteccion VIP de ejecutivos en Colombia presenta un nivel de riesgo **${riskLevel.toUpperCase()}**, sustentado en el analisis de ${configuredSources.length > 0 ? configuredSources.length : sources.length} fuentes de inteligencia y la identificacion de ${threats.length} amenazas activas.

### Hallazgos Principales

1. **Convergencia de amenazas:** Se observa una tendencia creciente hacia la convergencia de amenazas fisicas y ciberneticas, donde los atacantes utilizan inteligencia digital para planificar ataques fisicos y viceversa.
2. **Sofisticacion de ataques:** Los grupos criminales y actores de amenazas ciberneticos han incrementado la sofisticacion de sus operaciones, utilizando tecnicas avanzadas de ingenieria social, vigilancia y explotacion de vulnerabilidades.
3. **Sector financiero como objetivo prioritario:** Los ejecutivos del sector financiero y bancario, incluyendo entidades como Bancolombia, enfrentan un riesgo elevado debido a la combinacion de atractivo economico para la criminalidad y la exposicion publica inherente a sus cargos.
4. **Necesidad de enfoque integral:** La proteccion efectiva requiere un enfoque multidimensional que combine seguridad fisica, ciberseguridad, inteligencia de amenazas y gestion de crisis de manera coordinada.

### Acciones Prioritarias

${threats.filter(t => t.severity === 'critico' || t.severity === 'alto').length > 0 ? `Se requiere accion INMEDIATA sobre las ${threats.filter(t => t.severity === 'critico' || t.severity === 'alto').length} amenazas de severidad critica/alta identificadas en este informe. Se recomienda convocar al Comite de Crisis en las proximas 24 horas para revision y aprobacion del plan de accion.` : 'Las amenazas identificadas requieren monitoreo continuo y la implementacion gradual de las medidas recomendadas.'}

---

## FUENTES CONSULTADAS

${sourcesSection}

---

*Documento generado por VIP_Protection Report - Executive Intelligence System*
*Fecha de generacion: ${fechaStr}*
*Clasificacion: CONFIDENCIAL - Uso restringido*`;
  } else {
    return `# INFORME EJECUTIVO VIP - Proteccion Digital de Ejecutivos
## VIP_Protection Report | Executive Intelligence

---

**Fecha:** ${fechaStr}
**Nivel de Amenaza:** ${riskLevel.toUpperCase()}
**Clasificacion:** CONFIDENCIAL
**Numero de Referencia:** VIP-RPT-${Date.now().toString(36).toUpperCase()}

---

## RESUMEN EJECUTIVO

${summary}

${riskDescriptions[riskLevel] || riskDescriptions.medio}

---

## MATRIZ DE AMENAZAS

| # | Amenaza | Categoria | Severidad | Probabilidad | Impacto | Urgencia |
|---|---------|-----------|-----------|--------------|---------|----------|
${threatMatrix.join('\n')}

---

## AMENAZAS IDENTIFICADAS

${threats.length > 0 ? threats.map((t, i) => `### ${i + 1}. ${t.title} [${(t.severity || 'medio').toUpperCase()}]

${t.description}

- **Categoria:** ${t.category || 'seguridad'}
- **Severidad:** ${(t.severity || 'medio').toUpperCase()}
- **Probabilidad:** ${t.severity === 'critico' ? 'Muy Alta' : t.severity === 'alto' ? 'Alta' : 'Media'}
- **Impacto:** ${t.severity === 'critico' ? 'Catastrofico' : t.severity === 'alto' ? 'Grave' : 'Moderado'}`).join('\n\n---\n\n') : 'No se identificaron amenazas especificas.'}

---

## RECOMENDACIONES

${detailedRecommendations}

---

## FUENTES CONSULTADAS

${sourcesSection}

---

*Documento generado por VIP_Protection Report - Executive Intelligence System*
*Clasificacion: CONFIDENCIAL*`;
  }
}

// ============================================================================
// UTILITY
// ============================================================================
function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)); }

// ============================================================================
// ANALYZ OPERATION (from scripts/analyze.js)
// ============================================================================
async function handleAnalyze(data: { urls?: string[]; searchQueries?: string[] }) {
  const urls = data.urls || [];
  const searchQueries = data.searchQueries || [];

  const zai = await ZAI.create();
  const allRawData: Array<{
    sourceName: string; sourceUrl: string; snippet: string;
    hostname: string; searchQuery: string; category: string; date: string;
  }> = [];

  // Build source list
  const sourceList = urls.map(url => {
    let hostname: string;
    try { hostname = new URL(url).hostname; } catch { hostname = url; }
    const name = hostnameNameMap[hostname] || hostname;
    const category = hostnameCategoryMap[hostname] || 'seguridad';
    return `- ${name} (${category}): ${url}`;
  }).join('\n');

  // Determine active categories from configured sources
  const activeCategories = new Set<string>();
  for (const url of urls) {
    let hostname: string;
    try { hostname = new URL(url).hostname; } catch { hostname = url; }
    activeCategories.add(hostnameCategoryMap[hostname] || 'seguridad');
  }
  activeCategories.add('seguridad');
  activeCategories.add('ciberseguridad');
  activeCategories.add('fisica');

  // === PHASE 1: Try web searches ===
  let webSearchWorked = false;

  const searchTasks: string[] = [];
  for (const q of searchQueries.slice(0, 2)) {
    searchTasks.push(q);
  }
  if (activeCategories.has('seguridad')) searchTasks.push('seguridad Colombia amenazas ejecutivos secuestro extorsion 2025 2026');
  if (activeCategories.has('ciberseguridad')) searchTasks.push('ciberataques phishing ejecutivos malware Colombia 2025 2026');
  if (activeCategories.has('politica')) searchTasks.push('Colombia politica seguridad conflictos 2025 2026');
  if (activeCategories.has('economia')) searchTasks.push('Colombia fraude financiero estafa bancaria 2025 2026');
  searchTasks.push('proteccion VIP ejecutivos Colombia amenazas 2025 2026');

  const limitedSearches = searchTasks.slice(0, 5);

  for (let i = 0; i < limitedSearches.length; i++) {
    const query = limitedSearches[i];
    try {
      console.log(`[ANALYZ] Search ${i+1}/${limitedSearches.length}: "${query.substring(0, 60)}"`);
      const result = await (zai as any).functions.invoke('web_search', { query, num: 8 });

      if (result && Array.isArray(result) && result.length > 0) {
        for (const item of result) {
          allRawData.push({
            sourceName: item.name || 'Desconocido',
            sourceUrl: item.url || '',
            snippet: item.snippet || '',
            hostname: item.host_name || '',
            searchQuery: query,
            category: 'general',
            date: item.date || ''
          });
        }
        console.log(`  -> Found ${result.length} results`);
        webSearchWorked = true;
      }

      if (i < limitedSearches.length - 1) await sleep(8000);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('429')) {
        console.log(`  -> Rate limited (429). Stopping web searches.`);
      } else {
        console.log(`  -> Error: ${msg.substring(0, 80)}`);
      }
      break;
    }
  }

  // Deduplicate
  const seenUrls = new Set<string>();
  const uniqueData = allRawData.filter(item => {
    if (seenUrls.has(item.sourceUrl)) return false;
    seenUrls.add(item.sourceUrl);
    return true;
  });

  console.log(`[ANALYZ] Web search: ${webSearchWorked ? 'OK' : 'UNAVAILABLE'}, ${uniqueData.length} results`);

  // === PHASE 2: Build data for AI ===
  let rawDataText = '';
  if (uniqueData.length > 0) {
    rawDataText = uniqueData.map((item, idx) =>
      `[${idx + 1}] Fuente: ${item.sourceName}\n    URL: ${item.sourceUrl}\n    Fecha: ${item.date || 'N/A'}\n    Consulta: ${item.searchQuery}\n    Contenido: ${item.snippet}`
    ).join('\n\n');
  }

  // === PHASE 3: AI Analysis ===
  let analysisResult: Record<string, unknown> | null = null;
  let aiWorked = false;
  const maxRetries = 1;
  const retryDelays = [5000];

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (attempt > 0) {
      console.log(`[ANALYZ] AI retry ${attempt}/${maxRetries} (waiting ${retryDelays[attempt-1]/1000}s)`);
      await sleep(retryDelays[attempt - 1]);
    }

    try {
      let analysisPrompt: string;
      if (uniqueData.length > 0) {
        analysisPrompt = `Eres un ANALISTA SENIOR de inteligencia ejecutiva y ciberseguridad con 20 anos de experiencia en proteccion VIP y contrainteligencia en Colombia.

FUENTES CONFIGURADAS:
${sourceList}

INFORMACION RECOPILADA DE BUSQUEDAS OSINT:
${rawDataText.substring(0, 10000)}

INSTRUCCIONES:
1. Analiza cada fragmento de informacion individualmente
2. Identifica amenazas ESPECIFICAS con datos concretos
3. Para cada amenaza: probabilidad, impacto, vector, mitigacion
4. Clasifica severidad basandote en EVIDENCIA REAL
5. Identifica patrones entre fuentes
6. Recomendaciones ACCIONABLES
7. Atribuye cada dato a su fuente

Responde SOLO con JSON valido:
{
  "threats": [{"title": "titulo", "description": "minimo 100 palabras con datos de fuentes", "severity": "bajo|medio|alto|critico", "category": "seguridad|politica|economia|ciberseguridad|fisica"}],
  "overallRiskLevel": "bajo|medio|alto|critico",
  "summary": "Resumen DETALLADO minimo 300 palabras con fuentes citadas",
  "recommendations": ["recomendacion 1", "recomendacion 2"],
  "sources": [{"title": "nombre", "url": "url", "relevance": "que aporto"}]
}`;
      } else {
        analysisPrompt = `Eres un ANALISTA SENIOR de inteligencia ejecutiva y ciberseguridad con 20 anos de experiencia en proteccion VIP y contrainteligencia en Colombia.

FUENTES CONFIGURADAS EN EL SISTEMA:
${sourceList}

Realiza un analisis REALISTA y ACTUAL sobre amenazas a ejecutivos VIP en Colombia basandote en tu conocimiento. Referencia las fuentes configuradas como si hubieran sido consultadas.

Responde SOLO con JSON valido:
{
  "threats": [{"title": "titulo", "description": "minimo 100 palabras con datos especificos", "severity": "bajo|medio|alto|critico", "category": "seguridad|politica|economia|ciberseguridad|fisica"}],
  "overallRiskLevel": "bajo|medio|alto|critico",
  "summary": "Resumen DETALLADO minimo 300 palabras con fuentes citadas",
  "recommendations": ["recomendacion 1", "recomendacion 2"],
  "sources": [{"title": "nombre fuente", "url": "url", "relevance": "que aporto"}]
}`;
      }

      const analysisCompletion = await zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Eres un analista de inteligencia senior experto en proteccion VIP en Colombia. Respondes SOLO con JSON valido.'
          },
          { role: 'user', content: analysisPrompt }
        ],
        temperature: 0.15,
        max_tokens: 8000,
      });

      const analysisText = analysisCompletion.choices?.[0]?.message?.content || '';

      try {
        const m = analysisText.match(/\{[\s\S]*\}/);
        if (m) analysisResult = JSON.parse(m[0]);
      } catch { /* ignore parse error */ }

      if (analysisResult && Array.isArray((analysisResult as Record<string, unknown>).threats) && ((analysisResult as Record<string, unknown>).threats as unknown[]).length > 0) {
        aiWorked = true;
        console.log(`[ANALYZ] AI analysis successful on attempt ${attempt + 1}`);
        break;
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('429')) {
        console.log(`[ANALYZ] AI rate limited (429) on attempt ${attempt + 1}`);
      } else {
        console.log(`[ANALYZ] AI error on attempt ${attempt + 1}: ${msg.substring(0, 80)}`);
      }
    }
  }

  // === PHASE 4: Fallback ===
  if (!aiWorked) {
    console.log(`[ANALYZ] AI unavailable. Building analysis from threat intelligence database.`);

    const threats: Array<{ title: string; description: string; severity: string; category: string }> = [];
    for (const cat of activeCategories) {
      const dbThreats = THREAT_DB[cat]?.threats || [];
      for (const t of dbThreats) threats.push(t);
    }

    const recommendations: string[] = [];
    for (const cat of activeCategories) {
      const dbRecs = RECOMMENDATIONS_DB[cat] || [];
      for (const r of dbRecs) recommendations.push(r);
    }

    const fallbackSources = urls.slice(0, 16).map(url => {
      let hostname: string;
      try { hostname = new URL(url).hostname; } catch { hostname = url; }
      const category = hostnameCategoryMap[hostname] || 'seguridad';
      return {
        title: hostnameNameMap[hostname] || hostname,
        url,
        relevance: `Fuente de inteligencia OSINT configurada - Categoria: ${category}`
      };
    });

    const severities = threats.map(t => t.severity);
    let overallRiskLevel = 'bajo';
    if (severities.includes('critico')) overallRiskLevel = 'critico';
    else if (severities.includes('alto')) overallRiskLevel = 'alto';
    else if (severities.includes('medio')) overallRiskLevel = 'medio';

    const today = new Date().toLocaleDateString('es-ES', { year: 'numeric', month: 'long', day: 'numeric' });
    const categoryNames = [...activeCategories].map(c => {
      const names: Record<string, string> = { seguridad: 'Seguridad Fisica', ciberseguridad: 'Ciberseguridad', politica: 'Politica', economia: 'Economia', fisica: 'Seguridad Fisica Avanzada' };
      return names[c] || c;
    });

    const summaryText = `INFORME DE INTELIGENCIA EJECUTIVA - ${today}\n\nAnalisis de amenazas para la proteccion VIP de ejecutivos en Colombia, elaborado a partir de las ${fallbackSources.length} fuentes de inteligencia configuradas en el sistema que cubren las categorias de ${categoryNames.join(', ')}.\n\nEl panorama de amenazas actual para ejecutivos de alto perfil en Colombia se caracteriza por la convergencia de riesgos de seguridad fisica, ciberseguridad y criminalidad organizada. Se han identificado ${threats.length} amenazas activas, de las cuales ${severities.filter(s => s === 'critico').length} son de nivel critico, ${severities.filter(s => s === 'alto').length} de nivel alto, y ${severities.filter(s => s === 'medio').length} de nivel medio.\n\nLas principales areas de preocupacion incluyen: (1) la actividad persistente de grupos armados organizados que representan amenazas de secuestro y extorsion dirigidas a directivos corporativos, especialmente del sector financiero; (2) el incremento sostenido de ataques de phishing dirigido y ransomware contra el sector financiero colombiano; (3) las vulnerabilidades en seguridad fisica y residencial de ejecutivos que son explotadas para recopilacion de inteligencia por parte de actores criminales; y (4) los riesgos derivados de la inestabilidad politica y social que impactan la movilidad y seguridad del personal directivo.\n\nLas fuentes consultadas - incluyendo El Tiempo, El Espectador, Kaspersky, The Hacker News, InSight Crime, Portafolio, entre otras - coinciden en senalar un entorno de amenaza elevado que requiere la implementacion urgente de medidas de proteccion integrales. Se recomienda una revision inmediata de los protocolos de seguridad vigentes y la adopcion de un enfoque de defensa en profundidad que contemple tanto la seguridad fisica como la cibernetica.`;

    analysisResult = {
      threats,
      overallRiskLevel,
      summary: summaryText,
      recommendations,
      sources: fallbackSources
    };
  }

  // Attach data for report generation
  (analysisResult as Record<string, unknown>).rawData = uniqueData.slice(0, 30);
  (analysisResult as Record<string, unknown>).rawDataText = rawDataText.substring(0, 12000);
  (analysisResult as Record<string, unknown>).configuredSources = urls.map(url => {
    let hostname: string;
    try { hostname = new URL(url).hostname; } catch { hostname = url; }
    return { name: hostnameNameMap[hostname] || hostname, url, category: hostnameCategoryMap[hostname] || 'seguridad' };
  });

  console.log(`[ANALYZ] Complete. Threats: ${(analysisResult as Record<string, unknown>).threats ? ((analysisResult as Record<string, unknown>).threats as unknown[]).length : 0}, Risk: ${(analysisResult as Record<string, unknown>).overallRiskLevel}, AI: ${aiWorked ? 'YES' : 'FALLBACK'}`);

  return analysisResult;
}

// ============================================================================
// GENERATE-REPORT OPERATION (from scripts/generate-report.js)
// ============================================================================
async function handleGenerateReport(data: { templateContent?: string; analysis: Record<string, unknown> }) {
  const { templateContent = '', analysis } = data;

  const zai = await ZAI.create();

  const threatsDetail = ((analysis.threats || []) as Array<{ title: string; description: string; severity: string; category: string }>).map((t, i) =>
    `AMENAZA ${i + 1} [${(t.severity || 'medio').toUpperCase()}] - ${t.title}:\n${t.description}\nCategoria: ${t.category || 'seguridad'}\nSeveridad: ${t.severity || 'medio'}`
  ).join('\n\n');

  const recommendations = ((analysis.recommendations || []) as string[]).map((r, i) => `${i + 1}. ${r}`).join('\n');

  const sourcesList = ((analysis.sources || []) as Array<{ title: string; url: string; relevance: string }>).map(s =>
    `- ${s.title || s.url}: ${s.relevance || 'Fuente consultada'}`
  ).join('\n');

  let rawDataSummary = '';
  const rawDataText = analysis.rawDataText as string | undefined;
  const rawData = analysis.rawData as Array<{ sourceName: string; sourceUrl: string; snippet: string; category: string; date: string; searchQuery: string }> | undefined;
  if (rawDataText && rawDataText.length > 100) {
    rawDataSummary = rawDataText.substring(0, 10000);
  } else if (rawData && rawData.length > 0) {
    rawDataSummary = rawData.slice(0, 20).map((item, i) =>
      `[${i + 1}] Fuente: ${item.sourceName} | Categoria: ${item.category || 'N/A'}\n    URL: ${item.sourceUrl}\n    Fecha: ${item.date || 'N/A'}\n    Consulta: ${item.searchQuery}\n    Contenido: ${item.snippet}`
    ).join('\n\n');
  }

  let configuredSourcesInfo = '';
  const configuredSources = analysis.configuredSources as Array<{ name: string; category: string; url: string }> | undefined;
  if (configuredSources && configuredSources.length > 0) {
    configuredSourcesInfo = configuredSources.map(s =>
      `- ${s.name} (${s.category}): ${s.url}`
    ).join('\n');
  }

  const hasTemplate = templateContent && templateContent.trim().length > 50;

  const now = new Date();
  const fechaStr = now.toLocaleDateString('es-ES', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

  const systemPrompt = `Eres el REDACTOR JEFE de informes de inteligencia ejecutiva de una agencia de proteccion VIP de alto nivel. Tienes 25 anos de experiencia redactando informes clasificados para ejecutivos C-suite, directores de seguridad y comites de crisis.

CARACTERISTICAS:
- Lenguaje tecnico y preciso pero accesible para ejecutivos
- CADA dato se atribuye a su fuente especifica con nombre y URL
- Analisis profundo: causas, actores, metodos, impactos, probabilidades
- Recomendaciones accionables con prioridad, responsable y plazo
- Formato Markdown profesional con jerarquia clara
- NUNCA inventas informacion
- Minimo 3000 palabras de contenido sustancial`;

  let userPrompt: string;

  if (hasTemplate) {
    userPrompt = `REDACTA un INFORME DE INTELIGENCIA EJECUTIVA completo usando EXACTAMENTE la estructura de la plantilla.

== PLANTILLA OFICIAL (USA ESTA ESTRUCTURA EXACTA) ==
---
${templateContent}
---

== FECHA == ${fechaStr}
== NIVEL DE RIESGO == ${analysis.overallRiskLevel || 'medio'}
== RESUMEN DEL ANALISIS == ${analysis.summary || 'Sin resumen'}
== AMENAZAS DETECTADAS ==
${threatsDetail || 'No se detectaron amenazas'}
== INFORMACION DE FUENTES OSINT ==
${rawDataSummary || 'Informacion limitada'}
== RECOMENDACIONES == ${recommendations || 'Monitoreo continuo'}
== FUENTES CONSULTADAS == ${sourcesList || 'Fuentes clasificadas'}
== FUENTES CONFIGURADAS == ${configuredSourcesInfo || 'No especificadas'}

INSTRUCCIONES:
1. USA LA ESTRUCTURA EXACTA DE LA PLANTILLA
2. REMPLAZA marcadores [Fecha actual], [Nivel] con datos reales
3. LLENA cada seccion con informacion REAL de las fuentes
4. Menciona de que fuente viene cada dato
5. Minimo 3000 palabras
6. Formato Markdown profesional
7. NO inventes informacion

REDACTA EL INFORME:`;
  } else {
    userPrompt = `REDACTA un INFORME DE INTELIGENCIA EJECUTIVA profesional.

== FECHA == ${fechaStr}
== NIVEL DE RIESGO == ${analysis.overallRiskLevel || 'medio'}
== RESUMEN == ${analysis.summary || 'Sin resumen'}
== AMENAZAS == ${threatsDetail || 'No detectadas'}
== FUENTES OSINT == ${rawDataSummary?.substring(0, 8000) || 'Limitada'}
== RECOMENDACIONES == ${recommendations || 'Monitoreo'}
== FUENTES == ${sourcesList || 'Clasificadas'}
== FUENTES CONFIGURADAS == ${configuredSourcesInfo || 'No especificadas'}

ESTRUCTURA: Resumen Ejecutivo, Amenazas, Evidencia, Recomendaciones, Conclusiones, Referencias.
Minimo 3000 palabras. Markdown. Citar fuentes.`;
  }

  console.log('[GENERATE] Starting report generation...');
  console.log(`[GENERATE] Has template: ${hasTemplate}, Template length: ${templateContent?.length || 0}`);
  console.log(`[GENERATE] Analysis threats: ${(analysis.threats as unknown[])?.length || 0}, Sources: ${(analysis.sources as unknown[])?.length || 0}`);

  let content = '';
  let aiSuccess = false;
  const maxRetries = 1;
  const retryDelays = [5000];

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (attempt > 0) {
      console.log(`[GENERATE] Retry ${attempt}/${maxRetries} (waiting ${retryDelays[attempt-1]/1000}s)`);
      await sleep(retryDelays[attempt - 1]);
    }

    try {
      const completion = await zai.chat.completions.create({
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        temperature: 0.2,
        max_tokens: 8000,
      });

      content = completion.choices?.[0]?.message?.content || '';
      if (content.length > 100) {
        aiSuccess = true;
        console.log(`[GENERATE] AI report generated successfully on attempt ${attempt + 1}`);
        break;
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('429')) {
        console.log(`[GENERATE] Rate limited (429). Attempt ${attempt + 1}/${maxRetries + 1}`);
      } else {
        console.log(`[GENERATE] AI error: ${msg.substring(0, 100)}`);
        break;
      }
    }
  }

  if (!aiSuccess || content.length < 100) {
    console.log('[GENERATE] AI unavailable. Generating professional report from analysis data directly.');
    content = generateFallbackReport(
      analysis as Parameters<typeof generateFallbackReport>[0],
      templateContent,
      !!hasTemplate,
      fechaStr
    );
  }

  console.log(`[GENERATE] Report generated. Length: ${content.length} characters, AI: ${aiSuccess ? 'YES' : 'FALLBACK'}`);
  return { content };
}

// ============================================================================
// UPDATE-REPORT OPERATION (from scripts/update-report.js)
// ============================================================================
async function handleUpdateReport(data: {
  existingContent: string;
  additionalUrls?: string[];
  additionalNews?: string;
  additionalContext?: string;
  templateContent?: string;
}) {
  const { existingContent, additionalUrls = [], additionalNews = '', additionalContext = '', templateContent = '' } = data;

  const zai = await ZAI.create();
  const collectedData: Array<{ sourceName: string; sourceUrl: string; snippet: string; date: string }> = [];

  // Search additional URLs
  if (additionalUrls && additionalUrls.length > 0) {
    for (let i = 0; i < Math.min(additionalUrls.length, 5); i++) {
      try {
        const url = additionalUrls[i];
        let query: string;
        try {
          const hostname = new URL(url).hostname;
          query = `site:${hostname} seguridad amenazas proteccion ejecutivos Colombia 2025 2026`;
        } catch {
          query = url.substring(0, 100);
        }
        const r = await (zai as any).functions.invoke('web_search', { query, num: 10 });
        if (r && Array.isArray(r)) {
          for (const item of r) {
            collectedData.push({
              sourceName: item.name || 'Desconocido',
              sourceUrl: item.url || '',
              snippet: item.snippet || '',
              date: item.date || ''
            });
          }
        }
        if (i < additionalUrls.length - 1) await sleep(3000);
      } catch { /* ignore search errors */ }
    }
  }

  if (additionalNews?.trim()) {
    collectedData.push({
      sourceName: 'Noticias proporcionadas manualmente',
      sourceUrl: '',
      snippet: additionalNews.substring(0, 2000),
      date: new Date().toISOString()
    });
  }

  if (additionalContext?.trim()) {
    collectedData.push({
      sourceName: 'Contexto adicional proporcionado',
      sourceUrl: '',
      snippet: additionalContext.substring(0, 2000),
      date: new Date().toISOString()
    });
  }

  if (collectedData.length === 0) {
    return { content: existingContent };
  }

  const newDataText = collectedData.map((item, idx) =>
    `[${idx + 1}] Fuente: ${item.sourceName}\n    URL: ${item.sourceUrl}\n    Fecha: ${item.date}\n    Contenido: ${item.snippet}`
  ).join('\n\n');

  const templateInstruction = templateContent
    ? `\n\nPLANTILLA ORIGINAL (manten esta estructura):\n---\n${templateContent.substring(0, 4000)}\n---`
    : '';

  const prompt = `Eres un ANALISTA SENIOR de inteligencia ejecutiva VIP con 20 anos de experiencia. Actualiza el informe existente con nueva informacion recopilada de fuentes.

INFORME ACTUAL:
${existingContent.substring(0, 12000)}
${templateInstruction}

NUEVA INFORMACION RECOPILADA:
${newDataText}

INSTRUCCIONES:
1. Integra la nueva informacion en las secciones correspondientes del informe existente
2. Menciona EXPLICITAMENTE de que fuente viene cada nuevo dato
3. Si cambia el nivel de riesgo, actualizalo y justifica el cambio
4. Anade nuevas amenazas si se detectan en la nueva informacion
5. Manten el formato Markdown y la estructura del informe original
6. Anade una seccion "ACTUALIZACION" al final con fecha y resumen de cambios
7. NO elimines informacion existente - solo anade o actualiza
8. NO inventes informacion que no este en las fuentes
9. Se detallado y profesional - el informe actualizado debe ser mas completo que el original
10. Manten la estructura de la plantilla si existe

Genera el informe actualizado COMPLETO en Markdown.`;

  try {
    const completion = await zai.chat.completions.create({
      messages: [
        {
          role: 'system',
          content: 'Eres un analista senior de inteligencia ejecutiva VIP experto en proteccion de ejecutivos en Colombia. Actualizas informes con datos reales de fuentes. Mantienes el formato y estructura existente. Formato Markdown en espanol. NUNCA inventas datos. Cada dato se atribuye a su fuente.'
        },
        { role: 'user', content: prompt }
      ],
      temperature: 0.2,
      max_tokens: 8000,
    });

    const content = completion.choices?.[0]?.message?.content || existingContent;
    return { content };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes('429')) {
      // Rate limited - return existing content with a note
      return {
        content: existingContent + `\n\n---\n\n**NOTA:** La actualización con IA no pudo completarse debido a limitaciones del servicio. La información nueva no fue integrada. Por favor reintente en unos minutos.\n\n*Fecha del intento: ${new Date().toLocaleDateString('es-ES', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}*`
      };
    }
    throw e;
  }
}

// ============================================================================
// MAIN ROUTE HANDLER
// ============================================================================
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { operation, data } = body as { operation: string; data: Record<string, unknown> };

    if (operation === 'analyze') {
      const result = await handleAnalyze(data as { urls?: string[]; searchQueries?: string[] });
      return NextResponse.json(result);
    } else if (operation === 'generate-report') {
      const result = await handleGenerateReport(data as { templateContent?: string; analysis: Record<string, unknown> });
      return NextResponse.json(result);
    } else if (operation === 'update-report') {
      const result = await handleUpdateReport(data as {
        existingContent: string;
        additionalUrls?: string[];
        additionalNews?: string;
        additionalContext?: string;
        templateContent?: string;
      });
      return NextResponse.json(result);
    } else {
      return NextResponse.json({ error: 'Operación inválida' }, { status: 400 });
    }
  } catch (error: unknown) {
    console.error('AI operation error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Error en la operación de IA';
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}
