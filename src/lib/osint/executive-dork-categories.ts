// ============================================================================
// Protección Digital Ejecutiva - Categorías de Dork
// ============================================================================
// 21 categorías de consultas Dork OSINT para protección digital ejecutiva
// Cada categoría incluye la plantilla de dork y metadatos para módulos imprimibles

export interface ExecutiveDorkCategory {
  id: string;
  name: string;
  shortName: string;
  icon: string;
  description: string;
  dorkTemplate: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  results: DorkResult[];
}

export interface DorkResult {
  title: string;
  url: string;
  snippet: string;
  source: string;
  position: number;
  classification: 'validated' | 'potential' | 'discarded';
}

export interface ExecutiveDorkCategoryData {
  category: ExecutiveDorkCategory;
  targetName: string;
  executedAt: string;
  totalResults: number;
}

export const EXECUTIVE_DORK_CATEGORIES: ExecutiveDorkCategory[] = [
  {
    id: 'social_media',
    name: 'Perfiles en Redes Sociales',
    shortName: 'Redes Sociales',
    icon: '📱',
    description: 'Perfiles públicos del ejecutivo en LinkedIn, Facebook, Twitter/X, Instagram, TikTok, YouTube y más',
    dorkTemplate: '"{TARGET}" (site:linkedin.com | site:facebook.com | site:twitter.com | site:x.com | site:instagram.com | site:tiktok.com | site:youtube.com | site:threads.net | site:reddit.com | site:discord.com)',
    severity: 'LOW',
    results: [],
  },
  {
    id: 'social_media_custom',
    name: 'Redes Sociales Personalizadas / Fuentes Adicionales',
    shortName: 'Redes Custom',
    icon: '🔗',
    description: 'Búsqueda en fuentes de redes sociales personalizadas adicionales configuradas para el ejecutivo',
    dorkTemplate: '"{TARGET}" (site:linkedin.com | site:facebook.com | site:instagram.com | site:tiktok.com | site:youtube.com | site:threads.net | site:whatsapp.com | site:telegram.me | site:signal.org)',
    severity: 'MEDIUM',
    results: [],
  },
  {
    id: 'developer_profiles',
    name: 'Perfiles de Desarrollador y Tecnología',
    shortName: 'Dev/Tech',
    icon: '💻',
    description: 'Perfiles técnicos en GitHub, GitLab y Stack Overflow',
    dorkTemplate: '"{TARGET}" (site:github.com | site:gitlab.com | site:stackoverflow.com)',
    severity: 'LOW',
    results: [],
  },
  {
    id: 'general_web_presence',
    name: 'Presencia Web General (Acerca de, Contacto, Perfil)',
    shortName: 'Presencia Web',
    icon: '🌐',
    description: 'Búsqueda general de páginas sobre, contacto y perfil del ejecutivo',
    dorkTemplate: '"{TARGET}" (email | username | contact | contacto)',
    severity: 'LOW',
    results: [],
  },
  {
    id: 'find_emails',
    name: 'Encontrar Correos Electrónicos y Nombres de Usuario',
    shortName: 'Emails',
    icon: '📧',
    description: 'Búsqueda de correos electrónicos y nombres de usuario asociados',
    dorkTemplate: '"{TARGET}" (email | username | contact | contacto)',
    severity: 'MEDIUM',
    results: [],
  },
  {
    id: 'find_location',
    name: 'Encontrar Ubicación e Información de Contacto',
    shortName: 'Ubicación',
    icon: '📍',
    description: 'Datos de ubicación, dirección, teléfono e información de contacto',
    dorkTemplate: '"{TARGET}" (location | address | phone | "contact info" | ubicacion | direccion | telefono | contacto)',
    severity: 'HIGH',
    results: [],
  },
  {
    id: 'academic_publications',
    name: 'Publicaciones Académicas y Profesionales (PDF)',
    shortName: 'Publicaciones',
    icon: '📄',
    description: 'Currículos, papers y portafolios en formato PDF',
    dorkTemplate: '"{TARGET}" filetype:pdf (resume | cv | "hoja de vida" | paper | publication | portfolio | publicacion)',
    severity: 'MEDIUM',
    results: [],
  },
  {
    id: 'work_history',
    name: 'Historial Laboral y Menciones a Empresas',
    shortName: 'Trabajo',
    icon: '🏢',
    description: 'Historial laboral, empleo fundado y menciones empresariales',
    dorkTemplate: '"{TARGET}" (worked at | "trabajo en" | employed by | "empleado de" | founder of | "fundador de" | CEO of | company | empresa)',
    severity: 'MEDIUM',
    results: [],
  },
  {
    id: 'images',
    name: 'Imágenes',
    shortName: 'Imágenes',
    icon: '🖼️',
    description: 'Imágenes públicas del ejecutivo en la web',
    dorkTemplate: '"{TARGET}"',
    severity: 'MEDIUM',
    results: [],
  },
  {
    id: 'news_articles',
    name: 'Noticias, Blogs y Artículos',
    shortName: 'Noticias',
    icon: '📰',
    description: 'Noticias, entrevistas, blogs y artículos que mencionan al ejecutivo',
    dorkTemplate: '"{TARGET}" (interview | entrevista | article | articulo | mentioned in | "mencionado en" | blog | post)',
    severity: 'LOW',
    results: [],
  },
  {
    id: 'public_records',
    name: 'Registros Públicos y Documentos Legales',
    shortName: 'Registros',
    icon: '⚖️',
    description: 'Registros judiciales, demandas y documentos legales',
    dorkTemplate: '"{TARGET}" (court | corte | lawsuit | demanda | case | caso | docket | filing)',
    severity: 'HIGH',
    results: [],
  },
  {
    id: 'forum_discussions',
    name: 'Foros y Discusiones de Comunidad',
    shortName: 'Foros',
    icon: '💬',
    description: 'Discusiones en foros y comunidades en línea',
    dorkTemplate: '"{TARGET}" (inurl:forum | inurl:foro | inurl:thread | inurl:hilo | "discussion" | "discusion" | "profile" | "perfil")',
    severity: 'LOW',
    results: [],
  },
  {
    id: 'data_leaks',
    name: 'Filtraciones de Datos y Sitios de Pegado',
    shortName: 'Data Leaks',
    icon: '🔓',
    description: 'Búsqueda de credenciales expuestas en Pastebin y sitios de filtración',
    dorkTemplate: '"{TARGET}" (site:pastebin.com | site:ghostbin.com | site:throwbin.io | "leak" | "breach" | "filtracion" | "base de datos")',
    severity: 'CRITICAL',
    results: [],
  },
  {
    id: 'academic_profiles',
    name: 'Perfiles Académicos y de Investigación',
    shortName: 'Académico',
    icon: '🎓',
    description: 'Perfiles en Google Scholar, ResearchGate, Academia.edu y ORCID',
    dorkTemplate: '"{TARGET}" (site:scholar.google.com | site:researchgate.net | site:academia.edu | site:orcid.org)',
    severity: 'LOW',
    results: [],
  },
  {
    id: 'company_registries',
    name: 'Registros Empresariales y Presentaciones Comerciales',
    shortName: 'Registros Empresariales',
    icon: '🏛️',
    description: 'Registros de empresas, directores, accionistas y socios',
    dorkTemplate: '"{TARGET}" (site:opencorporates.com | site:sec.gov | "director" | "shareholder" | "administrador" | "socio" | "registro mercantil")',
    severity: 'HIGH',
    results: [],
  },
  {
    id: 'usernames_handles',
    name: 'Nombres de Usuario y Handles (Búsqueda Cruzada)',
    shortName: 'Usernames',
    icon: '🆔',
    description: 'Nombres de usuario y handles para búsqueda cruzada en múltiples plataformas',
    dorkTemplate: '"{TARGET}" (intext:"@" | "username:" | "alias" | "perfil de usuario" | "user profile")',
    severity: 'MEDIUM',
    results: [],
  },
  {
    id: 'breach_databases',
    name: 'Bases de Datos de Brechas (HaveIBeenPwned, LeakLookup, Breachbase)',
    shortName: 'Brechas',
    icon: '💥',
    description: 'Verificación de credenciales expuestas en bases de datos de brechas',
    dorkTemplate: '"{TARGET}" (site:haveibeenpwned.com | site:leak-lookup.com | site:breachbase.com | site:dehashed.com | "exposed in" | "found in breach")',
    severity: 'CRITICAL',
    results: [],
  },
  {
    id: 'intelligence_search',
    name: 'Búsqueda de Inteligencia (IntelX, Shodan, ZoomEye)',
    shortName: 'Inteligencia',
    icon: '🔍',
    description: 'Búsqueda de exposiciones e inteligencia en plataformas especializadas',
    dorkTemplate: '"{TARGET}" (site:intelx.io | site:shodan.io | site:zoomeye.org | site:fofa.info | "exposed" | "indexed")',
    severity: 'HIGH',
    results: [],
  },
  {
    id: 'dark_web',
    name: 'Menciones en la Web Oscura y Sitios Onion',
    shortName: 'Dark Web',
    icon: '🌑',
    description: 'Búsqueda de menciones en la dark web, sitios onion y redes Tor',
    dorkTemplate: '"{TARGET}" (site:onion.ly | site:dark.fail | "dark web" | "darkweb" | onion | tor | .onion)',
    severity: 'CRITICAL',
    results: [],
  },
  {
    id: 'phone_address',
    name: 'Búsquedas de Teléfono y Dirección',
    shortName: 'Teléfono/Dirección',
    icon: '📞',
    description: 'Búsquedas de número de teléfono y dirección en directorios públicos',
    dorkTemplate: '"{TARGET}" (site:truecaller.com | site:whitepages.com | site:spokeo.com | site:pipl.com | phone | telefono | address)',
    severity: 'HIGH',
    results: [],
  },
  {
    id: 'deep_fake',
    name: 'Búsqueda de Deep Fakes',
    shortName: 'Deep Fake',
    icon: '🎭',
    description: 'Búsqueda de contenido de deep fake y videos manipulados',
    dorkTemplate: '"{TARGET}" ("deepfake" OR "deep fake") (filetype:mp4 OR filetype:mkv OR filetype:avi OR site:reddit.com OR site:twitter.com OR site:x.com OR site:youtube.com)',
    severity: 'CRITICAL',
    results: [],
  },
];

export function getCategoryById(id: string): ExecutiveDorkCategory | undefined {
  return EXECUTIVE_DORK_CATEGORIES.find(c => c.id === id);
}

export function getCategoriesBySeverity(severity: string): ExecutiveDorkCategory[] {
  return EXECUTIVE_DORK_CATEGORIES.filter(c => c.severity === severity);
}

export function getAllSeverities(): string[] {
  return ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
}

export function getSeverityCount(): Record<string, number> {
  return {
    LOW: EXECUTIVE_DORK_CATEGORIES.filter(c => c.severity === 'LOW').length,
    MEDIUM: EXECUTIVE_DORK_CATEGORIES.filter(c => c.severity === 'MEDIUM').length,
    HIGH: EXECUTIVE_DORK_CATEGORIES.filter(c => c.severity === 'HIGH').length,
    CRITICAL: EXECUTIVE_DORK_CATEGORIES.filter(c => c.severity === 'CRITICAL').length,
  };
}

export const SEVERITY_LABELS: Record<string, { label: string; color: string; bg: string; border: string }> = {
  LOW: { label: 'BAJO', color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20' },
  MEDIUM: { label: 'MEDIO', color: 'text-yellow-500', bg: 'bg-yellow-600/15', border: 'border-yellow-600/20' },
  HIGH: { label: 'ALTO', color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20' },
  CRITICAL: { label: 'CRÍTICO', color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' },
};
