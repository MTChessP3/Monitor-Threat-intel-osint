<<<<<<< HEAD
# VIP_Protection Report - Executive Intelligence System

Sistema de Inteligencia Ejecutiva para la generacion de informes de proteccion VIP con analisis de amenazas basado en IA y fuentes OSINT.

## Funcionalidades

- **Plantillas de Informes**: Suba documentos oficiales como plantillas que el sistema llena automaticamente
- **Fuentes OSINT**: Configure fuentes de inteligencia (noticias, ciberseguridad, etc.)
- **Analisis con IA**: Busqueda y analisis automatico de amenazas usando IA
- **Generacion de Informes**: Informes profesionales en Markdown, PDF y DOCX
- **Matriz de Amenazas**: Clasificacion por severidad, probabilidad e impacto
- **Exportacion**: Descarga en PDF y DOCX

## Stack Tecnologico

- **Frontend**: Next.js 16, React 19, TailwindCSS 4, shadcn/ui
- **Backend**: Next.js API Routes (serverless)
- **Base de Datos**: SQLite (local) / Turso libSQL (Vercel) via Prisma
- **ORM**: Prisma
- **IA**: z-ai-web-dev-sdk (busqueda web + chat completions)
- **Export**: pdf-lib (PDF), docx (DOCX)

## Deploy en Vercel

### Prerequisitos

1. Cuenta en [GitHub](https://github.com)
2. Cuenta en [Vercel](https://vercel.com)
3. Clonar este repositorio

### Paso 1: Configurar Base de Datos (Turso/libSQL)

> **IMPORTANTE**: En Vercel, sin una base de datos externa, la app usa SQLite en `/tmp` (efimero por instancia). Los datos se pierden entre requests e instancias, y cada redeploy borra todo. Para que los datos persistan, configura Turso (libSQL) o cualquier base SQLite remota.

1. Crea una base de datos gratis en [Turso](https://turso.tech):
   ```bash
   # Con Turso CLI
   npm i -g @libsql/client @libsql/turso 2>/dev/null || true
   npx @libsql/turso db create vip-intelligence
   npx @libsql/turso db show vip-intelligence --url
   npx @libsql/turso db create-token vip-intelligence
   ```
2. Anota la **URL** (ej: `libsql://vip-intelligence-xxx.turso.io`) y el **token** generado.
3. En el Dashboard de Vercel, ve a **Storage** > **Create Database** > elige **Turso** (o configura manualmente las variables) y crea la base.
4. Vercel generara las variables de entorno `TURSO_DATABASE_URL` y `TURSO_AUTH_TOKEN`.

> **Nota**: El codigo (`src/lib/db.ts`) usa Turso solo si `TURSO_DATABASE_URL` esta definido. Sin esa variable, cae a SQLite `/tmp` en Vercel (no persistente) o a SQLite local en desarrollo.

### Paso 2: Configurar Variables de Entorno

En **Settings** > **Environment Variables**, agrega:

| Variable | Descripcion | Ejemplo |
|----------|-------------|---------|
| `TURSO_DATABASE_URL` | URL de conexion Turso/libSQL (persistente) | `libsql://vip-intelligence-xxx.turso.io` |
| `TURSO_AUTH_TOKEN` | Token de autenticacion de Turso | Tu token |
| `ZAI_BASE_URL` | URL base de la API publica de Z.AI | `https://api.z.ai/api/paas/v4` |
| `ZAI_API_KEY` | API Key de Z.AI (https://z.ai/manage-apikey/apikey-list) | Tu API key |
| `ZAI_MODEL` | (Opcional) Modelo para chat/analisis | `glm-4.5-flash` |

### Paso 3: Deploy

1. En Vercel, haz click en **Add New** > **Project**
2. Importa el repositorio de GitHub
3. Vercel detectara automaticamente Next.js
4. Asegurate de que las variables de entorno esten configuradas
5. Haz click en **Deploy**

### Paso 4: Seed de Datos Iniciales

Despues del deploy, ejecuta el seed para crear las fuentes de inteligencia y la plantilla predeterminada:

```bash
# Usando Vercel CLI
vercel env pull .env.local
npx prisma generate
npx prisma db seed
```

O manualmente desde el dashboard de Turso (consola SQL).

## Solucion de Problemas

### 1. Los datos desaparecen / errores "table does not exist" en produccion

**Sintoma**: Usuarios, ejecutivos o informes se crean pero luego no aparecen; ocasionalmente errores 500 `The table "main.Executive" does not exist`.

**Causa**: Sin `TURSO_DATABASE_URL`, Vercel usa SQLite en `/tmp`, que es efimero y unico por instancia serverless. Cada request puede caer en una instancia distinta con una base vacia.

**Solucion**: Configurar `TURSO_DATABASE_URL` + `TURSO_AUTH_TOKEN` (ver Paso 1). La app crea las tablas automaticamente en Turso al recibir el primer request, asi que no requiere pasos manuales adicionales. (Opcional: aplicar el schema manualmente con `npx prisma db push` apuntando a la URL de Turso.)

### 2. La busqueda web (OSINT/metasearch) no devuelve resultados en produccion

**Sintoma**: `/api/metasearch` responde 200 pero con `resultCount: 0`, `status: "failed"` ("No se obtuvieron resultados").

**Causa raiz (historica)**: La integracion original apuntaba a `https://internal-api.z.ai/v1`. Ese host es un balanceador INTERNO de Alibaba Cloud (cn-hongkong) con IPs privadas RFC1918 (`172.25.x.x`); NO es alcanzable desde Vercel ni desde internet publico. Cada llamada desde Vercel se colgaba ~10s y terminaba con `fetch failed` (o vacio, por el wrapper de timeouts). Ninguna configuracion de credenciales puede arreglarlo: el endpoint no es publico.

**Estado actual**: La busqueda web ahora es GRATIS y no requiere API key: usa scraping de DuckDuckGo (`html.duckduckgo.com`), que soporta los operadores `filetype:` y `site:`. El endpoint `/web_search` de Z.AI es de pago (error 1113 "Insufficient balance") y queda descartado salvo que recargues saldo en https://z.ai/manage-apikey/billing.

**Z.AI se usa solo para el chat/analisis** con el modelo gratuito `glm-4.5-flash`:
1. Crea una API key en https://z.ai/manage-apikey/apikey-list.
2. En Vercel > Settings > Environment Variables, establece `ZAI_BASE_URL=https://api.z.ai/api/paas/v4` y `ZAI_API_KEY=<tu key>` en Production, Preview y Development. Las variables antiguas (`ZAI_CHAT_ID`, `ZAI_TOKEN`, `ZAI_USER_ID`) ya no se usan y pueden eliminarse.
3. Redeplea y prueba `/api/metasearch`.

**Verificacion**: La respuesta de `/api/metasearch` incluye `zaiDiagnostics` por query (estado `ok`/`empty`/`timeout`/`error`). Si DuckDuckGo responde con un challenge anti-bot, el estado sera `error` con el detalle.

### 3. Los favicons/logos redirigen a /auth/login

**Sintoma**: En el navegador no carga el favicon ni los logos; las peticiones a `/favicon-32x32.png`, `/logo.png`, etc. devuelven 307 a `/auth/login`.

**Causa**: El middleware de autenticacion (src/middleware.ts) interceptaba todos los paths salvo una lista blanca corta.

**Solucion**: Ya corregido en `main` — el middleware ahora permite los assets publicos de `/public`. Si agregas nuevos archivos estaticos, agregalos a esa lista blanca.

## Desarrollo Local

```bash
# Clonar
git clone https://github.com/MTChessP3/vip-protection-report.git
cd vip-protection-report

# Instalar dependencias
npm install

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus valores

# Crear base de datos y aplicar migraciones
npx prisma migrate dev

# Seed de datos iniciales
npm run db:seed

# Iniciar servidor de desarrollo
npm run dev
```

## Estructura del Proyecto

```
src/
  app/
    page.tsx              # Dashboard principal
    api/
      ai-operation/       # API de operaciones IA (analisis, generacion, actualizacion)
      templates/          # CRUD de plantillas
      sources/            # CRUD de fuentes OSINT
      reports/            # CRUD de informes
      generate-report/    # Guardar informe generado
      update-report/      # Actualizar informe existente
      export-pdf/         # Exportar a PDF
      export-docx/        # Exportar a DOCX
      upload-template/    # Subir plantilla (PDF, DOCX, TXT, MD)
  lib/
    db.ts                 # Prisma client
    ai.ts                 # Helper de IA (scripts externos)
    pdf-export.ts         # Generacion de PDF
prisma/
  schema.prisma           # Esquema de base de datos
  seed.ts                 # Datos iniciales (fuentes + plantilla)
  migrations/             # Migraciones SQL
scripts/
  analyze.js              # Script de analisis de inteligencia
  generate-report.js      # Script de generacion de informes
  update-report.js        # Script de actualizacion de informes
```

## Licencia

Privado - Todos los derechos reservados.
=======
# 🛡️ NEXUS INTEL - OSINT & Threat Intelligence Platform

<p align="center">
  <img src="https://img.shields.io/badge/Next.js-16-black?style=flat-square&logo=next.js" alt="Next.js">
  <img src="https://img.shields.io/badge/React-19-black?style=flat-square&logo=react" alt="React">
  <img src="https://img.shields.io/badge/TypeScript-5-black?style=flat-square&logo=typescript" alt="TypeScript">
  <img src="https://img.shields.io/badge/Tailwind_CSS-4-black?style=flat-square&logo=tailwindcss" alt="Tailwind CSS">
  <img src="https://img.shields.io/badge/shadcn%2FUI-latest-black?style=flat-square" alt="shadcn/ui">
</p>

<p align="center">
  <strong>Plataforma profesional de Inteligencia de Amenazas y OSINT</strong><br>
  Análisis de IPs, Dominios, CVEs, URLs, Hashes y más con resultados en tiempo real
</p>

---

## ✨ Características Principales

### 🔍 **Módulos de Análisis**

| Módulo | Descripción | API Utilizada |
|--------|-------------|---------------|
| **IP Intelligence** | Geolocalización, detección proxy/VPN, threat scoring | ip-api.com |
| **Domain Analysis** | WHOIS, DNS records, reputación, seguridad | DNS Lookup |
| **CVE Database** | Búsqueda de vulnerabilidades NIST NVD | NVD API v2.0 |
| **URL Analyzer** | Detección phishing, typosquatting, SSL | Heuristics Engine |
| **Hash Lookup** | Análisis malware multi-engine | VirusTotal/MalwareBazaar style |

### 📊 **Inteligencia de Amenazas**

- **IOC Feed** en tiempo real (IPs, dominios, URLs, hashes, emails)
- **Alertas activas** clasificadas por severidad
- **Campañas APT** monitoreadas
- **Nivel de amenaza global** calculado
- **Grupos APT** perfilados (APT28, APT29, Lazarus, FIN7, etc.)

### 📄 **Informes Ejecutivos**

- **Threat Assessment Report** - Análisis completo del landscape
- **Incident Response Report** - Post-incidente
- **Intel Briefing** - Resumen diario/semanal
- **Executive Summary** - Métricas para C-level

### 👁️ **Monitoreo Especializado**

- **Live Feed** de eventos de seguridad
- **Dark Web Monitoring** (brechas, credenciales, marketplaces)
- **Estado del sistema** en tiempo real

---

## 🚀 Despliegue Rápido

### Opción 1: Vercel (Recomendado)

```bash
# 1. Clonar el repositorio
git clone <tu-repo-url>
cd nexus-intel

# 2. Instalar dependencias
npm install

# 3. Desplegar en Vercel
npx vercel --prod
```

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=<tu-repo-url>)

### Opción 2: GitHub + Vercel Automático

1. **Push** este repositorio a GitHub
2. Ve a [vercel.com/new](https://vercel.com/new)
3. Importa el repositorio
4. Añade las variables de entorno (ver sección Configuración)
5. ¡Listo! Vercel despliega automáticamente en cada push

### Opción 3: Local

```bash
# Instalar
bun install        # o: npm install

# Desarrollo
npm run dev

# Producción
npm run build && npm start
```

Abre [http://localhost:3000](http://localhost:3000)

---

## 📁 Estructura del Proyecto

```
src/
├── app/
│   ├── api/osint/        # APIs RESTful
│   │   ├── ip/           # IP Intelligence (ip-api.com)
│   │   ├── domain/       # Domain/DNS (Google DoH + RDAP)
│   │   ├── url/          # URL Scanner
│   │   ├── hash/         # Malware Hash (MalwareBazaar/VT)
│   │   ├── cve/          # CVE/NVD Search
│   │   ├── threats/      # Threat Feeds (CISA, Abuse.ch)
│   │   ├── darkweb/      # Dark Web Intel
│   │   ├── mobile/       # Mobile Security
│   │   ├── forensics/    # Domain Forensics
│   │   ├── ai/           # AI Analyst (Groq)
│   │   ├── iocs/         # IOC Manager (persistente)
│   │   ├── sources/      # Intelligence Sources CRUD
│   │   ├── export/       # Export JSON/CSV/STIX 2.1
│   │   └── reports/      # Report Generator
│   ├── page.tsx          # Dashboard Principal
│   ├── layout.tsx        # Layout raíz
│   └── globals.css       # Estilos globales
└── lib/
    ├── kv.ts             # Persistencia Vercel KV (+ fallback memoria)
    ├── store.ts          # Store de IOCs/análisis/alertas
    ├── sources.ts        # Registro de fuentes de inteligencia
    ├── intel/            # Motor de enriquecimiento compartido
    ├── agents/           # Agentes (enrichment/analysis/reporter)
    └── ai.ts             # Cliente IA OpenAI-compatible (Groq)
```

---

## 🎯 Guía de Uso Rápido

### Analizar una IP
1. Ve a la pestaña **"IP Intel"**
2. Ingresa: `8.8.8.8` o `1.1.1.1`
3. Click **"Analyze"**
4. Obtén geolocalización, ISP, threat score

### Buscar Vulnerabilidades
1. Ve a la pestaña **"CVE"**
2. Busca: `CVE-2024-1234` o `ransomware`
3. Ver CVSS scores, CWE, referencias

### Generar Informe Ejecutivo
1. Ve a la pestaña **"Reports"**
2. Click **"Threat Assessment"**
3. Espera generación automática
4. Exporta PDF

### Monitorear IOCs
1. Ve a **"Threats"**
2. Feed en tiempo actualizado
3. Filtra por tipo (ip, domain, hash)
4. Click **"Refresh"** para actualizar

---

## 🔧 Configuración

### Variables de Entorno

Copia `.env.example` a `.env` y completa los valores. **La plataforma funciona sin ninguna
clave** — IA y persistencia usan modos de respaldo claramente etiquetados — pero para
funcionalidad completa configura:

```env
# ===== IA (OpenAI-compatible, por defecto Groq) =====
# Clave gratuita: https://console.groq.com/keys
GROQ_API_KEY=            # O AI_API_KEY
AI_BASE_URL=https://api.groq.com/openai/v1
AI_MODEL=llama-3.3-70b-versatile
AI_TEMPERATURE=0.3
AI_MAX_TOKENS=2000

# ===== Persistencia (Vercel KV / Upstash Redis) =====
# Crea un store KV en el dashboard de Vercel (se inyecta automáticamente) o Upstash.
KV_REST_API_URL=
KV_REST_API_TOKEN=

# ===== Fuentes opcionales =====
NVD_API_KEY=             # https://nvd.nist.gov/developers/request-an-api-key
VIRUSTOTAL_API_KEY=      # https://www.virustotal.com/gui/my-apikey
```

> **En Vercel**: añade `GROQ_API_KEY`, `KV_REST_API_URL`, `KV_REST_API_TOKEN`
> (y opcionalmente `NVD_API_KEY`, `VIRUSTOTAL_API_KEY`) en **Settings → Environment Variables**.

### APIs Externas Utilizadas

| Servicio | Uso | Costo |
|----------|-----|-------|
| ip-api.com | Geolocalización IP | Gratis (45 req/min) |
| Google DoH + RDAP | DNS records + WHOIS | Gratis |
| NIST NVD | Base CVEs | Gratis (mejor con key) |
| MalwareBazaar (Abuse.ch) | Hashes de malware | Gratis |
| CISA KEV / Abuse.ch SSLBL | Feeds de amenazas | Gratis |
| Groq (Llama 3.3) | Análisis IA, resúmenes, agentes | Gratis con key |
| VirusTotal | Reputación de hashes | Opcional con key |

### Registro de fuentes

La pestaña **Intelligence Sources** permite listar, probar (connectivity check),
activar/desactivar y **añadir fuentes personalizadas** (GET/POST con API key opcional).
Las fuentes built-in se siembran automáticamente y no pueden borrarse.

---

## 🧪 Pruebas

```bash
# 1. Levanta el servidor de desarrollo
bun run dev        # o: npm run dev

# 2. En otra terminal, ejecuta la suite de tests de API
node tests/api-tests.mjs
```

Los 29 tests cubren todos los módulos (IP, Domain, URL, Hash, CVE, Threat Feeds,
Dark Web, AI, IOC CRUD, Export JSON/CSV/STIX, Reports, Sources, Forensics, Mobile).
Ver `TESTING.md` para el checklist manual y los comandos CI (`tsc`, `lint`, `build`).

---

## 🎨 Diseño UI

- **Tema**: Oscuro profesional (Dark Mode)
- **Framework**: shadcn/ui + Tailwind CSS 4
- **Responsive**: Mobile-first design
- **Componentes**: Accesibles (ARIA compliant)
- **Animaciones**: Transiciones suaves Framer Motion

---

## 📈 Roadmap

- [x] Persistencia de IOCs, análisis y reportes (Vercel KV)
- [x] Agentes de IA (enrichment, analysis, reporter) con Groq
- [x] Registro de fuentes de inteligencia personalizadas
- [x] Exportación STIX 2.1 de IOCs
- [x] Historial de reportes generados
- [ ] Alertas por email/SMS/Webhook
- [ ] Safe Browsing API para verificación de URLs
- [ ] YARA rules generator
- [ ] MISP integration
- [ ] Multi-tenant support
- [ ] SSO / LDAP auth

---

## 🤝 Contribuir

1. Fork el repositorio
2. Crear rama feature (`git checkout -b feature/amazing`)
3. Commit cambios (`git commit -m 'Add amazing feature'`)
4. Push a la rama (`git push origin feature/amazing`)
5. Abrir Pull Request

---

## 📄 Licencia

MIT License - Libre para uso personal y comercial

---

## ⚡ Stack Tecnológico

- **Frontend**: Next.js 16, React 19, TypeScript 5
- **Estilos**: Tailwind CSS 4, shadcn/ui
- **APIs**: Next.js Route Handlers
- **Icons**: Lucide React
- **Deploy**: Vercel (recomendado)

---

<div align="center">

**🛡️ NEXUS INTEL** - Plataforma OSINT & Threat Intelligence Profesional

*Hecho con ❤️ para la comunidad de ciberseguridad*

</div>
>>>>>>> 50e5c38fb5b2a482b6f45bd773eecb02f4a5bdac
