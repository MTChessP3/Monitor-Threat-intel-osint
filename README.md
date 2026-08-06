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
| `ZAI_MODEL` | (Opcional) Modelo para chat/analisis | `glm-5.2` |

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

**Causa raiz**: La integracion original apuntaba a `https://internal-api.z.ai/v1`. Ese host es un balanceador INTERNO de Alibaba Cloud (cn-hongkong) con IPs privadas RFC1918 (`172.25.x.x`); NO es alcanzable desde Vercel ni desde internet publico. Cada llamada desde Vercel se colgaba ~10s y terminaba con `fetch failed` (o vacio, por el wrapper de timeouts). Ninguna configuracion de credenciales puede arreglarlo: el endpoint no es publico.

**Solucion**: Usar la API publica de Z.AI:
1. Crea una API key en https://z.ai/manage-apikey/apikey-list.
2. En Vercel > Settings > Environment Variables, establece `ZAI_BASE_URL=https://api.z.ai/api/paas/v4` y `ZAI_API_KEY=<tu key>` en Production, Preview y Development. Las variables antiguas (`ZAI_CHAT_ID`, `ZAI_TOKEN`, `ZAI_USER_ID`) ya no se usan y pueden eliminarse.
3. Redeplea y prueba `/api/metasearch`.

**Verificacion**: La respuesta de `/api/metasearch` incluye `zaiDebug` (si la config esta activa) y `zaiDiagnostics` por query (estado `ok`/`empty`/`timeout`/`error` con el mensaje HTTP exacto).

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
