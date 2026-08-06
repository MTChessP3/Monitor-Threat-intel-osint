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
| `ZAI_BASE_URL` | URL base del SDK de IA | `https://internal-api.z.ai/v1` |
| `ZAI_API_KEY` | API Key del SDK de IA | Tu API key |
| `ZAI_CHAT_ID` | Chat ID del SDK de IA | Tu chat ID |
| `ZAI_TOKEN` | Token del SDK de IA | Tu token |
| `ZAI_USER_ID` | User ID del SDK de IA | Tu user ID |

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

**Sintoma**: `/api/metasearch` responde 200 pero con `resultCount: 0`, `status: "failed"` ("No se obtuvieron resultados"). El chat con IA funciona, pero `web_search` devuelve vacio.

**Causa**: El SDK invoca `zai.functions.invoke('web_search', ...)`, que requiere (a) las variables `ZAI_BASE_URL` y `ZAI_API_KEY` definidas en Vercel y (b) la funcion `web_search` habilitada/asignada en la plataforma Z AI.

**Verificacion**:
1. En Vercel > Settings > Environment Variables, confirma que `ZAI_BASE_URL` y `ZAI_API_KEY` esten definidas en todos los environments (Production, Preview, Development).
2. En el dashboard/panel de Z AI, verifica que la cuenta tenga acceso a la funcion `web_search` (no solo chat completions).
3. Si faltan, agrega las variables y redeplea; luego vuelve a probar `/api/metasearch` con una query libre.

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
