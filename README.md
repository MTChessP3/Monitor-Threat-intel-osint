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
- **Base de Datos**: PostgreSQL (Vercel Postgres / Neon)
- **ORM**: Prisma
- **IA**: z-ai-web-dev-sdk (busqueda web + chat completions)
- **Export**: pdf-lib (PDF), docx (DOCX)

## Deploy en Vercel

### Prerequisitos

1. Cuenta en [GitHub](https://github.com)
2. Cuenta en [Vercel](https://vercel.com)
3. Clonar este repositorio

### Paso 1: Configurar Base de Datos

1. En el Dashboard de Vercel, ve a **Storage** > **Create Database** > **Postgres (Neon)**
2. Selecciona la region y crea la base de datos
3. Vercel generara las variables de entorno `POSTGRES_PRISMA_URL` y `POSTGRES_URL_NON_POOLING`

### Paso 2: Configurar Variables de Entorno

En **Settings** > **Environment Variables**, agrega:

| Variable | Descripcion | Ejemplo |
|----------|-------------|---------|
| `POSTGRES_PRISMA_URL` | URL de conexion Postgres (pooling) | Auto de Vercel |
| `POSTGRES_URL_NON_POOLING` | URL de conexion Postgres (directa) | Auto de Vercel |
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

O manualmente desde el dashboard de Neon/Postgres.

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
