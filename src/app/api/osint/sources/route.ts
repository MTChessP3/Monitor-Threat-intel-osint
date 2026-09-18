import { NextRequest, NextResponse } from 'next/server';
import {
  getSources,
  getSourceById,
  addSource,
  updateSource,
  deleteSource,
  testSource,
  getSourcesHealth,
  type SourceType,
} from '@/lib/sources';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

const VALID_TYPES: SourceType[] = ['THREAT_FEED', 'GEO_IP', 'DNS', 'CVE', 'REPUTATION', 'BREACH', 'AI', 'CUSTOM'];

// GET: list sources or health
export async function GET(request: NextRequest) {
  const { module: sourcesModule, error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }
  const searchParams = request.nextUrl.searchParams;
  const action = searchParams.get('action');

  if (action === 'health') {
    const health = await getSourcesHealth();
    return NextResponse.json({ success: true, module: sourcesModule, data: health });
  }

  const sources = await getSources();
  return NextResponse.json({
    success: true,
    module: sourcesModule,
    data: sources,
    count: sources.length,
    message: `${sources.length} intelligence source(s) registered`,
  });
}

// POST: add a custom source / test a source
export async function POST(request: NextRequest) {
  const body = await request.json();
  const { module: sourcesModule, error: moduleError } = resolveModuleScope(request, body);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }
  const { action } = body;

  if (action === 'test') {
    const { id } = body;
    if (!id) return NextResponse.json({ success: false, error: 'Source ID required' }, { status: 400 });
    const result = await testSource(id);
    return NextResponse.json({ success: result.ok, module: sourcesModule, data: result, message: result.message });
  }

  // Add new source
  const { name, type, method, endpoint, apiKeyEnv, enabled, description } = body;
  if (!name || !endpoint) {
    return NextResponse.json(
      { success: false, error: 'Name and endpoint are required' },
      { status: 400 }
    );
  }
  if (!VALID_TYPES.includes(type)) {
    return NextResponse.json(
      { success: false, error: `Invalid type. Valid: ${VALID_TYPES.join(', ')}` },
      { status: 400 }
    );
  }

  const source = await addSource({
    name,
    type,
    method: method === 'POST' ? 'POST' : 'GET',
    endpoint,
    apiKeyEnv,
    enabled: enabled !== false,
    description,
  });

  return NextResponse.json(
    { success: true, module: sourcesModule, data: source, message: `Source "${name}" added` },
    { status: 201 }
  );
}

// PATCH: update source
export async function PATCH(request: NextRequest) {
  const body = await request.json();
  const { module: sourcesModule, error: moduleError } = resolveModuleScope(request, body);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }
  const { id, ...patch } = body;
  if (!id) return NextResponse.json({ success: false, error: 'Source ID required' }, { status: 400 });

  const updated = await updateSource(id, patch);
  if (!updated) return NextResponse.json({ success: false, error: 'Source not found' }, { status: 404 });

  return NextResponse.json({ success: true, module: sourcesModule, data: updated, message: 'Source updated' });
}

// DELETE: remove custom source (built-in sources get disabled instead)
export async function DELETE(request: NextRequest) {
  const { module: sourcesModule, error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }
  const searchParams = request.nextUrl.searchParams;
  const id = searchParams.get('id');
  if (!id) return NextResponse.json({ success: false, error: 'Source ID required' }, { status: 400 });

  const source = await getSourceById(id);
  if (!source) return NextResponse.json({ success: false, error: 'Source not found' }, { status: 404 });

  const removed = await deleteSource(id);
  return NextResponse.json({
    success: true,
    module: sourcesModule,
    data: { id, removed },
    message: removed ? 'Source removed' : 'Built-in sources are disabled instead of removed',
  });
}
