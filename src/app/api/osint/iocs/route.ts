import { NextRequest, NextResponse } from 'next/server';
import {
  getIOCs,
  getIOCByValue,
  createIOC,
  updateIOC,
  deleteIOC,
  getAnalysesByIOC,
  getAlerts,
  getStoreStats,
  updateAlertStatus,
  removeAlert,
} from '@/lib/store';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

// IOC CRUD Operations — persistent via Vercel KV / in-memory fallback
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const type = searchParams.get('type') || undefined;
  const status = searchParams.get('status') || undefined;
  const severity = searchParams.get('severity') || undefined;
  const search = searchParams.get('search') || undefined;
  const page = parseInt(searchParams.get('page') || '1');
  const limit = parseInt(searchParams.get('limit') || '50');
  const scope = searchParams.get('scope');

  const { module: iocsModule, error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }

  try {
    if (scope === 'alerts') {
      const alerts = await getAlerts({ status: searchParams.get('alertStatus') || undefined });
      return NextResponse.json({ success: true, data: alerts, module: iocsModule, scope: 'alerts' });
    }

    const result = await getIOCs({ type, status, severity, search, page, limit });

    const enrichedData = await Promise.all(
      result.data.map(async (ioc) => ({
        ...ioc,
        tags: ioc.tags || [],
        analyses: await getAnalysesByIOC(ioc.id),
        alerts: await getAlerts({ iocId: ioc.id, status: 'ACTIVE' }),
      }))
    );

    return NextResponse.json({
      success: true,
      module: iocsModule,
      data: enrichedData,
      pagination: {
        page: result.page,
        limit: result.limit,
        total: result.total,
        totalPages: result.totalPages,
      },
      stats: await getStoreStats(),
      message: `Found ${result.total} IOC(s)`,
    });
  } catch (error) {
    console.error('IOC List Error:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to fetch IOCs',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

// Create new IOC
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { type, value, description, severity, confidence, tags, source, status } = body;

    if (!type || !value) {
      return NextResponse.json(
        {
          success: false,
          error: 'Type and value are required',
          validTypes: ['IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL', 'CVE'],
        },
        { status: 400 }
      );
    }

    const existing = await getIOCByValue(value);
    if (existing) {
      return NextResponse.json(
        {
          success: false,
          error: 'IOC already exists',
          existingId: existing.id,
          existingValue: existing.value,
        },
        { status: 409 }
      );
    }

    const ioc = await createIOC({
      type,
      value,
      description: description || `${type}: ${value}`,
      severity: severity || 'MEDIUM',
      confidence: confidence || 50,
      status,
      source: source || 'manual',
      tags: tags || [],
    });

    return NextResponse.json(
      {
        success: true,
        ioc,
        message: `IOC ${value} created successfully`,
      },
      { status: 201 }
    );
  } catch (error: any) {
    console.error('Create IOC Error:', error);
    return NextResponse.json(
      {
        success: false,
        error: error.message || 'Failed to create IOC',
        details: error.message,
      },
      { status: 500 }
    );
  }
}

// Update IOC
export async function PATCH(request: NextRequest) {
  try {
    const body = await request.json();
    const { id, description, severity, status, confidence, tags } = body;

    if (!id) {
      return NextResponse.json(
        { success: false, error: 'IOC ID is required for update' },
        { status: 400 }
      );
    }

    const ioc = await updateIOC(id, { description, severity, status, confidence, tags });

    if (!ioc) {
      return NextResponse.json({ success: false, error: 'IOC not found' }, { status: 404 });
    }

    return NextResponse.json({
      success: true,
      ioc,
      message: `IOC ${ioc.value} updated successfully`,
    });
  } catch (error: any) {
    console.error('Update IOC Error:', error);
    return NextResponse.json(
      {
        success: false,
        error: error.message || 'Failed to update IOC',
        details: error.message,
      },
      { status: 500 }
    );
  }
}

// Delete IOC / update alert status
export async function DELETE(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const id = searchParams.get('id');
  const alertId = searchParams.get('alertId');

  if (alertId) {
    const removed = await removeAlert(alertId);
    return removed
      ? NextResponse.json({ success: true, message: 'Alert dismissed' })
      : NextResponse.json({ success: false, error: 'Alert not found' }, { status: 404 });
  }

  if (!id) {
    return NextResponse.json(
      { success: false, error: 'IOC ID is required for deletion' },
      { status: 400 }
    );
  }

  try {
    const deleted = await deleteIOC(id);
    if (!deleted) {
      return NextResponse.json(
        { success: false, error: 'IOC not found or already deleted' },
        { status: 404 }
      );
    }
    return NextResponse.json({ success: true, message: 'IOC deleted successfully' });
  } catch (error: any) {
    console.error('Delete IOC Error:', error);
    return NextResponse.json(
      {
        success: false,
        error: error.message || 'Failed to delete IOC',
        details: error.message,
      },
      { status: 500 }
    );
  }
}

// Alert status updates
export async function PUT(request: NextRequest) {
  const body = await request.json();
  const { alertId, status } = body;
  if (!alertId || !status) {
    return NextResponse.json({ success: false, error: 'alertId and status required' }, { status: 400 });
  }
  const updated = await updateAlertStatus(alertId, status);
  if (!updated) return NextResponse.json({ success: false, error: 'Alert not found' }, { status: 404 });
  return NextResponse.json({ success: true, data: updated, message: 'Alert updated' });
}
