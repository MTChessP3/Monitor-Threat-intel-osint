#!/usr/bin/env node
// NEXUS INTEL / MONITOR-THREAT — API Test Suite
// Usage:  node tests/api-tests.mjs [baseUrl]
// Default baseUrl: http://localhost:3000
//
// Requires the dev server running:  bun run dev  (or `npm run dev`)

const baseUrl = process.argv[2] || 'http://localhost:3000';

// Per-module scoping: every search/query endpoint requires ?module=<tab> (or
// body.module). Append the originating module on every call so no state/cache
// leaks across modules (see src/lib/intel/moduleScope.ts).
function mod(path, module) {
  if (!path) return path;
  return path.includes('?') ? `${path}&module=${module}` : `${path}?module=${module}`;
}

let passed = 0;
let failed = 0;
const failures = [];

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  } catch (err) {
    failed++;
    failures.push({ name, err });
    console.log(`  \x1b[31m✗\x1b[0m ${name}`);
    console.log(`      ${err.message}`);
  }
}

async function request(path, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  try {
    const res = await fetch(`${baseUrl}${path}`, { ...options, signal: controller.signal });
    let body;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    return { status: res.status, body };
  } finally {
    clearTimeout(timeout);
  }
}

async function main() {
  console.log(`\nNEXUS INTEL API Tests against ${baseUrl}\n`);
  console.log('Checking server availability...');

  const health = await request('/api/osint/ip?ip=8.8.8.8&module=ip').catch(() => null);
  if (!health) {
    console.log('\n\x1b[31mCannot reach server. Start it with `bun run dev` and retry.\x1b[0m\n');
    process.exit(1);
  }
  console.log('  \x1b[32m✓\x1b[0m Server reachable\n');

  // ---------- IP ----------
  console.log('IP Intelligence');
  await test('GET /api/osint/ip returns live data', async () => {
    const { status, body } = await request(mod('/api/osint/ip?ip=8.8.8.8', 'ip'));
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    if (!body.success) throw new Error(`success=false: ${body.error}`);
    if (!body.data || !body.data.country) throw new Error('missing data.country');
  });

  await test('GET /api/osint/ip rejects missing ip', async () => {
    const { status } = await request(mod('/api/osint/ip', 'ip'));
    if (status !== 400) throw new Error(`expected 400, got ${status}`);
  });

  // ---------- Domain ----------
  console.log('\nDomain Intelligence');
  await test('GET /api/osint/domain resolves DNS', async () => {
    const { status, body } = await request(mod('/api/osint/domain?domain=google.com', 'domain'));
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    if (!body.success) throw new Error(`success=false: ${body.error}`);
  });

  // ---------- URL ----------
  console.log('\nURL Scanner');
  await test('GET /api/osint/url scores a URL', async () => {
    const { status, body } = await request(mod('/api/osint/url?url=https://example.com', 'url'));
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    if (!body.riskAssessment || !body.riskAssessment.level) throw new Error('missing riskAssessment');
  });

  // ---------- Hash ----------
  console.log('\nHash Lookup');
  await test('GET /api/osint/hash returns 400 for missing hash', async () => {
    const { status } = await request(mod('/api/osint/hash', 'hash'));
    if (status !== 400) throw new Error(`expected 400, got ${status}`);
  });

  await test('GET /api/osint/hash handles lookup gracefully', async () => {
    const { status, body } = await request(mod('/api/osint/hash?hash=0000000000000000000000000000000000000000000000000000000000000000', 'hash'));
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    if (body.message === undefined) throw new Error('missing message');
  });

  // ---------- CVE ----------
  console.log('\nCVE Database');
  await test('GET /api/osint/cve returns 400 for missing input', async () => {
    const { status } = await request(mod('/api/osint/cve', 'cve'));
    if (status !== 400) throw new Error(`expected 400, got ${status}`);
  });

  await test('GET /api/osint/cve searches', async () => {
    const { status, body } = await request(mod('/api/osint/cve?keyword=log4j', 'cve'));
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
  });

  // ---------- Threats ----------
  console.log('\nThreat Feeds');
  await test('GET /api/osint/threats loads feeds', async () => {
    const { status, body } = await request(mod('/api/osint/threats?limit=5', 'threats'));
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    if (!body.success) throw new Error(`success=false: ${body.message}`);
  });

  // ---------- Dark Web ----------
  console.log('\nDark Web Intel');
  await test('GET /api/osint/darkweb rejects missing query', async () => {
    const { status } = await request(mod('/api/osint/darkweb', 'darkweb'));
    if (status !== 400) throw new Error(`expected 400, got ${status}`);
  });

  await test('GET /api/osint/darkweb returns matches', async () => {
    const { status, body } = await request(mod('/api/osint/darkweb?query=acme', 'darkweb'));
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    if (!Array.isArray(body.matches)) throw new Error('missing matches array');
  });

  // ---------- AI ----------
  console.log('\nAI Analyst');
  await test('GET /api/osint/ai reports status', async () => {
    const { status, body } = await request(mod('/api/osint/ai', 'ai'));
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    if (body.aiEnabled === undefined) throw new Error('missing aiEnabled flag');
  });

  await test('POST /api/osint/ai analyzes a target (fallback mode ok)', async () => {
    const { status, body } = await request('/api/osint/ai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: '8.8.8.8', type: 'IP', module: 'ai' }),
    });
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    if (body.analysis === undefined && body.error === undefined) throw new Error('missing analysis result');
  });

  // ---------- IOCs (persistence) ----------
  console.log('\nIOC Manager');
  const testIocValue = `test-${Date.now()}.example.com`;

  await test('POST /api/osint/iocs creates an IOC', async () => {
    const { status, body } = await request('/api/osint/iocs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'DOMAIN',
        value: testIocValue,
        description: 'API test IOC',
        severity: 'MEDIUM',
        status: 'UNKNOWN',
        source: 'api-tests',
        tags: ['test'],
        module: 'iocs',
      }),
    });
    if (status !== 200 && status !== 201) throw new Error(`expected 200/201, got ${status}`);
    if (!body.success) throw new Error(`success=false: ${body.error || body.message}`);
  });

  await test('GET /api/osint/iocs lists the created IOC', async () => {
    const { status, body } = await request('/api/osint/iocs?type=DOMAIN&module=iocs');
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    const found = (body.data || []).some((i) => i.value === testIocValue);
    if (!found) throw new Error('created IOC not found in list');
  });

  await test('PATCH /api/osint/iocs updates an IOC', async () => {
    const { body: list } = await request('/api/osint/iocs?type=DOMAIN&module=iocs');
    const ioc = (list.data || []).find((i) => i.value === testIocValue);
    if (!ioc) throw new Error('IOC not found to update');
    const { status } = await request('/api/osint/iocs', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: ioc.id, status: 'SUSPICIOUS', severity: 'HIGH', module: 'iocs' }),
    });
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
  });

  await test('DELETE /api/osint/iocs removes the IOC', async () => {
    const { body: list } = await request('/api/osint/iocs?type=DOMAIN&module=iocs');
    const ioc = (list.data || []).find((i) => i.value === testIocValue);
    if (!ioc) throw new Error('IOC not found to delete');
    const { status } = await request(`/api/osint/iocs?id=${ioc.id}&module=iocs`, { method: 'DELETE' });
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
  });

  // ---------- Export ----------
  console.log('\nExport');
  await test('GET /api/osint/export returns JSON', async () => {
    const res = await fetch(`${baseUrl}/api/osint/export?format=json&module=export`);
    if (res.status !== 200) throw new Error(`expected 200, got ${res.status}`);
    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('json')) throw new Error(`expected json content-type, got ${ct}`);
    const body = await res.json();
    if (!Array.isArray(body.data) && !Array.isArray(body.iocs)) throw new Error('expected export array');
  });

  await test('GET /api/osint/export returns CSV', async () => {
    const res = await fetch(`${baseUrl}/api/osint/export?format=csv&module=export`);
    if (res.status !== 200) throw new Error(`expected 200, got ${res.status}`);
    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('csv')) throw new Error(`expected csv content-type, got ${ct}`);
  });

  await test('GET /api/osint/export returns STIX 2.1', async () => {
    const res = await fetch(`${baseUrl}/api/osint/export?format=stix&module=export`);
    if (res.status !== 200) throw new Error(`expected 200, got ${res.status}`);
    const body = await res.json();
    if (body.type !== 'bundle' && body.type !== 'bundle-stix21') throw new Error(`expected STIX bundle, got type=${body.type}`);
  });

  // ---------- Reports ----------
  console.log('\nReports');
  await test('POST /api/osint/reports generates a report', async () => {
    const { status, body } = await request('/api/osint/reports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: `API Test Report ${Date.now()}`,
        modules: ['iocs', 'threats'],
        executiveSummary: true,
        recommendations: true,
        includeTimeline: false,
        module: 'reports',
      }),
    });
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    if (!body.success) throw new Error(`success=false: ${body.error || body.message}`);
  });

  await test('GET /api/osint/reports lists reports', async () => {
    const { status, body } = await request('/api/osint/reports?action=list&module=reports');
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    if (!Array.isArray(body.data)) throw new Error('expected reports array');
  });

  await test('GET /api/osint/reports downloads HTML', async () => {
    const { body: list } = await request('/api/osint/reports?action=list&module=reports');
    const report = list.data?.[0];
    if (!report) throw new Error('no report to download');
    const res = await fetch(`${baseUrl}/api/osint/reports?action=download&id=${report.id}&format=html&module=reports`);
    if (res.status !== 200) throw new Error(`expected 200, got ${res.status}`);
  });

  // ---------- Sources ----------
  console.log('\nIntelligence Sources');
  await test('GET /api/osint/sources lists sources', async () => {
    const { status, body } = await request('/api/osint/sources?module=sources');
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    if (!Array.isArray(body.data)) throw new Error('expected data array');
    if (body.data.length < 3) throw new Error(`expected built-in sources, got ${body.data.length}`);
  });

  await test('GET /api/osint/sources?action=health reports status', async () => {
    const { status, body } = await request('/api/osint/sources?action=health&module=sources');
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    if (typeof body.data !== 'object' || body.data === null) throw new Error('expected health object');
    if (body.data.totalSources === undefined) throw new Error('expected totalSources');
  });

  await test('POST /api/osint/sources adds custom source', async () => {
    const { status, body } = await request('/api/osint/sources', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: `Test Source ${Date.now()}`,
        type: 'CUSTOM',
        method: 'GET',
        endpoint: 'https://example.com/feed.json',
        enabled: true,
        module: 'sources',
      }),
    });
    if (status !== 201) throw new Error(`expected 201, got ${status}`);
    if (!body.success) throw new Error(`success=false: ${body.error}`);
  });

  // ---------- Forensics / Mobile ----------
  console.log('\nForensics & Mobile');
  await test('GET /api/osint/forensics lists analyses', async () => {
    const { status, body } = await request('/api/osint/forensics?action=list&module=forensics');
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    if (!Array.isArray(body.data)) throw new Error('expected data array');
  });

  await test('GET /api/osint/mobile reports capabilities', async () => {
    const { status, body } = await request('/api/osint/mobile?module=mobile');
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
  });

  await test('POST /api/osint/mobile analyzes a file name', async () => {
    const { status, body } = await request('/api/osint/mobile', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fileName: 'test-app.apk', fileType: 'APK', useAI: false, module: 'mobile' }),
    });
    if (status !== 200) throw new Error(`expected 200, got ${status}`);
    if (!body.data || !body.data.sha256) throw new Error('missing analysis data');
  });

  // ---------- Summary ----------
  console.log('\n' + '='.repeat(50));
  console.log(`\x1b[1mResults: ${passed} passed, ${failed} failed\x1b[0m`);
  if (failures.length) {
    console.log('\nFailures:');
    for (const f of failures) console.log(`  - ${f.name}: ${f.err.message}`);
  }
  console.log('='.repeat(50) + '\n');

  process.exit(failed > 0 ? 1 : 0);
}

main();
