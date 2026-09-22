import { NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';
import { loadDb, saveDb, genId } from '@/lib/local-db';

const prisma = new PrismaClient();

export async function GET() {
  try {
    const db = loadDb();
    return NextResponse.json({ executives: db.executives });
  } catch (err) {
    return NextResponse.json({ error: 'Failed to fetch executives' }, { status: 500 });
  }
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const db = loadDb();
    const newExecutive = {
      id: genId('e'),
      name: body.name,
      role: body.role,
      company: body.company,
      exposedEmails: body.exposedEmails || 0,
      exposedPhones: body.exposedPhones || 0,
      leakedCredentials: body.leakedCredentials || 0,
      riskScore: body.riskScore || 50,
      lastCheck: new Date().toISOString(),
      email: body.email || null,
      phone: body.phone || null,
      position: body.position || null,
      organization: body.organization || null,
      emailType: body.emailType || 'corporate',
      address: body.address || null,
      location: body.location || null,
      socialMedia: body.socialMedia ? JSON.stringify(body.socialMedia) : null,
      notes: body.notes || null,
      active: true,
    };
    db.executives.push(newExecutive);
    saveDb(db);

    try {
      await prisma.executive.create({ data: { ...newExecutive, socialMedia: newExecutive.socialMedia || undefined } });
    } catch {}

    return NextResponse.json(newExecutive, { status: 201 });
  } catch (err) {
    return NextResponse.json({ error: 'Failed to create executive' }, { status: 500 });
  }
}
