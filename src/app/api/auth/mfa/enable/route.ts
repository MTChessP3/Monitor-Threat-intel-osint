import { NextRequest, NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';
import { verifyToken, verifyMfaCode, AUTH_COOKIE_NAME } from '@/lib/auth';

export async function POST(request: NextRequest) {
  try {
    await ensureDatabaseInitialized();
    // Get auth cookie
    const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;
    if (!token) {
      return NextResponse.json({ error: 'No autenticado' }, { status: 401 });
    }

    const payload = await verifyToken(token);
    if (!payload || typeof payload !== 'object' || !('id' in payload)) {
      return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }

    const userId = (payload as { id: string }).id;

    const body = await request.json();
    const { secret, code } = body;

    if (!secret || !code) {
      return NextResponse.json(
        { error: 'Secreto y código son requeridos' },
        { status: 400 }
      );
    }

    // Verify the TOTP code against the secret
    const isValid = verifyMfaCode(secret, code);
    if (!isValid) {
      return NextResponse.json(
        { error: 'Código MFA inválido. Intente nuevamente.' },
        { status: 400 }
      );
    }

    // Save secret to user and enable MFA
    await db.user.update({
      where: { id: userId },
      data: {
        mfaEnabled: true,
        mfaSecret: secret,
      },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('MFA enable error:', error);
    return NextResponse.json(
      { error: 'Error interno del servidor' },
      { status: 500 }
    );
  }
}
