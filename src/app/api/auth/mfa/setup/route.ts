import { NextRequest, NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';
import { verifyToken, generateMfaSecret, generateQrCode, AUTH_COOKIE_NAME } from '@/lib/auth';

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

    // Verify user exists
    const user = await db.user.findUnique({ where: { id: userId } });
    if (!user) {
      return NextResponse.json({ error: 'Usuario no encontrado' }, { status: 404 });
    }

    // Generate MFA secret
    const { secret, uri } = generateMfaSecret(user.email);

    // Generate QR code
    const qrCode = await generateQrCode(uri);

    return NextResponse.json({
      secret,
      qrCode,
      uri,
    });
  } catch (error) {
    console.error('MFA setup error:', error);
    return NextResponse.json(
      { error: 'Error interno del servidor' },
      { status: 500 }
    );
  }
}
