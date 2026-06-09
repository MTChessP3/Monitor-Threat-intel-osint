import { NextRequest, NextResponse } from 'next/server';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';
import { db, ensureDatabaseInitialized } from '@/lib/db';

export async function GET(request: NextRequest) {
  try {
    const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;
    if (!token) {
      return NextResponse.json({ error: 'No autenticado' }, { status: 401 });
    }

    const payload = await verifyToken(token);
    if (!payload || typeof payload !== 'object' || !('id' in payload)) {
      return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }

    const jwtData = payload as { id: string; email: string; name: string; role: string; mfaPending?: boolean };

    // If token has mfaPending, the user hasn't completed MFA verification yet
    if (jwtData.mfaPending) {
      return NextResponse.json({ error: 'MFA pendiente de verificación' }, { status: 401 });
    }

    // Try to get fresh user data from DB, but fall back to JWT data if DB is unavailable
    try {
      await ensureDatabaseInitialized();

      const userId = jwtData.id;
      const user = await db.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          mfaEnabled: true,
        },
      });

      if (!user) {
        // DB was reset but JWT is still valid — return data from JWT token
        // This prevents session loss on ephemeral DB environments
        console.warn('[Session] User not found in DB, returning JWT-derived session data');
        return NextResponse.json({
          user: {
            id: jwtData.id,
            name: jwtData.name,
            email: jwtData.email,
            role: jwtData.role,
            mfaEnabled: false, // Can't determine from JWT, default to false
          },
          source: 'jwt_fallback',
        });
      }

      return NextResponse.json({ user });
    } catch (dbError) {
      // DB is completely unavailable — fall back to JWT data to keep session alive
      console.error('[Session] DB lookup failed, using JWT fallback:', dbError instanceof Error ? dbError.message.substring(0, 200) : String(dbError).substring(0, 200));
      return NextResponse.json({
        user: {
          id: jwtData.id,
          name: jwtData.name,
          email: jwtData.email,
          role: jwtData.role,
          mfaEnabled: false,
        },
        source: 'jwt_fallback',
      });
    }
  } catch (error) {
    console.error('Session error:', error);
    // Return 401 only for auth-specific errors, not for generic server errors
    // This prevents the client from losing session on transient server errors
    return NextResponse.json(
      { error: 'Error al verificar sesión' },
      { status: 401 }
    );
  }
}
