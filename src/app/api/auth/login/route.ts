import { NextRequest, NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';
import { verifyPassword, createToken, verifyMfaCode, AUTH_COOKIE_NAME } from '@/lib/auth';

export async function POST(request: NextRequest) {
  try {
    // Ensure database is initialized on Vercel serverless
    await ensureDatabaseInitialized();

    const body = await request.json();
    const { email, password, mfaCode } = body;

    // Validate fields
    if (!email || !password) {
      return NextResponse.json(
        { error: 'Correo electrónico y contraseña son requeridos' },
        { status: 400 }
      );
    }

    // Find user
    const user = await db.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!user) {
      return NextResponse.json(
        { error: 'Credenciales inválidas' },
        { status: 401 }
      );
    }

    // Verify password
    const isValid = await verifyPassword(password, user.password);
    if (!isValid) {
      return NextResponse.json(
        { error: 'Credenciales inválidas' },
        { status: 401 }
      );
    }

    // If MFA is enabled
    if (user.mfaEnabled) {
      if (!mfaCode) {
        // Create a temporary token for MFA verification
        const tempToken = await createToken({
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          mfaPending: true,
        });

        return NextResponse.json({
          requiresMfa: true,
          tempToken,
        });
      }

      // Verify MFA code
      if (!user.mfaSecret) {
        return NextResponse.json(
          { error: 'MFA no configurado correctamente. Contacte al administrador.' },
          { status: 400 }
        );
      }

      const isValidCode = verifyMfaCode(user.mfaSecret, mfaCode);
      if (!isValidCode) {
        return NextResponse.json(
          { error: 'Código MFA inválido' },
          { status: 401 }
        );
      }
    }

    // Create session token
    const token = await createToken({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    });

    const response = NextResponse.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        mfaEnabled: user.mfaEnabled,
        role: user.role,
      },
    });

    response.cookies.set(AUTH_COOKIE_NAME, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 24, // 24 hours
      path: '/',
    });

    return response;
  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      { error: 'Error interno del servidor' },
      { status: 500 }
    );
  }
}
