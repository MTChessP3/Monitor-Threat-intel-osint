import { NextRequest, NextResponse } from 'next/server';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Allow auth pages and API routes (they handle their own auth)
  // Also allow public static assets so they don't get redirected to login
  if (
    pathname.startsWith('/auth') ||
    pathname.startsWith('/api/auth') ||
    pathname.startsWith('/_next') ||
    pathname === '/robots.txt' ||
    pathname === '/favicon.ico' ||
    pathname === '/apple-touch-icon.png' ||
    pathname === '/logo.svg' ||
    pathname === '/logo.png' ||
    pathname === '/logo-new.png' ||
    pathname === '/site.webmanifest' ||
    /^\/favicon-\d+x\d+\.png$/.test(pathname)
  ) {
    return NextResponse.next();
  }

  // Check for auth cookie
  const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;

  if (!token) {
    // For API routes, return 401 JSON response instead of redirecting
    if (pathname.startsWith('/api/')) {
      return NextResponse.json(
        { error: 'No autenticado', code: 'SESSION_EXPIRED' },
        { status: 401 }
      );
    }
    return NextResponse.redirect(new URL('/auth/login', request.url));
  }

  // Verify token
  const payload = await verifyToken(token);
  if (!payload) {
    // For API routes, return 401 JSON response instead of redirecting
    if (pathname.startsWith('/api/')) {
      const response = NextResponse.json(
        { error: 'Sesión expirada', code: 'SESSION_EXPIRED' },
        { status: 401 }
      );
      // Also clear the invalid cookie
      response.cookies.set(AUTH_COOKIE_NAME, '', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 0,
        path: '/',
      });
      return response;
    }

    // For page requests, clear invalid cookie and redirect
    const response = NextResponse.redirect(new URL('/auth/login', request.url));
    response.cookies.set(AUTH_COOKIE_NAME, '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 0,
      path: '/',
    });
    return response;
  }

  // Check if token has mfaPending flag — user hasn't completed MFA yet
  if (payload && typeof payload === 'object' && 'mfaPending' in payload) {
    // Allow API auth routes through so MFA verification can proceed
    // For other routes, redirect to MFA verify page
    if (!pathname.startsWith('/api/')) {
      return NextResponse.redirect(new URL('/auth/mfa-verify', request.url));
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public files
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
