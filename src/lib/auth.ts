import bcrypt from 'bcryptjs';
import * as jose from 'jose';
import * as OTPAuth from 'otpauth';
import QRCode from 'qrcode';

export const AUTH_COOKIE_NAME = 'vip_session';

const JWT_SECRET = process.env.AUTH_SECRET || 'vip-protection-secret-key-change-in-production';

function getSecretKey(): Uint8Array {
  return new TextEncoder().encode(JWT_SECRET);
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export async function createToken(payload: object): Promise<string> {
  const secret = getSecretKey();
  const token = await new jose.SignJWT(payload as Record<string, unknown>)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('24h')
    .sign(secret);
  return token;
}

export async function verifyToken(token: string): Promise<object | null> {
  try {
    const secret = getSecretKey();
    const { payload } = await jose.jwtVerify(token, secret);
    return payload as object;
  } catch {
    return null;
  }
}

export function generateMfaSecret(email: string): { secret: string; uri: string } {
  const secret = new OTPAuth.Secret({ size: 20 });
  const totp = new OTPAuth.TOTP({
    issuer: 'VIP_Protection',
    label: email,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: secret,
  });

  return {
    secret: secret.base32,
    uri: totp.toString(),
  };
}

export async function generateQrCode(uri: string): Promise<string> {
  return QRCode.toDataURL(uri, {
    width: 256,
    margin: 2,
    color: {
      dark: '#000000',
      light: '#ffffff',
    },
  });
}

export function verifyMfaCode(secret: string, code: string): boolean {
  try {
    const totp = new OTPAuth.TOTP({
      issuer: 'VIP_Protection',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(secret),
    });

    const delta = totp.validate({
      token: code,
      window: 1,
    });

    return delta !== null;
  } catch {
    return false;
  }
}
