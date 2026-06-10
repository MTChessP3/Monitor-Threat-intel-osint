'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { motion } from 'framer-motion';
import { Shield, Mail, Lock, Loader2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { toast } from 'sonner';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { ThemeSelector } from '@/components/ThemeSelector';

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [showMfa, setShowMfa] = useState(false);
  const [tempToken, setTempToken] = useState('');
  const [loading, setLoading] = useState(false);

  // Check if redirected with mfa=1
  useEffect(() => {
    if (searchParams.get('mfa') === '1') {
      setShowMfa(true);
    }
  }, [searchParams]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        toast.error(data.error || 'Error al iniciar sesión');
        return;
      }

      if (data.requiresMfa) {
        setTempToken(data.tempToken);
        setShowMfa(true);
        toast.info('Ingrese su código de autenticación de doble factor');
        return;
      }

      toast.success('Sesión iniciada correctamente');

      // Cache the session data immediately so navigation doesn't lose it
      try {
        const { setCachedUser } = await import('@/lib/session-manager');
        if (data.user) {
          setCachedUser(data.user);
        }
      } catch {
        // Non-critical: session will be fetched on next page load
      }

      router.push('/');
    } catch {
      toast.error('Error de conexión');
    } finally {
      setLoading(false);
    }
  };

  const handleMfaVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (mfaCode.length !== 6) {
      toast.error('El código debe tener 6 dígitos');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, mfaCode }),
      });

      const data = await res.json();

      if (!res.ok) {
        toast.error(data.error || 'Código MFA inválido');
        return;
      }

      toast.success('Sesión iniciada correctamente');

      // Cache the session data immediately so navigation doesn't lose it
      try {
        const { setCachedUser } = await import('@/lib/session-manager');
        if (data.user) {
          setCachedUser(data.user);
        }
      } catch {
        // Non-critical: session will be fetched on next page load
      }

      router.push('/');
    } catch {
      toast.error('Error de conexión');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      {/* Theme selector in top-right corner */}
      <div className="fixed top-4 right-4 z-50">
        <ThemeSelector compact />
      </div>
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.2 }}
        className="w-full max-w-md"
      >
        {/* Logo */}
        <div className="text-center mb-8">
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ type: 'spring', stiffness: 200, damping: 15, delay: 0.1 }}
            className="w-16 h-16 rounded-xl overflow-hidden flex items-center justify-center mx-auto mb-4"
          >
            <img src="/favicon-128x128.png" alt="VIP-Intelligence" className="w-16 h-16" />
          </motion.div>
          <h1 className="text-2xl font-bold text-foreground tracking-wide">VIP-Intelligence</h1>
          <p className="text-sm text-muted-foreground mt-1">Protección Digital de Ejecutivos</p>
        </div>

        <Card className="border-border bg-card/80 backdrop-blur-sm card-elevated">
          <CardHeader className="text-center pb-2">
            <CardTitle className="text-xl text-foreground">
              {showMfa ? 'Autenticación de Doble Factor' : 'Iniciar Sesión'}
            </CardTitle>
            <CardDescription className="text-muted-foreground">
              {showMfa
                ? 'Ingrese el código de su aplicación autenticadora'
                : 'Acceda al sistema de inteligencia ejecutiva'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {!showMfa ? (
              <form onSubmit={handleLogin} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email" className="text-muted-foreground">Correo Electrónico</Label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      id="email"
                      type="email"
                      placeholder="correo@ejemplo.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="pl-10 bg-muted/30 border-border focus:border-primary/30"
                      required
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password" className="text-muted-foreground">Contraseña</Label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      id="password"
                      type="password"
                      placeholder="••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="pl-10 bg-muted/30 border-border focus:border-primary/30"
                      required
                    />
                  </div>
                </div>
                <Button
                  type="submit"
                  disabled={loading}
                  className="w-full primary-gradient text-primary-foreground font-semibold hover:opacity-90"
                >
                  {loading ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Shield className="w-4 h-4 mr-2" />
                  )}
                  {loading ? 'Verificando...' : 'Iniciar Sesión'}
                </Button>
              </form>
            ) : (
              <form onSubmit={handleMfaVerify} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="mfaCode" className="text-muted-foreground">Código de 6 dígitos</Label>
                  <Input
                    id="mfaCode"
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={6}
                    placeholder="000000"
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    className="text-center text-2xl tracking-[0.5em] bg-muted/30 border-border focus:border-primary/30 h-14 font-mono"
                    required
                    autoFocus
                  />
                </div>
                <Button
                  type="submit"
                  disabled={loading || mfaCode.length !== 6}
                  className="w-full primary-gradient text-primary-foreground font-semibold hover:opacity-90"
                >
                  {loading ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Shield className="w-4 h-4 mr-2" />
                  )}
                  {loading ? 'Verificando...' : 'Verificar Código'}
                </Button>
                <button
                  type="button"
                  onClick={() => { setShowMfa(false); setMfaCode(''); }}
                  className="w-full text-center text-sm text-muted-foreground hover:text-foreground transition-colors"
                >
                  ← Volver al inicio de sesión
                </button>
              </form>
            )}

            {!showMfa && (
              <div className="mt-6 text-center">
                <p className="text-sm text-muted-foreground">
                  ¿No tiene una cuenta?{' '}
                  <Link href="/auth/signup" className="text-primary hover:text-primary/80 font-medium transition-colors">
                    Registrarse
                  </Link>
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        <p className="text-center text-xs text-muted-foreground mt-6">
          VIP-Intelligence — Protección Digital de Ejecutivos
        </p>
      </motion.div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    }>
      <LoginForm />
    </Suspense>
  );
}
