'use client';

import React, { useState, Suspense } from 'react';
import { motion } from 'framer-motion';
import { Shield, Loader2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { toast } from 'sonner';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { ThemeSelector } from '@/components/ThemeSelector';

function MfaVerifyContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const email = searchParams.get('email') || '';

  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (code.length !== 6) {
      toast.error('El código debe tener 6 dígitos');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, mfaCode: code }),
      });

      const data = await res.json();

      if (!res.ok) {
        toast.error(data.error || 'Código inválido');
        return;
      }

      toast.success('Sesión iniciada correctamente');
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
          <p className="text-sm text-muted-foreground mt-1">Verificación de Doble Factor</p>
        </div>

        <Card className="border-border bg-card/80 backdrop-blur-sm card-elevated">
          <CardHeader className="text-center pb-2">
            <CardTitle className="text-xl text-foreground">Código de Autenticación</CardTitle>
            <CardDescription className="text-muted-foreground">
              Ingrese el código de 6 dígitos de su aplicación autenticadora
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleVerify} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="mfaCode" className="text-muted-foreground">Código de 6 dígitos</Label>
                <Input
                  id="mfaCode"
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={6}
                  placeholder="000000"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="text-center text-2xl tracking-[0.5em] bg-muted/30 border-border focus:border-primary/30 h-14 font-mono"
                  required
                  autoFocus
                />
              </div>
              <Button
                type="submit"
                disabled={loading || code.length !== 6}
                className="w-full primary-gradient text-primary-foreground font-semibold hover:opacity-90"
              >
                {loading ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Shield className="w-4 h-4 mr-2" />
                )}
                {loading ? 'Verificando...' : 'Verificar Código'}
              </Button>
            </form>

            <div className="mt-6 text-center">
              <Link
                href="/auth/login"
                className="text-sm text-muted-foreground hover:text-primary/80 transition-colors"
              >
                ← Volver al inicio de sesión
              </Link>
            </div>
          </CardContent>
        </Card>

        <p className="text-center text-xs text-muted-foreground mt-6">
          VIP-Intelligence — Protección Digital de Ejecutivos
        </p>
      </motion.div>
    </div>
  );
}

export default function MfaVerifyPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    }>
      <MfaVerifyContent />
    </Suspense>
  );
}
