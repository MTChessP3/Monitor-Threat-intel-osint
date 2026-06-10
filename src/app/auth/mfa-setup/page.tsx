'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, QrCode, Smartphone, CheckCircle, ArrowRight, Loader2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { toast } from 'sonner';
import { useRouter, useSearchParams } from 'next/navigation';
import { ThemeSelector } from '@/components/ThemeSelector';

function MfaSetupContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const isNew = searchParams.get('new') === '1';

  const [step, setStep] = useState<'choose' | 'setup' | 'verify'>('choose');
  const [qrCode, setQrCode] = useState('');
  const [secret, setSecret] = useState('');
  const [uri, setUri] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [setupLoading, setSetupLoading] = useState(false);

  const handleSetupMfa = async () => {
    setSetupLoading(true);
    try {
      const res = await fetch('/api/auth/mfa/setup', {
        method: 'POST',
      });

      const data = await res.json();

      if (!res.ok) {
        toast.error(data.error || 'Error al configurar MFA');
        return;
      }

      setQrCode(data.qrCode);
      setSecret(data.secret);
      setUri(data.uri);
      setStep('setup');
    } catch {
      toast.error('Error de conexión');
    } finally {
      setSetupLoading(false);
    }
  };

  const handleVerifyCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (verificationCode.length !== 6) {
      toast.error('El código debe tener 6 dígitos');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch('/api/auth/mfa/enable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret, code: verificationCode }),
      });

      const data = await res.json();

      if (!res.ok) {
        toast.error(data.error || 'Código inválido');
        return;
      }

      toast.success('Autenticación de doble factor activada');
      router.push('/');
    } catch {
      toast.error('Error de conexión');
    } finally {
      setLoading(false);
    }
  };

  const handleSkipMfa = () => {
    router.push('/');
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
        className="w-full max-w-lg"
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
          <p className="text-sm text-muted-foreground mt-1">Configuración de Seguridad</p>
        </div>

        {/* Success message for new accounts */}
        {isNew && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-6 p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center gap-3"
          >
            <CheckCircle className="w-5 h-5 shrink-0" />
            <p className="text-sm font-medium">¡Cuenta creada exitosamente!</p>
          </motion.div>
        )}

        <AnimatePresence mode="wait">
          {/* Step 1: Choose */}
          {step === 'choose' && (
            <motion.div
              key="choose"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ duration: 0.2 }}
            >
              <Card className="border-border bg-card/80 backdrop-blur-sm card-elevated">
                <CardHeader className="text-center pb-2">
                  <CardTitle className="text-xl text-foreground">¿Deseas activar autenticación de doble factor (MFA)?</CardTitle>
                  <CardDescription className="text-muted-foreground">
                    Añade una capa extra de seguridad a tu cuenta con Google Authenticator
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4 pt-4">
                  <Button
                    onClick={handleSetupMfa}
                    disabled={setupLoading}
                    className="w-full primary-gradient text-primary-foreground font-semibold hover:opacity-90 h-14 text-base"
                  >
                    {setupLoading ? (
                      <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                    ) : (
                      <Smartphone className="w-5 h-5 mr-2" />
                    )}
                    {setupLoading ? 'Preparando...' : 'Activar MFA'}
                  </Button>

                  <div className="relative">
                    <div className="absolute inset-0 flex items-center">
                      <span className="w-full border-t border-border" />
                    </div>
                    <div className="relative flex justify-center text-xs uppercase">
                      <span className="bg-card px-2 text-muted-foreground">o</span>
                    </div>
                  </div>

                  <Button
                    onClick={handleSkipMfa}
                    variant="outline"
                    className="w-full border-border hover:border-primary/20 h-14 text-base"
                  >
                    Continuar sin MFA
                    <ArrowRight className="w-4 h-4 ml-2" />
                  </Button>

                  <p className="text-xs text-center text-muted-foreground mt-4">
                    Puede activar MFA más tarde desde la configuración de su cuenta
                  </p>
                </CardContent>
              </Card>
            </motion.div>
          )}

          {/* Step 2: Show QR Code */}
          {step === 'setup' && (
            <motion.div
              key="setup"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ duration: 0.2 }}
            >
              <Card className="border-border bg-card/80 backdrop-blur-sm card-elevated">
                <CardHeader className="text-center pb-2">
                  <CardTitle className="text-xl text-foreground flex items-center justify-center gap-2">
                    <QrCode className="w-5 h-5 text-primary" />
                    Configurar Autenticador
                  </CardTitle>
                  <CardDescription className="text-muted-foreground">
                    Escanee el código QR con Google Authenticator u otra app compatible
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {/* QR Code */}
                  <div className="flex justify-center">
                    <div className="p-4 bg-white rounded-xl">
                      <img src={qrCode} alt="QR Code para MFA" width={200} height={200} />
                    </div>
                  </div>

                  {/* Instructions */}
                  <div className="space-y-3 p-4 rounded-lg bg-muted/30 border border-border">
                    <h4 className="text-sm font-semibold text-foreground">Instrucciones:</h4>
                    <ol className="text-xs text-muted-foreground space-y-2 list-decimal list-inside">
                      <li>Abra Google Authenticator en su teléfono</li>
                      <li>Toque el botón &quot;+&quot; para añadir una cuenta</li>
                      <li>Escanee el código QR de arriba</li>
                      <li>Ingrese el código de 6 dígitos que aparece en la app</li>
                    </ol>
                  </div>

                  {/* Secret key fallback */}
                  <div className="space-y-1">
                    <Label className="text-xs text-muted-foreground">Clave secreta (ingreso manual):</Label>
                    <div className="p-2 bg-muted/30 rounded border border-border font-mono text-xs text-foreground break-all select-all">
                      {secret}
                    </div>
                  </div>

                  {/* Verify code input */}
                  <form onSubmit={handleVerifyCode} className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="verificationCode" className="text-muted-foreground">
                        Código de verificación
                      </Label>
                      <Input
                        id="verificationCode"
                        type="text"
                        inputMode="numeric"
                        pattern="[0-9]*"
                        maxLength={6}
                        placeholder="000000"
                        value={verificationCode}
                        onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                        className="text-center text-2xl tracking-[0.5em] bg-muted/30 border-border focus:border-primary/30 h-14 font-mono"
                        required
                        autoFocus
                      />
                    </div>
                    <Button
                      type="submit"
                      disabled={loading || verificationCode.length !== 6}
                      className="w-full primary-gradient text-primary-foreground font-semibold hover:opacity-90"
                    >
                      {loading ? (
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      ) : (
                        <CheckCircle className="w-4 h-4 mr-2" />
                      )}
                      {loading ? 'Verificando...' : 'Verificar y Activar MFA'}
                    </Button>
                  </form>

                  <button
                    type="button"
                    onClick={() => { setStep('choose'); setVerificationCode(''); }}
                    className="w-full text-center text-sm text-muted-foreground hover:text-foreground transition-colors"
                  >
                    ← Volver
                  </button>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>

        <p className="text-center text-xs text-muted-foreground mt-6">
          VIP-Intelligence — Protección Digital de Ejecutivos
        </p>
      </motion.div>
    </div>
  );
}

export default function MfaSetupPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    }>
      <MfaSetupContent />
    </Suspense>
  );
}
