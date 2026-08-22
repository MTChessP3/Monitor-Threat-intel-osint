'use client';

import React, { useState, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Upload, FileText, Shield, Send, Download, Printer, CheckCircle, XCircle,
  AlertCircle, Clock, Globe, Mail, Bug, Eye, RefreshCw, Trash2, Copy,
  ChevronDown, ChevronUp, Filter, List, Settings, Key, ExternalLink
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from 'sonner';

interface ExtractedUrl {
  url: string;
  valid: boolean;
}

interface ServiceOption {
  id: string;
  name: string;
  icon: React.ReactNode;
  description: string;
  requiresApiKey: boolean;
  manualUrl?: string;
}

interface ReportResult {
  service: string;
  url: string;
  status: 'success' | 'failed' | 'pending' | 'manual';
  message: string;
  timestamp: string;
  referenceId?: string;
}

interface FullReport {
  reportId: string;
  timestamp: string;
  urls: string[];
  services: string[];
  notes?: string;
  results: ReportResult[];
  fingerprint: string;
  summary: {
    total: number;
    success: number;
    failed: number;
    pending: number;
    manual: number;
  };
}

const SERVICE_OPTIONS: ServiceOption[] = [
  {
    id: 'google',
    name: 'Google Safe Browsing',
    icon: <Shield className="w-4 h-4" />,
    description: 'Reporte automático vía API (requiere API Key) o manual',
    requiresApiKey: true,
    manualUrl: 'https://safebrowsing.google.com/safebrowsing/report_phish/',
  },
  {
    id: 'microsoft',
    name: 'Microsoft SmartScreen',
    icon: <Globe className="w-4 h-4" />,
    description: 'Reporte manual a través del portal web',
    requiresApiKey: false,
    manualUrl: 'https://www.microsoft.com/wdsi/support/report-unsafe-site',
  },
  {
    id: 'apwg',
    name: 'APWG (Anti-Phishing Working Group)',
    icon: <Mail className="w-4 h-4" />,
    description: 'Reporte por correo electrónico a reportphishing@apwg.org',
    requiresApiKey: false,
    manualUrl: 'mailto:reportphishing@apwg.org',
  },
  {
    id: 'cisa',
    name: 'CISA / US-CERT',
    icon: <Shield className="w-4 h-4" />,
    description: 'Reporte por correo a phishing-report@us-cert.gov',
    requiresApiKey: false,
    manualUrl: 'mailto:phishing-report@us-cert.gov',
  },
  {
    id: 'virustotal',
    name: 'VirusTotal',
    icon: <Bug className="w-4 h-4" />,
    description: 'Análisis de URL (requiere API Key) o consulta manual',
    requiresApiKey: true,
    manualUrl: 'https://www.virustotal.com/gui/home/url',
  },
];

const STATUS_CONFIG = {
  success: { label: 'ÉXITO', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30', icon: CheckCircle },
  failed: { label: 'FALLIDO', color: 'bg-red-500/20 text-red-400 border-red-500/30', icon: XCircle },
  pending: { label: 'PENDIENTE', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', icon: Clock },
  manual: { label: 'MANUAL', color: 'bg-blue-500/20 text-blue-400 border-blue-500/30', icon: ExternalLink },
};

export function TakeDownPanel() {
  const [activeStep, setActiveStep] = useState<'upload' | 'review' | 'services' | 'report' | 'result'>('upload');
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [extractedUrls, setExtractedUrls] = useState<ExtractedUrl[]>([]);
  const [selectedUrls, setSelectedUrls] = useState<Set<string>>(new Set());
  const [selectedServices, setSelectedServices] = useState<Set<string>>(new Set(SERVICE_OPTIONS.map(s => s.id)));
  const [notes, setNotes] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [processingProgress, setProcessingProgress] = useState(0);
  const [processingStep, setProcessingStep] = useState('');
  const [reportResult, setReportResult] = useState<FullReport | null>(null);
  const [showHtmlReport, setShowHtmlReport] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [apiKeys, setApiKeys] = useState<Record<string, string>>({
    google: '',
    virustotal: '',
  });

  const validUrls = extractedUrls.filter(u => u.valid).map(u => u.url);
  const invalidUrls = extractedUrls.filter(u => !u.valid).map(u => u.url);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const validExtensions = ['.txt', '.csv', '.xlsx'];
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!validExtensions.includes(ext)) {
      toast.error('Formato no soportado. Use .txt, .csv o .xlsx');
      return;
    }

    setUploadedFile(file);
    setIsProcessing(true);
    setProcessingStep('Extrayendo URLs del archivo...');
    setProcessingProgress(10);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const res = await fetch('/api/takedown/upload', {
        method: 'POST',
        body: formData,
      });

      setProcessingProgress(50);
      setProcessingStep('Procesando resultados...');

      if (res.ok) {
        const data = await res.json();
        const urls: ExtractedUrl[] = data.validUrls.map((url: string) => ({ url, valid: true }));
        setExtractedUrls(urls);
        setSelectedUrls(new Set(data.validUrls));
        toast.success(`${data.validCount} URLs válidas extraídas de ${data.fileName}`);
        setActiveStep('review');
      } else {
        const errorData = await res.json();
        toast.error(errorData.error || 'Error al procesar el archivo');
      }
    } catch {
      toast.error('Error al subir el archivo');
    } finally {
      setIsProcessing(false);
      setProcessingProgress(0);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const toggleUrlSelection = (url: string) => {
    setSelectedUrls(prev => {
      const next = new Set(prev);
      if (next.has(url)) next.delete(url); else next.add(url);
      return next;
    });
  };

  const toggleSelectAllUrls = () => {
    if (selectedUrls.size === validUrls.length) {
      setSelectedUrls(new Set());
    } else {
      setSelectedUrls(new Set(validUrls));
    }
  };

  const toggleServiceSelection = (id: string) => {
    setSelectedServices(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const generateReport = async () => {
    const urlsToReport = Array.from(selectedUrls);
    const servicesToReport = Array.from(selectedServices);

    if (urlsToReport.length === 0) {
      toast.error('Seleccione al menos una URL');
      return;
    }
    if (servicesToReport.length === 0) {
      toast.error('Seleccione al menos un servicio');
      return;
    }

    setActiveStep('report');
    setIsProcessing(true);
    setProcessingProgress(0);
    setProcessingStep('Iniciando reportes...');

    try {
      const res = await fetch('/api/takedown/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          urls: urlsToReport,
          services: servicesToReport,
          notes,
          apiKeys,
        }),
      });

      setProcessingProgress(50);
      setProcessingStep('Procesando respuestas de los servicios...');

      if (res.ok) {
        const data = await res.json();
        setReportResult(data);
        setProcessingProgress(100);
        setProcessingStep('Reporte completado');
        toast.success(`Reporte generado: ${data.summary.success} exitosos, ${data.summary.manual} manuales`);
      } else {
        const errorData = await res.json();
        toast.error(errorData.error || 'Error al generar reporte');
      }
    } catch {
      toast.error('Error de conexión');
    } finally {
      setIsProcessing(false);
    }
  };

  const generateHtmlReport = async () => {
    if (!reportResult) return;

    try {
      const res = await fetch('/api/takedown/report-html', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reportResult),
      });

      if (res.ok) {
        const html = await res.text();
        const blob = new Blob([html], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        window.open(url, '_blank');
        toast.success('Reporte HTML abierto en nueva pestaña');
      } else {
        toast.error('Error al generar reporte HTML');
      }
    } catch {
      toast.error('Error al generar reporte HTML');
    }
  };

  const downloadReport = async () => {
    if (!reportResult) return;

    try {
      const res = await fetch('/api/takedown/report-html', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reportResult),
      });

      if (res.ok) {
        const html = await res.text();
        const blob = new Blob([html], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `takedown-report-${reportResult.reportId}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast.success('Reporte HTML descargado');
      }
    } catch {
      toast.error('Error al descargar reporte');
    }
  };

  const copyFingerprint = () => {
    if (reportResult) {
      navigator.clipboard.writeText(reportResult.fingerprint);
      toast.success('Huella digital copiada al portapapeles');
    }
  };

  const resetAll = () => {
    setActiveStep('upload');
    setUploadedFile(null);
    setExtractedUrls([]);
    setSelectedUrls(new Set());
    setSelectedServices(new Set(SERVICE_OPTIONS.map(s => s.id)));
    setNotes('');
    setReportResult(null);
    setApiKeys({ google: '', virustotal: '' });
  };

  const getServiceOption = (id: string) => SERVICE_OPTIONS.find(s => s.id === id);

  const renderStepIndicator = (step: string, label: string, completed: boolean, active: boolean) => (
    <div className="flex flex-col items-center">
      <div className={`w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold transition-all ${
        completed
          ? 'bg-emerald-500 text-white'
          : active
          ? 'bg-primary text-primary-foreground'
          : 'bg-muted text-muted-foreground'
      }`}>
        {completed ? <CheckCircle className="w-5 h-5" /> : 
         active ? <span>{['1','2','3','4'].indexOf(step) + 1}</span> : 
         <span>{['1','2','3','4'].indexOf(step) + 1}</span>}
      </div>
      <span className={`text-xs mt-2 font-medium ${active ? 'text-primary' : 'text-muted-foreground'}`}>{label}</span>
      {step !== '4' && (
        <div className={`w-px h-16 flex-1 ${completed ? 'bg-emerald-500' : 'bg-border'}`} />
      )}
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="w-6 h-6 text-primary" />
            TakeDown URL
          </h2>
          <p className="text-muted-foreground mt-1">
            Cargue un archivo con URLs maliciosas y repórtelas a los principales servicios de seguridad
          </p>
        </div>
        {activeStep !== 'upload' && (
          <Button variant="outline" onClick={resetAll} className="gap-2">
            <RefreshCw className="w-4 h-4" />
            Reiniciar
          </Button>
        )}
      </div>

      {/* Step Indicator */}
      <div className="hidden md:flex items-center justify-center gap-0 px-4">
        {['upload', 'review', 'services', 'report'].map((step, i) => (
          <React.Fragment key={step}>
            {renderStepIndicator(
              String(i + 1),
              ['Subir', 'Revisar', 'Servicios', 'Reportar'][i],
              ['upload', 'review', 'services'].includes(activeStep) && ['review', 'services', 'report'].indexOf(step) >= 0 ? false : 
                ['upload', 'review', 'services'].indexOf(activeStep) > ['upload', 'review', 'services'].indexOf(step),
              activeStep === step
            )}
          </React.Fragment>
        ))}
      </div>

      <AnimatePresence mode="wait">
        {/* STEP 1: UPLOAD */}
        {activeStep === 'upload' && (
          <motion.div key="upload" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }}>
            <Card className="border-2 border-primary/20 bg-card/80 shadow-lg shadow-primary/5">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Upload className="w-5 h-5 text-primary" />
                  Paso 1: Subir Archivo con URLs
                </CardTitle>
                <CardDescription className="text-sm">
                  Arrastre o seleccione un archivo .txt, .csv o .xlsx que contenga las URLs a reportar.
                  El sistema extraerá automáticamente todas las URLs válidas.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".txt,.csv,.xlsx"
                  onChange={handleFileUpload}
                  className="hidden"
                  disabled={isProcessing}
                />
                <button
                  onClick={() => fileInputRef.current?.click()}
                  disabled={isProcessing}
                  className="w-full flex flex-col items-center justify-center gap-4 p-12 rounded-xl border-3 border-dashed border-primary/30 hover:border-primary bg-primary/5 hover:bg-primary/8 transition-all duration-300 cursor-pointer group"
                >
                  {isProcessing ? (
                    <>
                      <div className="flex flex-col items-center gap-3">
                        <div className="w-12 h-12 border-4 border-primary/20 border-t-primary rounded-full animate-spin" />
                        <span className="text-base text-muted-foreground font-medium">{processingStep}</span>
                        <Progress value={processingProgress} className="w-64 h-2" />
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="w-20 h-20 rounded-full bg-primary/10 flex items-center justify-center group-hover:bg-primary/15 transition-colors">
                        <Upload className="w-10 h-10 text-primary" />
                      </div>
                      <div className="text-center">
                        <p className="text-xl font-bold text-foreground">HAGA CLIC AQUÍ PARA SUBIR SU ARCHIVO</p>
                        <p className="text-sm text-muted-foreground mt-2">Formatos soportados: .txt, .csv, .xlsx</p>
                        <p className="text-xs text-muted-foreground mt-1">Máx. 10MB • El sistema detecta URLs automáticamente</p>
                      </div>
                    </>
                  )}
                </button>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-center">
                  <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                    <Shield className="w-6 h-6 text-emerald-500 mx-auto mb-2" />
                    <p className="text-sm font-medium text-emerald-600">Google Safe Browsing</p>
                    <p className="text-xs text-emerald-500/80 mt-1">API automática</p>
                  </div>
                  <div className="p-4 rounded-lg bg-blue-500/10 border border-blue-500/20">
                    <Mail className="w-6 h-6 text-blue-500 mx-auto mb-2" />
                    <p className="text-sm font-medium text-blue-600">APWG / CISA</p>
                    <p className="text-xs text-blue-500/80 mt-1">Reportes por email</p>
                  </div>
                  <div className="p-4 rounded-lg bg-purple-500/10 border border-purple-500/20">
                    <Bug className="w-6 h-6 text-purple-500 mx-auto mb-2" />
                    <p className="text-sm font-medium text-purple-600">VirusTotal</p>
                    <p className="text-xs text-purple-500/80 mt-1">Análisis de reputación</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}

        {/* STEP 2: REVIEW URLs */}
        {activeStep === 'review' && (
          <motion.div key="review" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="space-y-6">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <List className="w-5 h-5 text-primary" />
                      Paso 2: Revisar URLs Extraídas
                    </CardTitle>
                    <CardDescription className="text-sm">
                      Se encontraron {extractedUrls.length} URLs totales ({validUrls.length} válidas, {invalidUrls.length} inválidas)
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={toggleSelectAllUrls} className="gap-1">
                      {selectedUrls.size === validUrls.length ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                      {selectedUrls.size === validUrls.length ? 'Deseleccionar' : 'Seleccionar'} todas
                    </Button>
                    <Button onClick={() => setActiveStep('services')} className="primary-gradient text-primary-foreground font-semibold hover:opacity-95 gap-2">
                      Continuar <ChevronDown className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                {validUrls.length > 0 && (
                  <ScrollArea className="max-h-96">
                    <div className="space-y-2">
                      {validUrls.map((url, i) => (
                        <motion.div
                          key={url}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.03 }}
                          className={`flex items-center gap-3 p-3 rounded-lg border transition-all ${
                            selectedUrls.has(url)
                              ? 'border-primary/30 bg-primary/5'
                              : 'border-border bg-muted/30 hover:bg-muted/50'
                          }`}
                          onClick={() => toggleUrlSelection(url)}
                        >
                          <div className={`shrink-0 w-5 h-5 rounded-md border-2 flex items-center justify-center transition-all ${
                            selectedUrls.has(url)
                              ? 'border-primary bg-primary'
                              : 'border-muted-foreground/40'
                          }`}>
                            {selectedUrls.has(url) && <CheckCircle className="w-3.5 h-3.5 text-background" />}
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-mono text-foreground truncate">{url}</p>
                          </div>
                          <Badge variant="outline" className="text-xs border-emerald-500/30 text-emerald-500 shrink-0">
                            Válida
                          </Badge>
                        </motion.div>
                      ))}
                    </div>
                  </ScrollArea>
                )}

                {invalidUrls.length > 0 && (
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground flex items-center gap-1">
                      <AlertCircle className="w-3 h-3" />
                      URLs inválidas detectadas ({invalidUrls.length})
                    </Label>
                    <ScrollArea className="max-h-40">
                      <div className="space-y-1">
                        {invalidUrls.map((url, i) => (
                          <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-red-500/5 border border-red-500/10">
                            <XCircle className="w-4 h-4 text-red-500 shrink-0" />
                            <span className="text-sm font-mono text-red-500 truncate flex-1">{url}</span>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  </div>
                )}

                {validUrls.length === 0 && (
                  <div className="text-center py-12 text-muted-foreground">
                    <AlertCircle className="w-12 h-12 mx-auto mb-3 opacity-30" />
                    <p className="text-sm">No se encontraron URLs válidas en el archivo</p>
                    <Button variant="outline" className="mt-4" onClick={() => setActiveStep('upload')}>
                      <RefreshCw className="w-4 h-4 mr-2" />
                      Subir otro archivo
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>
        )}

        {/* STEP 3: SELECT SERVICES */}
        {activeStep === 'services' && (
          <motion.div key="services" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="space-y-6">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <Settings className="w-5 h-5 text-primary" />
                      Paso 3: Seleccionar Servicios de Reporte
                    </CardTitle>
                    <CardDescription className="text-sm">
                      {selectedUrls.size} URL(s) seleccionada(s). Elija a qué servicios enviar el reporte.
                    </CardDescription>
                  </div>
                  <Button onClick={() => setActiveStep('report')} className="primary-gradient text-primary-foreground font-semibold hover:opacity-95 gap-2">
                    Generar Reporte <Send className="w-4 h-4" />
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {SERVICE_OPTIONS.map((service) => {
                    const isSelected = selectedServices.has(service.id);
                    return (
                      <button
                        key={service.id}
                        onClick={() => toggleServiceSelection(service.id)}
                        className={`relative p-5 rounded-xl border-2 transition-all flex flex-col gap-3 ${
                          isSelected
                            ? 'border-primary/30 bg-primary/5 shadow-sm shadow-primary/5'
                            : 'border-border bg-muted/30 hover:border-primary/12 hover:bg-muted/50'
                        }`}
                      >
                        <div className="flex items-start gap-3">
                          <div className={`shrink-0 w-10 h-10 rounded-lg flex items-center justify-center ${
                            isSelected ? 'bg-primary/12 text-primary' : 'bg-muted/50 text-muted-foreground'
                          }`}>
                            {service.icon}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className={`font-medium ${isSelected ? 'text-foreground' : 'text-muted-foreground'}`}>
                                {service.name}
                              </span>
                              {service.requiresApiKey && (
                                <Badge variant="outline" className="text-xs border-amber-500/30 text-amber-500">
                                  <Key className="w-2.5 h-2.5 mr-1" />
                                  API Key
                                </Badge>
                              )}
                            </div>
                            <p className="text-xs text-muted-foreground mt-1">{service.description}</p>
                          </div>
                        </div>
                        <div className={`absolute top-3 right-3 w-6 h-6 rounded-full border-2 flex items-center justify-center transition-all ${
                          isSelected
                            ? 'border-primary bg-primary'
                            : 'border-muted-foreground/40'
                        }`}>
                          {isSelected && <CheckCircle className="w-4 h-4 text-background" />}
                        </div>
                      </button>
                    );
                  })}
                </div>

                {(selectedServices.has('google') || selectedServices.has('virustotal')) && (
                  <Card className="border-amber-500/30 bg-amber-500/5">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Key className="w-4 h-4 text-amber-500" />
                        Configuración de API Keys (Opcional)
                      </CardTitle>
                      <CardDescription className="text-xs">
                        Para reportes automáticos en Google Safe Browsing y VirusTotal. 
                        Sin API Key, se generarán enlaces para reporte manual.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {selectedServices.has('google') && (
                        <div className="space-y-1">
                          <Label className="text-xs text-muted-foreground">Google Safe Browsing API Key</Label>
                          <Input
                            type="password"
                            placeholder="Ingrese su API Key de Google Cloud"
                            value={apiKeys.google}
                            onChange={(e) => setApiKeys(prev => ({ ...prev, google: e.target.value }))}
                            className="bg-muted/30 border-border focus:border-primary/30"
                          />
                        </div>
                      )}
                      {selectedServices.has('virustotal') && (
                        <div className="space-y-1">
                          <Label className="text-xs text-muted-foreground">VirusTotal API Key</Label>
                          <Input
                            type="password"
                            placeholder="Ingrese su API Key de VirusTotal"
                            value={apiKeys.virustotal}
                            onChange={(e) => setApiKeys(prev => ({ ...prev, virustotal: e.target.value }))}
                            className="bg-muted/30 border-border focus:border-primary/30"
                          />
                        </div>
                      )}
                    </CardContent>
                  </Card>
                )}

                <div className="space-y-3">
                  <Label className="text-xs text-muted-foreground">Notas adicionales (opcional)</Label>
                  <Textarea
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    placeholder="Información adicional para incluir en los reportes por email (APWG, CISA)..."
                    className="min-h-24 bg-muted/30 border-border focus:border-primary/30"
                    rows={3}
                  />
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}

        {/* STEP 4: REPORT PROCESSING */}
        {activeStep === 'report' && (
          <motion.div key="report" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Send className="w-5 h-5 text-primary" />
                  Paso 4: Procesando Reportes
                </CardTitle>
                <CardDescription className="text-sm">
                  Enviando {selectedUrls.size} URL(s) a {selectedServices.size} servicio(s)...
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex flex-col items-center gap-4 py-8">
                  <div className="w-20 h-20 border-4 border-primary/20 border-t-primary rounded-full animate-spin" />
                  <div className="text-center">
                    <p className="text-lg font-medium text-foreground">{processingStep || 'Iniciando...'}</p>
                    <Progress value={processingProgress} className="w-64 h-3 mt-2" />
                    <p className="text-sm text-muted-foreground mt-2">{processingProgress}% completado</p>
                  </div>
                </div>
                {reportResult && (
                  <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
                    <div className="flex items-center gap-3">
                      <CheckCircle className="w-6 h-6 text-emerald-500" />
                      <div>
                        <p className="font-medium text-emerald-600">¡Reporte completado exitosamente!</p>
                        <p className="text-sm text-emerald-500/80 mt-1">
                          ID: {reportResult.reportId} | {reportResult.summary.success} exitosos, {reportResult.summary.manual} manuales, {reportResult.summary.failed} fallidos
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>
        )}

        {/* STEP 5: RESULTS */}
        {reportResult && activeStep !== 'report' && (
          <motion.div key="result" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="space-y-6">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between flex-wrap gap-4">
                  <div>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <CheckCircle className="w-5 h-5 text-emerald-500" />
                      Reporte Completado
                    </CardTitle>
                    <CardDescription className="text-sm">
                      ID: {reportResult.reportId} • {new Date(reportResult.timestamp).toLocaleString('es-ES')}
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <Button variant="outline" onClick={generateHtmlReport} className="gap-2">
                      <Eye className="w-4 h-4" />
                      Ver HTML
                    </Button>
                    <Button variant="outline" onClick={downloadReport} className="gap-2">
                      <Download className="w-4 h-4" />
                      Descargar HTML
                    </Button>
                    <Button variant="outline" onClick={copyFingerprint} className="gap-2">
                      <Copy className="w-4 h-4" />
                      Copiar Fingerprint
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Summary Cards */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  {[
                    { label: 'Total', value: reportResult.summary.total, color: 'bg-slate-500' },
                    { label: 'Éxitos', value: reportResult.summary.success, color: 'bg-emerald-500' },
                    { label: 'Manuales', value: reportResult.summary.manual, color: 'bg-blue-500' },
                    { label: 'Pendientes', value: reportResult.summary.pending, color: 'bg-yellow-500' },
                    { label: 'Fallidos', value: reportResult.summary.failed, color: 'bg-red-500' },
                  ].map((stat) => (
                    <div key={stat.label} className="p-4 rounded-xl text-center" style={{ background: `${stat.color}15`, border: `1px solid ${stat.color}30` }}>
                      <div className="text-3xl font-bold" style={{ color: stat.color }}>{stat.value}</div>
                      <div className="text-xs font-medium mt-1" style={{ color: stat.color }}>{stat.label}</div>
                    </div>
                  ))}
                </div>

                {/* Fingerprint */}
                <div className="p-4 rounded-lg bg-slate-900 border border-emerald-500/30">
                  <div className="flex items-center justify-between mb-2">
                    <Label className="text-xs text-emerald-400 flex items-center gap-1">
                      <Shield className="w-3 h-3" />
                      Huella Digital SHA-256 (Integridad del Reporte)
                    </Label>
                    <Button variant="ghost" size="sm" onClick={copyFingerprint} className="gap-1 text-emerald-400 hover:text-emerald-300">
                      <Copy className="w-3 h-3" />
                      Copiar
                    </Button>
                  </div>
                  <code className="font-mono text-xs text-emerald-300 break-all">{reportResult.fingerprint}</code>
                  <p className="text-xs text-emerald-500/60 mt-2">Verifique la integridad de este reporte comparando esta huella digital</p>
                </div>

                {/* Results Tabs */}
                <Tabs defaultValue="table" className="w-full">
                  <TabsList className="grid w-full grid-cols-2">
                    <TabsTrigger value="table">Tabla Consolidada</TabsTrigger>
                    <TabsTrigger value="detail">Detalle por URL</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="table" className="mt-4">
                    <ScrollArea className="max-h-96">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-border bg-muted/50">
                            <th className="p-3 text-left font-medium">Servicio</th>
                            <th className="p-3 text-left font-medium">URL</th>
                            <th className="p-3 text-center font-medium">Estado</th>
                            <th className="p-3 text-left font-medium">Mensaje</th>
                            <th className="p-3 text-left font-medium">Timestamp</th>
                            <th className="p-3 text-left font-medium">Ref. ID</th>
                          </tr>
                        </thead>
                        <tbody>
                          {reportResult.results.map((r, i) => {
                            const config = STATUS_CONFIG[r.status];
                            const Icon = config.icon;
                            return (
                              <tr key={i} className="border-b border-border/50 hover:bg-muted/30">
                                <td className="p-3 font-medium">{r.service}</td>
                                <td className="p-3 font-mono text-xs truncate max-w-xs">{r.url}</td>
                                <td className="p-3 text-center">
                                  <Badge className={config.color}><Icon className="w-3 h-3 mr-1" />{config.label}</Badge>
                                </td>
                                <td className="p-3 text-muted-foreground max-w-md">{r.message}</td>
                                <td className="p-3 font-mono text-xs text-muted-foreground">{new Date(r.timestamp).toLocaleString('es-ES')}</td>
                                <td className="p-3 font-mono text-xs text-muted-foreground">{r.referenceId || '-'}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </ScrollArea>
                  </TabsContent>

                  <TabsContent value="detail" className="mt-4">
                    <ScrollArea className="max-h-96">
                      <div className="space-y-4">
                        {reportResult.urls.map((url) => {
                          const urlResults = reportResult.results.filter(r => r.url === url);
                          return (
                            <div key={url} className="p-4 rounded-lg border border-border bg-muted/30">
                              <p className="font-mono text-sm text-primary mb-3 truncate" title={url}>{url}</p>
                              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                                {urlResults.map((r, i) => {
                                  const config = STATUS_CONFIG[r.status];
                                  const Icon = config.icon;
                                  return (
                                    <div key={i} className="p-3 rounded-lg border" style={{ background: `${config.color}10`, borderColor: `${config.color}30` }}>
                                      <div className="font-medium text-sm mb-1">{r.service}</div>
                                      <Badge className={config.color}><Icon className="w-3 h-3 mr-1" />{config.label}</Badge>
                                      <p className="text-xs text-muted-foreground mt-2">{r.message}</p>
                                      <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
                                        <span className="font-mono">{new Date(r.timestamp).toLocaleTimeString('es-ES')}</span>
                                        {r.referenceId && <span className="font-mono">{r.referenceId}</span>}
                                      </div>
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </ScrollArea>
                  </TabsContent>
                </Tabs>

                {/* Manual Report Links */}
                <div className="pt-4 border-t border-border">
                  <h4 className="font-medium mb-4 flex items-center gap-2">
                    <ExternalLink className="w-4 h-4" />
                    Enlaces Directos para Reportes Manuales
                  </h4>
                  <div className="space-y-3">
                    {reportResult.urls.map((url, urlIndex) => (
                      <div key={urlIndex} className="p-4 rounded-lg bg-muted/30 border border-border">
                        <p className="font-mono text-sm text-primary mb-3 truncate" title={url}>{url}</p>
                        <div className="flex flex-wrap gap-2">
                          <a
                            href={`https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(url)}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-3 py-1.5 text-xs font-medium rounded bg-blue-600/10 text-blue-600 border border-blue-600/20 hover:bg-blue-600/20 transition-colors"
                          >
                            🛡️ Google Safe Browsing
                          </a>
                          <a
                            href="https://www.microsoft.com/wdsi/support/report-unsafe-site"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-3 py-1.5 text-xs font-medium rounded bg-blue-700/10 text-blue-700 border border-blue-700/20 hover:bg-blue-700/20 transition-colors"
                          >
                            🔷 Microsoft SmartScreen
                          </a>
                          <a
                            href={`mailto:reportphishing@apwg.org?subject=Phishing%20Report&body=${encodeURIComponent(`URL: ${url}\n\n${notes || ''}`)}`}
                            className="px-3 py-1.5 text-xs font-medium rounded bg-red-600/10 text-red-600 border border-red-600/20 hover:bg-red-600/20 transition-colors"
                          >
                            📧 APWG
                          </a>
                          <a
                            href={`mailto:phishing-report@us-cert.gov?subject=Phishing%20Report&body=${encodeURIComponent(`URL: ${url}\n\n${notes || ''}`)}`}
                            className="px-3 py-1.5 text-xs font-medium rounded bg-slate-800/10 text-slate-800 border border-slate-800/20 hover:bg-slate-800/20 transition-colors"
                          >
                            🇺🇸 CISA/US-CERT
                          </a>
                          <a
                            href={`https://www.virustotal.com/gui/url/${Buffer.from(url).toString('base64').replace(/=+$/, '')}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-3 py-1.5 text-xs font-medium rounded bg-purple-600/10 text-purple-600 border border-purple-600/20 hover:bg-purple-600/20 transition-colors"
                          >
                            🦠 VirusTotal
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}