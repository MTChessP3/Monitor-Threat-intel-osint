'use client';

import React, { useState, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Upload, FileText, Shield, Send, Download, Printer, CheckCircle, XCircle,
  AlertCircle, Clock, Globe, Mail, Bug, Eye, RefreshCw, Trash2, Copy,
  ChevronDown, ChevronUp, Filter, List, Settings, Key, ExternalLink,
  ChevronRight, Layers, Loader2
} from 'lucide-react';

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

const URL_REGEX = /(?:https?:\/\/)?(?:www\.)?[\w-]+(?:\.[\w-]+)+(?:[\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?/gi;

function extractUrlsFromText(text: string): string[] {
  const urls = text.match(URL_REGEX) || [];
  const normalized = urls.map(u => {
    if (!u.startsWith('http://') && !u.startsWith('https://')) {
      return 'https://' + u;
    }
    return u;
  });
  return [...new Set(normalized)];
}

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
      alert('Formato no soportado. Use .txt, .csv o .xlsx');
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
        alert(`${data.validCount} URLs válidas extraídas de ${data.fileName}`);
        setActiveStep('review');
      } else {
        const errorData = await res.json();
        alert(errorData.error || 'Error al procesar el archivo');
      }
    } catch {
      alert('Error al subir el archivo');
    } finally {
      setIsProcessing(false);
      setProcessingProgress(0);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleTextPaste = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const textarea = form.querySelector('textarea');
    const text = textarea?.value || '';
    if (!text.trim()) return;

    setIsProcessing(true);
    setProcessingStep('Extrayendo URLs del texto...');
    setProcessingProgress(10);

    try {
      const urls = extractUrlsFromText(text);
      const validUrls = urls.filter(url => {
        try { new URL(url); return true; } catch { return false; }
      });
      const extractedUrls: ExtractedUrl[] = validUrls.map(url => ({ url, valid: true }));
      setExtractedUrls(extractedUrls);
      setSelectedUrls(new Set(validUrls));
      alert(`${validUrls.length} URLs válidas extraídas`);
      setActiveStep('review');
      if (textarea) textarea.value = '';
    } catch {
      alert('Error al procesar el texto');
    } finally {
      setIsProcessing(false);
      setProcessingProgress(0);
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

    const MAX_URLS = 50;

    if (urlsToReport.length === 0) {
      alert('Seleccione al menos una URL');
      return;
    }
    if (urlsToReport.length > MAX_URLS) {
      alert(`Demasiadas URLs seleccionadas (${urlsToReport.length}). Máximo ${MAX_URLS} por reporte para evitar timeout. Deseleccione algunas o divida en varios reportes.`);
      return;
    }
    if (servicesToReport.length === 0) {
      alert('Seleccione al menos un servicio');
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
        alert(`Reporte generado: ${data.summary.success} exitosos, ${data.summary.manual} manuales`);
      } else {
        const errorData = await res.json();
        alert(errorData.error || 'Error al generar reporte');
      }
    } catch {
      alert('Error de conexión');
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
        alert('Reporte HTML abierto en nueva pestaña');
      } else {
        alert('Error al generar reporte HTML');
      }
    } catch {
      alert('Error al generar reporte HTML');
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
        alert('Reporte HTML descargado');
      }
    } catch {
      alert('Error al descargar reporte');
    }
  };

  const copyFingerprint = () => {
    if (reportResult) {
      navigator.clipboard.writeText(reportResult.fingerprint);
      alert('Huella digital copiada al portapapeles');
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

  const renderStepIndicator = (step: number, label: string, completed: boolean, active: boolean) => (
    <div className="flex flex-col items-center">
      <div className={`w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold transition-all ${
        completed
          ? 'bg-green-500 text-white'
          : active
          ? 'bg-blue-600 text-white'
          : 'bg-gray-700 text-gray-400'
      }`}>
        {completed ? <CheckCircle className="w-5 h-5" /> : <span>{step}</span>}
      </div>
      <span className={`text-xs mt-2 font-medium ${active ? 'text-blue-400' : 'text-gray-500'}`}>{label}</span>
      {step !== 4 && (
        <div className={`w-px h-16 flex-1 ${completed ? 'bg-green-500' : 'bg-gray-700'}`} />
      )}
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-950 text-white p-4 md:p-8">
      {/* Header */}
      <div className="max-w-6xl mx-auto mb-8">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-3">
              <Shield className="w-8 h-8 text-green-400" />
              TakeDown URL
            </h1>
            <p className="text-gray-400 mt-1">
              Cargue URLs maliciosas y repórtelas a los principales servicios de seguridad
            </p>
          </div>
          {activeStep !== 'upload' && (
            <button
              onClick={resetAll}
              className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg transition-colors flex items-center gap-2"
            >
              <RefreshCw className="w-4 h-4" />
              Reiniciar
            </button>
          )}
        </div>

        {/* Step Indicator */}
        <div className="hidden md:flex items-center justify-center gap-0 px-4 mb-8">
          {['upload', 'review', 'services', 'report'].map((step, i) => (
            <React.Fragment key={step}>
              {renderStepIndicator(
                i + 1,
                ['Subir', 'Revisar', 'Servicios', 'Reportar'][i],
                ['upload', 'review', 'services'].includes(activeStep) && ['review', 'services', 'report'].indexOf(step) >= 0 ? false : 
                  ['upload', 'review', 'services'].indexOf(activeStep) > ['upload', 'review', 'services'].indexOf(step),
                activeStep === step
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      <div className="max-w-6xl mx-auto">
        <AnimatePresence mode="wait">
          {/* STEP 1: UPLOAD */}
          {activeStep === 'upload' && (
            <motion.div key="upload" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="bg-gray-900 rounded-2xl border border-gray-800 p-8">
              <div className="text-center mb-8">
                <Upload className="w-12 h-12 text-green-400 mx-auto mb-4" />
                <h2 className="text-2xl font-bold mb-2">Paso 1: Subir Archivo o Pegar URLs</h2>
                <p className="text-gray-400">Arrastre un archivo .txt, .csv, .xlsx o pegue URLs directamente</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {/* File Upload */}
                <div className="space-y-4">
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
                    className="w-full flex flex-col items-center justify-center gap-4 p-8 rounded-xl border-2 border-dashed border-green-500/30 hover:border-green-500 bg-green-500/5 hover:bg-green-500/10 transition-all duration-300 cursor-pointer"
                  >
                    {isProcessing ? (
                      <div className="flex flex-col items-center gap-3">
                        <div className="w-12 h-12 border-4 border-green-500/20 border-t-green-500 rounded-full animate-spin" />
                        <span className="text-gray-300 font-medium">{processingStep}</span>
                        <div className="w-64 h-2 bg-gray-800 rounded-full overflow-hidden">
                          <div className="h-full bg-green-500 rounded-full transition-all" style={{ width: `${processingProgress}%` }} />
                        </div>
                      </div>
                    ) : (
                      <>
                        <div className="w-20 h-20 rounded-full bg-green-500/10 flex items-center justify-center hover:bg-green-500/20 transition-colors">
                          <Upload className="w-10 h-10 text-green-400" />
                        </div>
                        <div className="text-center">
                          <p className="text-xl font-bold text-white">HAGA CLIC PARA SUBIR ARCHIVO</p>
                          <p className="text-sm text-gray-400 mt-2">Formatos: .txt, .csv, .xlsx (máx. 10MB)</p>
                        </div>
                      </>
                    )}
                  </button>
                  <p className="text-xs text-gray-500 text-center">El sistema detecta URLs automáticamente</p>
                </div>

                {/* Text Paste */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold flex items-center gap-2">
                    <FileText className="w-5 h-5 text-green-400" />
                    O pegue URLs directamente
                  </h3>
                  <form onSubmit={handleTextPaste} className="space-y-3">
                    <textarea
                      placeholder="https://ejemplo.com/malware&#10;http://phishing-site.com&#10;malicious-site.xyz&#10;... (una por línea o separadas por espacio/coma)"
                      className="w-full h-48 bg-gray-800 border border-gray-700 rounded-lg p-4 text-white placeholder-gray-500 font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500"
                      disabled={isProcessing}
                    />
                    <button
                      type="submit"
                      disabled={isProcessing}
                      className="w-full py-3 bg-green-600 hover:bg-green-700 text-white font-semibold rounded-lg transition-colors flex items-center justify-center gap-2"
                    >
                      {isProcessing ? (
                        <>
                          <Loader2 className="w-4 h-4 animate-spin" />
                          Procesando...
                        </>
                      ) : (
                        <>
                          <CheckCircle className="w-4 h-4" />
                          Extraer URLs
                        </>
                      )}
                    </button>
                  </form>
                </div>
              </div>

              {/* Services Preview */}
              <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-4">
                {SERVICE_OPTIONS.map(service => (
                  <div key={service.id} className="p-4 rounded-lg bg-gray-800/50 border border-gray-700">
                    <div className="flex items-center gap-3 mb-2">
                      <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center text-green-400">
                        {service.icon}
                      </div>
                      <span className="font-semibold">{service.name}</span>
                    </div>
                    <p className="text-sm text-gray-400">{service.description}</p>
                    {service.requiresApiKey && (
                      <span className="inline-block mt-2 px-2 py-1 text-xs bg-yellow-500/20 text-yellow-400 rounded">Requiere API Key</span>
                    )}
                  </div>
                ))}
              </div>
            </motion.div>
          )}

          {/* STEP 2: REVIEW URLs */}
          {activeStep === 'review' && (
            <motion.div key="review" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="space-y-6">
              <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6">
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <h2 className="text-2xl font-bold flex items-center gap-2">
                      <List className="w-6 h-6 text-green-400" />
                      Paso 2: Revisar URLs Extraídas
                    </h2>
                    <p className="text-gray-400 mt-1">
                      {extractedUrls.length} URLs totales ({validUrls.length} válidas, {invalidUrls.length} inválidas)
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={toggleSelectAllUrls}
                      className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm transition-colors flex items-center gap-1"
                    >
                      {selectedUrls.size === validUrls.length ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      {selectedUrls.size === validUrls.length ? 'Deseleccionar' : 'Seleccionar'} todas
                    </button>
                    <button
                      onClick={() => setActiveStep('services')}
                      className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white font-semibold rounded-lg transition-colors flex items-center gap-2"
                    >
                      Continuar <ChevronRight className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {validUrls.length > 0 && (
                  <div className="max-h-96 overflow-y-auto space-y-2">
                    {validUrls.map((url, i) => (
                      <motion.div
                        key={url}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.03 }}
                        className={`flex items-center gap-3 p-3 rounded-lg border transition-all ${
                          selectedUrls.has(url)
                            ? 'border-green-500/30 bg-green-500/5'
                            : 'border-gray-700 bg-gray-800/50 hover:bg-gray-800'
                        }`}
                        onClick={() => toggleUrlSelection(url)}
                      >
                        <div className={`shrink-0 w-5 h-5 rounded border-2 flex items-center justify-center transition-all ${
                          selectedUrls.has(url)
                            ? 'border-green-500 bg-green-500'
                            : 'border-gray-600'
                        }`}>
                          {selectedUrls.has(url) && <CheckCircle className="w-3.5 h-3.5 text-gray-900" />}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-mono text-white truncate">{url}</p>
                        </div>
                        <span className="px-2 py-0.5 text-xs rounded bg-green-500/20 text-green-400 border border-green-500/30 shrink-0">
                          Válida
                        </span>
                      </motion.div>
                    ))}
                  </div>
                )}

                {invalidUrls.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-sm text-gray-400 flex items-center gap-1">
                      <AlertCircle className="w-4 h-4" />
                      URLs inválidas detectadas ({invalidUrls.length})
                    </p>
                    <div className="max-h-40 overflow-y-auto space-y-1">
                      {invalidUrls.map((url, i) => (
                        <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-red-500/10 border border-red-500/20">
                          <XCircle className="w-4 h-4 text-red-500 shrink-0" />
                          <span className="text-sm font-mono text-red-400 truncate flex-1">{url}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {validUrls.length === 0 && (
                  <div className="text-center py-12 text-gray-400">
                    <AlertCircle className="w-12 h-12 mx-auto mb-3 opacity-30" />
                    <p className="text-sm">No se encontraron URLs válidas</p>
                    <button
                      onClick={() => setActiveStep('upload')}
                      className="mt-4 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg transition-colors"
                    >
                      Subir otro archivo
                    </button>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {/* STEP 3: SELECT SERVICES */}
          {activeStep === 'services' && (
            <motion.div key="services" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="space-y-6">
              <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6">
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <h2 className="text-2xl font-bold flex items-center gap-2">
                      <Settings className="w-6 h-6 text-green-400" />
                      Paso 3: Seleccionar Servicios de Reporte
                    </h2>
                    <p className="text-gray-400 mt-1">
                      {selectedUrls.size} URL(s) seleccionada(s). Elija a qué servicios enviar el reporte.
                    </p>
                  </div>
                  <button
                    onClick={() => setActiveStep('report')}
                    className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white font-semibold rounded-lg transition-colors flex items-center gap-2"
                  >
                    Generar Reporte <Send className="w-4 h-4" />
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                  {SERVICE_OPTIONS.map((service) => {
                    const isSelected = selectedServices.has(service.id);
                    return (
                      <button
                        key={service.id}
                        onClick={() => toggleServiceSelection(service.id)}
                        className={`relative p-5 rounded-xl border-2 transition-all flex flex-col gap-3 ${
                          isSelected
                            ? 'border-green-500/30 bg-green-500/5 shadow-sm shadow-green-500/5'
                            : 'border-gray-700 bg-gray-800/50 hover:border-green-500/30 hover:bg-gray-800'
                        }`}
                      >
                        <div className="flex items-start gap-3">
                          <div className={`shrink-0 w-10 h-10 rounded-lg flex items-center justify-center ${
                            isSelected ? 'bg-green-500/10 text-green-400' : 'bg-gray-800 text-gray-500'
                          }`}>
                            {service.icon}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className={`font-medium ${isSelected ? 'text-white' : 'text-gray-400'}`}>
                                {service.name}
                              </span>
                              {service.requiresApiKey && (
                                <span className="px-2 py-0.5 text-xs bg-yellow-500/20 text-yellow-400 rounded">
                                  <Key className="w-2.5 h-2.5 mr-1" />
                                  API Key
                                </span>
                              )}
                            </div>
                            <p className="text-xs text-gray-500 mt-1">{service.description}</p>
                          </div>
                        </div>
                        <div className={`absolute top-3 right-3 w-6 h-6 rounded-full border-2 flex items-center justify-center transition-all ${
                          isSelected
                            ? 'border-green-500 bg-green-500'
                            : 'border-gray-600'
                        }`}>
                          {isSelected && <CheckCircle className="w-4 h-4 text-gray-900" />}
                        </div>
                      </button>
                    );
                  })}
                </div>

                {(selectedServices.has('google') || selectedServices.has('virustotal')) && (
                  <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4 mb-6">
                    <h3 className="font-semibold flex items-center gap-2 text-yellow-400 mb-3">
                      <Key className="w-5 h-5" />
                      Configuración de API Keys (Opcional)
                    </h3>
                    <p className="text-sm text-gray-400 mb-4">
                      Para reportes automáticos en Google Safe Browsing y VirusTotal. Sin API Key, se generarán enlaces para reporte manual.
                    </p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {selectedServices.has('google') && (
                        <div className="space-y-1">
                          <label className="text-xs text-gray-400 block">Google Safe Browsing API Key</label>
                          <input
                            type="password"
                            placeholder="Ingrese su API Key de Google Cloud"
                            value={apiKeys.google}
                            onChange={(e) => setApiKeys(prev => ({ ...prev, google: e.target.value }))}
                            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500"
                          />
                        </div>
                      )}
                      {selectedServices.has('virustotal') && (
                        <div className="space-y-1">
                          <label className="text-xs text-gray-400 block">VirusTotal API Key</label>
                          <input
                            type="password"
                            placeholder="Ingrese su API Key de VirusTotal"
                            value={apiKeys.virustotal}
                            onChange={(e) => setApiKeys(prev => ({ ...prev, virustotal: e.target.value }))}
                            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500"
                          />
                        </div>
                      )}
                    </div>
                  </div>
                )}

                <div className="space-y-3">
                  <label className="text-xs text-gray-400 block">Notas adicionales (opcional)</label>
                  <textarea
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    placeholder="Información adicional para incluir en los reportes por email (APWG, CISA)..."
                    className="w-full h-24 bg-gray-800 border border-gray-700 rounded-lg p-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500"
                    rows={3}
                  />
                </div>
              </div>
            </motion.div>
          )}

          {/* STEP 4: REPORT PROCESSING */}
          {activeStep === 'report' && (
            <motion.div key="report" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="space-y-6">
              <div className="bg-gray-900 rounded-2xl border border-gray-800 p-8">
                <h2 className="text-2xl font-bold flex items-center gap-2 mb-2">
                  <Send className="w-6 h-6 text-green-400" />
                  Paso 4: Procesando Reportes
                </h2>
                <p className="text-gray-400 mb-8">
                  Enviando {selectedUrls.size} URL(s) a {selectedServices.size} servicio(s)...
                </p>

                <div className="flex flex-col items-center gap-6 py-8">
                  <div className="w-20 h-20 border-4 border-gray-700 border-t-green-500 rounded-full animate-spin" />
                  <div className="text-center">
                    <p className="text-lg font-medium text-white">{processingStep || 'Iniciando...'}</p>
                    <div className="w-64 h-3 bg-gray-800 rounded-full overflow-hidden mt-2">
                      <div className="h-full bg-green-500 rounded-full transition-all" style={{ width: `${processingProgress}%` }} />
                    </div>
                    <p className="text-sm text-gray-400 mt-2">{processingProgress}% completado</p>
                  </div>
                </div>

                {reportResult && (
                  <div className="p-4 rounded-lg bg-green-500/10 border border-green-500/30">
                    <div className="flex items-center gap-3">
                      <CheckCircle className="w-6 h-6 text-green-500" />
                      <div>
                        <p className="font-medium text-green-400">¡Reporte completado exitosamente!</p>
                        <p className="text-sm text-green-500/80 mt-1">
                          ID: {reportResult.reportId} | {reportResult.summary.success} exitosos, {reportResult.summary.manual} manuales, {reportResult.summary.failed} fallidos
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {/* STEP 5: RESULTS */}
          {reportResult && activeStep !== 'report' && (
            <motion.div key="result" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="space-y-6">
              <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6">
                <div className="flex items-center justify-between flex-wrap gap-4 mb-6">
                  <div>
                    <h2 className="text-2xl font-bold flex items-center gap-2">
                      <CheckCircle className="w-6 h-6 text-green-400" />
                      Reporte Completado
                    </h2>
                    <p className="text-gray-400 mt-1">
                      ID: {reportResult.reportId} • {new Date(reportResult.timestamp).toLocaleString('es-ES')}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <button
                      onClick={generateHtmlReport}
                      className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg transition-colors flex items-center gap-2"
                    >
                      <Eye className="w-4 h-4" />
                      Ver HTML
                    </button>
                    <button
                      onClick={downloadReport}
                      className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg transition-colors flex items-center gap-2"
                    >
                      <Download className="w-4 h-4" />
                      Descargar HTML
                    </button>
                    <button
                      onClick={copyFingerprint}
                      className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg transition-colors flex items-center gap-2"
                    >
                      <Copy className="w-4 h-4" />
                      Copiar Fingerprint
                    </button>
                  </div>
                </div>

                {/* Summary Cards */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                  {[
                    { label: 'Total', value: reportResult.summary.total, color: 'bg-gray-500' },
                    { label: 'Éxitos', value: reportResult.summary.success, color: 'bg-green-500' },
                    { label: 'Manuales', value: reportResult.summary.manual, color: 'bg-blue-500' },
                    { label: 'Pendientes', value: reportResult.summary.pending, color: 'bg-yellow-500' },
                    { label: 'Fallidos', value: reportResult.summary.failed, color: 'bg-red-500' },
                  ].map((stat) => (
                    <div key={stat.label} className="p-4 rounded-xl text-center" style={{ background: `${stat.color}20`, border: `1px solid ${stat.color}40` }}>
                      <div className="text-3xl font-bold" style={{ color: stat.color }}>{stat.value}</div>
                      <div className="text-xs font-medium mt-1" style={{ color: stat.color }}>{stat.label}</div>
                    </div>
                  ))}
                </div>

                {/* Fingerprint */}
                <div className="p-4 rounded-lg bg-gray-950 border border-green-500/30 mb-6">
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-xs text-green-400 flex items-center gap-1">
                      <Shield className="w-3 h-3" />
                      Huella Digital SHA-256 (Integridad del Reporte)
                    </label>
                    <button
                      onClick={copyFingerprint}
                      className="px-3 py-1.5 text-xs text-green-400 hover:text-green-300 transition-colors flex items-center gap-1"
                    >
                      <Copy className="w-3 h-3" />
                      Copiar
                    </button>
                  </div>
                  <code className="font-mono text-xs text-green-300 break-all">{reportResult.fingerprint}</code>
                  <p className="text-xs text-green-500/60 mt-2">Verifique la integridad de este reporte comparando esta huella digital</p>
                </div>

                {/* Results Tabs */}
                <div className="border-t border-gray-800 pt-6">
                  <div className="flex gap-2 mb-4">
                    <button className="px-4 py-2 bg-green-600 text-white rounded-lg font-medium">Tabla Consolidada</button>
                    <button className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg font-medium">Detalle por URL</button>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-gray-800 bg-gray-900">
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
                            <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/50">
                              <td className="p-3 font-medium">{r.service}</td>
                              <td className="p-3 font-mono text-xs truncate max-w-xs">{r.url}</td>
                              <td className="p-3 text-center">
                                <span className={`inline-block px-2 py-1 rounded-full text-xs font-medium ${config.color}`}>
                                  <Icon className="w-3 h-3 mr-1 inline-block" />
                                  {config.label}
                                </span>
                              </td>
                              <td className="p-3 text-gray-400 max-w-md">{r.message}</td>
                              <td className="p-3 font-mono text-xs text-gray-500">{new Date(r.timestamp).toLocaleString('es-ES')}</td>
                              <td className="p-3 font-mono text-xs text-gray-500">{r.referenceId || '-'}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Manual Report Links */}
                <div className="pt-6 border-t border-gray-800">
                  <h3 className="font-medium mb-4 flex items-center gap-2">
                    <ExternalLink className="w-4 h-4" />
                    Enlaces Directos para Reportes Manuales
                  </h3>
                  <div className="space-y-3">
                    {reportResult.urls.map((url, urlIndex) => (
                      <div key={urlIndex} className="p-4 rounded-lg bg-gray-800/50 border border-gray-700">
                        <p className="font-mono text-sm text-green-400 mb-3 truncate" title={url}>{url}</p>
                        <div className="flex flex-wrap gap-2">
                          <a
                            href={`https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(url)}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-3 py-1.5 text-xs font-medium rounded bg-blue-600/20 text-blue-400 border border-blue-600/30 hover:bg-blue-600/30 transition-colors"
                          >
                            🛡️ Google Safe Browsing
                          </a>
                          <a
                            href="https://www.microsoft.com/wdsi/support/report-unsafe-site"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-3 py-1.5 text-xs font-medium rounded bg-blue-700/20 text-blue-300 border border-blue-700/30 hover:bg-blue-700/30 transition-colors"
                          >
                            🔷 Microsoft SmartScreen
                          </a>
                          <a
                            href={`mailto:reportphishing@apwg.org?subject=Phishing%20Report&body=${encodeURIComponent(`URL: ${url}\n\n${notes || ''}`)}`}
                            className="px-3 py-1.5 text-xs font-medium rounded bg-red-600/20 text-red-400 border border-red-600/30 hover:bg-red-600/30 transition-colors"
                          >
                            📧 APWG
                          </a>
                          <a
                            href={`mailto:phishing-report@us-cert.gov?subject=Phishing%20Report&body=${encodeURIComponent(`URL: ${url}\n\n${notes || ''}`)}`}
                            className="px-3 py-1.5 text-xs font-medium rounded bg-gray-800 text-gray-300 border border-gray-700 hover:bg-gray-700 transition-colors"
                          >
                            🇺🇸 CISA/US-CERT
                          </a>
                          <a
                            href={`https://www.virustotal.com/gui/url/${Buffer.from(url).toString('base64').replace(/=+$/, '')}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-3 py-1.5 text-xs font-medium rounded bg-purple-600/20 text-purple-400 border border-purple-600/30 hover:bg-purple-600/30 transition-colors"
                          >
                            🦠 VirusTotal
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

export default TakeDownPanel;