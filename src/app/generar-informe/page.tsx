'use client';

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, AlertTriangle, FileText, Globe, Brain, Download,
  Plus, Trash2, Search, Loader2, CheckCircle, XCircle,
  Zap, ChevronRight, FileEdit, Lock, Eye, Play,
  ToggleLeft, ToggleRight, ListChecks, Filter, Info,
  Link as LinkIcon, Upload, File, X, FileUp, ClipboardPaste,
  AlertCircle, Paperclip
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import { toast } from 'sonner';
import ReactMarkdown from 'react-markdown';
import NextLink from 'next/link';
import { ThemeSelector } from '@/components/ThemeSelector';

// ============================================================================
// TYPES
// ============================================================================
interface AuthUser {
  id: string;
  name: string;
  email: string;
  role: string;
  mfaEnabled: boolean;
}

interface UploadedFile {
  id: string;
  name: string;
  size: number;
  content: string;
  type: string;
}

// ============================================================================
// CONSTANTS - Abuse Types
// ============================================================================
const ABUSE_TYPES = [
  { id: 'phishing', label: 'Phishing', icon: '🎣', color: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30' },
  { id: 'identity_theft', label: 'Suplantación de Identidad', icon: '🎭', color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  { id: 'financial_fraud', label: 'Fraude Financiero', icon: '💰', color: 'bg-primary/12 text-primary border-primary/15' },
  { id: 'social_media_scam', label: 'Estafas en Redes Sociales', icon: '📱', color: 'bg-pink-500/20 text-pink-400 border-pink-500/30' },
  { id: 'brand_abuse', label: 'Abuso de Marca', icon: '🏷️', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  { id: 'malware', label: 'Malware', icon: '🦠', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
  { id: 'ransomware', label: 'Ransomware', icon: '🔒', color: 'bg-red-600/20 text-red-500 border-red-600/30' },
  { id: 'social_engineering', label: 'Ingeniería Social', icon: '🎭', color: 'bg-violet-500/20 text-violet-400 border-violet-500/30' },
  { id: 'data_breach', label: 'Fuga de Datos', icon: '📂', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  { id: 'insider_threat', label: 'Amenaza Interna', icon: '👤', color: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30' },
  { id: 'ddos', label: 'Ataque DDoS', icon: '💥', color: 'bg-rose-500/20 text-rose-400 border-rose-500/30' },
  { id: 'supply_chain', label: 'Ataque a Cadena de Suministro', icon: '🔗', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' },
];

const SEVERITY_LEVELS = [
  { id: 'bajo', label: 'Bajo', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30', dot: 'bg-emerald-500' },
  { id: 'medio', label: 'Medio', color: 'bg-primary/12 text-primary border-primary/15', dot: 'bg-primary' },
  { id: 'alto', label: 'Alto', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30', dot: 'bg-orange-500' },
  { id: 'critico', label: 'Crítico', color: 'bg-red-500/20 text-red-400 border-red-500/30', dot: 'bg-red-500' },
];

const TLP_LEVELS = [
  { id: 'RED', label: 'TLP:RED', description: 'Solo destinatarios específicos. No redistribuir.', color: 'bg-red-600 text-white border-red-600', ring: 'ring-red-600' },
  { id: 'AMBER', label: 'TLP:AMBER', description: 'Uso limitado dentro de la organización.', color: 'bg-primary text-white border-primary', ring: 'ring-primary' },
  { id: 'GREEN', label: 'TLP:GREEN', description: 'Comunidad de interés. Compartir con pares.', color: 'bg-emerald-500 text-white border-emerald-500', ring: 'ring-emerald-500' },
  { id: 'CLEAR', label: 'TLP:CLEAR', description: 'Información pública. Sin restricciones.', color: 'bg-gray-200 text-gray-800 border-gray-300', ring: 'ring-gray-300' },
];

const ACCEPTED_FILE_TYPES = ['.txt', '.md', '.csv', '.log', '.pdf', '.docx', '.json', '.xml'];
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function getFileIcon(name: string): string {
  const ext = name.split('.').pop()?.toLowerCase() || '';
  const icons: Record<string, string> = {
    txt: '📄', md: '📝', csv: '📊', log: '📋', pdf: '📕', docx: '📘', json: '🔧', xml: '📰',
  };
  return icons[ext] || '📎';
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================
export default function GenerarInformePage() {
  // Auth
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [authLoading, setAuthLoading] = useState(true);

  // Mode toggle
  const [mode, setMode] = useState<'automatic' | 'manual'>('automatic');

  // Data Ingestion
  const [urlInputs, setUrlInputs] = useState<string[]>(['']);
  const [writtenData, setWrittenData] = useState('');
  const [reportTitle, setReportTitle] = useState('');

  // File uploads
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Manual mode selections
  const [selectedAbuseTypes, setSelectedAbuseTypes] = useState<Set<string>>(new Set());
  const [selectedSeverity, setSelectedSeverity] = useState('medio');
  const [selectedTlp, setSelectedTlp] = useState('GREEN');

  // Generation state
  const [isGenerating, setIsGenerating] = useState(false);
  const [generationProgress, setGenerationProgress] = useState(0);
  const [generationStep, setGenerationStep] = useState('');

  // Result
  const [generatedReport, setGeneratedReport] = useState<any>(null);
  const [showResult, setShowResult] = useState(false);

  // Check auth — resilient with caching and retry
  useEffect(() => {
    const initSession = async () => {
      try {
        const { checkSession: checkSess, clearCachedUser } = await import('@/lib/session-manager');
        const user = await checkSess(2);
        if (user) {
          setAuthUser(user);
        } else {
          clearCachedUser();
          window.location.href = '/auth/login';
        }
      } catch {
        // Fallback: direct API call with 401-only redirect
        try {
          const res = await fetch('/api/auth/session');
          if (res.ok) {
            const data = await res.json();
            setAuthUser(data.user);
          } else if (res.status === 401) {
            window.location.href = '/auth/login';
          }
          // Non-401 errors: don't redirect, keep user on page
        } catch {
          // Network error: don't redirect, might be temporary
        }
      } finally {
        setAuthLoading(false);
      }
    };
    initSession();
  }, []);

  // URL management
  const addUrlField = () => setUrlInputs([...urlInputs, '']);
  const removeUrlField = (index: number) => {
    if (urlInputs.length <= 1) return;
    setUrlInputs(urlInputs.filter((_, i) => i !== index));
  };
  const updateUrl = (index: number, value: string) => {
    const newUrls = [...urlInputs];
    newUrls[index] = value;
    setUrlInputs(newUrls);
  };

  // Abuse type toggle
  const toggleAbuseType = (id: string) => {
    setSelectedAbuseTypes(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  // Validate URLs
  const isValidUrl = (url: string): boolean => {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  };

  // ---- FILE UPLOAD HANDLING ----
  const processFile = async (file: File): Promise<UploadedFile | null> => {
    const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    if (!ACCEPTED_FILE_TYPES.includes(ext)) {
      toast.error(`Formato no soportado: ${ext}. Use: ${ACCEPTED_FILE_TYPES.join(', ')}`);
      return null;
    }
    if (file.size > MAX_FILE_SIZE) {
      toast.error(`Archivo demasiado grande: ${file.name} (${formatFileSize(file.size)}). Máximo 10MB.`);
      return null;
    }

    try {
      const formData = new FormData();
      formData.append('file', file);

      const res = await fetch('/api/upload-template', {
        method: 'POST',
        body: formData,
      });

      if (res.ok) {
        const data = await res.json();
        return {
          id: `file-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          name: file.name,
          size: file.size,
          content: data.text,
          type: ext.replace('.', ''),
        };
      } else {
        const errorData = await res.json();
        toast.error(errorData.error || `Error al procesar ${file.name}`);
        return null;
      }
    } catch {
      toast.error(`Error al subir ${file.name}`);
      return null;
    }
  };

  const handleFileUpload = async (files: FileList | File[]) => {
    setIsUploading(true);
    const fileArray = Array.from(files);
    let successCount = 0;

    for (const file of fileArray) {
      const result = await processFile(file);
      if (result) {
        setUploadedFiles(prev => [...prev, result]);
        successCount++;
      }
    }

    if (successCount > 0) {
      toast.success(`${successCount} archivo(s) cargado(s) exitosamente`);
    }
    setIsUploading(false);

    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const removeFile = (id: string) => {
    setUploadedFiles(prev => prev.filter(f => f.id !== id));
  };

  const clearAllFiles = () => {
    setUploadedFiles([]);
  };

  // Drag & Drop handlers
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files);
    }
  }, [uploadedFiles]);

  // Calculate total data size
  const totalFileChars = uploadedFiles.reduce((sum, f) => sum + f.content.length, 0);
  const totalDataChars = totalFileChars + writtenData.length;
  const validUrls = urlInputs.filter(u => u.trim() && isValidUrl(u)).length;
  const hasDataForAgent = validUrls > 0 || writtenData.trim().length > 0 || uploadedFiles.length > 0;

  // Build combined text from all sources for the AI agent
  const buildCombinedData = (): string => {
    let combined = '';

    // Add file contents
    if (uploadedFiles.length > 0) {
      combined += '=== ARCHIVOS CARGADOS ===\n\n';
      for (const file of uploadedFiles) {
        combined += `--- Archivo: ${file.name} (${formatFileSize(file.size)}) ---\n`;
        combined += file.content;
        combined += '\n\n';
      }
    }

    // Add written data
    if (writtenData.trim()) {
      combined += '=== DATOS ESCRITOS POR EL ANALISTA ===\n\n';
      combined += writtenData.trim();
      combined += '\n\n';
    }

    return combined;
  };

  // Handle generation
  const handleGenerate = async () => {
    const urlList = urlInputs.map(u => u.trim()).filter(u => u.length > 0);

    // Validate
    if (mode === 'automatic') {
      if (!hasDataForAgent) {
        toast.error('Proporcione al menos un archivo, URL o datos escritos para que el agente de IA analice');
        return;
      }
      // Check URL validity
      const invalidUrls = urlList.filter(u => !isValidUrl(u));
      if (invalidUrls.length > 0) {
        toast.error(`URL(s) inválida(s): ${invalidUrls.join(', ')}`);
        return;
      }
    } else {
      if (selectedAbuseTypes.size === 0) {
        toast.error('Seleccione al menos un tipo de amenaza');
        return;
      }
      if (!selectedSeverity) {
        toast.error('Seleccione un nivel de severidad');
        return;
      }
      if (!selectedTlp) {
        toast.error('Seleccione un protocolo TLP');
        return;
      }
    }

    setIsGenerating(true);
    setGenerationProgress(0);
    setShowResult(false);

    try {
      setGenerationStep(mode === 'automatic' ? 'Inicializando Agente de Inteligencia...' : 'Generando informe con clasificación manual...');
      setGenerationProgress(10);

      await new Promise(r => setTimeout(r, 300));

      if (mode === 'automatic') {
        setGenerationStep('Fase 1/4: Leyendo contenido real de las URLs proporcionadas...');
        setGenerationProgress(20);
        await new Promise(r => setTimeout(r, 500));
        setGenerationStep('Fase 2/4: Extrayendo entidades clave - identificando al VIP y datos expuestos...');
        setGenerationProgress(35);
        await new Promise(r => setTimeout(r, 500));
        setGenerationStep('Fase 3/4: Cruzando información con fuentes OSINT complementarias...');
        setGenerationProgress(50);
        await new Promise(r => setTimeout(r, 500));
        setGenerationStep('Fase 4/4: Análisis profundo de inteligencia - generando informe comprehensivo...');
        setGenerationProgress(65);
      }

      const combinedWrittenData = buildCombinedData();

      const res = await fetch('/api/generate-intel-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode,
          urls: urlList,
          writtenData: combinedWrittenData,
          abuseTypes: Array.from(selectedAbuseTypes),
          severity: selectedSeverity,
          tlpLevel: selectedTlp,
          title: reportTitle.trim() || undefined,
          fileNames: uploadedFiles.map(f => f.name),
        }),
      });

      setGenerationProgress(85);

      if (!res.ok) {
        const errorData = await res.json();
        toast.error(errorData.error || 'Error al generar informe');
        return;
      }

      const data = await res.json();
      setGenerationProgress(100);
      setGenerationStep('Informe generado exitosamente');
      setGeneratedReport(data);
      setShowResult(true);
      toast.success('Informe generado exitosamente');
    } catch {
      toast.error('Error de conexión al generar informe');
    } finally {
      setIsGenerating(false);
    }
  };

  // Download handlers
  const handleDownloadPDF = async () => {
    if (!generatedReport?.report?.id) return;
    try {
      const res = await fetch('/api/export-pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reportId: generatedReport.report.id }),
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${generatedReport.report.title.replace(/[^a-zA-Z0-9áéíóúñÁÉÍÓÚÑ ]/g, '')}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast.success('PDF descargado');
      }
    } catch {
      toast.error('Error al descargar PDF');
    }
  };

  const handleDownloadDOCX = async () => {
    if (!generatedReport?.report?.id) return;
    try {
      const res = await fetch('/api/export-docx', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reportId: generatedReport.report.id }),
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${generatedReport.report.title.replace(/[^a-zA-Z0-9áéíóúñÁÉÍÓÚÑ ]/g, '')}.docx`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast.success('DOCX descargado');
      }
    } catch {
      toast.error('Error al descargar DOCX');
    }
  };

  const handleDownloadMD = () => {
    if (!generatedReport?.report?.content) return;
    const blob = new Blob([generatedReport.report.content], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${generatedReport.report.title.replace(/[^a-zA-Z0-9áéíóúñÁÉÍÓÚÑ ]/g, '')}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success('Markdown descargado');
  };

  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept={ACCEPTED_FILE_TYPES.join(',')}
        onChange={(e) => e.target.files && handleFileUpload(e.target.files)}
        className="hidden"
      />

      {/* Top Navigation */}
      <header className="sticky top-0 z-30 border-b border-border bg-background/80 backdrop-blur-md">
        <div className="flex items-center justify-between px-4 lg:px-8 py-4">
          <div className="flex items-center gap-4">
            <NextLink href="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
              <div className="w-10 h-10 rounded-lg overflow-hidden flex items-center justify-center">
                <img src="/favicon-64x64.png" alt="VIP-Intelligence" className="w-10 h-10" />
              </div>
              <div>
                <h1 className="text-sm font-bold text-foreground tracking-wide">VIP-Intelligence</h1>
                <p className="text-xs text-primary font-medium">Protección Digital de Ejecutivos</p>
              </div>
            </NextLink>
            <Separator orientation="vertical" className="h-8 hidden sm:block" />
            <div className="hidden sm:block">
              <h2 className="text-lg font-bold text-foreground">Generar Informe de Inteligencia</h2>
              <p className="text-xs text-muted-foreground">Módulo de Generación AI-Driven & Manual</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Badge variant="outline" className="text-xs bg-primary/8 text-primary border-primary/12">
              <Shield className="w-3 h-3 mr-1" />
              Clasificado
            </Badge>
            <ThemeSelector compact />
            <NextLink href="/">
              <Button variant="outline" size="sm" className="border-border hover:border-primary/15">
                ← Volver al Panel
              </Button>
            </NextLink>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto p-4 lg:p-8 space-y-6">
        <AnimatePresence mode="wait">
          {!showResult ? (
            <motion.div
              key="form"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.15 }}
              className="space-y-6"
            >
              {/* ====== SECTION 1: DATA INGESTION - FILES ====== */}
              <Card className="border-border bg-card/80 border-primary/12">
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <FileUp className="w-5 h-5 text-primary" />
                    Cargar Datos para el Agente de IA
                  </CardTitle>
                  <CardDescription>
                    Suba archivos (TXT, MD, CSV, LOG, PDF, DOCX, JSON, XML) o pegue texto crudo. El agente de IA analizará toda esta información para construir su informe de inteligencia.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {/* Title */}
                  <div className="space-y-2">
                    <Label className="text-muted-foreground text-sm">Título del Informe (opcional)</Label>
                    <Input
                      placeholder="Ej: Informe de Inteligencia - Amenazas Q2 2026"
                      value={reportTitle}
                      onChange={(e) => setReportTitle(e.target.value)}
                      className="bg-muted/30 border-border focus:border-primary/50"
                    />
                  </div>

                  {/* Drag & Drop Zone */}
                  <div className="space-y-3">
                    <Label className="text-muted-foreground text-sm flex items-center gap-2">
                      <Paperclip className="w-3 h-3" />
                      Archivos - Cargue documentos para que el agente IA los analice
                    </Label>
                    <div
                      onDragOver={handleDragOver}
                      onDragLeave={handleDragLeave}
                      onDrop={handleDrop}
                      onClick={() => fileInputRef.current?.click()}
                      className={`relative border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all duration-300 ${
                        isDragOver
                          ? 'border-primary bg-primary/8 scale-[1.01]'
                          : 'border-border bg-muted/10 hover:border-primary/50 hover:bg-primary/5'
                      }`}
                    >
                      <div className="flex flex-col items-center gap-3">
                        <div className={`w-14 h-14 rounded-2xl flex items-center justify-center transition-colors ${
                          isDragOver ? 'primary-gradient' : 'bg-muted/50'
                        }`}>
                          <Upload className={`w-7 h-7 ${isDragOver ? 'text-primary-foreground' : 'text-muted-foreground'}`} />
                        </div>
                        <div>
                          <p className={`font-semibold text-sm ${isDragOver ? 'text-primary' : 'text-foreground'}`}>
                            {isDragOver ? 'Suelte los archivos aquí' : 'Arrastre archivos aquí o haga clic para seleccionar'}
                          </p>
                          <p className="text-xs text-muted-foreground mt-1">
                            TXT, MD, CSV, LOG, PDF, DOCX, JSON, XML — Máximo 10MB por archivo
                          </p>
                        </div>
                        {isUploading && (
                          <div className="flex items-center gap-2 text-primary">
                            <Loader2 className="w-4 h-4 animate-spin" />
                            <span className="text-xs">Procesando archivo(s)...</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Uploaded Files List */}
                  {uploadedFiles.length > 0 && (
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <Label className="text-muted-foreground text-sm flex items-center gap-2">
                          <FileText className="w-3 h-3" />
                          Archivos cargados ({uploadedFiles.length})
                        </Label>
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-xs bg-primary/8 text-primary border-primary/12">
                            {formatFileSize(uploadedFiles.reduce((s, f) => s + f.size, 0))} total
                          </Badge>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={clearAllFiles}
                            className="text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10"
                          >
                            <Trash2 className="w-3 h-3 mr-1" />
                            Limpiar todo
                          </Button>
                        </div>
                      </div>
                      <div className="space-y-2">
                        {uploadedFiles.map((file) => (
                          <div
                            key={file.id}
                            className="flex items-center gap-3 p-3 rounded-lg bg-muted/20 border border-border hover:border-primary/15 transition-colors"
                          >
                            <span className="text-xl">{getFileIcon(file.name)}</span>
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium text-foreground truncate">{file.name}</p>
                              <p className="text-xs text-muted-foreground">
                                {formatFileSize(file.size)} — {file.content.length.toLocaleString()} caracteres extraídos
                              </p>
                            </div>
                            <Badge variant="outline" className="text-xs shrink-0">
                              .{file.type}
                            </Badge>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => removeFile(file.id)}
                              className="text-muted-foreground hover:text-red-400 shrink-0 h-8 w-8 p-0"
                            >
                              <X className="w-4 h-4" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Written Data / Paste Area */}
                  <div className="space-y-2">
                    <Label className="text-muted-foreground text-sm flex items-center gap-2">
                      <ClipboardPaste className="w-3 h-3" />
                      Dato Escrito - Pegue aquí logs, notas, transcripciones, reportes o texto crudo
                    </Label>
                    <Textarea
                      placeholder="Pegue aquí cualquier información que desee que el agente de IA analice: logs de seguridad, transcripciones de comunicaciones, notas de campo, observaciones del analista, reportes previos, correos sospechosos, datos OSINT, etc..."
                      value={writtenData}
                      onChange={(e) => setWrittenData(e.target.value)}
                      className="bg-muted/30 border-border focus:border-primary/50 min-h-[200px] font-mono text-sm"
                    />
                    <div className="flex items-center justify-between">
                      <p className="text-xs text-muted-foreground">
                        {writtenData.length.toLocaleString()} caracteres ingresados
                      </p>
                      {writtenData.length > 0 && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setWrittenData('')}
                          className="text-xs text-muted-foreground hover:text-red-400"
                        >
                          <Trash2 className="w-3 h-3 mr-1" />
                          Limpiar texto
                        </Button>
                      )}
                    </div>
                  </div>

                  {/* URL Fields */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <Label className="text-muted-foreground text-sm flex items-center gap-2">
                        <LinkIcon className="w-3 h-3" />
                        URLs - Fuentes de inteligencia en línea
                      </Label>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={addUrlField}
                        className="text-primary hover:text-primary text-xs"
                      >
                        <Plus className="w-3 h-3 mr-1" />
                        Añadir URL
                      </Button>
                    </div>
                    {urlInputs.map((url, index) => (
                      <div key={index} className="flex gap-2">
                        <div className="flex-1 relative">
                          <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                          <Input
                            placeholder="https://ejemplo.com/fuente-de-inteligencia"
                            value={url}
                            onChange={(e) => updateUrl(index, e.target.value)}
                            className={`pl-10 bg-muted/30 border-border focus:border-primary/50 ${
                              url && !isValidUrl(url) ? 'border-red-500/50 focus:border-red-500' : ''
                            }`}
                          />
                          {url && !isValidUrl(url) && (
                            <p className="text-xs text-red-400 mt-1 ml-1">URL inválida</p>
                          )}
                        </div>
                        {urlInputs.length > 1 && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => removeUrlField(index)}
                            className="text-muted-foreground hover:text-red-400 shrink-0"
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        )}
                      </div>
                    ))}
                  </div>

                  {/* Data Summary Panel */}
                  <div className="p-4 rounded-lg bg-primary/5 border border-primary/12">
                    <div className="flex items-center gap-2 mb-3">
                      <Brain className="w-4 h-4 text-primary" />
                      <p className="text-sm font-medium text-primary">Resumen de datos para el Agente de IA</p>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div className="p-3 rounded-lg bg-muted/30 border border-border text-center">
                        <p className="text-lg font-bold text-foreground">{uploadedFiles.length}</p>
                        <p className="text-xs text-muted-foreground">Archivos</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border text-center">
                        <p className="text-lg font-bold text-foreground">
                          {writtenData.length > 0 ? 'Sí' : 'No'}
                        </p>
                        <p className="text-xs text-muted-foreground">Texto crudo</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border text-center">
                        <p className="text-lg font-bold text-foreground">{validUrls}</p>
                        <p className="text-xs text-muted-foreground">URLs válidas</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border text-center">
                        <p className="text-lg font-bold text-primary">
                          {totalDataChars > 0 ? `${(totalDataChars / 1000).toFixed(1)}K` : '0'}
                        </p>
                        <p className="text-xs text-muted-foreground">Caracteres totales</p>
                      </div>
                    </div>
                    {!hasDataForAgent && (
                      <div className="flex items-center gap-2 mt-3 p-2 rounded-md bg-red-500/10 border border-red-500/20">
                        <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                        <p className="text-xs text-red-400">Debe proporcionar al menos un archivo, texto o URL para que el agente analice</p>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* ====== SECTION 2: MODE TOGGLE ====== */}
              <Card className="border-border bg-card/80">
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Zap className="w-4 h-4 text-primary" />
                    Flujo de Generación del Informe
                  </CardTitle>
                  <CardDescription>
                    Seleccione cómo se procesará la información ingresada
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center justify-center gap-6 p-4">
                    {/* Automatic */}
                    <button
                      onClick={() => setMode('automatic')}
                      className={`flex-1 p-4 rounded-xl border-2 transition-all duration-200 text-left ${
                        mode === 'automatic'
                          ? 'border-primary bg-primary/8 shadow-lg shadow-primary/5'
                          : 'border-border bg-muted/20 hover:border-primary/15'
                      }`}
                    >
                      <div className="flex items-center gap-3 mb-2">
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                          mode === 'automatic' ? 'primary-gradient' : 'bg-muted/50'
                        }`}>
                          <Brain className={`w-5 h-5 ${mode === 'automatic' ? 'text-primary-foreground' : 'text-muted-foreground'}`} />
                        </div>
                        <div>
                          <h3 className={`font-semibold ${mode === 'automatic' ? 'text-primary' : 'text-foreground'}`}>
                            Modo Automático
                          </h3>
                          <p className="text-xs text-muted-foreground">Procesamiento por Agente de IA</p>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        El agente de IA analizará sus archivos y datos, cruzará con fuentes OSINT, y producirá un informe estructurado con resumen ejecutivo, amenazas identificadas, líneas de acción y nivel de riesgo.
                      </p>
                    </button>

                    {/* Manual */}
                    <button
                      onClick={() => setMode('manual')}
                      className={`flex-1 p-4 rounded-xl border-2 transition-all duration-200 text-left ${
                        mode === 'manual'
                          ? 'border-primary bg-primary/8 shadow-lg shadow-primary/5'
                          : 'border-border bg-muted/20 hover:border-primary/15'
                      }`}
                    >
                      <div className="flex items-center gap-3 mb-2">
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                          mode === 'manual' ? 'primary-gradient' : 'bg-muted/50'
                        }`}>
                          <ListChecks className={`w-5 h-5 ${mode === 'manual' ? 'text-primary-foreground' : 'text-muted-foreground'}`} />
                        </div>
                        <div>
                          <h3 className={`font-semibold ${mode === 'manual' ? 'text-primary' : 'text-foreground'}`}>
                            Modo Manual
                          </h3>
                          <p className="text-xs text-muted-foreground">Clasificación Estructurada</p>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Construya el informe con clasificaciones estandarizadas de la industria: tipos de amenaza, severidad y protocolo TLP.
                      </p>
                    </button>
                  </div>
                </CardContent>
              </Card>

              {/* ====== SECTION 3: MODE-SPECIFIC OPTIONS ====== */}
              <AnimatePresence mode="wait">
                {mode === 'automatic' ? (
                  <motion.div
                    key="automatic"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    transition={{ duration: 0.2 }}
                  >
                    <Card className="border-border bg-card/80 border-primary/12">
                      <CardHeader>
                        <CardTitle className="text-base flex items-center gap-2">
                          <Brain className="w-4 h-4 text-primary" />
                          Procesamiento Automático por Agente de IA
                        </CardTitle>
                        <CardDescription>
                          El agente de IA analizará los archivos y datos proporcionados para producir un informe de inteligencia completo y estructurado.
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <div className="p-4 rounded-lg bg-primary/5 border border-primary/12">
                          <div className="flex items-start gap-3">
                            <Info className="w-5 h-5 text-primary shrink-0 mt-0.5" />
                            <div className="text-xs text-muted-foreground space-y-2">
                              <p className="text-primary font-medium">Proceso de Análisis Multi-Fase del Agente de Inteligencia</p>
                              <ol className="list-decimal list-inside space-y-1.5">
                                <li><strong>Fase 1 - Lectura de URLs:</strong> Lee el contenido REAL de cada URL proporcionada (no solo busca snippets)</li>
                                <li><strong>Fase 2 - Extracción de Entidades:</strong> Identifica al VIP, cargo, organización y tipos de datos expuestos</li>
                                <li><strong>Fase 3 - Investigación OSINT:</strong> Cruza con fuentes web complementarias usando búsquedas dirigidas</li>
                                <li><strong>Fase 4 - Análisis Profundo:</strong> Evalúa amenazas concretas, riesgo de explotación, impacto y líneas de acción</li>
                                <li><strong>Resultado:</strong> Informe comprehensivo con perfil del VIP, análisis de exposición, amenazas con evidencia, y plan de acción por fases</li>
                              </ol>
                            </div>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                          <div className="p-3 rounded-lg bg-muted/30 border border-border text-center">
                            <p className="text-lg font-bold text-foreground">{uploadedFiles.length}</p>
                            <p className="text-xs text-muted-foreground">Archivos para analizar</p>
                          </div>
                          <div className="p-3 rounded-lg bg-muted/30 border border-border text-center">
                            <p className="text-lg font-bold text-foreground">{validUrls}</p>
                            <p className="text-xs text-muted-foreground">URLs válidas</p>
                          </div>
                          <div className="p-3 rounded-lg bg-muted/30 border border-border text-center">
                            <p className="text-lg font-bold text-foreground">
                              {writtenData.length > 0 ? 'Sí' : 'No'}
                            </p>
                            <p className="text-xs text-muted-foreground">Texto crudo</p>
                          </div>
                          <div className="p-3 rounded-lg bg-muted/30 border border-border text-center">
                            <p className="text-lg font-bold text-primary">IA</p>
                            <p className="text-xs text-muted-foreground">Motor de análisis</p>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </motion.div>
                ) : (
                  <motion.div
                    key="manual"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    transition={{ duration: 0.2 }}
                    className="space-y-6"
                  >
                    {/* ABUSE TYPES */}
                    <Card className="border-border bg-card/80 border-primary/12">
                      <CardHeader>
                        <div className="flex items-center justify-between">
                          <div>
                            <CardTitle className="text-base flex items-center gap-2">
                              <Filter className="w-4 h-4 text-primary" />
                              Modelos de Amenazas / Clasificación
                            </CardTitle>
                            <CardDescription>
                              Tipos de Abuso de Marca y clasificación de amenazas según taxonomías reconocidas
                            </CardDescription>
                          </div>
                          <Badge className="bg-primary/12 text-primary border-primary/15">
                            {selectedAbuseTypes.size} seleccionada(s)
                          </Badge>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
                          {ABUSE_TYPES.map(type => (
                            <button
                              key={type.id}
                              onClick={() => toggleAbuseType(type.id)}
                              className={`p-3 rounded-xl border transition-all duration-200 text-left ${
                                selectedAbuseTypes.has(type.id)
                                  ? `${type.color} border-current shadow-sm`
                                  : 'bg-muted/20 border-border hover:border-primary/15'
                              }`}
                            >
                              <div className="flex items-center gap-2">
                                <span className="text-lg">{type.icon}</span>
                                <span className="text-xs font-medium">{type.label}</span>
                              </div>
                            </button>
                          ))}
                        </div>
                      </CardContent>
                    </Card>

                    {/* SEVERITY */}
                    <Card className="border-border bg-card/80">
                      <CardHeader>
                        <CardTitle className="text-base flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 text-primary" />
                          Nivel de Criticidad / Severidad
                        </CardTitle>
                        <CardDescription>
                          Asigne el nivel de severidad del informe
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                          {SEVERITY_LEVELS.map(level => (
                            <button
                              key={level.id}
                              onClick={() => setSelectedSeverity(level.id)}
                              className={`p-4 rounded-xl border-2 transition-all duration-200 text-center ${
                                selectedSeverity === level.id
                                  ? `${level.color} border-current shadow-lg`
                                  : 'bg-muted/20 border-border hover:border-primary/15'
                              }`}
                            >
                              <div className={`w-4 h-4 rounded-full mx-auto mb-2 ${level.dot} ${
                                selectedSeverity === level.id ? 'status-pulse' : ''
                              }`} />
                              <p className="text-sm font-bold">{level.label}</p>
                            </button>
                          ))}
                        </div>
                      </CardContent>
                    </Card>

                    {/* TLP */}
                    <Card className="border-border bg-card/80">
                      <CardHeader>
                        <CardTitle className="text-base flex items-center gap-2">
                          <Lock className="w-4 h-4 text-primary" />
                          Protocolo de Compartición de Información (TLP)
                        </CardTitle>
                        <CardDescription>
                          Asigne el color TLP según la confidencialidad del informe
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                          {TLP_LEVELS.map(level => (
                            <button
                              key={level.id}
                              onClick={() => setSelectedTlp(level.id)}
                              className={`p-4 rounded-xl border-2 transition-all duration-200 text-center ${
                                selectedTlp === level.id
                                  ? `${level.color} ring-2 ${level.ring} ring-offset-2 ring-offset-background`
                                  : 'bg-muted/20 border-border hover:border-primary/15'
                              }`}
                            >
                              <p className="text-sm font-bold mb-1">{level.label}</p>
                              <p className="text-xs opacity-80">{level.description}</p>
                            </button>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* ====== GENERATE BUTTON ====== */}
              <Card className="border-border bg-card/80">
                <CardContent className="pt-6">
                  {isGenerating ? (
                    <div className="space-y-4">
                      <div className="flex items-center justify-center gap-3">
                        <Loader2 className="w-5 h-5 animate-spin text-primary" />
                        <span className="text-sm text-muted-foreground">{generationStep}</span>
                      </div>
                      <Progress value={generationProgress} className="h-2" />
                    </div>
                  ) : (
                    <Button
                      onClick={handleGenerate}
                      disabled={!hasDataForAgent && mode === 'automatic'}
                      className="w-full primary-gradient text-primary-foreground font-semibold hover:opacity-90 h-14 text-base disabled:opacity-50"
                    >
                      <Play className="w-5 h-5 mr-2" />
                      {mode === 'automatic'
                        ? `Generar Informe con Agente de IA (${uploadedFiles.length} archivo(s), ${validUrls} URL(s))`
                        : `Generar Informe Manual (${selectedAbuseTypes.size} amenaza(s), Severidad: ${selectedSeverity}, TLP: ${selectedTlp})`
                      }
                    </Button>
                  )}
                </CardContent>
              </Card>
            </motion.div>
          ) : (
            /* ====== RESULT VIEW ====== */
            <motion.div
              key="result"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.15 }}
              className="space-y-6"
            >
              {/* Result Header */}
              <Card className="border-border bg-card/80 border-emerald-500/20">
                <CardContent className="pt-6">
                  <div className="flex items-center gap-3 mb-4">
                    <CheckCircle className="w-6 h-6 text-emerald-400" />
                    <div>
                      <h3 className="font-bold text-foreground">Informe Generado Exitosamente</h3>
                      <p className="text-sm text-muted-foreground">
                        {generatedReport?.report?.title || 'Informe de Inteligencia'}
                      </p>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 mb-4">
                    <Badge className={`${
                      generatedReport?.report?.threatLevel === 'critico' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                      generatedReport?.report?.threatLevel === 'alto' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                      generatedReport?.report?.threatLevel === 'medio' ? 'bg-primary/12 text-primary border-primary/15' :
                      'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                    }`}>
                      Severidad: {(generatedReport?.report?.threatLevel || 'medio').toUpperCase()}
                    </Badge>
                    <Badge className="bg-primary/12 text-primary border-primary/15">
                      {generatedReport?.report?.generationMode === 'automatic' ? 'IA Automático' : 'Manual'}
                    </Badge>
                    {generatedReport?.report?.tlpLevel && (
                      <Badge className={
                        generatedReport.report.tlpLevel === 'RED' ? 'bg-red-600 text-white' :
                        generatedReport.report.tlpLevel === 'AMBER' ? 'bg-primary text-white' :
                        generatedReport.report.tlpLevel === 'GREEN' ? 'bg-emerald-500 text-white' :
                        'bg-gray-300 text-gray-800'
                      }>
                        TLP:{generatedReport.report.tlpLevel}
                      </Badge>
                    )}
                  </div>

                  {/* Download Buttons */}
                  <div className="flex flex-wrap items-center gap-2">
                    <Button
                      onClick={handleDownloadPDF}
                      className="primary-gradient text-primary-foreground font-semibold hover:opacity-90"
                    >
                      <Download className="w-4 h-4 mr-2" />
                      Descargar PDF
                    </Button>
                    <Button
                      onClick={handleDownloadDOCX}
                      variant="outline"
                      className="border-primary/15 text-primary hover:text-primary"
                    >
                      <FileText className="w-4 h-4 mr-2" />
                      Descargar DOCX
                    </Button>
                    <Button
                      onClick={handleDownloadMD}
                      variant="outline"
                      className="border-border hover:border-primary/15"
                    >
                      <Download className="w-4 h-4 mr-2" />
                      Markdown
                    </Button>
                    <Button
                      onClick={() => { setShowResult(false); setGeneratedReport(null); }}
                      variant="outline"
                      className="border-border hover:border-primary/15 ml-auto"
                    >
                      Generar Otro Informe
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Report Preview */}
              <Card className="border-border bg-card/80">
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Eye className="w-4 h-4 text-primary" />
                    Vista Previa del Informe
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="max-h-[600px] pr-4">
                    <div className="prose prose-invert prose-sm max-w-none">
                      {generatedReport?.report?.content && (
                        <ReactMarkdown>{generatedReport.report.content}</ReactMarkdown>
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* Footer */}
      <footer className="border-t border-border px-4 lg:px-8 py-3 mt-8">
        <div className="flex items-center justify-between text-xs text-muted-foreground max-w-5xl mx-auto">
          <div className="flex items-center gap-2">
            <Shield className="w-3 h-3 text-primary" />
            <span>VIP_Protection Report - Executive Intelligence System</span>
          </div>
          <div className="flex items-center gap-1">
            <span>Clasificado</span>
            <span className="text-primary">*</span>
            <span>{new Date().getFullYear()}</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
