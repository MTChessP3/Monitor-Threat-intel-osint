'use client';

import React, { useState, useCallback, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Upload, FileText, Download, RefreshCw, Search, Filter,
  ChevronDown, ChevronUp, Eye, Trash2, Clock, CheckCircle, XCircle,
  AlertCircle, Loader2, BarChart2, LayoutDashboard, Settings,
  ExternalLink, Copy, MoreHorizontal, Bell, BellOff, Send,
  Hash, Link, GripVertical, X, Sparkles, FileSpreadsheet,
  FileJson, FolderOpen, Wifi, WifiOff, Database, Lock, Key,
  Scan, ShieldCheck, AlertTriangle
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow
} from '@/components/ui/table';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger
} from '@/components/ui/dropdown-menu';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger
} from '@/components/ui/dialog';
import { toast } from 'sonner';
import { openPrintReport } from '@/lib/printable-report';
import { sha256OfFile, sha256, generateTransactionId } from '@/lib/takedown/hashGenerator';
import { defangUrl, normalizeUrl, isValidUrl, extractUrlsFromText } from '@/lib/takedown/defang';
import { generateHtmlReport } from '@/lib/takedown/reportGenerator';

interface ExtractedUrl {
  url: string;
  defangedUrl: string;
  valid: boolean;
  virustotalClassification?: string;
  virustotalMaliciousEngines?: number;
  selected: boolean;
  hash: string;
}

interface ServiceResult {
  id: string;
  service: string;
  serviceName: string;
  url: string;
  status: string;
  message?: string;
  referenceId?: string;
  retryCount: number;
  createdAt: string;
  timestamp: string;
}

interface TakeDownReport {
  id: string;
  batchId: string;
  url: string;
  status: string;
  fingerprint?: string;
  createdAt: string;
  serviceResults: ServiceResult[];
}

interface TakeDownBatch {
  id: string;
  name: string;
  status: string;
  totalUrls: number;
  processedUrls: number;
  successfulUrls: number;
  failedUrls: number;
  fingerprint: string;
  fileHash: string;
  reportHash: string;
  notes?: string;
  createdAt: string;
  completedAt?: string;
  reports: TakeDownReport[];
  virustotalResults?: Array<{ url: string; classification: string; maliciousEngines: number }>;
  _count?: { reports: number };
}

interface BatchListResponse {
  batches: TakeDownBatch[];
  pagination: { page: number; limit: number; total: number; totalPages: number };
}

const ALL_SERVICES = [
  { id: 'google', name: 'Google Safe Browsing', requiresApiKey: true },
  { id: 'microsoft', name: 'Microsoft SmartScreen', requiresApiKey: false },
  { id: 'netcraft', name: 'Netcraft', requiresApiKey: true },
  { id: 'eset', name: 'ESET', requiresApiKey: true },
  { id: 'phishfort', name: 'PhishFort', requiresApiKey: true },
  { id: 'phishreport', name: 'PhishReport', requiresApiKey: false },
  { id: 'easydmarc', name: 'EasyDMARC', requiresApiKey: true },
  { id: 'norton', name: 'Norton (Gen Digital)', requiresApiKey: false },
  { id: 'fortinet', name: 'Fortinet / FortiGuard', requiresApiKey: true },
  { id: 'mcafee', name: 'McAfee (Trellix)', requiresApiKey: false },
  { id: 'crdf', name: 'CRDF ThreatCenter', requiresApiKey: false },
  { id: 'phishtank', name: 'PhishTank', requiresApiKey: true },
  { id: 'antiphishing_ch', name: 'antiphishing.ch', requiresApiKey: false },
  { id: 'virustotal', name: 'VirusTotal (Pre-Check)', requiresApiKey: true },
  { id: 'apwg', name: 'APWG', requiresApiKey: false },
  { id: 'cisa', name: 'CISA / US-CERT', requiresApiKey: false },
];

const STATUS_CONFIG = {
  pending: { label: 'Pendiente', color: 'bg-slate-500/20 text-slate-500 border-slate-500/30', icon: Clock },
  processing: { label: 'Procesando', color: 'bg-blue-500/20 text-blue-500 border-blue-500/30', icon: Loader2 },
  completed: { label: 'Completado', color: 'bg-emerald-500/20 text-emerald-500 border-emerald-500/30', icon: CheckCircle },
  failed: { label: 'Fallido', color: 'bg-red-500/20 text-red-500 border-red-500/30', icon: XCircle },
  queued: { label: 'Encolado', color: 'bg-yellow-500/20 text-yellow-500 border-yellow-500/30', icon: Clock },
};

const SERVICE_STATUS_CONFIG = {
  pending: { label: 'Pendiente', color: 'bg-slate-500/20 text-slate-500', icon: Clock },
  sent: { label: 'Enviado', color: 'bg-blue-500/20 text-blue-500', icon: Loader2 },
  success: { label: 'Éxito', color: 'bg-emerald-500/20 text-emerald-500', icon: CheckCircle },
  failed: { label: 'Fallido', color: 'bg-red-500/20 text-red-500', icon: XCircle },
  manual: { label: 'Manual', color: 'bg-yellow-500/20 text-yellow-500', icon: ExternalLink },
  rate_limited: { label: 'Rate Limited', color: 'bg-orange-500/20 text-orange-500', icon: AlertCircle },
};

export default function TakeDownDashboard() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'batches' | 'reports' | 'settings'>('dashboard');
  const [batches, setBatches] = useState<TakeDownBatch[]>([]);
  const [selectedBatch, setSelectedBatch] = useState<TakeDownBatch | null>(null);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 0 });
  const [filters, setFilters] = useState({ status: '', search: '', service: '' });
  const [showNewBatch, setShowNewBatch] = useState(false);
  const [showSingleUrl, setShowSingleUrl] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [queueStats, setQueueStats] = useState({ waiting: 0, active: 0, completed: 0, failed: 0, delayed: 0 });
  const [isDragOver, setIsDragOver] = useState(false);

  // File upload state
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadStep, setUploadStep] = useState('');
  const [fileResult, setFileResult] = useState<{
    validUrls: ExtractedUrl[];
    invalidUrls: string[];
    fileName: string;
    fileHash: string;
    fileType: string;
    virustotalResults?: Array<{ url: string; classification: string; maliciousEngines: number }>;
  } | null>(null);

  // Batch form state
  const [batchForm, setBatchForm] = useState({
    file: null as File | null,
    services: [] as string[],
    notes: '',
    batchName: '',
    maxUrlsPerBatch: 500,
    virustotalApiKey: '',
    async: true,
  });

  // Single URL form state
  const [singleUrlForm, setSingleUrlForm] = useState({
    url: '',
    services: [] as string[],
    notes: '',
    apiKeys: {} as Record<string, string>,
    async: true,
    virustotalPreCheck: false,
  });

  // VirusTotal pre-check state
  const [virustotalResults, setVirustotalResults] = useState<Array<{ url: string; classification: string; maliciousEngines: number }>>([]);
  const [virustotalChecking, setVirustotalChecking] = useState(false);

  // Processing state
  const [submitting, setSubmitting] = useState(false);
  const [processingResult, setProcessingResult] = useState<{
    batchId: string;
    fingerprint: string;
    reportHash: string;
    totalUrls: number;
    successfulUrls: number;
    failedUrls: number;
    results: ServiceResult[];
  } | null>(null);

  const eventSourceRef = useRef<EventSource | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchBatches = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: String(pagination.page),
        limit: String(pagination.limit),
      });
      if (filters.status) params.append('status', filters.status);
      const res = await fetch(`/api/takedown/batch?${params}`);
      if (res.ok) {
        const data: BatchListResponse = await res.json();
        setBatches(data.batches);
        setPagination(prev => ({ ...prev, total: data.pagination.total, totalPages: data.pagination.totalPages }));
      }
    } catch (error) {
      console.error('Error fetching batches:', error);
    } finally {
      setLoading(false);
    }
  }, [pagination.page, pagination.limit, filters.status]);

  const fetchQueueStats = useCallback(async () => {
    try {
      const res = await fetch('/api/takedown/queue/stats');
      if (res.ok) {
        const data = await res.json();
        setQueueStats(data);
      }
    } catch { /* Silently fail */ }
  }, []);

  const fetchBatchDetails = useCallback(async (batchId: string) => {
    try {
      const res = await fetch(`/api/takedown/batch?batchId=${batchId}`);
      if (res.ok) {
        const batch = await res.json();
        setSelectedBatch(batch);
      }
    } catch (error) {
      console.error('Error fetching batch details:', error);
    }
  }, []);

  // Drag and drop handlers
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);

    const files = e.dataTransfer.files;
    if (files.length === 0) return;

    const file = files[0];
    const validExtensions = ['.txt', '.csv', '.xlsx'];
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!validExtensions.includes(ext)) {
      toast.error('Formato no soportado. Use .txt, .csv o .xlsx');
      return;
    }

    setUploadFile(file);
    await processFile(file);
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadFile(file);
    await processFile(file);
  };

  const processFile = async (file: File) => {
    setUploadProgress(10);
    setUploadStep('Leyendo archivo...');

    try {
      const buffer = await file.arrayBuffer();
      const fileHash = await sha256OfFile(buffer);

      setUploadProgress(30);
      setUploadStep('Enviando archivo al servidor para parseo...');

      const formData = new FormData();
      const blob = new Blob([buffer]);
      formData.append('file', blob, file.name);
      formData.append('virustotalApiKey', batchForm.virustotalApiKey || process.env.VIRUSTOTAL_API_KEY || '');

      const res = await fetch('/api/takedown/upload', {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || 'Error al parsear archivo');
      }

      const data = await res.json();

      setUploadProgress(70);
      setUploadStep('Procesando resultados...');

      const validUrls: ExtractedUrl[] = data.validUrls.map((url: string) => ({
        url,
        defangedUrl: defangUrl(url),
        valid: true,
        selected: true,
        hash: await sha256(url),
      }));

      setUploadProgress(90);
      setUploadStep('Generando huella digital SHA-256...');

      setFileResult({
        validUrls,
        invalidUrls: [],
        fileName: file.name,
        fileHash: data.fileHash,
        fileType: '.' + file.name.split('.').pop()?.toLowerCase(),
        virustotalResults: data.virustotalPreCheck,
      });

      setUploadProgress(100);
      setUploadStep('¡Archivo procesado exitosamente!');
      toast.success(`${data.validUrls.length} URLs válidas extraídas de ${file.name}`);
    } catch (error) {
      toast.error('Error al procesar el archivo');
      console.error(error);
    }
  };

  const handleBatchSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!fileResult && !batchForm.file) {
      toast.error('Seleccione un archivo o ingrese URLs');
      return;
    }

    setSubmitting(true);
    try {
      const formData = new FormData();
      if (batchForm.file) formData.append('file', batchForm.file);
      else if (fileResult) {
        const blob = new Blob([fileResult.validUrls.map(u => u.url).join('\n')]);
        formData.append('file', blob, 'urls.txt');
      }
      formData.append('services', JSON.stringify(batchForm.services.length > 0 ? batchForm.services : ALL_SERVICES.map(s => s.id)));
      formData.append('notes', batchForm.notes);
      formData.append('batchName', batchForm.batchName);
      formData.append('maxUrlsPerBatch', String(batchForm.maxUrlsPerBatch));
      formData.append('virustotalApiKey', batchForm.virustotalApiKey);

      const res = await fetch('/api/takedown/upload', {
        method: 'POST',
        body: formData,
      });

      if (res.ok) {
        const data = await res.json();
        toast.success(`${data.totalUrlsSubmitted} URLs encoladas para procesamiento`);
        setShowNewBatch(false);
        setBatchForm({ file: null, services: [], notes: '', batchName: '', maxUrlsPerBatch: 500, virustotalApiKey: '', async: true });
        setFileResult(null);
        setUploadFile(null);
        fetchBatches();
      } else {
        const error = await res.json();
        toast.error(error.error || 'Error al crear lote');
      }
    } catch {
      toast.error('Error de conexión');
    } finally {
      setSubmitting(false);
    }
  };

  const handleSingleUrlSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!singleUrlForm.url.trim()) {
      toast.error('Ingrese una URL');
      return;
    }

    setSubmitting(true);
    try {
      const virustotalApiKey = batchForm.virustotalApiKey || process.env.VIRUSTOTAL_API_KEY || '';
      const res = await fetch('/api/takedown/single', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: singleUrlForm.url,
          services: singleUrlForm.services.length > 0 ? singleUrlForm.services : ['virustotal'],
          notes: singleUrlForm.notes,
          apiKeys: singleUrlForm.apiKeys,
          async: singleUrlForm.async,
          virustotalApiKey,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        toast.success(data.status === 'queued' ? 'URL encolada para procesamiento' : 'Reporte completado');
        setShowSingleUrl(false);
        setSingleUrlForm({ url: '', services: [], notes: '', apiKeys: {}, async: true, virustotalPreCheck: false });
        setProcessingResult(null);
        fetchBatches();
      } else {
        const error = await res.json();
        toast.error(error.error || 'Error al enviar URL');
      }
    } catch {
      toast.error('Error de conexión');
    } finally {
      setSubmitting(false);
    }
  };

  const handleVirusTotalPreCheck = async (url: string) => {
    if (!url || !singleUrlForm.virustotalPreCheck) return;
    const apiKey = batchForm.virustotalApiKey || process.env.VIRUSTOTAL_API_KEY || '';
    if (!apiKey) {
      toast.error('VirusTotal API key no configurada');
      return;
    }
    setVirustotalChecking(true);
    try {
      const res = await fetch('/api/takedown/virustotal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, apiKey }),
      });
      if (res.ok) {
        const data = await res.json();
        setVirustotalResults([data]);
        toast.info(`VirusTotal: ${data.classification} (${data.maliciousEngines || 0} motores maliciosos)`);
      }
    } catch {
      toast.error('Error en VirusTotal pre-check');
    } finally {
      setVirustotalChecking(false);
    }
  };

  const handleExport = async (batchId: string, format: 'pdf' | 'csv' | 'json' | 'xlsx') => {
    try {
      const res = await fetch('/api/takedown/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ batchId, format, includeDetails: true }),
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        const disposition = res.headers.get('Content-Disposition');
        const filename = disposition?.match(/filename="(.+)"/)?.[1] || `export-${batchId}.${format}`;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        toast.success(`Exportado como ${format.toUpperCase()}`);
      } else {
        toast.error('Error al exportar');
      }
    } catch {
      toast.error('Error al exportar');
    }
  };

  const handleGenerateHtmlReport = async (batchId: string) => {
    try {
      const res = await fetch('/api/takedown/report-html', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ batchId }),
      });
      if (res.ok) {
        const html = await res.text();
        const reportHash = sha256(html);
        const blob = new Blob([html], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `takedown-report-${batchId}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast.success('Reporte HTML generado con SHA-256 fingerprint');
      }
    } catch {
      toast.error('Error al generar reporte HTML');
    }
  };

  const handleRetryBatch = async (batchId: string) => {
    try {
      const res = await fetch('/api/takedown/batch/retry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ batchId }),
      });
      if (res.ok) {
        toast.success('Reintentando URLs fallidas...');
        fetchBatches();
      }
    } catch {
      toast.error('Error al reintentar');
    }
  };

  useEffect(() => {
    fetchBatches();
    fetchQueueStats();
  }, [fetchBatches, fetchQueueStats]);

  useEffect(() => {
    if (selectedBatch && activeTab === 'reports') {
      eventSourceRef.current = new EventSource(`/api/takedown/events?batchId=${selectedBatch.id}`);
      eventSourceRef.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'progress') {
          setSelectedBatch(prev => prev ? { ...prev, ...data.batch } : null);
        }
      };
      return () => eventSourceRef.current?.close();
    }
  }, [selectedBatch, activeTab]);

  const getBatchStatusConfig = (status: string) => STATUS_CONFIG[status as keyof typeof STATUS_CONFIG] || STATUS_CONFIG.pending;
  const getServiceStatusConfig = (status: string) => SERVICE_STATUS_CONFIG[status as keyof typeof SERVICE_STATUS_CONFIG] || SERVICE_STATUS_CONFIG.pending;

  const dashboardStats = {
    totalBatches: batches.length,
    processingBatches: batches.filter(b => b.status === 'processing' || b.status === 'queued').length,
    completedBatches: batches.filter(b => b.status === 'completed').length,
    failedBatches: batches.filter(b => b.status === 'failed').length,
    totalUrls: batches.reduce((sum, b) => sum + b.totalUrls, 0),
    totalProcessed: batches.reduce((sum, b) => sum + b.processedUrls, 0),
    totalSuccess: batches.reduce((sum, b) => sum + b.successfulUrls, 0),
    totalFailed: batches.reduce((sum, b) => sum + b.failedUrls, 0),
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="w-6 h-6 text-primary" />
            TakeDown URL Module
          </h1>
          <p className="text-muted-foreground mt-1">
            Gestión profesional de reporte de URLs maliciosas — 13+ servicios con pre-check VirusTotal y firma SHA-256
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => setShowSingleUrl(true)} className="gap-2">
            <Link className="w-4 h-4" /> URL Individual
          </Button>
          <Button onClick={() => setShowNewBatch(true)} className="gap-2">
            <Upload className="w-4 h-4" /> Nuevo Lote
          </Button>
          <Button variant="outline" onClick={() => setAutoRefresh(!autoRefresh)} className="gap-2">
            {autoRefresh ? <Bell className="w-4 h-4" /> : <BellOff className="w-4 h-4" />}
            {autoRefresh ? 'Auto' : 'Manual'}
          </Button>
          <Button variant="outline" onClick={() => { fetchBatches(); fetchQueueStats(); }} className="gap-2" disabled={loading}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Actualizar
          </Button>
        </div>
      </div>

      {/* Queue Stats */}
      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="py-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <span className="font-medium text-primary">Cola de Procesamiento:</span>
            {[
              { label: 'Activos', value: queueStats.active, color: 'text-blue-500' },
              { label: 'Espera', value: queueStats.waiting, color: 'text-yellow-500' },
              { label: 'Completados', value: queueStats.completed, color: 'text-emerald-500' },
              { label: 'Fallidos', value: queueStats.failed, color: 'text-red-500' },
            ].map(item => (
              <Badge key={item.label} variant="outline" className={`gap-1 border-${item.color.replace('text-', '')}/30 ${item.color}`}>
                {item.label}: {item.value}
              </Badge>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Dashboard Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
        {[
          { label: 'Total Lotes', value: dashboardStats.totalBatches, icon: FileText, color: '' },
          { label: 'Procesando', value: dashboardStats.processingBatches, icon: Loader2, color: 'text-blue-500' },
          { label: 'Completados', value: dashboardStats.completedBatches, icon: CheckCircle, color: 'text-emerald-500' },
          { label: 'Fallidos', value: dashboardStats.failedBatches, icon: XCircle, color: 'text-red-500' },
          { label: 'Total URLs', value: dashboardStats.totalUrls, icon: FileText, color: '' },
          { label: 'Procesadas', value: dashboardStats.totalProcessed, icon: Clock, color: 'text-blue-500' },
          { label: 'Exitosas', value: dashboardStats.totalSuccess, icon: CheckCircle, color: 'text-emerald-500' },
          { label: 'Fallidas', value: dashboardStats.totalFailed, icon: XCircle, color: 'text-red-500' },
        ].map((stat, i) => (
          <Card key={i}>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">{stat.label}</p>
                  <p className={`text-3xl font-bold ${stat.color}`}>{stat.value}</p>
                </div>
                <stat.icon className={`w-10 h-10 ${stat.color || 'text-muted-foreground/30'}`} />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="dashboard"><LayoutDashboard className="w-4 h-4 mr-2" /> Dashboard</TabsTrigger>
          <TabsTrigger value="batches"><FileText className="w-4 h-4 mr-2" /> Lotes</TabsTrigger>
          <TabsTrigger value="reports"><Shield className="w-4 h-4 mr-2" /> Reportes</TabsTrigger>
          <TabsTrigger value="settings"><Settings className="w-4 h-4 mr-2" /> Servicios</TabsTrigger>
        </TabsList>

        <AnimatePresence mode="wait">
          {/* BATCHES TAB */}
          {activeTab === 'batches' && (
            <motion.div key="batches" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4 mt-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle>Lotes de Procesamiento</CardTitle>
                  <div className="flex items-center gap-2">
                    <Select value={filters.status} onValueChange={v => setFilters({...filters, status: v})}>
                      <SelectTrigger className="w-48">
                        <SelectValue placeholder="Filtrar por estado" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="">Todos</SelectItem>
                        <SelectItem value="pending">Pendiente</SelectItem>
                        <SelectItem value="processing">Procesando</SelectItem>
                        <SelectItem value="completed">Completado</SelectItem>
                        <SelectItem value="failed">Fallido</SelectItem>
                        <SelectItem value="queued">Encolado</SelectItem>
                      </SelectContent>
                    </Select>
                    <Input placeholder="Buscar..." value={filters.search} onChange={e => setFilters({...filters, search: e.target.value})} className="w-64" />
                  </div>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="max-h-[600px]">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Lote</TableHead>
                          <TableHead>Estado</TableHead>
                          <TableHead className="text-right">URLs</TableHead>
                          <TableHead className="text-right">Procesadas</TableHead>
                          <TableHead className="text-right">Éxitos</TableHead>
                          <TableHead className="text-right">Fallidas</TableHead>
                          <TableHead>Fingerprint SHA-256</TableHead>
                          <TableHead>Creado</TableHead>
                          <TableHead>Acciones</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {batches.length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={9} className="text-center py-8 text-muted-foreground">
                              No hay lotes. Cree uno nuevo para empezar.
                            </TableCell>
                          </TableRow>
                        ) : (
                          batches.map((batch) => {
                            const statusConfig = getBatchStatusConfig(batch.status);
                            const StatusIcon = statusConfig.icon;
                            return (
                              <TableRow key={batch.id} className="cursor-pointer hover:bg-muted/50" onClick={() => fetchBatchDetails(batch.id)}>
                                <TableCell className="font-medium">{batch.name}</TableCell>
                                <TableCell>
                                  <Badge className={statusConfig.color}><StatusIcon className="w-3 h-3 mr-1" />{statusConfig.label}</Badge>
                                </TableCell>
                                <TableCell className="text-right font-mono">{batch.totalUrls}</TableCell>
                                <TableCell className="text-right font-mono">{batch.processedUrls}</TableCell>
                                <TableCell className="text-right font-mono text-emerald-500">{batch.successfulUrls}</TableCell>
                                <TableCell className="text-right font-mono text-red-500">{batch.failedUrls}</TableCell>
                                <TableCell className="font-mono text-xs max-w-xs truncate" title={batch.fingerprint}>
                                  {batch.fingerprint.substring(0, 16)}...
                                </TableCell>
                                <TableCell className="font-mono text-xs">{new Date(batch.createdAt).toLocaleString()}</TableCell>
                                <TableCell>
                                  <DropdownMenu>
                                    <DropdownMenuTrigger asChild>
                                      <Button variant="ghost" size="icon" className="h-8 w-8">
                                        <MoreHorizontal className="w-4 h-4" />
                                      </Button>
                                    </DropdownMenuTrigger>
                                    <DropdownMenuContent align="end">
                                      <DropdownMenuItem onClick={() => fetchBatchDetails(batch.id)}>
                                        <Eye className="w-4 h-4 mr-2" /> Ver Detalle
                                      </DropdownMenuItem>
                                      <DropdownMenuItem onClick={() => handleExport(batch.id, 'csv')}>
                                        <Download className="w-4 h-4 mr-2" /> Exportar CSV
                                      </DropdownMenuItem>
                                      <DropdownMenuItem onClick={() => handleExport(batch.id, 'json')}>
                                        <Download className="w-4 h-4 mr-2" /> Exportar JSON
                                      </DropdownMenuItem>
                                      <DropdownMenuItem onClick={() => handleGenerateHtmlReport(batch.id)} className="text-emerald-500">
                                        <FileJson className="w-4 h-4 mr-2" /> Reporte HTML (SHA-256)
                                      </DropdownMenuItem>
                                      {batch.failedUrls > 0 && (
                                        <DropdownMenuItem onClick={() => handleRetryBatch(batch.id)} className="text-blue-500">
                                          <RefreshCw className="w-4 h-4 mr-2" /> Reintentar Fallidas
                                        </DropdownMenuItem>
                                      )}
                                    </DropdownMenuContent>
                                  </DropdownMenu>
                                </TableCell>
                              </TableRow>
                            );
                          })
                        )}
                      </TableBody>
                    </Table>
                  </ScrollArea>

                  {pagination.totalPages > 1 && (
                    <div className="flex items-center justify-center gap-2 mt-4">
                      <Button variant="outline" size="sm" onClick={() => setPagination(p => ({...p, page: p.page - 1}))} disabled={pagination.page === 1}>
                        <ChevronUp className="w-4 h-4" />
                      </Button>
                      <span className="text-sm font-medium">
                        Página {pagination.page} de {pagination.totalPages} ({pagination.total} total)
                      </span>
                      <Button variant="outline" size="sm" onClick={() => setPagination(p => ({...p, page: p.page + 1}))} disabled={pagination.page === pagination.totalPages}>
                        <ChevronDown className="w-4 h-4" />
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            </motion.div>
          )}

          {/* REPORTS TAB */}
          {activeTab === 'reports' && selectedBatch && (
            <motion.div key="reports" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4 mt-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <div>
                    <CardTitle>{selectedBatch.name}</CardTitle>
                    <CardDescription>
                      ID: {selectedBatch.id} • {selectedBatch.totalUrls} URLs • Fingerprint: {selectedBatch.fingerprint?.substring(0, 24)}...
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={() => handleGenerateHtmlReport(selectedBatch.id)} className="border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10 gap-1">
                      <FileJson className="w-4 h-4" /> Reporte HTML (SHA-256)
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => handleExport(selectedBatch.id, 'pdf')}>
                      <Download className="w-4 h-4 mr-1" /> PDF
                    </Button>
                    <Button variant="ghost" size="sm" onClick={() => setSelectedBatch(null)}>
                      <ChevronUp className="w-4 h-4 mr-1" /> Volver
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-6">
                  {/* Crypto Fingerprint Block */}
                  <Card className="border-emerald-500/20 bg-emerald-500/5">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2 text-emerald-500">
                        <Hash className="w-5 h-5" />
                        Integridad Criptográfica SHA-256
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="p-3 rounded-lg bg-gray-900 border border-gray-700">
                          <p className="text-xs text-emerald-400 font-semibold mb-1">Hash del Archivo Original</p>
                          <p className="font-mono text-xs text-emerald-300 break-all">{selectedBatch.fileHash}</p>
                        </div>
                        <div className="p-3 rounded-lg bg-gray-900 border border-gray-700">
                          <p className="text-xs text-emerald-400 font-semibold mb-1">Fingerprint del Lote</p>
                          <p className="font-mono text-xs text-emerald-300 break-all">{selectedBatch.fingerprint}</p>
                        </div>
                        <div className="p-3 rounded-lg bg-gray-900 border border-gray-700">
                          <p className="text-xs text-emerald-400 font-semibold mb-1">Hash de Ejecución del Reporte</p>
                          <p className="font-mono text-xs text-emerald-300 break-all">{selectedBatch.reportHash || 'Pendiente'}</p>
                        </div>
                        <div className="p-3 rounded-lg bg-gray-900 border border-gray-700">
                          <p className="text-xs text-emerald-400 font-semibold mb-1">ID de Transacción</p>
                          <p className="font-mono text-xs text-emerald-300 break-all">{selectedBatch.id}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="border-emerald-500/30 text-emerald-500">
                          <ShieldCheck className="w-3 h-3 mr-1" /> Verificable
                        </Badge>
                        <Button variant="ghost" size="sm" onClick={() => {
                          navigator.clipboard.writeText(selectedBatch.fingerprint || '');
                          toast.success('Fingerprint copiado al portapapeles');
                        }}>
                          <Copy className="w-3 h-3 mr-1" /> Copiar Fingerprint
                        </Button>
                      </div>
                    </CardContent>
                  </Card>

                  {/* VirusTotal Results */}
                  {selectedBatch.virustotalResults && selectedBatch.virustotalResults.length > 0 && (
                    <Card className="border-blue-500/20 bg-blue-500/5">
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-blue-500">
                          <Scan className="w-5 h-5" />
                          Pre-Check VirusTotal
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>URL</TableHead>
                              <TableHead>Clasificación</TableHead>
                              <TableHead>Motores Maliciosos</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {selectedBatch.virustotalResults.map((vt, i) => (
                              <TableRow key={i}>
                                <TableCell className="font-mono text-xs">{vt.url}</TableCell>
                                <TableCell>
                                  <Badge className={vt.classification === 'CONFIRMED_MALICIOUS' ? 'bg-red-500/20 text-red-500' : vt.classification === 'SUSPICIOUS' ? 'bg-yellow-500/20 text-yellow-500' : 'bg-gray-500/20 text-gray-500'}>
                                    {vt.classification}
                                  </Badge>
                                </TableCell>
                                <TableCell className="font-mono">{vt.maliciousEngines}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </CardContent>
                    </Card>
                  )}

                  {/* Service Status Summary */}
                  <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
                    {ALL_SERVICES.map(svc => {
                      const results = (selectedBatch.serviceResults || []).filter(sr => sr.service === svc.id);
                      const success = results.filter(r => r.status === 'success').length;
                      const failed = results.filter(r => r.status === 'failed').length;
                      const manual = results.filter(r => r.status === 'manual').length;
                      const total = results.length;
                      return (
                        <div key={svc.id} className="p-3 rounded-lg border border-border/50 bg-muted/30">
                          <div className="text-sm font-medium truncate mb-2">{svc.name}</div>
                          <div className="flex items-center gap-1 text-xs">
                            {success > 0 && <Badge variant="secondary" className="gap-1 bg-emerald-500/20 text-emerald-500">✓{success}</Badge>}
                            {manual > 0 && <Badge variant="secondary" className="gap-1 bg-yellow-500/20 text-yellow-500">M{manual}</Badge>}
                            {failed > 0 && <Badge variant="secondary" className="gap-1 bg-red-500/20 text-red-500">✗{failed}</Badge>}
                            {total === 0 && <span className="text-muted-foreground">Sin datos</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Action Buttons */}
                  <div className="flex flex-wrap gap-2">
                    <Button variant="outline" onClick={() => handleGenerateHtmlReport(selectedBatch.id)} className="border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10 gap-1">
                      <FileJson className="w-4 h-4" /> Generar Reporte HTML (SHA-256)
                    </Button>
                    <Button variant="outline" onClick={() => handleExport(selectedBatch.id, 'csv')}>
                      <Download className="w-4 h-4 mr-1" /> Exportar CSV
                    </Button>
                    <Button variant="outline" onClick={() => handleExport(selectedBatch.id, 'json')}>
                      <Download className="w-4 h-4 mr-1" /> Exportar JSON
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )}

          {/* SETTINGS TAB */}
          {activeTab === 'settings' && (
            <motion.div key="settings" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-6 mt-4">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Settings className="w-5 h-5" />
                    Configuración de Servicios (16 Proveedores)
                  </CardTitle>
                  <CardDescription>Estado de integración y configuración de cada servicio de reporte</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {ALL_SERVICES.map((svc) => (
                      <Card key={svc.id} className="border-border/50 hover:border-primary/30 transition-colors">
                        <CardContent className="p-4">
                          <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center text-primary">
                              <Shield className="w-5 h-5" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <p className="font-medium truncate">{svc.name}</p>
                              <p className="text-xs text-muted-foreground">
                                {svc.requiresApiKey ? 'Requiere API Key' : 'Disponible'}
                              </p>
                            </div>
                            <Badge variant="outline" className="border-emerald-500/30 text-emerald-500">
                              <CheckCircle className="w-3 h-3 mr-1" /> Activo
                            </Badge>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>
      </Tabs>

      {/* NEW BATCH DIALOG */}
      <Dialog open={showNewBatch} onOpenChange={setShowNewBatch}>
        <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Nuevo Lote de URLs</DialogTitle>
            <CardDescription>
              Arrastre y suelte un archivo .txt, .csv o .xlsx, o use la pestaña "Texto" para pegar URLs. Se calculará automáticamente el hash SHA-256 y se realizará pre-check con VirusTotal.
            </CardDescription>
          </DialogHeader>

          <form onSubmit={handleBatchSubmit} className="space-y-4 p-4">
            {/* Drag and Drop Zone */}
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
                isDragOver ? 'border-green-500 bg-green-500/10' : 'border-gray-600 hover:border-gray-500'
              }`}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.csv,.xlsx"
                onChange={handleFileChange}
                className="hidden"
              />
              {isDragOver ? (
                <div>
                  <FolderOpen className="w-12 h-12 text-green-400 mx-auto mb-4" />
                  <p className="text-green-400 font-semibold">¡Suelte el archivo aquí!</p>
                </div>
              ) : uploadProgress > 0 ? (
                <div>
                  <FileText className="w-12 h-12 text-primary mx-auto mb-4" />
                  <p className="font-medium">{uploadFile?.name || 'Procesando...'}</p>
                  <Progress value={uploadProgress} className="h-2 mt-2" />
                  <p className="text-xs text-muted-foreground mt-2">{uploadStep}</p>
                  {fileResult && (
                    <div className="mt-3 flex items-center justify-center gap-4 text-sm">
                      <Badge variant="secondary">{fileResult.validUrls.length} URLs válidas</Badge>
                      <Badge variant="outline">{fileResult.fileHash?.substring(0, 12)}... SHA-256</Badge>
                    </div>
                  )}
                </div>
              ) : (
                <div>
                  <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <p className="font-semibold mb-2">Arrastre y suelte aquí</p>
                  <p className="text-sm text-muted-foreground">Formatos: .txt, .csv, .xlsx (máx. 10MB)</p>
                  <p className="text-xs text-muted-foreground mt-1">Se calculará SHA-256 automáticamente</p>
                </div>
              )}
            </div>

            {/* File info after upload */}
            {fileResult && (
              <Card className="border-green-500/20 bg-green-500/5">
                <CardContent className="p-4">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                    <div>
                      <span className="text-muted-foreground">Archivo:</span>
                      <p className="font-medium">{fileResult.fileName}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Hash SHA-256:</span>
                      <p className="font-mono text-xs break-all">{fileResult.fileHash}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">URLs Válidas:</span>
                      <p className="font-medium">{fileResult.validUrls.length}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Inválidas:</span>
                      <p className="font-medium">{fileResult.invalidUrls.length}</p>
                    </div>
                  </div>

                  {/* Interactive Validation Table */}
                  <div className="mt-4">
                    <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4" />
                      Tabla de Validación ({fileResult.validUrls.length} URLs)
                    </h4>
                    <ScrollArea className="max-h-[200px]">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>URL Original</TableHead>
                            <TableHead>Defanged</TableHead>
                            <TableHead>SHA-256 Hash</TableHead>
                            <TableHead>VirusTotal</TableHead>
                            <TableHead>Seleccionado</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {fileResult.validUrls.slice(0, 50).map((u, i) => (
                            <TableRow key={i} className={u.selected ? 'bg-green-500/5' : ''}>
                              <TableCell className="font-mono text-xs">{u.url}</TableCell>
                              <TableCell className="font-mono text-xs text-red-400">{u.defangedUrl}</TableCell>
                              <TableCell className="font-mono text-xs text-gray-400 max-w-[120px] truncate">{u.hash?.substring(0, 12)}...</TableCell>
                              <TableCell>
                                {u.virustotalClassification ? (
                                  <Badge className={u.virustotalClassification === 'CONFIRMED_MALICIOUS' ? 'bg-red-500/20 text-red-500' : u.virustotalClassification === 'SUSPICIOUS' ? 'bg-yellow-500/20 text-yellow-500' : 'bg-gray-500/20 text-gray-500'}>
                                    {u.virustotalClassification} ({u.virustotalMaliciousEngines || 0})
                                  </Badge>
                                ) : (
                                  <span className="text-muted-foreground">—</span>
                                )}
                              </TableCell>
                              <TableCell>
                                <input
                                  type="checkbox"
                                  checked={u.selected}
                                  onChange={() => {
                                    const updated = [...fileResult.validUrls];
                                    updated[i] = { ...updated[i], selected: !updated[i].selected };
                                    setFileResult({ ...fileResult, validUrls: updated });
                                  }}
                                  className="rounded border-border"
                                />
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </ScrollArea>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Virustotal API Key */}
            <div className="space-y-2">
              <Label>VirusTotal API Key (para pre-check)</Label>
              <Input
                type="password"
                placeholder="VT_API_KEY"
                value={batchForm.virustotalApiKey}
                onChange={e => setBatchForm({...batchForm, virustotalApiKey: e.target.value})}
                className="font-mono"
              />
            </div>

            {/* Batch Name & Notes */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Nombre del lote (opcional)</Label>
                <Input
                  placeholder="Lote Phishing - Septiembre 2026"
                  value={batchForm.batchName}
                  onChange={e => setBatchForm({...batchForm, batchName: e.target.value})}
                />
              </div>
              <div className="space-y-2">
                <Label>Límite de URLs por lote</Label>
                <Input
                  type="number"
                  min="1" max="5000"
                  value={batchForm.maxUrlsPerBatch}
                  onChange={e => setBatchForm({...batchForm, maxUrlsPerBatch: parseInt(e.target.value) || 500})}
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label>Notas (opcional)</Label>
              <Textarea
                value={batchForm.notes}
                onChange={e => setBatchForm({...batchForm, notes: e.target.value})}
                placeholder="Información adicional..."
                rows={2}
              />
            </div>

            <div className="space-y-2">
              <Label>Servicios (vacío = todos los 16)</Label>
              <div className="flex flex-wrap gap-2 max-h-40 overflow-y-auto">
                {ALL_SERVICES.map(svc => (
                  <label key={svc.id} className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={batchForm.services.includes(svc.id)}
                      onChange={e => setBatchForm({
                        ...batchForm,
                        services: e.target.checked
                          ? [...batchForm.services, svc.id]
                          : batchForm.services.filter(s => s !== svc.id)
                      })}
                      className="rounded border-border"
                    />
                    <span className="text-sm">{svc.name}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-2">
              <input type="checkbox" id="async" checked={batchForm.async}
                onChange={e => setBatchForm({...batchForm, async: e.target.checked})}
                className="rounded border-border" />
              <Label htmlFor="async" className="text-sm cursor-pointer">Procesamiento asíncrono (cola BullMQ)</Label>
            </div>

            <div className="flex justify-end gap-2 pt-4 border-t">
              <Button type="button" variant="outline" onClick={() => setShowNewBatch(false)}>Cancelar</Button>
              <Button type="submit" disabled={submitting || (!fileResult && !uploadFile)}>
                {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4 mr-2" />}
                {submitting ? 'Enviando...' : 'Crear Lote'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* SINGLE URL DIALOG */}
      <Dialog open={showSingleUrl} onOpenChange={setShowSingleUrl}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Reportar URL Individual</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSingleUrlSubmit} className="space-y-4 p-4">
            <div className="space-y-2">
              <Label>URL a reportar</Label>
              <Input
                type="url"
                placeholder="https://ejemplo-malicioso.com"
                value={singleUrlForm.url}
                onChange={e => setSingleUrlForm({...singleUrlForm, url: e.target.value})}
                required
              />
            </div>

            {/* VirusTotal Pre-Check Toggle */}
            <div className="flex items-center gap-2 p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
              <input
                type="checkbox"
                id="vtPreCheck"
                checked={singleUrlForm.virustotalPreCheck}
                onChange={e => setSingleUrlForm({...singleUrlForm, virustotalPreCheck: e.target.checked})}
                className="rounded border-border"
              />
              <Label htmlFor="vtPreCheck" className="text-sm cursor-pointer flex items-center gap-1">
                <Scan className="w-4 h-4 text-blue-500" />
                Ejecutar pre-check VirusTotal antes de reportar
              </Label>
            </div>

            {/* VirusTotal Result */}
            {virustotalResults.length > 0 && (
              <Card className="border-blue-500/20 bg-blue-500/5">
                <CardContent className="p-4">
                  <h4 className="text-sm font-semibold text-blue-500 mb-2">Resultado VirusTotal</h4>
                  {virustotalResults.map((vt, i) => (
                    <div key={i} className="flex items-center gap-3 text-sm">
                      <code className="font-mono text-xs">{vt.url}</code>
                      <Badge className={vt.classification === 'CONFIRMED_MALICIOUS' ? 'bg-red-500/20 text-red-500' : vt.classification === 'SUSPICIOUS' ? 'bg-yellow-500/20 text-yellow-500' : 'bg-gray-500/20 text-gray-500'}>
                        {vt.classification}
                      </Badge>
                      <span className="text-muted-foreground">{vt.maliciousEngines} motores maliciosos</span>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            <div className="space-y-2">
              <Label>Servicios</Label>
              <div className="flex flex-wrap gap-2 max-h-40 overflow-y-auto">
                {ALL_SERVICES.map(svc => (
                  <label key={svc.id} className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={singleUrlForm.services.includes(svc.id)}
                      onChange={e => setSingleUrlForm({
                        ...singleUrlForm,
                        services: e.target.checked
                          ? [...singleUrlForm.services, svc.id]
                          : singleUrlForm.services.filter(s => s !== svc.id)
                      })}
                      className="rounded border-border"
                    />
                    <span className="text-sm">{svc.name}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <Label>Notas (para APWG / CISA email)</Label>
              <Textarea
                value={singleUrlForm.notes}
                onChange={e => setSingleUrlForm({...singleUrlForm, notes: e.target.value})}
                placeholder="Información adicional para enviar por correo a APWG y CISA..."
                rows={3}
              />
            </div>

            <div className="flex justify-end gap-2 pt-4 border-t">
              <Button type="button" variant="outline" onClick={() => setShowSingleUrl(false)}>Cancelar</Button>
              <Button type="submit" disabled={submitting || !singleUrlForm.url.trim()}>
                {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4 mr-2" />}
                {submitting ? 'Enviando...' : 'Enviar Reporte'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* PROCESSING RESULT DIALOG */}
      <AnimatePresence>
        {processingResult && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
          >
            <Card className="max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto border-emerald-500/30">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-emerald-500">
                  <CheckCircle className="w-5 h-5" />
                  Reporte de TakeDown Completado
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-3 rounded-lg bg-gray-900 border border-gray-700">
                    <p className="text-xs text-emerald-400 font-semibold">Fingerprint SHA-256</p>
                    <p className="font-mono text-xs text-emerald-300 break-all">{processingResult.fingerprint}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-gray-900 border border-gray-700">
                    <p className="text-xs text-emerald-400 font-semibold">Hash del Reporte</p>
                    <p className="font-mono text-xs text-emerald-300 break-all">{processingResult.reportHash}</p>
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div className="p-3 rounded-lg bg-gray-800 text-center">
                    <div className="text-2xl font-bold">{processingResult.totalUrls}</div>
                    <div className="text-xs text-muted-foreground">Total URLs</div>
                  </div>
                  <div className="p-3 rounded-lg bg-emerald-500/20 text-center">
                    <div className="text-2xl font-bold text-emerald-400">{processingResult.successfulUrls}</div>
                    <div className="text-xs text-muted-foreground">Exitosos</div>
                  </div>
                  <div className="p-3 rounded-lg bg-red-500/20 text-center">
                    <div className="text-2xl font-bold text-red-400">{processingResult.failedUrls}</div>
                    <div className="text-xs text-muted-foreground">Fallidos</div>
                  </div>
                </div>

                <Button onClick={() => setProcessingResult(null)}>Cerrar</Button>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
