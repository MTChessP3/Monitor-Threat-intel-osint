'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Upload, FileText, Download, RefreshCw, Search, Filter, 
  ChevronDown, ChevronUp, Eye, Trash2, Clock, CheckCircle, XCircle, 
  AlertCircle, Loader2, BarChart2, LayoutDashboard, Settings,
  ExternalLink, Copy, MoreHorizontal, Bell, BellOff, Send
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { toast } from 'sonner';

interface ServiceResult {
  id: string;
  service: string;
  serviceName: string;
  url: string;
  status: string;
  message?: string;
  referenceId?: string;
  requestPayload?: string;
  responsePayload?: string;
  errorDetails?: string;
  retryCount: number;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
}

interface TakeDownReport {
  id: string;
  batchId: string;
  url: string;
  status: string;
  notes?: string;
  fingerprint?: string;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
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
  userId: string;
  notes?: string;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
  reports: TakeDownReport[];
  serviceResults: ServiceResult[];
  _count?: {
    reports: number;
    serviceResults: number;
  };
}

interface BatchListResponse {
  batches: TakeDownBatch[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

const STATUS_CONFIG = {
  pending: { label: 'Pendiente', color: 'bg-slate-500/20 text-slate-500 border-slate-500/30', icon: Clock },
  processing: { label: 'Procesando', color: 'bg-blue-500/20 text-blue-500 border-blue-500/30', icon: Loader2 },
  completed: { label: 'Completado', color: 'bg-emerald-500/20 text-emerald-500 border-emerald-500/30', icon: CheckCircle },
  failed: { label: 'Fallido', color: 'bg-red-500/20 text-red-500 border-red-500/30', icon: XCircle },
  queued: { label: 'Encolado', color: 'bg-yellow-500/20 text-yellow-500 border-yellow-500/30', icon: Clock },
};

const SERVICE_STATUS_CONFIG = {
  pending: { label: 'Pendiente', color: 'bg-slate-500/20 text-slate-500 border-slate-500/30', icon: Clock },
  sent: { label: 'Enviado', color: 'bg-blue-500/20 text-blue-500 border-blue-500/30', icon: Loader2 },
  success: { label: 'Éxito', color: 'bg-emerald-500/20 text-emerald-500 border-emerald-500/30', icon: CheckCircle },
  failed: { label: 'Fallido', color: 'bg-red-500/20 text-red-500 border-red-500/30', icon: XCircle },
  manual: { label: 'Manual', color: 'bg-yellow-500/20 text-yellow-500 border-yellow-500/30', icon: ExternalLink },
  rate_limited: { label: 'Rate Limited', color: 'bg-orange-500/20 text-orange-500 border-orange-500/30', icon: AlertCircle },
};

const ALL_SERVICES = [
  { id: 'google', name: 'Google Safe Browsing', icon: Shield },
  { id: 'microsoft', name: 'Microsoft SmartScreen', icon: Shield },
  { id: 'netcraft', name: 'Netcraft', icon: Shield },
  { id: 'eset', name: 'ESET', icon: Shield },
  { id: 'phishfort', name: 'PhishFort', icon: Shield },
  { id: 'phishreport', name: 'PhishReport', icon: Shield },
  { id: 'easydmarc', name: 'EasyDMARC', icon: Shield },
  { id: 'norton', name: 'Norton (Gen Digital)', icon: Shield },
  { id: 'fortinet', name: 'Fortinet / FortiGuard', icon: Shield },
  { id: 'mcafee', name: 'McAfee (Trellix)', icon: Shield },
  { id: 'crdf', name: 'CRDF ThreatCenter', icon: Shield },
  { id: 'phishtank', name: 'PhishTank', icon: Shield },
  { id: 'antiphishing_ch', name: 'antiphishing.ch', icon: Shield },
  { id: 'virustotal', name: 'VirusTotal', icon: Shield },
  { id: 'apwg', name: 'APWG', icon: Shield },
  { id: 'cisa', name: 'CISA / US-CERT', icon: Shield },
];

export default function TakeDownDashboard() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'batches' | 'reports' | 'settings'>('dashboard');
  const [batches, setBatches] = useState<TakeDownBatch[]>([]);
  const [selectedBatch, setSelectedBatch] = useState<TakeDownBatch | null>(null);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 0 });
  const [filters, setFilters] = useState({ status: '', search: '', service: '' });
  const [showNewBatch, setShowNewBatch] = useState(false);
  const [showSingleUrl, setShowSingleUrl] = useState(false);
  const [singleUrlForm, setSingleUrlForm] = useState({ url: '', services: [] as string[], notes: '', async: true });
  const [batchForm, setBatchForm] = useState({ 
    file: null as File | null, 
    services: [] as string[], 
    notes: '', 
    batchName: '',
    maxUrlsPerBatch: 500 
  });
  const [submitting, setSubmitting] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [queueStats, setQueueStats] = useState({ waiting: 0, active: 0, completed: 0, failed: 0, delayed: 0 });
  const eventSourceRef = useRef<EventSource | null>(null);

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
    } catch {
      // Silently fail
    }
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

  const handleSingleUrlSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const res = await fetch('/api/takedown/single', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(singleUrlForm),
      });
      
      if (res.ok) {
        const data = await res.json();
        toast.success(data.status === 'queued' ? 'URL encolada para procesamiento' : 'Reporte completado');
        setShowSingleUrl(false);
        setSingleUrlForm({ url: '', services: [], notes: '', async: true });
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

  const handleBatchSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!batchForm.file && batchForm.urls?.length === 0) {
      toast.error('Seleccione un archivo o ingrese URLs');
      return;
    }

    setSubmitting(true);
    try {
      const formData = new FormData();
      if (batchForm.file) formData.append('file', batchForm.file);
      formData.append('services', JSON.stringify(batchForm.services.length > 0 ? batchForm.services : ALL_SERVICES.map(s => s.id)));
      formData.append('notes', batchForm.notes);
      formData.append('batchName', batchForm.batchName);
      formData.append('maxUrlsPerBatch', String(batchForm.maxUrlsPerBatch));

      const res = await fetch('/api/takedown/batch', {
        method: 'POST',
        body: formData,
      });

      if (res.ok) {
        const data = await res.json();
        toast.success(`${data.totalUrlsSubmitted} URLs encoladas para procesamiento`);
        setShowNewBatch(false);
        setBatchForm({ file: null, services: [], notes: '', batchName: '', maxUrlsPerBatch: 500 });
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

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copiado al portapapeles');
  };

  useEffect(() => {
    fetchBatches();
    fetchQueueStats();

    if (autoRefresh) {
      const interval = setInterval(() => {
        fetchBatches();
        fetchQueueStats();
        if (selectedBatch) {
          fetchBatchDetails(selectedBatch.id);
        }
      }, 10000);
      return () => clearInterval(interval);
    }
  }, [fetchBatches, fetchQueueStats, autoRefresh, selectedBatch, fetchBatchDetails]);

  useEffect(() => {
    if (selectedBatch) {
      eventSourceRef.current = new EventSource(`/api/takedown/events?batchId=${selectedBatch.id}`);
      eventSourceRef.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'progress') {
          setSelectedBatch(prev => prev ? { ...prev, ...data.batch } : null);
        }
      };
      return () => eventSourceRef.current?.close();
    }
  }, [selectedBatch]);

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
            TakeDown URL Dashboard
          </h1>
          <p className="text-muted-foreground mt-1">
            Monitoreo y gestión de reportes de URLs maliciosas a 13 servicios de seguridad
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => setShowSingleUrl(true)} className="gap-2">
            <ExternalLink className="w-4 h-4" />
            URL Individual
          </Button>
          <Button onClick={() => setShowNewBatch(true)} className="primary-gradient text-primary-foreground gap-2">
            <Upload className="w-4 h-4" />
            Nuevo Lote
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

      {/* Queue Stats Bar */}
      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="py-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-6 text-sm">
              <span className="font-medium text-primary">Cola de Procesamiento:</span>
              <Badge variant="outline" className="gap-1 border-blue-500/30 text-blue-500">
                <Loader2 className="w-3 h-3 animate-spin" />
                Activos: {queueStats.active}
              </Badge>
              <Badge variant="outline" className="gap-1 border-yellow-500/30 text-yellow-500">
                <Clock className="w-3 h-3" />
                Espera: {queueStats.waiting}
              </Badge>
              <Badge variant="outline" className="gap-1 border-emerald-500/30 text-emerald-500">
                <CheckCircle className="w-3 h-3" />
                Completados: {queueStats.completed}
              </Badge>
              <Badge variant="outline" className="gap-1 border-red-500/30 text-red-500">
                <XCircle className="w-3 h-3" />
                Fallidos: {queueStats.failed}
              </Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Dashboard Stats */}
      {activeTab === 'dashboard' && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Total Lotes</p>
                  <p className="text-3xl font-bold">{dashboardStats.totalBatches}</p>
                </div>
                <BarChart2 className="w-10 h-10 text-muted-foreground/30" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Procesando</p>
                  <p className="text-3xl font-bold text-blue-500">{dashboardStats.processingBatches}</p>
                </div>
                <Loader2 className="w-10 h-10 text-blue-500/30 animate-spin" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Completados</p>
                  <p className="text-3xl font-bold text-emerald-500">{dashboardStats.completedBatches}</p>
                </div>
                <CheckCircle className="w-10 h-10 text-emerald-500/30" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Fallidos</p>
                  <p className="text-3xl font-bold text-red-500">{dashboardStats.failedBatches}</p>
                </div>
                <XCircle className="w-10 h-10 text-red-500/30" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Total URLs</p>
                  <p className="text-3xl font-bold">{dashboardStats.totalUrls}</p>
                </div>
                <FileText className="w-10 h-10 text-muted-foreground/30" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Procesadas</p>
                  <p className="text-3xl font-bold text-blue-500">{dashboardStats.totalProcessed}</p>
                </div>
                <Clock className="w-10 h-10 text-blue-500/30" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Exitosas</p>
                  <p className="text-3xl font-bold text-emerald-500">{dashboardStats.totalSuccess}</p>
                </div>
                <CheckCircle className="w-10 h-10 text-emerald-500/30" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Fallidas</p>
                  <p className="text-3xl font-bold text-red-500">{dashboardStats.totalFailed}</p>
                </div>
                <XCircle className="w-10 h-10 text-red-500/30" />
              </div>
            </CardContent>
          </Card>
        </div>
      )}

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
                          <TableHead>Creado</TableHead>
                          <TableHead>Acciones</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {batches.length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
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
                                      <DropdownMenuItem onClick={() => handleExport(batch.id, 'pdf')}>
                                        <Download className="w-4 h-4 mr-2" /> Exportar PDF
                                      </DropdownMenuItem>
                                      <DropdownMenuItem onClick={() => handleExport(batch.id, 'csv')}>
                                        <Download className="w-4 h-4 mr-2" /> Exportar CSV
                                      </DropdownMenuItem>
                                      <DropdownMenuItem onClick={() => handleExport(batch.id, 'xlsx')}>
                                        <Download className="w-4 h-4 mr-2" /> Exportar Excel
                                      </DropdownMenuItem>
                                      <DropdownMenuItem onClick={() => handleExport(batch.id, 'json')}>
                                        <Download className="w-4 h-4 mr-2" /> Exportar JSON
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

                  {/* Pagination */}
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

          {/* REPORTS TAB - Detail View */}
          {activeTab === 'reports' && selectedBatch && (
            <motion.div key="reports" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4 mt-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <div>
                    <CardTitle>{selectedBatch.name}</CardTitle>
                    <CardDescription>ID: {selectedBatch.id} • {selectedBatch.totalUrls} URLs • {selectedBatch.reports.length} reportes</CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    {(() => {
                      const statusConfig = getBatchStatusConfig(selectedBatch.status);
                      const StatusIcon = statusConfig.icon;
                      return (
                        <Badge className={statusConfig.color}>
                          <StatusIcon className="w-3 h-3 mr-1" />
                          {statusConfig.label}
                        </Badge>
                      );
                    })()}
                    <Button variant="outline" size="sm" onClick={() => handleExport(selectedBatch.id, 'pdf')}>
                      <Download className="w-4 h-4 mr-1" /> PDF
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => handleExport(selectedBatch.id, 'csv')}>
                      <Download className="w-4 h-4 mr-1" /> CSV
                    </Button>
                    <Button variant="ghost" size="sm" onClick={() => setSelectedBatch(null)}>
                      <ChevronUp className="w-4 h-4 mr-1" /> Volver
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-6">
                  {/* Progress Bar */}
                  {selectedBatch.status === 'processing' || selectedBatch.status === 'queued' ? (
                    <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-medium">Progreso del Lote</span>
                        <span className="font-mono">{selectedBatch.processedUrls} / {selectedBatch.totalUrls}</span>
                      </div>
                      <Progress value={selectedBatch.totalUrls > 0 ? (selectedBatch.processedUrls / selectedBatch.totalUrls) * 100 : 0} className="h-3" />
                    </div>
                  ) : null}

                  {/* Service Status Summary */}
                  <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
                    {ALL_SERVICES.map(svc => {
                      const results = selectedBatch.serviceResults.filter(sr => sr.service === svc.id);
                      const success = results.filter(r => r.status === 'success').length;
                      const failed = results.filter(r => r.status === 'failed').length;
                      const manual = results.filter(r => r.status === 'manual').length;
                      const pending = results.filter(r => r.status === 'pending' || r.status === 'sent').length;
                      const total = results.length;
                      const Icon = svc.icon;
                      return (
                        <div key={svc.id} className="p-3 rounded-lg border border-border/50 bg-muted/30">
                          <div className="flex items-center gap-2 mb-2">
                            <Icon className="w-4 h-4 text-primary" />
                            <span className="text-sm font-medium truncate">{svc.name}</span>
                          </div>
                          <div className="flex items-center gap-2 text-xs">
                            {success > 0 && <Badge variant="secondary" className="gap-1 bg-emerald-500/20 text-emerald-500"><CheckCircle className="w-2.5 h-2.5" />{success}</Badge>}
                            {manual > 0 && <Badge variant="secondary" className="gap-1 bg-yellow-500/20 text-yellow-500"><ExternalLink className="w-2.5 h-2.5" />{manual}</Badge>}
                            {pending > 0 && <Badge variant="secondary" className="gap-1 bg-blue-500/20 text-blue-500"><Clock className="w-2.5 h-2.5" />{pending}</Badge>}
                            {failed > 0 && <Badge variant="secondary" className="gap-1 bg-red-500/20 text-red-500"><XCircle className="w-2.5 h-2.5" />{failed}</Badge>}
                            {total === 0 && <span className="text-muted-foreground">Sin datos</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Reports Table */}
                  <Tabs defaultValue="table" className="w-full">
                    <TabsList className="grid w-full grid-cols-2">
                      <TabsTrigger value="table">Tabla Consolidada</TabsTrigger>
                      <TabsTrigger value="urls">Por URL</TabsTrigger>
                    </TabsList>

                    <TabsContent value="table" className="mt-4">
                      <ScrollArea className="max-h-[500px]">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>URL</TableHead>
                              <TableHead>Servicio</TableHead>
                              <TableHead>Estado</TableHead>
                              <TableHead>Mensaje</TableHead>
                              <TableHead>Ref. ID</TableHead>
                              <TableHead>Timestamp</TableHead>
                              <TableHead>Reintentos</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {selectedBatch.serviceResults.length === 0 ? (
                              <TableRow>
                                <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                                  No hay resultados de servicios aún
                                </TableCell>
                              </TableRow>
                            ) : (
                              selectedBatch.serviceResults.map((sr) => {
                                const statusConfig = getServiceStatusConfig(sr.status);
                                const StatusIcon = statusConfig.icon;
                                return (
                                  <TableRow key={sr.id}>
                                    <TableCell className="font-mono text-xs max-w-xs truncate">{sr.url}</TableCell>
                                    <TableCell className="font-medium">{sr.serviceName}</TableCell>
                                    <TableCell>
                                      <Badge className={statusConfig.color}><StatusIcon className="w-3 h-3 mr-1" />{statusConfig.label}</Badge>
                                    </TableCell>
                                    <TableCell className="text-muted-foreground max-w-md">{sr.message}</TableCell>
                                    <TableCell className="font-mono text-xs">{sr.referenceId || '-'}</TableCell>
                                    <TableCell className="font-mono text-xs text-muted-foreground">{new Date(sr.createdAt).toLocaleString()}</TableCell>
                                    <TableCell className="text-center">{sr.retryCount > 0 ? <Badge variant="outline">{sr.retryCount}</Badge> : '-'}</TableCell>
                                  </TableRow>
                                );
                              })
                            )}
                          </TableBody>
                        </Table>
                      </ScrollArea>
                    </TabsContent>

                    <TabsContent value="urls" className="mt-4">
                      <ScrollArea className="max-h-[500px]">
                        <div className="space-y-4">
                          {selectedBatch.reports.map((report) => (
                            <Card key={report.id} className="border-border/50">
                              <CardHeader className="pb-3">
                                <div className="flex items-center justify-between">
                                  <p className="font-mono text-sm text-primary truncate flex-1 mr-4">{report.url}</p>
                                  {(() => {
                                    const statusConfig = getBatchStatusConfig(report.status);
                                    const StatusIcon = statusConfig.icon;
                                    return (
                                      <Badge className={statusConfig.color}>
                                        <StatusIcon className="w-3 h-3 mr-1" />
                                        {statusConfig.label}
                                      </Badge>
                                    );
                                  })()}
                                </div>
                              </CardHeader>
                              <CardContent>
                                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                                  {report.serviceResults.map((sr) => {
                                    const statusConfig = getServiceStatusConfig(sr.status);
                                    const StatusIcon = statusConfig.icon;
                                    return (
                                      <div key={sr.id} className="p-3 rounded-lg border" style={{ background: `${statusConfig.color}10`, borderColor: `${statusConfig.color}30` }}>
                                        <div className="font-medium text-sm mb-1">{sr.serviceName}</div>
                                        <Badge className={statusConfig.color}><StatusIcon className="w-3 h-3 mr-1" />{statusConfig.label}</Badge>
                                        <p className="text-xs text-muted-foreground mt-2">{sr.message}</p>
                                        <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
                                          <span className="font-mono">{new Date(sr.createdAt).toLocaleTimeString()}</span>
                                          {sr.referenceId && <span className="font-mono">{sr.referenceId}</span>}
                                        </div>
                                      </div>
                                    );
                                  })}
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      </ScrollArea>
                    </TabsContent>
                  </Tabs>
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
                    Configuración de Servicios (13 Proveedores)
                  </CardTitle>
                  <CardDescription>
                    Estado de integración y configuración de cada servicio de reporte
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {ALL_SERVICES.map((svc) => {
                      const Icon = svc.icon;
                      return (
                        <Card key={svc.id} className="border-border/50 hover:border-primary/30 transition-colors">
                          <CardContent className="p-4">
                            <div className="flex items-center gap-3">
                              <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                                <Icon className="w-5 h-5 text-primary" />
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className="font-medium truncate">{svc.name}</p>
                                <p className="text-xs text-muted-foreground">Integración lista</p>
                              </div>
                              <Badge variant="outline" className="border-emerald-500/30 text-emerald-500">
                                <CheckCircle className="w-3 h-3 mr-1" /> Activo
                              </Badge>
                            </div>
                          </CardContent>
                        </Card>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Endpoints de API</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div className="p-3 rounded-lg bg-muted/50">
                      <p className="font-mono text-primary">POST /api/takedown/single</p>
                      <p className="text-muted-foreground">Reporte de URL individual</p>
                    </div>
                    <div className="p-3 rounded-lg bg-muted/50">
                      <p className="font-mono text-primary">POST /api/takedown/batch</p>
                      <p className="text-muted-foreground">Carga masiva de URLs (archivo/lista)</p>
                    </div>
                    <div className="p-3 rounded-lg bg-muted/50">
                      <p className="font-mono text-primary">GET /api/takedown/batch</p>
                      <p className="text-muted-foreground">Listar/obtener lotes</p>
                    </div>
                    <div className="p-3 rounded-lg bg-muted/50">
                      <p className="font-mono text-primary">POST /api/takedown/export</p>
                      <p className="text-muted-foreground">Exportar reportes (PDF/CSV/JSON/XLSX)</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )}

          {/* Empty state for reports tab */}
          {activeTab === 'reports' && !selectedBatch && (
            <motion.div key="reports-empty" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="mt-4">
              <Card>
                <CardContent className="py-12 text-center">
                  <FileText className="w-16 h-16 mx-auto mb-4 text-muted-foreground/30" />
                  <h3 className="text-lg font-medium mb-2">Seleccione un lote</h3>
                  <p className="text-muted-foreground mb-4">Haga clic en un lote de la pestaña "Lotes" para ver el detalle de reportes</p>
                  <Button onClick={() => setActiveTab('batches')}>
                    <ChevronUp className="w-4 h-4 mr-2" />
                    Ir a Lotes
                  </Button>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>
      </Tabs>

      {/* Single URL Dialog */}
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
            <div className="space-y-2">
              <Label>Servicios</Label>
              <div className="flex flex-wrap gap-2">
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
              <Label>Notas (opcional)</Label>
              <Textarea
                value={singleUrlForm.notes}
                onChange={e => setSingleUrlForm({...singleUrlForm, notes: e.target.value})}
                placeholder="Información adicional para reportes por email..."
                rows={3}
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="async"
                checked={singleUrlForm.async}
                onChange={e => setSingleUrlForm({...singleUrlForm, async: e.target.checked})}
                className="rounded border-border"
              />
              <Label htmlFor="async" className="text-sm cursor-pointer">
                Procesamiento asíncrono (cola)
              </Label>
            </div>
            <div className="flex justify-end gap-2 pt-4 border-t">
              <Button type="button" variant="outline" onClick={() => setShowSingleUrl(false)}>
                Cancelar
              </Button>
              <Button type="submit" disabled={submitting || !singleUrlForm.url}>
                {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4 mr-2" />}
                {submitting ? 'Enviando...' : 'Enviar Reporte'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* New Batch Dialog */}
      <Dialog open={showNewBatch} onOpenChange={setShowNewBatch}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Nuevo Lote de URLs</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleBatchSubmit} className="space-y-4 p-4">
            <div className="space-y-2">
              <Label>Nombre del lote (opcional)</Label>
              <Input
                placeholder="Lote Phishing - Septiembre 2026"
                value={batchForm.batchName}
                onChange={e => setBatchForm({...batchForm, batchName: e.target.value})}
              />
            </div>
            <div className="space-y-2">
              <Label>Archivo .txt, .csv o .xlsx</Label>
              <input
                type="file"
                accept=".txt,.csv,.xlsx"
                onChange={e => setBatchForm({...batchForm, file: e.target.files?.[0] || null})}
                className="w-full text-sm"
              />
              <p className="text-xs text-muted-foreground">Máx. {batchForm.maxUrlsPerBatch} URLs por lote</p>
            </div>
            <div className="space-y-2">
              <Label>Límite de URLs por lote</Label>
              <Input
                type="number"
                min="1"
                max="5000"
                value={batchForm.maxUrlsPerBatch}
                onChange={e => setBatchForm({...batchForm, maxUrlsPerBatch: parseInt(e.target.value) || 500})}
              />
            </div>
            <div className="space-y-2">
              <Label>Servicios (vacío = todos los 13)</Label>
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
            <div className="space-y-2">
              <Label>Notas (opcional)</Label>
              <Textarea
                value={batchForm.notes}
                onChange={e => setBatchForm({...batchForm, notes: e.target.value})}
                placeholder="Información adicional para reportes por email..."
                rows={3}
              />
            </div>
            <div className="flex justify-end gap-2 pt-4 border-t">
              <Button type="button" variant="outline" onClick={() => setShowNewBatch(false)}>
                Cancelar
              </Button>
              <Button type="submit" disabled={submitting || (!batchForm.file && (!batchForm.urls || batchForm.urls.length === 0))}>
                {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4 mr-2" />}
                {submitting ? 'Procesando...' : 'Crear Lote'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}