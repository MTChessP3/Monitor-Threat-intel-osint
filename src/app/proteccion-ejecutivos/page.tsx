'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Search, Plus, Trash2, Edit3, UserCheck, AlertTriangle,
  Loader2, ExternalLink, X, Save, Eye,
  Building2, Mail, Phone, FileText, Globe, ChevronUp,
  Download, FileCheck, FileX, HardDrive, FolderOpen,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from '@/components/ui/dialog';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';
import { toast } from 'sonner';

// ============================================================================
// Types
// ============================================================================
interface Executive {
  id: string;
  identificationNum: string;
  fullName: string;
  email: string | null;
  phone: string | null;
  position: string | null;
  organization: string | null;
  riskLevel: string;
  notes: string | null;
  lastMetasearch: string | null;
  lastMetasearchResults: string | null;
  active: boolean;
  createdAt: string;
  updatedAt: string;
}

interface MetasearchResult {
  title: string;
  url: string;
  snippet: string;
  source: string;
  position: number;
  fileType?: string;
  isDownloadable?: boolean;
  downloaded?: boolean;
  localPath?: string;
}

interface EvidenceDetail {
  url: string;
  sourceDomain: string;
  discoveredAt: string;
  title: string;
  fileType: string;
  fileName: string;
  downloadStatus: 'success' | 'failed' | 'skipped';
  localPath: string;
  fileSize: number;
  error?: string;
}

interface MetasearchResponse {
  success: boolean;
  searchEngine: string;
  enginesUsed: string[];
  engineStats: { google: number; bing: number; yandex: number; duckduckgo: number; brave: number; webSearch: number };
  queryGroups: Array<{ label: string; queryCount: number; blockType: string }>;
  resultCount: number;
  downloadableCount: number;
  downloadedCount: number;
  results: MetasearchResult[];
  aiAnalysis: string;
  evidence: EvidenceDetail[];
  evidenceDetailPath: string;
  executive: { id: string; fullName: string; identificationNum: string; email: string | null } | null;
  timestamp: string;
}

// ============================================================================
// Risk Badge
// ============================================================================
function RiskBadge({ level }: { level: string }) {
  const config: Record<string, { color: string; bg: string; label: string }> = {
    bajo: { color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/20', label: 'BAJO' },
    medio: { color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/20', label: 'MEDIO' },
    alto: { color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20', label: 'ALTO' },
    critico: { color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20', label: 'CRÍTICO' },
  };
  const c = config[level] || config.bajo;
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-semibold border ${c.bg} ${c.color}`}>
      {c.label}
    </span>
  );
}

// File type icon
function FileTypeIcon({ fileType, downloaded }: { fileType: string; downloaded?: boolean }) {
  const colors: Record<string, string> = {
    pdf: 'text-red-400', xlsx: 'text-green-400', xls: 'text-green-400',
    doc: 'text-blue-400', docx: 'text-blue-400', ppt: 'text-orange-400',
    txt: 'text-gray-400', rar: 'text-purple-400', zip: 'text-purple-400',
    '7z': 'text-purple-400', csv: 'text-emerald-400', rtf: 'text-cyan-400',
    htm: 'text-teal-400', html: 'text-teal-400', json: 'text-yellow-400',
    xml: 'text-yellow-300', yaml: 'text-yellow-300', yml: 'text-yellow-300',
    env: 'text-red-500', conf: 'text-red-500', config: 'text-red-500', ini: 'text-red-500',
    bak: 'text-pink-400', old: 'text-pink-400', sql: 'text-indigo-400', db: 'text-indigo-400',
    sqlite: 'text-indigo-400', odt: 'text-blue-300', ods: 'text-green-300', odp: 'text-orange-300',
    png: 'text-sky-400', jpg: 'text-sky-400', jpeg: 'text-sky-400', svg: 'text-sky-400',
  };
  const color = colors[fileType] || 'text-muted-foreground';
  return (
    <span className={`text-[10px] font-mono font-bold ${color} uppercase`}>
      {downloaded ? '✓' : ''}{fileType}
    </span>
  );
}

// ============================================================================
// Main Component
// ============================================================================
export default function ProteccionEjecutivosPage() {
  const [executives, setExecutives] = useState<Executive[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedExecutive, setSelectedExecutive] = useState<Executive | null>(null);
  const [metasearchLoading, setMetasearchLoading] = useState(false);
  const [metasearchResults, setMetasearchResults] = useState<MetasearchResponse | null>(null);
  const [showResults, setShowResults] = useState(false);
  const [searchProgress, setSearchProgress] = useState('');

  // Dialog states
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [showDetailDialog, setShowDetailDialog] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    identificationNum: '', fullName: '', email: '', phone: '',
    position: '', organization: '', riskLevel: 'bajo', notes: '',
  });

  // Fetch executives
  const fetchExecutives = useCallback(async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (searchTerm) params.set('search', searchTerm);
      const res = await fetch(`/api/executives?${params.toString()}`);
      if (!res.ok) throw new Error('Error al cargar ejecutivos');
      const data = await res.json();
      setExecutives(data.executives || []);
    } catch {
      toast.error('Error al cargar la lista de ejecutivos');
    } finally {
      setLoading(false);
    }
  }, [searchTerm]);

  useEffect(() => { fetchExecutives(); }, [fetchExecutives]);

  const resetForm = () => {
    setFormData({
      identificationNum: '', fullName: '', email: '', phone: '',
      position: '', organization: '', riskLevel: 'bajo', notes: '',
    });
  };

  const handleCreate = async () => {
    try {
      const res = await fetch('/api/executives', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });
      const data = await res.json();
      if (!res.ok) { toast.error(data.error || 'Error al crear ejecutivo'); return; }
      toast.success(`Ejecutivo ${formData.fullName} creado exitosamente`);
      setShowCreateDialog(false); resetForm(); fetchExecutives();
    } catch { toast.error('Error de conexión al crear ejecutivo'); }
  };

  const handleUpdate = async () => {
    if (!selectedExecutive) return;
    try {
      const res = await fetch('/api/executives', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: selectedExecutive.id, ...formData }),
      });
      const data = await res.json();
      if (!res.ok) { toast.error(data.error || 'Error al actualizar ejecutivo'); return; }
      toast.success(`Ejecutivo ${formData.fullName} actualizado exitosamente`);
      setShowEditDialog(false); setSelectedExecutive(null); resetForm(); fetchExecutives();
    } catch { toast.error('Error de conexión al actualizar ejecutivo'); }
  };

  const handleDelete = async () => {
    if (!selectedExecutive) return;
    try {
      const res = await fetch(`/api/executives?id=${selectedExecutive.id}`, { method: 'DELETE' });
      if (!res.ok) { toast.error('Error al eliminar ejecutivo'); return; }
      toast.success('Ejecutivo eliminado exitosamente');
      setShowDeleteDialog(false); setSelectedExecutive(null); fetchExecutives();
    } catch { toast.error('Error de conexión al eliminar ejecutivo'); }
  };

  const openEditDialog = (exec: Executive) => {
    setSelectedExecutive(exec);
    setFormData({
      identificationNum: exec.identificationNum, fullName: exec.fullName,
      email: exec.email || '', phone: exec.phone || '', position: exec.position || '',
      organization: exec.organization || '', riskLevel: exec.riskLevel, notes: exec.notes || '',
    });
    setShowEditDialog(true);
  };

  // Execute metabúsqueda with OSINT query matrix
  const handleMetasearch = async () => {
    if (!selectedExecutive) return;
    setMetasearchLoading(true);
    setShowResults(true);
    setMetasearchResults(null);
    setSearchProgress('Iniciando Meta-Búsqueda OSINT v3.0 (6 motores + Dorking expandido)...');

    try {
      const res = await fetch('/api/metasearch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ executiveId: selectedExecutive.id, downloadFiles: true }),
      });

      const data = await res.json();
      if (!res.ok) {
        toast.error(data.error || 'Error en metabúsqueda');
        setMetasearchLoading(false);
        return;
      }

      setMetasearchResults(data);
      setSearchProgress('');

      // Summary toast
      const dlCount = data.downloadedCount || 0;
      const totalCount = data.resultCount || 0;
      toast.success(`Búsqueda completada: ${totalCount} resultados, ${dlCount} archivos descargados`);
    } catch {
      toast.error('Error de conexión en metabúsqueda');
      setSearchProgress('');
    } finally {
      setMetasearchLoading(false);
    }
  };

  const handleSelectExecutive = (exec: Executive) => {
    if (selectedExecutive?.id === exec.id) {
      setSelectedExecutive(null); setShowResults(false); setMetasearchResults(null);
    } else {
      setSelectedExecutive(exec); setShowResults(false); setMetasearchResults(null);
    }
  };

  const riskStats = executives.reduce((acc, e) => {
    acc[e.riskLevel] = (acc[e.riskLevel] || 0) + 1; return acc;
  }, {} as Record<string, number>);

  // Compute evidence count from results
  const evidenceCount = metasearchResults?.evidence?.filter(e => e.downloadStatus === 'success').length || 0;

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-amber-500 to-amber-700 flex items-center justify-center">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-foreground tracking-tight">Protección de Ejecutivos</h1>
                <p className="text-xs text-muted-foreground">Módulo de gestión y metabúsqueda OSINT</p>
              </div>
            </div>
            <a href="/" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
              ← Dashboard
            </a>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Stats Row */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Card className="border-border bg-card/60">
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold text-foreground">{executives.length}</p>
              <p className="text-xs text-muted-foreground">Total Ejecutivos</p>
            </CardContent>
          </Card>
          {['critico', 'alto', 'medio', 'bajo'].map(level => (
            <Card key={level} className="border-border bg-card/60">
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold text-foreground">{riskStats[level] || 0}</p>
                <p className="text-xs text-muted-foreground">Riesgo {level.charAt(0).toUpperCase() + level.slice(1)}</p>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Toolbar */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2 flex-1 w-full sm:w-auto">
            <div className="relative flex-1 sm:max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Buscar ejecutivo..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-9 bg-muted/30 border-border"
              />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              onClick={handleMetasearch}
              disabled={!selectedExecutive || metasearchLoading}
              className="bg-[#1a1a5e] hover:bg-[#252580] text-white font-medium gap-2 disabled:opacity-40"
              title={selectedExecutive ? `Meta-Búsqueda OSINT v3.0: ${selectedExecutive.fullName}` : 'Seleccione un ejecutivo primero'}
            >
              {metasearchLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              Meta-Búsqueda OSINT
            </Button>
            <Button
              onClick={() => { resetForm(); setShowCreateDialog(true); }}
              className="bg-amber-600 hover:bg-amber-700 text-white font-medium gap-2"
            >
              <Plus className="w-4 h-4" /> Nuevo Ejecutivo
            </Button>
          </div>
        </div>

        {/* Selection indicator */}
        {selectedExecutive && (
          <motion.div
            initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20"
          >
            <UserCheck className="w-4 h-4 text-amber-500" />
            <span className="text-sm text-amber-400">
              Seleccionado: <strong>{selectedExecutive.fullName}</strong>
              {selectedExecutive.position && ` — ${selectedExecutive.position}`}
              {selectedExecutive.organization && ` — ${selectedExecutive.organization}`}
            </span>
            <button onClick={() => { setSelectedExecutive(null); setShowResults(false); }} className="ml-auto text-amber-400 hover:text-amber-300">
              <X className="w-4 h-4" />
            </button>
          </motion.div>
        )}

        {/* Executives Table */}
        <Card className="border-border bg-card/60 overflow-hidden">
          <CardHeader className="pb-3">
            <CardTitle className="text-base text-foreground">Directorio de Ejecutivos</CardTitle>
            <CardDescription className="text-muted-foreground text-xs">
              Seleccione un ejecutivo para habilitar la Meta-Búsqueda OSINT v3.0 (Google + Bing + Yandex + DuckDuckGo + Brave + Web Search + Dorking 30+ extensiones)
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="w-6 h-6 animate-spin text-amber-500" />
                <span className="ml-2 text-muted-foreground">Cargando ejecutivos...</span>
              </div>
            ) : executives.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Shield className="w-12 h-12 mb-3 opacity-30" />
                <p className="text-sm">No hay ejecutivos registrados</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border hover:bg-transparent">
                      <TableHead className="w-10"></TableHead>
                      <TableHead className="text-xs text-muted-foreground">Identificación</TableHead>
                      <TableHead className="text-xs text-muted-foreground">Nombre Completo</TableHead>
                      <TableHead className="text-xs text-muted-foreground">Correo Electrónico</TableHead>
                      <TableHead className="text-xs text-muted-foreground">Cargo / Organización</TableHead>
                      <TableHead className="text-xs text-muted-foreground">Riesgo</TableHead>
                      <TableHead className="text-xs text-muted-foreground">Última Búsqueda</TableHead>
                      <TableHead className="w-24 text-xs text-muted-foreground">Acciones</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {executives.map((exec) => (
                      <TableRow
                        key={exec.id}
                        className={`border-border cursor-pointer transition-colors ${
                          selectedExecutive?.id === exec.id ? 'bg-amber-500/10 border-amber-500/30' : 'hover:bg-muted/30'
                        }`}
                        onClick={() => handleSelectExecutive(exec)}
                      >
                        <TableCell className="py-3">
                          <div className={`w-3 h-3 rounded-full border-2 ${
                            selectedExecutive?.id === exec.id ? 'bg-amber-500 border-amber-500' : 'border-muted-foreground/30'
                          }`} />
                        </TableCell>
                        <TableCell className="py-3"><span className="text-xs font-mono text-muted-foreground">{exec.identificationNum}</span></TableCell>
                        <TableCell className="py-3"><span className="text-sm font-medium text-foreground">{exec.fullName}</span></TableCell>
                        <TableCell className="py-3"><span className="text-xs text-muted-foreground">{exec.email || '—'}</span></TableCell>
                        <TableCell className="py-3">
                          <div className="flex flex-col">
                            <span className="text-xs text-foreground">{exec.position || '—'}</span>
                            <span className="text-xs text-muted-foreground">{exec.organization || ''}</span>
                          </div>
                        </TableCell>
                        <TableCell className="py-3"><RiskBadge level={exec.riskLevel} /></TableCell>
                        <TableCell className="py-3">
                          <span className="text-xs text-muted-foreground">
                            {exec.lastMetasearch ? new Date(exec.lastMetasearch).toLocaleDateString('es-CO', { day: '2-digit', month: 'short', year: 'numeric' }) : 'Nunca'}
                          </span>
                        </TableCell>
                        <TableCell className="py-3">
                          <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                            <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground" onClick={() => { setSelectedExecutive(exec); setShowDetailDialog(true); }}><Eye className="w-3.5 h-3.5" /></Button>
                            <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-amber-500" onClick={() => openEditDialog(exec)}><Edit3 className="w-3.5 h-3.5" /></Button>
                            <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-red-500" onClick={() => { setSelectedExecutive(exec); setShowDeleteDialog(true); }}><Trash2 className="w-3.5 h-3.5" /></Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Metasearch Results */}
        <AnimatePresence>
          {showResults && (
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }}>
              <Card className="border-border bg-card/60">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-base text-foreground flex items-center gap-2">
                        <Globe className="w-4 h-4 text-amber-500" />
                        Resultados de Meta-Búsqueda OSINT
                      </CardTitle>
                      {metasearchResults && (
                        <CardDescription className="text-xs text-muted-foreground mt-1">
                          {metasearchResults.searchEngine} — {metasearchResults.resultCount} resultados — {metasearchResults.downloadedCount} archivos descargados
                        </CardDescription>
                      )}
                    </div>
                    <Button variant="ghost" size="sm" onClick={() => setShowResults(false)} className="text-muted-foreground hover:text-foreground">
                      <ChevronUp className="w-4 h-4" />
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  {metasearchLoading ? (
                    <div className="flex flex-col items-center justify-center py-12">
                      <Loader2 className="w-8 h-8 animate-spin text-amber-500 mb-3" />
                      <p className="text-sm text-muted-foreground">Ejecutando Meta-Búsqueda OSINT Multi-Engine...</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Consultando: &quot;{selectedExecutive?.fullName}&quot; × 30+ extensiones en Google + Bing + Yandex + DuckDuckGo + Brave + Web Search
                      </p>
                      {searchProgress && (
                        <p className="text-xs text-amber-400 mt-2">{searchProgress}</p>
                      )}
                    </div>
                  ) : metasearchResults ? (
                    <>
                      {/* Engine Stats */}
                      {metasearchResults.engineStats && (
                        <div className="mb-4 p-3 rounded-lg bg-purple-500/5 border border-purple-500/20">
                          <div className="flex items-center gap-2 mb-2">
                            <Globe className="w-4 h-4 text-purple-400" />
                            <p className="text-xs font-medium text-purple-400">Motores de Búsqueda Consultados</p>
                          </div>
                          <div className="grid grid-cols-6 gap-2 text-center">
                            <div>
                              <p className="text-lg font-bold text-blue-400">{metasearchResults.engineStats.google}</p>
                              <p className="text-[10px] text-muted-foreground">Google</p>
                            </div>
                            <div>
                              <p className="text-lg font-bold text-cyan-400">{metasearchResults.engineStats.bing}</p>
                              <p className="text-[10px] text-muted-foreground">Bing</p>
                            </div>
                            <div>
                              <p className="text-lg font-bold text-red-400">{metasearchResults.engineStats.yandex}</p>
                              <p className="text-[10px] text-muted-foreground">Yandex</p>
                            </div>
                            <div>
                              <p className="text-lg font-bold text-orange-400">{metasearchResults.engineStats.duckduckgo}</p>
                              <p className="text-[10px] text-muted-foreground">DuckDuckGo</p>
                            </div>
                            <div>
                              <p className="text-lg font-bold text-amber-300">{metasearchResults.engineStats.brave}</p>
                              <p className="text-[10px] text-muted-foreground">Brave</p>
                            </div>
                            <div>
                              <p className="text-lg font-bold text-foreground">{metasearchResults.engineStats.webSearch}</p>
                              <p className="text-[10px] text-muted-foreground">Web Search</p>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Query Groups Summary */}
                      {metasearchResults.queryGroups && metasearchResults.queryGroups.length > 0 && (
                        <div className="mb-4 p-3 rounded-lg bg-muted/20 border border-border">
                          <p className="text-xs font-medium text-foreground mb-2">Matriz de Dorking OSINT Ejecutada:</p>
                          <div className="flex flex-wrap gap-2">
                            {metasearchResults.queryGroups.map((group, idx) => {
                              const blockColors: Record<string, string> = {
                                name: 'border-blue-500/30 text-blue-400',
                                email: 'border-purple-500/30 text-purple-400',
                                id: 'border-amber-500/30 text-amber-400',
                                combined: 'border-red-500/30 text-red-400',
                                custom: 'border-green-500/30 text-green-400',
                              };
                              const color = blockColors[group.blockType] || 'border-border';
                              return (
                                <Badge key={idx} variant="outline" className={`text-[10px] ${color}`}>
                                  [{group.blockType?.toUpperCase()}] {group.label} ({group.queryCount})
                                </Badge>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {/* AI Analysis */}
                      {metasearchResults.aiAnalysis && (
                        <div className="mb-4 p-4 rounded-lg bg-amber-500/5 border border-amber-500/20">
                          <div className="flex items-center gap-2 mb-3">
                            <Shield className="w-4 h-4 text-amber-400" />
                            <p className="text-xs font-semibold text-amber-400">Análisis de Inteligencia OSINT - IA</p>
                          </div>
                          <div className="text-xs text-foreground/90 whitespace-pre-wrap leading-relaxed">
                            {metasearchResults.aiAnalysis}
                          </div>
                        </div>
                      )}

                      {/* Evidence Summary */}
                      {(metasearchResults.downloadedCount > 0 || metasearchResults.downloadableCount > 0) && (
                        <div className="mb-4 p-3 rounded-lg bg-blue-500/5 border border-blue-500/20">
                          <div className="flex items-center gap-2 mb-2">
                            <HardDrive className="w-4 h-4 text-blue-400" />
                            <p className="text-xs font-medium text-blue-400">Evidencia Digital Preservada</p>
                          </div>
                          <div className="grid grid-cols-3 gap-2 text-center">
                            <div>
                              <p className="text-lg font-bold text-foreground">{metasearchResults.downloadableCount}</p>
                              <p className="text-[10px] text-muted-foreground">Documentos Encontrados</p>
                            </div>
                            <div>
                              <p className="text-lg font-bold text-emerald-400">{metasearchResults.downloadedCount}</p>
                              <p className="text-[10px] text-muted-foreground">Descargados</p>
                            </div>
                            <div>
                              <p className="text-lg font-bold text-red-400">{metasearchResults.downloadableCount - metasearchResults.downloadedCount}</p>
                              <p className="text-[10px] text-muted-foreground">Fallidos</p>
                            </div>
                          </div>
                          {metasearchResults.evidenceDetailPath && (
                            <div className="mt-2 flex items-center gap-1 text-xs text-muted-foreground">
                              <FolderOpen className="w-3 h-3" />
                              <span className="font-mono text-[10px]">{metasearchResults.evidenceDetailPath}</span>
                            </div>
                          )}
                        </div>
                      )}

                      {metasearchResults.results.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                          <Search className="w-10 h-10 mb-3 opacity-30" />
                          <p className="text-sm">No se encontraron resultados</p>
                        </div>
                      ) : (
                        <div className="space-y-2">
                          {metasearchResults.results.map((result, index) => (
                            <motion.div
                              key={index}
                              initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                              transition={{ delay: index * 0.03 }}
                              className={`p-3 rounded-lg border transition-colors ${
                                result.downloaded
                                  ? 'border-emerald-500/20 bg-emerald-500/5'
                                  : result.isDownloadable
                                    ? 'border-amber-500/20 bg-amber-500/5'
                                    : 'border-border bg-muted/20'
                              }`}
                            >
                              <div className="flex items-start gap-3">
                                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-amber-500/10 text-amber-500 flex items-center justify-center text-xs font-mono">
                                  {result.position}
                                </span>
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 mb-1">
                                    <a
                                      href={result.url} target="_blank" rel="noopener noreferrer"
                                      className="text-sm font-medium text-amber-500 hover:text-amber-400 hover:underline truncate"
                                    >
                                      {result.title}
                                    </a>
                                    <ExternalLink className="w-3 h-3 text-muted-foreground flex-shrink-0" />
                                  </div>
                                  <p className="text-xs text-muted-foreground mb-1 break-all">{result.url}</p>
                                  {result.snippet && (
                                    <p className="text-xs text-muted-foreground/80 line-clamp-2">{result.snippet}</p>
                                  )}
                                  <div className="flex items-center gap-2 mt-1.5">
                                    <Badge variant="outline" className="text-[10px] h-4 px-1.5 border-border">
                                      {result.source}
                                    </Badge>
                                    {result.fileType && result.fileType !== 'html' && (
                                      <Badge variant="outline" className="text-[10px] h-4 px-1.5 border-amber-500/30 text-amber-400">
                                        .{result.fileType}
                                      </Badge>
                                    )}
                                    {result.isDownloadable && (
                                      result.downloaded ? (
                                        <Badge className="text-[10px] h-4 px-1.5 bg-emerald-500/20 text-emerald-400 border-emerald-500/30 border">
                                          <FileCheck className="w-3 h-3 mr-1" /> Descargado
                                        </Badge>
                                      ) : (
                                        <Badge variant="outline" className="text-[10px] h-4 px-1.5 border-amber-500/30 text-amber-400">
                                          <Download className="w-3 h-3 mr-1" /> Descargable
                                        </Badge>
                                      )
                                    )}
                                  </div>
                                </div>
                              </div>
                            </motion.div>
                          ))}
                        </div>
                      )}
                    </>
                  ) : null}
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Dialogs - Create, Edit, Detail, Delete */}
        {/* Executive Detail Dialog */}
        <Dialog open={showDetailDialog} onOpenChange={setShowDetailDialog}>
          <DialogContent className="max-w-lg bg-card border-border">
            <DialogHeader>
              <DialogTitle className="text-foreground">Detalle del Ejecutivo</DialogTitle>
              <DialogDescription className="text-muted-foreground">Información completa del ejecutivo</DialogDescription>
            </DialogHeader>
            {selectedExecutive && (
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 rounded-full bg-amber-500/10 flex items-center justify-center"><Shield className="w-6 h-6 text-amber-500" /></div>
                  <div>
                    <h3 className="text-lg font-semibold text-foreground">{selectedExecutive.fullName}</h3>
                    <RiskBadge level={selectedExecutive.riskLevel} />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1"><p className="text-xs text-muted-foreground">Identificación</p><p className="text-sm text-foreground font-mono">{selectedExecutive.identificationNum}</p></div>
                  <div className="space-y-1"><p className="text-xs text-muted-foreground flex items-center gap-1"><Mail className="w-3 h-3" /> Correo</p><p className="text-sm text-foreground">{selectedExecutive.email || '—'}</p></div>
                  <div className="space-y-1"><p className="text-xs text-muted-foreground flex items-center gap-1"><Phone className="w-3 h-3" /> Teléfono</p><p className="text-sm text-foreground">{selectedExecutive.phone || '—'}</p></div>
                  <div className="space-y-1"><p className="text-xs text-muted-foreground flex items-center gap-1"><Building2 className="w-3 h-3" /> Organización</p><p className="text-sm text-foreground">{selectedExecutive.organization || '—'}</p></div>
                  <div className="space-y-1 col-span-2"><p className="text-xs text-muted-foreground">Cargo</p><p className="text-sm text-foreground">{selectedExecutive.position || '—'}</p></div>
                  {selectedExecutive.notes && (
                    <div className="space-y-1 col-span-2"><p className="text-xs text-muted-foreground flex items-center gap-1"><FileText className="w-3 h-3" /> Notas</p><p className="text-sm text-foreground whitespace-pre-wrap">{selectedExecutive.notes}</p></div>
                  )}
                </div>
                {selectedExecutive.lastMetasearch && (
                  <div className="p-3 rounded-lg bg-muted/30 border border-border">
                    <p className="text-xs text-muted-foreground">Última Meta-Búsqueda</p>
                    <p className="text-sm text-foreground">{new Date(selectedExecutive.lastMetasearch).toLocaleString('es-CO')}</p>
                  </div>
                )}
              </div>
            )}
          </DialogContent>
        </Dialog>

        {/* Create Dialog */}
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogContent className="max-w-lg bg-card border-border">
            <DialogHeader><DialogTitle className="text-foreground">Nuevo Ejecutivo</DialogTitle><DialogDescription className="text-muted-foreground">Registrar un nuevo ejecutivo</DialogDescription></DialogHeader>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Número de Identificación *</Label><Input placeholder="CC-12345678" value={formData.identificationNum} onChange={(e) => setFormData(prev => ({ ...prev, identificationNum: e.target.value }))} className="bg-muted/30 border-border" /></div>
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Nivel de Riesgo</Label>
                  <select value={formData.riskLevel} onChange={(e) => setFormData(prev => ({ ...prev, riskLevel: e.target.value }))} className="w-full h-9 rounded-md bg-muted/30 border border-border text-sm text-foreground px-3">
                    <option value="bajo">Bajo</option><option value="medio">Medio</option><option value="alto">Alto</option><option value="critico">Crítico</option>
                  </select>
                </div>
              </div>
              <div className="space-y-2"><Label className="text-xs text-muted-foreground">Nombre Completo *</Label><Input placeholder="Juan Carlos Pérez Gómez" value={formData.fullName} onChange={(e) => setFormData(prev => ({ ...prev, fullName: e.target.value }))} className="bg-muted/30 border-border" /></div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2"><Label className="text-xs text-muted-foreground flex items-center gap-1"><Mail className="w-3 h-3" /> Correo Electrónico</Label><Input placeholder="correo@ejemplo.com" type="email" value={formData.email} onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))} className="bg-muted/30 border-border" /></div>
                <div className="space-y-2"><Label className="text-xs text-muted-foreground flex items-center gap-1"><Phone className="w-3 h-3" /> Teléfono</Label><Input placeholder="+57 300 1234567" value={formData.phone} onChange={(e) => setFormData(prev => ({ ...prev, phone: e.target.value }))} className="bg-muted/30 border-border" /></div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Cargo</Label><Input placeholder="CEO, CFO, Director..." value={formData.position} onChange={(e) => setFormData(prev => ({ ...prev, position: e.target.value }))} className="bg-muted/30 border-border" /></div>
                <div className="space-y-2"><Label className="text-xs text-muted-foreground flex items-center gap-1"><Building2 className="w-3 h-3" /> Organización</Label><Input placeholder="Empresa S.A." value={formData.organization} onChange={(e) => setFormData(prev => ({ ...prev, organization: e.target.value }))} className="bg-muted/30 border-border" /></div>
              </div>
              <div className="space-y-2"><Label className="text-xs text-muted-foreground flex items-center gap-1"><FileText className="w-3 h-3" /> Notas</Label><Textarea placeholder="Observaciones adicionales..." value={formData.notes} onChange={(e) => setFormData(prev => ({ ...prev, notes: e.target.value }))} className="bg-muted/30 border-border min-h-[80px]" /></div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowCreateDialog(false)} className="border-border">Cancelar</Button>
              <Button onClick={handleCreate} disabled={!formData.identificationNum || !formData.fullName} className="bg-amber-600 hover:bg-amber-700 text-white"><Save className="w-4 h-4 mr-2" />Crear Ejecutivo</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Edit Dialog */}
        <Dialog open={showEditDialog} onOpenChange={setShowEditDialog}>
          <DialogContent className="max-w-lg bg-card border-border">
            <DialogHeader><DialogTitle className="text-foreground">Editar Ejecutivo</DialogTitle><DialogDescription className="text-muted-foreground">Modificar datos del ejecutivo</DialogDescription></DialogHeader>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Número de Identificación</Label><Input value={formData.identificationNum} onChange={(e) => setFormData(prev => ({ ...prev, identificationNum: e.target.value }))} className="bg-muted/30 border-border" /></div>
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Nivel de Riesgo</Label>
                  <select value={formData.riskLevel} onChange={(e) => setFormData(prev => ({ ...prev, riskLevel: e.target.value }))} className="w-full h-9 rounded-md bg-muted/30 border border-border text-sm text-foreground px-3">
                    <option value="bajo">Bajo</option><option value="medio">Medio</option><option value="alto">Alto</option><option value="critico">Crítico</option>
                  </select>
                </div>
              </div>
              <div className="space-y-2"><Label className="text-xs text-muted-foreground">Nombre Completo</Label><Input value={formData.fullName} onChange={(e) => setFormData(prev => ({ ...prev, fullName: e.target.value }))} className="bg-muted/30 border-border" /></div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Correo Electrónico</Label><Input type="email" value={formData.email} onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))} className="bg-muted/30 border-border" /></div>
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Teléfono</Label><Input value={formData.phone} onChange={(e) => setFormData(prev => ({ ...prev, phone: e.target.value }))} className="bg-muted/30 border-border" /></div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Cargo</Label><Input value={formData.position} onChange={(e) => setFormData(prev => ({ ...prev, position: e.target.value }))} className="bg-muted/30 border-border" /></div>
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Organización</Label><Input value={formData.organization} onChange={(e) => setFormData(prev => ({ ...prev, organization: e.target.value }))} className="bg-muted/30 border-border" /></div>
              </div>
              <div className="space-y-2"><Label className="text-xs text-muted-foreground">Notas</Label><Textarea value={formData.notes} onChange={(e) => setFormData(prev => ({ ...prev, notes: e.target.value }))} className="bg-muted/30 border-border min-h-[80px]" /></div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowEditDialog(false)} className="border-border">Cancelar</Button>
              <Button onClick={handleUpdate} className="bg-amber-600 hover:bg-amber-700 text-white"><Save className="w-4 h-4 mr-2" />Guardar Cambios</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Delete Dialog */}
        <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
          <DialogContent className="max-w-md bg-card border-border">
            <DialogHeader>
              <DialogTitle className="text-foreground flex items-center gap-2"><AlertTriangle className="w-5 h-5 text-red-500" /> Confirmar Eliminación</DialogTitle>
              <DialogDescription className="text-muted-foreground">¿Está seguro de eliminar al ejecutivo <strong>{selectedExecutive?.fullName}</strong>?</DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowDeleteDialog(false)} className="border-border">Cancelar</Button>
              <Button onClick={handleDelete} className="bg-red-600 hover:bg-red-700 text-white"><Trash2 className="w-4 h-4 mr-2" />Eliminar</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </main>
    </div>
  );
}
