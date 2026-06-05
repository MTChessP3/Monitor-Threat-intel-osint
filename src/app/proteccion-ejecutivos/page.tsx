'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Search, Plus, Trash2, Edit3, UserCheck, AlertTriangle,
  Loader2, ExternalLink, X, Save, Eye,
  Building2, Mail, Phone, FileText, Globe, ChevronUp, ChevronDown,
  Download, FileCheck, FileX, HardDrive, FolderOpen, FileJson,
  FileCode, Calendar, Users, Globe2, CheckCircle2, Filter,
  XCircle, ArrowUpCircle, ArrowDownCircle,
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
  querySource?: string;
  // V6.0 - Analytical metadata
  sourceDomain?: string;
  actors?: string;
  publicationDate?: string;
  matchedIdentifiers?: string[];
  // V6.0 - Classification
  classification?: 'validated' | 'potential' | 'discarded';
  classificationReason?: string;
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
  rawResultCount?: number;
  filteredOutCount?: number;
  downloadableCount: number;
  downloadedCount: number;
  results: MetasearchResult[];
  classificationStats: { validated: number; potential: number; discarded: number };
  validatedResults: MetasearchResult[];
  potentialResults: MetasearchResult[];
  discardedResults: MetasearchResult[];
  aiAnalysis: string;
  evidence: EvidenceDetail[];
  evidenceDetailPath: string;
  executive: { id: string; fullName: string; identificationNum: string; email: string | null } | null;
  timestamp: string;
  extensionsMonitored?: string[];
  elapsedSeconds: number;
}

// ============================================================================
// Risk Badge
// ============================================================================
function RiskBadge({ level }: { level: string }) {
  const config: Record<string, { color: string; bg: string; label: string }> = {
    bajo: { color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/20', label: 'BAJO' },
    medio: { color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/20', label: 'MEDIO' },
    alto: { color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20', label: 'ALTO' },
    critico: { color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20', label: 'CRITICO' },
  };
  const c = config[level] || config.bajo;
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-semibold border ${c.bg} ${c.color}`}>
      {c.label}
    </span>
  );
}

// ============================================================================
// Classification Icon
// ============================================================================
function ClassificationIcon({ classification, size = 4 }: { classification: string; size?: number }) {
  const sizeClass = `w-${size} h-${size}`;
  switch (classification) {
    case 'validated':
      return <CheckCircle2 className={`${sizeClass} text-emerald-400`} />;
    case 'potential':
      return <AlertTriangle className={`${sizeClass} text-amber-400`} />;
    case 'discarded':
      return <XCircle className={`${sizeClass} text-red-400`} />;
    default:
      return <CheckCircle2 className={`${sizeClass} text-emerald-400`} />;
  }
}

// ============================================================================
// Export helpers
// ============================================================================
function downloadAsFile(data: string, filename: string, mimeType: string) {
  const blob = new Blob([data], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function exportResultAsJson(result: MetasearchResult, execName: string) {
  const payload = {
    metadata: {
      exportedAt: new Date().toISOString(),
      executiveName: execName,
      agent: 'ActorTrace OSINT v6.0',
    },
    result: {
      title: result.title,
      url: result.url,
      snippet: result.snippet,
      source: result.source,
      position: result.position,
      fileType: result.fileType || 'html',
      isDownloadable: result.isDownloadable || false,
      querySource: result.querySource || '',
      sourceDomain: result.sourceDomain || '',
      actors: result.actors || '',
      publicationDate: result.publicationDate || '',
      matchedIdentifiers: result.matchedIdentifiers || [],
      classification: result.classification || 'validated',
      classificationReason: result.classificationReason || '',
    },
    rawPayload: {
      originalResponse: { ...result },
      captureTimestamp: new Date().toISOString(),
    },
  };
  const safeName = execName.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 40);
  const classSuffix = result.classification || 'validated';
  downloadAsFile(JSON.stringify(payload, null, 2), `OSINT_${safeName}_${classSuffix}_result_${result.position}.json`, 'application/json');
  toast.success('Resultado exportado como JSON');
}

function exportResultAsTxt(result: MetasearchResult, execName: string) {
  const lines = [
    `================================================================================`,
    `  ACTORTRACE OSINT v6.0 - REPORTE DE RESULTADO INDIVIDUAL`,
    `================================================================================`,
    ``,
    `EJECUTIVO: ${execName}`,
    `EXPORTADO: ${new Date().toISOString()}`,
    ``,
    `--- DATOS DEL RESULTADO ---`,
    ``,
    `Posicion:      ${result.position}`,
    `Titulo:        ${result.title}`,
    `URL:           ${result.url}`,
    `Fuente:        ${result.source}`,
    `Tipo Archivo:  ${result.fileType || 'html'}`,
    `Descargable:   ${result.isDownloadable ? 'Si' : 'No'}`,
    `Clasificacion: ${result.classification?.toUpperCase() || 'VALIDATED'}`,
    `Razon:         ${result.classificationReason || 'N/A'}`,
    ``,
    `--- METADATOS ANALITICOS ---`,
    ``,
    `Fuente (Dom):  ${result.sourceDomain || 'No disponible'}`,
    `Actores:       ${result.actors || 'No identificado'}`,
    `F. Publicacion:${result.publicationDate || 'No disponible'}`,
    `IDs Coincidentes: ${result.matchedIdentifiers?.join(', ') || 'Ninguno'}`,
    ``,
    `--- SNIPPET ---`,
    ``,
    `${result.snippet || 'Sin snippet'}`,
    ``,
    `--- QUERY ORIGEN ---`,
    ``,
    `${result.querySource || 'No disponible'}`,
    ``,
    `================================================================================`,
  ];
  const safeName = execName.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 40);
  const classSuffix = result.classification || 'validated';
  downloadAsFile(lines.join('\n'), `OSINT_${safeName}_${classSuffix}_result_${result.position}.txt`, 'text/plain');
  toast.success('Resultado exportado como TXT');
}

function exportTabAsJson(results: MetasearchResult[], tabName: string, response: MetasearchResponse) {
  const payload = {
    metadata: {
      exportedAt: new Date().toISOString(),
      agent: 'ActorTrace OSINT v6.0',
      tab: tabName,
      searchEngine: response.searchEngine,
      enginesUsed: response.enginesUsed,
      elapsedSeconds: response.elapsedSeconds,
    },
    executive: response.executive,
    classificationStats: response.classificationStats,
    results: results.map(r => ({
      ...r,
      rawPayload: { ...r },
      captureTimestamp: new Date().toISOString(),
    })),
  };
  const safeName = (response.executive?.fullName || 'custom').replace(/[^a-zA-Z0-9]/g, '_').substring(0, 40);
  downloadAsFile(JSON.stringify(payload, null, 2), `OSINT_${safeName}_${tabName}_${new Date().toISOString().slice(0, 10)}.json`, 'application/json');
  toast.success(`Exportados ${results.length} resultados ${tabName} como JSON`);
}

function exportTabAsTxt(results: MetasearchResult[], tabName: string, response: MetasearchResponse) {
  const lines = [
    `================================================================================`,
    `  ACTORTRACE OSINT v6.0 - REPORTE DE RESULTADOS ${tabName.toUpperCase()}`,
    `================================================================================`,
    ``,
    `Fecha:           ${new Date().toISOString()}`,
    `Motor:           ${response.searchEngine}`,
    `Tiempo:          ${response.elapsedSeconds}s`,
    `Clasificacion:   ${tabName}`,
    ``,
    `--- EJECUTIVO ---`,
    `Nombre:          ${response.executive?.fullName || 'N/A'}`,
    `ID:              ${response.executive?.identificationNum || 'N/A'}`,
    `Email:           ${response.executive?.email || 'N/A'}`,
    ``,
    `--- ESTADISTICAS DE CLASIFICACION ---`,
    `Validados:       ${response.classificationStats.validated}`,
    `Potenciales:     ${response.classificationStats.potential}`,
    `Descartados:     ${response.classificationStats.discarded}`,
    ``,
    `================================================================================`,
    `  RESULTADOS ${tabName.toUpperCase()} (${results.length})`,
    `================================================================================`,
    ``,
  ];

  for (const r of results) {
    lines.push(`--- Resultado #${r.position} ---`);
    lines.push(`Titulo:        ${r.title}`);
    lines.push(`URL:           ${r.url}`);
    lines.push(`Fuente:        ${r.source}`);
    lines.push(`Clasificacion: ${r.classification?.toUpperCase() || 'N/A'}`);
    lines.push(`Razon:         ${r.classificationReason || 'N/A'}`);
    lines.push(`Dominio:       ${r.sourceDomain || 'N/A'}`);
    lines.push(`Actores:       ${r.actors || 'No identificado'}`);
    lines.push(`F. Publicacion:${r.publicationDate || 'No disponible'}`);
    lines.push(`IDs Match:     ${r.matchedIdentifiers?.join(', ') || 'Ninguno'}`);
    lines.push(`Tipo Archivo:  ${r.fileType || 'html'}`);
    lines.push(`Descargable:   ${r.isDownloadable ? 'Si' : 'No'}`);
    lines.push(`Snippet:       ${r.snippet || 'Sin snippet'}`);
    lines.push(`Query:         ${r.querySource || 'N/A'}`);
    lines.push(``);
  }

  const safeName = (response.executive?.fullName || 'custom').replace(/[^a-zA-Z0-9]/g, '_').substring(0, 40);
  downloadAsFile(lines.join('\n'), `OSINT_${safeName}_${tabName}_${new Date().toISOString().slice(0, 10)}.txt`, 'text/plain');
  toast.success(`Exportados ${results.length} resultados ${tabName} como TXT`);
}

function exportAllAsJson(
  response: MetasearchResponse,
  localValidated: MetasearchResult[],
  localPotential: MetasearchResult[],
  localDiscarded: MetasearchResult[],
) {
  const allResults = [...localValidated, ...localPotential, ...localDiscarded];
  const payload = {
    metadata: {
      exportedAt: new Date().toISOString(),
      agent: 'ActorTrace OSINT v6.0',
      searchEngine: response.searchEngine,
      enginesUsed: response.enginesUsed,
      elapsedSeconds: response.elapsedSeconds,
    },
    executive: response.executive,
    statistics: {
      totalResults: response.resultCount,
      rawResults: response.rawResultCount || response.resultCount,
      filteredOut: response.filteredOutCount || 0,
      downloadable: response.downloadableCount,
      engineStats: response.engineStats,
      classificationStats: {
        validated: localValidated.length,
        potential: localPotential.length,
        discarded: localDiscarded.length,
      },
    },
    queryGroups: response.queryGroups,
    aiAnalysis: response.aiAnalysis,
    validatedResults: localValidated.map(r => ({ ...r, rawPayload: { ...r }, captureTimestamp: new Date().toISOString() })),
    potentialResults: localPotential.map(r => ({ ...r, rawPayload: { ...r }, captureTimestamp: new Date().toISOString() })),
    discardedResults: localDiscarded.map(r => ({ ...r, rawPayload: { ...r }, captureTimestamp: new Date().toISOString() })),
    results: allResults.map(r => ({ ...r, rawPayload: { ...r }, captureTimestamp: new Date().toISOString() })),
    evidence: response.evidence,
  };
  const safeName = (response.executive?.fullName || 'custom').replace(/[^a-zA-Z0-9]/g, '_').substring(0, 40);
  downloadAsFile(JSON.stringify(payload, null, 2), `OSINT_${safeName}_complete_${new Date().toISOString().slice(0, 10)}.json`, 'application/json');
  toast.success(`Exportados ${allResults.length} resultados (todas las clasificaciones) como JSON`);
}

function exportAllAsTxt(
  response: MetasearchResponse,
  localValidated: MetasearchResult[],
  localPotential: MetasearchResult[],
  localDiscarded: MetasearchResult[],
) {
  const allResults = [...localValidated, ...localPotential, ...localDiscarded];
  const lines = [
    `================================================================================`,
    `  ACTORTRACE OSINT v6.0 - REPORTE COMPLETO DE METABUSQUEDA`,
    `================================================================================`,
    ``,
    `Fecha:           ${new Date().toISOString()}`,
    `Motor:           ${response.searchEngine}`,
    `Motores Usados:  ${response.enginesUsed.join(', ')}`,
    `Tiempo:          ${response.elapsedSeconds}s`,
    ``,
    `--- EJECUTIVO ---`,
    `Nombre:          ${response.executive?.fullName || 'N/A'}`,
    `ID:              ${response.executive?.identificationNum || 'N/A'}`,
    `Email:           ${response.executive?.email || 'N/A'}`,
    ``,
    `--- ESTADISTICAS ---`,
    `Resultados Totales:   ${response.resultCount}`,
    `Resultados Crudos:    ${response.rawResultCount || response.resultCount}`,
    `Descargables:         ${response.downloadableCount}`,
    `Validados:            ${localValidated.length}`,
    `Potenciales:          ${localPotential.length}`,
    `Descartados:          ${localDiscarded.length}`,
    `Google:               ${response.engineStats.google}`,
    `Bing:                 ${response.engineStats.bing}`,
    `DuckDuckGo:           ${response.engineStats.duckduckgo}`,
    `Web Search:           ${response.engineStats.webSearch}`,
    ``,
    `--- ANALISIS IA ---`,
    ``,
    `${response.aiAnalysis || 'No disponible'}`,
    ``,
    `================================================================================`,
    `  RESULTADOS DETALLADOS (${allResults.length})`,
    `================================================================================`,
    ``,
  ];

  const sections: Array<{ label: string; results: MetasearchResult[] }> = [
    { label: 'VALIDADOS', results: localValidated },
    { label: 'POTENCIALES', results: localPotential },
    { label: 'DESCARTADOS', results: localDiscarded },
  ];

  for (const section of sections) {
    lines.push(``);
    lines.push(`--- ${section.label} (${section.results.length}) ---`);
    lines.push(``);
    for (const r of section.results) {
      lines.push(`  Resultado #${r.position}`);
      lines.push(`  Titulo:        ${r.title}`);
      lines.push(`  URL:           ${r.url}`);
      lines.push(`  Fuente:        ${r.source}`);
      lines.push(`  Dominio:       ${r.sourceDomain || 'N/A'}`);
      lines.push(`  Clasificacion: ${r.classification?.toUpperCase() || 'N/A'}`);
      lines.push(`  Razon:         ${r.classificationReason || 'N/A'}`);
      lines.push(`  Actores:       ${r.actors || 'No identificado'}`);
      lines.push(`  F. Publicacion:${r.publicationDate || 'No disponible'}`);
      lines.push(`  IDs Match:     ${r.matchedIdentifiers?.join(', ') || 'Ninguno'}`);
      lines.push(`  Tipo Archivo:  ${r.fileType || 'html'}`);
      lines.push(`  Descargable:   ${r.isDownloadable ? 'Si' : 'No'}`);
      lines.push(`  Snippet:       ${r.snippet || 'Sin snippet'}`);
      lines.push(`  Query:         ${r.querySource || 'N/A'}`);
      lines.push(``);
    }
  }

  const safeName = (response.executive?.fullName || 'custom').replace(/[^a-zA-Z0-9]/g, '_').substring(0, 40);
  downloadAsFile(lines.join('\n'), `OSINT_${safeName}_complete_${new Date().toISOString().slice(0, 10)}.txt`, 'text/plain');
  toast.success(`Exportados ${allResults.length} resultados (todas las clasificaciones) como TXT`);
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
  const [expandedResult, setExpandedResult] = useState<string | null>(null);
  const [resultFilter, setResultFilter] = useState<'all' | 'documents' | 'web'>('all');

  // V6.0 Classification tab state
  const [activeResultTab, setActiveResultTab] = useState<'validated' | 'potential' | 'discarded'>('validated');
  const [localValidated, setLocalValidated] = useState<MetasearchResult[]>([]);
  const [localPotential, setLocalPotential] = useState<MetasearchResult[]>([]);
  const [localDiscarded, setLocalDiscarded] = useState<MetasearchResult[]>([]);

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
    } catch { toast.error('Error de conexion al crear ejecutivo'); }
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
    } catch { toast.error('Error de conexion al actualizar ejecutivo'); }
  };

  const handleDelete = async () => {
    if (!selectedExecutive) return;
    try {
      const res = await fetch(`/api/executives?id=${selectedExecutive.id}`, { method: 'DELETE' });
      if (!res.ok) { toast.error('Error al eliminar ejecutivo'); return; }
      toast.success('Ejecutivo eliminado exitosamente');
      setShowDeleteDialog(false); setSelectedExecutive(null); fetchExecutives();
    } catch { toast.error('Error de conexion al eliminar ejecutivo'); }
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

  // V6.0 Promote/Demote handlers
  const promoteToValidated = (result: MetasearchResult) => {
    const updated = { ...result, classification: 'validated' as const, classificationReason: 'Promovido manualmente a validado' };
    setLocalPotential(prev => prev.filter(r => r.url !== result.url));
    setLocalDiscarded(prev => prev.filter(r => r.url !== result.url));
    setLocalValidated(prev => [...prev, updated]);
    toast.success('Resultado promovido a Validado');
  };

  const demoteToPotential = (result: MetasearchResult) => {
    const updated = { ...result, classification: 'potential' as const, classificationReason: 'Reclasificado como potencial' };
    setLocalValidated(prev => prev.filter(r => r.url !== result.url));
    setLocalDiscarded(prev => prev.filter(r => r.url !== result.url));
    setLocalPotential(prev => [...prev, updated]);
    toast.info('Resultado reclasificado como Potencial');
  };

  const demoteToDiscarded = (result: MetasearchResult) => {
    const updated = { ...result, classification: 'discarded' as const, classificationReason: 'Descartado manualmente' };
    setLocalValidated(prev => prev.filter(r => r.url !== result.url));
    setLocalPotential(prev => prev.filter(r => r.url !== result.url));
    setLocalDiscarded(prev => [...prev, updated]);
    toast.info('Resultado descartado');
  };

  // Execute metabusqueda with OSINT query matrix v6.0
  const handleMetasearch = async () => {
    if (!selectedExecutive) return;
    setMetasearchLoading(true);
    setShowResults(true);
    setMetasearchResults(null);
    setExpandedResult(null);
    setActiveResultTab('validated');
    setLocalValidated([]);
    setLocalPotential([]);
    setLocalDiscarded([]);
    setSearchProgress('Iniciando Meta-Busqueda OSINT v6.0 (Clasificacion Inteligente)...');

    try {
      const res = await fetch('/api/metasearch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ executiveId: selectedExecutive.id, downloadFiles: true }),
      });

      const data = await res.json();
      if (!res.ok) {
        toast.error(data.error || 'Error en metabusqueda');
        setMetasearchLoading(false);
        return;
      }

      setMetasearchResults(data);
      setSearchProgress('');

      // Initialize local classification state from API response
      const validated = data.validatedResults || [];
      const potential = data.potentialResults || [];
      const discarded = data.discardedResults || [];
      setLocalValidated(validated);
      setLocalPotential(potential);
      setLocalDiscarded(discarded);

      const vCount = validated.length;
      const pCount = potential.length;
      const dCount = discarded.length;
      toast.success(`Busqueda completada: ${vCount} validados, ${pCount} potenciales, ${dCount} descartados`);
    } catch {
      toast.error('Error de conexion en metabusqueda');
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

  // Get current tab results with doc/web filter
  const currentTabResults = (() => {
    let results: MetasearchResult[] = [];
    switch (activeResultTab) {
      case 'validated': results = localValidated; break;
      case 'potential': results = localPotential; break;
      case 'discarded': results = localDiscarded; break;
    }
    return results.filter(r => {
      if (resultFilter === 'documents') return r.isDownloadable;
      if (resultFilter === 'web') return !r.isDownloadable;
      return true;
    });
  })();

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
                <h1 className="text-xl font-bold text-foreground tracking-tight">Proteccion de Ejecutivos</h1>
                <p className="text-xs text-muted-foreground">Modulo OSINT v6.0 - Clasificacion Inteligente</p>
              </div>
            </div>
            <a href="/" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
              &larr; Dashboard
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
              title={selectedExecutive ? `Meta-Busqueda OSINT v6.0: ${selectedExecutive.fullName}` : 'Seleccione un ejecutivo primero'}
            >
              {metasearchLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              Meta-Busqueda OSINT
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
              {selectedExecutive.position && ` - ${selectedExecutive.position}`}
              {selectedExecutive.organization && ` - ${selectedExecutive.organization}`}
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
              Seleccione un ejecutivo para habilitar la Meta-Busqueda OSINT v6.0 (Clasificacion Inteligente + Dorking 40+ extensiones)
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
                      <TableHead className="text-xs text-muted-foreground">Identificacion</TableHead>
                      <TableHead className="text-xs text-muted-foreground">Nombre Completo</TableHead>
                      <TableHead className="text-xs text-muted-foreground">Correo Electronico</TableHead>
                      <TableHead className="text-xs text-muted-foreground">Cargo / Organizacion</TableHead>
                      <TableHead className="text-xs text-muted-foreground">Riesgo</TableHead>
                      <TableHead className="text-xs text-muted-foreground">Ultima Busqueda</TableHead>
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
                        <TableCell className="py-3"><span className="text-xs text-muted-foreground">{exec.email || '-'}</span></TableCell>
                        <TableCell className="py-3">
                          <div className="flex flex-col">
                            <span className="text-xs text-foreground">{exec.position || '-'}</span>
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

        {/* Metasearch Results - Enterprise Dashboard v6.0 */}
        <AnimatePresence>
          {showResults && (
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }}>
              <Card className="border-border bg-card/60">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-base text-foreground flex items-center gap-2">
                        <Globe className="w-4 h-4 text-amber-500" />
                        Resultados de Meta-Busqueda OSINT v6.0
                      </CardTitle>
                      {metasearchResults && (
                        <CardDescription className="text-xs text-muted-foreground mt-1">
                          {metasearchResults.searchEngine} - {localValidated.length} validados / {localPotential.length} potenciales / {localDiscarded.length} descartados
                          {metasearchResults.elapsedSeconds ? ` - ${metasearchResults.elapsedSeconds}s` : ''}
                        </CardDescription>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      {metasearchResults && !metasearchLoading && (
                        <>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => exportAllAsJson(metasearchResults, localValidated, localPotential, localDiscarded)}
                            className="text-[10px] h-7 gap-1 border-purple-500/30 text-purple-400 hover:bg-purple-500/10"
                          >
                            <FileJson className="w-3 h-3" /> Exportar TODO JSON
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => exportAllAsTxt(metasearchResults, localValidated, localPotential, localDiscarded)}
                            className="text-[10px] h-7 gap-1 border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10"
                          >
                            <FileCode className="w-3 h-3" /> Exportar TODO TXT
                          </Button>
                        </>
                      )}
                      <Button variant="ghost" size="sm" onClick={() => setShowResults(false)} className="text-muted-foreground hover:text-foreground">
                        <ChevronUp className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  {metasearchLoading ? (
                    <div className="flex flex-col items-center justify-center py-12">
                      <Loader2 className="w-8 h-8 animate-spin text-amber-500 mb-3" />
                      <p className="text-sm text-muted-foreground">Ejecutando Meta-Busqueda OSINT v6.0...</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Consultando: &quot;{selectedExecutive?.fullName}&quot; en Google + Bing + DuckDuckGo + Web Search
                      </p>
                      <p className="text-xs text-amber-400 mt-2">Clasificacion Inteligente de 3 niveles activada</p>
                      {searchProgress && (
                        <p className="text-xs text-amber-400 mt-1">{searchProgress}</p>
                      )}
                    </div>
                  ) : metasearchResults ? (
                    <>
                      {/* Engine Stats + Classification Stats Row */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
                        {/* Engine Stats */}
                        {metasearchResults.engineStats && (
                          <div className="p-3 rounded-lg bg-purple-500/5 border border-purple-500/20">
                            <div className="flex items-center gap-2 mb-2">
                              <Globe className="w-3.5 h-3.5 text-purple-400" />
                              <p className="text-[10px] font-medium text-purple-400">Motores de Busqueda</p>
                            </div>
                            <div className="grid grid-cols-4 gap-2 text-center">
                              <div>
                                <p className="text-sm font-bold text-blue-400">{metasearchResults.engineStats.google}</p>
                                <p className="text-[9px] text-muted-foreground">Google</p>
                              </div>
                              <div>
                                <p className="text-sm font-bold text-cyan-400">{metasearchResults.engineStats.bing}</p>
                                <p className="text-[9px] text-muted-foreground">Bing</p>
                              </div>
                              <div>
                                <p className="text-sm font-bold text-orange-400">{metasearchResults.engineStats.duckduckgo}</p>
                                <p className="text-[9px] text-muted-foreground">DDG</p>
                              </div>
                              <div>
                                <p className="text-sm font-bold text-foreground">{metasearchResults.engineStats.webSearch}</p>
                                <p className="text-[9px] text-muted-foreground">Web S.</p>
                              </div>
                            </div>
                          </div>
                        )}

                        {/* V6.0 Classification Stats - 3 columns */}
                        <div className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
                          <div className="flex items-center gap-2 mb-2">
                            <Shield className="w-3.5 h-3.5 text-amber-400" />
                            <p className="text-[10px] font-medium text-amber-400">Clasificacion Inteligente v6.0</p>
                          </div>
                          <div className="grid grid-cols-3 gap-2 text-center">
                            <div>
                              <div className="flex items-center justify-center gap-1">
                                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                                <p className="text-sm font-bold text-emerald-400">{localValidated.length}</p>
                              </div>
                              <p className="text-[9px] text-muted-foreground">Validados</p>
                            </div>
                            <div>
                              <div className="flex items-center justify-center gap-1">
                                <AlertTriangle className="w-3 h-3 text-amber-400" />
                                <p className="text-sm font-bold text-amber-400">{localPotential.length}</p>
                              </div>
                              <p className="text-[9px] text-muted-foreground">Potenciales</p>
                            </div>
                            <div>
                              <div className="flex items-center justify-center gap-1">
                                <XCircle className="w-3 h-3 text-red-400" />
                                <p className="text-sm font-bold text-red-400">{localDiscarded.length}</p>
                              </div>
                              <p className="text-[9px] text-muted-foreground">Descartados</p>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Query Groups Summary */}
                      {metasearchResults.queryGroups && metasearchResults.queryGroups.length > 0 && (
                        <div className="mb-4 p-3 rounded-lg bg-muted/20 border border-border">
                          <p className="text-[10px] font-medium text-foreground mb-2">Matriz de Dorking OSINT Ejecutada:</p>
                          <div className="flex flex-wrap gap-1.5">
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
                                <Badge key={idx} variant="outline" className={`text-[9px] ${color}`}>
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
                            <p className="text-xs font-semibold text-amber-400">Analisis de Inteligencia OSINT - IA</p>
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
                            <HardDrive className="w-3.5 h-3.5 text-blue-400" />
                            <p className="text-[10px] font-medium text-blue-400">Evidencia Digital</p>
                          </div>
                          <div className="grid grid-cols-3 gap-2 text-center">
                            <div>
                              <p className="text-sm font-bold text-foreground">{metasearchResults.downloadableCount}</p>
                              <p className="text-[9px] text-muted-foreground">Documentos</p>
                            </div>
                            <div>
                              <p className="text-sm font-bold text-emerald-400">{metasearchResults.downloadedCount}</p>
                              <p className="text-[9px] text-muted-foreground">Descargados</p>
                            </div>
                            <div>
                              <p className="text-sm font-bold text-red-400">{metasearchResults.downloadableCount - metasearchResults.downloadedCount}</p>
                              <p className="text-[9px] text-muted-foreground">Fallidos</p>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* V6.0 Three-tab Results Panel */}
                      <div className="mb-4">
                        {/* Tab Headers */}
                        <div className="flex items-center gap-1 mb-3 flex-wrap">
                          {[
                            { key: 'validated' as const, label: 'Validados', count: localValidated.length, icon: CheckCircle2, color: 'emerald' },
                            { key: 'potential' as const, label: 'Potenciales', count: localPotential.length, icon: AlertTriangle, color: 'amber' },
                            { key: 'discarded' as const, label: 'Descartados', count: localDiscarded.length, icon: XCircle, color: 'red' },
                          ].map(tab => {
                            const isActive = activeResultTab === tab.key;
                            const colorMap: Record<string, string> = {
                              emerald: isActive ? 'border-emerald-500/40 text-emerald-400 bg-emerald-500/10' : 'border-border text-muted-foreground hover:text-emerald-400',
                              amber: isActive ? 'border-amber-500/40 text-amber-400 bg-amber-500/10' : 'border-border text-muted-foreground hover:text-amber-400',
                              red: isActive ? 'border-red-500/40 text-red-400 bg-red-500/10' : 'border-border text-muted-foreground hover:text-red-400',
                            };
                            return (
                              <button
                                key={tab.key}
                                onClick={() => { setActiveResultTab(tab.key); setResultFilter('all'); }}
                                className={`text-[11px] px-3 py-1.5 rounded-md border transition-colors flex items-center gap-1.5 font-medium ${colorMap[tab.color]}`}
                              >
                                <tab.icon className="w-3.5 h-3.5" />
                                {tab.label}
                                <span className="ml-0.5 px-1.5 py-0 rounded-full text-[9px] bg-muted/50">{tab.count}</span>
                              </button>
                            );
                          })}

                          {/* Tab Export Buttons */}
                          {metasearchResults && !metasearchLoading && (
                            <div className="ml-auto flex items-center gap-1">
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => {
                                  const tabResults = activeResultTab === 'validated' ? localValidated : activeResultTab === 'potential' ? localPotential : localDiscarded;
                                  exportTabAsJson(tabResults, activeResultTab, metasearchResults);
                                }}
                                className="text-[9px] h-6 gap-1 border-purple-500/30 text-purple-400 hover:bg-purple-500/10"
                              >
                                <FileJson className="w-2.5 h-2.5" /> Tab JSON
                              </Button>
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => {
                                  const tabResults = activeResultTab === 'validated' ? localValidated : activeResultTab === 'potential' ? localPotential : localDiscarded;
                                  exportTabAsTxt(tabResults, activeResultTab, metasearchResults);
                                }}
                                className="text-[9px] h-6 gap-1 border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10"
                              >
                                <FileCode className="w-2.5 h-2.5" /> Tab TXT
                              </Button>
                            </div>
                          )}
                        </div>

                        {/* Document/Web Filter */}
                        {currentTabResults.length > 0 && (
                          <div className="flex items-center gap-2 mb-3">
                            <span className="text-[10px] text-muted-foreground">Filtrar:</span>
                            {[
                              { key: 'all' as const, label: 'Todos', count: (activeResultTab === 'validated' ? localValidated : activeResultTab === 'potential' ? localPotential : localDiscarded).length },
                              { key: 'documents' as const, label: 'Documentos', count: (activeResultTab === 'validated' ? localValidated : activeResultTab === 'potential' ? localPotential : localDiscarded).filter(r => r.isDownloadable).length },
                              { key: 'web' as const, label: 'Web', count: (activeResultTab === 'validated' ? localValidated : activeResultTab === 'potential' ? localPotential : localDiscarded).filter(r => !r.isDownloadable).length },
                            ].map(tab => (
                              <button
                                key={tab.key}
                                onClick={() => setResultFilter(tab.key)}
                                className={`text-[10px] px-2 py-0.5 rounded border transition-colors ${
                                  resultFilter === tab.key
                                    ? 'border-amber-500/40 text-amber-400 bg-amber-500/10'
                                    : 'border-border text-muted-foreground hover:text-foreground'
                                }`}
                              >
                                {tab.label} ({tab.count})
                              </button>
                            ))}
                          </div>
                        )}

                        {/* Results List for Current Tab */}
                        {currentTabResults.length === 0 ? (
                          <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                            {activeResultTab === 'validated' && <CheckCircle2 className="w-10 h-10 mb-3 opacity-30" />}
                            {activeResultTab === 'potential' && <AlertTriangle className="w-10 h-10 mb-3 opacity-30" />}
                            {activeResultTab === 'discarded' && <XCircle className="w-10 h-10 mb-3 opacity-30" />}
                            <p className="text-sm">
                              {activeResultTab === 'validated' && 'No hay resultados validados'}
                              {activeResultTab === 'potential' && 'No hay resultados potenciales'}
                              {activeResultTab === 'discarded' && 'No hay resultados descartados'}
                            </p>
                          </div>
                        ) : (
                          <div className="space-y-2 max-h-96 overflow-y-auto pr-1" style={{ scrollbarWidth: 'thin', scrollbarColor: 'rgba(255,255,255,0.1) transparent' }}>
                            {currentTabResults.map((result, index) => {
                              const isExpanded = expandedResult === `${activeResultTab}-${result.position}-${index}`;
                              const classificationBorderMap: Record<string, string> = {
                                validated: 'border-emerald-500/20 bg-emerald-500/5',
                                potential: 'border-amber-500/20 bg-amber-500/5',
                                discarded: 'border-red-500/20 bg-red-500/5',
                              };
                              const borderClass = classificationBorderMap[result.classification || 'validated'] || classificationBorderMap.validated;

                              return (
                                <motion.div
                                  key={`${result.url}-${index}`}
                                  initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                                  transition={{ delay: index * 0.02 }}
                                  className={`rounded-lg border transition-colors overflow-hidden ${borderClass}`}
                                >
                                  {/* Main Row - Always Visible */}
                                  <div
                                    className="p-3 cursor-pointer"
                                    onClick={() => setExpandedResult(isExpanded ? null : `${activeResultTab}-${result.position}-${index}`)}
                                  >
                                    <div className="flex items-start gap-3">
                                      {/* Status Icon + Position */}
                                      <div className="flex-shrink-0 flex flex-col items-center gap-1">
                                        <ClassificationIcon classification={result.classification || 'validated'} size={4} />
                                        <span className="text-[9px] text-muted-foreground font-mono">#{result.position}</span>
                                      </div>
                                      <div className="flex-1 min-w-0">
                                        {/* Title + Abrir Fuente */}
                                        <div className="flex items-center gap-2 mb-1">
                                          <a
                                            href={result.url}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            onClick={(e) => e.stopPropagation()}
                                            className="text-sm font-medium text-amber-500 hover:text-amber-400 hover:underline truncate max-w-[75%]"
                                          >
                                            {result.title}
                                          </a>
                                          <a
                                            href={result.url}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            onClick={(e) => e.stopPropagation()}
                                            className="flex-shrink-0 inline-flex items-center gap-1 text-[10px] text-blue-400 hover:text-blue-300 bg-blue-500/10 px-1.5 py-0.5 rounded border border-blue-500/20"
                                            title="Abrir URL directamente"
                                          >
                                            <ExternalLink className="w-3 h-3" /> Abrir Fuente
                                          </a>
                                        </div>

                                        {/* Snippet */}
                                        {result.snippet && (
                                          <p className="text-xs text-muted-foreground/80 line-clamp-2 mb-1.5">{result.snippet}</p>
                                        )}

                                        {/* Metadata Row */}
                                        <div className="flex flex-wrap items-center gap-1.5">
                                          {/* Source Badge */}
                                          <Badge variant="outline" className="text-[9px] h-4 px-1.5 border-border">
                                            {result.source}
                                          </Badge>

                                          {/* File Type Badge */}
                                          {result.fileType && result.fileType !== 'html' && (
                                            <Badge variant="outline" className="text-[9px] h-4 px-1.5 border-amber-500/30 text-amber-400">
                                              .{result.fileType}
                                            </Badge>
                                          )}

                                          {/* Matched Identifiers - only for validated */}
                                          {result.classification === 'validated' && result.matchedIdentifiers && result.matchedIdentifiers.length > 0 && (
                                            <Badge className="text-[9px] h-4 px-1.5 bg-emerald-500/20 text-emerald-400 border-emerald-500/30 border">
                                              <CheckCircle2 className="w-2.5 h-2.5 mr-0.5" /> {result.matchedIdentifiers.join(' + ')}
                                            </Badge>
                                          )}

                                          {/* Classification Reason */}
                                          {result.classificationReason && (
                                            <span className="text-[9px] text-muted-foreground/60 italic truncate max-w-[200px]">
                                              {result.classificationReason}
                                            </span>
                                          )}

                                          {/* Expand toggle */}
                                          <span className="ml-auto text-[9px] text-muted-foreground flex items-center gap-0.5">
                                            {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                                            {isExpanded ? 'Cerrar' : 'Detalle'}
                                          </span>
                                        </div>

                                        {/* Promote/Demote Buttons */}
                                        {(result.classification === 'potential' || result.classification === 'discarded' || result.classification === 'validated') && (
                                          <div className="flex items-center gap-1.5 mt-2" onClick={(e) => e.stopPropagation()}>
                                            {result.classification !== 'validated' && (
                                              <Button
                                                variant="outline"
                                                size="sm"
                                                className="text-[9px] h-5 px-2 gap-0.5 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10"
                                                onClick={() => promoteToValidated(result)}
                                              >
                                                <ArrowUpCircle className="w-3 h-3" /> Promover a Validado
                                              </Button>
                                            )}
                                            {result.classification !== 'discarded' && (
                                              <Button
                                                variant="outline"
                                                size="sm"
                                                className="text-[9px] h-5 px-2 gap-0.5 border-red-500/30 text-red-400 hover:bg-red-500/10"
                                                onClick={() => demoteToDiscarded(result)}
                                              >
                                                <XCircle className="w-3 h-3" /> Descartar
                                              </Button>
                                            )}
                                            {result.classification === 'validated' && (
                                              <Button
                                                variant="outline"
                                                size="sm"
                                                className="text-[9px] h-5 px-2 gap-0.5 border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
                                                onClick={() => demoteToPotential(result)}
                                              >
                                                <ArrowDownCircle className="w-3 h-3" /> Reclasificar Potencial
                                              </Button>
                                            )}
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                  </div>

                                  {/* Expanded Detail Panel */}
                                  <AnimatePresence>
                                    {isExpanded && (
                                      <motion.div
                                        initial={{ height: 0, opacity: 0 }}
                                        animate={{ height: 'auto', opacity: 1 }}
                                        exit={{ height: 0, opacity: 0 }}
                                        transition={{ duration: 0.2 }}
                                        className="border-t border-border overflow-hidden"
                                      >
                                        <div className="p-4 bg-muted/10 space-y-3">
                                          {/* Analytical Metadata Grid */}
                                          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                                            {/* Source Domain */}
                                            <div className="p-2 rounded bg-card/50 border border-border">
                                              <div className="flex items-center gap-1.5 mb-1">
                                                <Globe2 className="w-3 h-3 text-purple-400" />
                                                <p className="text-[10px] font-medium text-purple-400">Fuente</p>
                                              </div>
                                              <p className="text-xs text-foreground font-mono break-all">{result.sourceDomain || 'No disponible'}</p>
                                            </div>

                                            {/* Actors */}
                                            <div className="p-2 rounded bg-card/50 border border-border">
                                              <div className="flex items-center gap-1.5 mb-1">
                                                <Users className="w-3 h-3 text-cyan-400" />
                                                <p className="text-[10px] font-medium text-cyan-400">Actores</p>
                                              </div>
                                              <p className="text-xs text-foreground">{result.actors || 'No identificado'}</p>
                                            </div>

                                            {/* Publication Date */}
                                            <div className="p-2 rounded bg-card/50 border border-border">
                                              <div className="flex items-center gap-1.5 mb-1">
                                                <Calendar className="w-3 h-3 text-amber-400" />
                                                <p className="text-[10px] font-medium text-amber-400">Fecha Publicacion</p>
                                              </div>
                                              <p className="text-xs text-foreground">{result.publicationDate || 'No disponible'}</p>
                                            </div>
                                          </div>

                                          {/* Classification Detail */}
                                          <div className="p-2 rounded bg-card/50 border border-border">
                                            <div className="flex items-center gap-2">
                                              <ClassificationIcon classification={result.classification || 'validated'} size={3.5} />
                                              <span className="text-[10px] font-medium">
                                                Clasificacion: {result.classification?.toUpperCase() || 'VALIDATED'}
                                              </span>
                                              {result.classificationReason && (
                                                <span className="text-[10px] text-muted-foreground">- {result.classificationReason}</span>
                                              )}
                                            </div>
                                          </div>

                                          {/* Full URL */}
                                          <div className="p-2 rounded bg-card/50 border border-border">
                                            <p className="text-[10px] text-muted-foreground mb-0.5">URL Completa:</p>
                                            <a
                                              href={result.url}
                                              target="_blank"
                                              rel="noopener noreferrer"
                                              className="text-xs text-blue-400 hover:text-blue-300 break-all font-mono"
                                            >
                                              {result.url}
                                            </a>
                                          </div>

                                          {/* Full Snippet */}
                                          {result.snippet && (
                                            <div className="p-2 rounded bg-card/50 border border-border">
                                              <p className="text-[10px] text-muted-foreground mb-0.5">Snippet Completo:</p>
                                              <p className="text-xs text-foreground/90">{result.snippet}</p>
                                            </div>
                                          )}

                                          {/* Query Source + Matched Identifiers */}
                                          <div className="flex flex-wrap gap-3">
                                            {result.querySource && (
                                              <div>
                                                <p className="text-[10px] text-muted-foreground">Query Origen:</p>
                                                <p className="text-[10px] text-foreground font-mono">{result.querySource}</p>
                                              </div>
                                            )}
                                            {result.matchedIdentifiers && result.matchedIdentifiers.length > 0 && (
                                              <div>
                                                <p className="text-[10px] text-muted-foreground">Identificadores Coincidentes:</p>
                                                <div className="flex gap-1 mt-0.5">
                                                  {result.matchedIdentifiers.map((id, i) => (
                                                    <Badge key={i} className="text-[9px] h-4 px-1.5 bg-emerald-500/20 text-emerald-400 border-emerald-500/30 border">
                                                      {id}
                                                    </Badge>
                                                  ))}
                                                </div>
                                              </div>
                                            )}
                                          </div>

                                          {/* Export Buttons per Result */}
                                          <div className="flex items-center gap-2 pt-2 border-t border-border">
                                            <span className="text-[10px] text-muted-foreground">Exportar resultado:</span>
                                            <Button
                                              variant="outline"
                                              size="sm"
                                              className="text-[10px] h-6 gap-1 border-purple-500/30 text-purple-400 hover:bg-purple-500/10"
                                              onClick={() => exportResultAsJson(result, metasearchResults.executive?.fullName || 'unknown')}
                                            >
                                              <FileJson className="w-3 h-3" /> .JSON
                                            </Button>
                                            <Button
                                              variant="outline"
                                              size="sm"
                                              className="text-[10px] h-6 gap-1 border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10"
                                              onClick={() => exportResultAsTxt(result, metasearchResults.executive?.fullName || 'unknown')}
                                            >
                                              <FileCode className="w-3 h-3" /> .TXT
                                            </Button>
                                          </div>
                                        </div>
                                      </motion.div>
                                    )}
                                  </AnimatePresence>
                                </motion.div>
                              );
                            })}
                          </div>
                        )}
                      </div>
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
              <DialogDescription className="text-muted-foreground">Informacion completa del ejecutivo</DialogDescription>
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
                  <div className="space-y-1"><p className="text-xs text-muted-foreground">Identificacion</p><p className="text-sm text-foreground font-mono">{selectedExecutive.identificationNum}</p></div>
                  <div className="space-y-1"><p className="text-xs text-muted-foreground flex items-center gap-1"><Mail className="w-3 h-3" /> Correo</p><p className="text-sm text-foreground">{selectedExecutive.email || '-'}</p></div>
                  <div className="space-y-1"><p className="text-xs text-muted-foreground flex items-center gap-1"><Phone className="w-3 h-3" /> Telefono</p><p className="text-sm text-foreground">{selectedExecutive.phone || '-'}</p></div>
                  <div className="space-y-1"><p className="text-xs text-muted-foreground flex items-center gap-1"><Building2 className="w-3 h-3" /> Organizacion</p><p className="text-sm text-foreground">{selectedExecutive.organization || '-'}</p></div>
                  <div className="space-y-1 col-span-2"><p className="text-xs text-muted-foreground">Cargo</p><p className="text-sm text-foreground">{selectedExecutive.position || '-'}</p></div>
                  {selectedExecutive.notes && (
                    <div className="space-y-1 col-span-2"><p className="text-xs text-muted-foreground flex items-center gap-1"><FileText className="w-3 h-3" /> Notas</p><p className="text-sm text-foreground whitespace-pre-wrap">{selectedExecutive.notes}</p></div>
                  )}
                </div>
                {selectedExecutive.lastMetasearch && (
                  <div className="p-3 rounded-lg bg-muted/30 border border-border">
                    <p className="text-xs text-muted-foreground">Ultima Meta-Busqueda</p>
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
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Numero de Identificacion *</Label><Input placeholder="CC-12345678" value={formData.identificationNum} onChange={(e) => setFormData(prev => ({ ...prev, identificationNum: e.target.value }))} className="bg-muted/30 border-border" /></div>
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Nivel de Riesgo</Label>
                  <select value={formData.riskLevel} onChange={(e) => setFormData(prev => ({ ...prev, riskLevel: e.target.value }))} className="w-full h-9 rounded-md bg-muted/30 border border-border text-sm text-foreground px-3">
                    <option value="bajo">Bajo</option><option value="medio">Medio</option><option value="alto">Alto</option><option value="critico">Critico</option>
                  </select>
                </div>
              </div>
              <div className="space-y-2"><Label className="text-xs text-muted-foreground">Nombre Completo *</Label><Input placeholder="Juan Carlos Perez Gomez" value={formData.fullName} onChange={(e) => setFormData(prev => ({ ...prev, fullName: e.target.value }))} className="bg-muted/30 border-border" /></div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2"><Label className="text-xs text-muted-foreground flex items-center gap-1"><Mail className="w-3 h-3" /> Correo Electronico</Label><Input placeholder="correo@ejemplo.com" type="email" value={formData.email} onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))} className="bg-muted/30 border-border" /></div>
                <div className="space-y-2"><Label className="text-xs text-muted-foreground flex items-center gap-1"><Phone className="w-3 h-3" /> Telefono</Label><Input placeholder="+57 300 1234567" value={formData.phone} onChange={(e) => setFormData(prev => ({ ...prev, phone: e.target.value }))} className="bg-muted/30 border-border" /></div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Cargo</Label><Input placeholder="CEO, CFO, Director..." value={formData.position} onChange={(e) => setFormData(prev => ({ ...prev, position: e.target.value }))} className="bg-muted/30 border-border" /></div>
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Organizacion</Label><Input placeholder="Empresa S.A.S" value={formData.organization} onChange={(e) => setFormData(prev => ({ ...prev, organization: e.target.value }))} className="bg-muted/30 border-border" /></div>
              </div>
              <div className="space-y-2"><Label className="text-xs text-muted-foreground">Notas</Label><Textarea placeholder="Observaciones adicionales..." value={formData.notes} onChange={(e) => setFormData(prev => ({ ...prev, notes: e.target.value }))} className="bg-muted/30 border-border min-h-[60px]" /></div>
            </div>
            <DialogFooter>
              <Button variant="ghost" onClick={() => setShowCreateDialog(false)} className="text-muted-foreground">Cancelar</Button>
              <Button onClick={handleCreate} disabled={!formData.fullName || !formData.identificationNum} className="bg-amber-600 hover:bg-amber-700 text-white gap-2">
                <Save className="w-4 h-4" /> Crear Ejecutivo
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Edit Dialog */}
        <Dialog open={showEditDialog} onOpenChange={setShowEditDialog}>
          <DialogContent className="max-w-lg bg-card border-border">
            <DialogHeader><DialogTitle className="text-foreground">Editar Ejecutivo</DialogTitle><DialogDescription className="text-muted-foreground">Modificar informacion del ejecutivo</DialogDescription></DialogHeader>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Numero de Identificacion *</Label><Input value={formData.identificationNum} onChange={(e) => setFormData(prev => ({ ...prev, identificationNum: e.target.value }))} className="bg-muted/30 border-border" /></div>
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Nivel de Riesgo</Label>
                  <select value={formData.riskLevel} onChange={(e) => setFormData(prev => ({ ...prev, riskLevel: e.target.value }))} className="w-full h-9 rounded-md bg-muted/30 border border-border text-sm text-foreground px-3">
                    <option value="bajo">Bajo</option><option value="medio">Medio</option><option value="alto">Alto</option><option value="critico">Critico</option>
                  </select>
                </div>
              </div>
              <div className="space-y-2"><Label className="text-xs text-muted-foreground">Nombre Completo *</Label><Input value={formData.fullName} onChange={(e) => setFormData(prev => ({ ...prev, fullName: e.target.value }))} className="bg-muted/30 border-border" /></div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2"><Label className="text-xs text-muted-foreground flex items-center gap-1"><Mail className="w-3 h-3" /> Correo Electronico</Label><Input type="email" value={formData.email} onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))} className="bg-muted/30 border-border" /></div>
                <div className="space-y-2"><Label className="text-xs text-muted-foreground flex items-center gap-1"><Phone className="w-3 h-3" /> Telefono</Label><Input value={formData.phone} onChange={(e) => setFormData(prev => ({ ...prev, phone: e.target.value }))} className="bg-muted/30 border-border" /></div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Cargo</Label><Input value={formData.position} onChange={(e) => setFormData(prev => ({ ...prev, position: e.target.value }))} className="bg-muted/30 border-border" /></div>
                <div className="space-y-2"><Label className="text-xs text-muted-foreground">Organizacion</Label><Input value={formData.organization} onChange={(e) => setFormData(prev => ({ ...prev, organization: e.target.value }))} className="bg-muted/30 border-border" /></div>
              </div>
              <div className="space-y-2"><Label className="text-xs text-muted-foreground">Notas</Label><Textarea value={formData.notes} onChange={(e) => setFormData(prev => ({ ...prev, notes: e.target.value }))} className="bg-muted/30 border-border min-h-[60px]" /></div>
            </div>
            <DialogFooter>
              <Button variant="ghost" onClick={() => setShowEditDialog(false)} className="text-muted-foreground">Cancelar</Button>
              <Button onClick={handleUpdate} disabled={!formData.fullName || !formData.identificationNum} className="bg-amber-600 hover:bg-amber-700 text-white gap-2">
                <Save className="w-4 h-4" /> Guardar Cambios
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Delete Dialog */}
        <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
          <DialogContent className="max-w-md bg-card border-border">
            <DialogHeader>
              <DialogTitle className="text-foreground flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-500" /> Confirmar Eliminacion
              </DialogTitle>
              <DialogDescription className="text-muted-foreground">
                Esta accion no se puede deshacer. Se eliminara el ejecutivo <strong>{selectedExecutive?.fullName}</strong> y todos sus registros asociados.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="ghost" onClick={() => setShowDeleteDialog(false)} className="text-muted-foreground">Cancelar</Button>
              <Button onClick={handleDelete} className="bg-red-600 hover:bg-red-700 text-white gap-2">
                <Trash2 className="w-4 h-4" /> Eliminar
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </main>
    </div>
  );
}
