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
  FileSpreadsheet, Presentation, FileArchive, ChevronRight,
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
import GoogleDorkingPanel from '@/components/osint/GoogleDorkingPanel';
import { ThemeSelector } from '@/components/ThemeSelector';
import NextLink from 'next/link';

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
  familyMembers?: FamilyMember[];
}

interface FamilyMember {
  id: string;
  executiveId: string;
  fullName: string;
  relationship: string;
  identificationNum: string | null;
  email: string | null;
  phone: string | null;
  riskLevel: string;
  notes: string | null;
  active: boolean;
  createdAt: string;
  updatedAt: string;
}

const MAX_EXECUTIVES = 300;
const MAX_FAMILY_MEMBERS_PER_EXECUTIVE = 3;

const RELATIONSHIP_OPTIONS = [
  { value: 'esposo', label: 'Esposo/a' },
  { value: 'hijo', label: 'Hijo/a' },
  { value: 'padre', label: 'Padre/Madre' },
  { value: 'hermano', label: 'Hermano/a' },
  { value: 'otro', label: 'Otro' },
];

interface MetasearchResult {
  title: string;
  url: string;
  snippet: string;
  source: string;
  position: number;
  fileType?: string;
  isDownloadable?: boolean;
  querySource?: string;
  queryBlock?: string;
  sourceDomain?: string;
  actors?: string;
  publicationDate?: string;
  matchedIdentifiers?: string[];
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

interface EngineDetail {
  name: string;
  queriesRun: number;
  resultsFound: number;
  status: 'active' | 'failed' | 'skipped';
  details: string;
}

interface ExtensionGroup {
  label: string;
  exts: string[];
  icon: string;
}

interface QueryGroup {
  label: string;
  queryCount: number;
  blockType: string;
  resultsFound: number;
  sampleQueries: string[];
}

interface MetasearchResponse {
  success: boolean;
  searchEngine: string;
  enginesUsed: string[];
  engineDetails: EngineDetail[];
  queryGroups: QueryGroup[];
  resultCount: number;
  rawResultCount?: number;
  filteredOutCount?: number;
  classificationStats: { validated: number; potential: number; discarded: number };
  downloadableCount: number;
  downloadedCount: number;
  results: MetasearchResult[];
  validatedResults: MetasearchResult[];
  potentialResults: MetasearchResult[];
  discardedResults: MetasearchResult[];
  aiAnalysis: string;
  evidence: EvidenceDetail[];
  evidenceDetailPath: string;
  executive: { id: string; fullName: string; identificationNum: string; email: string | null; phone: string | null; organization: string | null } | null;
  targetType?: 'executive' | 'family';
  targetName?: string;
  timestamp: string;
  extensionsMonitored?: string[];
  extensionGroups?: ExtensionGroup[];
  elapsedSeconds: number;
}

// ============================================================================
// Risk Badge
// ============================================================================
function RiskBadge({ level }: { level: string }) {
  const config: Record<string, { color: string; bg: string; label: string }> = {
    bajo: { color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/20', label: 'BAJO' },
    medio: { color: 'text-yellow-500', bg: 'bg-yellow-600/15 border-yellow-600/20', label: 'MEDIO' },
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
      return <AlertTriangle className={`${sizeClass} text-primary`} />;
    case 'discarded':
      return <XCircle className={`${sizeClass} text-red-400`} />;
    default:
      return <CheckCircle2 className={`${sizeClass} text-emerald-400`} />;
  }
}

// ============================================================================
// Extension Group Icon Helper
// ============================================================================
function ExtGroupIcon({ iconName, className }: { iconName: string; className?: string }) {
  const cn = className || 'w-4 h-4';
  switch (iconName) {
    case 'file-text': return <FileText className={cn} />;
    case 'file-spreadsheet': return <FileSpreadsheet className={cn} />;
    case 'presentation': return <Presentation className={cn} />;
    case 'file-archive': return <FileArchive className={cn} />;
    case 'folder': return <FolderOpen className={cn} />;
    case 'globe': return <Globe className={cn} />;
    default: return <FileText className={cn} />;
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
      agent: 'VIP-Intelligence OSINT v7.0',
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
      queryBlock: result.queryBlock || '',
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
    `  VIP-INTELLIGENCE OSINT v7.0 - REPORTE DE RESULTADO INDIVIDUAL`,
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
    `Bloque Query:  ${result.queryBlock || 'N/A'}`,
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
      agent: 'VIP-Intelligence OSINT v7.0',
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
    `  VIP-INTELLIGENCE OSINT v7.0 - REPORTE DE RESULTADOS ${tabName.toUpperCase()}`,
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
    lines.push(`Bloque Query:  ${r.queryBlock || 'N/A'}`);
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
      agent: 'VIP-Intelligence OSINT v7.0',
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
      engineDetails: response.engineDetails,
      classificationStats: {
        validated: localValidated.length,
        potential: localPotential.length,
        discarded: localDiscarded.length,
      },
    },
    queryGroups: response.queryGroups,
    extensionGroups: response.extensionGroups,
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
    `  VIP-INTELLIGENCE OSINT v7.0 - REPORTE COMPLETO DE METABUSQUEDA`,
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
    ``,
    `--- MOTORES DE BUSQUEDA ---`,
    ...(response.engineDetails || []).map(ed =>
      `  ${ed.name}: ${ed.resultsFound} resultados / ${ed.queriesRun} consultas [${ed.status.toUpperCase()}] - ${ed.details}`
    ),
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
      lines.push(`  Bloque Query:  ${r.queryBlock || 'N/A'}`);
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
  const [authLoading, setAuthLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedExecutive, setSelectedExecutive] = useState<Executive | null>(null);
  const [metasearchLoading, setMetasearchLoading] = useState(false);
  const [metasearchResults, setMetasearchResults] = useState<MetasearchResponse | null>(null);
  const [showResults, setShowResults] = useState(false);
  const [searchProgress, setSearchProgress] = useState('');
  const [expandedResult, setExpandedResult] = useState<string | null>(null); // tracked by URL
  const [resultFilter, setResultFilter] = useState<'all' | 'documents' | 'web'>('all');

  // V7.0 Classification tab state
  const [activeResultTab, setActiveResultTab] = useState<'validated' | 'potential' | 'discarded'>('validated');
  const [localValidated, setLocalValidated] = useState<MetasearchResult[]>([]);
  const [localPotential, setLocalPotential] = useState<MetasearchResult[]>([]);
  const [localDiscarded, setLocalDiscarded] = useState<MetasearchResult[]>([]);

  // V7.0 Expandable panel states
  const [enginesExpanded, setEnginesExpanded] = useState(false);
  const [classificationExpanded, setClassificationExpanded] = useState(false);
  const [extensionsExpanded, setExtensionsExpanded] = useState(false);
  const [expandedQueryGroup, setExpandedQueryGroup] = useState<number | null>(null);

  // Google Dorking panel state
  const [showDorkingPanel, setShowDorkingPanel] = useState(false);

  // Dialog states
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [showDetailDialog, setShowDetailDialog] = useState(false);

  // Family Member Dialog states
  const [showCreateFamilyDialog, setShowCreateFamilyDialog] = useState(false);
  const [showEditFamilyDialog, setShowEditFamilyDialog] = useState(false);
  const [showDeleteFamilyDialog, setShowDeleteFamilyDialog] = useState(false);
  const [selectedFamilyMember, setSelectedFamilyMember] = useState<FamilyMember | null>(null);
  const [selectedExecutiveForFamily, setSelectedExecutiveForFamily] = useState<Executive | null>(null);

  // Form state
  const [formData, setFormData] = useState({
    identificationNum: '', fullName: '', email: '', phone: '',
    position: '', organization: '', riskLevel: 'bajo', notes: '',
  });

  // Family Member Form state
  const [familyFormData, setFamilyFormData] = useState({
    fullName: '', relationship: '', identificationNum: '', email: '',
    phone: '', riskLevel: 'bajo', notes: '',
  });

  // Tree view state
  const [expandedExecutives, setExpandedExecutives] = useState<Set<string>>(new Set());
  const [viewMode, setViewMode] = useState<'tree' | 'table'>('tree');

  // Check auth — resilient with caching and retry
  useEffect(() => {
    const initSession = async () => {
      try {
        const { checkSession: checkSess, clearCachedUser } = await import('@/lib/session-manager');
        const user = await checkSess(2);
        if (!user) {
          clearCachedUser();
          window.location.href = '/auth/login';
        }
      } catch {
        // Fallback: direct API call with 401-only redirect
        try {
          const res = await fetch('/api/auth/session');
          if (res.status === 401) {
            window.location.href = '/auth/login';
          }
          // Non-401 errors: don't redirect, middleware already validated the JWT
        } catch {
          // Network error: don't redirect, might be temporary
        }
      } finally {
        setAuthLoading(false);
      }
    };
    initSession();
  }, []);

  // Fetch executives
  const fetchExecutives = useCallback(async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (searchTerm) params.set('search', searchTerm);
      const res = await fetch(`/api/executives?${params.toString()}`);
      if (!res.ok) throw new Error('Error al cargar ejecutivos');
      const data = await res.json();
      
      // Fetch family members for each executive
      const executivesWithFamily = await Promise.all(
        (data.executives || []).map(async (exec: Executive) => {
          const familyRes = await fetch(`/api/family-members?executiveId=${exec.id}`);
          const familyData = await familyRes.json();
          return { ...exec, familyMembers: familyData.familyMembers || [] };
        })
      );
      setExecutives(executivesWithFamily);
    } catch {
      toast.error('Error al cargar la lista de ejecutivos');
    } finally {
      setLoading(false);
    }
  }, [searchTerm]);

  // Fetch family members for an executive
  const fetchFamilyMembers = useCallback(async (executiveId: string) => {
    try {
      const res = await fetch(`/api/family-members?executiveId=${executiveId}`);
      if (!res.ok) throw new Error('Error al cargar familiares');
      const data = await res.json();
      return data.familyMembers || [];
    } catch {
      toast.error('Error al cargar familiares');
      return [];
    }
  }, []);

  // Handle family member creation
  const handleCreateFamilyMember = async () => {
    if (!selectedExecutiveForFamily) return;
    try {
      const res = await fetch('/api/family-members', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          executiveId: selectedExecutiveForFamily.id,
          ...familyFormData,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        toast.error(data.error || 'Error al crear familiar');
        return;
      }
      toast.success(`Familiar ${familyFormData.fullName} creado exitosamente`);
      setShowCreateFamilyDialog(false);
      resetFamilyForm();
      fetchExecutives();
    } catch {
      toast.error('Error de conexión al crear familiar');
    }
  };

  // Handle family member update
  const handleUpdateFamilyMember = async () => {
    if (!selectedFamilyMember) return;
    try {
      const res = await fetch('/api/family-members', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: selectedFamilyMember.id,
          ...familyFormData,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        toast.error(data.error || 'Error al actualizar familiar');
        return;
      }
      toast.success(`Familiar ${familyFormData.fullName} actualizado exitosamente`);
      setShowEditFamilyDialog(false);
      setSelectedFamilyMember(null);
      resetFamilyForm();
      fetchExecutives();
    } catch {
      toast.error('Error de conexión al actualizar familiar');
    }
  };

  // Handle family member deletion
  const handleDeleteFamilyMember = async () => {
    if (!selectedFamilyMember) return;
    try {
      const res = await fetch(`/api/family-members?id=${selectedFamilyMember.id}`, { method: 'DELETE' });
      if (!res.ok) {
        toast.error('Error al eliminar familiar');
        return;
      }
      toast.success('Familiar eliminado exitosamente');
      setShowDeleteFamilyDialog(false);
      setSelectedFamilyMember(null);
      fetchExecutives();
    } catch {
      toast.error('Error de conexión al eliminar familiar');
    }
  };

  const resetFamilyForm = () => {
    setFamilyFormData({
      fullName: '', relationship: '', identificationNum: '', email: '',
      phone: '', riskLevel: 'bajo', notes: '',
    });
  };

  const openEditFamilyDialog = (familyMember: FamilyMember, executive: Executive) => {
    setSelectedFamilyMember(familyMember);
    setSelectedExecutiveForFamily(executive);
    setFamilyFormData({
      fullName: familyMember.fullName,
      relationship: familyMember.relationship,
      identificationNum: familyMember.identificationNum || '',
      email: familyMember.email || '',
      phone: familyMember.phone || '',
      riskLevel: familyMember.riskLevel,
      notes: familyMember.notes || '',
    });
    setShowEditFamilyDialog(true);
  };

  const openCreateFamilyDialog = (executive: Executive) => {
    setSelectedExecutiveForFamily(executive);
    resetFamilyForm();
    setShowCreateFamilyDialog(true);
  };

  const toggleExecutiveExpanded = (executiveId: string) => {
    setExpandedExecutives(prev => {
      const next = new Set(prev);
      if (next.has(executiveId)) {
        next.delete(executiveId);
      } else {
        next.add(executiveId);
      }
      return next;
    });
  };

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

  // V7.0 Promote/Demote handlers
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

  // Execute metabusqueda with OSINT query matrix v7.0
  const handleMetasearch = async (target?: { id: string; fullName: string; email: string | null; phone: string | null; organization: string | null }) => {
    const searchTarget = target || selectedExecutive;
    if (!searchTarget) return;
    
    setMetasearchLoading(true);
    setShowResults(true);
    setMetasearchResults(null);
    setExpandedResult(null);
    setLocalValidated([]);
    setLocalPotential([]);
    setLocalDiscarded([]);
    setEnginesExpanded(false);
    setClassificationExpanded(false);
    setExtensionsExpanded(false);
    setExpandedQueryGroup(null);
    setSearchProgress('Iniciando Meta-Busqueda OSINT v7.0 (ZAI Web Search + Dorking)...');

    try {
      const res = await fetch('/api/metasearch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          executiveId: searchTarget.id, 
          downloadFiles: true,
          targetType: 'executive' in searchTarget ? 'executive' : 'family',
          targetName: searchTarget.fullName,
          targetEmail: searchTarget.email,
          targetPhone: searchTarget.phone,
          targetOrg: searchTarget.organization,
        }),
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

      // AUTO-SELECT tab with results (prioritize: validated > potential > discarded)
      if (validated.length > 0) {
        setActiveResultTab('validated');
      } else if (potential.length > 0) {
        setActiveResultTab('potential');
      } else if (discarded.length > 0) {
        setActiveResultTab('discarded');
      } else {
        setActiveResultTab('validated');
      }

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

  // Helper: get results for a given classification
  const getResultsForClass = (cls: 'validated' | 'potential' | 'discarded') => {
    switch (cls) {
      case 'validated': return localValidated;
      case 'potential': return localPotential;
      case 'discarded': return localDiscarded;
    }
  };

  // Show auth loading state
  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-primary flex items-center justify-center">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-foreground tracking-tight">Proteccion de Ejecutivos</h1>
                <p className="text-xs text-muted-foreground">Modulo OSINT v7.0 - Clasificacion Inteligente</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <NextLink href="/" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                &larr; Dashboard
              </NextLink>
              <ThemeSelector compact />
            </div>
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
                placeholder="Buscar ejecutivo o familiar..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-9 bg-muted/30 border-border"
              />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1 border border-border rounded-lg p-1 bg-card">
              <Button
                variant={viewMode === 'tree' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setViewMode('tree')}
                className="gap-1"
              >
                <FolderOpen className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Árbol</span>
              </Button>
              <Button
                variant={viewMode === 'table' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setViewMode('table')}
                className="gap-1"
              >
                <FileSpreadsheet className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Tabla</span>
              </Button>
            </div>
            <Button
              onClick={() => setShowDorkingPanel(true)}
              className="bg-emerald-600 hover:bg-emerald-700 text-white font-medium gap-2"
              title={selectedExecutive ? `Google Dorking OSINT: ${selectedExecutive.fullName}` : 'Google Dorking OSINT'}
            >
              <Search className="w-4 h-4" />
              Meta-Busqueda OSINT
            </Button>
            <Button
              onClick={() => { resetForm(); setShowCreateDialog(true); }}
              className="bg-primary hover:bg-primary/90 text-white font-medium gap-2"
            >
              <Plus className="w-4 h-4" /> Nuevo Ejecutivo
            </Button>
          </div>
        </div>

        {/* Limits Info */}
        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <Users className="w-3 h-3" />
            Ejecutivos: {executives.length} / {MAX_EXECUTIVES}
            {executives.length >= MAX_EXECUTIVES * 0.9 && <AlertTriangle className="w-3 h-3 text-yellow-500" />}
          </span>
        </div>

        {/* Selection indicator */}
        {selectedExecutive && !showDorkingPanel && (
          <motion.div
            initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-3 p-3 rounded-lg bg-primary/8 border border-primary/12"
          >
            <UserCheck className="w-4 h-4 text-primary" />
            <span className="text-sm text-primary">
              Seleccionado: <strong>{selectedExecutive.fullName}</strong>
              {'identificationNum' in selectedExecutive && 'relationship' in selectedExecutive ? (
                <>
                  <Badge variant="outline" className="ml-2 text-[9px] h-4 px-1.5 border-green-500/20 text-green-400">
                    Familiar - {RELATIONSHIP_OPTIONS.find(r => r.value === (selectedExecutive as any).relationship)?.label || (selectedExecutive as any).relationship}
                  </Badge>
                </>
              ) : (
                <>
                  {selectedExecutive.position && ` - ${selectedExecutive.position}`}
                  {selectedExecutive.organization && ` - ${selectedExecutive.organization}`}
                </>
              )}
            </span>
            <Button
              variant="outline"
              size="sm"
              className="ml-auto gap-1 border-emerald-600/30 text-emerald-400 hover:bg-emerald-600/10"
              onClick={() => handleMetasearch(selectedExecutive)}
              disabled={metasearchLoading}
            >
              <Search className="w-3.5 h-3.5" />
              Ejecutar OSINT
            </Button>
            <button onClick={() => { setSelectedExecutive(null); setShowResults(false); }} className="ml-2 text-primary hover:text-primary/80">
              <X className="w-4 h-4" />
            </button>
          </motion.div>
        )}

        {/* Google Dorking OSINT Panel */}
        <AnimatePresence>
          {showDorkingPanel && (
            <GoogleDorkingPanel
              executiveTarget={selectedExecutive ? {
                fullName: selectedExecutive.fullName,
                email: selectedExecutive.email,
                phone: selectedExecutive.phone,
                organization: selectedExecutive.organization,
              } : undefined}
              onClose={() => setShowDorkingPanel(false)}
            />
          )}
        </AnimatePresence>

        {/* Executives Tree/Table View */}
        <Card className="border-border bg-card/60 overflow-hidden">
          <CardHeader className="pb-3">
            <CardTitle className="text-base text-foreground">Directorio de Ejecutivos y Familiares</CardTitle>
            <CardDescription className="text-muted-foreground text-xs">
              Seleccione un ejecutivo o familiar para habilitar la Meta-Busqueda OSINT v7.0. Límite: {MAX_EXECUTIVES} ejecutivos, {MAX_FAMILY_MEMBERS_PER_EXECUTIVE} familiares por ejecutivo.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="w-6 h-6 animate-spin text-primary" />
                <span className="ml-2 text-muted-foreground">Cargando ejecutivos...</span>
              </div>
            ) : executives.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Shield className="w-12 h-12 mb-3 opacity-30" />
                <p className="text-sm">No hay ejecutivos registrados</p>
                <p className="text-xs">Haga clic en "Nuevo Ejecutivo" para comenzar</p>
              </div>
            ) : (
              viewMode === 'tree' ? (
                <div className="p-2 max-h-[600px] overflow-y-auto">
                  {executives.map((exec) => (
                    <div key={exec.id} className="border-border">
                      {/* Executive Row */}
                      <div
                        className={`flex items-center gap-2 px-3 py-2.5 cursor-pointer transition-colors rounded-lg ${
                          selectedExecutive?.id === exec.id ? 'bg-primary/8 border border-primary/20' : 'hover:bg-muted/30'
                        }`}
                        onClick={() => handleSelectExecutive(exec)}
                      >
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 w-7 p-0 text-muted-foreground hover:text-primary"
                          onClick={(e) => { e.stopPropagation(); toggleExecutiveExpanded(exec.id); }}
                        >
                          {expandedExecutives.has(exec.id) ? (
                            <ChevronDown className="w-4 h-4" />
                          ) : (
                            <ChevronRight className="w-4 h-4" />
                          )}
                        </Button>
                        <div className={`w-3 h-3 rounded-full border-2 ${
                          selectedExecutive?.id === exec.id ? 'bg-primary border-primary' : 'border-muted-foreground/30'
                        }`} />
                        <div className="flex-1 min-w-0 flex items-center gap-2">
                          <span className="text-sm font-medium text-foreground truncate">{exec.fullName}</span>
                          <RiskBadge level={exec.riskLevel} />
                          <span className="text-xs text-muted-foreground font-mono">{exec.identificationNum}</span>
                          {exec.organization && <span className="text-xs text-muted-foreground">{exec.organization}</span>}
                        </div>
                        <div className="flex items-center gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 w-7 p-0 text-muted-foreground hover:text-primary"
                            onClick={(e) => { e.stopPropagation(); openCreateFamilyDialog(exec); }}
                            disabled={executives.length >= MAX_EXECUTIVES || (exec.familyMembers?.length || 0) >= MAX_FAMILY_MEMBERS_PER_EXECUTIVE}
                            title={(exec.familyMembers?.length || 0) >= MAX_FAMILY_MEMBERS_PER_EXECUTIVE ? `Máximo ${MAX_FAMILY_MEMBERS_PER_EXECUTIVE} familiares` : 'Agregar familiar'}
                          >
                            <Users className="w-3.5 h-3.5" />
                          </Button>
                          <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground" onClick={(e) => { e.stopPropagation(); setSelectedExecutive(exec); setShowDetailDialog(true); }}><Eye className="w-3.5 h-3.5" /></Button>
                          <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-primary" onClick={(e) => { e.stopPropagation(); openEditDialog(exec); }}><Edit3 className="w-3.5 h-3.5" /></Button>
                          <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-red-500" onClick={(e) => { e.stopPropagation(); setSelectedExecutive(exec); setShowDeleteDialog(true); }}><Trash2 className="w-3.5 h-3.5" /></Button>
                        </div>
                      </div>

                      {/* Family Members - Expanded */}
                      {expandedExecutives.has(exec.id) && exec.familyMembers && exec.familyMembers.length > 0 && (
                        <div className="pl-10 border-l border-border/30 ml-5 space-y-1">
                          {exec.familyMembers.map((family) => (
                            <div
                              key={family.id}
                              className={`flex items-center gap-2 px-3 py-2 cursor-pointer transition-colors rounded-lg ${
                                selectedExecutive?.id === family.id ? 'bg-primary/8 border border-primary/20' : 'hover:bg-muted/30'
                              }`}
                              onClick={() => handleSelectExecutive({ ...family, id: family.id, identificationNum: family.identificationNum || '', position: family.relationship, organization: exec.organization || '', lastMetasearch: null, lastMetasearchResults: null, active: family.active, createdAt: family.createdAt, updatedAt: family.updatedAt, riskLevel: family.riskLevel, notes: family.notes } as Executive)}
                            >
                              <div className="w-3 h-3 rounded-full border-2 border-primary/30 bg-primary/10" />
                              <div className="flex-1 min-w-0 flex items-center gap-2">
                                <span className="text-sm font-medium text-foreground truncate">{family.fullName}</span>
                                <Badge variant="outline" className="text-[9px] h-4 px-1.5 border-primary/20 text-primary">
                                  {RELATIONSHIP_OPTIONS.find(r => r.value === family.relationship)?.label || family.relationship}
                                </Badge>
                                <RiskBadge level={family.riskLevel} />
                                {family.identificationNum && <span className="text-xs text-muted-foreground font-mono">{family.identificationNum}</span>}
                              </div>
                              <div className="flex items-center gap-1">
                                <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-primary" onClick={(e) => { e.stopPropagation(); openEditFamilyDialog(family, exec); }}><Edit3 className="w-3.5 h-3.5" /></Button>
                                <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-red-500" onClick={(e) => { e.stopPropagation(); setSelectedFamilyMember(family); setShowDeleteFamilyDialog(true); }}><Trash2 className="w-3.5 h-3.5" /></Button>
                              </div>
                            </div>
                          ))}
                          {(exec.familyMembers.length < MAX_FAMILY_MEMBERS_PER_EXECUTIVE) && (
                            <Button
                              variant="outline"
                              size="sm"
                              className="w-full justify-start text-xs gap-1 border-dashed border-primary/30 text-primary hover:bg-primary/5"
                              onClick={(e) => { e.stopPropagation(); openCreateFamilyDialog(exec); }}
                            >
                              <Plus className="w-3.5 h-3.5" />
                              Agregar familiar ({exec.familyMembers.length}/{MAX_FAMILY_MEMBERS_PER_EXECUTIVE})
                            </Button>
                          )}
                        </div>
                      )}

                      {/* Empty Family State - Add Button */}
                      {expandedExecutives.has(exec.id) && (!exec.familyMembers || exec.familyMembers.length === 0) && (
                        <div className="pl-10 ml-5 py-2">
                          <Button
                            variant="outline"
                            size="sm"
                            className="w-full justify-start text-xs gap-1 border-dashed border-primary/30 text-primary hover:bg-primary/5"
                            onClick={(e) => { e.stopPropagation(); openCreateFamilyDialog(exec); }}
                          >
                            <Plus className="w-3.5 h-3.5" />
                            Agregar primer familiar (0/{MAX_FAMILY_MEMBERS_PER_EXECUTIVE})
                          </Button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow className="border-border hover:bg-transparent">
                        <TableHead className="w-10"></TableHead>
                        <TableHead className="text-xs text-muted-foreground">Identificacion</TableHead>
                        <TableHead className="text-xs text-muted-foreground">Nombre Completo</TableHead>
                        <TableHead className="text-xs text-muted-foreground">Tipo</TableHead>
                        <TableHead className="text-xs text-muted-foreground">Relación / Cargo</TableHead>
                        <TableHead className="text-xs text-muted-foreground">Correo Electronico</TableHead>
                        <TableHead className="text-xs text-muted-foreground">Organización</TableHead>
                        <TableHead className="text-xs text-muted-foreground">Riesgo</TableHead>
                        <TableHead className="text-xs text-muted-foreground">Ultima Busqueda</TableHead>
                        <TableHead className="w-28 text-xs text-muted-foreground">Acciones</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {executives.flatMap((exec) => [
                        <TableRow
                          key={exec.id}
                          className={`border-border cursor-pointer transition-colors ${
                            selectedExecutive?.id === exec.id ? 'bg-primary/8 border-primary/15' : 'hover:bg-muted/30'
                          }`}
                          onClick={() => handleSelectExecutive(exec)}
                        >
                          <TableCell className="py-3">
                            <div className={`w-3 h-3 rounded-full border-2 ${
                              selectedExecutive?.id === exec.id ? 'bg-primary border-primary' : 'border-muted-foreground/30'
                            }`} />
                          </TableCell>
                          <TableCell className="py-3"><span className="text-xs font-mono text-muted-foreground">{exec.identificationNum}</span></TableCell>
                          <TableCell className="py-3"><span className="text-sm font-medium text-foreground">{exec.fullName}</span></TableCell>
                          <TableCell className="py-3">
                            <Badge variant="outline" className="text-[9px] h-4 px-1.5 border-primary/20 text-primary">Ejecutivo</Badge>
                          </TableCell>
                          <TableCell className="py-3"><span className="text-xs text-foreground">{exec.position || '-'}</span></TableCell>
                          <TableCell className="py-3"><span className="text-xs text-muted-foreground">{exec.email || '-'}</span></TableCell>
                          <TableCell className="py-3"><span className="text-xs text-muted-foreground">{exec.organization || '-'}</span></TableCell>
                          <TableCell className="py-3"><RiskBadge level={exec.riskLevel} /></TableCell>
                          <TableCell className="py-3">
                            <span className="text-xs text-muted-foreground">
                              {exec.lastMetasearch ? new Date(exec.lastMetasearch).toLocaleDateString('es-CO', { day: '2-digit', month: 'short', year: 'numeric' }) : 'Nunca'}
                            </span>
                          </TableCell>
                          <TableCell className="py-3">
                            <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                              <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground" onClick={() => { setSelectedExecutive(exec); setShowDetailDialog(true); }}><Eye className="w-3.5 h-3.5" /></Button>
                              <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-primary" onClick={() => openEditDialog(exec)}><Edit3 className="w-3.5 h-3.5" /></Button>
                              <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-red-500" onClick={() => { setSelectedExecutive(exec); setShowDeleteDialog(true); }}><Trash2 className="w-3.5 h-3.5" /></Button>
                            </div>
                          </TableCell>
                        </TableRow>,
                        ...(exec.familyMembers || []).map((family) => (
                          <TableRow
                            key={family.id}
                            className={`border-border cursor-pointer transition-colors pl-4 ${
                              selectedExecutive?.id === family.id ? 'bg-primary/8 border-primary/15' : 'hover:bg-muted/30'
                            }`}
                            onClick={() => handleSelectExecutive({ ...family, id: family.id, identificationNum: family.identificationNum || '', position: family.relationship, organization: exec.organization || '', lastMetasearch: null, lastMetasearchResults: null, active: family.active, createdAt: family.createdAt, updatedAt: family.updatedAt, riskLevel: family.riskLevel, notes: family.notes } as Executive)}
                          >
                            <TableCell className="py-2">
                              <div className="w-3 h-3 rounded-full border-2 border-primary/30 bg-primary/10" />
                            </TableCell>
                            <TableCell className="py-2"><span className="text-xs font-mono text-muted-foreground">{family.identificationNum || '-'}</span></TableCell>
                            <TableCell className="py-2"><span className="text-sm font-medium text-foreground">{family.fullName}</span></TableCell>
                            <TableCell className="py-2">
                              <Badge variant="outline" className="text-[9px] h-4 px-1.5 border-green-500/20 text-green-400">Familiar</Badge>
                            </TableCell>
                            <TableCell className="py-2">
                              <Badge variant="outline" className="text-[9px] h-4 px-1.5 border-primary/20 text-primary">
                                {RELATIONSHIP_OPTIONS.find(r => r.value === family.relationship)?.label || family.relationship}
                              </Badge>
                            </TableCell>
                            <TableCell className="py-2"><span className="text-xs text-muted-foreground">{family.email || '-'}</span></TableCell>
                            <TableCell className="py-2"><span className="text-xs text-muted-foreground">{exec.organization || '-'}</span></TableCell>
                            <TableCell className="py-2"><RiskBadge level={family.riskLevel} /></TableCell>
                            <TableCell className="py-2"><span className="text-xs text-muted-foreground">-</span></TableCell>
                            <TableCell className="py-2">
                              <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                                <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-primary" onClick={(e) => { e.stopPropagation(); openEditFamilyDialog(family, exec); }}><Edit3 className="w-3.5 h-3.5" /></Button>
                                <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-red-500" onClick={(e) => { e.stopPropagation(); setSelectedFamilyMember(family); setShowDeleteFamilyDialog(true); }}><Trash2 className="w-3.5 h-3.5" /></Button>
                              </div>
                            </TableCell>
                          </TableRow>
                        ))
                      ])}
                    </TableBody>
                  </Table>
                </div>
              ))}
          </CardContent>
        </Card>

        {/* Metasearch Results - Enterprise Dashboard v7.0 */}
        <AnimatePresence>
          {showResults && (
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }}>
              <Card className="border-border bg-card/60">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-base text-foreground flex items-center gap-2">
                        <Globe className="w-4 h-4 text-primary" />
                        Resultados de Meta-Busqueda OSINT v7.0
                      </CardTitle>
                      {metasearchResults && (
                        <div className="flex items-center gap-2 mt-1">
                          <CardDescription className="text-xs text-muted-foreground">
                            {metasearchResults.searchEngine} - {localValidated.length} validados / {localPotential.length} potenciales / {localDiscarded.length} descartados
                            {metasearchResults.elapsedSeconds ? ` - ${metasearchResults.elapsedSeconds}s` : ''}
                          </CardDescription>
                          {metasearchResults.targetType === 'family' && (
                            <Badge variant="outline" className="text-[9px] h-4 px-1.5 border-green-500/20 text-green-400">
                              <Users className="w-2.5 h-2.5 mr-0.5" /> Familiar: {metasearchResults.targetName}
                            </Badge>
                          )}
                        </div>
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
                      <Loader2 className="w-8 h-8 animate-spin text-primary mb-3" />
                      <p className="text-sm text-muted-foreground">Ejecutando Meta-Busqueda OSINT v7.0...</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Consultando: &quot;{selectedExecutive?.fullName}&quot; en ZAI Web Search + Dorking OSINT (40+ extensiones)
                      </p>
                      <p className="text-xs text-primary mt-2">Clasificacion Inteligente de 3 niveles activada</p>
                      {searchProgress && (
                        <p className="text-xs text-primary mt-1">{searchProgress}</p>
                      )}
                    </div>
                  ) : metasearchResults ? (
                    <>
                      {/* V7.0 Expandable Panels Row */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">

                        {/* ============================================
                            MOTORES DE BUSQUEDA - EXPANDABLE v7.0
                            ============================================ */}
                        <div className="rounded-lg bg-purple-500/5 border border-purple-500/20 overflow-hidden">
                          <button
                            onClick={() => setEnginesExpanded(!enginesExpanded)}
                            className="w-full p-3 flex items-center gap-2 hover:bg-purple-500/5 transition-colors"
                          >
                            <Globe className="w-3.5 h-3.5 text-purple-400" />
                            <p className="text-[10px] font-medium text-purple-400">Motores de Busqueda</p>
                            <span className="ml-auto flex items-center gap-1">
                              {metasearchResults.engineDetails && metasearchResults.engineDetails.length > 0 && (
                                <span className="text-[9px] text-purple-400/60">
                                  {metasearchResults.engineDetails.filter(e => e.status === 'active').length} activo{metasearchResults.engineDetails.filter(e => e.status === 'active').length !== 1 ? 's' : ''}
                                </span>
                              )}
                              {enginesExpanded ? <ChevronUp className="w-3.5 h-3.5 text-purple-400/60" /> : <ChevronDown className="w-3.5 h-3.5 text-purple-400/60" />}
                            </span>
                          </button>

                          {/* Collapsed preview */}
                          {!enginesExpanded && metasearchResults.engineDetails && (
                            <div className="px-3 pb-3 flex flex-wrap gap-2">
                              {metasearchResults.engineDetails.map((engine, idx) => (
                                <div key={idx} className="flex items-center gap-1.5 text-[10px]">
                                  {engine.status === 'active' ? (
                                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                                  ) : engine.status === 'failed' ? (
                                    <XCircle className="w-3 h-3 text-red-400" />
                                  ) : (
                                    <AlertTriangle className="w-3 h-3 text-primary" />
                                  )}
                                  <span className="text-foreground/80">{engine.name}</span>
                                  <span className="text-muted-foreground">({engine.resultsFound})</span>
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Expanded details */}
                          <AnimatePresence>
                            {enginesExpanded && (
                              <motion.div
                                initial={{ height: 0, opacity: 0 }}
                                animate={{ height: 'auto', opacity: 1 }}
                                exit={{ height: 0, opacity: 0 }}
                                transition={{ duration: 0.2 }}
                                className="overflow-hidden"
                              >
                                <div className="px-3 pb-3 space-y-3">
                                  {/* Engine Details Table */}
                                  {metasearchResults.engineDetails && metasearchResults.engineDetails.length > 0 && (
                                    <div className="space-y-1.5">
                                      {metasearchResults.engineDetails.map((engine, idx) => (
                                        <div key={idx} className="flex items-center gap-2 p-2 rounded bg-card/50 border border-border">
                                          {engine.status === 'active' ? (
                                            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                                          ) : engine.status === 'failed' ? (
                                            <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                                          ) : (
                                            <AlertTriangle className="w-4 h-4 text-primary flex-shrink-0" />
                                          )}
                                          <div className="flex-1 min-w-0">
                                            <p className="text-xs font-medium text-foreground">{engine.name}</p>
                                            <p className="text-[9px] text-muted-foreground">{engine.details}</p>
                                          </div>
                                          <div className="flex items-center gap-3 text-[10px] flex-shrink-0">
                                            <span className="text-muted-foreground">{engine.queriesRun} consultas</span>
                                            <span className="font-bold text-foreground">{engine.resultsFound} resultados</span>
                                          </div>
                                        </div>
                                      ))}
                                    </div>
                                  )}

                                  {/* Query Groups - Ver consultas ejecutadas */}
                                  {metasearchResults.queryGroups && metasearchResults.queryGroups.length > 0 && (
                                    <div>
                                      <p className="text-[10px] font-medium text-purple-400 mb-2 flex items-center gap-1">
                                        <ChevronRight className="w-3 h-3" /> Consultas Ejecutadas ({metasearchResults.queryGroups.reduce((s, g) => s + g.queryCount, 0)} queries)
                                      </p>
                                      <div className="space-y-1">
                                        {metasearchResults.queryGroups.map((group, idx) => {
                                          const blockColors: Record<string, string> = {
                                            name: 'border-blue-500/30 text-blue-400',
                                            email: 'border-purple-500/30 text-purple-400',
                                            id: 'border-primary/15 text-primary',
                                            extension: 'border-green-500/30 text-green-400',
                                            combined: 'border-red-500/30 text-red-400',
                                            custom: 'border-cyan-500/30 text-cyan-400',
                                          };
                                          const color = blockColors[group.blockType] || 'border-border';
                                          const isExpandedGroup = expandedQueryGroup === idx;

                                          return (
                                            <div key={idx} className="rounded border border-border overflow-hidden">
                                              <button
                                                onClick={() => setExpandedQueryGroup(isExpandedGroup ? null : idx)}
                                                className="w-full flex items-center gap-2 p-1.5 hover:bg-muted/20 transition-colors text-left"
                                              >
                                                <Badge variant="outline" className={`text-[8px] h-4 px-1 ${color}`}>
                                                  {group.blockType?.toUpperCase()}
                                                </Badge>
                                                <span className="text-[10px] text-foreground/80 flex-1">{group.label}</span>
                                                <span className="text-[9px] text-muted-foreground">{group.queryCount}q</span>
                                                <span className="text-[9px] font-bold text-foreground">{group.resultsFound}r</span>
                                                {isExpandedGroup ? <ChevronUp className="w-3 h-3 text-muted-foreground" /> : <ChevronDown className="w-3 h-3 text-muted-foreground" />}
                                              </button>
                                              <AnimatePresence>
                                                {isExpandedGroup && group.sampleQueries && group.sampleQueries.length > 0 && (
                                                  <motion.div
                                                    initial={{ height: 0, opacity: 0 }}
                                                    animate={{ height: 'auto', opacity: 1 }}
                                                    exit={{ height: 0, opacity: 0 }}
                                                    transition={{ duration: 0.15 }}
                                                    className="overflow-hidden"
                                                  >
                                                    <div className="px-2 pb-2 pt-1 space-y-0.5">
                                                      {group.sampleQueries.map((q, qi) => (
                                                        <p key={qi} className="text-[9px] font-mono text-muted-foreground/80 truncate" title={q}>
                                                          {q}
                                                        </p>
                                                      ))}
                                                      {group.queryCount > group.sampleQueries.length && (
                                                        <p className="text-[8px] text-muted-foreground/50 italic">
                                                          +{group.queryCount - group.sampleQueries.length} consultas mas...
                                                        </p>
                                                      )}
                                                    </div>
                                                  </motion.div>
                                                )}
                                              </AnimatePresence>
                                            </div>
                                          );
                                        })}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </motion.div>
                            )}
                          </AnimatePresence>
                        </div>

                        {/* ============================================
                            CLASIFICACION INTELIGENTE - EXPANDABLE v7.0
                            ============================================ */}
                        <div className="rounded-lg bg-primary/5 border border-primary/12 overflow-hidden">
                          <button
                            onClick={() => setClassificationExpanded(!classificationExpanded)}
                            className="w-full p-3 flex items-center gap-2 hover:bg-primary/5 transition-colors"
                          >
                            <Shield className="w-3.5 h-3.5 text-primary" />
                            <p className="text-[10px] font-medium text-primary">Clasificacion Inteligente v7.0</p>
                            <span className="ml-auto flex items-center gap-1">
                              <span className="text-[9px] text-primary/60">
                                {localValidated.length + localPotential.length + localDiscarded.length} total
                              </span>
                              {classificationExpanded ? <ChevronUp className="w-3.5 h-3.5 text-primary/60" /> : <ChevronDown className="w-3.5 h-3.5 text-primary/60" />}
                            </span>
                          </button>

                          {/* Classification Buttons Row (always visible) */}
                          <div className="px-3 pb-2">
                            <div className="grid grid-cols-3 gap-2 text-center">
                              <button
                                onClick={(e) => { e.stopPropagation(); setActiveResultTab('validated'); setResultFilter('all'); setClassificationExpanded(true); }}
                                className={`rounded p-1.5 transition-all relative group ${activeResultTab === 'validated' ? 'bg-emerald-500/15 ring-1 ring-emerald-500/40' : 'hover:bg-emerald-500/10'}`}
                                title={`${localValidated.length} resultados validados`}
                              >
                                <div className="flex items-center justify-center gap-1">
                                  <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                                  <p className="text-sm font-bold text-emerald-400">{localValidated.length}</p>
                                </div>
                                <p className="text-[9px] text-muted-foreground">Validados</p>
                                {/* Tooltip */}
                                <div className="absolute -top-8 left-1/2 -translate-x-1/2 bg-foreground text-background text-[9px] px-2 py-0.5 rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-10">
                                  {localValidated.length} validados
                                </div>
                              </button>
                              <button
                                onClick={(e) => { e.stopPropagation(); setActiveResultTab('potential'); setResultFilter('all'); setClassificationExpanded(true); }}
                                className={`rounded p-1.5 transition-all relative group ${activeResultTab === 'potential' ? 'bg-primary/12 ring-1 ring-primary/30' : 'hover:bg-primary/8'}`}
                                title={`${localPotential.length} resultados potenciales`}
                              >
                                <div className="flex items-center justify-center gap-1">
                                  <AlertTriangle className="w-3 h-3 text-primary" />
                                  <p className="text-sm font-bold text-primary">{localPotential.length}</p>
                                </div>
                                <p className="text-[9px] text-muted-foreground">Potenciales</p>
                                {/* Tooltip */}
                                <div className="absolute -top-8 left-1/2 -translate-x-1/2 bg-foreground text-background text-[9px] px-2 py-0.5 rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-10">
                                  {localPotential.length} potenciales
                                </div>
                              </button>
                              <button
                                onClick={(e) => { e.stopPropagation(); setActiveResultTab('discarded'); setResultFilter('all'); setClassificationExpanded(true); }}
                                className={`rounded p-1.5 transition-all relative group ${activeResultTab === 'discarded' ? 'bg-red-500/15 ring-1 ring-red-500/40' : 'hover:bg-red-500/10'}`}
                                title={`${localDiscarded.length} resultados descartados`}
                              >
                                <div className="flex items-center justify-center gap-1">
                                  <XCircle className="w-3 h-3 text-red-400" />
                                  <p className="text-sm font-bold text-red-400">{localDiscarded.length}</p>
                                </div>
                                <p className="text-[9px] text-muted-foreground">Descartados</p>
                                {/* Tooltip */}
                                <div className="absolute -top-8 left-1/2 -translate-x-1/2 bg-foreground text-background text-[9px] px-2 py-0.5 rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-10">
                                  {localDiscarded.length} descartados
                                </div>
                              </button>
                            </div>
                          </div>

                          {/* Expanded panel: stats breakdown, summary, and result previews */}
                          <AnimatePresence>
                            {classificationExpanded && (
                              <motion.div
                                initial={{ height: 0, opacity: 0 }}
                                animate={{ height: 'auto', opacity: 1 }}
                                exit={{ height: 0, opacity: 0 }}
                                transition={{ duration: 0.2 }}
                                className="overflow-hidden"
                              >
                                <div className="px-3 pb-3 space-y-3">
                                  {/* Stats Breakdown Bar */}
                                  {(() => {
                                    const total = localValidated.length + localPotential.length + localDiscarded.length;
                                    if (total === 0) return null;
                                    const vPct = Math.round((localValidated.length / total) * 100);
                                    const pPct = Math.round((localPotential.length / total) * 100);
                                    const dPct = 100 - vPct - pPct;
                                    return (
                                      <div>
                                        <p className="text-[10px] font-medium text-primary mb-1.5">Desglose de Clasificacion</p>
                                        {/* Stacked bar */}
                                        <div className="flex h-3 rounded-full overflow-hidden bg-muted/30">
                                          {localValidated.length > 0 && (
                                            <div className="bg-emerald-500/70 transition-all" style={{ width: `${vPct}%` }} title={`${localValidated.length} validados (${vPct}%)`} />
                                          )}
                                          {localPotential.length > 0 && (
                                            <div className="bg-primary/70 transition-all" style={{ width: `${pPct}%` }} title={`${localPotential.length} potenciales (${pPct}%)`} />
                                          )}
                                          {localDiscarded.length > 0 && (
                                            <div className="bg-red-500/70 transition-all" style={{ width: `${dPct}%` }} title={`${localDiscarded.length} descartados (${dPct}%)`} />
                                          )}
                                        </div>
                                        {/* Legend + percentages */}
                                        <div className="flex items-center gap-4 mt-1.5">
                                          <div className="flex items-center gap-1">
                                            <div className="w-2 h-2 rounded-full bg-emerald-500/70" />
                                            <span className="text-[9px] text-emerald-400">Validados: {localValidated.length} ({vPct}%)</span>
                                          </div>
                                          <div className="flex items-center gap-1">
                                            <div className="w-2 h-2 rounded-full bg-primary/70" />
                                            <span className="text-[9px] text-primary">Potenciales: {localPotential.length} ({pPct}%)</span>
                                          </div>
                                          <div className="flex items-center gap-1">
                                            <div className="w-2 h-2 rounded-full bg-red-500/70" />
                                            <span className="text-[9px] text-red-400">Descartados: {localDiscarded.length} ({dPct}%)</span>
                                          </div>
                                        </div>
                                      </div>
                                    );
                                  })()}

                                  {/* Summary text */}
                                  {(() => {
                                    const total = localValidated.length + localPotential.length + localDiscarded.length;
                                    if (total === 0) return null;
                                    const ratio = localValidated.length > 0
                                      ? (localPotential.length / localValidated.length).toFixed(1)
                                      : 'N/A';
                                    const summaryText = localValidated.length > localPotential.length + localDiscarded.length
                                      ? `Alta tasa de validacion: ${Math.round((localValidated.length / total) * 100)}% de los resultados fueron confirmados como relevantes para el ejecutivo.`
                                      : localPotential.length > localValidated.length
                                      ? `Proporcion significativa de resultados potenciales (${localPotential.length}) frente a validados (${localValidated.length}). Se recomienda revision manual. Razon potencial/validado: ${ratio}.`
                                      : `Resultados distribuidos: ${localValidated.length} validados, ${localPotential.length} potenciales, ${localDiscarded.length} descartados de ${total} totales.`;
                                    return (
                                      <div className="p-2 rounded bg-card/50 border border-border">
                                        <div className="flex items-center gap-1.5 mb-1">
                                          <Shield className="w-3 h-3 text-primary" />
                                          <p className="text-[10px] font-medium text-primary">Resumen de Clasificacion</p>
                                        </div>
                                        <p className="text-[9px] text-foreground/80 leading-relaxed">{summaryText}</p>
                                      </div>
                                    );
                                  })()}

                                  {/* Per-category result previews */}
                                  {(['validated', 'potential', 'discarded'] as const).map(cls => {
                                    const results = getResultsForClass(cls);
                                    const colorMap: Record<string, string> = {
                                      validated: 'text-emerald-400 border-emerald-500/20',
                                      potential: 'text-primary border-primary/12',
                                      discarded: 'text-red-400 border-red-500/20',
                                    };
                                    const iconMap: Record<string, React.ReactNode> = {
                                      validated: <CheckCircle2 className="w-3 h-3 text-emerald-400" />,
                                      potential: <AlertTriangle className="w-3 h-3 text-primary" />,
                                      discarded: <XCircle className="w-3 h-3 text-red-400" />,
                                    };
                                    const labelMap: Record<string, string> = {
                                      validated: 'Validados',
                                      potential: 'Potenciales',
                                      discarded: 'Descartados',
                                    };

                                    return (
                                      <div key={cls} className="rounded border border-border overflow-hidden">
                                        <button
                                          onClick={() => { setActiveResultTab(cls); setResultFilter('all'); }}
                                          className={`w-full flex items-center gap-2 p-2 hover:bg-muted/20 transition-colors ${activeResultTab === cls ? 'bg-muted/10' : ''}`}
                                        >
                                          {iconMap[cls]}
                                          <span className={`text-[10px] font-medium ${colorMap[cls].split(' ')[0]}`}>
                                            {labelMap[cls]} ({results.length})
                                          </span>
                                        </button>
                                        {results.length > 0 ? (
                                          <div className="max-h-24 overflow-y-auto px-2 pb-2 space-y-0.5" style={{ scrollbarWidth: 'thin', scrollbarColor: 'rgba(255,255,255,0.1) transparent' }}>
                                            {results.slice(0, 5).map((r, ri) => (
                                              <div
                                                key={ri}
                                                className="flex items-center gap-1.5 text-[9px] cursor-pointer hover:bg-muted/20 rounded px-1 py-0.5"
                                                onClick={() => { setActiveResultTab(cls); setExpandedResult(r.url); }}
                                              >
                                                <span className="text-muted-foreground font-mono flex-shrink-0">#{r.position}</span>
                                                <span className="text-foreground/80 truncate">{r.title}</span>
                                                {r.fileType && r.fileType !== 'html' && (
                                                  <span className="text-primary flex-shrink-0">.{r.fileType}</span>
                                                )}
                                                {r.sourceDomain && (
                                                  <span className="text-muted-foreground/60 flex-shrink-0 ml-auto">{r.sourceDomain}</span>
                                                )}
                                              </div>
                                            ))}
                                            {results.length > 5 && (
                                              <button
                                                onClick={() => setActiveResultTab(cls)}
                                                className="text-[8px] text-primary/70 hover:text-primary italic pl-1"
                                              >
                                                +{results.length - 5} resultados mas...
                                              </button>
                                            )}
                                          </div>
                                        ) : (
                                          <p className="text-[9px] text-muted-foreground/50 px-2 pb-2 italic">Sin resultados</p>
                                        )}
                                      </div>
                                    );
                                  })}
                                </div>
                              </motion.div>
                            )}
                          </AnimatePresence>
                        </div>
                      </div>

                      {/* ============================================
                          EXTENSIONES MONITOREADAS - EXPANDABLE v7.0
                          ============================================ */}
                      {metasearchResults.extensionGroups && metasearchResults.extensionGroups.length > 0 && (
                        <div className="mb-4 rounded-lg bg-green-500/5 border border-green-500/20 overflow-hidden">
                          <button
                            onClick={() => setExtensionsExpanded(!extensionsExpanded)}
                            className="w-full p-3 flex items-center gap-2 hover:bg-green-500/5 transition-colors"
                          >
                            <FolderOpen className="w-3.5 h-3.5 text-green-400" />
                            <p className="text-[10px] font-medium text-green-400">Extensiones Monitoreadas</p>
                            <span className="text-[9px] text-green-400/60 ml-1">
                              {metasearchResults.extensionGroups.reduce((s, g) => s + g.exts.length, 0)} tipos
                            </span>
                            <span className="ml-auto flex items-center gap-1">
                              {!extensionsExpanded && (
                                <div className="flex items-center gap-1 mr-2">
                                  {metasearchResults.extensionGroups.slice(0, 4).map((g, i) => (
                                    <Badge key={i} variant="outline" className="text-[8px] h-4 px-1 border-green-500/20 text-green-400/70">
                                      {g.label}
                                    </Badge>
                                  ))}
                                  {metasearchResults.extensionGroups.length > 4 && (
                                    <span className="text-[8px] text-muted-foreground">+{metasearchResults.extensionGroups.length - 4}</span>
                                  )}
                                </div>
                              )}
                              {extensionsExpanded ? <ChevronUp className="w-3.5 h-3.5 text-green-400/60" /> : <ChevronDown className="w-3.5 h-3.5 text-green-400/60" />}
                            </span>
                          </button>
                          <AnimatePresence>
                            {extensionsExpanded && (
                              <motion.div
                                initial={{ height: 0, opacity: 0 }}
                                animate={{ height: 'auto', opacity: 1 }}
                                exit={{ height: 0, opacity: 0 }}
                                transition={{ duration: 0.2 }}
                                className="overflow-hidden"
                              >
                                <div className="px-3 pb-3 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                                  {metasearchResults.extensionGroups.map((group, idx) => (
                                    <div key={idx} className="p-2 rounded bg-card/50 border border-border">
                                      <div className="flex items-center gap-2 mb-1.5">
                                        <ExtGroupIcon iconName={group.icon} className="w-4 h-4 text-green-400" />
                                        <p className="text-[10px] font-medium text-foreground">{group.label}</p>
                                        <span className="text-[9px] text-muted-foreground ml-auto">{group.exts.length}</span>
                                      </div>
                                      <div className="flex flex-wrap gap-1">
                                        {group.exts.map((ext, ei) => (
                                          <Badge key={ei} variant="outline" className="text-[8px] h-3.5 px-1 border-green-500/20 text-green-400/70">
                                            {ext}
                                          </Badge>
                                        ))}
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </motion.div>
                            )}
                          </AnimatePresence>
                        </div>
                      )}

                      {/* AI Analysis - ALWAYS SHOW v7.0 */}
                      <div className="mb-4 p-4 rounded-lg bg-primary/5 border border-primary/12">
                        <div className="flex items-center gap-2 mb-3">
                          <Shield className="w-4 h-4 text-primary" />
                          <p className="text-xs font-semibold text-primary">Analisis de Inteligencia OSINT - IA</p>
                        </div>
                        <div className="text-xs text-foreground/90 whitespace-pre-wrap leading-relaxed">
                          {metasearchResults.aiAnalysis || 'Sin resultados para analizar. Intente ampliar los criterios de busqueda.'}
                        </div>
                      </div>

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

                      {/* V7.0 Three-tab Results Panel */}
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
                              amber: isActive ? 'border-primary/30 text-primary bg-primary/8' : 'border-border text-muted-foreground hover:text-primary',
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
                                    ? 'border-primary/30 text-primary bg-primary/8'
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
                            {/* Suggest other tabs with results */}
                            {activeResultTab === 'validated' && localPotential.length > 0 && (
                              <button onClick={() => setActiveResultTab('potential')} className="mt-2 text-xs text-primary hover:text-primary/80 underline">
                                Ver {localPotential.length} resultados potenciales
                              </button>
                            )}
                            {activeResultTab === 'validated' && localPotential.length === 0 && localDiscarded.length > 0 && (
                              <button onClick={() => setActiveResultTab('discarded')} className="mt-2 text-xs text-red-400 hover:text-red-300 underline">
                                Ver {localDiscarded.length} resultados descartados
                              </button>
                            )}
                            {activeResultTab === 'potential' && localValidated.length > 0 && (
                              <button onClick={() => setActiveResultTab('validated')} className="mt-2 text-xs text-emerald-400 hover:text-emerald-300 underline">
                                Ver {localValidated.length} resultados validados
                              </button>
                            )}
                            {activeResultTab === 'discarded' && (localValidated.length + localPotential.length) > 0 && (
                              <button onClick={() => setActiveResultTab(localValidated.length > 0 ? 'validated' : 'potential')} className="mt-2 text-xs text-primary hover:text-primary/80 underline">
                                Ver {localValidated.length + localPotential.length} resultados activos
                              </button>
                            )}
                          </div>
                        ) : (
                          <div className="space-y-2 max-h-96 overflow-y-auto pr-1" style={{ scrollbarWidth: 'thin', scrollbarColor: 'rgba(255,255,255,0.1) transparent' }}>
                            {currentTabResults.map((result, index) => {
                              const isExpanded = expandedResult === result.url;
                              const classificationBorderMap: Record<string, string> = {
                                validated: 'border-emerald-500/20 bg-emerald-500/5',
                                potential: 'border-primary/12 bg-primary/5',
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
                                    onClick={() => setExpandedResult(isExpanded ? null : result.url)}
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
                                            className="text-sm font-medium text-primary hover:text-primary hover:underline truncate max-w-[75%]"
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
                                            <Badge variant="outline" className="text-[9px] h-4 px-1.5 border-primary/15 text-primary">
                                              .{result.fileType}
                                            </Badge>
                                          )}

                                          {/* Query Block Badge - v7.0 */}
                                          {result.queryBlock && (
                                            <Badge variant="outline" className="text-[9px] h-4 px-1.5 border-cyan-500/30 text-cyan-400">
                                              {result.queryBlock}
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
                                                className="text-[9px] h-5 px-2 gap-0.5 border-primary/15 text-primary hover:bg-primary/8"
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
                                                <Calendar className="w-3 h-3 text-primary" />
                                                <p className="text-[10px] font-medium text-primary">Fecha Publicacion</p>
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
                                            {result.queryBlock && (
                                              <div>
                                                <p className="text-[10px] text-muted-foreground">Bloque Query:</p>
                                                <p className="text-[10px] text-cyan-400 font-mono">{result.queryBlock}</p>
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
                  <div className="w-12 h-12 rounded-full bg-primary/8 flex items-center justify-center"><Shield className="w-6 h-6 text-primary" /></div>
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
              <Button onClick={handleCreate} disabled={!formData.fullName || !formData.identificationNum} className="bg-primary hover:bg-primary/90 text-white gap-2">
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
              <Button onClick={handleUpdate} disabled={!formData.fullName || !formData.identificationNum} className="bg-primary hover:bg-primary/90 text-white gap-2">
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

        {/* Create Family Member Dialog */}
        <Dialog open={showCreateFamilyDialog} onOpenChange={setShowCreateFamilyDialog}>
          <DialogContent className="max-w-lg bg-card border-border">
            <DialogHeader>
              <DialogTitle className="text-foreground">Nuevo Familiar</DialogTitle>
              <DialogDescription className="text-muted-foreground">
                Registrar un familiar para <strong>{selectedExecutiveForFamily?.fullName}</strong>
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">Nombre Completo *</Label>
                  <Input placeholder="Maria Perez Gomez" value={familyFormData.fullName} onChange={(e) => setFamilyFormData(prev => ({ ...prev, fullName: e.target.value }))} className="bg-muted/30 border-border" />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">Relación *</Label>
                  <select value={familyFormData.relationship} onChange={(e) => setFamilyFormData(prev => ({ ...prev, relationship: e.target.value }))} className="w-full h-9 rounded-md bg-muted/30 border border-border text-sm text-foreground px-3">
                    {RELATIONSHIP_OPTIONS.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground flex items-center gap-1"><Mail className="w-3 h-3" /> Correo Electronico</Label>
                  <Input placeholder="correo@ejemplo.com" type="email" value={familyFormData.email} onChange={(e) => setFamilyFormData(prev => ({ ...prev, email: e.target.value }))} className="bg-muted/30 border-border" />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground flex items-center gap-1"><Phone className="w-3 h-3" /> Telefono</Label>
                  <Input placeholder="+57 300 1234567" value={familyFormData.phone} onChange={(e) => setFamilyFormData(prev => ({ ...prev, phone: e.target.value }))} className="bg-muted/30 border-border" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">Numero de Identificacion</Label>
                  <Input placeholder="CC-12345678" value={familyFormData.identificationNum} onChange={(e) => setFamilyFormData(prev => ({ ...prev, identificationNum: e.target.value }))} className="bg-muted/30 border-border" />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">Nivel de Riesgo</Label>
                  <select value={familyFormData.riskLevel} onChange={(e) => setFamilyFormData(prev => ({ ...prev, riskLevel: e.target.value }))} className="w-full h-9 rounded-md bg-muted/30 border border-border text-sm text-foreground px-3">
                    <option value="bajo">Bajo</option><option value="medio">Medio</option><option value="alto">Alto</option><option value="critico">Critico</option>
                  </select>
                </div>
              </div>
              <div className="space-y-2">
                <Label className="text-xs text-muted-foreground">Notas</Label>
                <Textarea placeholder="Observaciones adicionales..." value={familyFormData.notes} onChange={(e) => setFamilyFormData(prev => ({ ...prev, notes: e.target.value }))} className="bg-muted/30 border-border min-h-[60px]" />
              </div>
            </div>
            <DialogFooter>
              <Button variant="ghost" onClick={() => { setShowCreateFamilyDialog(false); resetFamilyForm(); }} className="text-muted-foreground">Cancelar</Button>
              <Button onClick={handleCreateFamilyMember} disabled={!familyFormData.fullName || !familyFormData.relationship} className="bg-primary hover:bg-primary/90 text-white gap-2">
                <Save className="w-4 h-4" /> Crear Familiar
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Edit Family Member Dialog */}
        <Dialog open={showEditFamilyDialog} onOpenChange={setShowEditFamilyDialog}>
          <DialogContent className="max-w-lg bg-card border-border">
            <DialogHeader>
              <DialogTitle className="text-foreground">Editar Familiar</DialogTitle>
              <DialogDescription className="text-muted-foreground">Modificar informacion del familiar de <strong>{selectedExecutiveForFamily?.fullName}</strong></DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">Nombre Completo *</Label>
                  <Input value={familyFormData.fullName} onChange={(e) => setFamilyFormData(prev => ({ ...prev, fullName: e.target.value }))} className="bg-muted/30 border-border" />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">Relación *</Label>
                  <select value={familyFormData.relationship} onChange={(e) => setFamilyFormData(prev => ({ ...prev, relationship: e.target.value }))} className="w-full h-9 rounded-md bg-muted/30 border border-border text-sm text-foreground px-3">
                    {RELATIONSHIP_OPTIONS.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground flex items-center gap-1"><Mail className="w-3 h-3" /> Correo Electronico</Label>
                  <Input type="email" value={familyFormData.email} onChange={(e) => setFamilyFormData(prev => ({ ...prev, email: e.target.value }))} className="bg-muted/30 border-border" />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground flex items-center gap-1"><Phone className="w-3 h-3" /> Telefono</Label>
                  <Input value={familyFormData.phone} onChange={(e) => setFamilyFormData(prev => ({ ...prev, phone: e.target.value }))} className="bg-muted/30 border-border" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">Numero de Identificacion</Label>
                  <Input value={familyFormData.identificationNum} onChange={(e) => setFamilyFormData(prev => ({ ...prev, identificationNum: e.target.value }))} className="bg-muted/30 border-border" />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">Nivel de Riesgo</Label>
                  <select value={familyFormData.riskLevel} onChange={(e) => setFamilyFormData(prev => ({ ...prev, riskLevel: e.target.value }))} className="w-full h-9 rounded-md bg-muted/30 border border-border text-sm text-foreground px-3">
                    <option value="bajo">Bajo</option><option value="medio">Medio</option><option value="alto">Alto</option><option value="critico">Critico</option>
                  </select>
                </div>
              </div>
              <div className="space-y-2">
                <Label className="text-xs text-muted-foreground">Notas</Label>
                <Textarea value={familyFormData.notes} onChange={(e) => setFamilyFormData(prev => ({ ...prev, notes: e.target.value }))} className="bg-muted/30 border-border min-h-[60px]" />
              </div>
            </div>
            <DialogFooter>
              <Button variant="ghost" onClick={() => { setShowEditFamilyDialog(false); setSelectedFamilyMember(null); resetFamilyForm(); }} className="text-muted-foreground">Cancelar</Button>
              <Button onClick={handleUpdateFamilyMember} disabled={!familyFormData.fullName || !familyFormData.relationship} className="bg-primary hover:bg-primary/90 text-white gap-2">
                <Save className="w-4 h-4" /> Guardar Cambios
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Delete Family Member Dialog */}
        <Dialog open={showDeleteFamilyDialog} onOpenChange={setShowDeleteFamilyDialog}>
          <DialogContent className="max-w-md bg-card border-border">
            <DialogHeader>
              <DialogTitle className="text-foreground flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-500" /> Confirmar Eliminacion
              </DialogTitle>
              <DialogDescription className="text-muted-foreground">
                Esta accion no se puede deshacer. Se eliminara el familiar <strong>{selectedFamilyMember?.fullName}</strong> de <strong>{selectedExecutiveForFamily?.fullName}</strong>.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="ghost" onClick={() => { setShowDeleteFamilyDialog(false); setSelectedFamilyMember(null); }} className="text-muted-foreground">Cancelar</Button>
              <Button onClick={handleDeleteFamilyMember} className="bg-red-600 hover:bg-red-700 text-white gap-2">
                <Trash2 className="w-4 h-4" /> Eliminar
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </main>
    </div>
  );
}
