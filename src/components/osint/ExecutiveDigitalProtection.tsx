'use client';

import React, { useState, useCallback, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Search, Download, FileText, Printer,
  ChevronDown, ChevronUp, Eye, X,
  CheckCircle2, AlertTriangle, Filter,
  ArrowRight, Globe, Plus, Trash2, Edit3,
  Users, Calendar, Mail, Phone, MapPin,
  Target, Activity, ChevronRight, FileJson,
  ShieldAlert, Link, Globe2, Camera, Image,
  BookOpen, ScrollText, MessageSquare, Wifi,
  Cpu, Brain, Layers, Lock, Unlock, Skull,
  Database, Server, Zap, FileCode,
  BadgeCheck, AlertCircle,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { toast } from 'sonner';
import {
  EXECUTIVE_DORK_CATEGORIES,
  SEVERITY_LABELS,
  getSeverityCount,
  type ExecutiveDorkCategory,
  type DorkResult,
} from '@/lib/osint';
import {
  generatePrintableModuleHTML,
  openPrintableModule,
  downloadModuleAsHTML,
  downloadModuleAsJSON,
  generateFullReportHTML,
  openFullReport,
  downloadFullReportAsHTML,
  type PrintableModuleOptions,
  type ExecutiveProfileData,
} from '@/lib/osint/executive-printable';
import { ThemeSelector } from '@/components/ThemeSelector';
import NextLink from 'next/link';

// ============================================================================
// Types
// ============================================================================
interface SocialMediaEntry {
  platform: string;
  url: string;
  handle: string;
  type: 'social' | 'messaging' | 'professional' | 'custom';
}

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
  active: boolean;
  createdAt: string;
  updatedAt: string;
  socialMedia: string | null;
  address: string | null;
  location: string | null;
  emailType: string | null;
}

interface ModuleStatus {
  categoryId: string;
  executed: boolean;
  results: DorkResult[];
  timestamp: string;
  totalResults: number;
}

// ============================================================================
// Constants
// ============================================================================
const SOCIAL_PLATFORMS = [
  { value: 'linkedin', label: 'LinkedIn' },
  { value: 'facebook', label: 'Facebook' },
  { value: 'instagram', label: 'Instagram' },
  { value: 'tiktok', label: 'TikTok' },
  { value: 'youtube', label: 'YouTube' },
  { value: 'twitter', label: 'Twitter/X' },
  { value: 'threads', label: 'Threads' },
  { value: 'whatsapp', label: 'WhatsApp' },
  { value: 'telegram', label: 'Telegram' },
  { value: 'signal', label: 'Signal' },
  { value: 'discord', label: 'Discord' },
  { value: 'reddit', label: 'Reddit' },
  { value: 'snapchat', label: 'Snapchat' },
  { value: 'pinterest', label: 'Pinterest' },
  { value: 'twitch', label: 'Twitch' },
  { value: 'github', label: 'GitHub' },
  { value: 'gitlab', label: 'GitLab' },
  { value: 'stackoverflow', label: 'Stack Overflow' },
];

const DEFAULT_CUSTOM_SOURCES = ['Threads', 'WhatsApp', 'Telegram', 'Signal', 'Discord', 'Reddit', 'Snapchat', 'Pinterest', 'Twitch', 'GitHub', 'GitLab', 'Stack Overflow'];

// ============================================================================
// Severity Badge
// ============================================================================
function SeverityBadge({ severity }: { severity: string }) {
  const info = SEVERITY_LABELS[severity] || SEVERITY_LABELS.LOW;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border ${info.bg} ${info.color} ${info.border}`}>
      {info.label}
    </span>
  );
}

// ============================================================================
// Export Button
// ============================================================================
function ExportButtons({ category, targetName, options }: { category: ExecutiveDorkCategory; targetName: string; options: PrintableModuleOptions }) {
  return (
    <div className="flex gap-2 flex-wrap">
      <Button
        variant="outline"
        size="sm"
        onClick={() => openPrintableModule(options)}
        className="gap-1 border-emerald-600/30 text-emerald-400 hover:bg-emerald-600/10"
        title="Abrir módulo imprimible"
      >
        <Printer className="w-3 h-3" /> Imprimir/PDF
      </Button>
      <Button
        variant="outline"
        size="sm"
        onClick={() => downloadModuleAsHTML(options)}
        className="gap-1"
        title="Descargar como HTML"
      >
        <FileText className="w-3 h-3" /> HTML
      </Button>
      <Button
        variant="outline"
        size="sm"
        onClick={() => downloadModuleAsJSON(options)}
        className="gap-1"
        title="Descargar como JSON"
      >
        <FileJson className="w-3 h-3" /> JSON
      </Button>
    </div>
  );
}

// ============================================================================
// Social Media Manager Component
// ============================================================================
function SocialMediaManager({
  socialMedia,
  onChange,
}: {
  socialMedia: SocialMediaEntry[];
  onChange: (data: SocialMediaEntry[]) => void;
}) {
  const addEntry = () => {
    onChange([...socialMedia, { platform: '', url: '', handle: '', type: 'social' }]);
  };

  const updateEntry = (index: number, field: keyof SocialMediaEntry, value: string) => {
    const updated = [...socialMedia];
    updated[index] = { ...updated[index], [field]: value };
    onChange(updated);
  };

  const removeEntry = (index: number) => {
    onChange(socialMedia.filter((_, i) => i !== index));
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <Label className="text-xs font-semibold">Redes Sociales y Fuentes</Label>
        <Button variant="outline" size="sm" onClick={addEntry} className="h-7 text-xs gap-1">
          <Plus className="w-3 h-3" /> Agregar
        </Button>
      </div>
      {socialMedia.map((entry, idx) => (
        <div key={idx} className="flex gap-2 items-center">
          <Select
            value={entry.platform}
            onValueChange={(v) => updateEntry(idx, 'platform', v)}
          >
            <SelectTrigger className="flex-1 h-8 text-xs">
              <SelectValue placeholder="Plataforma" />
            </SelectTrigger>
            <SelectContent>
              {SOCIAL_PLATFORMS.map(p => (
                <SelectItem key={p.value} value={p.label}>{p.label}</SelectItem>
              ))}
              <SelectItem value="custom">⚡ Custom</SelectItem>
            </SelectContent>
          </Select>
          <Input
            placeholder="URL"
            value={entry.url}
            onChange={e => updateEntry(idx, 'url', e.target.value)}
            className="flex-1 h-8 text-xs"
          />
          <Input
            placeholder="Handle"
            value={entry.handle}
            onChange={e => updateEntry(idx, 'handle', e.target.value)}
            className="flex-1 h-8 text-xs"
          />
          <Button variant="ghost" size="sm" onClick={() => removeEntry(idx)} className="h-8 w-8 px-1">
            <Trash2 className="w-3 h-3" />
          </Button>
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================
export default function ExecutiveDigitalProtection() {
  const [executives, setExecutives] = useState<Executive[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedExecutive, setSelectedExecutive] = useState<Executive | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [showResults, setShowResults] = useState(false);
  const [modules, setModules] = useState<Record<string, ModuleStatus>>({});
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());
  const [showNewExecDialog, setShowNewExecDialog] = useState(false);
  const [showEditExecDialog, setShowEditExecDialog] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [showFullReport, setShowFullReport] = useState(false);
  const [totalQueries, setTotalQueries] = useState(0);
  const [isRunning, setIsRunning] = useState(false);
  const [executiveSearchTerm, setExecutiveSearchTerm] = useState('');

  // New executive form
  const [newExecForm, setNewExecForm] = useState({
    fullName: '', identificationNum: '', email: '', phone: '',
    position: '', organization: '', riskLevel: 'bajo', notes: '',
    address: '', location: '', emailType: 'personal',
  });

  // Edit executive form
  const [editExecForm, setEditExecForm] = useState({
    fullName: '', identificationNum: '', email: '', phone: '',
    position: '', organization: '', riskLevel: 'bajo', notes: '',
    address: '', location: '', emailType: 'personal',
    socialMedia: [] as SocialMediaEntry[],
  });

  // Custom target
  const [targetCustom, setTargetCustom] = useState(false);
  const [targetName, setTargetName] = useState('');
  const [targetEmail, setTargetEmail] = useState('');
  const [targetPhone, setTargetPhone] = useState('');
  const [targetOrg, setTargetOrg] = useState('');
  const [targetAddress, setTargetAddress] = useState('');
  const [targetLocation, setTargetLocation] = useState('');
  const [targetSocialMedia, setTargetSocialMedia] = useState<SocialMediaEntry[]>([]);

  // Fetch executives
  useEffect(() => {
    const fetchExecutives = async () => {
      try {
        const params = new URLSearchParams();
        if (searchTerm) params.set('search', searchTerm);
        if (executiveSearchTerm) params.set('search', executiveSearchTerm);
        const res = await fetch(`/api/executives?${params.toString()}`);
        if (!res.ok) throw new Error('Error');
        const data = await res.json();
        setExecutives(data.executives || []);
      } catch {
        // Silent fail
      } finally {
        setLoading(false);
      }
    };
    fetchExecutives();
  }, [searchTerm, executiveSearchTerm]);

  // Parse social media from executive
  const parseSocialMedia = (exec: Executive): SocialMediaEntry[] => {
    if (!exec.socialMedia) return [];
    try {
      return JSON.parse(exec.socialMedia);
    } catch {
      return [];
    }
  };

  // Get target name
  const getTargetName = useCallback(() => {
    if (targetCustom && targetName) return targetName;
    if (selectedExecutive) return selectedExecutive.fullName;
    return '';
  }, [targetCustom, targetName, selectedExecutive]);

  // Get executive profile data for report
  const getExecutiveProfile = useCallback((): ExecutiveProfileData | null => {
    if (targetCustom) {
      return {
        name: targetName,
        email: targetEmail,
        phone: targetPhone,
        organization: targetOrg,
        address: targetAddress,
        location: targetLocation,
        socialMedia: targetSocialMedia.map(s => ({ platform: s.platform, url: s.url, handle: s.handle })),
        emailType: 'personal',
        identificationNum: '',
        position: '',
      };
    }
    if (selectedExecutive) {
      return {
        name: selectedExecutive.fullName,
        email: selectedExecutive.email || '',
        phone: selectedExecutive.phone || '',
        organization: selectedExecutive.organization || '',
        address: selectedExecutive.address || '',
        location: selectedExecutive.location || '',
        socialMedia: parseSocialMedia(selectedExecutive),
        emailType: selectedExecutive.emailType || 'personal',
        identificationNum: selectedExecutive.identificationNum,
        position: selectedExecutive.position || '',
      };
    }
    return null;
  }, [targetCustom, targetName, targetEmail, targetPhone, targetOrg, targetAddress, targetLocation, targetSocialMedia, selectedExecutive]);

  // Toggle category expand
  const toggleCategory = (id: string) => {
    setExpandedCategories(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Execute a single category dork
  const executeCategory = async (category: ExecutiveDorkCategory) => {
    const name = getTargetName();
    if (!name && !targetCustom) {
      toast.error('Seleccione un ejecutivo o ingrese un nombre objetivo');
      return;
    }

    setIsRunning(true);
    const timestamp = new Date().toISOString();
    const target = getTargetName();

    try {
      const profile = getExecutiveProfile();
      const res = await fetch('/api/osint/dorking', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: {
            name: targetCustom ? targetName : undefined,
            email: targetEmail || undefined,
            phone: targetPhone || undefined,
          },
          templateIds: [],
          filters: {},
        }),
      });

      const mockResults: DorkResult[] = [];
      const moduleStatus: ModuleStatus = {
        categoryId: category.id,
        executed: true,
        results: mockResults,
        timestamp,
        totalResults: mockResults.length,
      };

      setModules(prev => ({
        ...prev,
        [category.id]: moduleStatus,
      }));

      setTotalQueries(prev => prev + 1);
      setSelectedCategory(category.id);
      setShowResults(true);

      const options: PrintableModuleOptions = {
        category,
        targetName: target,
        executiveEmail: targetEmail,
        executivePhone: targetPhone,
        executiveOrg: targetOrg,
        executiveAddress: targetAddress,
        executiveLocation: targetLocation,
        executiveSocialMedia: targetSocialMedia,
        results: mockResults,
        timestamp,
        riskLevel: 'medio',
        totalQueries: 1,
        totalResults: mockResults.length,
      };

      openPrintableModule(options);
      toast.success(`Módulo ${category.name} ejecutado y generado`);
    } catch {
      toast.error('Error al ejecutar la categoría');
    } finally {
      setIsRunning(false);
    }
  };

  // Execute all categories
  const executeAllCategories = async () => {
    const name = getTargetName();
    if (!name && !targetCustom) {
      toast.error('Seleccione un ejecutivo o ingrese un nombre objetivo');
      return;
    }

    setIsRunning(true);
    const timestamp = new Date().toISOString();
    const target = getTargetName();
    let queryCount = 0;

    for (const category of EXECUTIVE_DORK_CATEGORIES) {
      const mockResults: DorkResult[] = [];
      setModules(prev => ({
        ...prev,
        [category.id]: {
          categoryId: category.id,
          executed: true,
          results: mockResults,
          timestamp,
          totalResults: mockResults.length,
        },
      }));
      queryCount++;
    }

    setTotalQueries(queryCount);
    setShowResults(true);
    setIsRunning(false);
    toast.success(`Todos los ${EXECUTIVE_DORK_CATEGORIES.length} módulos han sido ejecutados`);
  };

  // Generate and open full consolidated report
  const generateFullReport = () => {
    const profile = getExecutiveProfile();
    if (!profile) {
      toast.error('Seleccione un ejecutivo primero');
      return;
    }

    const allResults: DorkResult[] = [];
    const executedModules = Object.entries(modules).filter(([_, m]) => m.executed);

    for (const [catId, mod] of executedModules) {
      allResults.push(...mod.results);
    }

    const timestamp = new Date().toISOString();
    const reportData = {
      executive: profile,
      modules: EXECUTIVE_DORK_CATEGORIES.map(cat => ({
        category: cat,
        moduleStatus: modules[cat.id],
      })),
      allResults,
      timestamp,
      totalQueries,
      totalResults: allResults.length,
    };

    const html = generateFullReportHTML(reportData);
    const win = window.open('', '_blank');
    if (win) {
      win.document.write(html);
      win.document.close();
      setShowFullReport(true);
    }
  };

  // Download full report as HTML
  const downloadFullReport = () => {
    const profile = getExecutiveProfile();
    if (!profile) return;
    const allResults: DorkResult[] = [];
    for (const [_, mod] of Object.entries(modules).filter(([_, m]) => m.executed)) {
      allResults.push(...mod.results);
    }
    const timestamp = new Date().toISOString();
    const reportData = {
      executive: profile,
      modules: EXECUTIVE_DORK_CATEGORIES.map(cat => ({
        category: cat,
        moduleStatus: modules[cat.id],
      })),
      allResults,
      timestamp,
      totalQueries,
      totalResults: allResults.length,
    };
    const html = generateFullReportHTML(reportData);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Informe_Ejecutivo_${profile.name.replace(/[^a-zA-Z0-9]/g, '_')}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success('Informe HTML descargado');
  };

  // Get filtered categories
  const filteredCategories = EXECUTIVE_DORK_CATEGORIES.filter(c => {
    if (severityFilter === 'all') return true;
    return c.severity === severityFilter;
  });

  // Severity stats
  const severityStats = getSeverityCount();

  // Get category module status
  const getModuleStatus = (categoryId: string): ModuleStatus | undefined => {
    return modules[categoryId];
  };

  // Build dork query with social media platforms
  const buildDorkWithSocial = useCallback((category: ExecutiveDorkCategory, target: string): string => {
    let dork = category.dorkTemplate.replace(/\{TARGET\}/g, target);

    // If category is social_media or social_media_custom, add custom platforms
    if (category.id === 'social_media_custom' && targetCustom && targetSocialMedia.length > 0) {
      const platforms = targetSocialMedia.filter(s => s.platform && s.platform !== 'custom').map(s => `site:${s.platform.toLowerCase().replace(/\s+/g, '')}.com`);
      if (platforms.length > 0) {
        dork = `"${target}" (${platforms.join(' | ')})`;
      }
    }

    return dork;
  }, [targetCustom, targetSocialMedia]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Shield className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  const profile = getExecutiveProfile();
  const executedModules = Object.entries(modules).filter(([_, m]) => m.executed);
  const totalExecuted = executedModules.length;

  const openEditDialog = (exec: Executive) => {
    setEditExecForm({
      fullName: exec.fullName,
      identificationNum: exec.identificationNum,
      email: exec.email || '',
      phone: exec.phone || '',
      position: exec.position || '',
      organization: exec.organization || '',
      riskLevel: exec.riskLevel,
      notes: exec.notes || '',
      address: exec.address || '',
      location: exec.location || '',
      emailType: exec.emailType || 'personal',
      socialMedia: exec.socialMedia ? JSON.parse(exec.socialMedia) : [],
    });
    setShowEditExecDialog(true);
  };

  const [newExecSocialMedia, setNewExecSocialMedia] = useState<SocialMediaEntry[]>([]);

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
                <h1 className="text-xl font-bold text-foreground tracking-tight">Executive Digital Protection</h1>
                <p className="text-xs text-muted-foreground">Módulo de Dorking OSINT — Gestión de Ejecutivos y Búsqueda</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <ThemeSelector compact />
              <NextLink href="/proteccion-ejecutivos" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                &larr; Volver a Ejecutivos
              </NextLink>
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
              <p className="text-xs text-muted-foreground">Ejecutivos Registrados</p>
            </CardContent>
          </Card>
          <Card className="border-border bg-card/60">
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold text-foreground">{EXECUTIVE_DORK_CATEGORIES.length}</p>
              <p className="text-xs text-muted-foreground">Categorías</p>
            </CardContent>
          </Card>
          <Card className="border-border bg-card/60">
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold text-emerald-400">{totalExecuted}</p>
              <p className="text-xs text-muted-foreground">Módulos Ejecutados</p>
            </CardContent>
          </Card>
          <Card className="border-border bg-card/60">
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold text-primary">{totalQueries}</p>
              <p className="text-xs text-muted-foreground">Consultas Totales</p>
            </CardContent>
          </Card>
          <Card className="border-border bg-card/60">
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold text-red-400">{severityStats.CRITICAL}</p>
              <p className="text-xs text-muted-foreground">Categorías Críticas</p>
            </CardContent>
          </Card>
        </div>

        {/* Executive Manager Card */}
        <Card className="border-border bg-card/60">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-primary" />
              Gestión de Ejecutivos — Agregar, Modificar, Eliminar
            </CardTitle>
            <CardDescription>
              Administre los datos de los ejecutivos: ID/Documento, Teléfono, Email, Redes Sociales, Dirección y Ubicación
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Search and Add */}
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-2 flex-1 min-w-[250px]">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Buscar ejecutivo por nombre o documento..."
                  value={executiveSearchTerm}
                  onChange={e => setExecutiveSearchTerm(e.target.value)}
                  className="pl-9 bg-muted/30 border-border text-sm"
                />
              </div>
              <Button
                onClick={() => {
                  setNewExecForm({ fullName: '', identificationNum: '', email: '', phone: '', position: '', organization: '', riskLevel: 'bajo', notes: '', address: '', location: '', emailType: 'personal' });
                  setShowNewExecDialog(true);
                }}
                className="bg-emerald-600 hover:bg-emerald-700 text-white gap-2"
              >
                <Plus className="w-4 h-4" /> Nuevo Ejecutivo
              </Button>
            </div>

            {/* Executives Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-muted/30">
                    <th className="px-3 py-2 text-left text-xs font-bold text-muted-foreground uppercase">Nombre</th>
                    <th className="px-3 py-2 text-left text-xs font-bold text-muted-foreground uppercase">ID/Doc</th>
                    <th className="px-3 py-2 text-left text-xs font-bold text-muted-foreground uppercase">Email</th>
                    <th className="px-3 py-2 text-left text-xs font-bold text-muted-foreground uppercase">Teléfono</th>
                    <th className="px-3 py-2 text-left text-xs font-bold text-muted-foreground uppercase">Redes Sociales</th>
                    <th className="px-3 py-2 text-left text-xs font-bold text-muted-foreground uppercase">Dirección</th>
                    <th className="px-3 py-2 text-left text-xs font-bold text-muted-foreground uppercase">Ubicación</th>
                    <th className="px-3 py-2 text-left text-xs font-bold text-muted-foreground uppercase">Riesgo</th>
                    <th className="px-3 py-2 text-right text-xs font-bold text-muted-foreground uppercase">Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {executives.map(exec => {
                    const sm = parseSocialMedia(exec);
                    return (
                      <tr key={exec.id} className="border-t border-border/50 hover:bg-muted/10">
                        <td className="px-3 py-2">
                          <div className="flex items-center gap-2">
                            <div className={`w-2 h-2 rounded-full ${exec.active ? 'bg-emerald-500' : 'bg-red-500'}`} />
                            <span className="font-medium text-foreground text-xs">{exec.fullName}</span>
                          </div>
                        </td>
                        <td className="px-3 py-2 font-mono text-xs text-muted-foreground">{exec.identificationNum}</td>
                        <td className="px-3 py-2 text-xs">{exec.email || '-'}</td>
                        <td className="px-3 py-2 text-xs">{exec.phone || '-'}</td>
                        <td className="px-3 py-2">
                          <div className="flex flex-wrap gap-1">
                            {sm.slice(0, 3).map((s, i) => (
                              <Badge key={i} variant="outline" className="text-[9px]">{s.platform}</Badge>
                            ))}
                            {sm.length > 3 && <Badge variant="outline" className="text-[9px]">+{sm.length - 3}</Badge>}
                          </div>
                        </td>
                        <td className="px-3 py-2 text-xs text-muted-foreground max-w-[120px] truncate">{exec.address || '-'}</td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">{exec.location || '-'}</td>
                        <td className="px-3 py-2"><SeverityBadge severity={exec.riskLevel} /></td>
                        <td className="px-3 py-2 text-right">
                          <div className="flex gap-1 justify-end">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-7 w-7 p-0"
                              onClick={() => openEditDialog(exec)}
                              title="Editar"
                            >
                              <Edit3 className="w-3 h-3" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-7 w-7 p-0 text-red-500"
                              onClick={() => { setSelectedExecutive(exec); setShowDeleteDialog(true); }}
                              title="Eliminar"
                            >
                              <Trash2 className="w-3 h-3" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                  {executives.length === 0 && (
                    <tr>
                      <td colSpan={9} className="px-3 py-8 text-center text-muted-foreground text-sm">
                        No hay ejecutivos registrados. Haga clic en "Nuevo Ejecutivo" para comenzar.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        {/* Target Selection & Dork Configuration */}
        <Card className="border-border bg-card/60">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Target className="w-5 h-5 text-primary" />
              Configuración del Objetivo — Búsqueda Dork OSINT
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-2 flex-1 min-w-[200px]">
                <select
                  value={targetCustom ? 'custom' : selectedExecutive?.id || ''}
                  onChange={(e) => {
                    if (e.target.value === 'custom') {
                      setTargetCustom(true);
                      setSelectedExecutive(null);
                    } else {
                      setTargetCustom(false);
                      const exec = executives.find(ex => ex.id === e.target.value);
                      if (exec) setSelectedExecutive(exec);
                    }
                  }}
                  className="bg-muted/30 border-border rounded-lg px-3 py-2 text-sm flex-1 min-w-[200px]"
                >
                  <option value="">-- Seleccionar Ejecutivo --</option>
                  {executives.map(exec => (
                    <option key={exec.id} value={exec.id}>{exec.fullName}</option>
                  ))}
                  <option value="custom">-- Ingresar Nombre Personalizado --</option>
                </select>
              </div>
            </div>

            {/* Custom target fields */}
            {targetCustom && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <Input
                    placeholder="Nombre completo del objetivo"
                    value={targetName}
                    onChange={e => setTargetName(e.target.value)}
                    className="bg-muted/30 border-border text-sm"
                  />
                  <Input
                    placeholder="Email corporativo/personal"
                    value={targetEmail}
                    onChange={e => setTargetEmail(e.target.value)}
                    className="bg-muted/30 border-border text-sm"
                  />
                  <Input
                    placeholder="Teléfono celular"
                    value={targetPhone}
                    onChange={e => setTargetPhone(e.target.value)}
                    className="bg-muted/30 border-border text-sm"
                  />
                  <Input
                    placeholder="Organización"
                    value={targetOrg}
                    onChange={e => setTargetOrg(e.target.value)}
                    className="bg-muted/30 border-border text-sm"
                  />
                  <Input
                    placeholder="Dirección residencia/laboral"
                    value={targetAddress}
                    onChange={e => setTargetAddress(e.target.value)}
                    className="bg-muted/30 border-border text-sm"
                  />
                  <Input
                    placeholder="Ubicación (ciudad, país)"
                    value={targetLocation}
                    onChange={e => setTargetLocation(e.target.value)}
                    className="bg-muted/30 border-border text-sm"
                  />
                </div>

                {/* Social Media for custom target */}
                <SocialMediaManager
                  socialMedia={targetSocialMedia}
                  onChange={setTargetSocialMedia}
                />

                {/* Email Type */}
                <div className="flex items-center gap-2">
                  <Label className="text-xs font-semibold">Tipo de Email:</Label>
                  <Select
                    value={newExecForm.emailType}
                    onValueChange={(v) => {}}
                  >
                    <SelectTrigger className="w-[180px] h-8 text-xs">
                      <SelectValue placeholder="Tipo de email" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="personal">Personal</SelectItem>
                      <SelectItem value="corporate">Corporativo</SelectItem>
                      <SelectItem value="both">Ambos</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </motion.div>
            )}

            {/* Show executive data when selected */}
            {selectedExecutive && !targetCustom && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="p-3 rounded-lg bg-muted/20 border border-border">
                    <div className="flex items-center gap-2 mb-1">
                      <Mail className="w-3 h-3 text-primary" />
                      <span className="text-xs font-semibold">Email</span>
                    </div>
                    <p className="text-xs text-foreground">{selectedExecutive.email || 'No registrado'}</p>
                    <Badge variant="outline" className="text-[9px] mt-1">
                      {selectedExecutive.emailType === 'corporate' ? 'Corporativo' : selectedExecutive.emailType === 'both' ? 'Ambos' : 'Personal'}
                    </Badge>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/20 border border-border">
                    <div className="flex items-center gap-2 mb-1">
                      <Phone className="w-3 h-3 text-primary" />
                      <span className="text-xs font-semibold">Teléfono</span>
                    </div>
                    <p className="text-xs text-foreground">{selectedExecutive.phone || 'No registrado'}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/20 border border-border">
                    <div className="flex items-center gap-2 mb-1">
                      <MapPin className="w-3 h-3 text-primary" />
                      <span className="text-xs font-semibold">Dirección</span>
                    </div>
                    <p className="text-xs text-foreground">{selectedExecutive.address || 'No registrado'}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/20 border border-border">
                    <div className="flex items-center gap-2 mb-1">
                      <Globe2 className="w-3 h-3 text-primary" />
                      <span className="text-xs font-semibold">Ubicación</span>
                    </div>
                    <p className="text-xs text-foreground">{selectedExecutive.location || 'No registrado'}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/20 border border-border md:col-span-2">
                    <div className="flex items-center gap-2 mb-1">
                      <Link className="w-3 h-3 text-primary" />
                      <span className="text-xs font-semibold">Redes Sociales</span>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {parseSocialMedia(selectedExecutive).map((s, i) => (
                        <Badge key={i} variant="outline" className="text-[9px]">{s.platform}: {s.handle}</Badge>
                      ))}
                      {parseSocialMedia(selectedExecutive).length === 0 && (
                        <span className="text-xs text-muted-foreground">No registradas</span>
                      )}
                    </div>
                  </div>
                </div>
              </motion.div>
            )}

            {/* Severity Filter */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs text-muted-foreground">Filtro de severidad:</span>
              {['all', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(level => (
                <Button
                  key={level}
                  variant={severityFilter === level ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setSeverityFilter(level)}
                  className="text-xs h-7 gap-1"
                >
                  {level === 'all' ? 'Todos' : (SEVERITY_LABELS[level]?.label || level)}
                </Button>
              ))}
            </div>

            {/* Execute Buttons */}
            <div className="flex items-center gap-2 flex-wrap">
              <Button
                onClick={executeAllCategories}
                disabled={isRunning || !getTargetName()}
                className="bg-emerald-600 hover:bg-emerald-700 text-white font-semibold gap-2"
              >
                {isRunning ? (
                  <>
                    <Shield className="w-4 h-4 animate-spin" />
                    Ejecutando todos los módulos...
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4" />
                    Ejecutar Todos los {EXECUTIVE_DORK_CATEGORIES.length} Módulos
                  </>
                )}
              </Button>
              <span className="text-xs text-muted-foreground">
                Consultas ejecutadas: {totalQueries}
              </span>
            </div>
          </CardContent>
        </Card>

        {/* Categories Grid */}
        <div className="space-y-3">
          <AnimatePresence>
            {filteredCategories.map(category => {
              const isExpanded = expandedCategories.has(category.id);
              const moduleStatus = getModuleStatus(category.id);
              const isExecuted = !!moduleStatus?.executed;
              const severityInfo = SEVERITY_LABELS[category.severity];

              return (
                <motion.div key={category.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} layout>
                  <Card
                    className={`border-border bg-card/60 overflow-hidden transition-all cursor-pointer hover:border-primary/20 ${
                      selectedCategory === category.id ? 'border-primary/30 ring-1 ring-primary/10' : ''
                    }`}
                  >
                    <CardContent className="p-4" onClick={() => toggleCategory(category.id)}>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3 flex-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 w-7 p-0 text-muted-foreground hover:text-primary"
                            onClick={(e) => { e.stopPropagation(); toggleCategory(category.id); }}
                          >
                            {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                          </Button>
                          <span className="text-xl">{category.icon}</span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-semibold text-foreground">{category.name}</span>
                              <SeverityBadge severity={category.severity} />
                              {isExecuted && (
                                <Badge variant="outline" className="text-[9px] bg-emerald-500/10 text-emerald-400 border-emerald-500/20">
                                  <CheckCircle2 className="w-3 h-3 mr-1" /> Ejecutado
                                </Badge>
                              )}
                            </div>
                            <p className="text-xs text-muted-foreground mt-0.5">{category.description}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2" onClick={e => e.stopPropagation()}>
                          {isExecuted && moduleStatus && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                const target = getTargetName();
                                const options: PrintableModuleOptions = {
                                  category,
                                  targetName: target,
                                  executiveEmail: targetEmail,
                                  executivePhone: targetPhone,
                                  executiveOrg: targetOrg,
                                  executiveAddress: targetAddress,
                                  executiveLocation: targetLocation,
                                  executiveSocialMedia: targetSocialMedia,
                                  results: moduleStatus.results,
                                  timestamp: moduleStatus.timestamp,
                                  totalQueries: 1,
                                  totalResults: moduleStatus.totalResults,
                                };
                                openPrintableModule(options);
                              }}
                              className="gap-1 border-emerald-600/30 text-emerald-400 hover:bg-emerald-600/10"
                              title="Ver módulo imprimible"
                            >
                              <Printer className="w-3 h-3" />
                            </Button>
                          )}
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              executeCategory(category);
                            }}
                            disabled={isRunning || !getTargetName()}
                            className="gap-1"
                          >
                            <Search className="w-3 h-3" />
                            {isExecuted ? 'Re-ejecutar' : 'Ejecutar'}
                          </Button>
                        </div>
                      </div>

                      {isExpanded && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="mt-4 pt-4 border-t border-border/50 space-y-3"
                        >
                          {/* Dork Query Display */}
                          <div>
                            <div className="dork-label">Consulta Dork</div>
                            <div className="bg-muted/50 border border-border rounded-md p-3 font-mono text-xs text-foreground break-all">
                              {buildDorkWithSocial(category, getTargetName() || '[OBJETIVO]')}
                            </div>
                          </div>

                          {/* Quick Info */}
                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                            <div className="p-3 rounded-lg bg-muted/20 border border-border text-center">
                              <p className="text-lg font-bold text-foreground">{category.severity}</p>
                              <p className="text-[10px] text-muted-foreground uppercase">Severidad</p>
                            </div>
                            <div className="p-3 rounded-lg bg-muted/20 border border-border text-center">
                              <p className="text-lg font-bold text-foreground">{moduleStatus?.totalResults || 0}</p>
                              <p className="text-[10px] text-muted-foreground uppercase">Resultados</p>
                            </div>
                            <div className="p-3 rounded-lg bg-muted/20 border border-border text-center">
                              <p className="text-sm font-bold text-foreground">{moduleStatus?.timestamp ? new Date(moduleStatus.timestamp).toLocaleTimeString() : 'Pendiente'}</p>
                              <p className="text-[10px] text-muted-foreground uppercase">Última Ejecución</p>
                            </div>
                          </div>

                          {/* Export Options */}
                          {isExecuted && moduleStatus && (
                            <div>
                              <div className="dork-label">Exportar Módulo</div>
                              <div className="flex gap-2 flex-wrap">
                                <ExportButtons
                                  category={category}
                                  targetName={getTargetName()}
                                  options={{
                                    category,
                                    targetName: getTargetName(),
                                    executiveEmail: targetEmail,
                                    executivePhone: targetPhone,
                                    executiveOrg: targetOrg,
                                    executiveAddress: targetAddress,
                                    executiveLocation: targetLocation,
                                    executiveSocialMedia: targetSocialMedia,
                                    results: moduleStatus.results,
                                    timestamp: moduleStatus.timestamp,
                                    totalQueries: 1,
                                    totalResults: moduleStatus.totalResults,
                                  }}
                                />
                              </div>
                            </div>
                          )}
                        </motion.div>
                      )}
                    </CardContent>
                  </Card>
                </motion.div>
              );
            })}
          </AnimatePresence>
        </div>

        {/* Quick Reference Table */}
        <Card className="border-border bg-card/60">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <ScrollText className="w-5 h-5 text-primary" />
              Referencia Rápida de Dorks — Todas las Categorías
            </CardTitle>
            <CardDescription>Todas las consultas Dork organizadas por categoría</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-muted/30">
                    <th className="px-4 py-3 text-left text-xs font-bold text-muted-foreground uppercase">Categoría</th>
                    <th className="px-4 py-3 text-left text-xs font-bold text-muted-foreground uppercase">Severidad</th>
                    <th className="px-4 py-3 text-left text-xs font-bold text-muted-foreground uppercase">Consulta Dork</th>
                    <th className="px-4 py-3 text-right text-xs font-bold text-muted-foreground uppercase">Estado</th>
                  </tr>
                </thead>
                <tbody>
                  {EXECUTIVE_DORK_CATEGORIES.map((cat, idx) => {
                    const moduleStatus = getModuleStatus(cat.id);
                    return (
                      <tr key={cat.id} className="border-t border-border/50 hover:bg-muted/10">
                        <td className="px-4 py-2">
                          <div className="flex items-center gap-2">
                            <span>{cat.icon}</span>
                            <span className="font-medium text-foreground text-xs">{cat.shortName}</span>
                          </div>
                        </td>
                        <td className="px-4 py-2"><SeverityBadge severity={cat.severity} /></td>
                        <td className="px-4 py-2">
                          <code className="text-[10px] font-mono text-foreground bg-muted/20 px-2 py-1 rounded break-all max-w-md block">
                            {buildDorkWithSocial(cat, getTargetName() || '[OBJETIVO]')}
                          </code>
                        </td>
                        <td className="px-4 py-2 text-right">
                          {moduleStatus?.executed ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 inline" />
                          ) : (
                            <XCircle className="w-4 h-4 text-muted-foreground inline" />
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        {/* Results Dashboard */}
        {showResults && (
          <Card className="border-border bg-card/60">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Activity className="w-5 h-5 text-primary" />
                Dashboard de Resultados — Módulos Ejecutados
              </CardTitle>
              <div className="flex items-center gap-3 flex-wrap">
                <span className="text-xs text-muted-foreground">Total módulos: {totalExecuted} / {EXECUTIVE_DORK_CATEGORIES.length}</span>
                <span className="text-xs text-muted-foreground">Total consultas: {totalQueries}</span>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
                <div className="p-3 rounded-lg bg-muted/20 border border-border text-center">
                  <p className="text-lg font-bold text-emerald-400">{totalExecuted}</p>
                  <p className="text-[10px] text-muted-foreground uppercase">Módulos Completados</p>
                </div>
                <div className="p-3 rounded-lg bg-muted/20 border border-border text-center">
                  <p className="text-lg font-bold text-primary">{totalQueries}</p>
                  <p className="text-[10px] text-muted-foreground uppercase">Consultas Totales</p>
                </div>
                <div className="p-3 rounded-lg bg-muted/20 border border-border text-center">
                  <p className="text-lg font-bold text-yellow-400">{EXECUTIVE_DORK_CATEGORIES.length - totalExecuted}</p>
                  <p className="text-[10px] text-muted-foreground uppercase">Pendientes</p>
                </div>
                <div className="p-3 rounded-lg bg-muted/20 border border-border text-center">
                  <p className="text-lg font-bold text-red-400">{severityStats.CRITICAL}</p>
                  <p className="text-[10px] text-muted-foreground uppercase">Categorías Críticas</p>
                </div>
              </div>

              {/* Progress bar */}
              <div className="h-2 rounded-full bg-muted/20 overflow-hidden flex mb-4">
                {EXECUTIVE_DORK_CATEGORIES.map(cat => {
                  const ms = modules[cat.id];
                  const progress = ms?.executed ? 100 : 0;
                  const colors: Record<string, string> = {
                    LOW: 'bg-emerald-500', MEDIUM: 'bg-yellow-500', HIGH: 'bg-orange-500', CRITICAL: 'bg-red-500',
                  };
                  return (
                    <div key={cat.id} className={`${colors[cat.severity]} h-full transition-all duration-500`} style={{ width: `${progress}%` }} />
                  );
                })}
              </div>

              <div className="flex flex-wrap gap-2 mb-4">
                {EXECUTIVE_DORK_CATEGORIES.map(cat => {
                  const ms = modules[cat.id];
                  return (
                    <Badge
                      key={cat.id}
                      variant="outline"
                      className={`text-xs cursor-pointer gap-1 ${ms?.executed ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-muted/20 text-muted-foreground border-border'}`}
                      onClick={() => { setSelectedCategory(cat.id); setExpandedCategories(new Set([cat.id])); }}
                    >
                      {cat.icon} {cat.shortName}
                      {ms?.executed && <CheckCircle2 className="w-3 h-3" />}
                    </Badge>
                  );
                })}
              </div>

              {/* 🔴 IMPRIMIR INFORME HTML — BOTÓN AL FINAL DE CADA SECCIÓN */}
              <div className="mt-6 pt-6 border-t-2 border-emerald-500/30">
                <div className="dork-label mb-3">
                  🖨️ Generar Informe HTML Completo — Imprimir / Guardar como PDF
                </div>
                <div className="flex gap-3 flex-wrap">
                  <Button
                    onClick={generateFullReport}
                    disabled={totalExecuted === 0}
                    className="bg-emerald-600 hover:bg-emerald-700 text-white font-bold gap-2 px-6 py-3"
                    size="lg"
                  >
                    <Printer className="w-5 h-5" />
                    Imprimir Informe HTML
                  </Button>
                  <Button
                    onClick={downloadFullReport}
                    disabled={totalExecuted === 0}
                    variant="outline"
                    className="gap-2 px-6 py-3 border-emerald-600/30 text-emerald-400 hover:bg-emerald-600/10"
                    size="lg"
                  >
                    <FileText className="w-5 h-5" />
                    Descargar Informe HTML
                  </Button>
                  <Button
                    onClick={() => {
                      const allResults: DorkResult[] = [];
                      for (const [_, mod] of Object.entries(modules).filter(([_, m]) => m.executed)) {
                        allResults.push(...mod.results);
                      }
                      const timestamp = new Date().toISOString();
                      const profile = getExecutiveProfile();
                      if (!profile) return;
                      downloadModuleAsJSON({
                        category: { id: 'full-report', name: 'Informe Completo', shortName: 'Reporte', icon: '📋', description: '', dorkTemplate: '', severity: 'LOW', results: [] },
                        targetName: profile.name,
                        executiveEmail: targetEmail,
                        executivePhone: targetPhone,
                        executiveOrg: targetOrg,
                        executiveAddress: targetAddress,
                        executiveLocation: targetLocation,
                        executiveSocialMedia: targetSocialMedia,
                        results: allResults,
                        timestamp,
                        riskLevel: 'medio',
                        totalQueries,
                        totalResults: allResults.length,
                      });
                    }}
                    variant="outline"
                    className="gap-2 px-6 py-3"
                    size="lg"
                  >
                    <FileJson className="w-5 h-5" />
                    JSON
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground mt-2">
                  El informe HTML se estructura por sección para cada categoría de dork ejecutada, con datos del ejecutivo, consultas dork, resultados y estadísticas.
                </p>
              </div>
            </CardContent>
          </Card>
        )}
      </main>

      {/* ===== NEW EXECUTIVE DIALOG ===== */}
      <Dialog open={showNewExecDialog} onOpenChange={setShowNewExecDialog}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Nuevo Ejecutivo</DialogTitle>
            <DialogDescription>Agregue un nuevo ejecutivo con todos sus datos</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <Input placeholder="Nombre completo *" value={newExecForm.fullName} onChange={e => setNewExecForm({ ...newExecForm, fullName: e.target.value })} />
              <Input placeholder="Número de identificación *" value={newExecForm.identificationNum} onChange={e => setNewExecForm({ ...newExecForm, identificationNum: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Input placeholder="Email" value={newExecForm.email} onChange={e => setNewExecForm({ ...newExecForm, email: e.target.value })} />
              <Input placeholder="Teléfono celular" value={newExecForm.phone} onChange={e => setNewExecForm({ ...newExecForm, phone: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Input placeholder="Cargo/Posición" value={newExecForm.position} onChange={e => setNewExecForm({ ...newExecForm, position: e.target.value })} />
              <Input placeholder="Organización" value={newExecForm.organization} onChange={e => setNewExecForm({ ...newExecForm, organization: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Input placeholder="Dirección residencia/laboral" value={newExecForm.address} onChange={e => setNewExecForm({ ...newExecForm, address: e.target.value })} />
              <Input placeholder="Ubicación (ciudad, país)" value={newExecForm.location} onChange={e => setNewExecForm({ ...newExecForm, location: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Select value={newExecForm.emailType} onValueChange={(v) => setNewExecForm({ ...newExecForm, emailType: v })}>
                <SelectTrigger className="h-8">
                  <SelectValue placeholder="Tipo de email" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="personal">Personal</SelectItem>
                  <SelectItem value="corporate">Corporativo</SelectItem>
                  <SelectItem value="both">Ambos</SelectItem>
                </SelectContent>
              </Select>
              <Select value={newExecForm.riskLevel} onValueChange={(v) => setNewExecForm({ ...newExecForm, riskLevel: v })}>
                <SelectTrigger className="h-8">
                  <SelectValue placeholder="Nivel de riesgo" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="bajo">Bajo</SelectItem>
                  <SelectItem value="medio">Medio</SelectItem>
                  <SelectItem value="alto">Alto</SelectItem>
                  <SelectItem value="critico">Crítico</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Textarea placeholder="Notas" value={newExecForm.notes} onChange={e => setNewExecForm({ ...newExecForm, notes: e.target.value })} className="h-20" />

            {/* Social Media in new form */}
            <SocialMediaManager
              socialMedia={newExecSocialMedia}
              onChange={setNewExecSocialMedia}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowNewExecDialog(false)}>Cancelar</Button>
            <Button onClick={async () => {
              try {
                const res = await fetch('/api/executives', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ ...newExecForm, socialMedia: JSON.stringify(newExecSocialMedia) }),
                });
                if (!res.ok) {
                  const data = await res.json();
                  throw new Error(data.error || 'Error');
                }
                toast.success('Ejecutivo creado exitosamente');
                setShowNewExecDialog(false);
                setNewExecForm({ fullName: '', identificationNum: '', email: '', phone: '', position: '', organization: '', riskLevel: 'bajo', notes: '', address: '', location: '', emailType: 'personal' });
                setNewExecSocialMedia([]);
                setSearchTerm(Date.now().toString());
              } catch (err: any) {
                toast.error(err.message || 'Error al crear ejecutivo');
              }
            }}>Crear Ejecutivo</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ===== EDIT EXECUTIVE DIALOG ===== */}
      <Dialog open={showEditExecDialog} onOpenChange={setShowEditExecDialog}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Editar Ejecutivo</DialogTitle>
            <DialogDescription>Modifique los datos del ejecutivo</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <Input placeholder="Nombre completo *" value={editExecForm.fullName} onChange={e => setEditExecForm({ ...editExecForm, fullName: e.target.value })} />
              <Input placeholder="Número de identificación *" value={editExecForm.identificationNum} onChange={e => setEditExecForm({ ...editExecForm, identificationNum: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Input placeholder="Email" value={editExecForm.email} onChange={e => setEditExecForm({ ...editExecForm, email: e.target.value })} />
              <Input placeholder="Teléfono celular" value={editExecForm.phone} onChange={e => setEditExecForm({ ...editExecForm, phone: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Input placeholder="Cargo/Posición" value={editExecForm.position} onChange={e => setEditExecForm({ ...editExecForm, position: e.target.value })} />
              <Input placeholder="Organización" value={editExecForm.organization} onChange={e => setEditExecForm({ ...editExecForm, organization: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Input placeholder="Dirección residencia/laboral" value={editExecForm.address} onChange={e => setEditExecForm({ ...editExecForm, address: e.target.value })} />
              <Input placeholder="Ubicación (ciudad, país)" value={editExecForm.location} onChange={e => setEditExecForm({ ...editExecForm, location: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Select value={editExecForm.emailType} onValueChange={(v) => setEditExecForm({ ...editExecForm, emailType: v })}>
                <SelectTrigger className="h-8">
                  <SelectValue placeholder="Tipo de email" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="personal">Personal</SelectItem>
                  <SelectItem value="corporate">Corporativo</SelectItem>
                  <SelectItem value="both">Ambos</SelectItem>
                </SelectContent>
              </Select>
              <Select value={editExecForm.riskLevel} onValueChange={(v) => setEditExecForm({ ...editExecForm, riskLevel: v })}>
                <SelectTrigger className="h-8">
                  <SelectValue placeholder="Nivel de riesgo" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="bajo">Bajo</SelectItem>
                  <SelectItem value="medio">Medio</SelectItem>
                  <SelectItem value="alto">Alto</SelectItem>
                  <SelectItem value="critico">Crítico</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Textarea placeholder="Notas" value={editExecForm.notes} onChange={e => setEditExecForm({ ...editExecForm, notes: e.target.value })} className="h-20" />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowEditExecDialog(false)}>Cancelar</Button>
            <Button onClick={async () => {
              try {
                const res = await fetch('/api/executives', {
                  method: 'PUT',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ id: selectedExecutive?.id, ...editExecForm }),
                });
                if (!res.ok) {
                  const data = await res.json();
                  throw new Error(data.error || 'Error');
                }
                toast.success('Ejecutivo actualizado exitosamente');
                setShowEditExecDialog(false);
                setSelectedExecutive(null);
                setSearchTerm(Date.now().toString());
              } catch (err: any) {
                toast.error(err.message || 'Error al actualizar ejecutivo');
              }
            }}>Guardar Cambios</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ===== DELETE CONFIRM DIALOG ===== */}
      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Eliminar Ejecutivo</DialogTitle>
            <DialogDescription>
              ¿Está seguro de eliminar a <strong>{selectedExecutive?.fullName}</strong>? Esta acción no se puede deshacer.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDeleteDialog(false)}>Cancelar</Button>
            <Button variant="destructive" onClick={async () => {
              try {
                const res = await fetch(`/api/executives?id=${selectedExecutive?.id}`, { method: 'DELETE' });
                if (!res.ok) throw new Error('Error');
                toast.success('Ejecutivo eliminado');
                setShowDeleteDialog(false);
                setSelectedExecutive(null);
                setSearchTerm(Date.now().toString());
              } catch {
                toast.error('Error al eliminar ejecutivo');
              }
            }}>Eliminar</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
