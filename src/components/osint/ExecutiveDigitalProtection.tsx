'use client';

import React, { useState, useCallback, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Search, Download, FileText, Printer,
  ChevronDown, ChevronUp, Eye, EyeOff, X,
  Copy, CheckCircle2, AlertTriangle, Filter,
  ArrowRight, Globe, Plus, Trash2, Edit3,
  Users, FolderOpen, FileSpreadsheet, Presentation,
  FileArchive, Calendar, Mail, Phone, MapPin,
  Lock, Unlock, Skull, Target, Radar, Zap,
  FileCode, Database, Server, Globe2, Camera,
  Image, BookOpen, ScrollText, MessageSquare,
  Wifi, Cpu, Brain, Layers, Activity,
  ChevronRight, FileJson, ShieldAlert,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from '@/components/ui/dialog';
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
  type PrintableModuleOptions,
} from '@/lib/osint';
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
  active: boolean;
  createdAt: string;
  updatedAt: string;
}

interface CategoryResult {
  categoryId: string;
  results: DorkResult[];
  totalResults: number;
  queryExecuted: string;
}

interface ModuleStatus {
  categoryId: string;
  executed: boolean;
  results: DorkResult[];
  timestamp: string;
  totalResults: number;
}

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
// Category Icon
// ============================================================================
function CategoryIcon({ icon, className = 'w-5 h-5' }: { icon: string; className?: string }) {
  return <span className={className}>{icon}</span>;
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
  const [resultFilter, setResultFilter] = useState<'all' | 'validated' | 'potential' | 'discarded'>('all');
  const [showNewExecDialog, setShowNewExecDialog] = useState(false);
  const [newExecForm, setNewExecForm] = useState({ fullName: '', identificationNum: '', email: '', phone: '', position: '', organization: '', riskLevel: 'medio' as const });
  const [showTargetDialog, setShowTargetDialog] = useState(false);
  const [targetName, setTargetName] = useState('');
  const [targetEmail, setTargetEmail] = useState('');
  const [targetPhone, setTargetPhone] = useState('');
  const [targetOrg, setTargetOrg] = useState('');
  const [targetCustom, setTargetCustom] = useState(false);
  const [totalQueries, setTotalQueries] = useState(0);
  const [isRunning, setIsRunning] = useState(false);

  // Fetch executives
  useEffect(() => {
    const fetchExecutives = async () => {
      try {
        const params = new URLSearchParams();
        if (searchTerm) params.set('search', searchTerm);
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
  }, [searchTerm]);

  // Get target name
  const getTargetName = useCallback(() => {
    if (targetCustom && targetName) return targetName;
    if (selectedExecutive) return selectedExecutive.fullName;
    return '';
  }, [targetCustom, targetName, selectedExecutive]);

  // Get target info
  const getTargetInfo = useCallback(() => {
    if (targetCustom) {
      return { email: targetEmail, phone: targetPhone, org: targetOrg };
    }
    if (selectedExecutive) {
      return { email: selectedExecutive.email, phone: selectedExecutive.phone, org: selectedExecutive.organization };
    }
    return { email: '', phone: '', org: '' };
  }, [targetCustom, targetEmail, targetPhone, targetOrg, selectedExecutive]);

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
    const dorkQuery = category.dorkTemplate.replace(/\{TARGET\}/g, target);

    try {
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

      // For this module, we simulate results and generate the printable module
      // In production, this would use the actual dorking API results
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

      // Auto-generate printable module
      const options: PrintableModuleOptions = {
        category,
        targetName: target,
        executiveEmail: getTargetInfo().email,
        executivePhone: getTargetInfo().phone,
        executiveOrg: getTargetInfo().org,
        results: mockResults,
        timestamp,
        riskLevel: 'medio',
        totalQueries: 1,
        totalResults: mockResults.length,
      };

      // Open printable module automatically
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
      const dorkQuery = category.dorkTemplate.replace(/\{TARGET\}/g, target);
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

  // Handle result filter
  const filteredResults = (results: DorkResult[]) => {
    if (resultFilter === 'all') return results;
    return results.filter(r => r.classification === resultFilter);
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Shield className="w-8 h-8 animate-spin text-primary" />
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
                <h1 className="text-xl font-bold text-foreground tracking-tight">Executive Digital Protection</h1>
                <p className="text-xs text-muted-foreground">Módulo de Dorking OSINT — 21 Categorías de Búsqueda</p>
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
              <p className="text-2xl font-bold text-foreground">{EXECUTIVE_DORK_CATEGORIES.length}</p>
              <p className="text-xs text-muted-foreground">Categorías Totales</p>
            </CardContent>
          </Card>
          {Object.entries(severityStats).map(([level, count]) => {
            const info = SEVERITY_LABELS[level];
            return (
              <Card key={level} className="border-border bg-card/60">
                <CardContent className="p-4 text-center">
                  <p className="text-2xl font-bold text-foreground">{count}</p>
                  <p className="text-xs text-muted-foreground">{info.label}</p>
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* Target Selection Bar */}
        <Card className="border-border bg-card/60">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Target className="w-5 h-5 text-primary" />
              Configuración del Objetivo
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

              {targetCustom && (
                <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="flex gap-2 flex-wrap">
                  <Input
                    placeholder="Nombre completo"
                    value={targetName}
                    onChange={e => setTargetName(e.target.value)}
                    className="bg-muted/30 border-border text-sm"
                  />
                  <Input
                    placeholder="Email"
                    value={targetEmail}
                    onChange={e => setTargetEmail(e.target.value)}
                    className="bg-muted/30 border-border text-sm"
                  />
                  <Input
                    placeholder="Teléfono"
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
                </motion.div>
              )}

              <Button
                onClick={() => setShowTargetDialog(true)}
                variant="outline"
                size="sm"
                className="gap-1"
              >
                <Plus className="w-3 h-3" /> Nuevo Objetivo
              </Button>
            </div>

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
                <motion.div
                  key={category.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  layout
                >
                  <Card
                    className={`border-border bg-card/60 overflow-hidden transition-all cursor-pointer hover:border-primary/20 ${
                      selectedCategory === category.id ? 'border-primary/30 ring-1 ring-primary/10' : ''
                    }`}
                    onClick={() => toggleCategory(category.id)}
                  >
                    <CardContent className="p-4">
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
                        <div className="flex items-center gap-2">
                          {isExecuted && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                if (moduleStatus) {
                                  const target = getTargetName();
                                  const options: PrintableModuleOptions = {
                                    category,
                                    targetName: target,
                                    executiveEmail: getTargetInfo().email,
                                    executivePhone: getTargetInfo().phone,
                                    executiveOrg: getTargetInfo().org,
                                    results: moduleStatus.results,
                                    timestamp: moduleStatus.timestamp,
                                    totalQueries: 1,
                                    totalResults: moduleStatus.totalResults,
                                  };
                                  openPrintableModule(options);
                                }
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
                              {category.dorkTemplate.replace(/\{TARGET\}/g, getTargetName() || '[OBJETIVO]')}
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
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    const target = getTargetName();
                                    const options: PrintableModuleOptions = {
                                      category,
                                      targetName: target,
                                      executiveEmail: getTargetInfo().email,
                                      executivePhone: getTargetInfo().phone,
                                      executiveOrg: getTargetInfo().org,
                                      results: moduleStatus.results,
                                      timestamp: moduleStatus.timestamp,
                                      totalQueries: 1,
                                      totalResults: moduleStatus.totalResults,
                                    };
                                    openPrintableModule(options);
                                  }}
                                  className="gap-1 border-emerald-600/30 text-emerald-400 hover:bg-emerald-600/10"
                                >
                                  <Printer className="w-3 h-3" /> Imprimir PDF
                                </Button>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    const target = getTargetName();
                                    const options: PrintableModuleOptions = {
                                      category,
                                      targetName: target,
                                      executiveEmail: getTargetInfo().email,
                                      executivePhone: getTargetInfo().phone,
                                      executiveOrg: getTargetInfo().org,
                                      results: moduleStatus.results,
                                      timestamp: moduleStatus.timestamp,
                                      totalQueries: 1,
                                      totalResults: moduleStatus.totalResults,
                                    };
                                    downloadModuleAsHTML(options);
                                  }}
                                  className="gap-1"
                                >
                                  <FileText className="w-3 h-3" /> HTML
                                </Button>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    const target = getTargetName();
                                    const options: PrintableModuleOptions = {
                                      category,
                                      targetName: target,
                                      executiveEmail: getTargetInfo().email,
                                      executivePhone: getTargetInfo().phone,
                                      executiveOrg: getTargetInfo().org,
                                      results: moduleStatus.results,
                                      timestamp: moduleStatus.timestamp,
                                      totalQueries: 1,
                                      totalResults: moduleStatus.totalResults,
                                    };
                                    downloadModuleAsJSON(options);
                                  }}
                                  className="gap-1"
                                >
                                  <FileJson className="w-3 h-3" /> JSON
                                </Button>
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
              Referencia Rápida de Dorks — Todos los 21 Categorías
            </CardTitle>
            <CardDescription>
              Todas las consultas Dork organizadas por categoría
            </CardDescription>
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
                        <td className="px-4 py-2">
                          <SeverityBadge severity={cat.severity} />
                        </td>
                        <td className="px-4 py-2">
                          <code className="text-[10px] font-mono text-foreground bg-muted/20 px-2 py-1 rounded break-all max-w-md block">
                            {cat.dorkTemplate.replace(/\{TARGET\}/g, getTargetName() || '[OBJETIVO]')}
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
                <span className="text-xs text-muted-foreground">Total módulos: {Object.keys(modules).filter(k => modules[k].executed).length} / {EXECUTIVE_DORK_CATEGORIES.length}</span>
                <span className="text-xs text-muted-foreground">Total consultas: {totalQueries}</span>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
                <div className="p-3 rounded-lg bg-muted/20 border border-border text-center">
                  <p className="text-lg font-bold text-emerald-400">{Object.keys(modules).filter(k => modules[k].executed).length}</p>
                  <p className="text-[10px] text-muted-foreground uppercase">Módulos Completados</p>
                </div>
                <div className="p-3 rounded-lg bg-muted/20 border border-border text-center">
                  <p className="text-lg font-bold text-primary">{totalQueries}</p>
                  <p className="text-[10px] text-muted-foreground uppercase">Consultas Totales</p>
                </div>
                <div className="p-3 rounded-lg bg-muted/20 border border-border text-center">
                  <p className="text-lg font-bold text-yellow-400">{EXECUTIVE_DORK_CATEGORIES.length - Object.keys(modules).filter(k => modules[k].executed).length}</p>
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
                    LOW: 'bg-emerald-500',
                    MEDIUM: 'bg-yellow-500',
                    HIGH: 'bg-orange-500',
                    CRITICAL: 'bg-red-500',
                  };
                  return (
                    <div
                      key={cat.id}
                      className={`${colors[cat.severity]} h-full transition-all duration-500`}
                      style={{ width: `${progress}%` }}
                    />
                  );
                })}
              </div>

              <div className="flex flex-wrap gap-2">
                {EXECUTIVE_DORK_CATEGORIES.map(cat => {
                  const ms = modules[cat.id];
                  return (
                    <Badge
                      key={cat.id}
                      variant="outline"
                      className={`text-xs cursor-pointer gap-1 ${ms?.executed ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-muted/20 text-muted-foreground border-border'}`}
                      onClick={() => {
                        setSelectedCategory(cat.id);
                        setExpandedCategories(new Set([cat.id]));
                      }}
                    >
                      {cat.icon} {cat.shortName}
                      {ms?.executed && <CheckCircle2 className="w-3 h-3" />}
                    </Badge>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        )}
      </main>

      {/* New Executive Dialog */}
      <Dialog open={showNewExecDialog} onOpenChange={setShowNewExecDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Nuevo Ejecutivo</DialogTitle>
            <DialogDescription>Agregue un nuevo objetivo para la protección digital</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <Input
              placeholder="Nombre completo"
              value={newExecForm.fullName}
              onChange={e => setNewExecForm({ ...newExecForm, fullName: e.target.value })}
            />
            <Input
              placeholder="Número de identificación"
              value={newExecForm.identificationNum}
              onChange={e => setNewExecForm({ ...newExecForm, identificationNum: e.target.value })}
            />
            <Input
              placeholder="Email"
              value={newExecForm.email}
              onChange={e => setNewExecForm({ ...newExecForm, email: e.target.value })}
            />
            <Input
              placeholder="Teléfono"
              value={newExecForm.phone}
              onChange={e => setNewExecForm({ ...newExecForm, phone: e.target.value })}
            />
            <Input
              placeholder="Cargo"
              value={newExecForm.position}
              onChange={e => setNewExecForm({ ...newExecForm, position: e.target.value })}
            />
            <Input
              placeholder="Organización"
              value={newExecForm.organization}
              onChange={e => setNewExecForm({ ...newExecForm, organization: e.target.value })}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowNewExecDialog(false)}>Cancelar</Button>
            <Button onClick={async () => {
              try {
                const res = await fetch('/api/executives', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify(newExecForm),
                });
                if (!res.ok) throw new Error('Error');
                toast.success('Ejecutivo creado');
                setShowNewExecDialog(false);
                setNewExecForm({ fullName: '', identificationNum: '', email: '', phone: '', position: '', organization: '', riskLevel: 'medio' });
              } catch {
                toast.error('Error al crear ejecutivo');
              }
            }}>Crear</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
