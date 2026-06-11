'use client';

import React, { useState, useCallback, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, X, Loader2, ChevronDown, ChevronUp, ExternalLink,
  Shield, Database, FileWarning, Eye, LogIn, Globe, Copy,
  Filter, AlertTriangle, CheckCircle2, XCircle, Info,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { toast } from 'sonner';
import {
  DORK_TEMPLATES,
  CATEGORY_META,
  SEVERITY_COLORS,
  type DorkCategory,
  type SeverityLevel,
  type DorkTemplate,
} from '@/lib/osint/dork-templates';
import {
  type TargetInput,
  type SearchFilters,
  type DorkSearchResult,
  type DorkSearchResultItem,
  getPrimaryTarget,
} from '@/lib/osint/query-builder';

// ============================================================================
// Types
// ============================================================================
interface DorkProgress {
  taskId: string;
  totalQueries: number;
  completedQueries: number;
  totalResults: number;
}

// ============================================================================
// Category Icon
// ============================================================================
function CategoryIcon({ category, className = 'w-4 h-4' }: { category: DorkCategory; className?: string }) {
  const meta = CATEGORY_META[category];
  switch (category) {
    case 'login_pages': return <LogIn className={`${className} ${meta.color}`} />;
    case 'exposed_files': return <FileWarning className={`${className} ${meta.color}`} />;
    case 'databases': return <Database className={`${className} ${meta.color}`} />;
    case 'sensitive_info': return <Eye className={`${className} ${meta.color}`} />;
    case 'security': return <Shield className={`${className} ${meta.color}`} />;
    case 'general': return <Globe className={`${className} ${meta.color}`} />;
    default: return <Search className={className} />;
  }
}

// ============================================================================
// Severity Badge
// ============================================================================
function SeverityBadge({ severity }: { severity: SeverityLevel }) {
  const colors = SEVERITY_COLORS[severity];
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold border ${colors.bg} ${colors.text} ${colors.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${colors.dot}`} />
      {severity}
    </span>
  );
}

// ============================================================================
// Template Chip
// ============================================================================
function TemplateChip({
  template,
  selected,
  onToggle,
}: {
  template: DorkTemplate;
  selected: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      onClick={onToggle}
      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-all border cursor-pointer ${
        selected
          ? 'bg-primary/8 border-primary/30 text-primary'
          : 'bg-card/50 border-border text-muted-foreground hover:bg-muted/30 hover:text-foreground'
      }`}
    >
      <Search className="w-3 h-3" />
      {template.name}
      <SeverityBadge severity={template.severity} />
    </button>
  );
}

// ============================================================================
// Dork Result Card (Accordion)
// ============================================================================
function DorkResultCard({
  result,
  isExpanded,
  onToggle,
}: {
  result: DorkSearchResult;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const meta = CATEGORY_META[result.category as DorkCategory];

  return (
    <div className={`rounded-lg border ${isExpanded ? 'border-border' : 'border-border/50'} bg-card/40 overflow-hidden transition-all`}>
      {/* Card Header */}
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-3 hover:bg-muted/10 transition-colors text-left"
      >
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <SeverityBadge severity={result.severity} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-foreground truncate">{result.templateName}</span>
              <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                {meta?.label || result.category}
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground font-mono mt-0.5 truncate">
              {result.query}
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <Badge variant="secondary" className="text-xs">
              {result.resultCount > 0 ? `${result.resultCount} resultados` : 'Sin resultados'}
            </Badge>
            {isExpanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
          </div>
        </div>
      </button>

      {/* Card Detail (Expandable) */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-3 pb-3 space-y-2">
              {/* Query details */}
              <div className="bg-muted/20 rounded-md p-2">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Consulta ejecutada</p>
                <p className="text-xs font-mono text-foreground break-all">{result.query}</p>
              </div>

              {/* Engine info */}
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span>Motor: Investigation Search</span>
                <span className="text-border">|</span>
                <span>Completado: {new Date(result.completedAt).toLocaleTimeString()}</span>
                <span className="text-border">|</span>
                <a
                  href={result.searchUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300"
                >
                  Abrir en Google <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              {/* Results list */}
              {result.resultCount > 0 ? (
                <div className="space-y-1.5 max-h-64 overflow-y-auto">
                  {result.results.map((item, idx) => (
                    <div key={idx} className="bg-muted/10 rounded-md p-2 hover:bg-muted/20 transition-colors">
                      <div className="flex items-start gap-2">
                        <span className="text-[10px] text-muted-foreground mt-0.5 flex-shrink-0">#{idx + 1}</span>
                        <div className="flex-1 min-w-0">
                          <a
                            href={item.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs font-medium text-blue-400 hover:text-blue-300 line-clamp-2 flex items-start gap-1"
                          >
                            {item.title}
                            <ExternalLink className="w-3 h-3 flex-shrink-0 mt-0.5" />
                          </a>
                          <p className="text-[11px] text-muted-foreground font-mono mt-0.5 truncate">{item.url}</p>
                          {item.snippet && (
                            <p className="text-[11px] text-muted-foreground mt-1 line-clamp-2">{item.snippet}</p>
                          )}
                        </div>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground flex-shrink-0"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigator.clipboard.writeText(item.url);
                            toast.success('URL copiada al portapapeles');
                          }}
                          title="Copiar URL"
                        >
                          <Copy className="w-3 h-3" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="flex items-center gap-2 p-3 text-muted-foreground">
                  <Info className="w-4 h-4" />
                  <span className="text-xs">
                    {result.error ? `Error: ${result.error}` : 'No se encontraron resultados para esta consulta'}
                  </span>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ============================================================================
// Main Google Dorking Panel
// ============================================================================
interface GoogleDorkingPanelProps {
  /** Pre-fill target from selected executive */
  executiveTarget?: {
    fullName: string;
    email: string | null;
    phone: string | null;
    organization: string | null;
  };
  /** Callback when panel is closed */
  onClose: () => void;
}

export default function GoogleDorkingPanel({ executiveTarget, onClose }: GoogleDorkingPanelProps) {
  // Target input state
  const [targetName, setTargetName] = useState(executiveTarget?.fullName || '');
  const [targetEmail, setTargetEmail] = useState(executiveTarget?.email || '');
  const [targetAlias, setTargetAlias] = useState('');
  const [targetPhone, setTargetPhone] = useState(executiveTarget?.phone || '');
  const [targetDomain, setTargetDomain] = useState('');

  // Filter state
  const [siteFilter, setSiteFilter] = useState('');
  const [filetypeFilter, setFiletypeFilter] = useState('');
  const [dateRangeFilter, setDateRangeFilter] = useState('');
  const [showFilters, setShowFilters] = useState(false);

  // Category tabs
  const [activeCategory, setActiveCategory] = useState<DorkCategory>('login_pages');
  const categories: DorkCategory[] = ['login_pages', 'exposed_files', 'databases', 'sensitive_info', 'security', 'general'];

  // Template selection
  const [selectedTemplateIds, setSelectedTemplateIds] = useState<Set<string>>(new Set());

  // Search execution
  const [isSearching, setIsSearching] = useState(false);
  const [searchProgress, setSearchProgress] = useState<DorkProgress | null>(null);
  const [dorkResults, setDorkResults] = useState<DorkSearchResult[]>([]);
  const [expandedDork, setExpandedDork] = useState<string | null>(null);

  // EventSource ref
  const eventSourceRef = useRef<EventSource | null>(null);

  // Sync executive target when prop changes
  useEffect(() => {
    if (executiveTarget) {
      setTargetName(executiveTarget.fullName || '');
      setTargetEmail(executiveTarget.email || '');
      setTargetPhone(executiveTarget.phone || '');
      if (executiveTarget.email) {
        const domain = executiveTarget.email.split('@')[1];
        if (domain) setTargetDomain(domain);
      }
    }
  }, [executiveTarget]);

  // Get templates for active category
  const categoryTemplates = DORK_TEMPLATES.filter(t => t.category === activeCategory);

  // Toggle template selection
  const toggleTemplate = useCallback((templateId: string) => {
    setSelectedTemplateIds(prev => {
      const next = new Set(prev);
      if (next.has(templateId)) {
        next.delete(templateId);
      } else {
        next.add(templateId);
      }
      return next;
    });
  }, []);

  // Select all templates in current category
  const selectAllInCategory = useCallback(() => {
    setSelectedTemplateIds(prev => {
      const next = new Set(prev);
      const categoryIds = categoryTemplates.map(t => t.id);
      const allSelected = categoryIds.every(id => next.has(id));
      if (allSelected) {
        categoryIds.forEach(id => next.delete(id));
      } else {
        categoryIds.forEach(id => next.add(id));
      }
      return next;
    });
  }, [categoryTemplates]);

  // Run Dork Search
  const runDorkSearch = useCallback(async () => {
    const target: TargetInput = {
      name: targetName || undefined,
      email: targetEmail || undefined,
      alias: targetAlias || undefined,
      phone: targetPhone || undefined,
      domain: targetDomain || undefined,
    };

    if (!target.name && !target.email && !target.alias && !target.phone && !target.domain) {
      toast.error('Ingrese al menos un campo del objetivo');
      return;
    }

    if (selectedTemplateIds.size === 0) {
      toast.error('Seleccione al menos una plantilla de dork');
      return;
    }

    const filters: SearchFilters = {
      site: siteFilter || undefined,
      filetype: filetypeFilter || undefined,
      dateRange: dateRangeFilter || undefined,
    };

    setIsSearching(true);
    setDorkResults([]);
    setSearchProgress(null);
    setExpandedDork(null);

    try {
      const response = await fetch('/api/osint/dorking', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target,
          filters,
          templateIds: Array.from(selectedTemplateIds),
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Error desconocido' }));
        toast.error(errorData.error || 'Error al iniciar la busqueda');
        setIsSearching(false);
        return;
      }

      // Set up SSE reader
      const reader = response.body?.getReader();
      if (!reader) {
        toast.error('No se pudo iniciar el stream de resultados');
        setIsSearching(false);
        return;
      }

      const decoder = new TextDecoder();
      let buffer = '';

      const processStream = async () => {
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });

            // Parse SSE events from buffer
            const lines = buffer.split('\n');
            buffer = '';

            let currentEvent = '';
            let currentData = '';

            for (let i = 0; i < lines.length; i++) {
              const line = lines[i];

              if (line.startsWith('event: ')) {
                currentEvent = line.substring(7).trim();
              } else if (line.startsWith('data: ')) {
                currentData = line.substring(6);
              } else if (line === '' && currentEvent && currentData) {
                // Empty line = end of event
                try {
                  const parsed = JSON.parse(currentData);

                  switch (currentEvent) {
                    case 'start':
                      setSearchProgress({
                        taskId: parsed.taskId,
                        totalQueries: parsed.totalQueries,
                        completedQueries: 0,
                        totalResults: 0,
                      });
                      break;

                    case 'result':
                      setDorkResults(prev => [...prev, parsed.dork]);
                      setSearchProgress(parsed.progress);
                      break;

                    case 'complete':
                      setSearchProgress(prev => prev ? {
                        ...prev,
                        completedQueries: parsed.completedQueries,
                        totalResults: parsed.totalResults,
                      } : null);
                      toast.success(`Busqueda completada: ${parsed.totalResults} resultados en ${parsed.elapsedSeconds}s`);
                      break;

                    case 'error':
                      toast.error(`Error en la busqueda: ${parsed.error}`);
                      break;
                  }
                } catch (e) {
                  // Ignore parse errors for partial events
                  console.warn('SSE parse error:', e);
                }

                currentEvent = '';
                currentData = '';
              } else if (line !== '') {
                // Accumulate data for multi-line data fields
                if (currentData && !line.startsWith('event:')) {
                  currentData += line;
                }
              }
            }
          }
        } catch (e: unknown) {
          if (e instanceof Error && e.name !== 'AbortError') {
            console.error('Stream read error:', e);
            toast.error('Error en la conexion de stream');
          }
        } finally {
          setIsSearching(false);
        }
      };

      processStream();

    } catch (e: unknown) {
      console.error('Dork search error:', e);
      toast.error('Error al ejecutar la busqueda de dorks');
      setIsSearching(false);
    }
  }, [targetName, targetEmail, targetAlias, targetPhone, targetDomain, siteFilter, filetypeFilter, dateRangeFilter, selectedTemplateIds]);

  // Cancel search
  const cancelSearch = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setIsSearching(false);
    toast.info('Busqueda cancelada');
  }, []);

  // Summary stats
  const totalResults = dorkResults.reduce((sum, r) => sum + r.resultCount, 0);
  const criticalCount = dorkResults.filter(r => r.severity === 'CRITICAL' && r.resultCount > 0).length;
  const highCount = dorkResults.filter(r => r.severity === 'HIGH' && r.resultCount > 0).length;
  const mediumCount = dorkResults.filter(r => r.severity === 'MEDIUM' && r.resultCount > 0).length;
  const lowCount = dorkResults.filter(r => r.severity === 'LOW' && r.resultCount > 0).length;

  return (
    <motion.div
      initial={{ opacity: 0, y: -20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="space-y-4"
    >
      {/* ===== HEADER ===== */}
      <Card className="border-border bg-card/60 overflow-hidden">
        <div className="relative">
          {/* Background pattern */}
          <div className="absolute inset-0 opacity-5 pointer-events-none overflow-hidden">
            <div className="font-mono text-[8px] text-foreground leading-none whitespace-pre-wrap select-none">
              {Array.from({ length: 30 }, (_, i) =>
                Array.from({ length: 120 }, () => Math.random() > 0.5 ? '1' : '0').join('')
              ).join('\n')}
            </div>
          </div>

          <div className="relative p-4 sm:p-6 space-y-4">
            {/* Title */}
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-foreground flex items-center gap-2">
                  <span className="text-white">Google</span>
                  <span className="text-primary">Dorking</span>
                </h2>
                <p className="text-xs text-muted-foreground mt-1 max-w-2xl">
                  Automated advanced Google Dork searches to discover sensitive information, exposed files, login pages, databases, and security misconfigurations indexed by search engines.
                </p>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={onClose}
                className="text-muted-foreground hover:text-foreground"
              >
                <X className="w-5 h-5" />
              </Button>
            </div>

            {/* ===== CATEGORY TABS ===== */}
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Search className="w-3.5 h-3.5 text-muted-foreground" />
                <Label className="text-xs text-muted-foreground uppercase tracking-wider">Category</Label>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {categories.map(cat => {
                  const meta = CATEGORY_META[cat];
                  const isActive = activeCategory === cat;
                  const catTemplates = DORK_TEMPLATES.filter(t => t.category === cat);
                  const selectedInCat = catTemplates.filter(t => selectedTemplateIds.has(t.id)).length;

                  return (
                    <button
                      key={cat}
                      onClick={() => setActiveCategory(cat)}
                      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all border cursor-pointer ${
                        isActive
                          ? 'bg-primary/8 border-primary/30 text-primary'
                          : 'bg-card/50 border-border text-muted-foreground hover:bg-muted/30 hover:text-foreground'
                      }`}
                    >
                      <CategoryIcon category={cat} className="w-3.5 h-3.5" />
                      {meta.label}
                      {selectedInCat > 0 && (
                        <span className="bg-primary/12 text-primary text-[10px] px-1 rounded-full">
                          {selectedInCat}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* ===== OPTIONAL FILTERS ===== */}
            <div>
              <button
                onClick={() => setShowFilters(!showFilters)}
                className="flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                <Filter className="w-3.5 h-3.5 text-cyan-400" />
                <span className="uppercase tracking-wider">Optional Filters</span>
                {showFilters ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </button>

              <AnimatePresence>
                {showFilters && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="overflow-hidden"
                  >
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-3">
                      <div>
                        <Label className="text-xs text-muted-foreground">Site Filter</Label>
                        <Input
                          placeholder="e.g., example.com"
                          value={siteFilter}
                          onChange={e => setSiteFilter(e.target.value)}
                          className="mt-1 bg-muted/20 border-border text-sm h-9"
                        />
                      </div>
                      <div>
                        <Label className="text-xs text-muted-foreground">File Type</Label>
                        <Input
                          placeholder="e.g., pdf, sql, env"
                          value={filetypeFilter}
                          onChange={e => setFiletypeFilter(e.target.value)}
                          className="mt-1 bg-muted/20 border-border text-sm h-9"
                        />
                      </div>
                      <div>
                        <Label className="text-xs text-muted-foreground">Date Range</Label>
                        <select
                          value={dateRangeFilter}
                          onChange={e => setDateRangeFilter(e.target.value)}
                          className="mt-1 w-full h-9 rounded-md border border-border bg-muted/20 px-3 text-sm text-foreground"
                        >
                          <option value="">Any time</option>
                          <option value="last_day">Last day</option>
                          <option value="last_week">Last week</option>
                          <option value="last_month">Last month</option>
                          <option value="last_year">Last year</option>
                        </select>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* ===== TARGET INPUT ===== */}
            <div className="space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <Label className="text-xs text-muted-foreground">Nombre completo</Label>
                  <div className="relative mt-1">
                    <Input
                      placeholder="Digite el nombre completo"
                      value={targetName}
                      onChange={e => setTargetName(e.target.value)}
                      className="bg-muted/20 border-border text-sm pr-16"
                    />
                    <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                      {targetName && (
                        <button onClick={() => setTargetName('')} className="text-muted-foreground hover:text-foreground">
                          <X className="w-3.5 h-3.5" />
                        </button>
                      )}
                      <button
                        onClick={() => { navigator.clipboard.writeText(targetName); toast.success('Copiado'); }}
                        className="text-muted-foreground hover:text-foreground"
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">Email</Label>
                  <Input
                    placeholder="correo@dominio.com"
                    value={targetEmail}
                    onChange={e => setTargetEmail(e.target.value)}
                    className="mt-1 bg-muted/20 border-border text-sm"
                  />
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">Alias / Username</Label>
                  <Input
                    placeholder="Ingrese el username"
                    value={targetAlias}
                    onChange={e => setTargetAlias(e.target.value)}
                    className="mt-1 bg-muted/20 border-border text-sm"
                  />
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">Telefono / Celular</Label>
                  <Input
                    placeholder="Ej: +57 300 1234567"
                    value={targetPhone}
                    onChange={e => setTargetPhone(e.target.value)}
                    className="mt-1 bg-muted/20 border-border text-sm"
                  />
                </div>
              </div>
              <div className="max-w-xs">
                <Label className="text-xs text-muted-foreground">Dominio</Label>
                <Input
                  placeholder="Ej: empresa.com"
                  value={targetDomain}
                  onChange={e => setTargetDomain(e.target.value)}
                  className="mt-1 bg-muted/20 border-border text-sm"
                />
              </div>
            </div>

            {/* ===== PRESET DORK TEMPLATES ===== */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <Label className="text-xs text-muted-foreground uppercase tracking-wider">
                  Preset dork templates: <span className="text-foreground">{selectedTemplateIds.size} seleccionadas</span>
                </Label>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={selectAllInCategory}
                  className="text-[10px] h-6 px-2 text-muted-foreground hover:text-foreground"
                >
                  {categoryTemplates.every(t => selectedTemplateIds.has(t.id)) ? 'Deseleccionar todas' : 'Seleccionar todas'}
                </Button>
              </div>
              <div className="flex flex-wrap gap-2">
                {categoryTemplates.map(template => (
                  <TemplateChip
                    key={template.id}
                    template={template}
                    selected={selectedTemplateIds.has(template.id)}
                    onToggle={() => toggleTemplate(template.id)}
                  />
                ))}
              </div>
            </div>

            {/* ===== RUN BUTTON ===== */}
            <Button
              onClick={runDorkSearch}
              disabled={isSearching || selectedTemplateIds.size === 0}
              className="w-full bg-emerald-600 hover:bg-emerald-700 text-white font-semibold gap-2 h-11 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {isSearching ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Ejecutando {searchProgress ? `${searchProgress.completedQueries}/${searchProgress.totalQueries}` : '...'} busquedas...
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  Run Dork Search
                </>
              )}
            </Button>

            {isSearching && (
              <Button
                variant="outline"
                onClick={cancelSearch}
                className="w-full border-red-500/30 text-red-400 hover:bg-red-500/10"
              >
                Cancelar Busqueda
              </Button>
            )}
          </div>
        </div>
      </Card>

      {/* ===== RESULTS DASHBOARD ===== */}
      {(dorkResults.length > 0 || isSearching) && (
        <Card className="border-border bg-card/60">
          <CardHeader className="pb-3">
            <CardTitle className="text-base text-foreground flex items-center gap-2">
              <Globe className="w-4 h-4 text-primary" />
              Dashboard de Resultados
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Summary metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-muted/20 rounded-lg p-3 text-center">
                <p className="text-lg font-bold text-foreground">{searchProgress?.completedQueries || dorkResults.length}</p>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Ejecutadas</p>
              </div>
              <div className="bg-muted/20 rounded-lg p-3 text-center">
                <p className="text-lg font-bold text-foreground">{totalResults}</p>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total resultados</p>
              </div>
              <div className="bg-muted/20 rounded-lg p-3 text-center">
                <p className="text-lg font-bold text-red-400">{criticalCount}</p>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Criticos</p>
              </div>
              <div className="bg-muted/20 rounded-lg p-3 text-center">
                <p className="text-lg font-bold text-orange-400">{highCount}</p>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Altos</p>
              </div>
            </div>

            {/* Severity breakdown bar */}
            {totalResults > 0 && (
              <div className="space-y-1.5">
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" /> CRITICAL: {criticalCount}</span>
                  <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-500" /> HIGH: {highCount}</span>
                  <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-yellow-500" /> MEDIUM: {mediumCount}</span>
                  <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-500" /> LOW: {lowCount}</span>
                </div>
                <div className="h-2 rounded-full bg-muted/20 overflow-hidden flex">
                  {totalResults > 0 && (
                    <>
                      {criticalCount > 0 && <div className="bg-red-500 h-full" style={{ width: `${(criticalCount / dorkResults.filter(r => r.resultCount > 0).length) * 100}%` }} />}
                      {highCount > 0 && <div className="bg-orange-500 h-full" style={{ width: `${(highCount / dorkResults.filter(r => r.resultCount > 0).length) * 100}%` }} />}
                      {mediumCount > 0 && <div className="bg-yellow-500 h-full" style={{ width: `${(mediumCount / dorkResults.filter(r => r.resultCount > 0).length) * 100}%` }} />}
                      {lowCount > 0 && <div className="bg-blue-500 h-full" style={{ width: `${(lowCount / dorkResults.filter(r => r.resultCount > 0).length) * 100}%` }} />}
                    </>
                  )}
                </div>
              </div>
            )}

            {/* Live progress indicator */}
            {isSearching && searchProgress && (
              <div className="flex items-center gap-3 p-3 rounded-lg bg-primary/5 border border-primary/8">
                <Loader2 className="w-4 h-4 animate-spin text-primary" />
                <span className="text-sm text-primary">
                  Buscando consulta {searchProgress.completedQueries} de {searchProgress.totalQueries}...
                  {searchProgress.totalResults > 0 && ` | ${searchProgress.totalResults} resultados hasta ahora`}
                </span>
                <div className="ml-auto flex-1 max-w-xs">
                  <div className="h-1.5 rounded-full bg-muted/20 overflow-hidden">
                    <div
                      className="h-full bg-primary transition-all duration-500"
                      style={{ width: `${(searchProgress.completedQueries / searchProgress.totalQueries) * 100}%` }}
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Dork result cards (progressive) */}
            <div className="space-y-2">
              <AnimatePresence>
                {dorkResults.map(result => (
                  <motion.div
                    key={result.templateId}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.15 }}
                  >
                    <DorkResultCard
                      result={result}
                      isExpanded={expandedDork === result.templateId}
                      onToggle={() => setExpandedDork(
                        expandedDork === result.templateId ? null : result.templateId
                      )}
                    />
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>

            {/* Empty state while searching */}
            {isSearching && dorkResults.length === 0 && (
              <div className="flex items-center justify-center py-8 text-muted-foreground">
                <Loader2 className="w-5 h-5 animate-spin mr-2" />
                <span className="text-sm">Preparando búsquedas por campo...</span>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </motion.div>
  );
}
