'use client';

import React, { useState, useCallback, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, X, Loader2, ChevronDown, ChevronUp, ExternalLink,
  Copy, AlertTriangle, CheckCircle2, XCircle, Info,
  Shield, Database, FileWarning, Eye, LogIn, Globe, Filter,
  Terminal, Layers, Bug, Zap, FileText, Download, FolderOpen,
  ClipboardList, AlertCircle, Network,
  HardDrive, Server, Lock, Unlock, Wifi, Cpu, Monitor,
  Trash2,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Progress } from '@/components/ui/progress';
import { toast } from 'sonner';
import { ThemeSelector } from '@/components/ThemeSelector';
import NextLink from 'next/link';

// ============================================================================
// Types
// ============================================================================
interface UrlScanResult {
  url: string;
  title: string;
  description: string;
  ip?: string;
  domain?: string;
  ssl?: {
    valid: boolean;
    issuer?: string;
    expires?: string;
  };
  technologies?: string[];
  headers?: Record<string, string>;
  redirects?: string[];
  subdomains?: string[];
  dnsRecords?: Record<string, string[]>;
  screenshots?: string[];
  threatIntel?: {
    malicious: boolean;
    categories: string[];
    score: number;
    sources: string[];
  };
  whois?: {
    registrar?: string;
    created?: string;
    expires?: string;
    registrant?: string;
    country?: string;
  };
  analysis?: {
    riskLevel: 'bajo' | 'medio' | 'alto' | 'critico';
    findings: Array<{
      type: string;
      severity: 'info' | 'warning' | 'critical';
      description: string;
      evidence?: string;
    }>;
    recommendations: string[];
  };
  resourceTree?: ResourceTreeNode[];
}

interface ResourceTreeNode {
  id: string;
  name: string;
  type: 'url' | 'domain' | 'ip' | 'subdomain' | 'technology' | 'header' | 'redirect' | 'dns' | 'ssl' | 'whois' | 'threat' | 'screenshot';
  value: string;
  children?: ResourceTreeNode[];
  metadata?: Record<string, unknown>;
  clickable?: boolean;
  copyable?: boolean;
  analysis?: string;
}

interface ScanHistoryItem {
  id: string;
  url: string;
  domain: string;
  riskLevel: 'bajo' | 'medio' | 'alto' | 'critico';
  timestamp: string;
  result: UrlScanResult;
}

const riskColors: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  bajo: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/20', dot: 'bg-emerald-500' },
  medio: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/20', dot: 'bg-yellow-500' },
  alto: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20', dot: 'bg-orange-500' },
  critico: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20', dot: 'bg-red-500' },
};

const typeIcons: Record<string, React.ReactNode> = {
  url: <Globe className="w-3.5 h-3.5 text-blue-400" />,
  domain: <Server className="w-3.5 h-3.5 text-purple-400" />,
  ip: <Monitor className="w-3.5 h-3.5 text-green-400" />,
  subdomain: <Network className="w-3.5 h-3.5 text-cyan-400" />,
  technology: <Cpu className="w-3.5 h-3.5 text-yellow-400" />,
  header: <HardDrive className="w-3.5 h-3.5 text-pink-400" />,
  redirect: <ExternalLink className="w-3.5 h-3.5 text-orange-400" />,
  dns: <Database className="w-3.5 h-3.5 text-indigo-400" />,
  ssl: <Lock className="w-3.5 h-3.5 text-emerald-400" />,
  whois: <FileText className="w-3.5 h-3.5 text-slate-400" />,
  threat: <AlertTriangle className="w-3.5 h-3.5 text-red-400" />,
  screenshot: <Monitor className="w-3.5 h-3.5 text-violet-400" />,
};

const typeLabels: Record<string, string> = {
  url: 'URL Principal',
  domain: 'Dominio',
  ip: 'Dirección IP',
  subdomain: 'Subdominio',
  technology: 'Tecnología',
  header: 'Header HTTP',
  redirect: 'Redirección',
  dns: 'Registro DNS',
  ssl: 'Certificado SSL',
  whois: 'WHOIS',
  threat: 'Amenaza',
  screenshot: 'Captura',
};

// ============================================================================
// Resource Tree Node Component (Recursive, Clickable, Animated)
// ============================================================================
interface ResourceTreeNodeProps {
  node: ResourceTreeNode;
  depth?: number;
  onNodeClick?: (node: ResourceTreeNode) => void;
  onCopy?: (value: string, label: string) => void;
  selectedNodeId?: string;
  animationDelay?: number;
}

function ResourceTreeNodeComponent({
  node,
  depth = 0,
  onNodeClick,
  onCopy,
  selectedNodeId,
  animationDelay = 0,
}: ResourceTreeNodeProps) {
  const [expanded, setExpanded] = useState(node.children && node.children.length > 0);
  const [copied, setCopied] = useState(false);
  const nodeRef = useRef<HTMLDivElement>(null);

  const isSelected = selectedNodeId === node.id;
  const hasChildren = node.children && node.children.length > 0;
  const isClickable = node.clickable !== false && (onNodeClick || node.analysis || node.copyable);

  useEffect(() => {
    if (isSelected && nodeRef.current) {
      nodeRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [isSelected]);

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (onNodeClick) {
      onNodeClick(node);
    }
    if (hasChildren) {
      setExpanded(!expanded);
    }
  };

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (node.copyable !== false && onCopy) {
      onCopy(node.value, `${typeLabels[node.type]}: ${node.name}`);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleClick(e as unknown as React.MouseEvent);
    }
    if (e.key === 'c' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      handleCopy(e as unknown as React.MouseEvent);
    }
  };

  return (
    <motion.div
      ref={nodeRef}
      key={node.id}
      initial={{ opacity: 0, x: -20, height: 0 }}
      animate={{ opacity: 1, x: 0, height: 'auto' }}
      exit={{ opacity: 0, x: 20, height: 0 }}
      transition={{ duration: 0.2, delay: animationDelay * 0.03 }}
      className="select-none"
    >
      <div
        className={`flex items-center gap-2 py-1.5 px-2 rounded-lg transition-all duration-200 ${
          isSelected
            ? 'bg-primary/10 border border-primary/30 shadow-sm'
            : isClickable
              ? 'hover:bg-muted/30 hover:border-border/50 cursor-pointer'
              : ''
        } ${depth > 0 ? 'ml-6 border-l border-border/30 pl-3' : ''}`}
        onClick={handleClick}
        onKeyDown={handleKeyDown}
        tabIndex={isClickable ? 0 : -1}
        role={isClickable ? 'button' : undefined}
        aria-expanded={hasChildren ? expanded : undefined}
        aria-selected={isSelected}
        title={isClickable ? (node.analysis ? 'Clic para ver análisis • Ctrl+C para copiar' : 'Ctrl+C para copiar') : undefined}
      >
        {hasChildren && (
          <motion.button
            onClick={(e) => { e.stopPropagation(); setExpanded(!expanded); }}
            className="flex items-center justify-center w-5 h-5 text-muted-foreground hover:text-foreground rounded transition-colors"
            aria-label={expanded ? 'Colapsar' : 'Expandir'}
          >
            <motion.span
              animate={{ rotate: expanded ? 90 : 0 }}
              transition={{ duration: 0.2 }}
              className="inline-block"
            >
              <ChevronDown className="w-4 h-4" />
            </motion.span>
          </motion.button>
        )}

        <div className="flex items-center gap-2 flex-1 min-w-0">
          <span className="flex-shrink-0">{typeIcons[node.type]}</span>
          <div className="flex-1 min-w-0 flex items-center gap-2">
            <span className={`text-sm font-medium truncate ${isSelected ? 'text-primary' : 'text-foreground'}`}>
              {node.name}
            </span>
            <span className="text-xs text-muted-foreground font-mono truncate flex-1">{node.value}</span>
          </div>
        </div>

        <div className="flex items-center gap-1 flex-shrink-0">
          {node.copyable !== false && (
            <motion.button
              onClick={handleCopy}
              className="p-1.5 rounded text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-all"
              aria-label={`Copiar ${node.value}`}
              title="Copiar valor"
            >
              {copied ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              ) : (
                <Copy className="w-4 h-4" />
              )}
            </motion.button>
          )}
          {node.analysis && (
            <motion.button
              onClick={(e) => { e.stopPropagation(); onNodeClick?.(node); }}
              className="p-1.5 rounded text-muted-foreground hover:text-blue-400 hover:bg-blue-500/10 transition-all"
              aria-label="Ver análisis detallado"
              title="Ver análisis"
            >
              <Search className="w-4 h-4" />
            </motion.button>
          )}
        </div>
      </div>

      <AnimatePresence>
        {expanded && hasChildren && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="space-y-0.5">
              {node.children!.map((child, idx) => (
                <ResourceTreeNodeComponent
                  key={child.id}
                  node={child}
                  depth={depth + 1}
                  onNodeClick={onNodeClick}
                  onCopy={onCopy}
                  selectedNodeId={selectedNodeId}
                  animationDelay={animationDelay + idx + 1}
                />
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ============================================================================
// Analysis Detail Panel
// ============================================================================
interface AnalysisDetailProps {
  node: ResourceTreeNode | null;
  onClose: () => void;
}

function AnalysisDetail({ node, onClose }: AnalysisDetailProps) {
  if (!node) return null;

  return (
    <motion.div
      initial={{ opacity: 0, x: 50 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 50 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="analysis-title"
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 20 }}
        className="bg-card border border-border rounded-xl max-w-3xl w-full max-h-[85vh] overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-4 border-b border-border">
          <div className="flex items-center gap-3">
            {typeIcons[node.type]}
            <div>
              <h3 id="analysis-title" className="font-semibold text-foreground">{node.name}</h3>
              <p className="text-xs text-muted-foreground font-mono">{node.value}</p>
            </div>
            <Badge variant="outline" className="text-xs">{typeLabels[node.type]}</Badge>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="w-5 h-5" />
          </Button>
        </div>

        <ScrollArea className="flex-1 p-4 space-y-4">
          {node.analysis && (
            <div className="space-y-3">
              <h4 className="text-sm font-medium text-foreground flex items-center gap-2">
                <Info className="w-4 h-4 text-primary" />
                Análisis Detallado
              </h4>
              <div className="prose prose-sm max-w-none text-muted-foreground bg-muted/30 rounded-lg p-4 border border-border">
                {node.analysis.split('\n').map((line, i) => (
                  <p key={i} className="whitespace-pre-wrap">{line}</p>
                ))}
              </div>
            </div>
          )}

          {node.metadata && Object.keys(node.metadata).length > 0 && (
            <div className="space-y-3">
              <h4 className="text-sm font-medium text-foreground flex items-center gap-2">
                <Database className="w-4 h-4 text-primary" />
                Metadatos
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {Object.entries(node.metadata).map(([key, value]) => (
                  <div key={key} className="bg-muted/30 rounded-lg p-3 border border-border">
                    <p className="text-xs text-muted-foreground uppercase tracking-wider">{key}</p>
                    <p className="text-sm font-mono text-foreground break-all">{String(value)}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="flex items-center gap-2 pt-2 border-t border-border">
            <Button
              variant="outline"
              size="sm"
              onClick={() => { navigator.clipboard.writeText(node.value); toast.success('Copiado al portapapeles'); onClose(); }}
              className="gap-1"
            >
              <Copy className="w-3.5 h-3.5" />
              Copiar Valor
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => { navigator.clipboard.writeText(JSON.stringify(node.metadata, null, 2)); toast.success('Metadatos copiados'); }}
              className="gap-1"
            >
              <ClipboardList className="w-3.5 h-3.5" />
              Copiar Metadatos
            </Button>
          </div>
        </ScrollArea>
      </motion.div>
    </motion.div>
  );
}

// ============================================================================
// Forensic Site Modal
// ============================================================================
interface ForensicSiteProps {
  result: UrlScanResult | null;
  onClose: () => void;
}

function ForensicSite({ result, onClose }: ForensicSiteProps) {
  if (!result) return null;

  const [activeTab, setActiveTab] = useState<'overview' | 'network' | 'security' | 'tech' | 'dns' | 'whois' | 'threats' | 'raw'>('overview');

  const tabs = [
    { id: 'overview', label: 'Resumen', icon: Shield },
    { id: 'network', label: 'Red', icon: Network },
    { id: 'security', label: 'Seguridad', icon: Lock },
    { id: 'tech', label: 'Tecnologías', icon: Cpu },
    { id: 'dns', label: 'DNS', icon: Database },
    { id: 'whois', label: 'WHOIS', icon: FileText },
    { id: 'threats', label: 'Amenazas', icon: AlertTriangle },
    { id: 'raw', label: 'Datos Crudos', icon: Terminal },
  ];

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="forensic-title"
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 20 }}
        className="bg-card border border-border rounded-xl max-w-5xl w-full max-h-[90vh] overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-4 border-b border-border bg-muted/30">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h2 id="forensic-title" className="text-lg font-bold text-foreground">Forensic Site Analysis</h2>
              <p className="text-xs text-muted-foreground font-mono">{result.url}</p>
            </div>
            <Badge variant="outline" className={`${riskColors[result.analysis?.riskLevel || 'medio'].text} ${riskColors[result.analysis?.riskLevel || 'medio'].bg} ${riskColors[result.analysis?.riskLevel || 'medio'].border}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${riskColors[result.analysis?.riskLevel || 'medio'].dot} mr-1.5`} />
              Riesgo: {(result.analysis?.riskLevel || 'medio').toUpperCase()}
            </Badge>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="w-5 h-5" />
          </Button>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 overflow-hidden">
          <TabsList className="grid w-full grid-cols-8 p-2 bg-muted/30 border-b border-border">
            {tabs.map((tab) => (
              <TabsTrigger key={tab.id} value={tab.id} className="text-xs gap-1 h-8 px-2">
                <tab.icon className="w-3.5 h-3.5" />
                {tab.label}
              </TabsTrigger>
            ))}
          </TabsList>

          <TabsContent value="overview" className="flex-1 overflow-auto p-4 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Card className="border-border bg-muted/30">
                <CardContent className="p-4">
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">URL Objetivo</p>
                  <p className="text-sm font-mono text-foreground break-all">{result.url}</p>
                </CardContent>
              </Card>
              <Card className="border-border bg-muted/30">
                <CardContent className="p-4">
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Dominio</p>
                  <p className="text-sm font-mono text-foreground">{result.domain || 'N/A'}</p>
                </CardContent>
              </Card>
              <Card className="border-border bg-muted/30">
                <CardContent className="p-4">
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">IP</p>
                  <p className="text-sm font-mono text-foreground">{result.ip || 'Pendiente de resolución'}</p>
                </CardContent>
              </Card>
            </div>

            <Card className="border-border">
              <CardHeader>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Info className="w-4 h-4 text-primary" />
                  Hallazgos de Seguridad
                </CardTitle>
              </CardHeader>
              <CardContent>
                {result.analysis?.findings.length ? (
                  <div className="space-y-2">
                    {result.analysis.findings.map((finding, idx) => (
                      <div key={idx} className="flex items-start gap-3 p-3 rounded-lg bg-muted/30 border border-border">
                        {finding.severity === 'critical' && <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />}
                        {finding.severity === 'warning' && <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />}
                        {finding.severity === 'info' && <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />}
                        <div className="flex-1">
                          <p className="text-sm text-foreground">{finding.description}</p>
                          {finding.evidence && (
                            <p className="text-xs text-muted-foreground font-mono mt-1 truncate">{finding.evidence}</p>
                          )}
                        </div>
                        <Badge variant="outline" className={`text-xs ${
                          finding.severity === 'critical' ? 'text-red-400 border-red-500/30 bg-red-500/10' :
                          finding.severity === 'warning' ? 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10' :
                          'text-blue-400 border-blue-500/30 bg-blue-500/10'
                        }`}>
                          {finding.severity.toUpperCase()}
                        </Badge>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No se detectaron hallazgos significativos</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="network" className="flex-1 overflow-auto p-4 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="border-border">
                <CardHeader>
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <Network className="w-4 h-4 text-primary" />
                    Redirecciones
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {result.redirects && result.redirects.length > 0 ? (
                    <ul className="space-y-2">
                      {result.redirects.map((r, i) => (
                        <li key={i} className="flex items-center gap-2 text-sm font-mono text-foreground bg-muted/30 p-2 rounded">
                          <span className="text-muted-foreground">{i + 1}.</span>
                          <a href={r} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300 truncate flex-1">{r}</a>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-sm text-muted-foreground">Sin redirecciones detectadas</p>
                  )}
                </CardContent>
              </Card>

              <Card className="border-border">
                <CardHeader>
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <Server className="w-4 h-4 text-primary" />
                    Subdominios
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {result.subdomains && result.subdomains.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {result.subdomains.map((s, i) => (
                        <Badge key={i} variant="outline" className="text-xs font-mono cursor-pointer hover:bg-primary/10 hover:text-primary transition-colors"
                          onClick={() => navigator.clipboard.writeText(s)}>
                          {s}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">No se encontraron subdominios</p>
                  )}
                </CardContent>
              </Card>
            </div>

            <Card className="border-border">
              <CardHeader>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Globe className="w-4 h-4 text-primary" />
                  Headers HTTP
                </CardTitle>
              </CardHeader>
              <CardContent>
                {result.headers && Object.keys(result.headers).length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-64 overflow-y-auto">
                    {Object.entries(result.headers).map(([key, value]) => (
                      <div key={key} className="bg-muted/30 p-2 rounded border border-border">
                        <p className="text-xs font-medium text-muted-foreground">{key}</p>
                        <p className="text-xs font-mono text-foreground truncate">{value}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">Headers no disponibles</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="security" className="flex-1 overflow-auto p-4 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="border-border">
                <CardHeader>
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <Lock className="w-4 h-4 text-primary" />
                    Certificado SSL/TLS
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {result.ssl ? (
                    <div className="space-y-3">
                      <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 border border-border">
                        <div className={`w-3 h-3 rounded-full ${result.ssl.valid ? 'bg-emerald-500' : 'bg-red-500'}`} />
                        <span className="text-sm font-medium">{result.ssl.valid ? 'Válido' : 'Inválido / Expirado'}</span>
                      </div>
                      {result.ssl.issuer && (
                        <div className="bg-muted/30 p-3 rounded border border-border">
                          <p className="text-xs text-muted-foreground">Emisor</p>
                          <p className="text-sm font-mono text-foreground">{result.ssl.issuer}</p>
                        </div>
                      )}
                      {result.ssl.expires && (
                        <div className="bg-muted/30 p-3 rounded border border-border">
                          <p className="text-xs text-muted-foreground">Expira</p>
                          <p className="text-sm font-mono text-foreground">{new Date(result.ssl.expires).toLocaleDateString('es-ES')}</p>
                        </div>
                      )}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">Información SSL no disponible</p>
                  )}
                </CardContent>
              </Card>

              <Card className="border-border">
                <CardHeader>
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-primary" />
                    Inteligencia de Amenazas
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {result.threatIntel ? (
                    <div className="space-y-3">
                      <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 border border-border">
                        <div className={`w-3 h-3 rounded-full ${result.threatIntel.malicious ? 'bg-red-500' : 'bg-emerald-500'}`} />
                        <span className="text-sm font-medium">
                          {result.threatIntel.malicious ? 'MALICIOSO' : 'LIMPIO'}
                        </span>
                        <Badge variant="outline" className="ml-auto text-xs font-mono">
                          Score: {result.threatIntel.score}/100
                        </Badge>
                      </div>
                      {result.threatIntel.categories.length > 0 && (
                        <div>
                          <p className="text-xs text-muted-foreground mb-2">Categorías detectadas</p>
                          <div className="flex flex-wrap gap-2">
                            {result.threatIntel.categories.map((c, i) => (
                              <Badge key={i} variant="outline" className="text-xs text-red-400 border-red-500/30 bg-red-500/10">
                                {c}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                      <div className="bg-muted/30 p-3 rounded border border-border">
                        <p className="text-xs text-muted-foreground">Fuentes</p>
                        <p className="text-sm text-foreground">{result.threatIntel.sources.join(', ')}</p>
                      </div>
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">Análisis de amenazas pendiente</p>
                  )}
                </CardContent>
              </Card>
            </div>

            <Card className="border-border">
              <CardHeader>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Unlock className="w-4 h-4 text-primary" />
                  Recomendaciones de Seguridad
                </CardTitle>
              </CardHeader>
              <CardContent>
                {result.analysis?.recommendations.length ? (
                  <ol className="space-y-2">
                    {result.analysis.recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-3 p-3 rounded-lg bg-muted/30 border border-border">
                        <span className="flex-shrink-0 w-6 h-6 rounded-full bg-primary/10 text-primary text-xs font-bold flex items-center justify-center">{i + 1}</span>
                        <p className="text-sm text-foreground">{rec}</p>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <p className="text-sm text-muted-foreground">Sin recomendaciones específicas</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="tech" className="flex-1 overflow-auto p-4 space-y-4">
            <Card className="border-border">
              <CardHeader>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-primary" />
                  Stack Tecnológico Detectado
                </CardTitle>
              </CardHeader>
              <CardContent>
                {result.technologies && result.technologies.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {result.technologies.map((tech, i) => (
                      <Badge key={i} variant="outline" className="text-xs cursor-pointer hover:bg-primary/10 hover:text-primary transition-colors"
                        onClick={() => navigator.clipboard.writeText(tech)}>
                        {tech}
                      </Badge>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No se detectaron tecnologías específicas</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="dns" className="flex-1 overflow-auto p-4 space-y-4">
            <Card className="border-border">
              <CardHeader>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Database className="w-4 h-4 text-primary" />
                  Registros DNS
                </CardTitle>
              </CardHeader>
              <CardContent>
                {result.dnsRecords && Object.keys(result.dnsRecords).length > 0 ? (
                  <div className="space-y-3">
                    {Object.entries(result.dnsRecords).map(([type, records]) => (
                      <div key={type} className="bg-muted/30 p-3 rounded border border-border">
                        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">{type}</p>
                        <div className="flex flex-wrap gap-2">
                          {records.map((r, i) => (
                            <Badge key={i} variant="secondary" className="text-xs font-mono cursor-pointer hover:bg-primary/10 hover:text-primary transition-colors"
                              onClick={() => navigator.clipboard.writeText(r)}>
                              {r}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">Registros DNS no disponibles</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="whois" className="flex-1 overflow-auto p-4 space-y-4">
            <Card className="border-border">
              <CardHeader>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <FileText className="w-4 h-4 text-primary" />
                  Información WHOIS
                </CardTitle>
              </CardHeader>
              <CardContent>
                {result.whois && Object.keys(result.whois).length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {Object.entries(result.whois).map(([key, value]) => (
                      <div key={key} className="bg-muted/30 p-3 rounded border border-border">
                        <p className="text-xs text-muted-foreground uppercase tracking-wider">{key}</p>
                        <p className="text-sm font-mono text-foreground break-all">{value || 'N/A'}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">Información WHOIS no disponible</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="threats" className="flex-1 overflow-auto p-4 space-y-4">
            <Card className="border-border">
              <CardHeader>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-primary" />
                  Análisis de Amenazas Detallado
                </CardTitle>
              </CardHeader>
              <CardContent>
                {result.analysis?.findings.length ? (
                  <div className="space-y-3">
                    {result.analysis.findings.map((finding, idx) => (
                      <div key={idx} className="p-4 rounded-lg border border-border bg-muted/30">
                        <div className="flex items-start gap-3">
                          {finding.severity === 'critical' && <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />}
                          {finding.severity === 'warning' && <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />}
                          {finding.severity === 'info' && <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />}
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-sm font-medium text-foreground">{finding.type}</span>
                              <Badge variant="outline" className={`text-xs ${
                                finding.severity === 'critical' ? 'text-red-400 border-red-500/30 bg-red-500/10' :
                                finding.severity === 'warning' ? 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10' :
                                'text-blue-400 border-blue-500/30 bg-blue-500/10'
                              }`}>
                                {finding.severity.toUpperCase()}
                              </Badge>
                            </div>
                            <p className="text-sm text-foreground">{finding.description}</p>
                            {finding.evidence && (
                              <p className="text-xs text-muted-foreground font-mono mt-2 truncate">{finding.evidence}</p>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No se detectaron amenazas</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="raw" className="flex-1 overflow-auto p-4">
            <Card className="border-border h-full">
              <CardHeader>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-primary" />
                  Datos Crudos Completos (JSON)
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <ScrollArea className="h-[500px]">
                  <pre className="p-4 text-[10px] font-mono text-foreground overflow-x-auto">
                    {JSON.stringify(result, null, 2)}
                  </pre>
                </ScrollArea>
                <div className="p-3 border-t border-border flex justify-end">
                  <Button variant="outline" size="sm" onClick={() => {
                    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
                    toast.success('JSON copiado al portapapeles');
                  }} className="gap-1">
                    <Copy className="w-3.5 h-3.5" />
                    Copiar JSON Completo
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </motion.div>
    </motion.div>
  );
}

// ============================================================================
// Main URL Sandbox Page
// ============================================================================
export default function UrlSandboxPage() {
  const [urlInput, setUrlInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<UrlScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState<string>('');
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [selectedTreeNode, setSelectedTreeNode] = useState<ResourceTreeNode | null>(null);
  const [showForensic, setShowForensic] = useState(false);
  const [activeTab, setActiveTab] = useState<'scan' | 'history'>('scan');

  const buildResourceTree = useCallback((result: UrlScanResult): ResourceTreeNode[] => {
    const nodes: ResourceTreeNode[] = [];

    // Root URL node
    nodes.push({
      id: 'root-url',
      name: 'URL Principal',
      type: 'url',
      value: result.url,
      clickable: true,
      copyable: true,
      analysis: `URL analizada: ${result.url}\nDominio: ${result.domain}\nIP: ${result.ip || 'No resuelta'}\nNivel de riesgo: ${result.analysis?.riskLevel || 'medio'}\n\nEsta es la URL objetivo del escaneo. Todos los demás nodos del árbol derivan de este punto de entrada.`,
      children: []
    });

    // Domain node
    if (result.domain) {
      nodes.push({
        id: 'domain',
        name: 'Dominio',
        type: 'domain',
        value: result.domain,
        clickable: true,
        copyable: true,
        analysis: `Dominio principal: ${result.domain}\n\nEl dominio es la identidad legible por humanos que se resuelve a una dirección IP. El análisis del dominio incluye reputación, antigüedad, registrador y configuración DNS.`,
        metadata: { registrar: result.whois?.registrar, created: result.whois?.created, expires: result.whois?.expires },
        children: []
      });
    }

    // IP node
    if (result.ip) {
      nodes.push({
        id: 'ip',
        name: 'Dirección IP',
        type: 'ip',
        value: result.ip,
        clickable: true,
        copyable: true,
        analysis: `Dirección IP resuelta: ${result.ip}\n\nEsta es la dirección IP a la que resuelve el dominio. Permite geolocalización, análisis de reputación de IP, detección de hosting compartido y correlación con otras amenazas.`,
        children: []
      });
    }

    // SSL node
    if (result.ssl) {
      nodes.push({
        id: 'ssl',
        name: 'Certificado SSL/TLS',
        type: 'ssl',
        value: result.ssl.valid ? 'Válido' : 'Inválido / Expirado',
        clickable: true,
        copyable: true,
        analysis: `Certificado SSL/TLS para ${result.domain}\n\nVálido: ${result.ssl.valid ? 'Sí' : 'No'}\nEmisor: ${result.ssl.issuer || 'Desconocido'}\nExpira: ${result.ssl.expires ? new Date(result.ssl.expires).toLocaleDateString('es-ES') : 'Desconocido'}\n\nUn certificado válido garantiza comunicaciones cifradas. Verificar la cadena de confianza, fechas de expiración y algoritmos criptográficos.`,
        metadata: { issuer: result.ssl.issuer, expires: result.ssl.expires, valid: result.ssl.valid },
        children: []
      });
    }

    // Technologies
    if (result.technologies && result.technologies.length > 0) {
      const techChildren: ResourceTreeNode[] = result.technologies.map((tech, i) => ({
        id: `tech-${i}`,
        name: tech,
        type: 'technology',
        value: tech,
        clickable: true,
        copyable: true,
        analysis: `Tecnología detectada: ${tech}\n\nEsta tecnología forma parte del stack del servidor/aplicación. Conocer el stack permite identificar vulnerabilidades conocidas (CVEs), versiones desactualizadas y superficie de ataque.`,
      }));
      nodes.push({
        id: 'technologies',
        name: `Tecnologías (${result.technologies.length})`,
        type: 'technology',
        value: `${result.technologies.length} detectadas`,
        clickable: false,
        children: techChildren,
      });
    }

    // Headers
    if (result.headers && Object.keys(result.headers).length > 0) {
      const headerChildren: ResourceTreeNode[] = Object.entries(result.headers).map(([key, value], i) => ({
        id: `header-${i}`,
        name: key,
        type: 'header',
        value: value,
        clickable: true,
        copyable: true,
        analysis: `Header HTTP: ${key}\nValor: ${value}\n\nLos headers HTTP revelan configuración del servidor, políticas de seguridad (CSP, HSTS, X-Frame-Options), información de versión y cookies. Headers de seguridad faltantes o mal configurados son hallazgos comunes.`,
      }));
      nodes.push({
        id: 'headers',
        name: `Headers HTTP (${Object.keys(result.headers).length})`,
        type: 'header',
        value: `${Object.keys(result.headers).length} headers`,
        clickable: false,
        children: headerChildren,
      });
    }

    // Redirects
    if (result.redirects && result.redirects.length > 0) {
      const redirectChildren: ResourceTreeNode[] = result.redirects.map((r, i) => ({
        id: `redirect-${i}`,
        name: `Paso ${i + 1}`,
        type: 'redirect',
        value: r,
        clickable: true,
        copyable: true,
        analysis: `Redirección ${i + 1}: ${r}\n\nLas cadenas de redirección pueden ocultar el destino final, permitir tracking, o ser usadas en ataques de phishing. Analizar cada salto es crucial para entender el flujo real.`,
      }));
      nodes.push({
        id: 'redirects',
        name: `Redirecciones (${result.redirects.length})`,
        type: 'redirect',
        value: `${result.redirects.length} saltos`,
        clickable: false,
        children: redirectChildren,
      });
    }

    // Subdomains
    if (result.subdomains && result.subdomains.length > 0) {
      const subdomainChildren: ResourceTreeNode[] = result.subdomains.slice(0, 20).map((s, i) => ({
        id: `subdomain-${i}`,
        name: s,
        type: 'subdomain',
        value: s,
        clickable: true,
        copyable: true,
        analysis: `Subdominio: ${s}\nDominio principal: ${result.domain}\n\nLos subdominios expanden la superficie de ataque. Pueden exponer entornos de desarrollo, APIs, paneles de administración o servicios olvidados. Cada subdominio debe ser escaneado independientemente.`,
      }));
      nodes.push({
        id: 'subdomains',
        name: `Subdominios (${result.subdomains.length})`,
        type: 'subdomain',
        value: `${result.subdomains.length} encontrados`,
        clickable: false,
        children: subdomainChildren,
      });
    }

    // DNS Records
    if (result.dnsRecords && Object.keys(result.dnsRecords).length > 0) {
      const dnsChildren: ResourceTreeNode[] = Object.entries(result.dnsRecords).flatMap(([type, records]) =>
        records.map((r, i) => ({
          id: `dns-${type}-${i}`,
          name: `${type} #${i + 1}`,
          type: 'dns',
          value: r,
          clickable: true,
          copyable: true,
          analysis: `Registro DNS: ${type}\nValor: ${r}\n\nLos registros DNS revelan infraestructura: servidores de correo (MX), nombres de servidores (NS), alias (CNAME), direcciones IP (A/AAAA), y configuración de seguridad (TXT para SPF/DMARC/DKIM).`,
        }))
      );
      nodes.push({
        id: 'dns',
        name: `Registros DNS (${Object.keys(result.dnsRecords).length} tipos)`,
        type: 'dns',
        value: `${Object.keys(result.dnsRecords).length} tipos de registros`,
        clickable: false,
        children: dnsChildren,
      });
    }

    // Threats
    if (result.threatIntel && (result.threatIntel.malicious || result.threatIntel.categories.length > 0)) {
      const threatChildren: ResourceTreeNode[] = [
        {
          id: 'threat-score',
          name: 'Puntuación de Riesgo',
          type: 'threat',
          value: `${result.threatIntel.score}/100`,
          clickable: true,
          copyable: true,
          analysis: `Puntuación de amenaza: ${result.threatIntel.score}/100\n\nBasado en múltiples fuentes de inteligencia de amenazas. Puntuaciones >70 indican alta probabilidad de actividad maliciosa.`,
        },
        ...result.threatIntel.categories.map((cat, i) => ({
          id: `threat-cat-${i}`,
          name: cat,
          type: 'threat',
          value: cat,
          clickable: true,
          copyable: true,
          analysis: `Categoría de amenaza: ${cat}\n\nEsta categoría clasifica el tipo de actividad maliciosa detectada (malware, phishing, botnet, spam, etc.). Permite priorizar respuesta y aplicar contramedidas específicas.`,
        }))
      ];
      nodes.push({
        id: 'threats',
        name: `Amenazas Detectadas`,
        type: 'threat',
        value: result.threatIntel.malicious ? 'MALICIOSO' : 'Sospechoso',
        clickable: false,
        children: threatChildren,
      });
    }

    // WHOIS
    if (result.whois && Object.keys(result.whois).length > 0) {
      const whoisChildren: ResourceTreeNode[] = Object.entries(result.whois).map(([key, value], i) => ({
        id: `whois-${i}`,
        name: key.charAt(0).toUpperCase() + key.slice(1),
        type: 'whois',
        value: value || 'N/A',
        clickable: true,
        copyable: true,
        analysis: `WHOIS ${key}: ${value || 'No disponible'}\n\nWHOIS proporciona información de registro del dominio: registrador, fechas de creación/expiración, contactos administrativos/técnicos. Útil para atribución, detección de dominios recién registrados (typosquatting) y verificación de propiedad.`,
      }));
      nodes.push({
        id: 'whois',
        name: 'Información WHOIS',
        type: 'whois',
        value: `${Object.keys(result.whois).length} campos`,
        clickable: false,
        children: whoisChildren,
      });
    }

    // Analysis findings
    if (result.analysis?.findings.length) {
      const findingChildren: ResourceTreeNode[] = result.analysis.findings.map((f, i) => ({
        id: `finding-${i}`,
        name: `${f.type} [${f.severity}]`,
        type: 'threat',
        value: f.description.substring(0, 60) + '...',
        clickable: true,
        copyable: true,
        analysis: `Hallazgo de seguridad: ${f.type}\nSeveridad: ${f.severity.toUpperCase()}\nDescripción: ${f.description}\nEvidencia: ${f.evidence || 'N/A'}\n\nEste hallazgo fue identificado durante el escaneo automático. Revisar la evidencia y aplicar las recomendaciones correspondientes.`,
      }));
      nodes.push({
        id: 'findings',
        name: `Hallazgos (${result.analysis.findings.length})`,
        type: 'threat',
        value: `${result.analysis.findings.length} detectados`,
        clickable: false,
        children: findingChildren,
      });
    }

    return nodes;
  }, []);

  const handleScan = async () => {
    if (!urlInput.trim()) {
      toast.error('Ingrese una URL válida');
      return;
    }

    let targetUrl = urlInput.trim();
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'https://' + targetUrl;
    }

    try {
      new URL(targetUrl);
    } catch {
      toast.error('URL inválida');
      return;
    }

    setIsScanning(true);
    setScanError(null);
    setScanResult(null);
    setScanProgress('Iniciando escaneo...');
    setSelectedTreeNode(null);

    try {
      const steps = [
        'Resolviendo DNS...',
        'Analizando certificados SSL...',
        'Detectando tecnologías...',
        'Recopilando headers HTTP...',
        'Escaneando subdominios...',
        'Consultando inteligencia de amenazas...',
        'Analizando registros DNS...',
        'Obteniendo información WHOIS...',
        'Generando reporte forense...',
      ];

      for (let i = 0; i < steps.length; i++) {
        setScanProgress(steps[i]);
        await new Promise(r => setTimeout(r, 800));
      }

      const response = await fetch('/api/url-sandbox', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl, deepScan: true }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Error en el escaneo');
      }

      const data = await response.json();
      const result = data.result;

      // Build resource tree
      const resourceTree = buildResourceTree(result);
      result.resourceTree = resourceTree;

      setScanResult(result);
      setScanProgress('');

      // Add to history
      const historyItem: ScanHistoryItem = {
        id: `scan_${Date.now()}`,
        url: targetUrl,
        domain: result.domain || new URL(targetUrl).hostname,
        riskLevel: result.analysis?.riskLevel || 'medio',
        timestamp: new Date().toISOString(),
        result,
      };
      setHistory(prev => [historyItem, ...prev.slice(0, 49)]);

      toast.success(`Escaneo completado - Riesgo: ${(result.analysis?.riskLevel || 'medio').toUpperCase()}`);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Error desconocido';
      setScanError(errorMessage);
      toast.error(errorMessage);
    } finally {
      setIsScanning(false);
    }
  };

  const handleHistorySelect = (item: ScanHistoryItem) => {
    setScanResult(item.result);
    setSelectedTreeNode(null);
    setShowForensic(false);
    setActiveTab('scan');
  };

  const handleClearHistory = () => {
    setHistory([]);
    toast.success('Historial limpiado');
  };

  const handleExportReport = () => {
    if (!scanResult) return;
    const report = `# URL Sandbox - Reporte Forense\n\n**URL:** ${scanResult.url}\n**Dominio:** ${scanResult.domain}\n**IP:** ${scanResult.ip}\n**Riesgo:** ${scanResult.analysis?.riskLevel}\n**Fecha:** ${new Date().toLocaleString('es-ES')}\n\n---\n\n## Hallazgos\n${scanResult.analysis?.findings.map((f, i) => `${i + 1}. [${f.severity.toUpperCase()}] ${f.type}: ${f.description}`).join('\n') || 'Ninguno'}\n\n## Recomendaciones\n${scanResult.analysis?.recommendations.map((r, i) => `${i + 1}. ${r}`).join('\n') || 'Ninguna'}\n\n---\n\n${JSON.stringify(scanResult, null, 2)}`;
    navigator.clipboard.writeText(report);
    toast.success('Reporte copiado al portapapeles');
  };

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
                <h1 className="text-xl font-bold text-foreground tracking-tight">URL Sandbox</h1>
                <p className="text-xs text-muted-foreground">Análisis Forense de URLs • Resource Tree Interactivo</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <NextLink href="/" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                ← Dashboard
              </NextLink>
              <ThemeSelector compact />
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="scan">
              <Search className="w-4 h-4 mr-2" />
              Nuevo Escaneo
            </TabsTrigger>
            <TabsTrigger value="history">
              <ClipboardList className="w-4 h-4 mr-2" />
              Historial ({history.length})
            </TabsTrigger>
          </TabsList>

          {/* Scan Tab */}
          <TabsContent value="scan" className="space-y-6">
            {/* Input Section */}
            <Card className="border-border bg-card/60">
              <CardHeader>
                <CardTitle className="text-base text-foreground flex items-center gap-2">
                  <Globe className="w-4 h-4 text-primary" />
                  URL a Analizar
                </CardTitle>
                <CardDescription className="text-xs text-muted-foreground">
                  Ingrese una URL para realizar análisis forense completo: DNS, SSL, tecnologías, headers, subdominios, amenazas y WHOIS
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      placeholder="https://ejemplo.com o ejemplo.com"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                      className="pl-10 bg-muted/30 border-border text-sm"
                      disabled={isScanning}
                    />
                  </div>
                  <Button
                    onClick={handleScan}
                    disabled={isScanning || !urlInput.trim()}
                    className="bg-primary hover:bg-primary/90 text-white font-semibold gap-2 h-10 px-6 disabled:opacity-40"
                    style={{ minWidth: '160px' }}
                  >
                    {isScanning ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Escaneando...
                      </>
                    ) : (
                      <>
                        <Search className="w-4 h-4" />
                        Iniciar Escaneo
                      </>
                    )}
                  </Button>
                </div>

                {isScanning && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-3 p-3 rounded-lg bg-primary/5 border border-primary/8">
                      <Loader2 className="w-4 h-4 animate-spin text-primary" />
                      <span className="text-sm text-primary">{scanProgress}</span>
                      <div className="ml-auto flex-1 max-w-xs">
                        <Progress value={Math.floor(Math.random() * 100)} className="h-1.5" />
                      </div>
                    </div>
                  </div>
                )}

                {scanError && (
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                    <AlertCircle className="w-4 h-4 inline mr-1" />
                    Error: {scanError}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Results Section */}
            {scanResult && (
              <AnimatePresence>
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-6"
                >
                  {/* Summary Cards */}
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                    <Card className="border-border bg-card/60">
                      <CardContent className="p-4 text-center">
                        <p className="text-2xl font-bold text-foreground">{scanResult.domain || 'N/A'}</p>
                        <p className="text-xs text-muted-foreground">Dominio</p>
                      </CardContent>
                    </Card>
                    <Card className="border-border bg-card/60">
                      <CardContent className="p-4 text-center">
                        <p className="text-2xl font-bold text-foreground">{scanResult.ip || '—'}</p>
                        <p className="text-xs text-muted-foreground">IP</p>
                      </CardContent>
                    </Card>
                    <Card className={`border-border bg-card/60 ${riskColors[scanResult.analysis?.riskLevel || 'medio'].border}`}>
                      <CardContent className="p-4 text-center">
                        <div className="flex items-center justify-center gap-2 mb-1">
                          <span className={`w-2 h-2 rounded-full ${riskColors[scanResult.analysis?.riskLevel || 'medio'].dot}`} />
                          <span className={`text-sm font-semibold ${riskColors[scanResult.analysis?.riskLevel || 'medio'].text}`}>
                            {(scanResult.analysis?.riskLevel || 'medio').toUpperCase()}
                          </span>
                        </div>
                        <p className="text-xs text-muted-foreground">Nivel de Riesgo</p>
                      </CardContent>
                    </Card>
                    <Card className="border-border bg-card/60">
                      <CardContent className="p-4 text-center">
                        <p className="text-2xl font-bold text-foreground">{scanResult.threatIntel?.score || 0}/100</p>
                        <p className="text-xs text-muted-foreground">Threat Score</p>
                      </CardContent>
                    </Card>
                    <Card className="border-border bg-card/60">
                      <CardContent className="p-4 text-center">
                        <p className="text-2xl font-bold text-foreground">{scanResult.technologies?.length || 0}</p>
                        <p className="text-xs text-muted-foreground">Tecnologías</p>
                      </CardContent>
                    </Card>
                  </div>

                  {/* Resource Tree */}
                  <Card className="border-border bg-card/60">
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <CardTitle className="text-base text-foreground flex items-center gap-2">
                            <Layers className="w-4 h-4 text-primary" />
                            Resource Tree Interactivo
                          </CardTitle>
                          <CardDescription className="text-xs text-muted-foreground">
                            Árbol de recursos navegable. Clic en nodo = expandir/ver análisis • Ctrl+C = copiar valor • Botón 🔍 = análisis detallado
                          </CardDescription>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setShowForensic(true)}
                            className="bg-emerald-600 hover:bg-emerald-700 border-emerald-500/30 text-emerald-400 hover:text-white gap-1"
                          >
                            <Bug className="w-3.5 h-3.5" />
                            Forensic Site
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={handleExportReport}
                            className="gap-1"
                          >
                            <Download className="w-3.5 h-3.5" />
                            Exportar
                          </Button>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent className="p-0">
                      <ScrollArea className="h-[500px] max-h-[60vh] p-4">
                        {scanResult.resourceTree && scanResult.resourceTree.length > 0 ? (
                          <div className="space-y-0.5">
                            {scanResult.resourceTree.map((node, idx) => (
                              <ResourceTreeNodeComponent
                                key={node.id}
                                node={node}
                                onNodeClick={setSelectedTreeNode}
                                onCopy={(value, label) => {
                                  navigator.clipboard.writeText(value);
                                  toast.success(`${label} copiado: ${value.substring(0, 50)}${value.length > 50 ? '...' : ''}`);
                                }}
                                selectedNodeId={selectedTreeNode?.id}
                                animationDelay={idx}
                              />
                            ))}
                          </div>
                        ) : (
                          <div className="flex items-center justify-center h-full text-muted-foreground">
                            <Layers className="w-12 h-12 mb-3 opacity-30" />
                            <p className="text-sm">No hay recursos para mostrar</p>
                          </div>
                        )}
                      </ScrollArea>
                    </CardContent>
                  </Card>

                  {/* Analysis Detail Panel (inline) */}
                  {selectedTreeNode && (
                    <Card className="border-border bg-primary/5 border-primary/10">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-base text-foreground flex items-center gap-2">
                          <MagnifyingGlass className="w-4 h-4 text-primary" />
                          Análisis Detallado: {selectedTreeNode.name}
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-3">
                        {selectedTreeNode.analysis && (
                          <div className="prose prose-sm max-w-none text-muted-foreground bg-muted/30 rounded-lg p-4 border border-border">
                            {selectedTreeNode.analysis.split('\n').map((line, i) => (
                              <p key={i} className="whitespace-pre-wrap">{line}</p>
                            ))}
                          </div>
                        )}
                        {selectedTreeNode.metadata && Object.keys(selectedTreeNode.metadata).length > 0 && (
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                            {Object.entries(selectedTreeNode.metadata).map(([key, value]) => (
                              <div key={key} className="bg-muted/30 rounded-lg p-3 border border-border">
                                <p className="text-xs text-muted-foreground uppercase tracking-wider">{key}</p>
                                <p className="text-sm font-mono text-foreground break-all">{String(value)}</p>
                              </div>
                            ))}
                          </div>
                        )}
                        <div className="flex items-center gap-2 pt-2 border-t border-border">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              navigator.clipboard.writeText(selectedTreeNode.value);
                              toast.success('Copiado al portapapeles');
                            }}
                            className="gap-1"
                          >
                            <Copy className="w-3.5 h-3.5" />
                            Copiar Valor
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              navigator.clipboard.writeText(JSON.stringify(selectedTreeNode.metadata, null, 2));
                              toast.success('Metadatos copiados');
                            }}
                            className="gap-1"
                          >
                            <ClipboardList className="w-3.5 h-3.5" />
                            Copiar Metadatos
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setSelectedTreeNode(null)}
                            className="ml-auto gap-1"
                          >
                            <X className="w-3.5 h-3.5" />
                            Cerrar
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </motion.div>
              </AnimatePresence>
            )}

            {/* Empty State */}
            {!scanResult && !isScanning && (
              <Card className="border-border bg-card/60">
                <CardContent className="py-16 text-center">
                  <Globe className="w-16 h-16 mx-auto mb-4 opacity-30 text-muted-foreground" />
                  <h3 className="text-lg font-medium text-foreground mb-2">Listo para analizar</h3>
                  <p className="text-sm text-muted-foreground max-w-md mx-auto">
                    Ingrese una URL arriba para iniciar el escaneo forense completo. El Resource Tree le permitirá navegar
                    todos los artefactos descubiertos con análisis detallado en cada nodo.
                  </p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* History Tab */}
          <TabsContent value="history" className="space-y-4">
            <Card className="border-border bg-card/60">
              <CardHeader className="flex flex-row items-center justify-between pb-3">
                <CardTitle className="text-base text-foreground flex items-center gap-2">
                  <ClipboardList className="w-4 h-4 text-primary" />
                  Historial de Escaneos
                </CardTitle>
                {history.length > 0 && (
                  <Button variant="ghost" size="sm" onClick={handleClearHistory} className="text-red-400 hover:text-red-300">
                    <Trash2 className="w-3.5 h-3.5 mr-1" />
                    Limpiar
                  </Button>
                )}
              </CardHeader>
              <CardContent>
                {history.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                    <ClipboardList className="w-12 h-12 mb-3 opacity-30" />
                    <p className="text-sm">No hay escaneos previos</p>
                  </div>
                ) : (
                  <div className="space-y-2 max-h-[500px] overflow-y-auto">
                    {history.map((item) => (
                      <motion.div
                        key={item.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 border border-border hover:bg-muted/50 transition-colors cursor-pointer"
                        onClick={() => handleHistorySelect(item)}
                      >
                        <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
                          <Globe className="w-5 h-5 text-primary" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-foreground truncate">{item.url}</p>
                          <p className="text-xs text-muted-foreground font-mono">{item.domain}</p>
                        </div>
                        <Badge variant="outline" className={`${riskColors[item.riskLevel].text} ${riskColors[item.riskLevel].bg} ${riskColors[item.riskLevel].border} text-xs`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${riskColors[item.riskLevel].dot} mr-1.5`} />
                          {item.riskLevel.toUpperCase()}
                        </Badge>
                        <span className="text-xs text-muted-foreground font-mono">
                          {new Date(item.timestamp).toLocaleString('es-ES')}
                        </span>
                        <Button variant="ghost" size="sm" className="text-muted-foreground hover:text-foreground">
                          <ExternalLink className="w-4 h-4" />
                        </Button>
                      </motion.div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Analysis Detail Modal */}
      <AnimatePresence>
        {selectedTreeNode && (
          <AnalysisDetail
            node={selectedTreeNode}
            onClose={() => setSelectedTreeNode(null)}
          />
        )}
      </AnimatePresence>

      {/* Forensic Site Modal */}
      <AnimatePresence>
        {showForensic && (
          <ForensicSite
            result={scanResult}
            onClose={() => setShowForensic(false)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}