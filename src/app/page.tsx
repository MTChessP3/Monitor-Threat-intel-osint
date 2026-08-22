'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, AlertTriangle, FileText, Globe, Brain, Download,
  Plus, Trash2, Search, BarChart3, Activity, Eye, ChevronRight,
  Loader2, CheckCircle, XCircle, Menu, X, Zap, Target, TrendingUp,
  BookOpen, Newspaper, Play, RefreshCw, ExternalLink, Pencil, FileDown,
  Upload, CheckSquare, Square, Filter, ListChecks, ToggleLeft, ToggleRight,
  LogOut, User as UserIcon, Lock, Smartphone, Layers, Bug, Send
} from 'lucide-react';
import { ThemeSelector } from '@/components/ThemeSelector';
import { TakeDownPanel } from '@/components/takedown/TakeDownPanel';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { toast } from 'sonner';
import ReactMarkdown from 'react-markdown';
import NextLink from 'next/link';

// Types
interface ReportTemplate {
  id: string;
  name: string;
  content: string;
  isDefault: boolean;
  createdAt: string;
  updatedAt: string;
}

interface NewsSource {
  id: string;
  name: string;
  url: string;
  type: string;
  category: string;
  active: boolean;
  createdAt: string;
  updatedAt: string;
}

interface Threat {
  title: string;
  description: string;
  severity: 'bajo' | 'medio' | 'alto' | 'critico';
  category: string;
}

interface AnalysisResult {
  threats: Threat[];
  overallRiskLevel: 'bajo' | 'medio' | 'alto' | 'critico';
  summary: string;
  recommendations: string[];
  sources: Array<{ title: string; url: string; relevance: string }>;
  rawData?: Array<{ sourceName: string; sourceUrl: string; snippet: string; hostname: string; searchQuery: string; category: string; date: string }>;
  rawDataText?: string;
}

interface Report {
  id: string;
  title: string;
  date: string;
  summary: string;
  threatLevel: string;
  content: string;
  templateId: string | null;
  sourcesUsed: string;
  createdAt: string;
  updatedAt: string;
  template?: { name: string };
}

type ActiveTab = 'panel' | 'plantillas' | 'fuentes' | 'analisis' | 'informes' | 'url-sandbox' | 'takedown';

const threatLevelColors: Record<string, string> = {
  bajo: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  medio: 'bg-yellow-600/15 text-yellow-500 border-yellow-600/20',
  alto: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  critico: 'bg-red-500/20 text-red-400 border-red-500/30',
};

const threatLevelDots: Record<string, string> = {
  bajo: 'bg-emerald-500',
  medio: 'bg-yellow-600',
  alto: 'bg-orange-500',
  critico: 'bg-red-500',
};

const categoryColors: Record<string, string> = {
  seguridad: 'bg-red-500/20 text-red-400',
  politica: 'bg-purple-500/20 text-purple-400',
  economia: 'bg-emerald-500/20 text-emerald-400',
  social: 'bg-sky-500/20 text-sky-400',
};

interface AuthUser {
  id: string;
  name: string;
  email: string;
  role: string;
  mfaEnabled: boolean;
}

export default function Home() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('panel');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Auth state
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [mfaSetupModal, setMfaSetupModal] = useState(false);
  const [mfaQrCode, setMfaQrCode] = useState('');
  const [mfaSecret, setMfaSecret] = useState('');
  const [mfaVerifyCode, setMfaVerifyCode] = useState('');
  const [mfaLoading, setMfaLoading] = useState(false);
  const [disableMfaPassword, setDisableMfaPassword] = useState('');
  const [disableMfaLoading, setDisableMfaLoading] = useState(false);
  const [showDisableMfaDialog, setShowDisableMfaDialog] = useState(false);

  // Check auth session — resilient with caching and retry
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

  // Logout handler
  const handleLogout = async () => {
    try {
      const { clearCachedUser } = await import('@/lib/session-manager');
      clearCachedUser();
      await fetch('/api/auth/logout', { method: 'POST' });
      window.location.href = '/auth/login';
    } catch {
      toast.error('Error al cerrar sesión');
    }
  };

  // MFA Setup handler
  const handleMfaSetup = async () => {
    setMfaLoading(true);
    try {
      const res = await fetch('/api/auth/mfa/setup', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setMfaQrCode(data.qrCode);
        setMfaSecret(data.secret);
        setMfaSetupModal(true);
      } else {
        toast.error('Error al configurar MFA');
      }
    } catch {
      toast.error('Error de conexión');
    } finally {
      setMfaLoading(false);
    }
  };

  // MFA Enable handler
  const handleMfaEnable = async () => {
    if (mfaVerifyCode.length !== 6) {
      toast.error('El código debe tener 6 dígitos');
      return;
    }
    setMfaLoading(true);
    try {
      const res = await fetch('/api/auth/mfa/enable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret: mfaSecret, code: mfaVerifyCode }),
      });
      if (res.ok) {
        toast.success('MFA activado exitosamente');
        setMfaSetupModal(false);
        setMfaVerifyCode('');
        setAuthUser(prev => prev ? { ...prev, mfaEnabled: true } : null);
      } else {
        const data = await res.json();
        toast.error(data.error || 'Código inválido');
      }
    } catch {
      toast.error('Error de conexión');
    } finally {
      setMfaLoading(false);
    }
  };

  // MFA Disable handler
  const handleMfaDisable = async () => {
    if (!disableMfaPassword) {
      toast.error('Ingrese su contraseña');
      return;
    }
    setDisableMfaLoading(true);
    try {
      const res = await fetch('/api/auth/mfa/disable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: disableMfaPassword }),
      });
      if (res.ok) {
        toast.success('MFA desactivado');
        setShowDisableMfaDialog(false);
        setDisableMfaPassword('');
        setAuthUser(prev => prev ? { ...prev, mfaEnabled: false } : null);
      } else {
        const data = await res.json();
        toast.error(data.error || 'Error al desactivar MFA');
      }
    } catch {
      toast.error('Error de conexión');
    } finally {
      setDisableMfaLoading(false);
    }
  };

  // Data states
  const [templates, setTemplates] = useState<ReportTemplate[]>([]);
  const [sources, setSources] = useState<NewsSource[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [totalReports, setTotalReports] = useState(0);

  // Template form
  const [templateName, setTemplateName] = useState('');
  const [templateContent, setTemplateContent] = useState('');
  const [templateIsDefault, setTemplateIsDefault] = useState(false);

  // Source form
  const [sourceName, setSourceName] = useState('');
  const [sourceUrl, setSourceUrl] = useState('');
  const [sourceType, setSourceType] = useState('web');
  const [sourceCategory, setSourceCategory] = useState('seguridad');

  // Source selection for analysis
  const [selectedSourceIds, setSelectedSourceIds] = useState<Set<string>>(new Set());

  // Analysis states
  const [selectedCategories, setSelectedCategories] = useState<Set<string>>(new Set());
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [analysisStep, setAnalysisStep] = useState('');

  // Report generation
  const [selectedTemplateId, setSelectedTemplateId] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatingProgress, setGeneratingProgress] = useState(0);

  // Report preview
  const [previewReport, setPreviewReport] = useState<Report | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);

  // Loading states
  const [loadingTemplates, setLoadingTemplates] = useState(false);
  const [loadingSources, setLoadingSources] = useState(false);
  const [loadingReports, setLoadingReports] = useState(false);

  // Edit report states
  const [editingReport, setEditingReport] = useState<Report | null>(null);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [editAdditionalUrls, setEditAdditionalUrls] = useState('');
  const [editAdditionalNews, setEditAdditionalNews] = useState('');
  const [editAdditionalContext, setEditAdditionalContext] = useState('');
  const [isUpdating, setIsUpdating] = useState(false);

  // File upload state
  const [isUploadingFile, setIsUploadingFile] = useState(false);
  const [uploadedFileName, setUploadedFileName] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Fetch data functions
  const fetchTemplates = useCallback(async () => {
    setLoadingTemplates(true);
    try {
      const res = await fetch('/api/templates');
      if (res.ok) {
        const data = await res.json();
        setTemplates(data);
        // Set default template as selected
        const defaultTpl = data.find((t: ReportTemplate) => t.isDefault);
        if (defaultTpl && !selectedTemplateId) {
          setSelectedTemplateId(defaultTpl.id);
        }
      }
    } catch {
      toast.error('Error al cargar plantillas');
    } finally {
      setLoadingTemplates(false);
    }
  }, [selectedTemplateId]);

  const fetchSources = useCallback(async () => {
    setLoadingSources(true);
    try {
      const res = await fetch('/api/sources');
      if (res.ok) {
        const data = await res.json();
        setSources(data);
      }
    } catch {
      toast.error('Error al cargar fuentes');
    } finally {
      setLoadingSources(false);
    }
  }, []);

  const fetchReports = useCallback(async () => {
    setLoadingReports(true);
    try {
      const res = await fetch('/api/reports?limit=20');
      if (res.ok) {
        const data = await res.json();
        setReports(data.reports);
        setTotalReports(data.total);
      }
    } catch {
      toast.error('Error al cargar informes');
    } finally {
      setLoadingReports(false);
    }
  }, []);

  useEffect(() => {
    fetchTemplates();
    fetchSources();
    fetchReports();
  }, [fetchTemplates, fetchSources, fetchReports]);

  // File upload handler
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const validExtensions = ['.pdf', '.docx', '.txt', '.md'];
    const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    if (!validExtensions.includes(ext)) {
      toast.error('Formato no soportado. Use PDF, DOCX, TXT o MD.');
      return;
    }

    setIsUploadingFile(true);
    try {
      const formData = new FormData();
      formData.append('file', file);

      const res = await fetch('/api/upload-template', {
        method: 'POST',
        body: formData,
      });

      if (res.ok) {
        const data = await res.json();
        setTemplateContent(data.text);
        setUploadedFileName(data.fileName);
        if (!templateName.trim()) {
          setTemplateName(file.name.replace(/\.[^/.]+$/, ''));
        }
        toast.success(`Archivo "${data.fileName}" cargado exitosamente`);
      } else {
        const errorData = await res.json();
        toast.error(errorData.error || 'Error al procesar el archivo');
      }
    } catch {
      toast.error('Error al subir el archivo');
    } finally {
      setIsUploadingFile(false);
      // Reset the file input so the same file can be re-uploaded
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  // Template CRUD
  const handleSaveTemplate = async () => {
    if (!templateName.trim() || !templateContent.trim()) {
      toast.error('Nombre y contenido son requeridos');
      return;
    }
    try {
      const res = await fetch('/api/templates', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: templateName, content: templateContent, isDefault: templateIsDefault }),
      });
      if (res.ok) {
        toast.success('Plantilla guardada exitosamente');
        setTemplateName('');
        setTemplateContent('');
        setTemplateIsDefault(false);
        fetchTemplates();
      } else {
        toast.error('Error al guardar plantilla');
      }
    } catch {
      toast.error('Error de conexión');
    }
  };

  // Source CRUD
  const handleAddSource = async () => {
    if (!sourceName.trim() || !sourceUrl.trim()) {
      toast.error('Nombre y URL son requeridos');
      return;
    }
    try {
      const res = await fetch('/api/sources', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: sourceName, url: sourceUrl, type: sourceType, category: sourceCategory }),
      });
      if (res.ok) {
        toast.success('Fuente añadida exitosamente');
        setSourceName('');
        setSourceUrl('');
        setSourceType('web');
        setSourceCategory('seguridad');
        fetchSources();
      } else {
        toast.error('Error al añadir fuente');
      }
    } catch {
      toast.error('Error de conexión');
    }
  };

  const handleDeleteSource = async (id: string) => {
    try {
      const res = await fetch('/api/sources', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      });
      if (res.ok) {
        toast.success('Fuente eliminada');
        fetchSources();
      } else {
        toast.error('Error al eliminar fuente');
      }
    } catch {
      toast.error('Error de conexión');
    }
  };

  // Analysis
  const handleAnalyze = async () => {
    const hasSelectedSources = selectedSourceIds.size > 0;
    const hasSelectedCategories = selectedCategories.size > 0;
    const allActiveSources = sources.filter(s => s.active);

    if (!hasSelectedSources && allActiveSources.length === 0 && !hasSelectedCategories) {
      toast.error('Seleccione fuentes o categorías de análisis');
      return;
    }

    setIsAnalyzing(true);
    setAnalysisProgress(0);
    setAnalysisResult(null);

    try {
      setAnalysisStep('Consultando fuentes de inteligencia OSINT...');
      setAnalysisProgress(10);
      await new Promise(r => setTimeout(r, 300));

      // Use selected sources, or all active sources if none specifically selected
      const activeSources = hasSelectedSources
        ? sources.filter(s => selectedSourceIds.has(s.id))
        : allActiveSources;
      const urls = activeSources.map(s => s.url);

      setAnalysisStep(`Buscando en ${activeSources.length} fuente(s) seleccionada(s)...`);
      setAnalysisProgress(20);

      // Build dynamic queries incorporating selected sources and categories
      let queries: string[];
      if (hasSelectedCategories) {
        queries = buildDynamicQueries(selectedCategories, activeSources);
      } else {
        queries = buildDynamicQueries(
          new Set(['amenazas-vip', 'ciberseguridad', 'secuestro-extorsion', 'seguridad-digital', 'crimen-organizado']),
          activeSources
        );
      }

      // Include source metadata for the backend
      const sourceInfo = activeSources.map(s => ({
        id: s.id,
        name: s.name,
        url: s.url,
        domain: extractDomain(s.url),
        type: s.type,
        category: s.category,
      }));

      const selectedCategoryLabels = hasSelectedCategories
        ? Array.from(selectedCategories).map(catId => industryCategories.find(c => c.id === catId)?.label).filter(Boolean)
        : [];

      const res = await fetch('/api/ai-operation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operation: 'analyze',
          data: {
            urls,
            searchQueries: queries,
            sourceInfo,
            selectedCategories: selectedCategoryLabels,
            selectedSourceNames: activeSources.map(s => s.name),
          },
        }),
      });

      setAnalysisStep('Analizando datos recopilados con IA...');
      setAnalysisProgress(50);

      if (res.ok) {
        const data = await res.json();
        setAnalysisResult(data);
        setAnalysisStep('Análisis completado');
        setAnalysisProgress(100);
        toast.success('Análisis completado exitosamente');
      } else {
        let errorMsg = 'Error en el análisis';
        try {
          const errorData = await res.json();
          errorMsg = errorData.error || errorMsg;
        } catch {
          // Use default error message
        }
        toast.error(errorMsg, { duration: 8000 });
      }
    } catch {
      toast.error('Error de conexión durante el análisis. Intente nuevamente.', { duration: 8000 });
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Generate Report
  const handleGenerateReport = async () => {
    if (!analysisResult) {
      toast.error('Realice un análisis primero');
      return;
    }

    setIsGenerating(true);
    setGeneratingProgress(0);

    try {
      setGeneratingProgress(30);

      // Get the actual template content from the selected template
      let activeTemplateContent = '';
      if (selectedTemplateId) {
        const selectedTemplate = templates.find(t => t.id === selectedTemplateId);
        if (selectedTemplate) {
          activeTemplateContent = selectedTemplate.content;
        }
      }

      // Build dynamic report title based on actual analysis content
      const activeSources = selectedSourceIds.size > 0
        ? sources.filter(s => selectedSourceIds.has(s.id))
        : sources.filter(s => s.active);
      const sourceNames = activeSources.map(s => s.name);
      const categoryLabels = Array.from(selectedCategories).map(
        catId => industryCategories.find(c => c.id === catId)?.label
      ).filter(Boolean) as string[];

      const riskLabel = analysisResult.overallRiskLevel
        ? analysisResult.overallRiskLevel.charAt(0).toUpperCase() + analysisResult.overallRiskLevel.slice(1)
        : '';
      const threatCount = analysisResult.threats?.length || 0;
      const dateStr = new Date().toLocaleDateString('es-ES', { day: '2-digit', month: 'long', year: 'numeric' });

      let dynamicTitle = 'Informe de Inteligencia';
      if (categoryLabels.length > 0) {
        dynamicTitle += ` - ${categoryLabels.slice(0, 3).join(', ')}`;
        if (categoryLabels.length > 3) dynamicTitle += ` +${categoryLabels.length - 3}`;
      }
      if (riskLabel) {
        dynamicTitle += ` [Riesgo ${riskLabel}]`;
      }
      if (sourceNames.length > 0) {
        dynamicTitle += ` - ${sourceNames.slice(0, 2).join(', ')}`;
        if (sourceNames.length > 2) dynamicTitle += ` +${sourceNames.length - 2}`;
      }
      dynamicTitle += ` - ${dateStr}`;

      // Build context metadata for report structure
      const reportContext = {
        selectedCategories: categoryLabels,
        selectedSources: sourceNames,
        threatCount,
        riskLevel: analysisResult.overallRiskLevel,
        summary: analysisResult.summary,
        topThreats: analysisResult.threats?.slice(0, 5).map(t => ({
          title: t.title,
          severity: t.severity,
          category: t.category,
        })),
        sourcesUsed: analysisResult.sources?.slice(0, 10).map(s => s.title),
      };

      // Step 1: Generate report content with AI, passing context for dynamic structure
      const aiRes = await fetch('/api/ai-operation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operation: 'generate-report',
          data: {
            templateContent: activeTemplateContent,
            analysis: analysisResult,
            reportContext,
          },
        }),
      });

      if (!aiRes.ok) {
        toast.error('Error al generar informe con IA');
        return;
      }

      const aiData = await aiRes.json();
      const reportContent = aiData.content || '';

      setGeneratingProgress(70);

      // Step 2: Save to database
      const saveRes = await fetch('/api/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          templateId: selectedTemplateId || null,
          analysis: analysisResult,
          title: dynamicTitle,
          reportContent: reportContent,
          selectedCategories: categoryLabels,
          selectedSources: sourceNames,
        }),
      });

      if (saveRes.ok) {
        const data = await saveRes.json();
        setGeneratingProgress(100);
        toast.success('Informe generado exitosamente');
        fetchReports();
        setPreviewReport(data);
        setPreviewOpen(true);
      } else {
        toast.error('Error al guardar informe');
      }
    } catch {
      toast.error('Error de conexión al generar informe');
    } finally {
      setIsGenerating(false);
      setGeneratingProgress(0);
    }
  };

  // Delete report
  const handleDeleteReport = async (id: string) => {
    try {
      const res = await fetch('/api/reports', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      });
      if (res.ok) {
        toast.success('Informe eliminado');
        fetchReports();
        if (previewReport?.id === id) {
          setPreviewReport(null);
          setPreviewOpen(false);
        }
      } else {
        toast.error('Error al eliminar informe');
      }
    } catch {
      toast.error('Error de conexión');
    }
  };

  // Download report as markdown
  const handleDownloadReport = (report: Report) => {
    const blob = new Blob([report.content], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.title.replace(/[^a-zA-Z0-9áéíóúñÁÉÍÓÚÑ ]/g, '')}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success('Informe MD descargado');
  };

  // Download report as PDF
  const handleDownloadPDF = async (report: Report) => {
    try {
      const res = await fetch('/api/export-pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reportId: report.id }),
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${report.title.replace(/[^a-zA-Z0-9áéíóúñÁÉÍÓÚÑ ]/g, '')}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast.success('PDF descargado exitosamente');
      } else {
        toast.error('Error al generar PDF');
      }
    } catch {
      toast.error('Error de conexión');
    }
  };

  // Download report as DOCX
  const handleDownloadDOCX = async (report: Report) => {
    try {
      const res = await fetch('/api/export-docx', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reportId: report.id }),
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${report.title.replace(/[^a-zA-Z0-9áéíóúñÁÉÍÓÚÑ ]/g, '')}.docx`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast.success('DOCX descargado exitosamente');
      } else {
        toast.error('Error al generar DOCX');
      }
    } catch {
      toast.error('Error de conexión');
    }
  };

  // Open edit dialog
  const handleOpenEdit = (report: Report) => {
    setEditingReport(report);
    setEditAdditionalUrls('');
    setEditAdditionalNews('');
    setEditAdditionalContext('');
    setEditDialogOpen(true);
  };

  // Update report with new information
  const handleUpdateReport = async () => {
    if (!editingReport) return;
    if (!editAdditionalUrls.trim() && !editAdditionalNews.trim() && !editAdditionalContext.trim()) {
      toast.error('Debe proporcionar al menos una URL, noticias adicionales o contexto');
      return;
    }

    setIsUpdating(true);
    try {
      // Step 1: Update content with AI
      const aiRes = await fetch('/api/ai-operation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operation: 'update-report',
          data: {
            existingContent: editingReport.content,
            additionalUrls: editAdditionalUrls.split(',').map((u: string) => u.trim()).filter((u: string) => u.length > 0),
            additionalNews: editAdditionalNews,
            additionalContext: editAdditionalContext,
          },
        }),
      });

      if (!aiRes.ok) {
        toast.error('Error al actualizar con IA');
        return;
      }

      const aiData = await aiRes.json();
      const updatedContent = aiData.content || editingReport.content;

      // Step 2: Save to database
      const saveRes = await fetch('/api/update-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reportId: editingReport.id,
          updatedContent: updatedContent,
          additionalUrls: editAdditionalUrls,
          additionalNews: editAdditionalNews,
          additionalContext: editAdditionalContext,
        }),
      });
      if (saveRes.ok) {
        const updatedReport = await saveRes.json();
        toast.success('Informe actualizado exitosamente');
        setEditDialogOpen(false);
        setEditingReport(null);
        fetchReports();
        if (previewReport?.id === editingReport.id) {
          setPreviewReport(updatedReport);
        }
      } else {
        toast.error('Error al guardar actualización');
      }
    } catch {
      toast.error('Error de conexión al actualizar informe');
    } finally {
      setIsUpdating(false);
    }
  };

  // Industry classification categories for analysis
  const industryCategories = [
    { id: 'amenazas-vip', label: 'Amenazas Seguridad VIP', icon: Shield, color: 'bg-red-500/20 text-red-400 border-red-500/30' },
    { id: 'conflictos-politicos', label: 'Conflictos Políticos', icon: AlertTriangle, color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
    { id: 'riesgos-ejecutiva', label: 'Riesgos Protección Ejecutiva', icon: Shield, color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
    { id: 'ciberseguridad', label: 'Ciberseguridad', icon: Globe, color: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30' },
    { id: 'crimen-organizado', label: 'Crimen Organizado', icon: Target, color: 'bg-rose-500/20 text-rose-400 border-rose-500/30' },
    { id: 'secuestro-extorsion', label: 'Secuestro y Extorsión', icon: AlertTriangle, color: 'bg-red-600/20 text-red-500 border-red-600/30' },
    { id: 'fraude-corporativo', label: 'Fraude Corporativo', icon: FileText, color: 'bg-yellow-600/15 text-yellow-500 border-yellow-600/20' },
    { id: 'seguridad-fisica', label: 'Seguridad Física', icon: Shield, color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' },
    { id: 'inteligencia-competitiva', label: 'Inteligencia Competitiva', icon: Brain, color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
    { id: 'seguridad-informacion', label: 'Seguridad de la Información', icon: Globe, color: 'bg-sky-500/20 text-sky-400 border-sky-500/30' },
    { id: 'geopolitica', label: 'Geopolítica', icon: Globe, color: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30' },
    { id: 'riesgos-financieros', label: 'Riesgos Financieros', icon: TrendingUp, color: 'bg-green-500/20 text-green-400 border-green-500/30' },
    { id: 'seguridad-digital', label: 'Seguridad Digital', icon: Globe, color: 'bg-teal-500/20 text-teal-400 border-teal-500/30' },
    { id: 'proteccion-datos', label: 'Protección de Datos', icon: Shield, color: 'bg-violet-500/20 text-violet-400 border-violet-500/30' },
    { id: 'seguridad-viajes', label: 'Seguridad en Viajes', icon: Activity, color: 'bg-lime-500/20 text-lime-400 border-lime-500/30' },
  ];

  // Base search term templates per category (will be enhanced with source context dynamically)
  const categoryBaseTerms: Record<string, string> = {
    'amenazas-vip': 'amenazas seguridad ejecutivos VIP',
    'conflictos-politicos': 'conflictos políticos impacto seguridad',
    'riesgos-ejecutiva': 'riesgos protección ejecutiva directivos',
    'ciberseguridad': 'ciberseguridad phishing ataques ejecutivos',
    'crimen-organizado': 'criminalidad organizada directivos empresarios',
    'secuestro-extorsion': 'secuestro extorsión empresarios',
    'fraude-corporativo': 'fraude corporativo estafa empresa',
    'seguridad-fisica': 'seguridad física protección ejecutiva',
    'inteligencia-competitiva': 'inteligencia competitiva espionaje industrial',
    'seguridad-informacion': 'seguridad información filtración datos',
    'geopolitica': 'geopolítica riesgos regionales',
    'riesgos-financieros': 'riesgos financieros lavado activos',
    'seguridad-digital': 'seguridad digital amenazas cibernéticas',
    'proteccion-datos': 'protección datos privacidad información',
    'seguridad-viajes': 'seguridad viajes riesgos movilidad ejecutivos',
  };

  // Extract domain from URL for site: operator
  const extractDomain = (url: string): string | null => {
    try {
      const hostname = new URL(url).hostname;
      return hostname.replace(/^www\./, '');
    } catch {
      return null;
    }
  };

  // Build dynamic queries combining category terms with source-specific context
  const buildDynamicQueries = (categoryIds: Set<string>, activeSources: NewsSource[]): string[] => {
    const currentYear = new Date().getFullYear();
    const nextYear = currentYear + 1;
    const queries: string[] = [];

    for (const catId of categoryIds) {
      const baseTerm = categoryBaseTerms[catId];
      if (!baseTerm) continue;

      if (activeSources.length > 0) {
        // Create one query per source with site: operator for targeted search
        for (const source of activeSources) {
          const domain = extractDomain(source.url);
          if (domain) {
            queries.push(`${baseTerm} site:${domain} ${nextYear}`);
          } else {
            queries.push(`${baseTerm} ${source.name} ${currentYear} ${nextYear}`);
          }
        }
        // Also add a general query without site: restriction for broader coverage
        queries.push(`${baseTerm} Colombia ${currentYear} ${nextYear}`);
      } else {
        queries.push(`${baseTerm} Colombia ${currentYear} ${nextYear}`);
      }
    }

    return queries;
  };

  // Toggle source selection
  const toggleSourceSelection = (id: string) => {
    setSelectedSourceIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const toggleSelectAllSources = () => {
    if (selectedSourceIds.size === sources.length) {
      setSelectedSourceIds(new Set());
    } else {
      setSelectedSourceIds(new Set(sources.map(s => s.id)));
    }
  };

  // Toggle category selection
  const toggleCategory = (id: string) => {
    setSelectedCategories(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const toggleSelectAllCategories = () => {
    if (selectedCategories.size === industryCategories.length) {
      setSelectedCategories(new Set());
    } else {
      setSelectedCategories(new Set(industryCategories.map(c => c.id)));
    }
  };

  // Stats
  const activeSourcesCount = selectedSourceIds.size > 0 ? selectedSourceIds.size : sources.filter(s => s.active).length;
  const detectedThreats = analysisResult?.threats?.length || 0;
  const currentRiskLevel = analysisResult?.overallRiskLevel || 'bajo';

  const navItems = [
    { id: 'panel' as ActiveTab, label: 'Panel', icon: BarChart3 },
    { id: 'plantillas' as ActiveTab, label: 'Documento Oficial', icon: BookOpen },
    { id: 'fuentes' as ActiveTab, label: 'Fuentes', icon: Globe },
    { id: 'analisis' as ActiveTab, label: 'Análisis', icon: Brain },
    { id: 'informes' as ActiveTab, label: 'Informes', icon: FileText },
    { id: 'url-sandbox' as ActiveTab, label: 'URL Sandbox', icon: Layers },
    { id: 'takedown' as ActiveTab, label: 'TakeDown URL', icon: Send },
  ];

  return (
    <div className="min-h-screen flex bg-background">
      {/* Sidebar - Desktop */}
      <aside className="hidden lg:flex flex-col w-64 border-r border-border bg-card/50 backdrop-blur-sm">
        <div className="p-6 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg overflow-hidden flex items-center justify-center">
              <img src="/favicon-64x64.png" alt="VIP-Intelligence" className="w-10 h-10" />
            </div>
            <div>
              <h1 className="text-sm font-bold text-foreground tracking-wide">VIP-Intelligence</h1>
              <p className="text-xs text-primary font-medium">Protección Digital de Ejecutivos</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-1">
          {/* Quick Upload Button in Sidebar */}
          <button
            onClick={() => { setActiveTab('plantillas'); setTimeout(() => fileInputRef.current?.click(), 300); }}
            className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg text-sm font-bold primary-gradient text-primary-foreground mb-3 hover:opacity-95 transition-all"
          >
            <Upload className="w-4 h-4" />
            Subir Plantilla
          </button>
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 ${
                activeTab === item.id
                  ? 'bg-primary/8 text-primary border border-primary/15'
                  : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
              }`}
            >
              <item.icon className="w-4 h-4" />
              {item.label}
              {activeTab === item.id && <ChevronRight className="w-3 h-3 ml-auto" />}
            </button>
          ))}
          <Separator className="my-2" />
          <NextLink
            href="/proteccion-ejecutivos"
            className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 text-blue-400 bg-blue-500/8 border border-blue-500/15 hover:bg-blue-500/10"
          >
            <Shield className="w-4 h-4" />
            Protección Ejecutivos
            <ChevronRight className="w-3 h-3 ml-auto" />
          </NextLink>
          <NextLink
            href="/generar-informe"
            className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 text-primary bg-primary/8 border border-primary/15 hover:bg-primary/10"
          >
            <Zap className="w-4 h-4" />
            Generar Informe
            <ChevronRight className="w-3 h-3 ml-auto" />
          </NextLink>
          <NextLink
            href="/url-sandbox"
            className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 text-purple-400 bg-purple-500/8 border border-purple-500/15 hover:bg-purple-500/10"
          >
            <Layers className="w-4 h-4" />
            URL Sandbox
            <ChevronRight className="w-3 h-3 ml-auto" />
          </NextLink>
          <button
            onClick={() => setActiveTab('takedown')}
            className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 text-orange-400 bg-orange-500/8 border border-orange-500/15 hover:bg-orange-500/10"
          >
            <Send className="w-4 h-4" />
            TakeDown URL
            <ChevronRight className="w-3 h-3 ml-auto" />
          </button>
        </nav>

        <div className="p-4 border-t border-border space-y-3">
          {authUser && (
            <div className="flex items-center gap-3 p-2 rounded-lg bg-muted/30">
              <div className="w-8 h-8 rounded-full bg-primary/15 flex items-center justify-center shrink-0">
                <UserIcon className="w-4 h-4 text-primary" />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-medium text-foreground truncate">{authUser.name}</p>
                <p className="text-xs text-muted-foreground truncate">{authUser.email}</p>
              </div>
              {authUser.mfaEnabled && (
                <Lock className="w-3 h-3 text-primary shrink-0" />
              )}
            </div>
          )}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Activity className="w-3 h-3 text-primary" />
              Sistema activo
            </div>
            <button
              onClick={handleLogout}
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-red-400 transition-colors"
            >
              <LogOut className="w-3 h-3" />
              Salir
            </button>
          </div>
        </div>
      </aside>

      {/* Mobile menu overlay */}
      <AnimatePresence>
        {sidebarOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black/50 z-40 lg:hidden"
              onClick={() => setSidebarOpen(false)}
            />
            <motion.aside
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="fixed left-0 top-0 bottom-0 w-64 z-50 bg-card border-r border-border lg:hidden"
            >
              <div className="p-6 border-b border-border flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg overflow-hidden flex items-center justify-center">
                    <img src="/favicon-64x64.png" alt="VIP-Intelligence" className="w-10 h-10" />
                  </div>
                  <div>
                    <h1 className="text-sm font-bold text-foreground tracking-wide">VIP-Intelligence</h1>
                    <p className="text-xs text-primary font-medium">Protección Digital de Ejecutivos</p>
                  </div>
                </div>
                <button onClick={() => setSidebarOpen(false)} className="text-muted-foreground hover:text-foreground">
                  <X className="w-5 h-5" />
                </button>
              </div>
              <nav className="p-4 space-y-1">
                {/* Quick Upload Button in Mobile Sidebar */}
                <button
                  onClick={() => { setActiveTab('plantillas'); setSidebarOpen(false); setTimeout(() => fileInputRef.current?.click(), 300); }}
                  className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg text-sm font-bold primary-gradient text-primary-foreground mb-3 hover:opacity-95 transition-all"
                >
                  <Upload className="w-4 h-4" />
                  Subir Plantilla
                </button>
                {navItems.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => { setActiveTab(item.id); setSidebarOpen(false); }}
                    className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                      activeTab === item.id
                        ? 'bg-primary/8 text-primary border border-primary/15'
                        : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
                    }`}
                  >
                    <item.icon className="w-4 h-4" />
                    {item.label}
                  </button>
                ))}
                <Separator className="my-2" />
                <NextLink
                  href="/proteccion-ejecutivos"
                  onClick={() => setSidebarOpen(false)}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 text-blue-400 bg-blue-500/8 border border-blue-500/15 hover:bg-blue-500/10"
                >
                  <Shield className="w-4 h-4" />
                  Protección Ejecutivos
                </NextLink>
                <NextLink
                  href="/generar-informe"
                  onClick={() => setSidebarOpen(false)}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 text-primary bg-primary/8 border border-primary/15 hover:bg-primary/10"
                >
                  <Zap className="w-4 h-4" />
                  Generar Informe
                </NextLink>
                <NextLink
                  href="/url-sandbox"
                  onClick={() => setSidebarOpen(false)}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 text-purple-400 bg-purple-500/8 border border-purple-500/15 hover:bg-purple-500/10"
                >
                  <Layers className="w-4 h-4" />
                  URL Sandbox
                </NextLink>
                <button
                  onClick={() => { setActiveTab('takedown'); setSidebarOpen(false); }}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 text-orange-400 bg-orange-500/8 border border-orange-500/15 hover:bg-orange-500/10"
                >
                  <Send className="w-4 h-4" />
                  TakeDown URL
                </button>
              </nav>
              {authUser && (
                <div className="p-4 border-t border-border mt-auto space-y-3">
                  <div className="flex items-center gap-3 p-2 rounded-lg bg-muted/30">
                    <div className="w-8 h-8 rounded-full bg-primary/15 flex items-center justify-center shrink-0">
                      <UserIcon className="w-4 h-4 text-primary" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-medium text-foreground truncate">{authUser.name}</p>
                      <p className="text-xs text-muted-foreground truncate">{authUser.email}</p>
                    </div>
                    {authUser.mfaEnabled && <Lock className="w-3 h-3 text-primary shrink-0" />}
                  </div>
                  <button
                    onClick={() => { handleLogout(); setSidebarOpen(false); }}
                    className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs text-red-400 hover:bg-red-500/10 transition-colors"
                  >
                    <LogOut className="w-3 h-3" />
                    Cerrar Sesión
                  </button>
                </div>
              )}
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      {/* Main content */}
      <main className="flex-1 flex flex-col min-w-0">
        {/* Top header */}
        <header className="sticky top-0 z-30 border-b border-border bg-background/80 backdrop-blur-md">
          <div className="flex items-center justify-between px-4 lg:px-8 py-4">
            <div className="flex items-center gap-4">
              <button
                onClick={() => setSidebarOpen(true)}
                className="lg:hidden text-muted-foreground hover:text-foreground"
              >
                <Menu className="w-5 h-5" />
              </button>
              <div>
                <h2 className="text-lg font-bold text-foreground capitalize">
                  {navItems.find(n => n.id === activeTab)?.label}
                </h2>
                <p className="text-xs text-muted-foreground">
                  Sistema de Inteligencia Ejecutiva
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Badge variant="outline" className={`${threatLevelColors[currentRiskLevel]} text-xs`}>
                <span className={`w-2 h-2 rounded-full ${threatLevelDots[currentRiskLevel]} mr-1.5 ${currentRiskLevel === 'critico' ? 'status-pulse' : ''}`} />
                Riesgo: {currentRiskLevel.charAt(0).toUpperCase() + currentRiskLevel.slice(1)}
              </Badge>
              <div className="hidden sm:flex items-center gap-1 text-xs text-muted-foreground">
                <Shield className="w-3 h-3 text-primary" />
                Clasificado
              </div>
              <ThemeSelector compact />
              {authUser && (
                <button
                  onClick={handleLogout}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition-all"
                  title="Cerrar sesión"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">{authUser.name}</span>
                </button>
              )}
            </div>
          </div>
        </header>

        {/* Content area */}
        <div className="flex-1 p-4 lg:p-8 overflow-auto">
          {authLoading ? (
            <div className="flex items-center justify-center py-20">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : (
          <AnimatePresence mode="wait">
            {/* ========== PANEL ========== */}
            {activeTab === 'panel' && (
              <motion.div
                key="panel"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.15 }}
                className="space-y-6"
              >
                {/* Stats Cards */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
                    <Card className="card-elevated border-border bg-card/80 hover:border-primary/15 transition-all duration-300">
                      <CardContent className="p-4 lg:p-6">
                        <div className="flex items-center justify-between mb-3">
                          <FileText className="w-5 h-5 text-primary" />
                          <Badge variant="outline" className="text-xs bg-primary/8 text-primary border-primary/12">
                            Total
                          </Badge>
                        </div>
                        <div className="text-2xl lg:text-3xl font-bold text-foreground">{totalReports}</div>
                        <p className="text-xs text-muted-foreground mt-1">Informes Generados</p>
                      </CardContent>
                    </Card>
                  </motion.div>

                  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
                    <Card className="card-elevated border-border bg-card/80 hover:border-emerald-500/30 transition-all duration-300">
                      <CardContent className="p-4 lg:p-6">
                        <div className="flex items-center justify-between mb-3">
                          <Globe className="w-5 h-5 text-emerald-500" />
                          <Badge variant="outline" className="text-xs bg-emerald-500/10 text-emerald-400 border-emerald-500/20">
                            Activas
                          </Badge>
                        </div>
                        <div className="text-2xl lg:text-3xl font-bold text-foreground">{activeSourcesCount}</div>
                        <p className="text-xs text-muted-foreground mt-1">Fuentes Activas</p>
                      </CardContent>
                    </Card>
                  </motion.div>

                  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
                    <Card className="card-elevated border-border bg-card/80 hover:border-orange-500/30 transition-all duration-300">
                      <CardContent className="p-4 lg:p-6">
                        <div className="flex items-center justify-between mb-3">
                          <AlertTriangle className="w-5 h-5 text-orange-500" />
                          <Badge variant="outline" className="text-xs bg-orange-500/10 text-orange-400 border-orange-500/20">
                            Detectadas
                          </Badge>
                        </div>
                        <div className="text-2xl lg:text-3xl font-bold text-foreground">{detectedThreats}</div>
                        <p className="text-xs text-muted-foreground mt-1">Amenazas Detectadas</p>
                      </CardContent>
                    </Card>
                  </motion.div>

                  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
                    <Card className="card-elevated border-border bg-card/80 hover:border-red-500/30 transition-all duration-300">
                      <CardContent className="p-4 lg:p-6">
                        <div className="flex items-center justify-between mb-3">
                          <Target className="w-5 h-5 text-red-500" />
                          <Badge className={`text-xs ${threatLevelColors[currentRiskLevel]}`}>
                            Nivel
                          </Badge>
                        </div>
                        <div className="text-2xl lg:text-3xl font-bold text-foreground capitalize">{currentRiskLevel}</div>
                        <p className="text-xs text-muted-foreground mt-1">Nivel de Riesgo</p>
                      </CardContent>
                    </Card>
                  </motion.div>
                </div>

                {/* Quick Actions & Recent Reports */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  {/* Quick Actions */}
                  <Card className="border-border bg-card/80">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-semibold flex items-center gap-2">
                        <Zap className="w-4 h-4 text-primary" />
                        Acciones Rápidas
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      <Button
                        onClick={() => setActiveTab('analisis')}
                        className="w-full justify-start gap-2 primary-gradient text-primary-foreground font-semibold hover:opacity-95"
                      >
                        <Brain className="w-4 h-4" />
                        Nuevo Análisis
                      </Button>
                      <Button
                        onClick={() => setActiveTab('fuentes')}
                        variant="outline"
                        className="w-full justify-start gap-2 border-border hover:border-primary/15"
                      >
                        <Globe className="w-4 h-4" />
                        Añadir Fuente
                      </Button>
                      <Button
                        onClick={() => setActiveTab('plantillas')}
                        variant="outline"
                        className="w-full justify-start gap-2 border-border hover:border-primary/15"
                      >
                        <BookOpen className="w-4 h-4" />
                        Documento Oficial
                      </Button>
                    </CardContent>
                  </Card>

                  {/* Recent Reports */}
                  <Card className="lg:col-span-2 border-border bg-card/80">
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-sm font-semibold flex items-center gap-2">
                          <FileText className="w-4 h-4 text-primary" />
                          Informes Recientes
                        </CardTitle>
                        <Button variant="ghost" size="sm" className="text-xs text-primary hover:text-primary/80" onClick={() => setActiveTab('informes')}>
                          Ver todos <ChevronRight className="w-3 h-3 ml-1" />
                        </Button>
                      </div>
                    </CardHeader>
                    <CardContent>
                      {loadingReports ? (
                        <div className="flex items-center justify-center py-8">
                          <Loader2 className="w-6 h-6 animate-spin text-primary" />
                        </div>
                      ) : reports.length === 0 ? (
                        <div className="text-center py-8 text-muted-foreground">
                          <FileText className="w-8 h-8 mx-auto mb-2 opacity-30" />
                          <p className="text-sm">No hay informes generados</p>
                          <p className="text-xs mt-1">Realice un análisis para generar su primer informe</p>
                        </div>
                      ) : (
                        <ScrollArea className="max-h-64">
                          <div className="space-y-2">
                            {reports.slice(0, 5).map((report) => (
                              <div
                                key={report.id}
                                className="flex items-center justify-between p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors cursor-pointer"
                                onClick={() => { setPreviewReport(report); setPreviewOpen(true); }}
                              >
                                <div className="flex items-center gap-3 min-w-0">
                                  <span className={`w-2 h-2 rounded-full shrink-0 ${threatLevelDots[report.threatLevel] || 'bg-gray-500'}`} />
                                  <div className="min-w-0">
                                    <p className="text-sm font-medium truncate">{report.title}</p>
                                    <p className="text-xs text-muted-foreground">
                                      {new Date(report.createdAt).toLocaleDateString('es-ES')}
                                    </p>
                                  </div>
                                </div>
                                <Badge className={`text-xs shrink-0 ${threatLevelColors[report.threatLevel] || ''}`}>
                                  {report.threatLevel}
                                </Badge>
                              </div>
                            ))}
                          </div>
                        </ScrollArea>
                      )}
                    </CardContent>
                  </Card>
                </div>

                {/* Threat Overview */}
                {analysisResult && (
                  <Card className="border-border bg-card/80">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-semibold flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-orange-500" />
                        Último Análisis de Amenazas
                      </CardTitle>
                      <CardDescription>{analysisResult.summary}</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {analysisResult.threats.slice(0, 4).map((threat, i) => (
                          <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-muted/30">
                            <span className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${threatLevelDots[threat.severity]}`} />
                            <div className="min-w-0">
                              <p className="text-sm font-medium">{threat.title}</p>
                              <p className="text-xs text-muted-foreground line-clamp-2">{threat.description}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Security & Profile Settings */}
                {authUser && (
                  <Card className="border-border bg-card/80">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-semibold flex items-center gap-2">
                        <Lock className="w-4 h-4 text-primary" />
                        Seguridad de la Cuenta
                      </CardTitle>
                      <CardDescription>Configuración de seguridad y autenticación</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30">
                        <div className="flex items-center gap-3">
                          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${authUser.mfaEnabled ? 'bg-emerald-500/20' : 'bg-muted'}`}>
                            <Smartphone className={`w-5 h-5 ${authUser.mfaEnabled ? 'text-emerald-400' : 'text-muted-foreground'}`} />
                          </div>
                          <div>
                            <p className="text-sm font-medium text-foreground">Autenticación de Doble Factor (MFA)</p>
                            <p className="text-xs text-muted-foreground">
                              {authUser.mfaEnabled ? 'Activada — Su cuenta está protegida' : 'Desactivada — Se recomienda activar MFA'}
                            </p>
                          </div>
                        </div>
                        {authUser.mfaEnabled ? (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setShowDisableMfaDialog(true)}
                            className="border-red-500/30 text-red-400 hover:bg-red-500/10 hover:text-red-300"
                          >
                            Desactivar
                          </Button>
                        ) : (
                          <Button
                            size="sm"
                            onClick={handleMfaSetup}
                            disabled={mfaLoading}
                            className="primary-gradient text-primary-foreground font-semibold hover:opacity-95"
                          >
                            {mfaLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : 'Activar MFA'}
                          </Button>
                        )}
                      </div>
                      <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-lg bg-primary/12 flex items-center justify-center">
                            <Shield className="w-5 h-5 text-primary" />
                          </div>
                          <div>
                            <p className="text-sm font-medium text-foreground">Rol de Usuario</p>
                            <p className="text-xs text-muted-foreground capitalize">{authUser.role}</p>
                          </div>
                        </div>
                        <Badge variant="outline" className="text-xs bg-primary/8 text-primary border-primary/12 capitalize">
                          {authUser.role}
                        </Badge>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </motion.div>
            )}

            {/* ========== PLANTILLAS ========== */}
            {activeTab === 'plantillas' && (
              <motion.div
                key="plantillas"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.15 }}
                className="space-y-6"
              >
                {/* PROMINENT FILE UPLOAD SECTION */}
                <Card className="border-2 border-primary/20 bg-card/80 shadow-lg shadow-primary/5">
                  <CardHeader>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <Upload className="w-5 h-5 text-primary" />
                      Subir Documento Oficial (Plantilla)
                    </CardTitle>
                    <CardDescription className="text-sm">
                      Suba su documento oficial o plantilla aqui. El sistema la llenara automaticamente con la informacion de inteligencia recopilada de las fuentes y noticias.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {/* Large File Upload Area */}
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".pdf,.docx,.txt,.md"
                      onChange={handleFileUpload}
                      className="hidden"
                    />
                    <button
                      onClick={() => fileInputRef.current?.click()}
                      disabled={isUploadingFile}
                      className="w-full flex flex-col items-center justify-center gap-4 p-10 rounded-xl border-3 border-dashed border-primary/30 hover:border-primary bg-primary/5 hover:bg-primary/8 transition-all duration-300 cursor-pointer group"
                    >
                      {isUploadingFile ? (
                        <>
                          <Loader2 className="w-12 h-12 text-primary animate-spin" />
                          <span className="text-base text-muted-foreground font-medium">Procesando archivo...</span>
                        </>
                      ) : (
                        <>
                          <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center group-hover:bg-primary/15 transition-colors">
                            <Upload className="w-8 h-8 text-primary" />
                          </div>
                          <div className="text-center">
                            <p className="text-lg font-bold text-foreground">HAGA CLIC AQUI PARA SUBIR SU PLANTILLA</p>
                            <p className="text-sm text-muted-foreground mt-2">Formatos soportados: PDF, DOCX, TXT, MD</p>
                          </div>
                        </>
                      )}
                    </button>
                    {uploadedFileName && (
                      <div className="flex items-center gap-3 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
                        <CheckCircle className="w-5 h-5 text-emerald-400" />
                        <div>
                          <span className="text-sm font-medium text-emerald-400">{uploadedFileName} cargado exitosamente</span>
                          <p className="text-xs text-muted-foreground mt-0.5">El contenido se ha cargado en el campo de texto abajo. Puede editarlo si lo desea.</p>
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* New Template Form */}
                  <Card className="border-border bg-card/80">
                    <CardHeader>
                      <CardTitle className="text-base flex items-center gap-2">
                        <Plus className="w-4 h-4 text-primary" />
                        Configurar y Guardar Plantilla
                      </CardTitle>
                      <CardDescription>Si subio un archivo, el contenido ya esta cargado. Ajuste el nombre y guarde la plantilla.</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">Nombre de la Plantilla</Label>
                        <Input
                          value={templateName}
                          onChange={(e) => setTemplateName(e.target.value)}
                          placeholder="Ej: Informe Ejecutivo Semanal"
                          className="bg-muted/30 border-border focus:border-primary/30"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">Contenido del Documento Oficial</Label>
                        <Textarea
                          value={templateContent}
                          onChange={(e) => setTemplateContent(e.target.value)}
                          placeholder={`Suba su archivo arriba o pegue aqui su documento oficial. El sistema lo llenara automaticamente con la informacion de inteligencia recopilada.\n\n# INFORME EJECUTIVO DE PROTECCION VIP\n\n## Resumen Ejecutivo\n...\n\n## Amenazas Detectadas\n...`}
                          className="min-h-48 bg-muted/30 border-border focus:border-primary/30 font-mono text-xs"
                        />
                      </div>
                      <div className="flex items-center gap-3">
                        <Switch
                          checked={templateIsDefault}
                          onCheckedChange={setTemplateIsDefault}
                        />
                        <Label className="text-sm">Plantilla predeterminada</Label>
                      </div>
                      <Button onClick={handleSaveTemplate} className="w-full primary-gradient text-primary-foreground font-semibold hover:opacity-95">
                        <Plus className="w-4 h-4 mr-2" />
                        Guardar Plantilla
                      </Button>
                    </CardContent>
                  </Card>

                  {/* Existing Templates */}
                  <Card className="border-border bg-card/80">
                    <CardHeader>
                      <CardTitle className="text-base flex items-center gap-2">
                        <BookOpen className="w-4 h-4 text-primary" />
                        Documentos Guardados
                      </CardTitle>
                      <CardDescription>{templates.length} documento(s) disponible(s)</CardDescription>
                    </CardHeader>
                    <CardContent>
                      {loadingTemplates ? (
                        <div className="flex items-center justify-center py-8">
                          <Loader2 className="w-6 h-6 animate-spin text-primary" />
                        </div>
                      ) : templates.length === 0 ? (
                        <div className="text-center py-8 text-muted-foreground">
                          <BookOpen className="w-8 h-8 mx-auto mb-2 opacity-30" />
                          <p className="text-sm">No hay plantillas</p>
                        </div>
                      ) : (
                        <ScrollArea className="max-h-96">
                          <div className="space-y-3">
                            {templates.map((template) => (
                              <div
                                key={template.id}
                                className={`p-4 rounded-lg border transition-all cursor-pointer ${
                                  selectedTemplateId === template.id
                                    ? 'border-primary/20 bg-primary/5'
                                    : 'border-border bg-muted/20 hover:border-primary/12'
                                }`}
                                onClick={() => setSelectedTemplateId(template.id)}
                              >
                                <div className="flex items-center justify-between mb-2">
                                  <div className="flex items-center gap-2">
                                    <FileText className="w-4 h-4 text-primary" />
                                    <span className="text-sm font-medium">{template.name}</span>
                                  </div>
                                  {template.isDefault && (
                                    <Badge className="text-xs primary-gradient text-primary-foreground border-0">Predeterminada</Badge>
                                  )}
                                </div>
                                <p className="text-xs text-muted-foreground line-clamp-2">
                                  {template.content.substring(0, 120)}...
                                </p>
                                <p className="text-xs text-muted-foreground mt-2">
                                  {new Date(template.createdAt).toLocaleDateString('es-ES')}
                                </p>
                              </div>
                            ))}
                          </div>
                        </ScrollArea>
                      )}
                    </CardContent>
                  </Card>
                </div>

                {/* Template Preview */}
                {selectedTemplateId && templates.find(t => t.id === selectedTemplateId) && (
                  <Card className="border-border bg-card/80">
                    <CardHeader>
                      <CardTitle className="text-base flex items-center gap-2">
                        <Eye className="w-4 h-4 text-primary" />
                        Vista Previa: {templates.find(t => t.id === selectedTemplateId)?.name}
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="p-4 rounded-lg bg-muted/20 border border-border prose prose-invert prose-sm max-w-none">
                        <ReactMarkdown>
                          {templates.find(t => t.id === selectedTemplateId)?.content || ''}
                        </ReactMarkdown>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </motion.div>
            )}

            {/* ========== FUENTES ========== */}
            {activeTab === 'fuentes' && (
              <motion.div
                key="fuentes"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.15 }}
                className="space-y-6"
              >
                {/* Add Source Form */}
                <Card className="border-border bg-card/80">
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <Plus className="w-4 h-4 text-primary" />
                      Añadir Fuente de Información
                    </CardTitle>
                    <CardDescription>Agregue URLs y feeds RSS como fuentes de inteligencia</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">Nombre</Label>
                        <Input
                          value={sourceName}
                          onChange={(e) => setSourceName(e.target.value)}
                          placeholder="Ej: Reuters - Seguridad"
                          className="bg-muted/30 border-border focus:border-primary/30"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">URL</Label>
                        <Input
                          value={sourceUrl}
                          onChange={(e) => setSourceUrl(e.target.value)}
                          placeholder="https://ejemplo.com/noticias"
                          className="bg-muted/30 border-border focus:border-primary/30"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">Tipo</Label>
                        <Select value={sourceType} onValueChange={setSourceType}>
                          <SelectTrigger className="bg-muted/30 border-border">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="web">Web</SelectItem>
                            <SelectItem value="rss">RSS</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">Categoría</Label>
                        <Select value={sourceCategory} onValueChange={setSourceCategory}>
                          <SelectTrigger className="bg-muted/30 border-border">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="seguridad">Seguridad</SelectItem>
                            <SelectItem value="politica">Política</SelectItem>
                            <SelectItem value="economia">Economía</SelectItem>
                            <SelectItem value="social">Social</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                    <Button onClick={handleAddSource} className="mt-4 primary-gradient text-primary-foreground font-semibold hover:opacity-95">
                      <Plus className="w-4 h-4 mr-2" />
                      Añadir Fuente
                    </Button>
                  </CardContent>
                </Card>

                {/* Sources List */}
                <Card className="border-border bg-card/80">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base flex items-center gap-2">
                        <Newspaper className="w-4 h-4 text-primary" />
                        Fuentes Registradas
                      </CardTitle>
                      <div className="flex items-center gap-2">
                        {selectedSourceIds.size > 0 && (
                          <Badge className="text-xs primary-gradient text-primary-foreground font-semibold">
                            {selectedSourceIds.size} seleccionada(s)
                          </Badge>
                        )}
                        <Badge variant="outline" className="text-xs">
                          {sources.length} fuente(s)
                        </Badge>
                      </div>
                    </div>
                    <CardDescription className="text-xs">
                      Seleccione las fuentes que desea utilizar para el análisis e informe de inteligencia
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {loadingSources ? (
                      <div className="flex items-center justify-center py-8">
                        <Loader2 className="w-6 h-6 animate-spin text-primary" />
                      </div>
                    ) : sources.length === 0 ? (
                      <div className="text-center py-8 text-muted-foreground">
                        <Globe className="w-8 h-8 mx-auto mb-2 opacity-30" />
                        <p className="text-sm">No hay fuentes registradas</p>
                        <p className="text-xs mt-1">Añada fuentes para comenzar el análisis</p>
                      </div>
                    ) : (
                      <>
                        {/* Select All Bar */}
                        <div className="flex items-center justify-between mb-3 p-3 rounded-lg bg-primary/5 border border-primary/12">
                          <button
                            onClick={toggleSelectAllSources}
                            className="flex items-center gap-2 text-sm font-medium text-primary hover:text-primary/80 transition-colors"
                          >
                            {selectedSourceIds.size === sources.length ? (
                              <CheckSquare className="w-4 h-4" />
                            ) : (
                              <Square className="w-4 h-4" />
                            )}
                            {selectedSourceIds.size === sources.length ? 'Deseleccionar todas' : 'Seleccionar todas'}
                          </button>
                          <span className="text-xs text-muted-foreground">
                            Las fuentes seleccionadas se usarán para el análisis
                          </span>
                        </div>
                        <ScrollArea className="max-h-96">
                          <div className="space-y-2">
                            {sources.map((source) => {
                              const isSelected = selectedSourceIds.has(source.id);
                              return (
                                <div
                                  key={source.id}
                                  className={`flex items-center justify-between p-4 rounded-lg border transition-all cursor-pointer ${
                                    isSelected
                                      ? 'border-primary/30 bg-primary/8 hover:bg-primary/10'
                                      : 'border-border bg-muted/20 hover:bg-muted/30'
                                  }`}
                                  onClick={() => toggleSourceSelection(source.id)}
                                >
                                  <div className="flex items-center gap-3 min-w-0">
                                    {/* Checkbox */}
                                    <div className={`shrink-0 w-5 h-5 rounded-md border-2 flex items-center justify-center transition-all ${
                                      isSelected
                                        ? 'border-primary bg-primary'
                                        : 'border-muted-foreground/40'
                                    }`}>
                                      {isSelected && <CheckCircle className="w-3.5 h-3.5 text-background" />}
                                    </div>
                                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${categoryColors[source.category] || 'bg-gray-500/20 text-gray-400'}`}>
                                      {source.type === 'rss' ? <Activity className="w-4 h-4" /> : <Globe className="w-4 h-4" />}
                                    </div>
                                    <div className="min-w-0">
                                      <div className="flex items-center gap-2">
                                        <p className={`text-sm font-medium truncate ${isSelected ? 'text-foreground' : 'text-muted-foreground'}`}>{source.name}</p>
                                        <Badge variant="outline" className="text-xs shrink-0">{source.type.toUpperCase()}</Badge>
                                        <Badge className={`text-xs shrink-0 ${categoryColors[source.category] || ''}`}>
                                          {source.category}
                                        </Badge>
                                      </div>
                                      <p className="text-xs text-muted-foreground truncate max-w-xs lg:max-w-lg">
                                        {source.url}
                                      </p>
                                    </div>
                                  </div>
                                  <div className="flex items-center gap-2 shrink-0" onClick={(e) => e.stopPropagation()}>
                                    <a
                                      href={source.url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="p-2 rounded-md hover:bg-muted/50 text-muted-foreground hover:text-foreground"
                                    >
                                      <ExternalLink className="w-3 h-3" />
                                    </a>
                                    <button
                                      onClick={() => handleDeleteSource(source.id)}
                                      className="p-2 rounded-md hover:bg-red-500/10 text-muted-foreground hover:text-red-400 transition-colors"
                                    >
                                      <Trash2 className="w-3 h-3" />
                                    </button>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </ScrollArea>
                      </>
                    )}
                  </CardContent>
                </Card>
              </motion.div>
            )}

            {/* ========== ANÁLISIS ========== */}
            {activeTab === 'analisis' && (
              <motion.div
                key="analisis"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.15 }}
                className="space-y-6"
              >
                {/* Analysis Configuration */}
                <Card className="border-border bg-card/80">
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <Brain className="w-4 h-4 text-primary" />
                      Análisis de Inteligencia con IA
                    </CardTitle>
                    <CardDescription>
                      Seleccione las clasificaciones de la industria a investigar y las fuentes a consultar
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    {/* Industry Classification Categories - Dynamic Menu */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <Label className="text-sm font-semibold flex items-center gap-2">
                          <Filter className="w-4 h-4 text-primary" />
                          Clasificaciones de la Industria
                        </Label>
                        <button
                          onClick={toggleSelectAllCategories}
                          className="flex items-center gap-1.5 text-xs font-medium text-primary hover:text-primary/80 transition-colors"
                        >
                          {selectedCategories.size === industryCategories.length ? (
                            <>
                              <CheckSquare className="w-3.5 h-3.5" />
                              Deseleccionar todas
                            </>
                          ) : (
                            <>
                              <Square className="w-3.5 h-3.5" />
                              Seleccionar todas
                            </>
                          )}
                        </button>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Seleccione las áreas de inteligencia que desea investigar. Cada categoría generará una búsqueda especializada.
                      </p>
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                        {industryCategories.map((cat) => {
                          const isSelected = selectedCategories.has(cat.id);
                          const IconComp = cat.icon;
                          return (
                            <button
                              key={cat.id}
                              onClick={() => toggleCategory(cat.id)}
                              className={`flex items-center gap-2.5 p-3 rounded-lg border text-left transition-all duration-200 ${
                                isSelected
                                  ? `border-primary/30 bg-primary/8 shadow-sm shadow-primary/5`
                                  : 'border-border bg-muted/20 hover:bg-muted/30'
                              }`}
                            >
                              <div className={`shrink-0 w-8 h-8 rounded-lg flex items-center justify-center ${isSelected ? 'bg-primary/12 text-primary' : cat.color}`}>
                                <IconComp className="w-4 h-4" />
                              </div>
                              <div className="min-w-0 flex-1">
                                <p className={`text-xs font-medium leading-tight ${isSelected ? 'text-foreground' : 'text-muted-foreground'}`}>
                                  {cat.label}
                                </p>
                              </div>
                              <div className={`shrink-0 w-4 h-4 rounded-full border-2 flex items-center justify-center transition-all ${
                                isSelected
                                  ? 'border-primary bg-primary'
                                  : 'border-muted-foreground/30'
                              }`}>
                                {isSelected && <CheckCircle className="w-2.5 h-2.5 text-background" />}
                              </div>
                            </button>
                          );
                        })}
                      </div>
                      {selectedCategories.size > 0 && (
                        <div className="flex items-center gap-2 mt-2">
                          <Badge className="text-xs primary-gradient text-primary-foreground font-semibold">
                            {selectedCategories.size} categoría(s) seleccionada(s)
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            → Se generarán {selectedCategories.size} búsquedas especializadas
                          </span>
                        </div>
                      )}
                    </div>

                    <Separator />

                    {/* Selected Sources Summary */}
                    <div className="space-y-3">
                      <Label className="text-sm font-semibold flex items-center gap-2">
                        <ListChecks className="w-4 h-4 text-primary" />
                        Fuentes Seleccionadas para el Análisis
                      </Label>
                      {selectedSourceIds.size > 0 ? (
                        <div className="p-3 rounded-lg bg-primary/5 border border-primary/12">
                          <div className="flex items-center gap-2 mb-2">
                            <Badge className="text-xs primary-gradient text-primary-foreground font-semibold">
                              {selectedSourceIds.size} fuente(s)
                            </Badge>
                            <span className="text-xs text-muted-foreground">serán consultadas en el análisis</span>
                          </div>
                          <div className="flex flex-wrap gap-1.5">
                            {sources
                              .filter(s => selectedSourceIds.has(s.id))
                              .map(s => (
                                <Badge key={s.id} variant="outline" className="text-xs border-primary/15 text-primary">
                                  {s.name}
                                </Badge>
                              ))}
                          </div>
                        </div>
                      ) : (
                        <div className="p-3 rounded-lg bg-muted/20 border border-border">
                          <p className="text-xs text-muted-foreground">
                            No ha seleccionado fuentes específicas. Se usarán todas las fuentes activas ({sources.filter(s => s.active).length} disponible(s)).
                          </p>
                          <Button variant="link" size="sm" className="text-primary p-0 h-auto text-xs mt-1" onClick={() => setActiveTab('fuentes')}>
                            Ir a seleccionar fuentes →
                          </Button>
                        </div>
                      )}
                    </div>

                    <Separator />

                    {/* Template Selection */}
                    <div className="space-y-2">
                      <Label className="text-xs text-muted-foreground">Plantilla para Informe</Label>
                      <Select value={selectedTemplateId} onValueChange={setSelectedTemplateId}>
                        <SelectTrigger className="bg-muted/30 border-border">
                          <SelectValue placeholder="Seleccionar plantilla" />
                        </SelectTrigger>
                        <SelectContent>
                          {templates.map((t) => (
                            <SelectItem key={t.id} value={t.id}>
                              {t.name} {t.isDefault ? '(Predeterminada)' : ''}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    {/* Analyze Button */}
                    <Button
                      onClick={handleAnalyze}
                      disabled={isAnalyzing}
                      className="w-full primary-gradient text-primary-foreground font-semibold hover:opacity-95"
                      size="lg"
                    >
                      {isAnalyzing ? (
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      ) : (
                        <Play className="w-4 h-4 mr-2" />
                      )}
                      {isAnalyzing ? 'Analizando...' : `Iniciar Análisis${selectedCategories.size > 0 ? ` (${selectedCategories.size} categorías)` : ''}`}
                    </Button>

                    {/* Progress */}
                    {isAnalyzing && (
                      <div className="space-y-3 p-4 rounded-lg bg-muted/20 border border-primary/12">
                        <div className="flex items-center gap-2 text-sm">
                          <Loader2 className="w-4 h-4 animate-spin text-primary" />
                          <span>{analysisStep}</span>
                        </div>
                        <Progress value={analysisProgress} className="h-2" />
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Analysis Results */}
                {analysisResult && !isAnalyzing && (
                  <>
                    {/* Summary & Risk Level */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                      <Card className="lg:col-span-2 border-border bg-card/80">
                        <CardHeader className="pb-3">
                          <CardTitle className="text-base flex items-center gap-2">
                            <Activity className="w-4 h-4 text-primary" />
                            Resumen del Análisis
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <p className="text-sm text-muted-foreground leading-relaxed">
                            {analysisResult.summary}
                          </p>
                          <div className="mt-4 flex items-center gap-4">
                            <Badge className={`text-sm px-3 py-1 ${threatLevelColors[analysisResult.overallRiskLevel]}`}>
                              Riesgo: {analysisResult.overallRiskLevel.toUpperCase()}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              {analysisResult.threats.length} amenazas identificadas
                            </span>
                          </div>
                        </CardContent>
                      </Card>

                      <Card className="border-border bg-card/80">
                        <CardHeader className="pb-3">
                          <CardTitle className="text-base flex items-center gap-2">
                            <Shield className="w-4 h-4 text-primary" />
                            Generar Informe
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <p className="text-xs text-muted-foreground">
                            Convierta este análisis en un informe ejecutivo profesional usando la plantilla seleccionada.
                          </p>
                          <Button
                            onClick={handleGenerateReport}
                            disabled={isGenerating}
                            className="w-full primary-gradient text-primary-foreground font-semibold hover:opacity-95"
                          >
                            {isGenerating ? (
                              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                            ) : (
                              <FileText className="w-4 h-4 mr-2" />
                            )}
                            {isGenerating ? 'Generando...' : 'Generar Informe'}
                          </Button>
                          {isGenerating && (
                            <Progress value={generatingProgress} className="h-1.5" />
                          )}
                        </CardContent>
                      </Card>
                    </div>

                    {/* Threats */}
                    <Card className="border-border bg-card/80">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-base flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 text-orange-500" />
                          Amenazas Detectadas
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          {analysisResult.threats.map((threat, i) => (
                            <motion.div
                              key={i}
                              initial={{ opacity: 0, x: -20 }}
                              animate={{ opacity: 1, x: 0 }}
                              transition={{ delay: i * 0.1 }}
                              className="flex items-start gap-3 p-4 rounded-lg border border-border bg-muted/20"
                            >
                              <span className={`w-3 h-3 rounded-full mt-1 shrink-0 ${threatLevelDots[threat.severity]} ${threat.severity === 'critico' ? 'status-pulse' : ''}`} />
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 mb-1 flex-wrap">
                                  <span className="text-sm font-semibold">{threat.title}</span>
                                  <Badge className={`text-xs ${threatLevelColors[threat.severity]}`}>
                                    {threat.severity.toUpperCase()}
                                  </Badge>
                                  <Badge variant="outline" className="text-xs">
                                    {threat.category}
                                  </Badge>
                                </div>
                                <p className="text-sm text-muted-foreground">{threat.description}</p>
                              </div>
                            </motion.div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>

                    {/* Recommendations */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      <Card className="border-border bg-card/80">
                        <CardHeader className="pb-3">
                          <CardTitle className="text-base flex items-center gap-2">
                            <TrendingUp className="w-4 h-4 text-primary" />
                            Recomendaciones
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ScrollArea className="max-h-64">
                            <div className="space-y-2">
                              {analysisResult.recommendations.map((rec, i) => (
                                <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-muted/20">
                                  <CheckCircle className="w-4 h-4 text-emerald-500 mt-0.5 shrink-0" />
                                  <p className="text-sm text-muted-foreground">{rec}</p>
                                </div>
                              ))}
                            </div>
                          </ScrollArea>
                        </CardContent>
                      </Card>

                      <Card className="border-border bg-card/80">
                        <CardHeader className="pb-3">
                          <CardTitle className="text-base flex items-center gap-2">
                            <Search className="w-4 h-4 text-primary" />
                            Fuentes Consultadas
                          </CardTitle>
                          <CardDescription className="text-xs">
                            {selectedSourceIds.size > 0
                              ? `${selectedSourceIds.size} fuente(s) seleccionada(s) para este análisis`
                              : 'Fuentes encontradas durante la investigación'}
                          </CardDescription>
                        </CardHeader>
                        <CardContent>
                          <ScrollArea className="max-h-64">
                            <div className="space-y-2">
                              {/* Show user-selected sources first */}
                              {selectedSourceIds.size > 0 && sources.filter(s => selectedSourceIds.has(s.id)).map((source) => (
                                <div key={`sel-${source.id}`} className="flex items-start gap-3 p-3 rounded-lg bg-primary/5 border border-primary/12">
                                  <CheckCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                                  <div className="min-w-0">
                                    <p className="text-sm font-medium truncate">{source.name}</p>
                                    <p className="text-xs text-muted-foreground truncate">{source.url}</p>
                                    <Badge className={`text-xs mt-0.5 ${categoryColors[source.category] || ''}`}>
                                      {source.category}
                                    </Badge>
                                  </div>
                                </div>
                              ))}
                              {/* Then show AI-discovered sources */}
                              {analysisResult.sources.map((source, i) => (
                                <div key={`ai-${i}`} className="flex items-start gap-3 p-3 rounded-lg bg-muted/20">
                                  <Globe className="w-4 h-4 text-sky-500 mt-0.5 shrink-0" />
                                  <div className="min-w-0">
                                    <p className="text-sm font-medium truncate">{source.title}</p>
                                    <p className="text-xs text-muted-foreground truncate">{source.url}</p>
                                    <p className="text-xs text-primary/50 mt-0.5">{source.relevance}</p>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </ScrollArea>
                        </CardContent>
                      </Card>
                    </div>
                  </>
                )}
              </motion.div>
            )}

            {/* ========== INFORMES ========== */}
            {activeTab === 'informes' && (
              <motion.div
                key="informes"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.15 }}
                className="space-y-6"
              >
                <Card className="border-border bg-card/80">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="text-base flex items-center gap-2">
                          <FileText className="w-4 h-4 text-primary" />
                          Informes Generados
                        </CardTitle>
                        <CardDescription>{totalReports} informe(s) en total</CardDescription>
                      </div>
                      <Button variant="outline" size="sm" onClick={fetchReports} className="gap-1">
                        <RefreshCw className="w-3 h-3" />
                        Actualizar
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent>
                    {loadingReports ? (
                      <div className="flex items-center justify-center py-8">
                        <Loader2 className="w-6 h-6 animate-spin text-primary" />
                      </div>
                    ) : reports.length === 0 ? (
                      <div className="text-center py-12 text-muted-foreground">
                        <FileText className="w-12 h-12 mx-auto mb-3 opacity-20" />
                        <p className="text-sm">No hay informes generados</p>
                        <p className="text-xs mt-1">Vaya a Análisis para generar su primer informe</p>
                        <Button
                          variant="outline"
                          className="mt-4 border-primary/15 text-primary hover:text-primary/80"
                          onClick={() => setActiveTab('analisis')}
                        >
                          Ir a Análisis
                        </Button>
                      </div>
                    ) : (
                      <ScrollArea className="max-h-[600px]">
                        <div className="space-y-3">
                          {reports.map((report, i) => (
                            <motion.div
                              key={report.id}
                              initial={{ opacity: 0, y: 10 }}
                              animate={{ opacity: 1, y: 0 }}
                              transition={{ delay: i * 0.05 }}
                              className="p-4 rounded-lg border border-border bg-muted/20 hover:bg-muted/30 transition-colors"
                            >
                              <div className="flex items-start justify-between gap-4">
                                <div className="flex items-start gap-3 min-w-0">
                                  <span className={`w-3 h-3 rounded-full mt-1.5 shrink-0 ${threatLevelDots[report.threatLevel] || 'bg-gray-500'} ${report.threatLevel === 'critico' ? 'status-pulse' : ''}`} />
                                  <div className="min-w-0">
                                    <div className="flex items-center gap-2 flex-wrap">
                                      <h3 className="text-sm font-semibold">{report.title}</h3>
                                      <Badge className={`text-xs ${threatLevelColors[report.threatLevel] || ''}`}>
                                        {report.threatLevel.toUpperCase()}
                                      </Badge>
                                    </div>
                                    <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                                      {report.summary || 'Sin resumen disponible'}
                                    </p>
                                    <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                                      <span>{new Date(report.createdAt).toLocaleDateString('es-ES', { year: 'numeric', month: 'long', day: 'numeric' })}</span>
                                      {report.template && (
                                        <>
                                          <Separator orientation="vertical" className="h-3" />
                                          <span>Plantilla: {report.template.name}</span>
                                        </>
                                      )}
                                    </div>
                                  </div>
                                </div>
                                <div className="flex items-center gap-1 shrink-0">
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => { setPreviewReport(report); setPreviewOpen(true); }}
                                    className="text-primary hover:text-primary/80"
                                    title="Ver informe"
                                  >
                                    <Eye className="w-4 h-4" />
                                  </Button>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => handleDownloadPDF(report)}
                                    className="text-muted-foreground hover:text-foreground"
                                    title="Descargar PDF"
                                  >
                                    <FileDown className="w-4 h-4" />
                                  </Button>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => handleDownloadDOCX(report)}
                                    className="text-muted-foreground hover:text-foreground"
                                    title="Descargar DOCX"
                                  >
                                    <FileText className="w-4 h-4" />
                                  </Button>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => handleOpenEdit(report)}
                                    className="text-primary hover:text-primary/80"
                                    title="Mejorar informe"
                                  >
                                    <Pencil className="w-4 h-4" />
                                  </Button>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => handleDeleteReport(report.id)}
                                    className="text-muted-foreground hover:text-red-400"
                                    title="Eliminar informe"
                                  >
                                    <Trash2 className="w-4 h-4" />
                                  </Button>
                                </div>
                              </div>
                            </motion.div>
                          ))}
                        </div>
                      </ScrollArea>
                    )}
                  </CardContent>
                </Card>
              </motion.div>
            )}

            {/* ========== TAKEDOWN URL ========== */}
            {activeTab === 'takedown' && (
              <motion.div
                key="takedown"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.15 }}
                className="space-y-6"
              >
                <TakeDownPanel />
              </motion.div>
            )}
          </AnimatePresence>
          )}
        </div>

        {/* Footer */}
        <footer className="border-t border-border px-4 lg:px-8 py-3 mt-auto">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <div className="flex items-center gap-2">
              <Shield className="w-3 h-3 text-primary" />
              <span>VIP_Protection Report - Executive Intelligence System</span>
            </div>
            <div className="flex items-center gap-1">
              <span>Clasificado</span>
              <span className="text-primary">•</span>
              <span>{new Date().getFullYear()}</span>
            </div>
          </div>
        </footer>
      </main>

      {/* Report Preview Dialog */}
      <Dialog open={previewOpen} onOpenChange={setPreviewOpen}>
        <DialogContent className="max-w-4xl max-h-[85vh] bg-card border-border">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileText className="w-5 h-5 text-primary" />
              {previewReport?.title || 'Vista Previa'}
            </DialogTitle>
            <DialogDescription className="flex items-center gap-3">
              {previewReport && (
                <>
                  <Badge className={`${threatLevelColors[previewReport.threatLevel]}`}>
                    {previewReport.threatLevel.toUpperCase()}
                  </Badge>
                  <span>{new Date(previewReport.createdAt).toLocaleDateString('es-ES', { year: 'numeric', month: 'long', day: 'numeric' })}</span>
                </>
              )}
            </DialogDescription>
          </DialogHeader>
          <ScrollArea className="max-h-[65vh] pr-4">
            <div className="prose prose-invert prose-sm max-w-none">
              {previewReport && (
                <ReactMarkdown>{previewReport.content}</ReactMarkdown>
              )}
            </div>
          </ScrollArea>
          <div className="flex flex-wrap items-center gap-2 mt-4 pt-4 border-t border-border">
            {previewReport && (
              <>
                <Button onClick={() => handleDownloadPDF(previewReport)} className="primary-gradient text-primary-foreground font-semibold hover:opacity-95">
                  <FileDown className="w-4 h-4 mr-2" />
                  Descargar PDF
                </Button>
                <Button onClick={() => handleDownloadDOCX(previewReport)} variant="outline" className="border-primary/15 text-primary hover:text-primary/80 hover:border-primary/30">
                  <FileText className="w-4 h-4 mr-2" />
                  Descargar DOCX
                </Button>
                <Button onClick={() => handleDownloadReport(previewReport)} variant="outline" className="border-border hover:border-primary/15">
                  <Download className="w-4 h-4 mr-2" />
                  Descargar MD
                </Button>
                <Button onClick={() => { setPreviewOpen(false); handleOpenEdit(previewReport); }} variant="outline" className="border-border text-primary hover:text-primary/80 hover:border-primary/15">
                  <Pencil className="w-4 h-4 mr-2" />
                  Mejorar
                </Button>
              </>
            )}
            <Button variant="outline" onClick={() => setPreviewOpen(false)} className="border-border ml-auto">
              Cerrar
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Edit Report Dialog */}
      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent className="max-w-2xl bg-card border-border">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Pencil className="w-5 h-5 text-primary" />
              Mejorar Informe
            </DialogTitle>
            <DialogDescription>
              {editingReport ? `Añada nueva información para mejorar: ${editingReport.title}` : 'Añada nueva información para mejorar el informe'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label className="text-xs text-muted-foreground">Nuevas URLs (separadas por coma)</Label>
              <Textarea
                value={editAdditionalUrls}
                onChange={(e) => setEditAdditionalUrls(e.target.value)}
                placeholder="https://ejemplo.com/noticia1, https://ejemplo.com/noticia2"
                className="bg-muted/30 border-border focus:border-primary/30"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-xs text-muted-foreground">Nuevas Noticias</Label>
              <Textarea
                value={editAdditionalNews}
                onChange={(e) => setEditAdditionalNews(e.target.value)}
                placeholder="Pegue aquí texto adicional de noticias o información relevante..."
                className="min-h-32 bg-muted/30 border-border focus:border-primary/30"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-xs text-muted-foreground">Contexto Adicional</Label>
              <Textarea
                value={editAdditionalContext}
                onChange={(e) => setEditAdditionalContext(e.target.value)}
                placeholder="Instrucciones o contexto adicional para el análisis..."
                className="min-h-24 bg-muted/30 border-border focus:border-primary/30"
              />
            </div>
          </div>
          <div className="flex items-center gap-2 mt-4 pt-4 border-t border-border">
            <Button
              onClick={handleUpdateReport}
              disabled={isUpdating}
              className="primary-gradient text-primary-foreground font-semibold hover:opacity-95"
            >
              {isUpdating ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <RefreshCw className="w-4 h-4 mr-2" />
              )}
              {isUpdating ? 'Actualizando...' : 'Actualizar Informe'}
            </Button>
            <Button variant="outline" onClick={() => setEditDialogOpen(false)} className="border-border">
              Cancelar
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* MFA Setup Dialog */}
      <Dialog open={mfaSetupModal} onOpenChange={setMfaSetupModal}>
        <DialogContent className="max-w-md bg-card border-border">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Smartphone className="w-5 h-5 text-primary" />
              Configurar Autenticación de Doble Factor
            </DialogTitle>
            <DialogDescription>
              Escanee el código QR con Google Authenticator y verifique
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            {mfaQrCode && (
              <div className="flex justify-center">
                <div className="p-3 bg-white rounded-xl">
                  <img src={mfaQrCode} alt="QR Code para MFA" width={180} height={180} />
                </div>
              </div>
            )}
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground">Clave secreta (ingreso manual):</p>
              <div className="p-2 bg-muted/30 rounded border border-border font-mono text-xs text-foreground break-all select-all">
                {mfaSecret}
              </div>
            </div>
            <div className="space-y-2">
              <Label className="text-sm text-muted-foreground">Código de verificación</Label>
              <Input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                placeholder="000000"
                value={mfaVerifyCode}
                onChange={(e) => setMfaVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                className="text-center text-xl tracking-[0.5em] bg-muted/30 border-border focus:border-primary/30 h-12 font-mono"
              />
            </div>
            <div className="flex items-center gap-2">
              <Button
                onClick={handleMfaEnable}
                disabled={mfaLoading || mfaVerifyCode.length !== 6}
                className="primary-gradient text-primary-foreground font-semibold hover:opacity-95 flex-1"
              >
                {mfaLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4 mr-2" />}
                {mfaLoading ? 'Verificando...' : 'Verificar y Activar'}
              </Button>
              <Button variant="outline" onClick={() => { setMfaSetupModal(false); setMfaVerifyCode(''); }} className="border-border">
                Cancelar
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Disable MFA Dialog */}
      <Dialog open={showDisableMfaDialog} onOpenChange={setShowDisableMfaDialog}>
        <DialogContent className="max-w-sm bg-card border-border">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Lock className="w-5 h-5 text-red-400" />
              Desactivar MFA
            </DialogTitle>
            <DialogDescription>
              Ingrese su contraseña para desactivar la autenticación de doble factor
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label className="text-sm text-muted-foreground">Contraseña</Label>
              <Input
                type="password"
                placeholder="••••••••"
                value={disableMfaPassword}
                onChange={(e) => setDisableMfaPassword(e.target.value)}
                className="bg-muted/30 border-border focus:border-primary/30"
              />
            </div>
            <div className="flex items-center gap-2">
              <Button
                onClick={handleMfaDisable}
                disabled={disableMfaLoading || !disableMfaPassword}
                className="flex-1 bg-red-500/80 hover:bg-red-500 text-white font-semibold"
              >
                {disableMfaLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Desactivar MFA'}
              </Button>
              <Button variant="outline" onClick={() => { setShowDisableMfaDialog(false); setDisableMfaPassword(''); }} className="border-border">
                Cancelar
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
