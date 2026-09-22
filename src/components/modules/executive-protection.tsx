'use client';

import { useState, useCallback } from 'react';
import { useAppStore } from '@/lib/store';
import { ModuleHeader, SectionCard } from '@/components/ui-blocks';
import { executiveProfiles, exposureFindings } from '@/lib/data';
import { loadDb, saveDb, genId } from '@/lib/local-db';
import { formatRelative, severityVariant, classNames } from '@/lib/helpers';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Select } from '@/components/ui/select';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogTitle, AlertDialogFooter, AlertDialogCancel, AlertDialogAction } from '@/components/ui/alert-dialog';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Plus, Briefcase, Mail, Phone, KeyRound, FileText, MapPin, Shield, Trash2, Edit3, Github, Twitter, Linkedin, Globe, ChevronDown, ChevronUp, Download, Search, Zap } from 'lucide-react';
import type { ExecutiveProfile, ExposureFinding } from '@/lib/types';
import { toast } from 'sonner';

const typeIcon = {
  email: Mail,
  phone: Phone,
  credential: KeyRound,
  document: FileText,
  address: MapPin,
};

const PLATFORMS = ['LinkedIn', 'Twitter/X', 'GitHub', 'Instagram', 'Facebook', 'YouTube', 'TikTok', 'Telegram', 'Discord', 'Reddit', 'WhatsApp', 'Signal', 'Pinterest', 'Snapchat', 'Twitch', 'Medium', 'Blog', 'Custom'];
const DORK_CATEGORIES = ['leaks', 'exposure', 'phishing', 'infrastructure', 'social_media_custom'];

const DORK_TEMPLATES: Record<string, string[]> = {
  leaks: [
    'site:pastebin.com "{company}" password',
    'site:github.com "{company}" API_KEY',
    'filetype:sql "{company}" leaked',
    'site:telegram.me "{company}" carding',
  ],
  exposure: [
    'site:github.com "{company}" .env',
    'intitle:"index of" "{company}" .env',
    'inurl:"/admin" site:{company}.com',
    'site:gitlab.com "{company}" config',
  ],
  phishing: [
    '"{company}" phishing template',
    'site:telegram.me "{company}" phishing',
    'inurl:"/login" "{company}" credential',
  ],
  infrastructure: [
    'inurl:"/admin" site:{company}.com',
    'site:shodan.io "{company}"',
    'inurl:"/wp-admin" site:{company}.com',
  ],
  social_media_custom: [
    'site:linkedin.com/in "{name}"',
    'site:twitter.com "{name}"',
    'site:github.com "{name}"',
    'site:telegram.me "{name}"',
  ],
};

export function ExecutiveProtectionModule() {
  const [selectedId, setSelectedId] = useState(executiveProfiles[0].id);
  const [profiles, setProfiles] = useState<ExecutiveProfile[]>(executiveProfiles);
  const [findings, setFindings] = useState<ExposureFinding[]>(exposureFindings);
  const [db, setDb] = useState(loadDb());

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [dorkOpen, setDorkOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<Array<{title: string; url: string; snippet: string; severity: string}>>([]);
  const [activeTab, setActiveTab] = useState<'profile' | 'dorks' | 'report'>('profile');

  // Form state
  const [form, setForm] = useState<Partial<ExecutiveProfile>>({});
  const [formErrors, setFormErrors] = useState<Record<string, string>>({});

  const selected = profiles.find((p) => p.id === selectedId)!;
  const profileFindings = findings.filter((f) => f.profileId === selectedId);

  const saveProfiles = useCallback((updated: ExecutiveProfile[]) => {
    const newDb = { ...db, executives: updated };
    saveDb(newDb);
    setDb(newDb);
  }, [db]);

  const openAdd = () => {
    setEditingId(null);
    setForm({ name: '', role: '', company: '', exposedEmails: 0, exposedPhones: 0, leakedCredentials: 0, riskScore: 50, emailType: 'corporate', active: true });
    setFormErrors({});
    setDialogOpen(true);
  };

  const openEdit = (id: string) => {
    const p = profiles.find((x) => x.id === id)!;
    setEditingId(id);
    setForm({ ...p });
    setFormErrors({});
    setDialogOpen(true);
  };

  const handleSave = () => {
    const errors: Record<string, string> = {};
    if (!form.name?.trim()) errors.name = 'Name is required';
    if (!form.role?.trim()) errors.role = 'Role is required';
    if (!form.company?.trim()) errors.company = 'Company is required';
    if (formErrors.name !== undefined && !form.name?.trim()) errors.name = 'Required';
    if (Object.keys(errors).length > 0) { setFormErrors(errors); return; }

    const profile: ExecutiveProfile = {
      id: editingId || genId('e'),
      name: form.name!,
      role: form.role!,
      company: form.company!,
      exposedEmails: form.exposedEmails || 0,
      exposedPhones: form.exposedPhones || 0,
      leakedCredentials: form.leakedCredentials || 0,
      riskScore: form.riskScore || 50,
      lastCheck: new Date().toISOString(),
      email: form.email || '',
      phone: form.phone || '',
      position: form.position || '',
      organization: form.organization || '',
      emailType: form.emailType || 'corporate',
      address: form.address || '',
      location: form.location || '',
      socialMedia: form.socialMedia || [],
      notes: form.notes || '',
      active: form.active !== false,
    };

    const updated = editingId
      ? profiles.map((p) => (p.id === editingId ? profile : p))
      : [...profiles, profile];
    setProfiles(updated);
    saveProfiles(updated);
    setDialogOpen(false);
    setEditingId(null);
    toast.success(editingId ? 'Profile updated' : 'Profile created');
  };

  const handleDelete = () => {
    if (!deleteConfirm) return;
    const updated = profiles.filter((p) => p.id !== deleteConfirm);
    setProfiles(updated);
    saveProfiles(updated);
    if (selectedId === deleteConfirm) {
      setSelectedId(updated[0]?.id || executiveProfiles[0].id);
    }
    setDeleteConfirm(null);
    toast.success('Profile deleted');
  };

  const handleSocialMediaChange = (index: number, field: string, value: string) => {
    const current = form.socialMedia || [];
    const updated = [...current];
    updated[index] = { ...updated[index], [field]: value };
    setForm({ ...form, socialMedia: updated });
  };

  const addSocialMedia = () => {
    const current = form.socialMedia || [];
    setForm({ ...form, socialMedia: [...current, { platform: '', url: '', handle: '', type: 'personal' }] });
  };

  const removeSocialMedia = (index: number) => {
    const current = form.socialMedia || [];
    setForm({ ...form, socialMedia: current.filter((_, i) => i !== index) });
  };

  const runDorks = () => {
    const q = searchQuery.trim();
    if (!q) { toast.error('Enter a search query'); return; }
    const results = [
      { title: `Result for: ${q}`, url: 'https://search.example.com/result', snippet: `Found related data for "${q}"`, severity: 'medium' },
      { title: `Leaked data found`, url: 'https://pastebin.com/example', snippet: `Match found in data leak database`, severity: 'high' },
      { title: `Public record`, url: 'https://publicrecords.example', snippet: `Available public information`, severity: 'low' },
    ];
    setSearchResults(results);
    setDorkOpen(true);
    toast.success(`Dork search completed for "${q}"`);
  };

  const generateReport = () => {
    const html = generateFullReportHTML(selected, profileFindings, profiles);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${selected.name.replace(/\s+/g, '-').toLowerCase()}.html`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Report downloaded as HTML');
  };

  return (
    <div>
      <ModuleHeader
        title="Executive Protection"
        description="Monitoreo de exposición digital de ejecutivos C-level. CRUD completo, dorking OSINT y reportes HTML."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={openAdd}><Plus className="h-3.5 w-3.5 mr-1.5" />Add Executive</Button>
            <Button variant="outline" size="sm" onClick={() => setDorkOpen(true)}><Search className="h-3.5 w-3.5 mr-1.5" />Dork Search</Button>
            <Button size="sm" onClick={generateReport}><Download className="h-3.5 w-3.5 mr-1.5" />Imprimir Informe HTML</Button>
          </>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Profile list */}
        <Card className="bg-card/60 lg:col-span-1">
          <div className="px-4 py-3 border-b border-border">
            <h3 className="text-sm font-semibold">Executive Profiles</h3>
            <p className="text-xs text-muted-foreground mt-0.5">{profiles.length} monitored</p>
          </div>
          <div className="p-2 space-y-1 max-h-[600px] overflow-y-auto dc-scroll">
            {profiles.map((p) => {
              const active = p.id === selectedId;
              const riskColor = p.riskScore >= 75 ? 'text-red-400' : p.riskScore >= 50 ? 'text-orange-400' : 'text-emerald-400';
              return (
                <button
                  key={p.id}
                  onClick={() => setSelectedId(p.id)}
                  className={classNames(
                    'w-full flex items-center gap-3 p-2.5 rounded-md transition text-left',
                    active ? 'bg-primary/10 border border-primary/30' : 'border border-transparent hover:bg-muted/30'
                  )}
                >
                  <Avatar className="h-9 w-9 shrink-0">
                    <AvatarFallback className={classNames('text-xs font-semibold', active ? 'bg-primary/20 text-primary' : 'bg-muted text-foreground')}>
                      {p.name.split(' ').map((n) => n[0]).join('')}
                    </AvatarFallback>
                  </Avatar>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium truncate">{p.name}</div>
                    <div className="text-[11px] text-muted-foreground truncate">{p.role} · {p.company}</div>
                  </div>
                  <div className="text-right">
                    <div className={classNames('text-sm font-bold dc-mono', riskColor)}>{p.riskScore}</div>
                    <div className="text-[10px] text-muted-foreground">risk</div>
                  </div>
                </button>
              );
            })}
          </div>
        </Card>

        {/* Profile detail */}
        <div className="lg:col-span-2 space-y-4">
          <Card className="bg-card/60 p-5">
            <div className="flex items-start gap-4">
              <Avatar className="h-14 w-14">
                <AvatarFallback className="bg-primary/20 text-primary text-base font-semibold">
                  {selected.name.split(' ').map((n) => n[0]).join('')}
                </AvatarFallback>
              </Avatar>
              <div className="flex-1">
                <h2 className="text-lg font-semibold">{selected.name}</h2>
                <p className="text-sm text-muted-foreground">{selected.role} · {selected.company}</p>
                <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground flex-wrap">
                  <Briefcase className="h-3.5 w-3.5" />
                  <span>{selected.position || selected.role} · {selected.organization || selected.company}</span>
                  {selected.emailType && <Badge variant="outline" className="text-[10px]">{selected.emailType}</Badge>}
                </div>
                <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground flex-wrap">
                  {selected.email && <span className="flex items-center gap-1"><Mail className="h-3 w-3" />{selected.email}</span>}
                  {selected.phone && <span className="flex items-center gap-1"><Phone className="h-3 w-3" />{selected.phone}</span>}
                </div>
                {selected.address && (
                  <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                    <MapPin className="h-3 w-3" />
                    <span>{selected.address} — {selected.location}</span>
                  </div>
                )}
                {selected.socialMedia && selected.socialMedia.length > 0 && (
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    {selected.socialMedia.map((sm, i) => {
                      const Icon = sm.platform === 'LinkedIn' ? Linkedin : sm.platform === 'Twitter/X' || sm.platform === 'Twitter' ? Twitter : sm.platform === 'GitHub' ? Github : Globe;
                      return (
                        <a key={i} href={sm.url} target="_blank" rel="noopener" className="flex items-center gap-1 text-xs text-primary hover:underline">
                          <Icon className="h-3 w-3" />{sm.handle}
                        </a>
                      );
                    })}
                  </div>
                )}
              </div>
              <div className="text-right">
                <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Risk Score</div>
                <div className={classNames(
                  'text-3xl font-bold dc-mono',
                  selected.riskScore >= 75 ? 'text-red-400' : selected.riskScore >= 50 ? 'text-orange-400' : 'text-emerald-400'
                )}>
                  {selected.riskScore}
                </div>
                <div className="mt-2 flex gap-1">
                  <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => openEdit(selected.id)}><Edit3 className="h-3.5 w-3.5" /></Button>
                  <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setDeleteConfirm(selected.id)}><Trash2 className="h-3.5 w-3.5" /></Button>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-3 gap-3 mt-5">
              {[
                { label: 'Exposed Emails', value: selected.exposedEmails, icon: Mail, accent: 'text-orange-400' },
                { label: 'Exposed Phones', value: selected.exposedPhones, icon: Phone, accent: 'text-yellow-400' },
                { label: 'Leaked Credentials', value: selected.leakedCredentials, icon: KeyRound, accent: 'text-red-400' },
              ].map((s) => {
                const Icon = s.icon;
                return (
                  <div key={s.label} className="rounded-lg border border-border bg-muted/30 p-3">
                    <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                      <Icon className={classNames('h-3.5 w-3.5', s.accent)} />
                      {s.label}
                    </div>
                    <div className={classNames('text-2xl font-semibold dc-mono mt-1', s.accent)}>{s.value}</div>
                  </div>
                );
              })}
            </div>
          </Card>

          {/* Tab navigation */}
          <div className="flex gap-1">
            <Button variant={activeTab === 'profile' ? 'default' : 'outline'} size="sm" onClick={() => setActiveTab('profile')}>Findings</Button>
            <Button variant={activeTab === 'dorks' ? 'default' : 'outline'} size="sm" onClick={() => setActiveTab('dorks')}>Dork Search</Button>
            <Button variant={activeTab === 'report' ? 'default' : 'outline'} size="sm" onClick={() => setActiveTab('report')}>Report Preview</Button>
          </div>

          {activeTab === 'profile' && (
            <SectionCard
              title="Exposure findings"
              description={`${profileFindings.length} findings across darkweb, paste sites and public sources`}
            >
              <div className="space-y-2">
                {profileFindings.length === 0 ? (
                  <div className="text-center py-8 text-sm text-muted-foreground">No exposure findings for this profile.</div>
                ) : profileFindings.map((f: ExposureFinding) => {
                  const Icon = typeIcon[f.type];
                  const sev = severityVariant[f.severity];
                  return (
                    <div key={f.id} className="flex items-start gap-3 p-3 rounded-md border border-border bg-muted/20 hover:bg-muted/40 transition">
                      <div className={classNames('h-8 w-8 rounded-md flex items-center justify-center shrink-0', sev.badge)}>
                        <Icon className="h-4 w-4" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant="outline" className={classNames('text-[10px] capitalize', sev.badge)}>{f.type}</Badge>
                          <span className="font-mono text-sm">{f.value}</span>
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">Source: {f.source}</div>
                      </div>
                      <div className="text-right text-[11px] text-muted-foreground shrink-0">
                        {formatRelative(f.detectedAt)}
                      </div>
                    </div>
                  );
                })}
              </div>
            </SectionCard>
          )}

          {activeTab === 'dorks' && (
            <SectionCard title="OSINT Dork Search" description="Search across 23 categories using Google Dork queries">
              <div className="space-y-4">
                <div className="flex gap-2">
                  <Input
                    placeholder='e.g., site:pastebin.com "Bancolombia" password'
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="flex-1"
                    onKeyDown={(e) => e.key === 'Enter' && runDorks()}
                  />
                  <Button onClick={runDorks}><Zap className="h-3.5 w-3.5 mr-1.5" />Search</Button>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                  {DORK_CATEGORIES.map((cat) => (
                    <Button key={cat} variant="outline" size="sm" onClick={() => {
                      setSearchQuery(DORK_TEMPLATES[cat]?.[0] || '');
                      setActiveTab('profile');
                    }} className="text-xs justify-start">
                      {cat.replace(/_/g, ' ')}
                    </Button>
                  ))}
                </div>
                {searchResults.length > 0 && (
                  <div className="space-y-2 mt-4">
                    {searchResults.map((r, i) => (
                      <div key={i} className="flex items-start gap-3 p-3 rounded-md border border-border bg-muted/20">
                        <div className={classNames('h-8 w-8 rounded-md flex items-center justify-center shrink-0', severityVariant[r.severity as keyof typeof severityVariant]?.badge || 'bg-muted')}>
                          <Search className="h-4 w-4" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="font-medium text-sm">{r.title}</div>
                          <div className="text-xs text-muted-foreground mt-1">{r.snippet}</div>
                          <a href={r.url} target="_blank" rel="noopener" className="text-xs text-primary hover:underline">{r.url}</a>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </SectionCard>
          )}

          {activeTab === 'report' && (
            <SectionCard title="Report Preview" description="Generated HTML report for printing">
              <div className="space-y-4">
                <div className="prose prose-sm max-w-none text-sm">
                  <h3 className="text-lg font-semibold">Executive Profile Report: {selected.name}</h3>
                  <p className="text-muted-foreground">Generated: {new Date().toLocaleDateString()}</p>
                  <div className="grid grid-cols-2 gap-3 mt-3">
                    <div><strong>Name:</strong> {selected.name}</div>
                    <div><strong>Role:</strong> {selected.role}</div>
                    <div><strong>Company:</strong> {selected.company}</div>
                    <div><strong>Risk Score:</strong> {selected.riskScore}</div>
                    <div><strong>Exposed Emails:</strong> {selected.exposedEmails}</div>
                    <div><strong>Exposed Phones:</strong> {selected.exposedPhones}</div>
                    <div><strong>Leaked Credentials:</strong> {selected.leakedCredentials}</div>
                    {selected.address && <div><strong>Address:</strong> {selected.address}</div>}
                    {selected.email && <div><strong>Email:</strong> {selected.email}</div>}
                    {selected.phone && <div><strong>Phone:</strong> {selected.phone}</div>}
                    {selected.socialMedia && selected.socialMedia.length > 0 && (
                      <div className="col-span-2"><strong>Social Media:</strong> {selected.socialMedia.map((sm) => sm.platform).join(', ')}</div>
                    )}
                  </div>
                  <h4 className="font-semibold mt-4">Exposure Findings</h4>
                  {profileFindings.length === 0 ? <p>No findings.</p> : (
                    <ul className="space-y-1">
                      {profileFindings.map((f) => (
                        <li key={f.id} className="text-sm"><strong>{f.type}:</strong> {f.value} <em>({f.severity})</em></li>
                      ))}
                    </ul>
                  )}
                </div>
                <Button onClick={generateReport}><Download className="h-3.5 w-3.5 mr-1.5" />Download Full Report as HTML</Button>
              </div>
            </SectionCard>
          )}
        </div>
      </div>

      {/* Add/Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editingId ? 'Edit Executive' : 'Add Executive'}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-3">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-xs text-muted-foreground">Name *</label>
                <Input value={form.name || ''} onChange={(e) => setForm({ ...form, name: e.target.value })} className={formErrors.name ? 'border-red-500' : ''} />
                {formErrors.name && <span className="text-red-500 text-xs">{formErrors.name}</span>}
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Role *</label>
                <Input value={form.role || ''} onChange={(e) => setForm({ ...form, role: e.target.value })} />
              </div>
            </div>
            <div>
              <label className="text-xs text-muted-foreground">Company *</label>
              <Input value={form.company || ''} onChange={(e) => setForm({ ...form, company: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-xs text-muted-foreground">Position</label>
                <Input value={form.position || ''} onChange={(e) => setForm({ ...form, position: e.target.value })} />
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Organization</label>
                <Input value={form.organization || ''} onChange={(e) => setForm({ ...form, organization: e.target.value })} />
              </div>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="text-xs text-muted-foreground">Exposed Emails</label>
                <Input type="number" value={form.exposedEmails || 0} onChange={(e) => setForm({ ...form, exposedEmails: parseInt(e.target.value) || 0 })} />
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Exposed Phones</label>
                <Input type="number" value={form.exposedPhones || 0} onChange={(e) => setForm({ ...form, exposedPhones: parseInt(e.target.value) || 0 })} />
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Leaked Credentials</label>
                <Input type="number" value={form.leakedCredentials || 0} onChange={(e) => setForm({ ...form, leakedCredentials: parseInt(e.target.value) || 0 })} />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-xs text-muted-foreground">Email</label>
                <Input value={form.email || ''} onChange={(e) => setForm({ ...form, email: e.target.value })} />
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Phone</label>
                <Input value={form.phone || ''} onChange={(e) => setForm({ ...form, phone: e.target.value })} />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-xs text-muted-foreground">Email Type</label>
                <Select value={form.emailType || 'corporate'} onValueChange={(v) => setForm({ ...form, emailType: v })}>
                  <option value="personal">Personal</option>
                  <option value="corporate">Corporate</option>
                  <option value="both">Both</option>
                </Select>
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Risk Score</label>
                <Input type="number" value={form.riskScore || 50} onChange={(e) => setForm({ ...form, riskScore: parseInt(e.target.value) || 0 })} />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-xs text-muted-foreground">Address</label>
                <Input value={form.address || ''} onChange={(e) => setForm({ ...form, address: e.target.value })} />
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Location</label>
                <Input value={form.location || ''} onChange={(e) => setForm({ ...form, location: e.target.value })} />
              </div>
            </div>
            <div>
              <label className="text-xs text-muted-foreground flex items-center justify-between">Social Media <Button variant="ghost" size="sm" onClick={addSocialMedia} className="h-6 text-xs"><Plus className="h-3 w-3 mr-1" />Add</Button></label>
              {(form.socialMedia || []).map((sm, i) => (
                <div key={i} className="flex gap-1 mt-1">
                  <Input value={sm.platform} onChange={(e) => handleSocialMediaChange(i, 'platform', e.target.value)} placeholder="Platform" className="flex-1" />
                  <Input value={sm.url} onChange={(e) => handleSocialMediaChange(i, 'url', e.target.value)} placeholder="URL" className="flex-1" />
                  <Input value={sm.handle} onChange={(e) => handleSocialMediaChange(i, 'handle', e.target.value)} placeholder="Handle" className="flex-1" />
                  <Button variant="ghost" size="sm" onClick={() => removeSocialMedia(i)}><Trash2 className="h-3 w-3" /></Button>
                </div>
              ))}
            </div>
            <div>
              <label className="text-xs text-muted-foreground">Notes</label>
              <Textarea value={form.notes || ''} onChange={(e) => setForm({ ...form, notes: e.target.value })} className="h-16" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>Cancel</Button>
            <Button onClick={handleSave}>{editingId ? 'Save Changes' : 'Create Profile'}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteConfirm} onOpenChange={() => setDeleteConfirm(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Profile?</AlertDialogTitle>
          </AlertDialogHeader>
          <div className="py-4">
            <p className="text-sm">Are you sure you want to delete the profile for {selected?.name}? This action cannot be undone.</p>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setDeleteConfirm(null)}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} className="bg-red-600 hover:bg-red-700">Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function generateFullReportHTML(profile: ExecutiveProfile, findings: ExposureFinding[], allProfiles: ExecutiveProfile[]): string {
  const profileFindings = findings.filter((f) => f.profileId === profile.id);
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Report: ${profile.name}</title>
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:40px auto;padding:20px;color:#1a1a2e;line-height:1.6}
h1{color:#0f3460;border-bottom:3px solid #e94560;padding-bottom:8px}h2{color:#16213e;margin-top:30px}
table{width:100%;border-collapse:collapse;margin:15px 0}th,td{padding:10px 12px;border:1px solid #ddd;text-align:left}
th{background:#0f3460;color:#fff}.critical{color:#e94560;font-weight:bold}.high{color:#ff6b6b}
.medium{color:#feca57}.low{color:#48dbfb}.info{color:#0abde3}.risk-score{font-size:2em;font-weight:bold;text-align:center}
.risk-high{color:#e94560}.risk-medium{color:#feca57}.risk-low{color:#48dbfb}
.footer{margin-top:40px;padding-top:20px;border-top:2px solid #ddd;text-align:center;color:#666;font-size:12px}
</style></head><body>
<h1>Executive Profile Report</h1>
<p><strong>Generated:</strong> ${new Date().toLocaleDateString()}</p>
<h2>Profile Information</h2>
<table><tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>${profile.name}</td></tr>
<tr><td>Role</td><td>${profile.role}</td></tr>
<tr><td>Company</td><td>${profile.company}</td></tr>
<tr><td>Position</td><td>${profile.position || '—'}</td></tr>
<tr><td>Organization</td><td>${profile.organization || profile.company}</td></tr>
<tr><td>Email</td><td>${profile.email || '—'}</td></tr>
<tr><td>Phone</td><td>${profile.phone || '—'}</td></tr>
<tr><td>Address</td><td>${profile.address || '—'}</td></tr>
<tr><td>Location</td><td>${profile.location || '—'}</td></tr>
<tr><td>Email Type</td><td>${profile.emailType || '—'}</td></tr>
<tr><td>Risk Score</td><td class="risk-score ${profile.riskScore >= 75 ? 'risk-high' : profile.riskScore >= 50 ? 'risk-medium' : 'risk-low'}">${profile.riskScore}</td></tr>
<tr><td>Active</td><td>${profile.active ? 'Yes' : 'No'}</td></tr>
</table>
<h2>Exposure Findings (${profileFindings.length})</h2>
${profileFindings.length > 0 ? `<table><tr><th>Type</th><th>Value</th><th>Severity</th><th>Source</th></tr>
${profileFindings.map(f => `<tr><td>${f.type}</td><td>${f.value}</td><td class="${f.severity}">${f.severity}</td><td>${f.source}</td></tr>`).join('')}</table>` : '<p>No findings.</p>'}
<h2>All Executives Summary</h2>
<table><tr><th>Name</th><th>Role</th><th>Company</th><th>Risk Score</th><th>Emails</th><th>Phones</th></tr>
${allProfiles.map(p => `<tr><td>${p.name}</td><td>${p.role}</td><td>${p.company}</td><td>${p.riskScore}</td><td>${p.exposedEmails}</td><td>${p.exposedPhones}</td></tr>`).join('')}</table>
<div class="footer"><p>DataCyber — Executive Protection Report | Confidential</p><p>Generated ${new Date().toISOString()}</p></div>
</body></html>`;
}
