import { NextRequest, NextResponse } from 'next/server';
import { kv } from '@/lib/kv';

const EXECUTIVES_KEY = 'exec-protection:executives';
const DORK_CATEGORIES = [
  {
    id: 'social-media',
    name: 'Social Media Profiles',
    description: 'LinkedIn, Facebook, Twitter, Instagram, TikTok',
    query: '"{name}" (site:linkedin.com | site:facebook.com | site:twitter.com | site:instagram.com | site:tiktok.com)',
    sources: ['linkedin.com', 'facebook.com', 'twitter.com', 'instagram.com', 'tiktok.com'],
  },
  {
    id: 'developer-tech',
    name: 'Developer & Tech Profiles',
    description: 'GitHub, GitLab, Stack Overflow',
    query: '"{name}" (site:github.com | site:gitlab.com | site:stackoverflow.com)',
    sources: ['github.com', 'gitlab.com', 'stackoverflow.com'],
  },
  {
    id: 'general-web',
    name: 'General Web Presence',
    description: 'About, Contact, Profile pages',
    query: '"{name}" (email | username | contact | contacto)',
    sources: ['github.com', 'gitlab.com', 'stackoverflow.com'],
  },
  {
    id: 'emails-usernames',
    name: 'Find Emails & Usernames',
    description: 'Email addresses and usernames',
    query: '"{name}" (email | username | contact | contacto)',
    sources: ['web'],
  },
  {
    id: 'location-contact',
    name: 'Find Location & Contact Info',
    description: 'Location, address, phone, contact info',
    query: '"{name}" (location | address | phone | "contact info" | ubicacion | direccion | telefono | contacto)',
    sources: ['web'],
  },
  {
    id: 'professional-publications',
    name: 'Professional & Academic Publications',
    description: 'PDF resumes, CVs, papers, portfolios',
    query: '"{name}" filetype:pdf (resume | cv | "hoja de vida" | paper | publication | portfolio | publicacion)',
    sources: ['web'],
  },
  {
    id: 'work-history',
    name: 'Work History & Company Mentions',
    description: 'Employment history, company mentions',
    query: '"{name}" (worked at | "trabajo en" | employed by | "empleado de" | founder of | "fundador de" | CEO of | company | empresa)',
    sources: ['web'],
  },
  {
    id: 'images',
    name: 'Images',
    description: 'Images of the executive',
    query: '"{name}"',
    sources: ['images.google.com', 'bing.com/images'],
    isImageSearch: true,
  },
  {
    id: 'news-blogs',
    name: 'News, Blogs, & Articles',
    description: 'Interviews, articles, mentions',
    query: '"{name}" (interview | entrevista | article | articulo | mentioned in | "mencionado en" | blog | post)',
    sources: ['news.google.com', 'web'],
  },
  {
    id: 'public-records',
    name: 'Public Records & Legal Documents',
    description: 'Court cases, lawsuits, legal filings',
    query: '"{name}" (court | corte | lawsuit | demanda | case | caso | docket | filing)',
    sources: ['web'],
  },
  {
    id: 'forum-discussions',
    name: 'Forum & Community Discussions',
    description: 'Forum posts, threads, profiles',
    query: '"{name}" (inurl:forum | inurl:foro | inurl:thread | inurl:hilo | "discussion" | "discusion" | "profile" | "perfil")',
    sources: ['web'],
  },
  {
    id: 'data-leaks',
    name: 'Data Leaks & Paste Sites',
    description: 'Pastebin, ghostbin, breach data',
    query: '"{name}" (site:pastebin.com | site:ghostbin.com | site:throwbin.io | "leak" | "breach" | "filtracion" | "base de datos")',
    sources: ['pastebin.com', 'ghostbin.com', 'throwbin.io'],
  },
  {
    id: 'academic-research',
    name: 'Academic & Research Profiles',
    description: 'Google Scholar, ResearchGate, Academia.edu, ORCID',
    query: '"{name}" (site:scholar.google.com | site:researchgate.net | site:academia.edu | site:orcid.org)',
    sources: ['scholar.google.com', 'researchgate.net', 'academia.edu', 'orcid.org'],
  },
  {
    id: 'company-registries',
    name: 'Company Registries & Business Filings',
    description: 'OpenCorporates, SEC, business records',
    query: '"{name}" (site:opencorporates.com | site:sec.gov | "director" | "shareholder" | "administrador" | "socio" | "registro mercantil")',
    sources: ['opencorporates.com', 'sec.gov'],
  },
  {
    id: 'usernames-handles',
    name: 'Usernames & Handles (cross-reference)',
    description: 'Usernames, aliases, handles',
    query: '"{name}" (intext:"@" | "username:" | "alias" | "perfil de usuario" | "user profile")',
    sources: ['web'],
  },
  {
    id: 'breach-databases',
    name: 'Breach Databases',
    description: 'HaveIBeenPwned, LeakLookup, Breachbase, Dehashed',
    query: '"{name}" (site:haveibeenpwned.com | site:leak-lookup.com | site:breachbase.com | site:dehashed.com | "exposed in" | "found in breach")',
    sources: ['haveibeenpwned.com', 'leak-lookup.com', 'breachbase.com', 'dehashed.com'],
  },
  {
    id: 'intelligence-search',
    name: 'Intelligence Search',
    description: 'IntelX, Shodan, ZoomEye, FOFA',
    query: '"{name}" (site:intelx.io | site:shodan.io | site:zoomeye.org | site:fofa.info | "exposed" | "indexed")',
    sources: ['intelx.io', 'shodan.io', 'zoomeye.org', 'fofa.info'],
  },
  {
    id: 'darkweb-onion',
    name: 'Dark Web & Onion Mentions',
    description: 'Onion sites, dark web references',
    query: '"{name}" (site:onion.ly | site:dark.fail | "dark web" | "darkweb" | onion | tor | .onion)',
    sources: ['onion.ly', 'dark.fail'],
  },
  {
    id: 'phone-address',
    name: 'Phone & Address Lookups',
    description: 'Truecaller, Whitepages, Spokeo, Pipl',
    query: '"{name}" (site:truecaller.com | site:whitepages.com | site:spokeo.com | site:pipl.com | phone | telefono | address)',
    sources: ['truecaller.com', 'whitepages.com', 'spokeo.com', 'pipl.com'],
  },
  {
    id: 'deepfake',
    name: 'Deep Fake Search',
    description: 'Deepfake videos and content',
    query: '"{name}" ("deepfake" OR "deep fake") (filetype:mp4 OR filetype:mkv OR filetype:avi OR site:reddit.com | site:twitter.com | site:x.com | site:youtube.com)',
    sources: ['reddit.com', 'twitter.com', 'x.com', 'youtube.com'],
  },
];

function generateId(): string {
  return `exec_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
}

function getExecutives(): Promise<Executive[]> {
  return kv.get<Executive[]>(EXECUTIVES_KEY) || Promise.resolve([]);
}

async function saveExecutives(executives: Executive[]): Promise<void> {
  await kv.set(EXECUTIVES_KEY, executives);
}

interface SocialMedia {
  platform: string;
  url: string;
  username: string;
}

interface Executive {
  id: string;
  documentId: string;
  phone: string;
  emailCorporate: string;
  emailPersonal: string;
  socialMedia: SocialMedia[];
  address: string;
  location: string;
  createdAt: string;
  updatedAt: string;
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const id = searchParams.get('id');
  const action = searchParams.get('action');

  try {
    if (action === 'dork-categories') {
      return NextResponse.json({
        success: true,
        data: DORK_CATEGORIES,
      });
    }

    const executives = await getExecutives();

    if (id) {
      const executive = executives.find(e => e.id === id);
      if (!executive) {
        return NextResponse.json({ success: false, error: 'Executive not found' }, { status: 404 });
      }
      return NextResponse.json({ success: true, data: executive });
    }

    return NextResponse.json({
      success: true,
      data: executives,
      total: executives.length,
    });
  } catch (error: any) {
    console.error('Executive Protection GET Error:', error);
    return NextResponse.json(
      { success: false, error: error.message || 'Failed to fetch executives' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { action, ...data } = body;

    if (action === 'search-dorks') {
      const { executiveId, categoryId } = data;
      const executives = await getExecutives();
      const executive = executives.find(e => e.id === executiveId);
      
      if (!executive) {
        return NextResponse.json({ success: false, error: 'Executive not found' }, { status: 404 });
      }

      const category = DORK_CATEGORIES.find(c => c.id === categoryId);
      if (!category) {
        return NextResponse.json({ success: false, error: 'Dork category not found' }, { status: 404 });
      }

      const fullName = executive.documentId;
      const query = category.query.replace('{name}', fullName);

      return NextResponse.json({
        success: true,
        data: {
          category: category.name,
          query,
          executive: executive.documentId,
        },
      });
    }

    if (action === 'search-all-dorks') {
      const { executiveId } = data;
      const executives = await getExecutives();
      const executive = executives.find(e => e.id === executiveId);
      
      if (!executive) {
        return NextResponse.json({ success: false, error: 'Executive not found' }, { status: 404 });
      }

      const fullName = executive.documentId;
      const queries = DORK_CATEGORIES.map(category => ({
        category: category.name,
        categoryId: category.id,
        query: category.query.replace('{name}', fullName),
        description: category.description,
        sources: category.sources,
        isImageSearch: category.isImageSearch || false,
      }));

      return NextResponse.json({
        success: true,
        data: {
          executive: executive.documentId,
          queries,
        },
      });
    }

    const executives = await getExecutives();
    
    const newExecutive: Executive = {
      id: generateId(),
      documentId: data.documentId || '',
      phone: data.phone || '',
      emailCorporate: data.emailCorporate || '',
      emailPersonal: data.emailPersonal || '',
      socialMedia: data.socialMedia || [],
      address: data.address || '',
      location: data.location || '',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    executives.push(newExecutive);
    await saveExecutives(executives);

    return NextResponse.json({
      success: true,
      data: newExecutive,
      message: 'Executive created successfully',
    }, { status: 201 });
  } catch (error: any) {
    console.error('Executive Protection POST Error:', error);
    return NextResponse.json(
      { success: false, error: error.message || 'Failed to create executive' },
      { status: 500 }
    );
  }
}

export async function PATCH(request: NextRequest) {
  try {
    const body = await request.json();
    const { id, ...updates } = body;

    if (!id) {
      return NextResponse.json({ success: false, error: 'Executive ID is required' }, { status: 400 });
    }

    const executives = await getExecutives();
    const index = executives.findIndex(e => e.id === id);

    if (index === -1) {
      return NextResponse.json({ success: false, error: 'Executive not found' }, { status: 404 });
    }

    executives[index] = {
      ...executives[index],
      ...updates,
      updatedAt: new Date().toISOString(),
    };

    await saveExecutives(executives);

    return NextResponse.json({
      success: true,
      data: executives[index],
      message: 'Executive updated successfully',
    });
  } catch (error: any) {
    console.error('Executive Protection PATCH Error:', error);
    return NextResponse.json(
      { success: false, error: error.message || 'Failed to update executive' },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const id = searchParams.get('id');

  if (!id) {
    return NextResponse.json({ success: false, error: 'Executive ID is required' }, { status: 400 });
  }

  try {
    const executives = await getExecutives();
    const filtered = executives.filter(e => e.id !== id);

    if (filtered.length === executives.length) {
      return NextResponse.json({ success: false, error: 'Executive not found' }, { status: 404 });
    }

    await saveExecutives(filtered);

    return NextResponse.json({
      success: true,
      message: 'Executive deleted successfully',
    });
  } catch (error: any) {
    console.error('Executive Protection DELETE Error:', error);
    return NextResponse.json(
      { success: false, error: error.message || 'Failed to delete executive' },
      { status: 500 }
    );
  }
}