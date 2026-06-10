'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Sun, Moon, MoonStar, Check } from 'lucide-react';
import { useTheme, type Theme } from './ThemeProvider';

const themeConfig: Record<Theme, {
  label: string;
  description: string;
  icon: React.ElementType;
  preview: { bg: string; fg: string; accent: string };
}> = {
  light: {
    label: 'Claro',
    description: 'Ambientes iluminados',
    icon: Sun,
    preview: { bg: '#f8fafc', fg: '#0f172a', accent: '#d97706' },
  },
  dim: {
    label: 'Intermedio',
    description: 'Equilibrio visual',
    icon: MoonStar,
    preview: { bg: '#15202b', fg: '#d1d9e6', accent: '#f59e0b' },
  },
  dark: {
    label: 'Oscuro',
    description: 'Pantallas OLED',
    icon: Moon,
    preview: { bg: '#0a0a0a', fg: '#e5e7eb', accent: '#fbbf24' },
  },
};

export function ThemeSelector({ compact = false }: { compact?: boolean }) {
  const { theme, setTheme } = useTheme();
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown on click outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [isOpen]);

  // Close on Escape key
  useEffect(() => {
    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') setIsOpen(false);
    }
    if (isOpen) {
      document.addEventListener('keydown', handleEscape);
      return () => document.removeEventListener('keydown', handleEscape);
    }
  }, [isOpen]);

  const currentConfig = themeConfig[theme];
  const CurrentIcon = currentConfig.icon;

  if (compact) {
    return (
      <div className="relative" ref={dropdownRef}>
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium
                     bg-muted/30 border border-border hover:bg-muted/50 transition-all duration-200"
          title={`Tema: ${currentConfig.label}`}
        >
          <CurrentIcon className="w-3.5 h-3.5 text-amber-500" />
          <span className="hidden sm:inline text-muted-foreground">{currentConfig.label}</span>
        </button>

        {isOpen && (
          <div className="absolute right-0 top-full mt-2 w-56 rounded-xl border border-border bg-card shadow-xl z-50 overflow-hidden">
            <div className="p-2 border-b border-border">
              <p className="text-xs font-medium text-muted-foreground px-2">Tema Visual</p>
            </div>
            <div className="p-1.5 space-y-1">
              {(Object.entries(themeConfig) as [Theme, typeof themeConfig.light][]).map(([key, config]) => {
                const Icon = config.icon;
                const isActive = theme === key;
                return (
                  <button
                    key={key}
                    onClick={() => { setTheme(key); setIsOpen(false); }}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 ${
                      isActive
                        ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                        : 'text-foreground hover:bg-muted/50 border border-transparent'
                    }`}
                  >
                    {/* Color preview circle */}
                    <div
                      className="w-6 h-6 rounded-full border-2 flex items-center justify-center shrink-0"
                      style={{
                        backgroundColor: config.preview.bg,
                        borderColor: isActive ? config.preview.accent : 'var(--border)',
                      }}
                    >
                      <Icon className="w-3 h-3" style={{ color: config.preview.fg }} />
                    </div>
                    <div className="flex-1 text-left">
                      <p className="font-medium text-xs">{config.label}</p>
                      <p className="text-[10px] text-muted-foreground">{config.description}</p>
                    </div>
                    {isActive && <Check className="w-3.5 h-3.5 text-amber-500 shrink-0" />}
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>
    );
  }

  // Full inline selector (for settings panels)
  return (
    <div className="flex items-center gap-2">
      {(Object.entries(themeConfig) as [Theme, typeof themeConfig.light][]).map(([key, config]) => {
        const Icon = config.icon;
        const isActive = theme === key;
        return (
          <button
            key={key}
            onClick={() => setTheme(key)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-200 ${
              isActive
                ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20 shadow-sm'
                : 'text-muted-foreground hover:bg-muted/30 border border-transparent hover:border-border'
            }`}
            title={config.description}
          >
            <div
              className="w-4 h-4 rounded-full border"
              style={{
                backgroundColor: config.preview.bg,
                borderColor: isActive ? config.preview.accent : 'var(--border)',
              }}
            />
            <Icon className="w-3.5 h-3.5" />
            <span>{config.label}</span>
            {isActive && <Check className="w-3 h-3" />}
          </button>
        );
      })}
    </div>
  );
}
