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
    description: 'Uso diario, ambientes iluminados',
    icon: Sun,
    preview: { bg: '#f7f8fa', fg: '#1a2332', accent: '#1e3a5f' },
  },
  dim: {
    label: 'Intermedio',
    description: 'Sesiones prolongadas, equilibrio visual',
    icon: MoonStar,
    preview: { bg: '#1a1f2e', fg: '#c8cdd5', accent: '#4a8cc7' },
  },
  dark: {
    label: 'Oscuro',
    description: 'Pantallas OLED, baja iluminación',
    icon: Moon,
    preview: { bg: '#0d1117', fg: '#c9d1d9', accent: '#5b9bd5' },
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
          className="flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium
                     bg-muted/30 border border-border hover:bg-muted/50 transition-colors duration-150"
          title={`Tema: ${currentConfig.label}`}
        >
          <CurrentIcon className="w-3.5 h-3.5 text-primary" />
          <span className="hidden sm:inline text-muted-foreground">{currentConfig.label}</span>
        </button>

        {isOpen && (
          <div className="absolute right-0 top-full mt-2 w-60 rounded-lg border border-border bg-card shadow-lg z-50 overflow-hidden">
            <div className="px-3 py-2 border-b border-border">
              <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Tema Visual</p>
            </div>
            <div className="p-1.5 space-y-0.5">
              {(Object.entries(themeConfig) as [Theme, typeof themeConfig.light][]).map(([key, config]) => {
                const Icon = config.icon;
                const isActive = theme === key;
                return (
                  <button
                    key={key}
                    onClick={() => { setTheme(key); setIsOpen(false); }}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors duration-150 ${
                      isActive
                        ? 'bg-primary/10 text-primary border border-primary/15'
                        : 'text-foreground hover:bg-muted/40 border border-transparent'
                    }`}
                  >
                    <div
                      className="w-5 h-5 rounded-full border shrink-0"
                      style={{
                        backgroundColor: config.preview.bg,
                        borderColor: isActive ? config.preview.accent : 'var(--border)',
                      }}
                    />
                    <div className="flex-1 text-left">
                      <p className="font-medium text-xs">{config.label}</p>
                      <p className="text-[10px] text-muted-foreground leading-tight">{config.description}</p>
                    </div>
                    {isActive && <Check className="w-3.5 h-3.5 text-primary shrink-0" />}
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
            className={`flex items-center gap-2 px-3 py-2 rounded-md text-xs font-medium transition-colors duration-150 ${
              isActive
                ? 'bg-primary/10 text-primary border border-primary/15'
                : 'text-muted-foreground hover:bg-muted/30 border border-transparent hover:border-border'
            }`}
            title={config.description}
          >
            <div
              className="w-3.5 h-3.5 rounded-full border"
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
