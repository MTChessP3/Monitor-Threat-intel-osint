'use client';

import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';

export type Theme = 'light' | 'dim' | 'dark';

interface ThemeContextType {
  theme: Theme;
  setTheme: (theme: Theme) => void;
}

const ThemeContext = createContext<ThemeContextType>({
  theme: 'dim',
  setTheme: () => {},
});

export function useTheme() {
  return useContext(ThemeContext);
}

const THEME_STORAGE_KEY = 'actortrace-theme';
const DEFAULT_THEME: Theme = 'dim';

function getStoredTheme(): Theme {
  if (typeof window === 'undefined') return DEFAULT_THEME;
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === 'light' || stored === 'dim' || stored === 'dark') {
      return stored;
    }
  } catch {
    // localStorage unavailable
  }
  return DEFAULT_THEME;
}

function applyTheme(theme: Theme, animate: boolean = false) {
  const html = document.documentElement;

  // Add transition class for smooth animation
  if (animate) {
    html.classList.add('theme-transition');
  }

  // Remove all theme classes
  html.classList.remove('light', 'dim', 'dark');

  // Add the active theme class
  html.classList.add(theme);

  // Set a data-theme attribute for any CSS that needs it
  html.setAttribute('data-theme', theme);

  // Update meta theme-color for mobile browsers
  const themeColor = theme === 'light' ? '#f8fafc' : theme === 'dim' ? '#15202b' : '#0a0a0a';
  let metaThemeColor = document.querySelector('meta[name="theme-color"]');
  if (!metaThemeColor) {
    metaThemeColor = document.createElement('meta');
    metaThemeColor.setAttribute('name', 'theme-color');
    document.head.appendChild(metaThemeColor);
  }
  metaThemeColor.setAttribute('content', themeColor);

  // Remove transition class after animation completes
  if (animate) {
    const removeTransition = () => {
      html.classList.remove('theme-transition');
    };
    // 300ms matches the CSS transition duration
    setTimeout(removeTransition, 350);
  }
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(DEFAULT_THEME);
  const [mounted, setMounted] = useState(false);

  // Initialize theme from localStorage on mount
  useEffect(() => {
    const storedTheme = getStoredTheme();
    setThemeState(storedTheme);
    applyTheme(storedTheme, false);
    setMounted(true);
  }, []);

  const setTheme = useCallback((newTheme: Theme) => {
    setThemeState(newTheme);
    applyTheme(newTheme, true);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, newTheme);
    } catch {
      // localStorage unavailable
    }
  }, []);

  // Prevent flash of wrong theme — render nothing until mounted
  // This is important for SSR compatibility
  if (!mounted) {
    return (
      <ThemeContext.Provider value={{ theme: DEFAULT_THEME, setTheme: () => {} }}>
        {children}
      </ThemeContext.Provider>
    );
  }

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}
