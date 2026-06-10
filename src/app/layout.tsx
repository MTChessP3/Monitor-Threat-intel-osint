import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/sonner";
import { ThemeProvider } from "@/components/ThemeProvider";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "VIP-Intelligence — Protección Digital de Ejecutivos",
  description: "Plataforma corporativa de inteligencia y protección ejecutiva VIP. Análisis de amenazas, informes ejecutivos y gestión de fuentes de inteligencia.",
  icons: {
    icon: [
      { url: "/favicon-32x32.png", sizes: "32x32", type: "image/png" },
      { url: "/favicon-16x16.png", sizes: "16x16", type: "image/png" },
      { url: "/logo.svg", type: "image/svg+xml" },
    ],
    apple: "/apple-touch-icon.png",
  },
};

/**
 * Inline script to prevent theme flash on page load.
 * Runs before React hydrates, reading from localStorage.
 * Default theme is "dim" (midnight) for new users.
 */
const themeScript = `
(function() {
  try {
    var theme = localStorage.getItem('actortrace-theme');
    if (theme !== 'light' && theme !== 'dim' && theme !== 'dark') theme = 'dim';
    var html = document.documentElement;
    html.classList.remove('light', 'dim', 'dark');
    html.classList.add(theme);
    html.setAttribute('data-theme', theme);
    var themeColor = theme === 'light' ? '#f7f8fa' : theme === 'dim' ? '#1a1f2e' : '#0d1117';
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', themeColor);
  } catch(e) {}
})();
`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
        <meta name="theme-color" content="#1a1f2e" />
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        <ThemeProvider>
          {children}
          <Toaster richColors position="top-right" />
        </ThemeProvider>
      </body>
    </html>
  );
}
