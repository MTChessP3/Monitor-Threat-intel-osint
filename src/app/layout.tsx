import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "MONITOR-THREAT | Cyber Threat Intelligence Platform",
  description: "Professional OSINT threat intelligence platform for cybersecurity analysis, IP geolocation, CVE tracking, and executive reporting.",
  keywords: ["OSINT", "Threat Intelligence", "Cybersecurity", "CVE", "IP Geolocation", "Malware Analysis", "APT Tracking"],
  authors: [{ name: "MONITOR-THREAT Team" }],
  icons: {
    icon: "/logo.svg",
  },
  openGraph: {
    title: "MONITOR-THREAT - Cyber Threat Intelligence Platform",
    description: "Professional-grade threat intelligence for security operations",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-black text-white`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
