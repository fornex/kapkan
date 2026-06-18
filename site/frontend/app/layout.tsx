import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono, Poppins } from "next/font/google";
import "./globals.css";
import { site } from "@/lib/site";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

// Brand wordmark face — Poppins 600, self-hosted by next/font. Used only by
// the <Logo> lockup (see components/Logo.tsx + .kapkan-word in globals.css).
const poppins = Poppins({
  variable: "--font-poppins",
  subsets: ["latin"],
  weight: ["600"],
});

const description =
  "Kapkan is a single Go binary that ingests NetFlow/IPFIX/sFlow telemetry, detects volumetric DDoS attacks in seconds, and triggers automated BGP RTBH mitigation. Free and open source.";

// favicon.ico, icon.svg, apple-icon.png and opengraph-image/twitter-image live
// in app/ as file-convention metadata — Next emits their <head> tags and
// (with metadataBase) absolute social-card URLs automatically.
export const metadata: Metadata = {
  metadataBase: new URL("https://kapkan.io"),
  title: {
    default: `${site.name} — ${site.tagline}`,
    template: `%s — ${site.name}`,
  },
  description,
  applicationName: site.name,
  manifest: "/site.webmanifest",
  openGraph: {
    type: "website",
    siteName: site.name,
    url: "/",
    title: `${site.name} — ${site.tagline}`,
    description,
  },
  twitter: {
    card: "summary_large_image",
    title: `${site.name} — ${site.tagline}`,
    description,
  },
};

export const viewport: Viewport = {
  themeColor: "#0f1419",
};

// Set the theme class before paint to avoid a flash of the wrong theme.
const themeScript = `(function(){try{var t=localStorage.getItem('theme');var d=t?t==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;if(d)document.documentElement.classList.add('dark');}catch(e){}})();`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${geistSans.variable} ${geistMono.variable} ${poppins.variable} h-full antialiased`}
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body className="min-h-full bg-background font-sans text-foreground">{children}</body>
    </html>
  );
}
