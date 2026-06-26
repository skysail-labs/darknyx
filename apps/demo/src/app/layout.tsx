import type { Metadata, Viewport } from "next";
import { JetBrains_Mono, Space_Grotesk } from "next/font/google";

import "./globals.css";

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-space-grotesk",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-jetbrains-mono",
  display: "swap",
});

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: "Nyx — settle in the dark, prove in the light",
  description:
    "A privacy-preserving darkpool on Solana with TEE-attested execution and zero-knowledge settlement.",
  icons: {
    icon: [
      { url: "/favicon.svg", type: "image/svg+xml" },
      { url: "/favicon-32.png", sizes: "32x32" },
    ],
    apple: "/apple-touch-icon.png",
  },
  manifest: "/site.webmanifest",
  openGraph: {
    title: "Nyx — settle in the dark, prove in the light",
    description:
      "A privacy-preserving darkpool on Solana with TEE-attested execution and zero-knowledge settlement.",
    images: ["/brand/og-default.png"],
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Nyx — settle in the dark, prove in the light",
    description:
      "A privacy-preserving darkpool on Solana with TEE-attested execution and zero-knowledge settlement.",
    images: ["/brand/og-default.png"],
  },
};

export const viewport: Viewport = {
  themeColor: "#0a0a0d",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${spaceGrotesk.variable} ${jetbrainsMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-nyx-ink text-nyx-chalk">
        {children}
      </body>
    </html>
  );
}
