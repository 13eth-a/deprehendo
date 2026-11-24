import type { ReactNode } from "react";
import { cookies } from "next/headers";
import { IBM_Plex_Mono, IBM_Plex_Sans, IBM_Plex_Sans_Condensed } from "next/font/google";

import { ZoneProvider } from "../components/Clock.tsx";
import { decodeDisplay, DISPLAY_COOKIE } from "../lib/display.ts";
import "../styles/dashboard.css";
import "../styles/vendor.css";

// IBM Plex: an engineering typeface family with a true condensed cut for
// headings and a monospace for machine values (signatures, IDs, times).
// next/font downloads the files at build time and serves them from this app,
// so the CSP's font-src 'self' still holds.
const sans = IBM_Plex_Sans({ subsets: ["latin"], weight: ["400", "500", "600"], variable: "--font-plex-sans", display: "swap" });
const condensed = IBM_Plex_Sans_Condensed({ subsets: ["latin"], weight: ["500", "600"], variable: "--font-plex-condensed", display: "swap" });
const mono = IBM_Plex_Mono({ subsets: ["latin"], weight: ["400", "500"], variable: "--font-plex-mono", display: "swap" });

export const metadata = {
  title: { default: "deprehendo", template: "%s · deprehendo" },
  description: "Find out why a self-hosted GitHub Actions runner died.",
};

// display settings (lib/display.ts) are read here, so the first response
// already has the reader's theme, density and time zone.
export default async function RootLayout({ children }: { children: ReactNode }) {
  const display = decodeDisplay((await cookies()).get(DISPLAY_COOKIE)?.value);
  return (
    <html
      lang="en"
      className={`${sans.variable} ${condensed.variable} ${mono.variable}`}
      data-theme={display.theme}
      data-density={display.density}
    >
      <body>
        <ZoneProvider zone={display.zone}>{children}</ZoneProvider>
      </body>
    </html>
  );
}
