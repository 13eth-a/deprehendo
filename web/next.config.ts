import type { NextConfig } from "next";

// security headers for the dashboard (7.60 gate; docs/cloud/browser-auth.md
// step 4). the browser talks only to this app's own origin: the auth client
// goes through /api/auth, and runopsy API calls are made server-side, so
// connect-src stays 'self'. the neon auth origin is allowed for frames only,
// for the SDK's OAuth popup flow.
//
// Next.js injects inline bootstrap scripts, so script-src needs
// 'unsafe-inline' without a nonce. in development the policy is off, because react's
// refresh runtime needs eval.
function authOrigin(): string {
  try {
    return new URL(process.env.NEON_AUTH_BASE_URL ?? "").origin;
  } catch {
    return "";
  }
}

const isProduction = process.env.NODE_ENV === "production";

const csp = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  `frame-src 'self' ${authOrigin()}`.trim(),
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join("; ");

const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "same-origin" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  ...(isProduction
    ? [
        { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
        { key: "Content-Security-Policy", value: csp },
      ]
    : []),
];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  // the repo root also has a package-lock.json (neon's CLI tooling), so pin
  // the workspace root to this app. `next build` runs from web/, locally and
  // on railway (root directory "web").
  turbopack: { root: process.cwd() },
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
