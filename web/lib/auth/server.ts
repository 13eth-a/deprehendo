// neon managed better auth, server side (contract §8.2, docs/cloud/browser-auth.md).
// one instance for server components, server actions, route handlers and the
// proxy. NEON_AUTH_BASE_URL comes from `neon deploy`; the cookie secret is
// the app's own (32+ characters, `openssl rand -base64 32`).
import { createNeonAuth } from "@neon/auth/next/server";

export const auth = createNeonAuth({
  baseUrl: process.env.NEON_AUTH_BASE_URL!,
  cookies: { secret: process.env.NEON_AUTH_COOKIE_SECRET! },
});
