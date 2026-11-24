// route protection (next 16 proxy). Signed-out visitors reach only the public
// pages below and the SDK's own auth routes (/api/auth, /auth/sign-in,
// /auth/sign-up, ... are public by default). pages that read data still check
// the session themselves (lib/deprehendo-api.ts); this redirect is not the
// authorization.
import { auth } from "./lib/auth/server.ts";

export default auth.middleware({
  loginUrl: "/auth/sign-in",
  publicRoutes: ["/", "/demo", "/install", "/auth/reset-password"],
});

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|icon.svg).*)"],
};
