// Server-only bridge from the dashboard to the runopsy API
// (docs/cloud/browser-auth.md). every call:
//
//   1. requires a signed-in session (no session: redirect to sign-in);
//   2. takes the session's short-lived JWT from neon auth;
//   3. calls RUNOPSY_API_URL with authorization: bearer <jwt> and, when the
//      user has chosen one, X-Runopsy-Organization.
//
// the JWT never reaches the browser, so the API needs no CORS. authorization
// (organization membership, roles) is decided by the API on every request;
// this module only forwards identity.
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { auth } from "./auth/server.ts";

export const ORG_COOKIE = "runopsy_org";
const ORG_ID = /^org_[a-z0-9]{1,64}$/;
const API_TIMEOUT_MS = 15_000;

export interface ApiResult<T> {
  status: number;
  body: T | null;
  /** the §4 error envelope's code, when the API answered with one. */
  errorCode: string | null;
}

function apiBase(): URL {
  const raw = process.env.RUNOPSY_API_URL;
  if (!raw) throw new Error("RUNOPSY_API_URL is not set");
  return new URL(raw);
}

/** the signed-in user, or a redirect to sign-in. */
export async function requireUser(): Promise<{ id: string; email: string; name: string }> {
  const { data: session } = await auth.getSession();
  const user = session?.user;
  if (!user) return redirect("/auth/sign-in");
  return { id: user.id, email: user.email, name: user.name };
}

// the server SDK implements GET /token (its endpoint table lists it, and
// @neon/auth 0.8.2 defines it at runtime), but its type is picked from a
// client type without the JWT plugin, so TypeScript sees `unknown`. this is
// the shape neon's skill documents: `auth.token()` then `data.token`.
type TokenMethod = () => Promise<{ data?: { token?: string } | null; error?: unknown }>;
function sessionToken() {
  // called as a method at request time, so `this` is the SDK instance.
  return (auth as unknown as { token: TokenMethod }).token();
}

/** the organization the user picked, if it is well formed. */
export async function chosenOrganization(): Promise<string | null> {
  const value = (await cookies()).get(ORG_COOKIE)?.value ?? "";
  return ORG_ID.test(value) ? value : null;
}

export function isOrganizationId(value: string): boolean {
  return ORG_ID.test(value);
}

/**
 * GET one API path as the signed-in user. `withOrganization: false` is for
 * /api/me, which lists organizations and must work before one is chosen.
 */
export async function apiGet<T>(path: string, options: { withOrganization?: boolean } = {}): Promise<ApiResult<T>> {
  await requireUser();
  const { data, error } = await sessionToken();
  const jwt = data?.token;
  if (error || !jwt) return redirect("/auth/sign-in");

  const headers: Record<string, string> = { authorization: `Bearer ${jwt}`, accept: "application/json" };
  if (options.withOrganization !== false) {
    const org = await chosenOrganization();
    if (org) headers["x-runopsy-organization"] = org;
  }
  let res: Response;
  try {
    res = await fetch(new URL(path, apiBase()), {
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(API_TIMEOUT_MS),
    });
  } catch (err) {
    // API unreachable or timed out: a status page, not a crashed render. the
    // cause goes to the server log only (it names the API host and port).
    console.error("runopsy api unreachable:", (err as { cause?: { code?: string } }).cause?.code ?? String(err));
    return { status: 503, body: null, errorCode: "API_UNREACHABLE" };
  }
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  const errorCode =
    !res.ok && body && typeof body === "object" && "error" in body
      ? String((body as { error?: { code?: unknown } }).error?.code ?? "")
      : null;
  return { status: res.status, body: res.ok ? (body as T) : null, errorCode: errorCode || null };
}

/** the API's GET /api/me response (internal/cloudserver/me.go). */
export interface Me {
  user_id: string;
  auth: "browser" | "token";
  organizations: { id: string; name: string; role: string }[];
}
