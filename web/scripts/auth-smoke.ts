// Email-and-password sign-up smoke test for neon's managed better auth
// (contract §8.2, docs/cloud/browser-auth.md). it proves the auth service
// works end to end with a real user, using neon's auth SDK:
//
//   1. sign up a new user with email and password;
//   2. read the current user back from the session;
//   3. sign out, sign in again with the same password, read the user again;
//   4. take the session JWT and, if RUNOPSY_API_URL is set, call the runopsy
//      API's GET /api/me with it, which checks the go verifier against
//      neon's real signing keys.
//
// run from web/:  npm run auth:smoke
// it reads NEON_AUTH_BASE_URL from ../.env.local (written by `neon deploy`).
//
// nothing secret is printed: the password is random and kept in memory, and
// the session cookie and JWT are shown only by their length.
//
// node has no browser cookie jar, so the script carries the session cookie
// itself between calls. it also sends an origin header, because managed auth
// only accepts requests from trusted origins; localhost is trusted by default.

import { createAuthClient } from "@neon/auth";
import { randomBytes } from "node:crypto";

const baseURL = process.env.NEON_AUTH_BASE_URL;
if (!baseURL) {
  console.error("NEON_AUTH_BASE_URL is not set. Run `neon deploy` so it is written to .env.local.");
  process.exit(2);
}
const origin = process.env.AUTH_SMOKE_ORIGIN ?? "http://localhost:3000";
const email = process.env.AUTH_SMOKE_EMAIL ?? `runopsy-smoke-${Date.now()}@example.com`;
const password = randomBytes(18).toString("base64url"); // never printed
const apiURL = process.env.RUNOPSY_API_URL; // optional, e.g. http://127.0.0.1:6080

// plain better auth methods, no adapter (the skill's non-React form).
const client = createAuthClient(baseURL);

let cookie = "";
let sessionJWT = "";

type Ctx = { response: Response };

// keep the latest session cookie and the JWT the auth service sends back.
function capture(ctx: Ctx): void {
  const headers = ctx.response.headers;
  const setCookies = typeof headers.getSetCookie === "function" ? headers.getSetCookie() : [];
  const pairs = setCookies.map((c) => c.split(";")[0]?.trim()).filter((p): p is string => !!p);
  if (pairs.length > 0) {
    // merge by name so a later cookie replaces an earlier one.
    const jar = new Map(cookie.split("; ").filter(Boolean).map((p) => [p.split("=")[0], p] as const));
    for (const p of pairs) jar.set(p.split("=")[0], p);
    cookie = [...jar.values()].filter((p) => !p.endsWith("=")).join("; ");
  }
  const jwt = headers.get("set-auth-jwt");
  if (jwt) sessionJWT = jwt;
}

function fetchOptions() {
  return {
    headers: { origin, ...(cookie ? { cookie } : {}) },
    onSuccess: capture,
  };
}

// the SDK reports some failures by throwing an AuthApiError (for example a
// 401 on a wrong password) and others in the { data, error } result. call()
// turns both into the result shape so every step is handled the same way.
type Result<T> = { data: T | null; error: { status?: number; code?: string; message?: string } | null };
async function call<T>(fn: () => Promise<Result<T>>): Promise<Result<T>> {
  try {
    return await fn();
  } catch (err) {
    const e = err as { __isAuthError?: boolean; status?: number; code?: string; message?: string };
    if (e && e.__isAuthError) return { data: null, error: { status: e.status, code: e.code, message: e.message } };
    throw err;
  }
}

function fail(step: string, error: unknown): never {
  const e = (error ?? {}) as { status?: number; code?: string; message?: string };
  console.error(`FAIL ${step}: ${e.status ?? ""} ${e.code ?? ""} ${e.message ?? String(error)}`.trim());
  process.exit(1);
}

async function currentUser(step: string): Promise<{ id: string; email: string }> {
  const res = await call(() => client.getSession({ fetchOptions: fetchOptions() }) as Promise<Result<any>>);
  if (res.error) fail(step, res.error);
  const user = res.data?.user;
  if (!user?.id) fail(step, { message: "no signed-in user in the session" });
  return { id: user.id, email: user.email };
}

console.log(`auth: ${new URL(baseURL).origin}`);
console.log(`test user: ${email}`);

// 1. sign up.
const signUp = await call(() => client.signUp.email({ email, password, name: "Runopsy smoke test" }, fetchOptions()) as Promise<Result<any>>);
if (signUp.error) fail("sign-up", signUp.error);
const signedUpID = signUp.data?.user?.id;
console.log(`PASS sign-up: user ${signedUpID}`);

// 2. read the current user back.
const first = await currentUser("session after sign-up");
if (first.id !== signedUpID || first.email !== email) {
  fail("session after sign-up", { message: `session user ${first.id} <${first.email}> does not match the new user` });
}
console.log(`PASS current user: ${first.id} <${first.email}>`);

// 3. sign out, then sign in with the same password.
const out = await call(() => client.signOut({ fetchOptions: fetchOptions() }) as Promise<Result<any>>);
if (out.error) fail("sign-out", out.error);
cookie = "";
sessionJWT = "";
const afterOut = await call(() => client.getSession({ fetchOptions: fetchOptions() }) as Promise<Result<any>>);
if (afterOut.data?.user) fail("sign-out", { message: "a session survived sign-out" });
console.log("PASS sign-out: no session");

const wrong = await call(() => client.signIn.email({ email, password: password + "x" }, fetchOptions()) as Promise<Result<any>>);
if (!wrong.error) fail("wrong password", { message: "a wrong password was accepted" });
if (wrong.error.status !== 401) fail("wrong password", wrong.error);
console.log(`PASS wrong password refused (${wrong.error.status} ${wrong.error.code ?? ""})`);

const signIn = await call(() => client.signIn.email({ email, password }, fetchOptions()) as Promise<Result<any>>);
if (signIn.error) fail("sign-in", signIn.error);
const again = await currentUser("session after sign-in");
if (again.id !== signedUpID) fail("session after sign-in", { message: "signed in as a different user" });
console.log(`PASS sign-in: ${again.id}`);

// 4. the session JWT, and the runopsy API reading the user from it.
if (!sessionJWT) {
  const tok = await call(() => client.token({ fetchOptions: fetchOptions() }) as Promise<Result<any>>);
  if (tok.error) fail("session JWT", tok.error);
  sessionJWT = tok.data?.token ?? "";
}
if (!sessionJWT || sessionJWT.split(".").length !== 3) fail("session JWT", { message: "no JWT returned" });
console.log(`PASS session JWT: ${sessionJWT.length} characters (not shown)`);

if (apiURL) {
  const res = await fetch(new URL("/api/me", apiURL), { headers: { authorization: `Bearer ${sessionJWT}` } });
  const body = (await res.json().catch(() => ({}))) as { user_id?: string; auth?: string; error?: { code?: string } };
  if (res.status !== 200 || body.user_id !== signedUpID || body.auth !== "browser") {
    fail("Runopsy /api/me", { status: res.status, code: body.error?.code, message: "API did not return the signed-in user" });
  }
  console.log(`PASS Runopsy API /api/me: user ${body.user_id} (auth ${body.auth})`);
} else {
  console.log("SKIP Runopsy API check (set RUNOPSY_API_URL to run it)");
}

console.log("ALL PASS");
