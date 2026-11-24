"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { auth } from "../../lib/auth/server.ts";
import { checkPasswordChange, cleanName, type AccountStatus } from "../../lib/account.ts";
import { requireUser } from "../../lib/deprehendo-api.ts";
import { cleanDisplay, DISPLAY_COOKIE, encodeDisplay } from "../../lib/display.ts";
import { LINK_COOKIE } from "../../lib/account.ts";

// Neon Auth (Better Auth) user endpoints, called on the server so passwords
// travel only in the POST body to this app and then to Neon. The SDK lists
// these methods in its endpoint table (update-user, change-password,
// revoke-other-sessions); the narrow types below are the request and result
// shapes Better Auth documents, written out so a loose SDK type does not leak
// `any` into this file.
type AuthResult = { data?: unknown; error?: { status?: number; code?: string; message?: string } | null };
type UserMethods = {
  updateUser(body: { name: string }): Promise<AuthResult>;
  changePassword(body: { currentPassword: string; newPassword: string; revokeOtherSessions: boolean }): Promise<AuthResult>;
  revokeOtherSessions(): Promise<AuthResult>;
};
const users = auth as unknown as UserMethods;

function back(status: AccountStatus): never {
  redirect(`/account?status=${status}`);
}

async function call(fn: () => Promise<AuthResult>): Promise<AuthResult["error"]> {
  try {
    return (await fn())?.error ?? null;
  } catch (err) {
    return (err as AuthResult["error"]) ?? { message: "request failed" };
  }
}

export async function updateName(formData: FormData): Promise<void> {
  await requireUser();
  const name = cleanName(String(formData.get("name") ?? ""));
  if (!name) back("name-invalid");
  const error = await call(() => users.updateUser({ name }));
  back(error ? "failed" : "name-saved");
}

export async function changePassword(formData: FormData): Promise<void> {
  await requireUser();
  const current = String(formData.get("current") ?? "");
  const next = String(formData.get("next") ?? "");
  const confirm = String(formData.get("confirm") ?? "");
  const problem = checkPasswordChange(current, next, confirm);
  if (problem) back(problem);
  const error = await call(() =>
    users.changePassword({ currentPassword: current, newPassword: next, revokeOtherSessions: true }),
  );
  if (!error) back("password-changed");
  // Better Auth answers a wrong current password with INVALID_PASSWORD (400)
  // and an account without a password (GitHub only) with CREDENTIAL_ACCOUNT_NOT_FOUND.
  if (error.code === "CREDENTIAL_ACCOUNT_NOT_FOUND") back("password-none");
  if (error.code === "INVALID_PASSWORD" || error.status === 400 || error.status === 401) back("password-wrong");
  back("failed");
}

export async function signOutOtherDevices(): Promise<void> {
  await requireUser();
  const error = await call(() => users.revokeOtherSessions());
  back(error ? "failed" : "sessions-revoked");
}

/** Display settings are per browser: a cookie, not the account. Bad values fall back to the defaults. */
export async function saveDisplay(formData: FormData): Promise<void> {
  await requireUser();
  const settings = cleanDisplay({
    theme: formData.get("theme"),
    zone: formData.get("zone"),
    density: formData.get("density"),
  });
  (await cookies()).set(DISPLAY_COOKIE, encodeDisplay(settings), {
    path: "/",
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: 60 * 60 * 24 * 365,
  });
  back("display-saved");
}

/**
 * GitHub linking runs through the normal GitHub sign-in (link-social cannot:
 * its OAuth state cookie is set on this app's origin, but GitHub returns to
 * Neon's callback, which never sees it, so every attempt fails with
 * state_mismatch). Neon Auth links a GitHub sign-in to the existing account
 * when the verified emails match. This notes who started, so the account
 * page can tell afterwards whether GitHub was linked here or the sign-in
 * landed in a different account.
 */
export async function startGitHubLink(): Promise<void> {
  const user = await requireUser();
  (await cookies()).set(LINK_COOKIE, user.id, {
    path: "/account",
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: 10 * 60,
  });
}
