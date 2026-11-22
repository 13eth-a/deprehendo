"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { apiGet, isOrganizationId, ORG_COOKIE, type Me } from "../../lib/runopsy-api.ts";

/**
 * remembers the chosen organization. it is set only if the API lists the user
 * as a member right now; the API still checks membership on every request,
 * so the cookie is a preference, not a permission.
 */
export async function chooseOrganization(formData: FormData): Promise<void> {
  const org = String(formData.get("organization") ?? "");
  if (!isOrganizationId(org)) redirect("/org");
  const me = await apiGet<Me>("/api/me", { withOrganization: false });
  if (!me.body?.organizations.some((o) => o.id === org)) redirect("/org");
  (await cookies()).set(ORG_COOKIE, org, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 365,
  });
  redirect("/incidents");
}
