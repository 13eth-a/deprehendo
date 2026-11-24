import { redirect } from "next/navigation";

import { SignInForm } from "../../../components/AuthForms.tsx";
import { PublicHeader } from "../../../components/PublicHeader.tsx";
import { currentUser } from "../../../lib/deprehendo-api.ts";

export const dynamic = "force-dynamic";

/** Already signed in: there is nothing to do here, so go to the dashboard. */
export default async function SignIn({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  if (await currentUser()) redirect("/incidents");
  const query = await searchParams;
  const reset = query.reset === "1";
  const verified = query.verified === "1";
  return (
    <>
      <PublicHeader current="auth" />
      <SignInForm passwordReset={reset} verified={verified} />
    </>
  );
}
