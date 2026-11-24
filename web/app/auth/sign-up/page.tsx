import { redirect } from "next/navigation";

import { SignUpForm } from "../../../components/AuthForms.tsx";
import { PublicHeader } from "../../../components/PublicHeader.tsx";
import { currentUser } from "../../../lib/deprehendo-api.ts";

export const dynamic = "force-dynamic";

/** Already signed in: there is nothing to do here, so go to the dashboard. */
export default async function SignUp() {
  if (await currentUser()) redirect("/incidents");
  return (
    <>
      <PublicHeader current="auth" />
      <SignUpForm />
    </>
  );
}
