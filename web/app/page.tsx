import { redirect } from "next/navigation";

import { LandingPage } from "../components/LandingPage.tsx";
import { PublicHeader, SiteFooter } from "../components/PublicHeader.tsx";
import { currentUser } from "../lib/deprehendo-api.ts";

export const dynamic = "force-dynamic";

/** Signed-out landing page. A signed-in visitor goes straight to the dashboard. */
export default async function Home() {
  if (await currentUser()) redirect("/incidents");
  return (
    <>
      <PublicHeader />
      <LandingPage installHref="/install" demoHref="/demo" />
      <SiteFooter />
    </>
  );
}
