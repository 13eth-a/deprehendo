import { readFileSync } from "node:fs";
import { join } from "node:path";
import { redirect } from "next/navigation";

import { DemoIncident } from "../../components/DemoIncident.tsx";
import { FailureState } from "../../components/FailureState.tsx";
import { PublicHeader, SiteFooter } from "../../components/PublicHeader.tsx";
import { checkAnalysisDocument } from "../../lib/guards.ts";
import { currentUser } from "../../lib/deprehendo-api.ts";

function one(value: string | string[] | undefined): string | undefined {
  const v = Array.isArray(value) ? value[0] : value;
  return v ? v.slice(0, 200) : undefined;
}

// The sample is a checked-in fixture produced by the real analyzer from
// testdata/incidents/frozen-worker.deprehendo; it contains no customer data.
// It is for signed-out visitors only: a signed-in user has real incidents.
export default async function Demo({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  if (await currentUser()) redirect("/incidents");
  const raw = JSON.parse(readFileSync(join(process.cwd(), "test/fixtures/analysis/frozen-worker.json"), "utf8"));
  const check = checkAnalysisDocument(raw);
  const params = await searchParams;
  const requested = Number(one(params.page) ?? "1");
  return (
    <>
      <PublicHeader current="demo" />
      {check.ok ? (
        <DemoIncident
          doc={check.document}
          uploadHref="/auth/sign-in"
          page={Number.isInteger(requested) ? requested : 1}
          selectedEvent={one(params.event)}
          selectedEvidence={one(params.evidence)}
        />
      ) : (
        <main className="page">
          <FailureState kind="invalid_document" detail={check.detail} />
        </main>
      )}
      <SiteFooter />
    </>
  );
}
