import { readFileSync } from "node:fs";
import { join } from "node:path";

import { DemoIncident } from "../../components/DemoIncident.tsx";
import { FailureState } from "../../components/FailureState.tsx";
import { checkAnalysisDocument } from "../../lib/guards.ts";

// the sample is a checked-in fixture produced by the real analyzer from
// testdata/incidents/frozen-worker.runopsy; it contains no customer data.
export default function Demo() {
  const raw = JSON.parse(readFileSync(join(process.cwd(), "test/fixtures/analysis/frozen-worker.json"), "utf8"));
  const check = checkAnalysisDocument(raw);
  if (!check.ok) return <FailureState kind="invalid_document" detail={check.detail} />;
  return <DemoIncident doc={check.document} uploadHref="/auth/sign-in" />;
}
