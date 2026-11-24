/**
 * copy for every state the dashboard can show instead of data (checklist
 * 7.32: "no blank pages"). each entry says what happened and what the user
 * can do next. none of it states a diagnosis.
 */
export type FailureKind =
  | "unsupported_bundle"
  | "corrupt_bundle"
  | "invalid_document"
  | "unsupported_version"
  | "missing_trace"
  | "partial_evidence"
  | "old_analyzer"
  | "unknown_diagnosis";

export interface FailureCopy {
  title: string;
  body: string;
  action?: string;
}

export const FAILURE_COPY: Record<FailureKind, FailureCopy> = {
  unsupported_bundle: {
    title: "This bundle format is not supported",
    body: "The bundle was written in a format this version of Deprehendo Cloud cannot read. Nothing was changed, and the original file is still available for download.",
    action: "Download the original bundle, or open it with a matching deprehendo-agent release.",
  },
  corrupt_bundle: {
    title: "This bundle is damaged",
    body: "The file failed integrity checks, so it cannot be analyzed. Nothing was stored from it.",
    action: "Upload the file again from the machine that wrote it.",
  },
  invalid_document: {
    title: "The analysis could not be displayed",
    body: "The stored analysis does not match the expected format. The raw bundle is unchanged.",
    action: "Try again later. If it persists, report the incident ID.",
  },
  unsupported_version: {
    title: "This analysis uses a newer format",
    body: "The stored analysis was produced by a newer document version than this dashboard reads.",
    action: "Reload after the dashboard update is deployed.",
  },
  missing_trace: {
    title: "No kernel trace in this incident",
    body: "The bundle has no direct kernel observations. Conclusions rely on periodic samples, so they are inferred, not observed.",
  },
  partial_evidence: {
    title: "Some evidence is missing",
    body: "Some collectors did not report during this incident. The diagnosis lists what it could not check.",
  },
  old_analyzer: {
    title: "A newer analyzer is available",
    body: "This analysis was produced by an older analyzer. Its results are stored as they were. Re-analysis creates a new result and does not replace this one.",
    action: "Re-analyze to compare results.",
  },
  unknown_diagnosis: {
    title: "No known signature matched",
    body: "Deprehendo did not find a known failure pattern. The timeline and evidence below are still complete.",
  },
};

export function failureCopy(kind: FailureKind): FailureCopy {
  return FAILURE_COPY[kind];
}
