// types for the deprehendo.analysis document, version 1 (docs/cloud/contract.md §3.3).
//
// the document is produced by the go analyzer (internal/analysis.Run). this
// file only describes its JSON so the dashboard can read it. it never
// interprets it: no diagnosis, confidence, causal link or evidence class is
// derived here (contract §3.1, checklist 7.43).
//
// field names are the wire names. several go types have no JSON tags, so
// their keys are go field names: causal.SubjectRef ("kind", "ID"),
// collector.Snapshot ("CaptureIndex"), causal.RejectedEdge (all five fields)
// and analysis.Interpretation's provider list. those are typed exactly as the
// fixtures show them. the fixtures in test/fixtures/analysis are real output
// (see test/fixtures/README.md); test/fixtures.test.ts pins their key set.

export const SUPPORTED_DOCUMENT_VERSION = 1;

/** evidence class of one premise (internal/incident/quality.go). */
export type Quality =
  | "DIRECT_KERNEL"
  | "DIRECT_PROCESS"
  | "DERIVED_SNAPSHOT"
  | "PROVIDER_LOG"
  | "PROVIDER_API"
  | "AGENT"
  | "UNKNOWN";

/** Claim-level word (internal/incident/quality.go, contract §10). */
export type ClaimWord = "direct" | "mixed" | "inferred" | "unknown";

export type ConfidenceBand = "LOW" | "MEDIUM" | "HIGH" | "MODERATE" | string;

export type FailureStatus = "EXPLAINED" | "AMBIGUOUS" | "UNKNOWN";

export type EventClass = "CONDITION" | "FAILURE" | "CONTEXT";

export type CheckStatus = "PRESENT" | "ABSENT" | "UNKNOWN";

/**
 * edge relation. the vocabulary may grow, so it is open. the values the UI
 * names are listed for documentation only.
 */
export type Relation =
  | "CAUSES"
  | "CONTRIBUTES_TO"
  | "PRECEDES"
  | "CORRELATED_WITH"
  | "RECOVERY_OF"
  | "CONTRADICTS"
  | "ESCALATES_TO"
  | (string & {});

export interface Engine {
  analyzer_version: string;
  signature_version: number;
  signature_set_version: number;
  /** sha256 over the sorted causal rule IDs (golden test pins it). */
  causal_rules: string;
  privacy_policy: string;
  bundle_formats: { format_version: number; schema_version: number }[];
}

export interface FileDigest {
  size: number;
  sha256: string;
}

export interface BundleInfo {
  sha256: string;
  incident_id: string;
  schema_version: number;
  format_version: number;
  snapshot_encoding: string;
  created_at: string;
  agent_version: string;
  platform: string;
  architecture: string;
  files?: Record<string, FileDigest>;
}

/**
 * what the bundle contains. A true flag means the kind of data is present in
 * the bundle. A false flag means it is absent, whether because it was
 * redacted or never collected: the report cannot tell those apart.
 */
export interface PrivacyReport {
  policy: string;
  hostname: boolean;
  command_lines: boolean;
  environment: boolean;
  repository_name: boolean;
  network_addresses: boolean;
  filesystem_paths: boolean;
  process_names: boolean;
  user_note: boolean;
  provider_identifiers?: boolean;
}

/** diagnosis.Evidence. observed/threshold are heterogeneous, so they are unknown. */
export interface Evidence {
  code: string;
  source: string;
  at: string;
  weight: number;
  observed?: unknown;
  threshold?: unknown;
}

export interface SignatureMatch {
  signature: string;
  signature_version: number;
  confidence: number;
  confidence_band: ConfidenceBand;
  severity: string;
  summary: string;
  supporting?: Evidence[];
  contradicting?: Evidence[];
  missing_evidence?: string[];
  attributes?: Record<string, string>;
  process_group_id?: number;
  process_identities?: { pid: number; start_ticks: number }[];
  related_events?: string[];
  /** present on rejections only: why the signature is not a diagnosis. */
  rejected?: string;
}

/** diagnosis.Report. `unknown` is true when no signature cleared the bar. */
export interface DiagnosisReport {
  incident_id: string;
  trigger: string;
  triggered_at: string;
  analyzer_version: string;
  signature_set_version: number;
  min_confidence: number;
  matches: SignatureMatch[];
  rejections: SignatureMatch[];
  ambiguous?: string[];
  unknown: boolean;
  strong_observations?: Evidence[];
}

/** causal.Event with its JSON keys. optional keys are omitted when empty. */
export interface CausalEvent {
  id: string;
  type: string;
  timestamp: string;
  sequence: number;
  /** causal.SubjectRef has no JSON tags: keys are "kind" and "ID". */
  subject: { Kind: string; ID: string };
  data?: Record<string, unknown>;
  provenance: {
    rule_id?: string;
    sources: { kind: "snapshot" | "event" | "trigger" | (string & {}); ref: string }[];
  };
  class: EventClass;
  episode?: string;
  pid?: number;
  ppid?: number;
  start_ticks?: number;
  onset_unknown?: boolean;
  onset_window?: { not_before: string; observed_at: string };
}

/** one timeline entry: the event with its per-event evidence class. */
export interface TimelineEvent extends CausalEvent {
  evidence_class: Quality;
}

export interface CausalNode {
  event: CausalEvent;
  evidence_class: Quality;
}

export interface CheckRecord {
  kind: "required" | "contradicting" | "supporting" | (string & {});
  code: string;
  status: CheckStatus;
  detail: string;
  sampled?: boolean;
}

export interface CausalEdge {
  id: string;
  from: string;
  to: string;
  relation: Relation;
  confidence: ConfidenceBand;
  rule: string;
  checks: CheckRecord[];
  demotions?: string[];
  same_instant?: boolean;
  mechanism: string;
  missing_supporting?: string[];
  competes_with?: string[];
}

/** causal.RejectedEdge has no JSON tags: keys are the go field names. */
export interface RejectedEdge {
  From: string;
  To: string;
  Relation: Relation;
  RuleID: string;
  Reason: string;
}

export interface CausalFailure {
  anchor: string;
  anchor_type: string;
  status: FailureStatus;
  candidates?: unknown[];
  /** ordered event IDs from the root to the anchor, as go computed them. */
  known_chain?: string[];
  missing_evidence?: string[];
  alternatives: string[];
  claim: ClaimWord;
}

export interface CausalSection {
  healthy: boolean;
  other_exits: number;
  unconfirmed_severe?: string[];
  nodes: CausalNode[];
  /**
   * null when the graph has no accepted edge: go nil slices serialize as
   * null. every consumer must accept both forms.
   */
  edges: CausalEdge[] | null;
  rejected_edges?: RejectedEdge[];
  failures: CausalFailure[];
}

export interface ProcessSnapshot {
  pid: number;
  ppid: number;
  pgid: number;
  sid: number;
  name: string;
  state: string;
  rss_bytes?: number;
  cpu_ticks?: number;
  start_ticks?: number;
  threads?: number;
  exit_status?: string;
  cpu_percent: number;
  open_fds: number;
}

export interface ConnectionSnapshot {
  local_addr: string;
  local_port: number;
  remote_addr: string;
  remote_port: number;
  state: string;
  inode?: number;
  pid?: number;
  start_ticks?: number;
  fd: number;
}

/** subset of collector.SystemSnapshot the dashboard renders. */
export interface SystemSnapshot {
  cpu_available: boolean;
  cpu_percent_available: boolean;
  cpu_percent: number;
  cpu_count: number;
  load_available: boolean;
  load_average: number;
  memory_stats_available: boolean;
  memory_total: number;
  memory_used: number;
  memory_free: number;
  memory_cached?: number;
  memory_buffers?: number;
  swap_total?: number;
  swap_free?: number;
  process_count_available: boolean;
  process_count: number;
}

/** one capture sample. the series keeps capture order (index == position). */
export interface Snapshot {
  timestamp: string;
  /**
   * collector.Snapshot has no JSON tag: the key is "CaptureIndex". it is zero
   * in v1 bundles, so order and label samples by array position instead.
   */
  CaptureIndex: number;
  system?: SystemSnapshot;
  /** pressure keys are cpu/io/memory; their values are not rendered yet. */
  pressure?: Record<string, unknown>;
  processes?: ProcessSnapshot[];
  connections?: ConnectionSnapshot[];
  errors?: { collector: string; error: string }[];
}

/**
 * the whole document. diagnosis is null when the analyzer produced none,
 * and providers is absent when the bundle has none. provider interpretations
 * carry go field names (no JSON tags) and are not typed here yet.
 */
/**
 * evaluation options actually applied by the engine. absent when the run used
 * the defaults, which is what the cloud always does (§3.3).
 */
export interface DocumentOptions {
  min_confidence: number;
  disabled?: string[];
}

export interface AnalysisDocument {
  document_version: number;
  engine: Engine;
  options?: DocumentOptions;
  bundle: BundleInfo;
  privacy: PrivacyReport;
  diagnosis: DiagnosisReport | null;
  providers?: unknown[];
  causal: CausalSection;
  timeline: TimelineEvent[];
  series: Snapshot[];
}
