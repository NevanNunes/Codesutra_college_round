// Frozen contract types — field names must match D's snake_case wire format exactly.
// Do NOT rename fields. Any schema changes go through Session D.

export type DefensePreset = 'baseline' | 'gateway';
export type ExecutionMode = 'live' | 'fixture';
export type RunStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'interrupted';
export type Surface = 'document' | 'email';
export type OracleOutcome = 'success' | 'failure' | 'inconclusive';
export type CaseStatus = 'completed' | 'failed' | 'cancelled' | 'timed_out';
export type RunPhase = 'queued' | 'benign' | 'attack' | 'retest' | 'done';

export type EventType =
  | 'run_started'
  | 'candidate_generated'
  | 'case_started'
  | 'source_injected'
  | 'model_request'
  | 'model_response'
  | 'tool_proposed'
  | 'policy_decision'
  | 'tool_executed'
  | 'tool_blocked'
  | 'oracle_result'
  | 'case_completed'
  | 'run_completed'
  | 'run_error'
  | 'run_cancelled';

export interface HealthResponse {
  status: string;
  schema_version: number;
  live_ready: boolean;
}

export interface ScenarioSpecPublic {
  id: string;
  task_id: string;
  version: number;
  title: string;
  surface: Surface;
  source_id: string;
  legitimate_task: string;
  attack_goal: string;
}

export interface ScenariosResponse {
  items: ScenarioSpecPublic[];
}

export interface Budget {
  max_candidates: number;
  max_model_turns: number;
  max_tool_calls: number;
  case_timeout_s: number;
  run_timeout_s: number;
  max_total_tokens: number;
}

export interface RunRequest {
  scenario_ids: string[];
  operation: 'discover' | 'suite';
  defense: DefensePreset;
  execution_mode: ExecutionMode;
  budget: Budget;
  seed: number;
}

export interface RunAccepted {
  run_id: string;
  status: 'queued';
}

export interface RunProgress {
  scheduled: number;
  completed: number;
  failed: number;
  phase: RunPhase;
}

export interface ErrorDetail {
  code: string;
  message: string;
}

export function formatErrorDetail(error: ErrorDetail | string | null | undefined): string {
  if (!error) return '';
  if (typeof error === 'string') return error;
  if (typeof error === 'object') {
    if (error.code && error.message) {
      return `${error.code}: ${error.message}`;
    }
    return error.message || error.code || JSON.stringify(error);
  }
  return String(error);
}

export interface RunSummary {
  id: string;
  status: RunStatus;
  request: RunRequest;
  created_at: string;
  completed_at: string | null;
  progress: RunProgress;
  metrics: Record<string, unknown>;
  error: ErrorDetail | string | null;
  source_run_id: string | null;
}

export interface RunsResponse {
  items: RunSummary[];
}

export interface ToolCounts {
  proposed: number;
  denied: number;
  forbidden_executed: number;
}

export interface Usage {
  input_tokens: number;
  output_tokens: number;
}

export interface ViolationDetail {
  kind: 'unauthorized_read' | 'unauthorized_send' | 'canary_leak';
  impact: 'high' | 'medium' | 'low';
  evidence_event_ids: string[];
  details: Record<string, unknown>;
}

export interface CaseResultPublic {
  run_id: string;
  trial_id: string;
  scenario_id: string;
  task_id: string;
  candidate_id: string | null;
  payload_sha256: string | null;
  fixture_sha256: string;
  policy_version: string;
  defense: DefensePreset;
  execution_mode: ExecutionMode;
  status: CaseStatus;
  oracle_outcome: OracleOutcome;
  violations: ViolationDetail[];
  attempted_violations: ViolationDetail[];
  benign_success: boolean | null;
  final_output: string;
  evidence_event_ids: string[];
  source_consumed: boolean;
  tool_counts: ToolCounts;
  duration_ms: number;
  usage: Usage;
  error: ErrorDetail | string | null;
}

export interface RunDetailResponse {
  run: RunSummary;
  cases: CaseResultPublic[];
}

export interface TraceEvent {
  schema_version: number;
  id: string;
  run_id: string;
  trial_id: string | null;
  seq: number;
  timestamp: string;
  type: EventType;
  parent_event_ids: string[];
  data: Record<string, unknown>;
}

export interface EventsResponse {
  items: TraceEvent[];
  next_after_seq: number;
  has_more: boolean;
}

export interface RetestRequest {
  defense: 'gateway';
  include_benign: boolean;
}

export interface RetestAccepted {
  run_id: string;
}

export interface CancelResponse {
  run_id: string;
  status: RunStatus;
}

export interface ErrorResponse {
  error: ErrorDetail;
}

export const DEFAULT_BUDGET: Budget = {
  max_candidates: 6,
  max_model_turns: 6,
  max_tool_calls: 8,
  case_timeout_s: 60,
  run_timeout_s: 300,
  max_total_tokens: 60000,
};

export const TERMINAL_STATUSES: RunStatus[] = ['completed', 'failed', 'cancelled', 'interrupted'];
