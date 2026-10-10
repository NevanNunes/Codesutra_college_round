import type { RunStatus, CaseStatus, OracleOutcome } from '../types';

interface StatusBadgeProps {
  status: RunStatus | CaseStatus;
  label?: string;
}

const STATUS_LABELS: Record<RunStatus | CaseStatus, string> = {
  queued: 'Queued',
  running: 'Running',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
  interrupted: 'Interrupted',
  timed_out: 'Timed Out',
};

export function StatusBadge({ status, label }: StatusBadgeProps) {
  return (
    <span className={`badge ${status}`} aria-label={`Status: ${STATUS_LABELS[status]}`}>
      <span className="badge-dot" aria-hidden="true" />
      {label ?? STATUS_LABELS[status]}
    </span>
  );
}

// Oracle outcome — clearly labeled; "success" means ATTACKER success
const ORACLE_LABELS: Record<OracleOutcome, string> = {
  success: 'Attack Succeeded',
  failure: 'Attack Failed (Defense Held)',
  inconclusive: 'Inconclusive',
};

export function OracleBadge({ outcome }: { outcome: OracleOutcome }) {
  return (
    <span className={`badge oracle-${outcome}`} aria-label={`Oracle: ${ORACLE_LABELS[outcome]}`}>
      {outcome === 'success' && '⚠ '}
      {ORACLE_LABELS[outcome]}
    </span>
  );
}

export function ModeBadge({ mode }: { mode: 'live' | 'fixture' | 'recorded' }) {
  const labels = {
    live: 'LIVE',
    fixture: 'FIXTURE SIMULATION',
    recorded: 'RECORDED LIVE EVIDENCE',
  };
  return (
    <span className={`mode-badge ${mode}`}>
      {mode === 'live' && '⬤ '}
      {labels[mode]}
    </span>
  );
}

export function SimulationBanner() {
  return (
    <div className="simulation-banner" role="status">
      ⚠ <strong>FIXTURE SIMULATION</strong> — Data shown is synthetic contract fixture, not real attack evidence.
    </div>
  );
}
