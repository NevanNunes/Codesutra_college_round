import { useState } from 'react';
import { api, ApiError } from '../api';
import { StatusBadge } from './Badges';
import type { RunSummary } from '../types';
import { TERMINAL_STATUSES } from '../types';

interface RunOverviewProps {
  run: RunSummary;
  onCancelled: () => void;
  onRetest: (newRunId: string) => void;
  onExport: (format: 'json' | 'markdown') => void;
}

export function RunOverview({ run, onCancelled, onRetest, onExport }: RunOverviewProps) {
  const [cancelling, setCancelling] = useState(false);
  const [retesting, setRetesting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const isTerminal = TERMINAL_STATUSES.includes(run.status);
  const progress = run.progress;
  const pct = progress.scheduled > 0
    ? Math.round((progress.completed / progress.scheduled) * 100)
    : 0;

  const elapsed = (() => {
    const start = new Date(run.created_at).getTime();
    const end = run.completed_at ? new Date(run.completed_at).getTime() : Date.now();
    const secs = Math.floor((end - start) / 1000);
    if (secs < 60) return `${secs}s`;
    return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  })();

  const handleCancel = async () => {
    if (!confirm('Cancel this run?')) return;
    setCancelling(true);
    setActionError(null);
    try {
      await api.postCancel(run.id);
      onCancelled();
    } catch (e) {
      setActionError(e instanceof ApiError ? e.message : 'Cancel failed.');
    } finally {
      setCancelling(false);
    }
  };

  const handleRetest = async () => {
    setRetesting(true);
    setActionError(null);
    try {
      const result = await api.postRetest(run.id, { defense: 'gateway', include_benign: true });
      onRetest(result.run_id);
    } catch (e) {
      setActionError(e instanceof ApiError ? e.message : 'Retest failed.');
    } finally {
      setRetesting(false);
    }
  };

  return (
    <div>
      {/* Header row */}
      <div className="flex items-center justify-between mb-16">
        <div className="flex items-center gap-12">
          <StatusBadge status={run.status} />
          <span className="font-mono text-xs text-muted">{run.id}</span>
        </div>
        <div className="flex items-center gap-8">
          {run.status === 'completed' && !run.source_run_id && (
            <>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => onExport('json')}
                aria-label="Export run as JSON"
              >
                ↓ JSON
              </button>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => onExport('markdown')}
                aria-label="Export run as Markdown"
              >
                ↓ MD
              </button>
              <button
                className="btn btn-secondary btn-sm"
                onClick={handleRetest}
                disabled={retesting}
                id="retest-btn"
                aria-label="Retest with gateway defense"
              >
                {retesting ? <><span className="spinner" style={{ width: 12, height: 12 }} /> Retesting...</> : '⟳ Retest w/ Gateway'}
              </button>
            </>
          )}
          {!isTerminal && (
            <button
              className="btn btn-danger btn-sm"
              onClick={handleCancel}
              disabled={cancelling}
              id="cancel-run-btn"
              aria-label="Cancel run"
            >
              {cancelling ? 'Cancelling...' : '✕ Cancel'}
            </button>
          )}
        </div>
      </div>

      {run.source_run_id && (
        <div className="callout info mb-16">
          <span>🔁</span>
          <span>Retest of run <code>{run.source_run_id.slice(0, 8)}</code> with gateway defense.</span>
        </div>
      )}

      {actionError && (
        <div className="callout danger mb-16" role="alert">
          <span>✕</span> {actionError}
        </div>
      )}

      {/* Stats grid */}
      <div className="grid-4 mb-16">
        <div className="card" style={{ padding: 16 }}>
          <div className="metric-value">{progress.scheduled}</div>
          <div className="metric-label">Scheduled</div>
        </div>
        <div className="card" style={{ padding: 16 }}>
          <div className="metric-value" style={{ color: 'var(--status-completed)' }}>{progress.completed}</div>
          <div className="metric-label">Completed</div>
        </div>
        <div className="card" style={{ padding: 16 }}>
          <div className="metric-value" style={{ color: progress.failed > 0 ? 'var(--status-failed)' : undefined }}>{progress.failed}</div>
          <div className="metric-label">Failed</div>
        </div>
        <div className="card" style={{ padding: 16 }}>
          <div className="metric-value text-sm">{elapsed}</div>
          <div className="metric-label">Elapsed</div>
        </div>
      </div>

      {/* Progress bar */}
      {!isTerminal && (
        <div className="card mb-16" style={{ padding: 14 }}>
          <div className="flex items-center justify-between mb-8">
            <span className="text-sm text-secondary">Phase: <strong>{progress.phase}</strong></span>
            <span className="text-sm text-muted">{pct}%</span>
          </div>
          <div className="progress-bar-track">
            <div className="progress-bar-fill" style={{ width: `${pct}%` }} />
          </div>
        </div>
      )}

      {/* Config */}
      <div className="card" style={{ padding: 16 }}>
        <h3 className="mb-12" style={{ color: 'var(--text-secondary)' }}>Configuration</h3>
        <div className="grid-2" style={{ gap: 10 }}>
          {[
            ['Scenarios', run.request.scenario_ids.join(', ')],
            ['Operation', run.request.operation],
            ['Defense', run.request.defense],
            ['Execution Mode', run.request.execution_mode],
            ['Seed', String(run.request.seed)],
            ['Max Candidates', String(run.request.budget.max_candidates)],
          ].map(([k, v]) => (
            <div key={k}>
              <span className="text-xs text-muted">{k}</span>
              <div className="text-sm font-medium mt-4">{v}</div>
            </div>
          ))}
        </div>
      </div>

      {run.error && (
        <div className="callout danger mt-16" role="alert">
          <span>✕</span> <span>Run error: {run.error}</span>
        </div>
      )}
    </div>
  );
}
