import { useState, useEffect } from 'react';
import { api, ApiError } from '../api';
import { StatusBadge } from './Badges';
import type { RunSummary } from '../types';

interface SidebarProps {
  selectedRunId: string | null;
  onSelectRun: (id: string) => void;
  onNewRun: () => void;
  refreshTrigger: number;
}

export function Sidebar({ selectedRunId, onSelectRun, onNewRun, refreshTrigger }: SidebarProps) {
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    const fetch = async () => {
      try {
        const resp = await api.getRuns(50);
        if (mounted) { setRuns(resp.items); setError(null); }
      } catch (e) {
        if (mounted) {
          if (e instanceof ApiError && e.status === 404) {
            setError('Run API not implemented yet.');
          } else {
            setError('Cannot reach backend.');
          }
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };
    fetch();
    return () => { mounted = false; };
  }, [refreshTrigger]);

  return (
    <nav className="sidebar" aria-label="Run list">
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
        <button
          className="btn btn-primary"
          style={{ width: '100%', justifyContent: 'center' }}
          onClick={onNewRun}
          id="new-run-btn"
        >
          + New Run
        </button>
      </div>

      <div className="sidebar-nav">
        <span className="sidebar-section-label">Recent Runs</span>

        {loading && (
          <div style={{ padding: '16px', display: 'flex', justifyContent: 'center' }}>
            <div className="spinner" />
          </div>
        )}

        {error && !loading && (
          <div style={{ padding: '12px 10px' }}>
            <p className="text-xs text-muted">{error}</p>
          </div>
        )}

        {!loading && !error && runs.length === 0 && (
          <div className="empty-state" style={{ padding: '24px 12px' }}>
            <span className="text-xs text-muted">No runs yet</span>
          </div>
        )}

        {runs.map(run => (
          <button
            key={run.id}
            className={`sidebar-item ${selectedRunId === run.id ? 'active' : ''}`}
            onClick={() => onSelectRun(run.id)}
            aria-current={selectedRunId === run.id ? 'page' : undefined}
            aria-label={`Run ${run.id.slice(0, 8)}, status: ${run.status}`}
          >
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="flex items-center gap-8" style={{ marginBottom: 3 }}>
                <span className="truncate font-mono text-xs" style={{ maxWidth: 100 }}>
                  {run.id.slice(0, 8)}
                </span>
                <StatusBadge status={run.status} />
              </div>
              <div className="text-xs text-muted truncate">
                {run.request.scenario_ids.join(', ')} · {run.request.defense}
              </div>
            </div>
          </button>
        ))}
      </div>
    </nav>
  );
}
