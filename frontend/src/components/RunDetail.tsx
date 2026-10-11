import { useState } from 'react';
import { api, ApiError } from '../api';
import { useRunData } from '../hooks/useRunData';
import { RunOverview } from './RunOverview';
import { CaseList } from './CaseList';
import { CaseEvidence } from './CaseEvidence';
import { EventGraph, EventList, EventDetail } from './EventGraph';
import { GuardRetest } from './GuardRetest';
import { Comparison } from './Comparison';
import type { CaseResultPublic, TraceEvent } from '../types';
import { TERMINAL_STATUSES } from '../types';

type Tab = 'overview' | 'cases' | 'events' | 'guard' | 'comparison';

interface RunDetailProps {
  runId: string;
  onRetest: (newRunId: string) => void;
  retestRunId: string | null;
  retestData?: { cases: CaseResultPublic[] };
}

export function RunDetail({ runId, onRetest, retestRunId, retestData }: RunDetailProps) {
  const { run, cases, events, loading, error, disconnected, refresh } = useRunData(runId);
  const isRetestRun = Boolean(run?.source_run_id);
  const pairedRunId = isRetestRun ? run?.source_run_id : retestRunId;
  const {
    run: pairedRun,
    cases: pairedCases,
    loading: pairedLoading,
    error: pairedError,
  } = useRunData(pairedRunId ?? null);

  const [tab, setTab] = useState<Tab>('overview');
  const [selectedCase, setSelectedCase] = useState<CaseResultPublic | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<TraceEvent | null>(null);
  const [eventsView, setEventsView] = useState<'graph' | 'list'>('graph');
  const [retested, setRetested] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const handleExport = async (format: 'json' | 'markdown') => {
    setExportError(null);
    try {
      const url = api.getExportUrl(runId, format);
      const resp = await fetch(url);
      if (!resp.ok) {
        let msg = resp.statusText;
        try {
          const err = await resp.json();
          msg = err.error?.message ?? msg;
        } catch { /* ignore */ }
        setExportError(`Export failed: ${msg}`);
        return;
      }
      const blob = await resp.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `agentbreak-run-${runId.slice(0, 8)}.${format === 'markdown' ? 'md' : 'json'}`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch {
      setExportError('Export request failed. Check connection.');
    }
  };

  const handleRetest = (newRunId: string) => {
    setRetested(true);
    onRetest(newRunId);
    setTab('comparison');
  };

  if (loading) {
    return (
      <div className="empty-state">
        <div className="spinner" />
        <p>Loading run...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="empty-state">
        <span className="empty-state-icon">✕</span>
        <p>{error}</p>
      </div>
    );
  }

  if (!run) return null;

  const hasComparison = Boolean(pairedRunId);
  const TABS: { id: Tab; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'cases', label: `Cases (${cases.length})` },
    { id: 'events', label: `Events (${events.length})` },
    { id: 'guard', label: 'Guard & Retest' },
    ...(hasComparison ? [{ id: 'comparison' as Tab, label: 'Comparison' }] : []),
  ];

  return (
    <div>
      {disconnected && (
        <div className="callout warning mb-16" role="status">
          <span>⚠</span>
          <span>Disconnected from backend. Showing last known data.</span>
          <button className="btn btn-sm btn-secondary" onClick={refresh} style={{ marginLeft: 'auto' }}>Retry</button>
        </div>
      )}

      {exportError && (
        <div className="callout danger mb-16" role="alert">
          <span>✕</span> {exportError}
        </div>
      )}

      <div className="tabs">
        {TABS.map(t => (
          <button
            key={t.id}
            className={`tab ${tab === t.id ? 'active' : ''}`}
            onClick={() => setTab(t.id)}
            aria-pressed={tab === t.id}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'overview' && (
        <RunOverview
          run={run}
          onCancelled={refresh}
          onRetest={handleRetest}
          onExport={handleExport}
        />
      )}

      {tab === 'cases' && (
        <>
          <CaseList
            cases={cases}
            onSelectCase={setSelectedCase}
            selectedTrialId={selectedCase?.trial_id ?? null}
          />
          {selectedCase && (
            <CaseEvidence caseResult={selectedCase} onClose={() => setSelectedCase(null)} />
          )}
        </>
      )}

      {tab === 'events' && (
        <div>
          <div className="flex items-center justify-between mb-16">
            <h3>Execution Trace</h3>
            <div className="tabs" style={{ marginBottom: 0 }}>
              <button
                className={`tab ${eventsView === 'graph' ? 'active' : ''}`}
                onClick={() => setEventsView('graph')}
              >
                Graph
              </button>
              <button
                className={`tab ${eventsView === 'list' ? 'active' : ''}`}
                onClick={() => setEventsView('list')}
              >
                Timeline
              </button>
            </div>
          </div>

          <div className="callout info mb-16" style={{ fontSize: 12 }}>
            <span>ℹ</span>
            <span>
              Edges show recorded context and execution dependencies, not the model's private reasoning or proof of semantic causality.
              An attacker proposal is not an executed effect, and a denial is not automatically a completed legitimate task.
            </span>
          </div>

          {eventsView === 'graph'
            ? <EventGraph events={events} onSelectEvent={setSelectedEvent} />
            : <EventList events={events} onSelectEvent={setSelectedEvent} />
          }

          {selectedEvent && (
            <div className="mt-16">
              <EventDetail event={selectedEvent} />
            </div>
          )}
        </div>
      )}

      {tab === 'guard' && (
        <GuardRetest
          runId={runId}
          alreadyRetested={retested}
          onRetest={async () => {
            try {
              const result = await api.postRetest(runId, { defense: 'gateway', include_benign: true });
              handleRetest(result.run_id);
            } catch (e) {
              if (e instanceof ApiError) {
                setExportError(e.message);
              }
            }
          }}
        />
      )}

      {tab === 'comparison' && (
        <div>
          {!pairedRunId ? (
            <div className="callout info">
              <span>ℹ</span>
              <span>No paired baseline or retest run found for comparison. Run a retest from the &quot;Guard &amp; Retest&quot; tab first.</span>
            </div>
          ) : pairedLoading && pairedCases.length === 0 && (!retestData?.cases || retestData.cases.length === 0) ? (
            <div className="empty-state">
              <div className="spinner" />
              <p>Loading paired run data for comparison...</p>
            </div>
          ) : pairedError ? (
            <div className="callout danger">
              <span>✕</span> Failed to load paired run ({pairedRunId.slice(0, 8)}): {pairedError}
            </div>
          ) : (
            <>
              {pairedRun && !TERMINAL_STATUSES.includes(pairedRun.status) && (
                <div className="callout info mb-16">
                  <span>ℹ</span>
                  <span>
                    Retest run (ID: <code>{pairedRunId.slice(0, 8)}</code>) is currently <strong>{pairedRun.status}</strong>.
                    Results will update as cases complete.
                  </span>
                </div>
              )}
              <Comparison
                baselineCases={isRetestRun ? pairedCases : cases}
                retestCases={isRetestRun ? cases : (retestData?.cases ?? pairedCases)}
                baselineRunId={isRetestRun ? (run.source_run_id ?? '') : run.id}
                retestRunId={isRetestRun ? run.id : pairedRunId}
              />
            </>
          )}
        </div>
      )}
    </div>
  );
}
