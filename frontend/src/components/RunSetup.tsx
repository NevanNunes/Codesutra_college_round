import { useState, useEffect } from 'react';
import { api, ApiError } from '../api';
import type { ScenarioSpecPublic, RunRequest, Budget } from '../types';
import { DEFAULT_BUDGET } from '../types';
import { FIXTURE_SCENARIOS } from '../fixtures';
import { SimulationBanner } from './Badges';

interface RunSetupProps {
  onRunCreated: (runId: string) => void;
  liveReady: boolean;
}

export function RunSetup({ onRunCreated, liveReady }: RunSetupProps) {
  const [scenarios, setScenarios] = useState<ScenarioSpecPublic[]>([]);
  const [scenariosFromFixture, setScenariosFromFixture] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set(['doc_exfil']));
  const [operation, setOperation] = useState<'discover' | 'suite'>('discover');
  const [defense, setDefense] = useState<'baseline' | 'gateway'>('baseline');
  const [executionMode, setExecutionMode] = useState<'fixture' | 'live'>('fixture');
  const [seed, setSeed] = useState(0);
  const [budget, setBudget] = useState<Budget>({ ...DEFAULT_BUDGET });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    api.getScenarios()
      .then(r => { if (mounted) { setScenarios(r.items); setScenariosFromFixture(false); } })
      .catch(() => { if (mounted) { setScenarios(FIXTURE_SCENARIOS.items); setScenariosFromFixture(true); } });
    return () => { mounted = false; };
  }, []);

  const toggleScenario = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        if (next.size === 1) return prev; // must keep at least one
        next.delete(id);
      } else {
        if (next.size >= 2) return prev; // max 2
        next.add(id);
      }
      return next;
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedIds.size === 0) return;
    setSubmitting(true);
    setError(null);
    const body: RunRequest = {
      scenario_ids: Array.from(selectedIds),
      operation,
      defense,
      execution_mode: executionMode,
      budget,
      seed,
    };
    try {
      const accepted = await api.postRun(body);
      onRunCreated(accepted.run_id);
    } catch (e) {
      if (e instanceof ApiError) {
        setError(`${e.code}: ${e.message}`);
      } else {
        setError('Failed to start run. Please try again.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  const updateBudget = (key: keyof Budget, val: number) => {
    setBudget(prev => ({ ...prev, [key]: val }));
  };

  return (
    <form onSubmit={handleSubmit} aria-label="New run setup">
      <h2 style={{ marginBottom: 20 }}>New Run</h2>

      {scenariosFromFixture && <SimulationBanner />}

      <div className="callout info mb-16">
        <span>ℹ</span>
        <span>This replaces one mock source document or email — no real tools, email, or customer records are used.</span>
      </div>

      {/* Scenario selection */}
      <div className="form-group mb-16">
        <label className="form-label">Scenarios (select 1–2)</label>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {scenarios.map(sc => (
            <label
              key={sc.id}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: 10,
                padding: '12px 14px',
                background: selectedIds.has(sc.id) ? 'var(--accent-subtle)' : 'var(--bg-elevated)',
                border: `1px solid ${selectedIds.has(sc.id) ? 'rgba(79,124,255,0.35)' : 'var(--border)'}`,
                borderRadius: 'var(--radius)',
                cursor: 'pointer',
                transition: 'all var(--transition)',
              }}
            >
              <input
                type="checkbox"
                checked={selectedIds.has(sc.id)}
                onChange={() => toggleScenario(sc.id)}
                style={{ marginTop: 2 }}
                aria-label={sc.title}
              />
              <div>
                <div className="font-semibold" style={{ fontSize: 13 }}>{sc.title}</div>
                <div className="text-xs text-secondary mt-4">{sc.legitimate_task}</div>
                <div className="text-xs text-muted mt-4">
                  Surface: {sc.surface} · Attack goal: {sc.attack_goal}
                </div>
              </div>
            </label>
          ))}
        </div>
      </div>

      <div className="grid-2 mb-16">
        <div className="form-group">
          <label className="form-label" htmlFor="operation">Operation</label>
          <select
            id="operation"
            className="form-select"
            value={operation}
            onChange={e => setOperation(e.target.value as 'discover' | 'suite')}
          >
            <option value="discover">Discover</option>
            <option value="suite">Suite</option>
          </select>
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor="defense">Defense Preset</label>
          <select
            id="defense"
            className="form-select"
            value={defense}
            onChange={e => setDefense(e.target.value as 'baseline' | 'gateway')}
          >
            <option value="baseline">Baseline</option>
            <option value="gateway">Gateway</option>
          </select>
        </div>
      </div>

      <div className="form-group mb-16">
        <label className="form-label" htmlFor="exec-mode">Execution Mode</label>
        <select
          id="exec-mode"
          className="form-select"
          value={executionMode}
          onChange={e => setExecutionMode(e.target.value as 'fixture' | 'live')}
          disabled={!liveReady && executionMode === 'fixture'}
        >
          <option value="fixture">Fixture Simulation</option>
          <option value="live" disabled={!liveReady}>
            Live{!liveReady ? ' (backend not ready)' : ''}
          </option>
        </select>
        {!liveReady && (
          <p className="text-xs text-muted mt-4">
            Live mode is disabled — backend is not ready (live_ready: false).
          </p>
        )}
      </div>

      <div className="form-group mb-16">
        <label className="form-label" htmlFor="seed">Seed</label>
        <input
          id="seed"
          className="form-input"
          type="number"
          min={0}
          max={4294967295}
          value={seed}
          onChange={e => setSeed(Number(e.target.value))}
        />
      </div>

      {/* Budget */}
      <div style={{ marginBottom: 20 }}>
        <h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Budget</h3>
        <div className="grid-2" style={{ gap: 10 }}>
          {([
            ['max_candidates', 'Max Candidates', 1, 12],
            ['max_model_turns', 'Max Model Turns', 1, 6],
            ['max_tool_calls', 'Max Tool Calls', 1, 8],
            ['case_timeout_s', 'Case Timeout (s)', 1, 60],
            ['run_timeout_s', 'Run Timeout (s)', 1, 300],
            ['max_total_tokens', 'Max Total Tokens', 1, 60000],
          ] as [keyof Budget, string, number, number][]).map(([key, label, min, max]) => (
            <div className="form-group" key={key}>
              <label className="form-label" htmlFor={`budget-${key}`}>{label}</label>
              <input
                id={`budget-${key}`}
                className="form-input"
                type="number"
                min={min}
                max={max}
                value={budget[key]}
                onChange={e => updateBudget(key, Number(e.target.value))}
              />
            </div>
          ))}
        </div>
      </div>

      {error && (
        <div className="callout danger mb-16" role="alert">
          <span>✕</span> {error}
        </div>
      )}

      <button
        type="submit"
        className="btn btn-primary"
        style={{ width: '100%', justifyContent: 'center' }}
        disabled={submitting || selectedIds.size === 0}
        id="start-run-btn"
      >
        {submitting ? <><span className="spinner" /> Starting...</> : '▶ Start Run'}
      </button>
    </form>
  );
}
