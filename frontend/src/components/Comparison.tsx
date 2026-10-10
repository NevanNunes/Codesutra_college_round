// Paired comparison — baseline vs gateway side-by-side.
// Shows identical candidate/fixture hashes and changed policy version.
// Never mixes fixture and live results.
// Zero denominators shown as N/A, never fabricated percentages.

import { OracleBadge } from './Badges';
import type { CaseResultPublic } from '../types';

interface ComparisonProps {
  baselineCases: CaseResultPublic[];
  retestCases: CaseResultPublic[];
  baselineRunId: string;
  retestRunId: string;
}

interface PairedCase {
  candidateId: string | null;
  taskId: string;
  baseline: CaseResultPublic | null;
  retest: CaseResultPublic | null;
}

function pairCases(baseline: CaseResultPublic[], retest: CaseResultPublic[]): PairedCase[] {
  // Pair by (task_id, candidate_id) — same identity means same input
  const pairs = new Map<string, PairedCase>();

  baseline.forEach(c => {
    const key = `${c.task_id}::${c.candidate_id ?? 'benign'}`;
    pairs.set(key, { candidateId: c.candidate_id, taskId: c.task_id, baseline: c, retest: null });
  });

  retest.forEach(c => {
    const key = `${c.task_id}::${c.candidate_id ?? 'benign'}`;
    const existing = pairs.get(key);
    if (existing) {
      existing.retest = c;
    } else {
      pairs.set(key, { candidateId: c.candidate_id, taskId: c.task_id, baseline: null, retest: c });
    }
  });

  return Array.from(pairs.values());
}

function rate(cases: CaseResultPublic[], check: (c: CaseResultPublic) => boolean): string {
  const conclusive = cases.filter(c => c.oracle_outcome !== 'inconclusive');
  if (conclusive.length === 0) return 'N/A';
  const passing = conclusive.filter(check).length;
  return `${passing}/${conclusive.length}`;
}

export function Comparison({ baselineCases, retestCases, baselineRunId, retestRunId }: ComparisonProps) {
  const pairs = pairCases(baselineCases, retestCases);

  // Check for mixed execution modes — never mix live and fixture
  const baseModes = new Set(baselineCases.map(c => c.execution_mode));
  const retestModes = new Set(retestCases.map(c => c.execution_mode));
  const modesMixed = [...baseModes, ...retestModes].length > 1 &&
    !([...baseModes].every(m => retestModes.has(m)));

  const attackBaseline = baselineCases.filter(c => c.candidate_id !== null);
  const attackRetest = retestCases.filter(c => c.candidate_id !== null);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {modesMixed && (
        <div className="callout warning">
          <span>⚠</span> Execution mode mismatch detected. Never mix fixture and live results.
        </div>
      )}

      {/* Summary metrics */}
      <div className="grid-2">
        {[
          {
            label: 'Baseline',
            runId: baselineRunId,
            attackCases: attackBaseline,
            defense: baselineCases[0]?.defense ?? 'baseline',
            mode: baselineCases[0]?.execution_mode,
          },
          {
            label: 'Retest (Gateway)',
            runId: retestRunId,
            attackCases: attackRetest,
            defense: retestCases[0]?.defense ?? 'gateway',
            mode: retestCases[0]?.execution_mode,
          },
        ].map(col => (
          <div key={col.label} className="card" style={{ padding: 16 }}>
            <div className="flex items-center justify-between mb-12">
              <h3>{col.label}</h3>
              <span className="text-xs font-mono text-muted">{col.runId.slice(0, 8)}</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div>
                <span className="text-xs text-muted">Defense</span>
                <div className="text-sm font-medium mt-4">{col.defense}</div>
              </div>
              <div>
                <span className="text-xs text-muted">Mode</span>
                <div className="text-sm mt-4">{col.mode ?? 'N/A'}</div>
              </div>
              <div>
                <span className="text-xs text-muted">Attack failures (defense held)</span>
                <div className="text-sm font-semibold mt-4 text-success">
                  {rate(col.attackCases, c => c.oracle_outcome === 'failure')}
                </div>
              </div>
              <div>
                <span className="text-xs text-muted">Attack successes (attacker won)</span>
                <div className="text-sm font-semibold mt-4 text-danger">
                  {rate(col.attackCases, c => c.oracle_outcome === 'success')}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Per-case comparison table */}
      <div className="table-container">
        <table aria-label="Baseline vs retest comparison">
          <thead>
            <tr>
              <th>Task / Candidate</th>
              <th>Type</th>
              <th>Baseline Oracle</th>
              <th>Retest Oracle</th>
              <th>Benign (base → retest)</th>
              <th>Fingerprints match</th>
            </tr>
          </thead>
          <tbody>
            {pairs.map((pair, i) => {
              const b = pair.baseline;
              const r = pair.retest;
              const hashMatch = b && r
                ? b.fixture_sha256 === r.fixture_sha256 && b.payload_sha256 === r.payload_sha256
                : null;

              return (
                <tr key={i}>
                  <td>
                    <div className="text-sm font-medium">{pair.taskId}</div>
                    {pair.candidateId && (
                      <div className="hash-value mt-4">{pair.candidateId.slice(0, 8)}</div>
                    )}
                  </td>
                  <td>
                    <span style={{
                      fontSize: 11, fontWeight: 600, padding: '2px 7px', borderRadius: 100,
                      background: pair.candidateId ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)',
                      color: pair.candidateId ? '#ef4444' : '#22c55e',
                    }}>
                      {pair.candidateId ? 'Attack' : 'Benign'}
                    </span>
                  </td>
                  <td>
                    {b ? <OracleBadge outcome={b.oracle_outcome} /> : <span className="text-xs text-muted">—</span>}
                  </td>
                  <td>
                    {r ? <OracleBadge outcome={r.oracle_outcome} /> : <span className="text-xs text-muted">—</span>}
                  </td>
                  <td>
                    {b && r
                      ? <span className="text-xs">
                          {b.benign_success === null ? 'N/A' : b.benign_success ? '✓' : '✗'}
                          {' → '}
                          {r.benign_success === null ? 'N/A' : r.benign_success ? '✓' : '✗'}
                          {b.benign_success && !r.benign_success
                            ? <span className="text-warn font-semibold"> ⚠ regression</span>
                            : null}
                        </span>
                      : <span className="text-xs text-muted">—</span>
                    }
                  </td>
                  <td>
                    {hashMatch === null
                      ? <span className="text-xs text-muted">—</span>
                      : hashMatch
                        ? <span className="text-xs text-success">✓ Match</span>
                        : <span className="text-xs text-danger">✗ Mismatch</span>
                    }
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
