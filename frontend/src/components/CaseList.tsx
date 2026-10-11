import { useState } from 'react';
import { OracleBadge, StatusBadge } from './Badges';
import type { CaseResultPublic } from '../types';

interface CaseListProps {
  cases: CaseResultPublic[];
  onSelectCase: (c: CaseResultPublic) => void;
  selectedTrialId: string | null;
}

export function CaseList({ cases, onSelectCase, selectedTrialId }: CaseListProps) {
  const [filter, setFilter] = useState<'all' | 'attack' | 'benign'>('all');

  const filtered = cases.filter(c => {
    if (filter === 'attack') return c.candidate_id !== null;
    if (filter === 'benign') return c.candidate_id === null;
    return true;
  });

  if (cases.length === 0) {
    return (
      <div className="empty-state">
        <span className="empty-state-icon">📋</span>
        <p>No cases yet</p>
        <p className="text-xs text-muted">Cases appear as the run progresses.</p>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-16">
        <h3>{cases.length} Case{cases.length !== 1 ? 's' : ''}</h3>
        <div className="tabs" style={{ marginBottom: 0 }}>
          {(['all', 'attack', 'benign'] as const).map(f => (
            <button
              key={f}
              className={`tab ${filter === f ? 'active' : ''}`}
              onClick={() => setFilter(f)}
              aria-pressed={filter === f}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <div className="table-container">
        <table aria-label="Case results table">
          <thead>
            <tr>
              <th>Scenario / Task</th>
              <th>Type</th>
              <th>Defense</th>
              <th>Oracle</th>
              <th>Benign</th>
              <th>Status</th>
              <th>Tools</th>
              <th>Duration</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(c => {
              const isAttack = c.candidate_id !== null;
              const benignLabels: Record<string, { title: string; subtitle: string }> = {
                'doc_exfil.status_email': { title: 'Doc Exfil · Benign', subtitle: 'Canonical Status Email to ops@acme.test' },
                'doc_exfil.status_email_paraphrase': { title: 'Doc Exfil · Benign', subtitle: 'Paraphrased Variant' },
                'doc_exfil.status_lookup_only': { title: 'Doc Exfil · Benign', subtitle: 'Lookup Only (Zero-Email Constraint)' },
                'doc_exfil.status_email_ignore_noise': { title: 'Doc Exfil · Benign', subtitle: 'Distractor Noise Filtering' },
                'email_bola.ticket_summary': { title: 'Email BOLA · Benign', subtitle: 'Ticket Summary (No Email)' },
                'email_bola.ticket_summary_paraphrase': { title: 'Email BOLA · Benign', subtitle: 'Paraphrased Ticket Summary' },
                'email_bola.ticket_with_status': { title: 'Email BOLA · Benign', subtitle: 'Ticket & Account Status Composite' },
                'email_bola.ticket_summary_email': { title: 'Email BOLA · Benign', subtitle: 'Ticket Summary Emailed to Ops' },
              };

              const label = isAttack
                ? (c.scenario_id === 'doc_exfil'
                    ? { title: 'Doc Exfil · Attack', subtitle: 'Canary Exfil to External Mailbox' }
                    : { title: 'Email BOLA · Attack', subtitle: 'Cross-Account Read (cust_b)' })
                : (benignLabels[c.task_id] || { title: c.scenario_id, subtitle: c.task_id });

              return (
                <tr
                  key={c.trial_id}
                  onClick={() => onSelectCase(c)}
                  style={{
                    cursor: 'pointer',
                    background: selectedTrialId === c.trial_id ? 'var(--accent-subtle)' : undefined,
                  }}
                  aria-selected={selectedTrialId === c.trial_id}
                >
                  <td>
                    <div className="font-medium" style={{ fontSize: 13 }}>{label.title}</div>
                    <div className="text-xs text-muted font-mono">{label.subtitle}</div>
                  </td>
                  <td>
                    <span style={{
                      fontSize: 11, fontWeight: 600, padding: '2px 7px',
                      borderRadius: 100,
                      background: isAttack ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)',
                      color: isAttack ? '#ef4444' : '#22c55e',
                    }}>
                      {isAttack ? 'Attack' : 'Benign'}
                    </span>
                  </td>
                  <td><span className="text-sm">{c.defense}</span></td>
                  <td><OracleBadge outcome={c.oracle_outcome} /></td>
                  <td>
                    {c.benign_success === null
                      ? <span className="text-xs text-muted">N/A</span>
                      : c.benign_success
                        ? <span className="text-success text-xs font-semibold">✓ Pass</span>
                        : <span className="text-danger text-xs font-semibold">✗ Fail</span>
                    }
                  </td>
                  <td><StatusBadge status={c.status} /></td>
                  <td>
                    <span className="text-xs text-muted font-mono">
                      {c.tool_counts.proposed}p / {c.tool_counts.denied}d / {c.tool_counts.forbidden_executed}f
                    </span>
                  </td>
                  <td>
                    <span className="text-xs text-muted">{c.duration_ms}ms</span>
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
