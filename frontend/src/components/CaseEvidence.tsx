import { OracleBadge, StatusBadge } from './Badges';
import type { CaseResultPublic } from '../types';

interface CaseEvidenceProps {
  caseResult: CaseResultPublic;
  onClose: () => void;
}

// All payload/output content is treated as hostile text.
// Never use dangerouslySetInnerHTML. Render as plain text in code blocks only.
function SafeText({ text, label }: { text: string; label: string }) {
  return (
    <div>
      <div className="text-xs text-muted mb-4">{label}</div>
      {/* Hostile text: rendered as plain text inside a code block. No HTML parsing. */}
      <div className="code-block" aria-label={label}>{text}</div>
    </div>
  );
}

export function CaseEvidence({ caseResult: c, onClose }: CaseEvidenceProps) {
  const isAttack = c.candidate_id !== null;

  return (
    <div
      style={{
        position: 'fixed', inset: 0, zIndex: 200,
        background: 'rgba(0,0,0,0.7)', display: 'flex',
        alignItems: 'center', justifyContent: 'center',
        padding: 24,
      }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
      role="dialog"
      aria-label="Case evidence"
      aria-modal="true"
    >
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius-xl)', width: '100%', maxWidth: 720,
        maxHeight: '85vh', overflow: 'hidden',
        display: 'flex', flexDirection: 'column',
      }}>
        {/* Dialog header */}
        <div className="flex items-center justify-between" style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center gap-12">
            <h2>Case Evidence</h2>
            <StatusBadge status={c.status} />
            <OracleBadge outcome={c.oracle_outcome} />
          </div>
          <button
            className="btn btn-secondary btn-sm"
            onClick={onClose}
            aria-label="Close case evidence"
          >
            ✕
          </button>
        </div>

        <div style={{ overflow: 'y', padding: 20, display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto' }}>
          {/* Violation warning */}
          {c.violations.length > 0 && (
            <div className="callout danger">
              <span>⚠</span>
              <div>
                <strong>Verified forbidden effects ({c.violations.length})</strong>
                {c.violations.map((v, i) => (
                  <div key={i} className="mt-4 text-sm">
                    {v.kind} · impact: {v.impact}
                  </div>
                ))}
              </div>
            </div>
          )}
          {c.attempted_violations.length > 0 && c.violations.length === 0 && (
            <div className="callout warning">
              <span>⚠</span>
              <div>
                <strong>Attempted violations ({c.attempted_violations.length}) — not executed</strong>
                <div className="text-xs mt-4">A proposed call is not a prohibited effect. Denial is not task success.</div>
              </div>
            </div>
          )}

          {/* Scenario info */}
          <div className="card" style={{ padding: 14 }}>
            <h3 className="mb-12">Scenario</h3>
            <div className="grid-2" style={{ gap: 10 }}>
              <div>
                <span className="text-xs text-muted">ID</span>
                <div className="text-sm font-medium mt-4">{c.scenario_id}</div>
              </div>
              <div>
                <span className="text-xs text-muted">Task ID</span>
                <div className="text-sm font-medium mt-4">{c.task_id}</div>
              </div>
              <div>
                <span className="text-xs text-muted">Defense</span>
                <div className="text-sm font-medium mt-4">{c.defense}</div>
              </div>
              <div>
                <span className="text-xs text-muted">Mode</span>
                <div className="text-sm font-medium mt-4">{c.execution_mode}</div>
              </div>
              <div>
                <span className="text-xs text-muted">Policy Version</span>
                <div className="text-sm font-mono mt-4">{c.policy_version}</div>
              </div>
              <div>
                <span className="text-xs text-muted">Source Consumed</span>
                <div className="text-sm mt-4">{c.source_consumed ? '✓ Yes' : '✗ No'}</div>
              </div>
            </div>
          </div>

          {/* Candidate (attack cases only) */}
          {isAttack && (
            <div className="card" style={{ padding: 14 }}>
              <h3 className="mb-12">Candidate</h3>
              <div className="mb-12">
                <span className="text-xs text-muted">Candidate ID</span>
                <div className="hash-value mt-4">{c.candidate_id}</div>
              </div>
              <div className="mb-12">
                <span className="text-xs text-muted">Payload SHA-256</span>
                <div className="hash-value mt-4">{c.payload_sha256}</div>
              </div>
              <div>
                <span className="text-xs text-muted">Fixture SHA-256</span>
                <div className="hash-value mt-4">{c.fixture_sha256}</div>
              </div>
            </div>
          )}

          {/* Final output — hostile text, rendered as plain text only */}
          <SafeText
            text={c.final_output}
            label="Final Output (plain text — hostile content rendered safely)"
          />

          {/* Benign result */}
          <div className="card" style={{ padding: 14 }}>
            <h3 className="mb-12">Outcome</h3>
            <div className="grid-2" style={{ gap: 10 }}>
              <div>
                <span className="text-xs text-muted">Benign Success</span>
                <div className="text-sm mt-4">
                  {c.benign_success === null
                    ? 'N/A (inconclusive — not a fabricated pass or fail)'
                    : c.benign_success
                      ? <span className="text-success font-semibold">✓ Task completed correctly</span>
                      : <span className="text-danger font-semibold">✗ Task did not complete correctly</span>
                  }
                </div>
              </div>
              <div>
                <span className="text-xs text-muted">Duration</span>
                <div className="text-sm mt-4">{c.duration_ms} ms</div>
              </div>
              <div>
                <span className="text-xs text-muted">Tokens (in / out)</span>
                <div className="text-sm mt-4 font-mono">{c.usage.input_tokens} / {c.usage.output_tokens}</div>
              </div>
              <div>
                <span className="text-xs text-muted">Tools (proposed / denied / forbidden exec)</span>
                <div className="text-sm mt-4 font-mono">
                  {c.tool_counts.proposed} / {c.tool_counts.denied} / {c.tool_counts.forbidden_executed}
                </div>
              </div>
            </div>
          </div>

          {/* Evidence event IDs */}
          {c.evidence_event_ids.length > 0 && (
            <div>
              <span className="text-xs text-muted">Evidence Event IDs</span>
              <div className="flex" style={{ flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
                {c.evidence_event_ids.map(id => (
                  <code key={id} style={{
                    fontSize: 11, background: 'var(--bg-elevated)',
                    padding: '2px 6px', borderRadius: 4, color: 'var(--text-code)'
                  }}>{id}</code>
                ))}
              </div>
            </div>
          )}

          {c.error && (
            <div className="callout danger">
              <span>✕</span> Case error: {c.error}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
