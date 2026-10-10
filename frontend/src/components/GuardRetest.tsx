// Guard & Retest panel — explains the predefined gateway policy, then submits retest.
// Does NOT call this "automatic code repair."

interface GuardRetestProps {
  runId: string;
  alreadyRetested: boolean;
  onRetest: () => void;
}

export function GuardRetest({ runId: _runId, alreadyRetested, onRetest }: GuardRetestProps) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="card" style={{ padding: 18 }}>
        <h3 className="mb-12">Gateway Defense Policy</h3>
        <p className="text-sm text-secondary mb-12">
          The <strong>gateway</strong> preset adds a predefined permission and recipient check
          before any tool execution. It enforces:
        </p>
        <ul style={{ paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[
            'Exact allowed_recipients allowlist — send_email is denied to any recipient not in the grant.',
            'Protected field enforcement — get_customer results are filtered against allowed_customer_ids.',
            'Tool allowlist — only search_docs, get_customer, and send_email are permitted.',
          ].map((rule, i) => (
            <li key={i} className="text-sm text-secondary">{rule}</li>
          ))}
        </ul>
        <div className="callout info mt-16" style={{ fontSize: 12 }}>
          <span>ℹ</span>
          <span>
            This is a <strong>predefined server-side policy</strong>, not automatic code generation or repair.
            The policy hash is verified against D/B's versioned policy registry.
          </span>
        </div>
      </div>

      <div className="card" style={{ padding: 18 }}>
        <h3 className="mb-12">Retest</h3>
        <p className="text-sm text-secondary mb-16">
          Retest replays the same candidates under the gateway defense with new trial IDs.
          Original baseline data is preserved unchanged. Results show the defense's effect
          on the exact same attack inputs.
        </p>
        <div className="callout warning mb-16" style={{ fontSize: 12 }}>
          <span>⚠</span>
          <span>
            A defense that blocks everything must still complete legitimate clean tasks correctly.
            Watch for clean tasks that pass baseline but fail under gateway — that would indicate
            over-blocking.
          </span>
        </div>

        {alreadyRetested ? (
          <div className="callout success">
            <span>✓</span> Retest submitted. Check the new run in the sidebar.
          </div>
        ) : (
          <button
            className="btn btn-primary"
            style={{ width: '100%', justifyContent: 'center' }}
            onClick={onRetest}
            id="guard-retest-btn"
            aria-label="Submit retest with gateway defense"
          >
            Submit Gateway Retest
          </button>
        )}
      </div>
    </div>
  );
}
