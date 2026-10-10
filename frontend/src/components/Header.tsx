import { useState, useEffect } from 'react';
import { api } from '../api';
import { ModeBadge } from './Badges';
import type { HealthResponse } from '../types';

interface HeaderProps {
  onTokenChange: (token: string | null) => void;
  hasToken: boolean;
}

export function Header({ onTokenChange, hasToken }: HeaderProps) {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState(false);
  const [showTokenInput, setShowTokenInput] = useState(false);
  const [tokenDraft, setTokenDraft] = useState('');

  useEffect(() => {
    let mounted = true;
    const check = async () => {
      try {
        const h = await api.getHealth();
        if (mounted) { setHealth(h); setHealthError(false); }
      } catch {
        if (mounted) setHealthError(true);
      }
    };
    check();
    const id = setInterval(check, 10_000);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  const mode: 'live' | 'fixture' = health?.live_ready ? 'live' : 'fixture';

  return (
    <header className="app-header" role="banner">
      <div className="header-brand">
        <svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden="true">
          <rect width="22" height="22" rx="6" fill="#4f7cff" fillOpacity="0.15"/>
          <path d="M6 16L11 6L16 16" stroke="#4f7cff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
          <path d="M8 13h6" stroke="#4f7cff" strokeWidth="1.8" strokeLinecap="round"/>
        </svg>
        <h1>AgentBreak</h1>
        <span className="header-sandbox-label">sandbox only</span>
      </div>

      <div className="header-spacer" />

      <div className="header-status">
        <ModeBadge mode={mode} />

        {healthError ? (
          <span style={{ color: 'var(--oracle-inconclusive)', fontSize: 12 }}>⚠ Backend unreachable</span>
        ) : health ? (
          <span className="text-sm text-secondary">
            schema v{health.schema_version}
          </span>
        ) : (
          <span className="spinner" style={{ width: 14, height: 14 }} />
        )}

        <button
          className="btn btn-sm btn-secondary"
          onClick={() => setShowTokenInput(v => !v)}
          aria-label="Configure access token"
        >
          {hasToken ? '🔑 Token set' : '🔑 Token'}
        </button>
      </div>

      {showTokenInput && (
        <div
          style={{
            position: 'fixed', top: 56, right: 24, zIndex: 100,
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-lg)', padding: 16, width: 320,
            boxShadow: 'var(--shadow-lg)'
          }}
          role="dialog"
          aria-label="Access token configuration"
        >
          <p className="text-sm text-secondary mb-8">
            Demo access token — stored in memory only. Never put model API keys here.
          </p>
          <div className="form-group">
            <input
              className="form-input"
              type="password"
              placeholder="Paste token..."
              value={tokenDraft}
              onChange={e => setTokenDraft(e.target.value)}
              autoComplete="off"
              autoCapitalize="off"
            />
          </div>
          <div className="flex gap-8 mt-8">
            <button
              className="btn btn-primary btn-sm"
              onClick={() => {
                onTokenChange(tokenDraft || null);
                setShowTokenInput(false);
                setTokenDraft('');
              }}
            >
              Set
            </button>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => { onTokenChange(null); setShowTokenInput(false); setTokenDraft(''); }}
            >
              Clear
            </button>
          </div>
        </div>
      )}
    </header>
  );
}
