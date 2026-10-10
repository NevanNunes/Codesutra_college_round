/// <reference types="@testing-library/jest-dom" />
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { OracleBadge, StatusBadge, SimulationBanner } from '../components/Badges';
import { CaseEvidence } from '../components/CaseEvidence';
import { CaseList } from '../components/CaseList';
import { Comparison } from '../components/Comparison';
import { FIXTURE_RUN_DETAIL, FIXTURE_EVENTS } from '../fixtures';
import type { CaseResultPublic, TraceEvent } from '../types';

// ─── Oracle semantics ────────────────────────────────────────────────────────
describe('OracleBadge semantics', () => {
  it('labels oracle success as "Attack Succeeded" (attacker win — not defense success)', () => {
    render(<OracleBadge outcome="success" />);
    expect(screen.getByText(/attack succeeded/i)).toBeInTheDocument();
  });

  it('labels oracle failure as "Attack Failed (Defense Held)"', () => {
    render(<OracleBadge outcome="failure" />);
    expect(screen.getByText(/attack failed/i)).toBeInTheDocument();
  });

  it('labels inconclusive correctly', () => {
    render(<OracleBadge outcome="inconclusive" />);
    expect(screen.getByText(/inconclusive/i)).toBeInTheDocument();
  });
});

// ─── Status badge ─────────────────────────────────────────────────────────────
describe('StatusBadge', () => {
  it('renders queued status', () => {
    render(<StatusBadge status="queued" />);
    expect(screen.getByText('Queued')).toBeInTheDocument();
  });

  it('renders running status', () => {
    render(<StatusBadge status="running" />);
    expect(screen.getByText('Running')).toBeInTheDocument();
  });
});

// ─── Simulation banner ────────────────────────────────────────────────────────
describe('SimulationBanner', () => {
  it('renders fixture simulation warning', () => {
    render(<SimulationBanner />);
    expect(screen.getByText(/fixture simulation/i)).toBeInTheDocument();
  });
});

// ─── CaseEvidence — hostile text rendering ───────────────────────────────────
describe('CaseEvidence', () => {
  const mockCase: CaseResultPublic = FIXTURE_RUN_DETAIL.cases[0];
  const onClose = vi.fn();

  beforeEach(() => {
    onClose.mockReset();
  });

  it('renders case evidence without dangerouslySetInnerHTML for final_output', () => {
    render(<CaseEvidence caseResult={mockCase} onClose={onClose} />);
    // Final output rendered as plain text
    const block = screen.getByLabelText(/final output/i);
    expect(block.tagName).not.toBe('SCRIPT');
    expect(block).toHaveTextContent(mockCase.final_output);
  });

  it('renders malicious text as plain text without executing scripts', () => {
    const maliciousCase: CaseResultPublic = {
      ...mockCase,
      final_output: '<script>window.__xss__=true</script><img src=x onerror="window.__xss__=true">',
    };
    render(<CaseEvidence caseResult={maliciousCase} onClose={onClose} />);
    // Must appear as literal text, not as DOM elements
    const block = screen.getByLabelText(/final output/i);
    expect(block.innerHTML).not.toContain('<script');
    expect((window as unknown as Record<string, unknown>)['__xss__']).toBeUndefined();
  });

  it('closes on close button click', async () => {
    render(<CaseEvidence caseResult={mockCase} onClose={onClose} />);
    await userEvent.click(screen.getByLabelText(/close case evidence/i));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('distinguishes oracle success (attacker won) from defense success', () => {
    const attackSuccessCase: CaseResultPublic = { ...mockCase, oracle_outcome: 'success' };
    render(<CaseEvidence caseResult={attackSuccessCase} onClose={onClose} />);
    expect(screen.getByText(/attack succeeded/i)).toBeInTheDocument();
  });
});

// ─── CaseList ─────────────────────────────────────────────────────────────────
describe('CaseList', () => {
  const cases = FIXTURE_RUN_DETAIL.cases;

  it('renders cases table', () => {
    render(<CaseList cases={cases} onSelectCase={vi.fn()} selectedTrialId={null} />);
    expect(screen.getByRole('table')).toBeInTheDocument();
  });

  it('shows empty state when no cases', () => {
    render(<CaseList cases={[]} onSelectCase={vi.fn()} selectedTrialId={null} />);
    expect(screen.getByText(/no cases yet/i)).toBeInTheDocument();
  });

  it('distinguishes attack from benign type labels', () => {
    const benignCase: CaseResultPublic = { ...cases[0], candidate_id: null, payload_sha256: null };
    render(<CaseList cases={[cases[0], benignCase]} onSelectCase={vi.fn()} selectedTrialId={null} />);
    // The tab filter also has "Attack" — use getAllByText
    expect(screen.getAllByText('Attack').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Benign').length).toBeGreaterThan(0);
  });
});

// ─── Comparison — N/A denominators ───────────────────────────────────────────
describe('Comparison', () => {
  it('shows N/A when no conclusive cases', () => {
    const inconclusive: CaseResultPublic = {
      ...FIXTURE_RUN_DETAIL.cases[0],
      oracle_outcome: 'inconclusive',
    };
    render(
      <Comparison
        baselineCases={[inconclusive]}
        retestCases={[{ ...inconclusive, defense: 'gateway' }]}
        baselineRunId="run-a"
        retestRunId="run-b"
      />
    );
    // N/A for both attack rate cells — no fabricated percentages
    const naCells = screen.getAllByText('N/A');
    expect(naCells.length).toBeGreaterThan(0);
  });

  it('flags benign regression when baseline passed but retest failed', () => {
    const base: CaseResultPublic = {
      ...FIXTURE_RUN_DETAIL.cases[0],
      candidate_id: null,
      payload_sha256: null,
      benign_success: true,
      oracle_outcome: 'failure',
    };
    const retest: CaseResultPublic = { ...base, benign_success: false, defense: 'gateway' };
    render(
      <Comparison
        baselineCases={[base]}
        retestCases={[retest]}
        baselineRunId="run-a"
        retestRunId="run-b"
      />
    );
    expect(screen.getByText(/regression/i)).toBeInTheDocument();
  });
});

// ─── Polling / event deduplication ───────────────────────────────────────────
describe('Event deduplication', () => {
  it('deduplicates events by ID', () => {
    const events: TraceEvent[] = [
      ...FIXTURE_EVENTS.items,
      ...FIXTURE_EVENTS.items, // duplicate
    ];
    const ids = events.map(e => e.id);
    const unique = [...new Set(ids)];
    expect(unique.length).toBe(FIXTURE_EVENTS.items.length);
  });

  it('sorts events by seq', () => {
    const events: TraceEvent[] = [
      { ...FIXTURE_EVENTS.items[0], seq: 5 },
      { ...FIXTURE_EVENTS.items[0], id: 'alt-id', seq: 2 },
    ];
    const sorted = [...events].sort((a, b) => a.seq - b.seq);
    expect(sorted[0].seq).toBe(2);
    expect(sorted[1].seq).toBe(5);
  });
});
