import { useMemo, useCallback } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  type Node,
  type Edge,
  type Connection,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { TraceEvent, EventType } from '../types';

// Node color by event type — not by timestamp proximity (that is not a causal link)
const EVENT_COLORS: Record<EventType, string> = {
  run_started: '#4f7cff',
  candidate_generated: '#8b5cf6',
  case_started: '#3b9dff',
  source_injected: '#06b6d4',
  model_request: '#f59e0b',
  model_response: '#f59e0b',
  tool_proposed: '#f97316',
  policy_decision: '#6366f1',
  tool_executed: '#ef4444',    // executed = notable (could be forbidden)
  tool_blocked: '#22c55e',     // blocked = defense acted
  oracle_result: '#a855f7',
  case_completed: '#3b9dff',
  run_completed: '#4f7cff',
  run_error: '#ef4444',
  run_cancelled: '#8b93b0',
};

const EVENT_ICONS: Record<EventType, string> = {
  run_started: '▶',
  candidate_generated: '⚡',
  case_started: '📋',
  source_injected: '📄',
  model_request: '→',
  model_response: '←',
  tool_proposed: '🔧',
  policy_decision: '🔒',
  tool_executed: '⚠',
  tool_blocked: '✓',
  oracle_result: '🔍',
  case_completed: '✓',
  run_completed: '⬛',
  run_error: '✕',
  run_cancelled: '⊘',
};

function buildLayout(events: TraceEvent[]): { nodes: Node[]; edges: Edge[] } {
  const sorted = [...events].sort((a, b) => a.seq - b.seq);
  const nodeMap = new Map<string, TraceEvent>();
  sorted.forEach(e => nodeMap.set(e.id, e));

  // Simple left-to-right layout using seq as x-position
  const COLS = 5;
  const COL_W = 180;
  const ROW_H = 100;

  const nodes: Node[] = sorted.map((e, i) => {
    const col = i % COLS;
    const row = Math.floor(i / COLS);
    const color = EVENT_COLORS[e.type] ?? '#8b93b0';

    return {
      id: e.id,
      position: { x: col * COL_W, y: row * ROW_H },
      data: {
        label: (
          <div style={{ textAlign: 'center', fontSize: 11 }}>
            <div style={{ fontSize: 16 }}>{EVENT_ICONS[e.type]}</div>
            <div style={{ fontWeight: 600, color }}>{e.type.replace(/_/g, ' ')}</div>
            <div style={{ color: '#8b93b0', fontSize: 10 }}>seq {e.seq}</div>
          </div>
        ),
        event: e,
      },
      style: {
        background: 'var(--bg-elevated)',
        border: `1.5px solid ${color}40`,
        borderRadius: 8,
        width: 150,
        boxShadow: `0 0 0 0 ${color}`,
        cursor: 'pointer',
      },
    };
  });

  const edges: Edge[] = [];
  sorted.forEach(e => {
    e.parent_event_ids.forEach(parentId => {
      if (nodeMap.has(parentId)) {
        edges.push({
          id: `${parentId}->${e.id}`,
          source: parentId,
          target: e.id,
          style: { stroke: '#2a3050', strokeWidth: 1.5 },
          animated: false,
        });
      }
    });
  });

  return { nodes, edges };
}

interface EventGraphProps {
  events: TraceEvent[];
  onSelectEvent?: (event: TraceEvent) => void;
}

export function EventGraph({ events, onSelectEvent }: EventGraphProps) {
  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => buildLayout(events), [events]);
  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  const onConnect = useCallback((connection: Connection) => {
    setEdges(eds => addEdge(connection, eds));
  }, [setEdges]);

  if (events.length === 0) {
    return (
      <div className="empty-state">
        <span className="empty-state-icon">🕸</span>
        <p>No events recorded yet</p>
      </div>
    );
  }

  return (
    <div style={{ height: 480, borderRadius: 'var(--radius-lg)', overflow: 'hidden', border: '1px solid var(--border)', background: 'var(--bg-base)' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onNodeClick={(_, node) => {
          if (onSelectEvent && node.data?.event) {
            onSelectEvent(node.data.event as TraceEvent);
          }
        }}
        fitView
        attributionPosition="bottom-right"
      >
        <Background color="#1e2540" gap={20} size={1} />
        <Controls />
        <MiniMap
          style={{ background: 'var(--bg-elevated)' }}
          nodeColor={n => {
            const e = n.data?.event as TraceEvent | undefined;
            return e ? (EVENT_COLORS[e.type] ?? '#8b93b0') : '#8b93b0';
          }}
        />
      </ReactFlow>
    </div>
  );
}

// Accessible chronological event list (fallback / complementary view)
export function EventList({ events, onSelectEvent }: EventGraphProps) {
  const sorted = [...events].sort((a, b) => a.seq - b.seq);

  if (sorted.length === 0) {
    return (
      <div className="empty-state">
        <span className="empty-state-icon">📜</span>
        <p>No events yet</p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }} role="list" aria-label="Event timeline">
      {sorted.map(e => {
        const color = EVENT_COLORS[e.type] ?? '#8b93b0';
        return (
          <button
            key={e.id}
            role="listitem"
            onClick={() => onSelectEvent?.(e)}
            style={{
              display: 'flex', alignItems: 'flex-start', gap: 12,
              padding: '10px 14px',
              background: 'var(--bg-elevated)', border: `1px solid ${color}30`,
              borderRadius: 'var(--radius)', cursor: 'pointer',
              textAlign: 'left', width: '100%', fontFamily: 'inherit',
              transition: 'all 150ms ease',
            }}
            onMouseOver={e_ => (e_.currentTarget.style.borderColor = `${color}60`)}
            onMouseOut={e_ => (e_.currentTarget.style.borderColor = `${color}30`)}
            aria-label={`Event: ${e.type}, sequence ${e.seq}`}
          >
            <span style={{ color, fontSize: 16, lineHeight: 1.2 }}>{EVENT_ICONS[e.type]}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="flex items-center gap-8">
                <span style={{ color, fontWeight: 600, fontSize: 12 }}>{e.type.replace(/_/g, ' ')}</span>
                <span className="text-xs text-muted font-mono">seq {e.seq}</span>
              </div>
              <div className="text-xs text-muted font-mono mt-4">{e.timestamp}</div>
              {e.parent_event_ids.length > 0 && (
                <div className="text-xs text-muted mt-4">
                  parents: {e.parent_event_ids.map(id => id.slice(0, 8)).join(', ')}
                </div>
              )}
            </div>
          </button>
        );
      })}
    </div>
  );
}

// Selected event detail panel
export function EventDetail({ event }: { event: TraceEvent }) {
  const color = EVENT_COLORS[event.type] ?? '#8b93b0';

  return (
    <div className="card" style={{ padding: 16 }}>
      <div className="flex items-center gap-10 mb-12">
        <span style={{ color, fontSize: 18 }}>{EVENT_ICONS[event.type]}</span>
        <h3 style={{ color }}>{event.type.replace(/_/g, ' ')}</h3>
        <span className="text-xs text-muted font-mono">seq {event.seq}</span>
      </div>

      <div className="callout info mb-12" style={{ fontSize: 12 }}>
        <span>ℹ</span>
        <span>Edges show recorded context and execution dependencies, not the model's private reasoning or proof of semantic causality.</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div>
          <span className="text-xs text-muted">Event ID</span>
          <div className="hash-value mt-4">{event.id}</div>
        </div>
        <div>
          <span className="text-xs text-muted">Timestamp</span>
          <div className="text-sm font-mono mt-4">{event.timestamp}</div>
        </div>
        {event.trial_id && (
          <div>
            <span className="text-xs text-muted">Trial ID</span>
            <div className="hash-value mt-4">{event.trial_id}</div>
          </div>
        )}
        {event.parent_event_ids.length > 0 && (
          <div>
            <span className="text-xs text-muted">Parent Events (recorded input dependency)</span>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
              {event.parent_event_ids.map(id => (
                <code key={id} style={{ fontSize: 11, background: 'var(--bg-base)', padding: '2px 6px', borderRadius: 4 }}>{id.slice(0, 8)}</code>
              ))}
            </div>
          </div>
        )}
        {Object.keys(event.data).length > 0 && (
          <div>
            <span className="text-xs text-muted">Data (plain text — treat as hostile)</span>
            {/* Event data rendered as safe pre-formatted text */}
            <pre className="code-block mt-4">{JSON.stringify(event.data, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  );
}
