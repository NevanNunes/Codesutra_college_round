// useRunData — polls run summary + events while active, stops at terminal status.
// Merges/deduplicates events by ID+seq. Cancels subscriptions on unmount/run change.

import { useState, useEffect, useRef, useCallback } from 'react';
import { api, ApiError } from '../api';
import type { RunSummary, CaseResultPublic, TraceEvent } from '../types';
import { TERMINAL_STATUSES } from '../types';

export interface RunData {
  run: RunSummary | null;
  cases: CaseResultPublic[];
  events: TraceEvent[];
  loading: boolean;
  error: string | null;
  disconnected: boolean;
  refresh: () => void;
}

export function useRunData(runId: string | null): RunData {
  const [run, setRun] = useState<RunSummary | null>(null);
  const [cases, setCases] = useState<CaseResultPublic[]>([]);
  const [events, setEvents] = useState<TraceEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [disconnected, setDisconnected] = useState(false);

  const afterSeqRef = useRef(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const mountedRef = useRef(true);

  const fetchEvents = useCallback(async (id: string) => {
    let seq = afterSeqRef.current;
    let hasMore = true;
    while (hasMore) {
      const resp = await api.getEvents(id, seq, 200);
      if (!mountedRef.current) return;
      setEvents(prev => {
        const existingIds = new Set(prev.map(e => e.id));
        const newItems = resp.items.filter(e => !existingIds.has(e.id));
        if (newItems.length === 0) return prev;
        return [...prev, ...newItems].sort((a, b) => a.seq - b.seq);
      });
      if (resp.items.length > 0) {
        seq = resp.next_after_seq;
        afterSeqRef.current = seq;
      }
      hasMore = resp.has_more;
    }
  }, []);

  const fetchAll = useCallback(async (id: string, initial = false) => {
    if (initial) setLoading(true);
    try {
      const detail = await api.getRun(id);
      if (!mountedRef.current) return;
      setRun(detail.run);
      setCases(detail.cases);
      setError(null);
      setDisconnected(false);
      await fetchEvents(id);
      if (TERMINAL_STATUSES.includes(detail.run.status)) {
        if (intervalRef.current) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
        }
      }
    } catch (e) {
      if (!mountedRef.current) return;
      if (e instanceof ApiError && e.status === 404) {
        setError('Run not found.');
      } else {
        setDisconnected(true);
      }
    } finally {
      if (mountedRef.current && initial) setLoading(false);
    }
  }, [fetchEvents]);

  const refresh = useCallback(() => {
    if (runId) fetchAll(runId);
  }, [runId, fetchAll]);

  useEffect(() => {
    mountedRef.current = true;
    if (!runId) {
      setRun(null);
      setCases([]);
      setEvents([]);
      setError(null);
      setDisconnected(false);
      afterSeqRef.current = 0;
      return;
    }

    afterSeqRef.current = 0;
    setEvents([]);
    setCases([]);
    setRun(null);

    fetchAll(runId, true);

    intervalRef.current = setInterval(() => {
      if (!mountedRef.current) return;
      // Only poll if not already in terminal state
      setRun(prev => {
        if (prev && TERMINAL_STATUSES.includes(prev.status)) {
          if (intervalRef.current) clearInterval(intervalRef.current);
          return prev;
        }
        fetchAll(runId);
        return prev;
      });
    }, 1000);

    return () => {
      mountedRef.current = false;
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [runId, fetchAll]);

  return { run, cases, events, loading, error, disconnected, refresh };
}
