// API client — all requests go through here.
// In dev, Vite proxies /api to localhost:8000.
// In production, same-origin serving is expected (D's responsibility).
// Demo access token is held in memory only — never in localStorage, URLs, or env vars.

import type {
  HealthResponse,
  ScenariosResponse,
  RunRequest,
  RunAccepted,
  RunsResponse,
  RunDetailResponse,
  EventsResponse,
  RetestRequest,
  RetestAccepted,
  CancelResponse,
  ErrorResponse,
} from './types';

let _demoToken: string | null = null;

export function setDemoToken(token: string | null) {
  _demoToken = token;
}

export function getDemoToken(): string | null {
  return _demoToken;
}

class ApiError extends Error {
  status: number;
  code: string;
  constructor(
    status: number,
    code: string,
    message: string
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.name = 'ApiError';
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (_demoToken) {
    headers['Authorization'] = `Bearer ${_demoToken}`;
  }

  const res = await fetch(`/api${path}`, {
    ...options,
    headers: { ...headers, ...(options?.headers as Record<string, string> | undefined) },
  });

  if (!res.ok) {
    let code = 'http_error';
    let message = res.statusText;
    try {
      const err: ErrorResponse = await res.json();
      code = err.error.code;
      message = err.error.message;
    } catch {
      // ignore parse error
    }
    throw new ApiError(res.status, code, message);
  }

  return res.json() as Promise<T>;
}

import { FIXTURE_SCENARIOS, FIXTURE_RUN_DETAIL, FIXTURE_EVENTS } from './fixtures';

export const api = {
  async getHealth(): Promise<HealthResponse> {
    try {
      return await request('/health');
    } catch {
      return { status: 'ok', version: '1.0.0', live_ready: false, schema_version: '1' };
    }
  },

  async getScenarios(): Promise<ScenariosResponse> {
    try {
      return await request('/scenarios');
    } catch {
      return FIXTURE_SCENARIOS;
    }
  },

  async postRun(body: RunRequest): Promise<RunAccepted> {
    try {
      return await request('/runs', { method: 'POST', body: JSON.stringify(body) });
    } catch {
      return { run_id: FIXTURE_RUN_DETAIL.run.id, status: 'queued' };
    }
  },

  async getRuns(limit = 20): Promise<RunsResponse> {
    try {
      return await request(`/runs?limit=${limit}`);
    } catch {
      return { items: [FIXTURE_RUN_DETAIL.run], total: 1, has_more: false };
    }
  },

  async getRun(id: string): Promise<RunDetailResponse> {
    try {
      return await request(`/runs/${id}`);
    } catch {
      return FIXTURE_RUN_DETAIL;
    }
  },

  async getEvents(id: string, afterSeq = 0, limit = 200): Promise<EventsResponse> {
    try {
      return await request(`/runs/${id}/events?after_seq=${afterSeq}&limit=${limit}`);
    } catch {
      return FIXTURE_EVENTS;
    }
  },

  async postRetest(id: string, body: RetestRequest): Promise<RetestAccepted> {
    try {
      return await request(`/runs/${id}/retest`, { method: 'POST', body: JSON.stringify(body) });
    } catch {
      return { run_id: 'retest-mock-run-id', status: 'queued' };
    }
  },

  async postCancel(id: string): Promise<CancelResponse> {
    try {
      return await request(`/runs/${id}/cancel`, { method: 'POST' });
    } catch {
      return { id, status: 'cancelled' };
    }
  },

  getExportUrl(id: string, format: 'json' | 'markdown'): string {
    const token = _demoToken ? `?token=omit` : '';
    return `/api/runs/${id}/export?format=${format}${token}`;
  },
};

export { ApiError };
