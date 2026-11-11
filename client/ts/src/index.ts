export class APIError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

const messages: Readonly<Partial<Record<number, string>>> = {
  400: 'Check the information you entered.',
  401: 'Sign in again to continue.',
  403: 'You do not have permission for this action.',
  404: 'This item is unavailable.',
  409: 'This item changed. Reload it before saving again.',
  429: 'Too many requests. Try again in a moment.',
};

function csrfToken() {
  const cookie = document.cookie.split('; ').find((item) => item.startsWith('__Host-arc_csrf='));
  return cookie?.slice('__Host-arc_csrf='.length);
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  body?: unknown;
  key?: string;
}

export async function api<T = void>(path: string, { method = 'GET', body, key }: RequestOptions = {}): Promise<T> {
  const headers = new Headers({ Accept: 'application/json' });
  if (body !== undefined) headers.set('Content-Type', 'application/json');
  const csrf = csrfToken();
  if (csrf && method !== 'GET') headers.set('X-CSRF-Token', csrf);
  if (key) headers.set('Idempotency-Key', key);
  let response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
      signal: AbortSignal.timeout(15000),
    });
  } catch {
    throw new APIError(0, 'Arc is unreachable. Check your connection and try again.');
  }
  if (!response.ok) throw new APIError(response.status, messages[response.status] ?? 'Arc is temporarily unavailable.');
  return response.status === 204 ? undefined as T : response.json();
}

export interface Profile {
  id: string;
  email: string;
}

export interface Workspace {
  id: string;
  acl_root_id: string;
  name: string;
  role: string;
  revision: number;
}

export interface TaskRoot {
  id: string;
  can_write: boolean;
}

export interface Invitation {
  id: string;
  workspace_id: string;
  email: string;
  role: string;
  expires_at: string;
}

export interface Task {
  id: string;
  workspace_id: string;
  acl_root_id: string;
  title: string;
  status: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface TaskList {
  task: Task[];
}
