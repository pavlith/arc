export class APIError extends Error {
  constructor(readonly status: number, message: string, readonly code?: string, readonly requestId?: string) {
    super(message);
    this.name = 'APIError';
  }
}

const messages: Readonly<Partial<Record<number, string>>> = {
  400: 'Check the information you entered.',
  401: 'Sign in again to continue.',
  403: 'You do not have permission for this action.',
  404: 'This item is unavailable.',
  409: 'This item changed. Reload it before saving again.',
  413: 'The request is too large.',
  429: 'Too many requests. Try again in a moment.',
};
export interface CallOptions { signal?: AbortSignal; timeoutMs?: number }
export interface CommandOptions extends CallOptions { key: string }
export interface RequestOptions extends CallOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  body?: unknown;
  key?: string;
}
export interface ClientOptions {
  fetch?: typeof globalThis.fetch;
  /** Same-origin Gate origin. Required outside a browser unless fetch handles relative URLs. */
  baseURL?: string;
  csrfToken?: () => string | undefined;
  timeoutMs?: number;
}
export interface Transport { request<T>(path: string, options?: RequestOptions): Promise<T> }

function browserCSRF(): string | undefined {
  if (typeof document === 'undefined') return undefined;
  return document.cookie.split(';').map((item) => item.trim()).find((item) => item.startsWith('__Host-arc_csrf='))?.slice('__Host-arc_csrf='.length);
}
export function createTransport(config: ClientOptions = {}): Transport {
  const fetcher = config.fetch ?? globalThis.fetch.bind(globalThis);
  const browserOrigin = typeof location === 'undefined' ? undefined : location.origin;
  const base = config.baseURL === undefined ? browserOrigin : new URL(config.baseURL).origin;
  if (config.baseURL !== undefined) {
    const url = new URL(config.baseURL);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new TypeError('baseURL must be an HTTP origin.');
  }
  if (browserOrigin && base !== browserOrigin) throw new TypeError('Arc requires a same-origin Gate.');
  return { async request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    if (!path.startsWith('/api/v1/') || !new URL(path, base ?? 'https://arc.invalid').pathname.startsWith('/api/v1/') || path.includes('\\') || path.includes('#')) throw new TypeError('Expected an Arc API path.');
    const { method = 'GET', body, key, signal } = options;
    const timeoutMs = options.timeoutMs ?? config.timeoutMs ?? 15000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2147483647) throw new TypeError('timeoutMs must be positive.');
    const timeout = AbortSignal.timeout(timeoutMs);
    const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
    const headers = new Headers({ Accept: 'application/json' });
    if (body !== undefined) headers.set('Content-Type', 'application/json');
    const csrf = (config.csrfToken ?? browserCSRF)();
    if (csrf && method !== 'GET') headers.set('X-CSRF-Token', csrf);
    if (key !== undefined) {
      if (!/^[A-Za-z0-9_-]{1,128}$/.test(key)) throw new TypeError('Invalid idempotency key.');
      headers.set('Idempotency-Key', key);
    }
    const connectionError = () => {
      if (signal?.aborted) return new APIError(0, 'The request was cancelled.', 'ABORTED');
      if (timeout.aborted) return new APIError(0, 'Arc did not respond in time.', 'TIMEOUT');
      return new APIError(0, 'Arc is unreachable. Check your connection and try again.', 'NETWORK_ERROR');
    };
    const payload = body === undefined ? undefined : JSON.stringify(body);
    let response: Response;
    try {
      combined.throwIfAborted();
      response = await fetcher(base ? new URL(path, base).href : path, {
        method, headers, body: payload,
        credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: combined,
      });
    } catch { throw connectionError(); }
    if (!response.ok) {
      const data: unknown = await response.json().catch(() => undefined);
      let code: string | undefined, requestId: string | undefined;
      if (data && typeof data === 'object') {
        const envelope = data as { error?: { code?: unknown }; request_id?: unknown };
        if (typeof envelope.error?.code === 'string' && /^[A-Z_]{1,64}$/.test(envelope.error.code)) code = envelope.error.code;
        if (typeof envelope.request_id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(envelope.request_id)) requestId = envelope.request_id;
      }
      throw new APIError(response.status, messages[response.status] ?? 'Arc is temporarily unavailable.', code, requestId);
    }
    if (response.status === 204) return undefined as T;
    try { return await response.json() as T; }
    catch {
      if (combined.aborted) throw connectionError();
      throw new APIError(response.status, 'Arc returned an invalid response.', 'INVALID_RESPONSE');
    }
  } };
}

interface Route {
  method: NonNullable<RequestOptions['method']>;
  path: string;
  bindings: readonly { source: string; name: string; field: string; type: string }[];
}
export function callRoute<I, O>(transport: Transport, route: Route, input: I, options?: CallOptions & { key?: string }): Promise<O> {
  const body = { ...input } as Record<string, unknown>;
  let path = route.path;
  const query = new URLSearchParams();
  for (const binding of route.bindings) {
    const value = body[binding.field];
    delete body[binding.field];
    if (binding.source === 'path') {
      if (typeof value !== 'string' || !value || value === '.' || value === '..' || /[\\/]/.test(value)) throw new TypeError(`Invalid path field ${binding.field}.`);
      path = path.replace(`{${binding.name}}`, encodeURIComponent(value));
    } else if (binding.source === 'query') {
      if (value !== undefined) query.set(binding.name, String(value));
    } else throw new TypeError('Unsupported route binding.');
  }
  if (route.method !== 'GET' && !options?.key) throw new TypeError('An explicit idempotency key is required.');
  if (query.size) path += '?' + query.toString();
  return transport.request<O>(path, { ...options, method: route.method, body: route.method === 'GET' ? undefined : body });
}

let defaultTransport: Transport | undefined;
/** Backwards-compatible browser helper. No automatic refresh or mutation retry. */
export function api<T = void>(path: string, options?: RequestOptions): Promise<T> {
  return (defaultTransport ??= createTransport()).request<T>(path, options);
}
