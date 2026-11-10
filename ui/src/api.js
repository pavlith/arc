export class APIError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const messages = {
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

export async function api(path, { method = 'GET', body, key } = {}) {
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
  return response.status === 204 ? undefined : response.json();
}
