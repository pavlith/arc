import { createClient, APIError } from '@arc/client';

/** One same-origin browser client. Authentication and command retries stay explicit. */
export const arc = createClient({ fetch: (...args) => globalThis.fetch(...args) });
export { APIError };

export function errorMessage(error: unknown): string {
  return error instanceof APIError ? error.message : 'The request could not be completed. Try again.';
}

/** A retry of unchanged input retains its key, including after an uncertain timeout. */
export function commandKey() {
  let previous = '';
  let key = '';
  return (input: unknown) => {
    const serialized = JSON.stringify(input);
    if (!key || previous !== serialized) {
      previous = serialized;
      key = crypto.randomUUID();
    }
    return { key };
  };
}
