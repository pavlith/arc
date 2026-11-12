import type { User } from '$lib/types/auth';
import { getMe } from '$lib/api/auth';
import { APIError, errorMessage } from '$lib/api/arc';

class AuthState {
  user = $state<User | null>(null);
  loading = $state(true);
  error = $state('');
  authenticated = $derived(this.user !== null);
  private generation = 0;

  async init(_redirectOnUnauthorized = true, signal?: AbortSignal) {
    const generation = ++this.generation;
    this.loading = true;
    this.error = '';
    try {
      const user = await getMe({ signal });
      if (generation === this.generation) this.user = user;
    } catch (error) {
      if (generation !== this.generation || signal?.aborted) return;
      this.user = null;
      // An authority outage must not masquerade as an anonymous session.
      if (!(error instanceof APIError && error.status === 401)) this.error = errorMessage(error);
    } finally {
      if (generation === this.generation) this.loading = false;
    }
  }
  setUser(user: User | null) {
    this.generation++;
    this.user = user;
    this.loading = false;
    this.error = '';
  }
  clear() { this.setUser(null); }
}
export const authState = new AuthState();
