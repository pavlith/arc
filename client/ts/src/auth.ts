import type { Transport, CallOptions } from './transport.js';
import type { Session } from './identity.js';

export interface BrowserLogin { email: string; password: string }
export interface BrowserSessionResult { session: Session; csrf: string }
export interface BrowserRefreshResult { session: Session }
export interface InvitedRegistration extends BrowserLogin { name?: string; token: string }
export interface InvitedRegistrationResult { user_id: string; workspace_id: string; recovery_code: string }
export interface RecoveryRequest { email: string; code: string; password: string }
export interface RecoveryResult { code: string }

/** Recovery/registration results contain one-time secrets; keep them out of logs/storage. */
export function createAuthAPI(transport: Transport) {
  const post = <I, O>(path: string) => (input: I, options?: CallOptions) => transport.request<O>('/api/v1/arc/auth/' + path, { ...options, method: 'POST', body: input });
  return {
    login: post<BrowserLogin, BrowserSessionResult>('login'),
    session: (options?: CallOptions) => transport.request<Session>('/api/v1/arc/auth/session', options),
    refresh: (options?: CallOptions) => post<Record<string, never>, BrowserRefreshResult>('refresh')({}, options),
    logout: (options?: CallOptions) => post<Record<string, never>, void>('logout')({}, options),
    registerInvited: post<InvitedRegistration, InvitedRegistrationResult>('register-invited'),
    recover: post<RecoveryRequest, RecoveryResult>('recover'),
  };
}
