import type { CallOptions } from '@arc/client';
import { arc, APIError } from './arc';
import type { User, LoginRequest, UpdateProfileRequest } from '$lib/types/auth';

export async function login(input: LoginRequest, options?: CallOptions): Promise<User> {
  await arc.auth.login(input, options);
  return getMe(options);
}
export async function logout(): Promise<void> { await arc.auth.logout(); }
export function getMe(options?: CallOptions): Promise<User> { return arc.identity.profile(options); }

export async function updateProfile(input: UpdateProfileRequest): Promise<User> {
  if (input.avatar_url !== undefined) throw new APIError(400, 'Use a Files avatar receipt to change your avatar.');
  if (!input.revision || input.name === undefined || input.display_name === undefined) {
    throw new APIError(409, 'Reload your profile before saving.');
  }
  await arc.identity.account.profile.update({ name: input.name, display_name: input.display_name,
    revision: input.revision }, { key: crypto.randomUUID() });
  return getMe();
}
export async function uploadAvatar(_file: File, _progress?: (fraction: number) => void): Promise<User> {
  throw new APIError(501, 'Avatar uploads require the Files integration.');
}
