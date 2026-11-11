import { SLUG_FALLBACK, SLUG_MAX_LENGTH, toSlug } from './slug.ts';

const DEFAULT_WORKSPACE_SUFFIX = "'s Workspace";
const DEFAULT_WORKSPACE_NAME_BASE_LENGTH = 100 - DEFAULT_WORKSPACE_SUFFIX.length;
const SLUG_COLLISION_RETRIES = 3;

export function defaultWorkspaceName(userName: string): string {
	const base = [...userName].slice(0, DEFAULT_WORKSPACE_NAME_BASE_LENGTH).join('');
	return `${base}${DEFAULT_WORKSPACE_SUFFIX}`;
}

export function randomSlugSuffix(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(4));
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function slugWithSuffix(base: string, suffix: string): string {
	const prefixLength = SLUG_MAX_LENGTH - suffix.length - 1;
	const prefix = base.slice(0, prefixLength).replace(/-+$/, '');
	return `${prefix}-${suffix}`;
}

function isSlugTakenError(error: unknown): boolean {
	if (!error || typeof error !== 'object' || !('error' in error)) return false;
	const body = (error as { error?: { code?: unknown } }).error;
	return body?.code === 'WORKSPACE_SLUG_TAKEN';
}

export async function createDefaultWorkspace<T>(
	userName: string,
	create: (name: string, slug: string) => Promise<T>,
	createSuffix: () => string = randomSlugSuffix
): Promise<T> {
	const name = defaultWorkspaceName(userName);
	const derivedSlug = toSlug(userName);
	const baseSlug = derivedSlug || SLUG_FALLBACK;
	let slug = derivedSlug || slugWithSuffix(baseSlug, createSuffix());

	for (let attempt = 0; ; attempt += 1) {
		try {
			return await create(name, slug);
		} catch (error) {
			if (!isSlugTakenError(error) || attempt >= SLUG_COLLISION_RETRIES) throw error;
			slug = slugWithSuffix(baseSlug, createSuffix());
		}
	}
}
