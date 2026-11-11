export const SLUG_MAX_LENGTH = 50;

export const SLUG_FALLBACK = 'workspace';

/**
 * Derives a workspace slug accepted by the backend `slug` validator:
 * lowercase alphanumeric groups joined by single hyphens, with no leading,
 * trailing or repeated hyphens, capped at SLUG_MAX_LENGTH characters.
 *
 * Accents are folded rather than dropped, so "José" becomes "jose" instead of
 * "jos". Returns an empty string when the input has no usable characters —
 * callers decide whether to fall back or reject.
 */
export function toSlug(value: string): string {
	return value
		.normalize('NFD')
		.replace(/\p{Diacritic}/gu, '')
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-+|-+$/g, '')
		.slice(0, SLUG_MAX_LENGTH)
		.replace(/-+$/, '');
}
