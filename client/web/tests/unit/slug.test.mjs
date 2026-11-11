import assert from 'node:assert/strict';
import test from 'node:test';
import { toSlug } from '../../src/lib/utils/slug.ts';

test('derives lowercase ASCII slugs accepted by the backend', () => {
	const cases = [
		['Ada Lovelace', 'ada-lovelace'],
		['José', 'jose'],
		['  Acme -- Engineering  ', 'acme-engineering'],
		['東京', ''],
		['a'.repeat(49) + ' b', 'a'.repeat(49)]
	];

	for (const [input, expected] of cases) {
		const slug = toSlug(input);
		assert.equal(slug, expected);
		if (slug) {
			assert.match(slug, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
			assert.ok(slug.length <= 50);
		}
	}
});
