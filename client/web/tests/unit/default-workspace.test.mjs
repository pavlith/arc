import assert from 'node:assert/strict';
import test from 'node:test';
import {
	createDefaultWorkspace,
	defaultWorkspaceName,
	randomSlugSuffix,
	slugWithSuffix
} from '../../src/lib/utils/default-workspace.ts';

const slugTakenError = () => ({
	error: { code: 'WORKSPACE_SLUG_TAKEN', message: 'Workspace slug is already taken' }
});

test('limits only the default workspace name base to 88 Unicode characters', () => {
	assert.equal(defaultWorkspaceName('a'.repeat(100)), `${'a'.repeat(88)}'s Workspace`);

	const unicodeName = defaultWorkspaceName('😀'.repeat(100));
	assert.equal([...unicodeName].length, 100);
	assert.equal(unicodeName, `${'😀'.repeat(88)}'s Workspace`);
});

test('generates lowercase hexadecimal random suffixes', () => {
	for (let i = 0; i < 10; i += 1) {
		assert.match(randomSlugSuffix(), /^[a-f0-9]{8}$/);
	}
});

test('appends a suffix without exceeding the slug limit', () => {
	const slug = slugWithSuffix('a'.repeat(50), 'deadbeef');

	assert.equal(slug, `${'a'.repeat(41)}-deadbeef`);
	assert.equal(slug.length, 50);
	assert.match(slug, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
});

test('creates the default workspace with the friendly slug first', async () => {
	const requests = [];
	const workspace = { slug: 'ada-lovelace' };

	const result = await createDefaultWorkspace('Ada Lovelace', async (name, slug) => {
		requests.push({ name, slug });
		return workspace;
	});

	assert.equal(result, workspace);
	assert.deepEqual(requests, [{ name: "Ada Lovelace's Workspace", slug: 'ada-lovelace' }]);
});

test('uses a unique fallback slug when the name has no ASCII characters', async () => {
	const requests = [];

	await createDefaultWorkspace(
		'東京',
		async (name, slug) => {
			requests.push({ name, slug });
			return { slug };
		},
		() => 'deadbeef'
	);

	assert.deepEqual(requests, [{ name: "東京's Workspace", slug: 'workspace-deadbeef' }]);
});

test('retries a slug collision with a random suffix', async () => {
	const requests = [];

	const result = await createDefaultWorkspace(
		'a'.repeat(100),
		async (name, slug) => {
			requests.push({ name, slug });
			if (requests.length === 1) throw slugTakenError();
			return { slug };
		},
		() => 'deadbeef'
	);

	assert.equal([...requests[0].name].length, 100);
	assert.equal(requests[0].slug, 'a'.repeat(50));
	assert.equal(requests[1].slug, `${'a'.repeat(41)}-deadbeef`);
	assert.equal(result.slug, requests[1].slug);
});

test('retries at most three collisions', async () => {
	const slugs = [];
	const suffixes = ['00000001', '00000002', '00000003'];
	let suffixIndex = 0;

	await assert.rejects(
		createDefaultWorkspace(
			'Ada Lovelace',
			async (_name, slug) => {
				slugs.push(slug);
				throw slugTakenError();
			},
			() => suffixes[suffixIndex++]
		),
		(error) => error?.error?.code === 'WORKSPACE_SLUG_TAKEN'
	);

	assert.deepEqual(slugs, ['ada-lovelace', 'ada-lovelace-00000001', 'ada-lovelace-00000002', 'ada-lovelace-00000003']);
});

test('does not retry unrelated workspace creation failures', async () => {
	const databaseError = { error: { code: 'INTERNAL_ERROR', message: 'Try again later' } };
	let attempts = 0;

	await assert.rejects(
		createDefaultWorkspace('Ada Lovelace', async () => {
			attempts += 1;
			throw databaseError;
		}),
		(error) => error === databaseError
	);
	assert.equal(attempts, 1);
});
