import { expect, test, type Page } from '@playwright/test';

const alpha = '11111111-1111-4111-8111-111111111111';
const beta = '22222222-2222-4222-8222-222222222222';
const user = '33333333-3333-4333-8333-333333333333';
const root = '44444444-4444-4444-8444-444444444444';
const secondRoot = '55555555-5555-4555-8555-555555555555';
const profile = { id: user, email: 'member@example.test', name: 'Member', display_name: 'Member', revision: 1, avatar_url: null, is_sysadmin: false };
const workspace = (id: string, slug: string, role = 'owner') => ({ id, slug, name: slug === 'alpha' ? 'Alpha' : 'Beta', acl_root_id: root, role, revision: 1 });

async function gate(page: Page, active = true) {
  const state = { active, outage: false, denyLogin: false, denyMembers: false, conflict: false, creationFailure: false, logoutFailure: false, role: 'owner', revision: 1 };
  const requests: { path: string; method: string; body: any; key: string | undefined; csrf: string | undefined }[] = [];
  const unexpected: string[] = [];
  await page.route('**/api/**', async route => {
    const request = route.request(); const url = new URL(request.url()); const path = url.pathname;
    const body = request.postDataJSON(); const method = request.method();
    requests.push({ path, method, body, key: request.headers()['idempotency-key'], csrf: request.headers()['x-csrf-token'] });
    const fail = (status: number, code: string) => route.fulfill({ status, json: { error: { code } } });
    if (path === '/api/v1/arc/auth/register-invited') return route.fulfill({ status: 201, json: { user_id: user, workspace_id: alpha, recovery_code: 'registration-fixture-code' } });
    if (path === '/api/v1/arc/auth/recover') { state.active = false; return route.fulfill({ json: { code: 'replacement-fixture-code' } }); }
    if (path === '/api/v1/arc/auth/login') {
      if (state.denyLogin) return fail(401, 'UNAUTHENTICATED');
      state.active = true;
      return route.fulfill({ json: { session: { id: 'browser-session', user_id: user }, csrf: 'fixture-csrf' }, headers: { 'set-cookie': '__Host-arc_csrf=fixture-csrf; Path=/; Secure; SameSite=Lax' } });
    }
    if (state.outage) return fail(503, 'UNAVAILABLE');
    if (!state.active) return fail(401, 'UNAUTHENTICATED');
    if (path === '/api/v1/arc/identity/profile') return route.fulfill({ json: { ...profile, revision: state.revision } });
    if (path === '/api/v1/arc/identity/workspaces/list') {
      expect(url.searchParams.has('limit')).toBe(false);
      return route.fulfill({ json: [workspace(alpha, 'alpha', state.role), workspace(beta, 'beta', 'member')] });
    }
    if (path === '/api/v1/arc/identity/workspaces/by_slug') return route.fulfill({ json: url.searchParams.get('slug') === 'beta' ? workspace(beta, 'beta', 'member') : workspace(alpha, 'alpha', state.role) });
    if (path === '/api/v1/arc/identity/task_roots/list') return route.fulfill({ json: [{ id: url.searchParams.get('workspace_id') === beta ? secondRoot : root, can_read: true, can_write: true, can_manage: false }] });
    if (path === '/api/v1/arc/identity/workspaces/create') {
      if (state.creationFailure) { state.creationFailure = false; return fail(503, 'UNAVAILABLE'); }
      return route.fulfill({ json: workspace(alpha, body.slug ?? 'alpha') });
    }
    if (path === '/api/v1/arc/identity/members/list') {
      if (state.denyMembers) return fail(403, 'PERMISSION_DENIED');
      return route.fulfill({ json: [{ ...profile, email: 'visible-member@example.test', role: 'member' }] });
    }
    if (path === '/api/v1/arc/identity/account/profile/update') {
      if (state.conflict) return fail(409, 'CONFLICT');
      return route.fulfill({ json: { ...profile, revision: state.revision + 1 } });
    }
    if (path === '/api/v1/arc/auth/logout') {
      if (state.logoutFailure) return fail(503, 'UNAVAILABLE');
      state.active = false; return route.fulfill({ status: 204 });
    }
    if (path === '/api/v1/arc/identity/groups/list') return route.fulfill({ json: [] });
    if (path === '/api/v1/arc/identity/groups/create') return route.fulfill({ json: { id: root, name: body.name } });
    if (path.endsWith('/teams')) return route.fulfill({ json: { teams: [{ id: root, name: 'Engineering', key: 'ENG' }] } });
    if (path.endsWith('/statuses')) return route.fulfill({ json: { statuses: [{ id: root, name: 'Backlog', category: 'backlog' }] } });
    if (path.includes('/api/v1/task/') && path.endsWith('/work')) {
      if (method === 'POST') return route.fulfill({ json: { id: root } });
      return route.fulfill({ json: { tasks: [{ id: root, title: 'Existing task', identifier: 'ENG-1', status: 'backlog', team_id: root, status_id: root, description: 'Original', revision: 3, updated_at: '2026-11-12T00:00:00Z', priority: 2, sort_order: 7, assignee_ids: [user], label_ids: [beta], project_id: beta }] } });
    }
    if (path.includes('/api/v1/task/') && path.endsWith(`/work/${root}`)) {
      if (method === 'PATCH') return state.conflict ? fail(409, 'CONFLICT') : route.fulfill({ json: { id: root } });
      return route.fulfill({ json: { id: root, title: 'Existing task', identifier: 'ENG-1', team_id: root, status_id: root, description: 'Original', revision: 3, updated_at: '2026-11-12T00:00:00Z', priority: 2, sort_order: 7, assignee_ids: [user], label_ids: [beta], project_id: beta } });
    }
    if (path === '/api/v1/notify/notifications') return route.fulfill({ json: { notifications: [{ id: root, kind: 'task.created', created_at: '2026-11-12T00:00:00Z', revision: 2, read_at: null, archived_at: null, snoozed_until: null }], unread_count: 1 } });
    if (path === `/api/v1/notify/notifications/${root}/state`) return route.fulfill({ json: { id: root, revision: 3 } });
    unexpected.push(path); return fail(404, 'NOT_FOUND');
  });
  return { state, requests, unexpected };
}

test('sign-in uses Arc and the workspace shell makes no upstream feature requests', async ({ page }) => {
  const fixture = await gate(page, false);
  await page.goto('/login');
  await page.getByLabel('Email', { exact: true }).fill(profile.email);
  await page.getByLabel('Password', { exact: true }).fill('Fixture password 123');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('link', { name: 'Alpha', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Alpha', exact: true })).toBeVisible();
  await expect(page.getByLabel('Task root')).toContainText(root);
  const login = fixture.requests.find(request => request.path.endsWith('/auth/login'))!;
  expect(login.body).toEqual({ email: profile.email, password: 'Fixture password 123' });
  expect(fixture.requests.some(request => request.path.endsWith('/auth/refresh'))).toBe(false);
  expect(fixture.unexpected).toEqual([]);
});

test('failed credentials do not refresh or retry', async ({ page }) => {
  const fixture = await gate(page, false); fixture.state.denyLogin = true;
  await page.goto('/login');
  await page.getByLabel('Email', { exact: true }).fill(profile.email);
  await page.getByLabel('Password', { exact: true }).fill('Wrong password');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Sign in again');
  expect(fixture.requests.filter(request => request.path.includes('/auth/'))).toHaveLength(1);
});

test('invitation registration scrubs the fragment and shows recovery once without signing in', async ({ page }) => {
  const fixture = await gate(page, false);
  await page.goto('/login#invite=private-fixture-invitation');
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByLabel('Invitation token')).toHaveValue('private-fixture-invitation');
  await page.getByLabel('Email', { exact: true }).fill(profile.email);
  await page.getByLabel('Password', { exact: true }).fill('Fixture password 123');
  await page.getByRole('button', { name: 'Create account', exact: true }).click();
  await expect(page.getByLabel('Recovery code', { exact: true })).toHaveText('registration-fixture-code');
  await expect(page.getByRole('button', { name: 'Continue to sign in' })).toBeDisabled();
  expect(fixture.requests.map(request => request.path)).toEqual(['/api/v1/arc/auth/register-invited']);
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).not.toContain('registration-fixture-code');
  await page.getByLabel('I saved my recovery code').check();
  await page.getByRole('button', { name: 'Continue to sign in' }).click();
  await expect(page.getByText('registration-fixture-code')).toHaveCount(0);
});

test('recovery uses the code endpoint and requires a separate sign-in', async ({ page }) => {
  const fixture = await gate(page, false);
  await page.goto('/forgot-password');
  await page.getByLabel('Email', { exact: true }).fill(profile.email);
  await page.getByLabel('Recovery code', { exact: true }).fill('old-fixture-code');
  await page.getByLabel('New password', { exact: true }).fill('Fixture password 456');
  await page.getByRole('button', { name: 'Recover account', exact: true }).click();
  await expect(page.getByLabel('Recovery code', { exact: true })).toHaveText('replacement-fixture-code');
  expect(fixture.requests.map(request => request.path)).toEqual(['/api/v1/arc/auth/recover']);
});

test('authority outage stays an error instead of redirecting to sign-in', async ({ page }) => {
  const fixture = await gate(page); fixture.state.outage = true;
  await page.goto('/');
  await expect(page.getByRole('alert')).toContainText('temporarily unavailable');
  await expect(page).toHaveURL(/\/$/);
  fixture.state.outage = false;
  await page.getByRole('button', { name: 'Retry' }).click();
  await expect(page.getByRole('link', { name: 'Alpha', exact: true })).toBeVisible();
});

test('switching workspaces clears roots and does not expose owner controls to a member', async ({ page }) => {
  const fixture = await gate(page);
  await page.goto('/alpha');
  await page.getByLabel('Task root').selectOption(root);
  await expect(page.getByText(`Selected root: ${root}`, { exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Switch workspace' }).click();
  await page.getByRole('link', { name: 'Beta', exact: true }).click();
  await expect(page.getByLabel('Task root')).toHaveValue('');
  await expect(page.getByLabel('Task root')).not.toContainText(root);
  await expect(page.getByLabel('Task root')).toContainText(secondRoot);
  await page.getByRole('link', { name: 'Account & workspace settings' }).click();
  await expect(page.getByRole('heading', { name: 'Your profile' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create invitation' })).toHaveCount(0);
  expect(fixture.unexpected).toEqual([]);
});

test('retrying workspace creation retains the command key and propagates browser CSRF', async ({ page, context }) => {
  const fixture = await gate(page); fixture.state.creationFailure = true;
  await context.addCookies([{ name: '__Host-arc_csrf', value: 'fixture-csrf', domain: '127.0.0.1', path: '/', secure: true, sameSite: 'Lax' }]);
  await page.goto('/workspace-setup');
  await page.getByLabel('Name', { exact: true }).fill('Alpha');
  await page.getByLabel('Slug (optional)').fill('alpha');
  await page.getByRole('button', { name: 'Create workspace', exact: true }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await page.getByRole('button', { name: 'Create workspace', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Alpha', exact: true })).toBeVisible();
  const calls = fixture.requests.filter(request => request.path.endsWith('/workspaces/create'));
  expect(calls).toHaveLength(2); expect(calls[0].key).toBeTruthy(); expect(calls[0].key).toBe(calls[1].key);
  expect(calls.every(request => request.csrf === 'fixture-csrf')).toBe(true);
});

test('profile CAS conflict does not retry or replace the revision until explicit reload', async ({ page }) => {
  const fixture = await gate(page); fixture.state.conflict = true;
  await page.goto('/alpha/settings');
  await page.getByLabel('Display name', { exact: true }).fill('Changed');
  await page.getByRole('button', { name: 'Save profile', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('changed');
  const calls = fixture.requests.filter(request => request.path.endsWith('/account/profile/update'));
  expect(calls).toHaveLength(1); expect(calls[0].body.revision).toBe(1);
  fixture.state.conflict = false; fixture.state.revision = 2;
  await page.getByRole('button', { name: 'Reload profile' }).click();
  await page.getByRole('button', { name: 'Save profile', exact: true }).click();
  await expect(page.getByRole('status')).toHaveText('Profile saved.');
  expect(fixture.requests.filter(request => request.path.endsWith('/account/profile/update')).at(-1)!.body.revision).toBe(2);
});

test('denied member reload removes previously visible membership data', async ({ page }) => {
  const fixture = await gate(page);
  await page.goto('/alpha/settings');
  await page.getByRole('button', { name: 'Load members', exact: true }).click();
  await expect(page.getByText('visible-member@example.test · member', { exact: true })).toBeVisible();
  fixture.state.denyMembers = true;
  await page.getByRole('button', { name: 'Load members', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('permission');
  await expect(page.getByText('visible-member@example.test · member', { exact: true })).toHaveCount(0);
});

test('a new successful group creation uses a new key and unsupported sections make no upstream calls', async ({ page }) => {
  const fixture = await gate(page);
  await page.goto('/alpha/settings');
  for (let i = 0; i < 2; i++) {
    await page.getByLabel('Group name', { exact: true }).fill('Engineering');
    await page.getByRole('button', { name: 'Create group', exact: true }).click();
    await expect(page.getByRole('status')).toHaveText('Group saved.');
  }
  const calls = fixture.requests.filter(request => request.path.endsWith('/groups/create'));
  expect(calls).toHaveLength(2); expect(calls[0].key).not.toBe(calls[1].key);
  await page.goto('/alpha/projects');
  await expect(page.getByRole('heading', { name: 'This section is not connected to Arc yet' })).toBeVisible();
  expect(fixture.unexpected).toEqual([]);
});


test('Task edit preserves untouched projection fields and uses current revision', async ({ page }) => {
  const fixture = await gate(page);
  await page.goto('/alpha');
  await page.getByLabel('Task root', { exact: true }).selectOption(root);
  await page.getByRole('button', { name: 'Open task', exact: true }).click();
  await page.getByLabel('Task title', { exact: true }).fill('Edited title');
  await page.getByRole('button', { name: 'Save task', exact: true }).click();
  await expect(page.getByText('Task saved.', { exact: true })).toBeVisible();
  const update = fixture.requests.find(request => request.method === 'PATCH' && request.path.endsWith(`/work/${root}`))!;
  expect(update.body).toMatchObject({ title: 'Edited title', revision: 3, expected_updated_at: '2026-11-12T00:00:00Z', priority: 2, sort_order: 7, assignee_ids: [user], label_ids: [beta], project_id: beta });
  expect(update.key).toBeTruthy(); expect(fixture.unexpected).toEqual([]);
});

test('Inbox reads recipient-scoped results and writes revision-bound state', async ({ page }) => {
  const fixture = await gate(page);
  await page.goto('/alpha/inbox');
  await page.getByRole('button', { name: 'Mark read', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Mark read', exact: true })).toBeEnabled();
  const update = fixture.requests.find(request => request.path.endsWith(`/notifications/${root}/state`))!;
  expect(update.body).toEqual({ action: 'read', revision: 2 });
  expect(update.key).toBeTruthy(); expect(fixture.unexpected).toEqual([]);
});

test('Task conflict blocks saving until reload and never becomes a create', async ({ page }) => {
  const fixture = await gate(page); fixture.state.conflict = true;
  await page.goto('/alpha');
  await page.getByLabel('Task root', { exact: true }).selectOption(root);
  await page.getByRole('button', { name: 'Open task', exact: true }).click();
  await page.getByRole('button', { name: 'Save task', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('changed');
  await expect(page.getByRole('button', { name: 'Save task', exact: true })).toBeDisabled();
  expect(fixture.requests.some(request => request.method === 'POST' && request.path.endsWith('/work'))).toBe(false);
});
