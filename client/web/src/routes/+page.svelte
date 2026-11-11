<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Field from '#lib/components/ui/field/index.js';
  import { Input } from '#lib/components/ui/input/index.js';
  import * as NativeSelect from '#lib/components/ui/native-select/index.js';
  import { api, APIError } from '@arc/client';
  import type { Invitation, Profile, RequestOptions, Task, TaskList, TaskRoot, Workspace } from '@arc/client';

  let loading = $state(true);
  let busy = $state(false);
  let error = $state('');
  let profile = $state<Profile | null>(null);
  let email = $state('');
  let password = $state('');
  let workspaces = $state<Workspace[]>([]);
  let workspace = $state<Workspace | null>(null);
  let scopes = $state<TaskRoot[]>([]);
  let scope = $state<TaskRoot | null>(null);
  let tasks = $state<Task[]>([]);
  let task = $state<Task | null>(null);
  let title = $state('');
  let draft = $state('');
  let workspaceName = $state('');
  let inviting = $state(false);
  let inviteEmail = $state('');
  let inviteRole = $state('member');
  let shareInvite = $state<Invitation & { url: string } | null>(null);
  let incomingInvite = $state('');
  let inviteDraft: { signature: string; token: string } | null = null;
  let retry: { signature: string; key: string } | null = null;

  const identity = '/api/v1/arc/identity';
  const auth = '/api/v1/arc/auth';
  const time = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

  function reset() {
    profile = null;
    workspaces = [];
    workspace = null;
    scopes = [];
    scope = null;
    tasks = [];
    task = null;
    shareInvite = null;
    inviteDraft = null;
    inviting = false;
    retry = null;
  }

  async function run(action: () => Promise<void>, quietUnauthorized = false) {
    if (busy) return;
    busy = true;
    error = '';
    try {
      await action();
    } catch (err) {
      if (err instanceof APIError && err.status === 401) {
        reset();
        if (!quietUnauthorized) error = err.message;
      } else {
        error = err instanceof APIError ? err.message : 'Arc could not load this view.';
      }
    } finally {
      busy = false;
      loading = false;
    }
  }

  async function pages<T extends { id: string }>(path: string, params: Record<string, string> = {}) {
    const items: T[] = [];
    let after = '';
    for (;;) {
      const query = new URLSearchParams(params);
      if (after) query.set('after', after);
      const page = await api<T[]>(`${path}?${query}`);
      items.push(...page);
      if (page.length < 100) return items;
      const next = page.at(-1)?.id;
      if (!next || next <= after) throw new Error('Invalid page cursor');
      after = next;
    }
  }

  async function loadProfile() {
    profile = await api<Profile>(`${identity}/profile`);
    workspaces = await pages<Workspace>(`${identity}/workspaces/list`);
    if (workspaces.length) await chooseWorkspace(workspaces[0]);
  }

  onMount(() => {
    const token = new URLSearchParams(location.hash.slice(1)).get('invite');
    if (token && /^[A-Za-z0-9_-]{43}$/.test(token)) {
      incomingInvite = token;
      void goto(location.pathname + location.search, { replace: true, shallow: true });
    }
    void run(loadProfile, true);
  });

  async function signIn(event: SubmitEvent) {
    event.preventDefault();
    await run(async () => {
      const credentials = { email, password };
      password = '';
      await api(`${auth}/login`, { method: 'POST', body: credentials });
      await loadProfile();
    });
  }

  async function chooseWorkspace(item: Workspace) {
    workspace = item;
    scope = null;
    scopes = [];
    tasks = [];
    task = null;
    shareInvite = null;
    inviteDraft = null;
    inviting = false;
    scopes = await pages<TaskRoot>(`${identity}/task_roots/list`, { workspace_id: item.id });
    if (scopes.length) await chooseScope(scopes[0]);
  }

  function taskPath() {
    if (!workspace || !scope) throw new Error('Missing task scope');
    return `/api/v1/task/workspaces/${encodeURIComponent(workspace.id)}/roots/${encodeURIComponent(scope.id)}/tasks`;
  }

  async function chooseScope(item: TaskRoot) {
    scope = item;
    tasks = [];
    task = null;
    await loadTasks();
  }

  async function loadTasks() {
    tasks = (await api<TaskList>(`${taskPath()}?limit=100`)).task;
  }

  async function openTask(item: Task) {
    task = await api<Task>(`${taskPath()}/${encodeURIComponent(item.id)}`);
    draft = task.title;
  }

  async function command<T = void>(method: NonNullable<RequestOptions['method']>, path: string, body: unknown) {
    const signature = JSON.stringify([method, path, body]);
    if (retry?.signature !== signature) retry = { signature, key: crypto.randomUUID() };
    const result = await api<T>(path, { method, body, key: retry.key });
    retry = null;
    return result;
  }

  async function createWorkspace(event: SubmitEvent) {
    event.preventDefault();
    if (!workspaceName.trim()) return;
    await run(async () => {
      const item = await command<Workspace>('POST', `${identity}/workspaces/create`, { name: workspaceName.trim() });
      workspaceName = '';
      workspaces = [...workspaces.filter((old) => old.id !== item.id), item];
      await chooseWorkspace(item);
    });
  }

  function newInviteToken() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  }

  async function createInvitation(event: SubmitEvent) {
    event.preventDefault();
    if (!workspace) return;
    const workspaceId = workspace.id;
    await run(async () => {
      const input = { workspace_id: workspaceId, email: inviteEmail.trim(), role: inviteRole };
      const signature = JSON.stringify(input);
      if (inviteDraft?.signature !== signature) inviteDraft = { signature, token: newInviteToken() };
      const invite = await command<Invitation>('POST', `${identity}/invitations/create`, { ...input, token: inviteDraft.token });
      shareInvite = { ...invite, url: `${location.origin}/#invite=${inviteDraft.token}` };
      inviteDraft = null;
      inviteEmail = '';
    });
  }

  async function revokeInvitation() {
    if (!workspace || !shareInvite) return;
    const input = { workspace_id: workspace.id, id: shareInvite.id };
    await run(async () => {
      await command('POST', `${identity}/invitations/revoke`, input);
      shareInvite = null;
    });
  }

  async function acceptInvitation() {
    await run(async () => {
      const item = await command<Workspace>('POST', `${identity}/invitations/accept`, { token: incomingInvite });
      incomingInvite = '';
      workspaces = [...workspaces.filter((old) => old.id !== item.id), item];
      await chooseWorkspace(item);
    });
  }

  async function createTask(event: SubmitEvent) {
    event.preventDefault();
    if (!title.trim()) return;
    await run(async () => {
      task = await command<Task>('POST', taskPath(), { title: title.trim() });
      title = '';
      draft = task.title;
      await loadTasks();
    });
  }

  async function editTask(event: SubmitEvent) {
    event.preventDefault();
    if (!draft.trim() || !task) return;
    const current = task;
    await run(async () => {
      task = await command<Task>('PATCH', `${taskPath()}/${encodeURIComponent(current.id)}`, {
        title: draft.trim(), expected_updated_at: current.updated_at,
      });
      draft = task.title;
      await loadTasks();
    });
  }
</script>

{#if loading}
  <main class="center"><p role="status">Opening Arc…</p></main>
{:else if !profile}
  <main class="center">
    <section class="signin" aria-labelledby="signin-title">
      <span class="brand">Arc</span>
      <h1 id="signin-title">Sign in</h1>
      {#if incomingInvite}<p class="muted">Sign in with the email address on your invitation.</p>{/if}
      {#if error}<p class="error" role="alert">{error}</p>{/if}
      <form onsubmit={signIn}>
        <Field.FieldGroup class="gap-4">
          <Field.Field>
            <Field.FieldLabel for="email">Email</Field.FieldLabel>
            <Input id="email" type="email" autocomplete="username" required maxlength={254} bind:value={email} />
          </Field.Field>
          <Field.Field>
            <Field.FieldLabel for="password">Password</Field.FieldLabel>
            <Input id="password" type="password" autocomplete="current-password" required bind:value={password} />
          </Field.Field>
          <Button type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</Button>
        </Field.FieldGroup>
      </form>
    </section>
  </main>
{:else}
  <header class="topbar">
    <span class="brand">Arc</span>
    <div class="account"><span>{profile.email}</span><Button variant="outline" disabled={busy} onclick={() => run(async () => {
      await api(`${auth}/logout`, { method: 'POST', body: {} });
      reset();
    })}>Sign out</Button></div>
  </header>
  <div class="shell">
    <aside class="workspaces" aria-label="Workspaces">
      <h2>Workspaces</h2>
      {#each workspaces as item (item.id)}
        <Button class="workspace-button" variant={item.id === workspace?.id ? 'secondary' : 'ghost'} aria-current={item.id === workspace?.id ? 'true' : undefined}
          disabled={busy} onclick={() => run(() => chooseWorkspace(item))}>{item.name}</Button>
      {:else}
        <p class="muted">No workspaces assigned.</p>
      {/each}
      <form class="new-workspace" onsubmit={createWorkspace}>
        <Field.FieldGroup class="gap-4">
          <Field.Field>
            <Field.FieldLabel for="workspace-name">Workspace name</Field.FieldLabel>
            <Input id="workspace-name" required maxlength={128} bind:value={workspaceName} />
          </Field.Field>
          <Button type="submit" disabled={busy}>Create workspace</Button>
        </Field.FieldGroup>
      </form>
    </aside>
    <main class="content" aria-busy={busy}>
      {#if error}<p class="error" role="alert">{error}</p>{/if}
      {#if incomingInvite}
        <section class="invitation" aria-label="Workspace invitation">
          <p>You have a workspace invitation.</p>
          <Button disabled={busy} onclick={acceptInvitation}>Accept invitation</Button>
        </section>
      {/if}
      {#if workspace}
        <div class="section-header"><div><p class="muted">{workspace.name}</p><h1>Tasks</h1></div>
          <div class="actions">
            {#if workspace.role === 'owner' || workspace.role === 'admin'}
              <Button variant="outline" disabled={busy} onclick={() => inviting = !inviting}>{inviting ? 'Close invitation form' : 'Invite member'}</Button>
            {/if}
            {#if scope}<Button variant="outline" disabled={busy} onclick={() => run(loadTasks)}>Refresh</Button>{/if}
          </div>
        </div>
        {#if inviting}
          <section class="invitation" aria-label="Invite a workspace member">
            <form onsubmit={createInvitation}>
              <Field.FieldGroup class="gap-4">
                <Field.Field>
                  <Field.FieldLabel for="recipient-email">Recipient email</Field.FieldLabel>
                  <Input id="recipient-email" type="email" required maxlength={254} bind:value={inviteEmail} />
                </Field.Field>
                <Field.Field>
                  <Field.FieldLabel for="invitation-role">Role</Field.FieldLabel>
                  <NativeSelect.Root id="invitation-role" bind:value={inviteRole}>
                    <NativeSelect.Option value="member">Member</NativeSelect.Option>
                    <NativeSelect.Option value="guest">Guest</NativeSelect.Option>
                  </NativeSelect.Root>
                </Field.Field>
                <Button type="submit" disabled={busy}>Create invitation</Button>
              </Field.FieldGroup>
            </form>
            {#if shareInvite}
              <Field.Field>
                <Field.FieldLabel for="share-this-invitation-link">Share this invitation link</Field.FieldLabel>
                <Input id="share-this-invitation-link" readonly value={shareInvite.url} />
              </Field.Field>
              <p class="muted">Expires {time.format(new Date(shareInvite.expires_at))}.</p>
              <Button variant="outline" disabled={busy} onclick={revokeInvitation}>Revoke invitation</Button>
            {/if}
          </section>
        {/if}
        {#if scopes.length > 1}
          <Field.Field class="scope">
            <Field.FieldLabel for="task-scope">Task scope</Field.FieldLabel>
            <NativeSelect.Root id="task-scope" value={scope?.id} disabled={busy} onchange={(event) => {
              const next = scopes.find((item) => item.id === event.currentTarget.value);
              if (next) void run(() => chooseScope(next));
            }}>
              {#each scopes as item (item.id)}<NativeSelect.Option value={item.id}>{item.id}</NativeSelect.Option>{/each}
            </NativeSelect.Root>
          </Field.Field>
        {/if}
        {#if !scope}
          <p class="empty">{busy ? 'Loading task scopes…' : 'No Task roots are available in this workspace.'}</p>
        {:else}
          {#if scope.can_write}
            <form class="new-task" onsubmit={createTask}>
              <Field.FieldGroup class="task-form-fields">
                <Field.Field>
                  <Field.FieldLabel for="new-task">New task</Field.FieldLabel>
                  <Input id="new-task" placeholder="Task title" required maxlength={300} bind:value={title} />
                </Field.Field>
                <Button type="submit" disabled={busy}>Add task</Button>
              </Field.FieldGroup>
            </form>
          {/if}
          <div class="task-grid">
            <section aria-label="Task list">
              {#if tasks.length}
                <ul class="task-list">
                  {#each tasks as item (item.id)}
                    <li><Button class="task-button" variant={task?.id === item.id ? 'secondary' : 'ghost'} aria-pressed={task?.id === item.id} disabled={busy} onclick={() => run(() => openTask(item))}>
                      <span>{item.title}</span><Badge variant="secondary">Open</Badge>
                    </Button></li>
                  {/each}
                </ul>
              {:else}
                <p class="empty">{busy ? 'Loading tasks…' : 'No tasks yet.'}</p>
              {/if}
            </section>
            {#if task}
              <section class="details" aria-labelledby="task-heading">
                <h2 id="task-heading">{task.title}</h2>
                <p class="muted">Updated {time.format(new Date(task.updated_at))}</p>
                {#if scope.can_write && task.created_by === profile.id}
                  <form onsubmit={editTask}>
                    <Field.FieldGroup class="gap-4">
                      <Field.Field>
                        <Field.FieldLabel for="title">Title</Field.FieldLabel>
                        <Input id="title" required maxlength={300} bind:value={draft} />
                      </Field.Field>
                      <div class="actions">
                        <Button type="submit" disabled={busy || draft.trim() === task.title}>Save changes</Button>
                        <Button variant="outline" disabled={busy} onclick={() => {
                          const current = task;
                          if (current) void run(() => openTask(current));
                        }}>Reload</Button>
                      </div>
                    </Field.FieldGroup>
                  </form>
                {/if}
              </section>
            {/if}
          </div>
        {/if}
      {:else}
        <h1>Workspaces</h1>
        <p class="empty">{busy ? 'Loading workspaces…' : 'Your workspaces will appear here when you are added.'}</p>
        {#if error}<Button variant="outline" disabled={busy} onclick={() => run(loadProfile)}>Try again</Button>{/if}
      {/if}
    </main>
  </div>
{/if}
