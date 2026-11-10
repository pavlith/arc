<script>
  import { onMount } from 'svelte';
  import { api, APIError } from './api.js';

  let loading = $state(true);
  let busy = $state(false);
  let error = $state('');
  let profile = $state(null);
  let email = $state('');
  let password = $state('');
  let workspaces = $state([]);
  let workspace = $state(null);
  let scopes = $state([]);
  let scope = $state(null);
  let tasks = $state([]);
  let task = $state(null);
  let title = $state('');
  let draft = $state('');
  let retry = null;

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
    retry = null;
  }

  async function run(action, quietUnauthorized = false) {
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

  async function pages(path, params = {}) {
    const items = [];
    let after = '';
    for (;;) {
      const query = new URLSearchParams(params);
      if (after) query.set('after', after);
      const page = await api(`${path}?${query}`);
      items.push(...page);
      if (page.length < 100) return items;
      const next = page.at(-1).id;
      if (!next || next <= after) throw new Error('Invalid page cursor');
      after = next;
    }
  }

  async function loadProfile() {
    profile = await api(`${identity}/profile`);
    workspaces = await pages(`${identity}/workspaces/list`);
    if (workspaces.length) await chooseWorkspace(workspaces[0]);
  }

  onMount(() => { void run(loadProfile, true); });

  async function signIn(event) {
    event.preventDefault();
    await run(async () => {
      const credentials = { email, password };
      password = '';
      await api(`${auth}/login`, { method: 'POST', body: credentials });
      await loadProfile();
    });
  }

  async function chooseWorkspace(item) {
    workspace = item;
    scope = null;
    scopes = [];
    tasks = [];
    task = null;
    scopes = await pages(`${identity}/task_roots/list`, { workspace_id: item.id });
    if (scopes.length) await chooseScope(scopes[0]);
  }

  function taskPath() {
    return `/api/v1/task/workspaces/${encodeURIComponent(workspace.id)}/roots/${encodeURIComponent(scope.id)}/tasks`;
  }

  async function chooseScope(item) {
    scope = item;
    tasks = [];
    task = null;
    await loadTasks();
  }

  async function loadTasks() {
    tasks = (await api(`${taskPath()}?limit=100`)).task;
  }

  async function openTask(item) {
    task = await api(`${taskPath()}/${encodeURIComponent(item.id)}`);
    draft = task.title;
  }

  async function command(method, path, body) {
    const signature = JSON.stringify([method, path, body]);
    if (retry?.signature !== signature) retry = { signature, key: crypto.randomUUID() };
    const result = await api(path, { method, body, key: retry.key });
    retry = null;
    return result;
  }

  async function createTask(event) {
    event.preventDefault();
    if (!title.trim()) return;
    await run(async () => {
      task = await command('POST', taskPath(), { title: title.trim() });
      title = '';
      draft = task.title;
      await loadTasks();
    });
  }

  async function editTask(event) {
    event.preventDefault();
    if (!draft.trim()) return;
    await run(async () => {
      task = await command('PATCH', `${taskPath()}/${encodeURIComponent(task.id)}`, {
        title: draft.trim(), expected_updated_at: task.updated_at,
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
      {#if error}<p class="error" role="alert">{error}</p>{/if}
      <form onsubmit={signIn}>
        <label>Email <input type="email" autocomplete="username" required maxlength="254" bind:value={email} /></label>
        <label>Password <input type="password" autocomplete="current-password" required bind:value={password} /></label>
        <button class="primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
    </section>
  </main>
{:else}
  <header class="topbar">
    <span class="brand">Arc</span>
    <div class="account"><span>{profile.email}</span><button disabled={busy} onclick={() => run(async () => {
      await api(`${auth}/logout`, { method: 'POST', body: {} });
      reset();
    })}>Sign out</button></div>
  </header>
  <div class="shell">
    <aside class="workspaces" aria-label="Workspaces">
      <h2>Workspaces</h2>
      {#each workspaces as item (item.id)}
        <button class:current={item.id === workspace?.id} aria-current={item.id === workspace?.id ? 'true' : undefined}
          disabled={busy} onclick={() => run(() => chooseWorkspace(item))}>{item.name}</button>
      {:else}
        <p class="muted">No workspaces assigned.</p>
      {/each}
    </aside>
    <main class="content" aria-busy={busy}>
      {#if error}<p class="error" role="alert">{error}</p>{/if}
      {#if workspace}
        <div class="section-header"><div><p class="muted">{workspace.name}</p><h1>Tasks</h1></div>
          {#if scope}<button disabled={busy} onclick={() => run(loadTasks)}>Refresh</button>{/if}
        </div>
        {#if scopes.length > 1}
          <label class="scope">Task scope
            <select value={scope?.id} disabled={busy} onchange={(event) => {
              const next = scopes.find((item) => item.id === event.currentTarget.value);
              if (next) void run(() => chooseScope(next));
            }}>
              {#each scopes as item (item.id)}<option value={item.id}>{item.id}</option>{/each}
            </select>
          </label>
        {/if}
        {#if !scope}
          <p class="empty">{busy ? 'Loading task scopes…' : 'No task scopes are available in this workspace.'}</p>
        {:else}
          {#if scope.can_write}
            <form class="new-task" onsubmit={createTask}>
              <label>New task <input placeholder="Task title" required maxlength="300" bind:value={title} /></label>
              <button class="primary" disabled={busy}>Add task</button>
            </form>
          {/if}
          <div class="task-grid">
            <section aria-label="Task list">
              {#if tasks.length}
                <ul class="task-list">
                  {#each tasks as item (item.id)}
                    <li><button class:current={task?.id === item.id} disabled={busy} onclick={() => run(() => openTask(item))}>
                      <span>{item.title}</span><span class="status">Open</span>
                    </button></li>
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
                    <label>Title <input required maxlength="300" bind:value={draft} /></label>
                    <div class="actions"><button class="primary" disabled={busy || draft.trim() === task.title}>Save changes</button>
                      <button type="button" disabled={busy} onclick={() => run(() => openTask(task))}>Reload</button></div>
                  </form>
                {/if}
              </section>
            {/if}
          </div>
        {/if}
      {:else}
        <h1>Workspaces</h1>
        <p class="empty">{busy ? 'Loading workspaces…' : 'Your workspaces will appear here when you are added.'}</p>
        {#if error}<button disabled={busy} onclick={() => run(loadProfile)}>Try again</button>{/if}
      {/if}
    </main>
  </div>
{/if}
