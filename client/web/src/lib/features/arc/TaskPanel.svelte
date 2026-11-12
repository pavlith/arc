<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { arc, commandKey, errorMessage } from '$lib/api/arc';
  import type { TaskWork, TaskTeam, TaskStatus } from '@arc/client';
  import { Button } from '$lib/components/ui/button';
  import { Input } from '$lib/components/ui/input';
  import { Textarea } from '$lib/components/ui/textarea';
  let { workspaceId, rootId, canWrite, canManage }: { workspaceId: string; rootId: string; canWrite: boolean; canManage: boolean } = $props();
  const controller = new AbortController();
  const options = { signal: controller.signal };
  const scope = () => ({ workspace_id: workspaceId, acl_root_id: rootId });
  let tasks = $state<TaskWork[]>([]); let teams = $state<TaskTeam[]>([]); let statuses = $state<TaskStatus[]>([]);
  let selected = $state<TaskWork | null>(null); let team = $state(''); let status = $state('');
  let title = $state(''); let description = $state(''); let search = $state(''); let cursor = $state<string | undefined>();
  let teamName = $state(''); let teamKey = $state(''); let error = $state(''); let notice = $state(''); let busy = $state(false);
  let blocked = $state(false);
  let key = commandKey();
  async function run(work: () => Promise<void>) {
    if (busy) return; busy = true; error = ''; notice = '';
    try { await work(); key = commandKey(); } catch (cause) { if (!controller.signal.aborted) { blocked = true; error = errorMessage(cause); tasks = []; teams = []; statuses = []; selected = null; } }
    finally { if (!controller.signal.aborted) busy = false; }
  }
  async function load(append = false) {
    const result = await arc.task.work.list({ ...scope(), limit: 50, ...(search.trim() ? { search: search.trim() } : {}), ...(append && cursor ? { cursor } : {}) }, options);
    tasks = append ? [...tasks, ...result.tasks] : result.tasks; cursor = result.next_cursor;
  }
  async function initialize() {
    const result = await arc.task.teams.list({ ...scope(), limit: 100 }, options);
    teams = result.teams; await load(); reset(); blocked = false;
  }
  async function loadStatuses() {
    statuses = []; status = '';
    if (team) { const result = await arc.task.statuses.list({ ...scope(), team_id: team }, options); statuses = result.statuses; }
  }
  function reset() { selected = null; title = ''; description = ''; team = ''; status = ''; statuses = []; }
  async function edit(task: TaskWork) {
    await run(async () => {
      const current = await arc.task.work.get({ ...scope(), task_id: task.id }, options);
      selected = current; title = current.title; description = current.description; team = current.team_id ?? '';
      await loadStatuses(); status = current.status_id ?? '';
    });
  }
  async function save(event: SubmitEvent) {
    event.preventDefault();
    await run(async () => {
      // Updates replace the mutable projection: preserve fields not edited here.
      const input = { ...scope(), title: title.trim(), description, team_id: team, ...(status ? { status_id: status } : {}),
        ...(selected ? { task_id: selected.id, revision: selected.revision, expected_updated_at: selected.updated_at,
          priority: selected.priority, due_date: selected.due_date, sort_order: selected.sort_order,
          assignee_ids: selected.assignee_ids, project_id: selected.project_id, label_ids: selected.label_ids } : {}) };
      if (selected) await arc.task.work.update({ ...input, task_id: selected.id, revision: selected.revision, expected_updated_at: selected.updated_at }, { ...key(input), ...options });
      else await arc.task.work.create(input, { ...key(input), ...options });
      reset(); await load(); notice = 'Task saved.';
    });
  }
  async function archive(task: TaskWork) {
    await run(async () => {
      const input = { ...scope(), task_id: task.id, revision: task.revision, expected_updated_at: task.updated_at };
      await arc.task.work.archive(input, { ...key(input), ...options }); reset(); await load(); notice = 'Task archived.';
    });
  }
  async function createTeam(event: SubmitEvent) {
    event.preventDefault(); await run(async () => {
      const input = { ...scope(), name: teamName.trim(), key: teamKey.trim() };
      await arc.task.teams.create(input, { ...key(input), ...options }); teamName = ''; teamKey = ''; await initialize();
    });
  }
  async function subscribe() {
    await run(async () => { const input = { ...scope(), resource_kind: 'task' as const }; await arc.notify.subscriptions.subscribe(input, { ...key(input), ...options }); notice = 'Subscribed to Task notifications.'; });
  }
  onMount(() => { void run(initialize); });
  onDestroy(() => controller.abort());
</script>
<section class="mt-8 grid gap-5"><h2 class="text-xl font-semibold">Tasks</h2>
  {#if error}<p role="alert">{error} Reload current data before retrying.</p>{/if}{#if notice}<p role="status">{notice}</p>{/if}
  <div class="flex flex-wrap gap-3"><Button disabled={busy} onclick={() => run(initialize)}>Reload tasks</Button><Button variant="outline" disabled={busy} onclick={subscribe}>Subscribe to Task notifications</Button></div>
  <form class="flex gap-3" onsubmit={(event) => { event.preventDefault(); void run(() => load()); }}><label for="task-search">Search tasks</label><Input id="task-search" bind:value={search} /><Button type="submit" disabled={busy}>Search</Button></form>
  {#if busy}<p role="status">Loading…</p>{/if}
  <ul class="grid gap-3">{#each tasks as task (task.id)}<li class="flex flex-wrap items-center gap-3"><span>{task.identifier} · {task.title} · {task.status}</span><Button variant="outline" disabled={busy} onclick={() => edit(task)}>Open task</Button>{#if canWrite}<Button variant="outline" disabled={busy || blocked} onclick={() => archive(task)}>Archive task</Button>{/if}</li>{/each}</ul>
  {#if !busy && !error && !tasks.length}<p>No tasks found.</p>{/if}
  {#if cursor}<Button disabled={busy} onclick={() => run(() => load(true))}>Load more tasks</Button>{/if}
  {#if selected && !canWrite}<h3>{title}</h3><p class="whitespace-pre-wrap">{description}</p>{/if}
  {#if canWrite}<form onsubmit={save} class="grid gap-3"><h3 class="text-lg font-semibold">{selected ? 'Edit task' : 'Create task'}</h3>
    <label for="task-title">Task title</label><Input id="task-title" bind:value={title} required />
    <label for="task-description">Description</label><Textarea id="task-description" bind:value={description} />
    <label for="task-team">Team</label><select id="task-team" bind:value={team} required disabled={busy} onchange={() => run(loadStatuses)}><option value="">Choose team</option>{#each teams as item (item.id)}<option value={item.id}>{item.name}</option>{/each}</select>
    <label for="task-status">Status</label><select id="task-status" bind:value={status} disabled={busy}><option value="">Team default</option>{#each statuses as item (item.id)}<option value={item.id}>{item.name}</option>{/each}</select>
    <Button type="submit" disabled={busy || blocked}>Save task</Button>{#if selected}<Button variant="outline" disabled={busy} onclick={reset}>Cancel edit</Button>{/if}
  </form>{/if}
  {#if canManage}<form onsubmit={createTeam} class="grid gap-3"><h3 class="text-lg font-semibold">Create team</h3><label for="new-team-name">Team name</label><Input id="new-team-name" bind:value={teamName} required /><label for="new-team-key">Team key</label><Input id="new-team-key" bind:value={teamKey} required /><Button type="submit" disabled={busy}>Create team</Button></form>{/if}
</section>
