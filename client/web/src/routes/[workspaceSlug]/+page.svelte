<script lang="ts">
  import TaskPanel from '$lib/features/arc/TaskPanel.svelte';
  import { arc, errorMessage } from '$lib/api/arc';
  import { useArcWorkspace } from '$lib/features/workspaces/arc-workspace.svelte';
  import type { TaskRoot } from '@arc/client';
  import { Button } from '$lib/components/ui/button';
  const context = useArcWorkspace();
  let roots = $state<TaskRoot[]>([]); let loading = $state(false); let error = $state(''); let more = $state(false);
  let generation = 0;
  async function load(append = false) {
    const workspace = context.workspace; if (!workspace) return;
    const current = ++generation; loading = true; error = '';
    try {
      const next = await arc.identity.taskRoots.list({ workspace_id: workspace.id, ...(append && roots.length ? { after: roots.at(-1)!.id } : {}) });
      if (current !== generation || context.workspace?.id !== workspace.id) return;
      roots = append ? [...roots, ...next] : next; more = next.length === 100;
      context.root = null;
    } catch (cause) { if (current === generation) { context.root = null; roots = []; error = errorMessage(cause); } }
    finally { if (current === generation) loading = false; }
  }
  $effect(() => { context.workspace?.id; roots = []; context.root = null; void load(); return () => { generation++; }; });
</script>
<svelte:head><title>Workspace · Arc</title></svelte:head>
<section class="grid gap-5"><h2 class="text-xl font-semibold">Task roots</h2><p>Choose an accessible Task root. Permission hints do not replace live server authorization.</p>
  {#if loading}<p role="status">Loading Task roots…</p>{/if}
  {#if error}<p role="alert">{error}</p><Button onclick={() => load()}>Retry</Button>{/if}
  {#if !loading && !error && !roots.length}<p>No accessible Task roots. Ask a workspace administrator to provision a root or grant access.</p>{/if}
  <label for="task-root">Task root</label><select id="task-root" class="rounded border p-2" disabled={loading} value={context.root?.id ?? ''} onchange={(event) => { context.root = roots.find(root => root.id === event.currentTarget.value && root.can_read) ?? null; }}><option value="">Select a root</option>{#each roots as root (root.id)}<option value={root.id} disabled={!root.can_read}>{root.id}{root.can_write ? ' · write' : ' · read'}</option>{/each}</select>
  {#if more}<Button disabled={loading} onclick={() => load(true)}>Load more roots</Button>{/if}
  {#if context.root}<p role="status">Selected root: {context.root.id}</p><!-- Root-specific state is destroyed when the selected authority changes. -->{/if}
</section>

{#if context.root && context.workspace}{#key `${context.workspace.id}:${context.root.id}`}<TaskPanel workspaceId={context.workspace.id} rootId={context.root.id} canWrite={context.root.can_write} canManage={context.root.can_manage} />{/key}{/if}
