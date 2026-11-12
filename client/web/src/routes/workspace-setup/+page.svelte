<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { arc, commandKey, errorMessage } from '$lib/api/arc';
  import { authState } from '$lib/features/auth/auth.state.svelte';
  import { Button } from '$lib/components/ui/button';
  import { Input } from '$lib/components/ui/input';
  const scope = new AbortController();
  let name = $state(''); let slug = $state(''); let error = $state(''); let busy = $state(false); let ready = $state(false);
  const key = commandKey();
  async function initialize() {
    error = ''; await authState.init(false, scope.signal);
    if (scope.signal.aborted) return;
      if (authState.error) { error = authState.error; return; }
    if (!authState.user) { await goto('/login'); return; } ready = true;
  }
  async function create(event: SubmitEvent) {
    event.preventDefault(); if (busy) return;
    busy = true; error = '';
    try {
      const input = { name: name.trim(), ...(slug.trim() ? { slug: slug.trim() } : {}) };
      const workspace = await arc.identity.workspaces.create(input, { ...key(input), signal: scope.signal });
      await goto(`/${encodeURIComponent(workspace.slug)}`);
    } catch (cause) { error = errorMessage(cause); } finally { busy = false; }
  }
  onMount(() => { void initialize(); return () => scope.abort(); });
</script>
<svelte:head><title>Create workspace · Arc</title></svelte:head>
<main class="mx-auto grid max-w-lg gap-5 p-8"><h1 class="text-2xl font-semibold">Create a workspace</h1>
  {#if error}<p role="alert">{error}</p>{#if !ready}<Button onclick={initialize}>Retry</Button>{/if}{/if}
  {#if ready}<form onsubmit={create} class="grid gap-3"><label for="workspace-name">Name</label><Input id="workspace-name" bind:value={name} required /><label for="workspace-slug">Slug (optional)</label><Input id="workspace-slug" bind:value={slug} /><Button type="submit" disabled={busy}>Create workspace</Button></form>{/if}
  <a class="underline" href="/">Back to workspaces</a>
</main>
