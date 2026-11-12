<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { arc, commandKey, errorMessage } from '$lib/api/arc';
  import { authState } from '$lib/features/auth/auth.state.svelte';
  import type { Workspace } from '@arc/client';
  import { Button } from '$lib/components/ui/button';
  import { Input } from '$lib/components/ui/input';
  const scope = new AbortController();
  let workspaces = $state<Workspace[]>([]); let loading = $state(true); let error = $state('');
  let token = $state(''); let accepting = $state(false); let more = $state(false);
  const acceptanceKey = commandKey();
  async function load(append = false) {
    loading = true; error = '';
    try {
      await authState.init(false, scope.signal);
      if (scope.signal.aborted) return;
      if (authState.error) { error = authState.error; return; }
      if (!authState.user) { await goto('/login'); return; }
      const next = await arc.identity.workspaces.list({ ...(append && workspaces.length ? { after: workspaces.at(-1)!.id } : {}) }, { signal: scope.signal });
      workspaces = append ? [...workspaces, ...next] : next; more = next.length === 100;
    } catch (cause) { error = errorMessage(cause); } finally { loading = false; }
  }
  async function accept(event: SubmitEvent) {
    event.preventDefault(); if (accepting) return;
    accepting = true; error = '';
    try {
      const input = { token: token.trim() };
      const workspace = await arc.identity.invitations.accept(input, { ...acceptanceKey(input), signal: scope.signal });
      token = ''; await goto(`/${encodeURIComponent(workspace.slug)}`);
    } catch (cause) { error = errorMessage(cause); } finally { accepting = false; }
  }
  onMount(() => { void load(); return () => { scope.abort(); token = ''; }; });
</script>
<svelte:head><title>Workspaces · Arc</title></svelte:head>
<main class="mx-auto grid max-w-2xl gap-6 p-8">
  <h1 class="text-2xl font-semibold">Your workspaces</h1>
  {#if error}<p role="alert">{error}</p><Button onclick={() => load()}>Retry</Button>{/if}
  {#if loading}<p role="status">Loading workspaces…</p>{/if}
  {#if authState.user}
    <p>Signed in as {authState.user.email}</p>
    <ul class="grid gap-3">{#each workspaces as workspace (workspace.id)}<li><a class="underline" href={`/${encodeURIComponent(workspace.slug)}`}>{workspace.name}</a> <span>({workspace.role})</span></li>{/each}</ul>
    {#if !loading && !error && !workspaces.length}<p>No workspaces yet. Create one or accept an invitation.</p>{/if}
    {#if more}<Button disabled={loading} onclick={() => load(true)}>Load more workspaces</Button>{/if}
    <a class="underline" href="/workspace-setup">Create a workspace</a>
    <form onsubmit={accept} class="grid gap-3"><h2 class="text-lg font-semibold">Accept an invitation</h2><label for="existing-invite">Invitation token</label><Input id="existing-invite" bind:value={token} required autocomplete="off" /><Button type="submit" disabled={accepting}>Accept invitation</Button></form>
  {/if}
</main>
