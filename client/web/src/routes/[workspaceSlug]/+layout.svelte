<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { goto } from '$app/navigation';
  import { arc, APIError, errorMessage } from '$lib/api/arc';
  import { authState } from '$lib/features/auth/auth.state.svelte';
  import { provideArcWorkspace } from '$lib/features/workspaces/arc-workspace.svelte';
  import { Button } from '$lib/components/ui/button';
  let { children } = $props();
  const context = provideArcWorkspace();
  const slug = $derived(page.params.workspaceSlug ?? '');
  const base = $derived(`/${encodeURIComponent(slug)}`);
  const supported = $derived([base, `${base}/settings`, `${base}/inbox`].includes(page.url.pathname.replace(/\/$/, '')));
  let loading = $state(true); let error = $state(''); let signingOut = $state(false);
  let request: AbortController | undefined;
  async function load(workspaceSlug: string) {
    request?.abort(); const current = new AbortController(); request = current;
    context.workspace = null; context.root = null; loading = true; error = '';
    try {
      const profile = await arc.identity.profile({ signal: current.signal });
      const workspace = await arc.identity.workspaces.bySlug({ slug: workspaceSlug }, { signal: current.signal });
      if (current.signal.aborted) return;
      authState.setUser(profile); context.workspace = workspace;
    } catch (cause) {
      if (current.signal.aborted) return;
      if (cause instanceof APIError && cause.status === 401) { authState.clear(); await goto('/login'); }
      else error = errorMessage(cause);
    } finally { if (!current.signal.aborted) loading = false; }
  }
  $effect(() => { const workspaceSlug = slug; page.url.pathname; void load(workspaceSlug); return () => request?.abort(); });
  onMount(() => {
    const validate = () => { if (document.visibilityState === 'visible') void load(slug); };
    window.addEventListener('pageshow', validate); window.addEventListener('focus', validate);
    return () => { window.removeEventListener('pageshow', validate); window.removeEventListener('focus', validate); };
  });
  async function logout() {
    if (signingOut) return; signingOut = true; error = '';
    try { await arc.auth.logout(); request?.abort(); context.workspace = null; context.root = null; authState.clear(); await goto('/login'); }
    catch (cause) {
      if (cause instanceof APIError && cause.status === 401) { request?.abort(); context.workspace = null; context.root = null; authState.clear(); await goto('/login'); }
      else error = errorMessage(cause);
    } finally { signingOut = false; }
  }
</script>
<div class="min-h-screen">
  <header class="flex flex-wrap items-center gap-5 border-b p-4"><a href="/" class="font-semibold">Arc</a><nav aria-label="Workspace" class="flex flex-wrap gap-4"><a href={base}>Tasks</a><a href={`${base}/inbox`}>Inbox</a><a href={`${base}/settings`}>Account &amp; workspace settings</a><a href="/">Switch workspace</a></nav><Button variant="outline" disabled={signingOut} onclick={logout}>Sign out</Button></header>
  <main class="mx-auto max-w-5xl p-6">
    {#if error}<p role="alert">{error}</p><Button onclick={() => load(slug)}>Retry</Button>{/if}
    {#if loading}<p role="status">Checking workspace access…</p>
    {:else if context.workspace}
      <h1 class="mb-6 text-2xl font-semibold">{context.workspace.name}</h1>
      {#if supported}{@render children()}{:else}<section class="grid gap-3"><h2 class="text-xl font-semibold">This section is not connected to Arc yet</h2><p>Use the workspace home and account settings while the remaining product flows are adapted.</p><a class="underline" href={base}>Back to workspace</a></section>{/if}
    {/if}
  </main>
</div>
