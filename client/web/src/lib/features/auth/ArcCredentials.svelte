<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { goto } from '$app/navigation';
  import { arc, errorMessage } from '$lib/api/arc';
  import { login } from '$lib/api/auth';
  import { authState } from './auth.state.svelte';
  import { Button } from '$lib/components/ui/button';
  import { Input } from '$lib/components/ui/input';
  import { Password } from '$lib/components/ui/password';

  let { initialMode = 'login' }: { initialMode?: 'login' | 'register' | 'recover' } = $props();
  const scope = new AbortController();
  let mode = $state(untrack(() => initialMode));
  let email = $state(''); let password = $state(''); let name = $state('');
  let token = $state(''); let recovery = $state(''); let oneTimeCode = $state('');
  let saved = $state(false); let busy = $state(false); let error = $state('');
  onMount(() => {
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const invitation = fragment.get('invite');
    if (invitation) {
      token = invitation; mode = 'register';
      // Keep the invitation out of history entries, referrers and future navigation.
      history.replaceState(history.state, '', window.location.pathname + window.location.search);
    }
    return () => { scope.abort(); token = ''; password = ''; recovery = ''; oneTimeCode = ''; };
  });
  function switchMode(next: typeof mode) {
    mode = next; password = ''; recovery = ''; error = '';
  }
  async function submit(event: SubmitEvent) {
    event.preventDefault(); if (busy) return;
    busy = true; error = '';
    try {
      if (mode === 'login') {
        const user = await login({ email: email.trim(), password }, { signal: scope.signal });
        if (scope.signal.aborted) return;
        password = ''; authState.setUser(user); await goto('/');
      } else if (mode === 'register') {
        const result = await arc.auth.registerInvited({ email: email.trim(), password, name: name.trim(), token: token.trim() }, { signal: scope.signal });
        password = ''; token = ''; oneTimeCode = result.recovery_code; saved = false;
      } else {
        const result = await arc.auth.recover({ email: email.trim(), code: recovery.trim(), password }, { signal: scope.signal });
        password = ''; recovery = ''; authState.clear(); oneTimeCode = result.code; saved = false;
      }
    } catch (cause) {
      if (scope.signal.aborted) return;
      error = errorMessage(cause);
      if (mode === 'register') error += ' If a previous registration response was lost, try signing in before retrying.';
    } finally { busy = false; }
  }
</script>

<svelte:head><title>{mode === 'login' ? 'Sign in' : mode === 'register' ? 'Accept invitation' : 'Recover account'} · Arc</title><meta name="referrer" content="no-referrer" /></svelte:head>
<div class="mx-auto flex min-h-screen max-w-md flex-col justify-center gap-6 p-8">
  <a href="/" class="text-2xl font-semibold">Arc</a>
  {#if oneTimeCode}
    <h1 class="text-xl font-semibold">Save your recovery code</h1>
    <p>This code is shown once. Store it privately before continuing. You will sign in separately.</p>
    <output aria-label="Recovery code" class="break-all rounded border p-4 font-mono select-all">{oneTimeCode}</output>
    <label class="flex items-center gap-2"><input type="checkbox" bind:checked={saved} /> I saved my recovery code</label>
    <Button disabled={!saved} onclick={() => { oneTimeCode = ''; switchMode('login'); }}>Continue to sign in</Button>
  {:else}
    <h1 class="text-xl font-semibold">{mode === 'login' ? 'Sign in to Arc' : mode === 'register' ? 'Create an invited account' : 'Recover your account'}</h1>
    {#if mode === 'register'}<p>Registration requires an email-bound workspace invitation. Existing users sign in, then accept the invitation from Workspaces.</p>{/if}
    {#if mode === 'recover'}<p>Use your saved recovery code. Recovery replaces the code and ends existing sessions.</p>{/if}
    {#if error}<p role="alert">{error}</p>{/if}
    <form onsubmit={submit} class="grid gap-4">
      <label for="arc-email">Email</label><Input id="arc-email" type="email" bind:value={email} required autocomplete="username" />
      {#if mode === 'register'}
        <label for="arc-name">Name</label><Input id="arc-name" bind:value={name} autocomplete="name" />
        <label for="arc-invitation">Invitation token</label><Input id="arc-invitation" bind:value={token} required autocomplete="off" />
      {/if}
      {#if mode === 'recover'}<label for="arc-recovery">Recovery code</label><Input id="arc-recovery" bind:value={recovery} required autocomplete="off" />{/if}
      <label for="arc-password">{mode === 'recover' ? 'New password' : 'Password'}</label>
      <Password id="arc-password" bind:value={password} required minlength={mode === 'login' ? undefined : 12} maxlength={1024} autocomplete={mode === 'login' ? 'current-password' : 'new-password'} />
      <Button type="submit" disabled={busy}>{busy ? 'Please wait…' : mode === 'login' ? 'Sign in' : mode === 'register' ? 'Create account' : 'Recover account'}</Button>
    </form>
    <div class="flex flex-wrap gap-3">
      {#if mode !== 'login'}<Button variant="outline" disabled={busy} onclick={() => switchMode('login')}>Sign in instead</Button>{/if}
      {#if mode !== 'register'}<Button variant="outline" disabled={busy} onclick={() => switchMode('register')}>I have an invitation</Button>{/if}
      {#if mode !== 'recover'}<Button variant="outline" disabled={busy} onclick={() => switchMode('recover')}>Use a recovery code</Button>{/if}
    </div>
  {/if}
</div>
