<script lang="ts">
	import '../app.css';
	import { Toaster } from 'svelte-sonner';
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { setCurrentWorkspace } from '$lib/features/workspaces/current-workspace.svelte';
	import { preferencesState } from '$lib/features/preferences/preferences.state.svelte';
	import { registerServiceWorker } from '$lib/features/pwa/register-service-worker';
	import { lockInstalledAppZoom } from '$lib/features/pwa/installed-viewport';
	import { m, getLocale, setLocale } from '$lib/features/i18n/messages';
	import { remoteImages } from '$lib/components/shared/remote-images.action';

	let { children } = $props();
	setCurrentWorkspace();
	const supported = $derived(!!page.params.workspaceSlug || ['/', '/login', '/workspace-setup', '/forgot-password', '/reset-password'].includes(page.url.pathname) || page.url.pathname.startsWith('/invite/'));

	onMount(() => {
		preferencesState.init();
		registerServiceWorker();
		return lockInstalledAppZoom();
	});
</script>

<!-- Remote images in user content wait for the reader, on every page. -->
<svelte:body use:remoteImages />

<Toaster position="bottom-right" theme={preferencesState.resolvedMode} />
{#if supported}
{@render children()}
{:else}
<main class="mx-auto grid max-w-xl gap-4 p-8"><h1>This page is not available in Arc yet</h1><a href="/">Back to workspaces</a></main>
{/if}
