<script lang="ts">
	import * as LucideIcons from '@lucide/svelte';
	import type { LucideIcon, LucideProps } from '@lucide/svelte';
	import { teamBrandIconNodes } from './team-brand-icons';

	let { name, ...props }: LucideProps & { name: string } = $props();
	const iconMap = LucideIcons as unknown as Record<string, LucideIcon>;
	const brandNode = $derived(Object.hasOwn(teamBrandIconNodes, name) ? teamBrandIconNodes[name] : undefined);
	const Icon = $derived(typeof iconMap[name] === 'function' ? iconMap[name] : LucideIcons.SquareUser);
</script>

{#if brandNode}
	<LucideIcons.Icon iconNode={brandNode} {...props} />
{:else}
	<Icon {...props} />
{/if}
