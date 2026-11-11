<script lang="ts">
  import '../app.css';

  let { children } = $props();
</script>

<svelte:head>
  <title>Arc</title>
</svelte:head>

{@render children()}
