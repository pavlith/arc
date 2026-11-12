<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { arc, commandKey, errorMessage } from '$lib/api/arc';
  import type { NotifyInbox, NotifyChange, NotifySubscription, NotifyPage } from '@arc/client';
  import { Button } from '$lib/components/ui/button';
  const controller = new AbortController(); const options = { signal: controller.signal };
  let notifications = $state<NotifyInbox['notifications']>([]); let subscriptions = $state<NotifySubscription[]>([]);
  let tab = $state<NonNullable<NotifyPage['tab']>>('all'); let cursor = $state<string | undefined>();
  let subscriptionCursor = $state<string | undefined>(); let unread = $state(0); let busy = $state(false); let error = $state('');
  let key = commandKey();
  async function run(work: () => Promise<void>) {
    if (busy) return; busy = true; error = '';
    try { await work(); key = commandKey(); } catch (cause) { if (!controller.signal.aborted) { error = errorMessage(cause); notifications = []; subscriptions = []; unread = 0; } }
    finally { if (!controller.signal.aborted) busy = false; }
  }
  async function load(append = false) {
    const result = await arc.notify.inbox.list({ limit: 50, tab, ...(append && cursor ? { cursor } : {}) }, options);
    notifications = append ? [...notifications, ...result.notifications] : result.notifications; cursor = result.next_cursor; unread = result.unread_count;
  }
  async function loadSubscriptions(append = false) {
    const result = await arc.notify.subscriptions.list({ limit: 50, ...(append && subscriptionCursor ? { cursor: subscriptionCursor } : {}) }, options);
    subscriptions = append ? [...subscriptions, ...result.subscriptions] : result.subscriptions; subscriptionCursor = result.next_cursor;
  }
  async function change(item: NotifyInbox['notifications'][number], action: NotifyChange['action']) {
    await run(async () => {
      const input = { id: item.id, revision: item.revision, action, ...(action === 'snooze' ? { until: new Date(Date.now() + 3600000).toISOString() } : {}) };
      await arc.notify.inbox.update(input, { ...key(input), ...options }); await load();
    });
  }
  onMount(() => { void run(() => load()); }); onDestroy(() => controller.abort());
</script>
<svelte:head><title>Inbox · Arc</title></svelte:head>
<section class="grid gap-5"><h2 class="text-xl font-semibold">Your Inbox</h2><p>Unread: {unread}</p>
  {#if error}<p role="alert">{error} Reload before retrying.</p>{/if}
  <label for="inbox-tab">Inbox filter</label><select id="inbox-tab" bind:value={tab} disabled={busy} onchange={() => run(() => load())}><option value="all">All</option><option value="unread">Unread</option><option value="archived">Archived</option><option value="snoozed">Snoozed</option></select>
  <Button disabled={busy} onclick={() => run(() => load())}>Reload Inbox</Button>
  <Button disabled={busy} onclick={() => run(async () => { await arc.notify.inbox.markAllRead({}, { ...key({}), ...options }); await load(); })}>Mark all read</Button>
  {#if busy}<p role="status">Loading…</p>{/if}
  {#if !busy && !error && !notifications.length}<p>Your Inbox is empty.</p>{/if}
  <ul class="grid gap-4">{#each notifications as item (item.id)}<li class="flex flex-wrap items-center gap-3"><span>{item.kind} · {item.created_at}</span><Button variant="outline" disabled={busy} onclick={() => change(item, item.read_at ? 'unread' : 'read')}>{item.read_at ? 'Mark unread' : 'Mark read'}</Button><Button variant="outline" disabled={busy} onclick={() => change(item, item.archived_at ? 'unarchive' : 'archive')}>{item.archived_at ? 'Unarchive' : 'Archive'}</Button><Button variant="outline" disabled={busy} onclick={() => change(item, item.snoozed_until ? 'unsnooze' : 'snooze')}>{item.snoozed_until ? 'Unsnooze' : 'Snooze for one hour'}</Button></li>{/each}</ul>
  {#if cursor}<Button disabled={busy} onclick={() => run(() => load(true))}>Load more notifications</Button>{/if}
  <h3 class="text-lg font-semibold">Subscriptions</h3><Button disabled={busy} onclick={() => run(() => loadSubscriptions())}>Load subscriptions</Button>
  <ul>{#each subscriptions as subscription}<li>{subscription.resource_kind} · {subscription.acl_root_id} · {subscription.active ? 'Active' : 'Inactive'}<Button disabled={busy || !subscription.active} onclick={() => run(async () => { const input = { workspace_id: subscription.workspace_id, acl_root_id: subscription.acl_root_id, resource_kind: subscription.resource_kind }; await arc.notify.subscriptions.unsubscribe(input, { ...key(input), ...options }); await loadSubscriptions(); })}>Unsubscribe</Button></li>{/each}</ul>
  {#if subscriptionCursor}<Button disabled={busy} onclick={() => run(() => loadSubscriptions(true))}>Load more subscriptions</Button>{/if}
</section>
