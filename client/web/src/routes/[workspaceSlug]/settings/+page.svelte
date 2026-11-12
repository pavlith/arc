<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { goto } from '$app/navigation';
  import { arc, APIError, commandKey, errorMessage } from '$lib/api/arc';
  import { authState } from '$lib/features/auth/auth.state.svelte';
  import { useArcWorkspace } from '$lib/features/workspaces/arc-workspace.svelte';
  import type { SelfProfile, AccountSession, Member, Group, Profile, InvitationDetails, WorkspaceRole } from '@arc/client';
  import { Button } from '$lib/components/ui/button';
  import { Input } from '$lib/components/ui/input';
  import { Password } from '$lib/components/ui/password';
  const context = useArcWorkspace();
  const scope = new AbortController();
  const readOptions = { signal: scope.signal };
  const keyFor = new Map<string, ReturnType<typeof commandKey>>();
  let usedKeys = new Set<string>();
  let passwordKey = crypto.randomUUID();
  function options(action: string, input: unknown) {
    usedKeys.add(action);
    if (!keyFor.has(action)) keyFor.set(action, commandKey());
    return { ...keyFor.get(action)!(input), ...readOptions };
  }
  const admin = $derived(context.workspace?.role === 'owner' || context.workspace?.role === 'admin');
  let error = $state(''); let notice = $state(''); let busy = $state(false);
  let profile = $state<SelfProfile | null>(null); let name = $state(''); let displayName = $state('');
  let sessions = $state<AccountSession[]>([]); let currentSession = $state('');
  let password = $state(''); let nextPassword = $state('');
  let members = $state<Member[]>([]); let groups = $state<Group[]>([]); let groupMembers = $state<Profile[]>([]);
  let invitations = $state<InvitationDetails[]>([]); let group = $state(''); let groupName = $state(''); let principal = $state('');
  let inviteEmail = $state(''); let inviteRole = $state<'member' | 'guest'>('member'); let inviteURL = $state('');
  let workspaceName = $state(context.workspace?.name ?? ''); let workspaceSlug = $state(context.workspace?.slug ?? '');
  let confirmWorkspace = $state(false);
  let more = $state({ members: false, groups: false, invitations: false, groupMembers: false, sessions: false });
  const workspaceID = () => context.workspace!.id;
  async function run(work: () => Promise<void>, message = '') {
    if (busy) return; busy = true; error = ''; notice = ''; usedKeys = new Set();
    try { await work(); if (!scope.signal.aborted) { notice = message; for (const key of usedKeys) keyFor.delete(key); } }
    catch (cause) {
      if (scope.signal.aborted) return;
      error = errorMessage(cause);
      if (cause instanceof APIError && cause.status === 401) { authState.clear(); await goto('/login'); }
      if (cause instanceof APIError && (cause.status === 403 || cause.status === 404)) {
        members = []; groups = []; invitations = []; groupMembers = []; group = ''; inviteURL = ''; invitationToken = '';
      }
    } finally { if (!scope.signal.aborted) busy = false; }
  }
  async function loadProfile() {
    const result = await arc.identity.profile(readOptions);
    if (scope.signal.aborted) return;
    profile = result; name = result.name; displayName = result.display_name; authState.setUser(result);
  }
  async function loadMembers(append = false) {
    const next = await arc.identity.members.list({ workspace_id: workspaceID(), ...(append && members.length ? { after: members.at(-1)!.id } : {}) }, readOptions);
    members = append ? [...members, ...next] : next; more.members = next.length === 100;
  }
  async function loadGroups(append = false) {
    const next = await arc.identity.groups.list({ workspace_id: workspaceID(), ...(append && groups.length ? { after: groups.at(-1)!.id } : {}) }, readOptions);
    groups = append ? [...groups, ...next] : next; more.groups = next.length === 100;
  }
  async function loadInvitations(append = false) {
    const next = await arc.identity.invitations.list({ workspace_id: workspaceID(), ...(append && invitations.length ? { after: invitations.at(-1)!.id } : {}) }, readOptions);
    invitations = append ? [...invitations, ...next] : next; more.invitations = next.length === 100;
  }
  async function loadGroupMembers(append = false) {
    if (!group) { groupMembers = []; return; }
    const next = await arc.identity.groups.members.list({ workspace_id: workspaceID(), group_id: group, ...(append && groupMembers.length ? { after: groupMembers.at(-1)!.id } : {}) }, readOptions);
    groupMembers = append ? [...groupMembers, ...next] : next; more.groupMembers = next.length === 100;
  }
  async function loadSessions(append = false) {
    const [session, next] = await Promise.all([arc.auth.session(readOptions), arc.identity.account.sessions.list({ ...(append && sessions.length ? { after: sessions.at(-1)!.id } : {}) }, readOptions)]);
    currentSession = session.id; sessions = append ? [...sessions, ...next] : next; more.sessions = next.length === 100;
  }
  async function saveProfile(event: SubmitEvent) {
    event.preventDefault(); if (!profile) return;
    const input = { name: name.trim(), display_name: displayName.trim(), revision: profile.revision };
    await run(async () => { await arc.identity.account.profile.update(input, options('profile', input)); await loadProfile(); }, 'Profile saved.');
  }
  async function changePassword(event: SubmitEvent) {
    event.preventDefault(); const input = { current_password: password, new_password: nextPassword };
    await run(async () => {
      // Passwords are never retained by the idempotency helper.
      await arc.identity.account.password.change(input, { key: passwordKey, ...readOptions });
      password = ''; nextPassword = ''; passwordKey = crypto.randomUUID();
    }, 'Password changed.');
  }
  async function setRole(member: Member, role: WorkspaceRole) {
    const input = { workspace_id: workspaceID(), user_id: member.id, role };
    await run(async () => { await arc.identity.members.set(input, options(`role:${member.id}`, input)); await loadMembers(); }, 'Membership updated.');
  }
  async function removeMember(member: Member) {
    const input = { workspace_id: workspaceID(), user_id: member.id };
    await run(async () => { await arc.identity.members.remove(input, options(`member:${member.id}`, input)); await loadMembers(); }, 'Member removed.');
  }
  async function saveGroup(event: SubmitEvent) {
    event.preventDefault();
    const input = { workspace_id: workspaceID(), name: groupName.trim(), ...(group ? { group_id: group } : {}) };
    await run(async () => {
      if (group) await arc.identity.groups.update({ ...input, group_id: group }, options('group-update', input));
      else await arc.identity.groups.create(input, options('group-create', input));
      groupName = ''; await loadGroups();
    }, 'Group saved.');
  }
  async function deleteGroup() {
    const input = { workspace_id: workspaceID(), group_id: group };
    await run(async () => { await arc.identity.groups.delete(input, options('group-delete', input)); group = ''; groupMembers = []; await loadGroups(); }, 'Group deleted.');
  }
  async function groupMembership(remove = false, userId = principal.trim()) {
    const input = { workspace_id: workspaceID(), group_id: group, user_id: userId };
    await run(async () => {
      if (remove) await arc.identity.groups.members.remove(input, options(`group-remove:${userId}`, input));
      else await arc.identity.groups.members.add(input, options(`group-add:${userId}`, input));
      principal = ''; await loadGroupMembers();
    }, 'Group membership updated.');
  }
  let invitationToken = '';
  async function createInvitation(event: SubmitEvent) {
    event.preventDefault();
    if (!invitationToken) invitationToken = Array.from(crypto.getRandomValues(new Uint8Array(32)), value => value.toString(16).padStart(2, '0')).join('');
    const input = { workspace_id: workspaceID(), email: inviteEmail.trim(), role: inviteRole, token: invitationToken };
    await run(async () => {
      await arc.identity.invitations.create(input, options('invite-create', input));
      inviteURL = `${location.origin}/login#invite=${encodeURIComponent(invitationToken)}`;
      invitationToken = ''; inviteEmail = ''; await loadInvitations();
    }, 'Invitation created. Share the private link with the invited account only.');
  }
  async function revokeInvitation(id: string) {
    const input = { workspace_id: workspaceID(), id };
    await run(async () => { await arc.identity.invitations.revoke(input, options(`invite-revoke:${id}`, input)); await loadInvitations(); }, 'Invitation revoked.');
  }
  async function saveWorkspace(event: SubmitEvent) {
    event.preventDefault(); const workspace = context.workspace; if (!workspace) return;
    const input = { workspace_id: workspace.id, name: workspaceName.trim(), slug: workspaceSlug.trim(), revision: workspace.revision };
    await run(async () => { const result = await arc.identity.workspaces.update(input, options('workspace', input)); await goto(`/${encodeURIComponent(result.slug)}`); });
  }
  async function leaveOrArchive(archive: boolean) {
    if (!confirmWorkspace) return;
    const input = { workspace_id: workspaceID() };
    await run(async () => {
      if (archive) await arc.identity.workspaces.archive(input, options('archive', input));
      else await arc.identity.workspaces.leave(input, options('leave', input));
      await goto('/');
    });
  }
  onMount(() => { void run(loadProfile); });
  onDestroy(() => { scope.abort(); password = ''; nextPassword = ''; invitationToken = ''; inviteURL = ''; });
</script>
<svelte:head><title>Account &amp; workspace settings · Arc</title><meta name="referrer" content="no-referrer" /></svelte:head>
<div class="grid gap-8">
  <h2 class="text-xl font-semibold">Account &amp; workspace settings</h2>
  {#if error}<p role="alert">{error} Reload current data before retrying a conflict.</p>{/if}
  {#if notice}<p role="status">{notice}</p>{/if}
  <section class="grid gap-3"><h3 class="text-lg font-semibold">Your profile</h3><Button variant="outline" disabled={busy} onclick={() => run(loadProfile)}>Reload profile</Button>
    {#if profile}<p>{profile.email}</p><form onsubmit={saveProfile} class="grid gap-3"><label for="profile-name">Name</label><Input id="profile-name" bind:value={name} required /><label for="profile-display">Display name</label><Input id="profile-display" bind:value={displayName} /><Button type="submit" disabled={busy}>Save profile</Button></form>{/if}
  </section>
  <section><h3 class="text-lg font-semibold">Change password</h3><form onsubmit={changePassword} class="grid gap-3"><label for="current-password">Current password</label><Password id="current-password" bind:value={password} oninput={() => { passwordKey = crypto.randomUUID(); }} required autocomplete="current-password" /><label for="new-password">New password</label><Password id="new-password" bind:value={nextPassword} oninput={() => { passwordKey = crypto.randomUUID(); }} required autocomplete="new-password" /><Button type="submit" disabled={busy}>Change password</Button></form></section>
  <section class="grid gap-3"><h3 class="text-lg font-semibold">Sessions</h3><Button variant="outline" disabled={busy} onclick={() => run(() => loadSessions())}>Load sessions</Button><ul>{#each sessions as session (session.id)}<li class="flex flex-wrap items-center gap-3">{session.channel} · {session.expires_at} {session.id === currentSession ? '(this session)' : ''}<Button variant="outline" disabled={busy} onclick={() => run(async () => { const input = { id: session.id }; await arc.identity.account.sessions.revoke(input, options(`session:${session.id}`, input)); if (session.id === currentSession) { authState.clear(); await goto('/login'); } else await loadSessions(); })}>Revoke session</Button></li>{/each}</ul>{#if more.sessions}<Button disabled={busy} onclick={() => run(() => loadSessions(true))}>Load more sessions</Button>{/if}</section>
  <section class="grid gap-3"><h3 class="text-lg font-semibold">Members</h3><Button variant="outline" disabled={busy} onclick={() => run(() => loadMembers())}>Load members</Button><ul>{#each members as member (member.id)}<li class="flex flex-wrap items-center gap-3"><span>{member.email} · {member.role}</span>{#if admin}<label>Role for {member.email}<select class="rounded border p-2" value={member.role} disabled={busy} onchange={(event) => { void setRole(member, event.currentTarget.value as WorkspaceRole); }}><option value="owner">Owner</option><option value="admin">Admin</option><option value="member">Member</option><option value="guest">Guest</option></select></label><Button variant="outline" disabled={busy} onclick={() => removeMember(member)}>Remove member</Button>{/if}</li>{/each}</ul>{#if more.members}<Button disabled={busy} onclick={() => run(() => loadMembers(true))}>Load more members</Button>{/if}</section>
  <section class="grid gap-3"><h3 class="text-lg font-semibold">Access groups</h3><p>Access groups are separate from business Teams.</p><Button variant="outline" disabled={busy} onclick={() => run(() => loadGroups())}>Load groups</Button><label for="group">Group</label><select id="group" class="rounded border p-2" bind:value={group} disabled={busy} onchange={() => { groupMembers = []; groupName = groups.find(item => item.id === group)?.name ?? ''; void run(() => loadGroupMembers()); }}><option value="">New group</option>{#each groups as item (item.id)}<option value={item.id}>{item.name}</option>{/each}</select>{#if more.groups}<Button disabled={busy} onclick={() => run(() => loadGroups(true))}>Load more groups</Button>{/if}
    {#if admin}<form onsubmit={saveGroup} class="grid gap-3"><label for="group-name">Group name</label><Input id="group-name" bind:value={groupName} required /><Button type="submit" disabled={busy}>{group ? 'Rename group' : 'Create group'}</Button></form>{#if group}<Button variant="outline" disabled={busy} onclick={deleteGroup}>Delete group</Button><form onsubmit={(event) => { event.preventDefault(); void groupMembership(); }} class="grid gap-3"><label for="group-user">Member user ID</label><Input id="group-user" bind:value={principal} required /><Button type="submit" disabled={busy}>Add group member</Button></form>{/if}{/if}
    <ul>{#each groupMembers as member (member.id)}<li>{member.email}{#if admin}<Button variant="outline" disabled={busy} onclick={() => groupMembership(true, member.id)}>Remove from group</Button>{/if}</li>{/each}</ul>{#if more.groupMembers}<Button disabled={busy} onclick={() => run(() => loadGroupMembers(true))}>Load more group members</Button>{/if}
  </section>
  {#if admin}
    <section class="grid gap-3"><h3 class="text-lg font-semibold">Invitations</h3><Button variant="outline" disabled={busy} onclick={() => run(() => loadInvitations())}>Load invitations</Button><form onsubmit={createInvitation} class="grid gap-3"><label for="invite-email">Invited email</label><Input id="invite-email" type="email" bind:value={inviteEmail} required /><label for="invite-role">Invitation role</label><select id="invite-role" class="rounded border p-2" bind:value={inviteRole}><option value="member">Member</option><option value="guest">Guest</option></select><Button type="submit" disabled={busy}>Create invitation</Button></form>
      {#if inviteURL}<label for="private-invite">Private invitation link</label><Input id="private-invite" readonly value={inviteURL} /><Button variant="outline" onclick={() => { inviteURL = ''; }}>Hide invitation link</Button>{/if}
      <ul>{#each invitations as invitation (invitation.id)}<li>{invitation.email} · {invitation.role} · {invitation.status}{#if invitation.status === 'pending'}<Button variant="outline" disabled={busy} onclick={() => revokeInvitation(invitation.id)}>Revoke invitation</Button>{/if}</li>{/each}</ul>{#if more.invitations}<Button disabled={busy} onclick={() => run(() => loadInvitations(true))}>Load more invitations</Button>{/if}
    </section>
    <section class="grid gap-3"><h3 class="text-lg font-semibold">Workspace details</h3><form onsubmit={saveWorkspace} class="grid gap-3"><label for="workspace-name">Workspace name</label><Input id="workspace-name" bind:value={workspaceName} required /><label for="workspace-slug">Workspace slug</label><Input id="workspace-slug" bind:value={workspaceSlug} required /><Button type="submit" disabled={busy}>Save workspace</Button></form></section>
  {/if}
  <section class="grid gap-3"><h3 class="text-lg font-semibold">Workspace lifecycle</h3><p>Leaving or archiving a workspace does not transfer your personal resources.</p><label><input type="checkbox" bind:checked={confirmWorkspace} /> I confirm this workspace change</label><Button variant="outline" disabled={busy || !confirmWorkspace} onclick={() => leaveOrArchive(false)}>Leave workspace</Button>{#if context.workspace?.role === 'owner'}<Button variant="outline" disabled={busy || !confirmWorkspace} onclick={() => leaveOrArchive(true)}>Archive workspace</Button>{/if}</section>
</div>
