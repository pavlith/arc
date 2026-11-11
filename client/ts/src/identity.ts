import { type Transport, type CallOptions, type CommandOptions } from './transport.js';

export type Empty = Record<string, never>;
export type WorkspaceRole = 'owner' | 'admin' | 'member' | 'guest';
export interface Profile {
  id: string; email: string; name: string; display_name: string;
  avatar_url: string | null; revision: number;
}
export interface SelfProfile extends Profile { is_sysadmin: boolean }
export interface Workspace {
  id: string; acl_root_id: string; name: string; slug: string;
  role: WorkspaceRole; revision: number;
}
export interface Member extends Profile { role: WorkspaceRole }
export interface Group { id: string; name: string }
export interface TaskRoot { id: string; can_write: boolean; can_read: boolean; can_manage: boolean }
export interface Invitation {
  id: string; workspace_id: string; email: string; role: 'member' | 'guest'; expires_at: string;
}
export interface InvitationDetails extends Invitation {
  issuer_id: string;
  status: 'pending' | 'accepted' | 'revoked' | 'expired' | 'invalidated';
  consumed_at?: string; revoked_at?: string;
}
export interface Session { id: string; user_id: string; expires_at: string }
export interface AccountSession extends Session { created_at: string; channel: 'browser' | 'cli' | 'legacy' }
export interface ManagedUser extends Profile { status: 'active' | 'disabled'; created_at: string }
export type WorkflowCategory = 'backlog' | 'unstarted' | 'started' | 'completed' | 'cancelled';
export interface WorkflowSortOverride {
  mode: 'default' | 'active-first' | 'custom' | 'inherit'; workflow_sort_order?: WorkflowCategory[];
}
export interface PreferencesData {
  font_size: 'small' | 'default' | 'large'; pointer_cursors: boolean;
  theme_mode: 'system' | 'light' | 'dark'; light_theme: 'light' | 'rose-light' | 'blue-light';
  dark_theme: 'dark' | 'dark-gray' | 'amethyst-dark' | 'emerald-dark' | 'cyber-77' | 'blade-49' | 'pipboy';
  workflow_sort_mode: 'default' | 'active-first' | 'custom'; workflow_sort_order: WorkflowCategory[];
  team_workflow_sort_overrides: Record<string, WorkflowSortOverride>;
  recent_due_dates: string[]; issues_group_by: 'status' | 'priority' | 'assignee' | 'project' | 'none';
}
export interface AccountPreferences extends PreferencesData { revision: number }
export interface Page { after?: string }
export interface WorkspaceInput { workspace_id: string }
export interface WorkspacePage extends WorkspaceInput, Page {}
export interface GroupInput extends WorkspaceInput { group_id: string }
export interface GroupPage extends GroupInput, Page {}
export interface GroupMemberInput extends GroupInput { user_id: string }
export interface WorkspaceCreate { name: string; slug?: string }
export interface WorkspaceUpdate extends WorkspaceInput { name: string; revision: number; slug?: string }
export interface ProfileUpdate { name: string; display_name: string; revision: number; avatar_receipt?: string }
export interface UserProvision { email: string; password: string; name?: string }
export interface InvitationCreate extends WorkspaceInput { email: string; role: 'member' | 'guest'; token: string }
export interface UserPage extends Page { email?: string; status?: 'active' | 'disabled' }

/** Gate-owned Identity routes; private RPC session envelopes are never exposed. */
export function createIdentityAPI(transport: Transport) {
  const prefix = '/api/v1/arc/identity/';
  const read = <I extends object, O>(path: string) => (input: I, options?: CallOptions): Promise<O> => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(input)) if (value !== undefined) query.set(key, String(value));
    return transport.request<O>(prefix + path + (query.size ? '?' + query.toString() : ''), options);
  };
  const write = <I, O>(path: string) => (input: I, options: CommandOptions): Promise<O> => {
    if (!options?.key) throw new TypeError('An explicit idempotency key is required.');
    return transport.request<O>(prefix + path, { ...options, method: 'POST', body: input });
  };
  return {
    profile: (options?: CallOptions) => transport.request<SelfProfile>(prefix + 'profile', options),
    account: {
      profile: { update: write<ProfileUpdate, Profile>('account/profile/update') },
      preferences: {
        get: (options?: CallOptions) => transport.request<AccountPreferences>(prefix + 'account/preferences/get', options),
        update: write<{ revision: number; changes: Partial<PreferencesData> }, AccountPreferences>('account/preferences/update'),
      },
      sessions: {
        list: read<Page, AccountSession[]>('account/sessions/list'),
        revoke: write<{ id: string }, Empty>('account/sessions/revoke'),
      },
      password: { change: write<{ current_password: string; new_password: string }, Empty>('account/password/change') },
    },
    workspaces: {
      list: read<Page, Workspace[]>('workspaces/list'),
      get: read<WorkspaceInput, Workspace>('workspaces/get'),
      bySlug: read<{ slug: string }, Workspace>('workspaces/by_slug'),
      create: write<WorkspaceCreate, Workspace>('workspaces/create'),
      update: write<WorkspaceUpdate, Workspace>('workspaces/update'),
      archive: write<WorkspaceInput, Empty>('workspaces/archive'),
      leave: write<WorkspaceInput, Empty>('workspaces/leave'),
    },
    members: {
      list: read<WorkspacePage, Member[]>('members/list'),
      set: write<WorkspaceInput & { user_id: string; role: WorkspaceRole }, Empty>('members/set'),
      remove: write<WorkspaceInput & { user_id: string }, Empty>('members/remove'),
    },
    users: {
      list: read<UserPage, ManagedUser[]>('users/list'),
      provision: write<UserProvision, Profile>('users/provision'),
      status: write<{ user_id: string; status: 'active' | 'disabled' }, Empty>('users/status'),
    },
    invitations: {
      list: read<WorkspacePage, InvitationDetails[]>('invitations/list'),
      create: write<InvitationCreate, Invitation>('invitations/create'),
      revoke: write<WorkspaceInput & { id: string }, Empty>('invitations/revoke'),
      accept: write<{ token: string }, Workspace>('invitations/accept'),
    },
    groups: {
      list: read<WorkspacePage, Group[]>('groups/list'),
      create: write<WorkspaceInput & { name: string }, Group>('groups/create'),
      update: write<GroupInput & { name: string }, Group>('groups/update'),
      delete: write<GroupInput, Group>('groups/delete'),
      members: {
        list: read<GroupPage, Profile[]>('groups/members/list'),
        add: write<GroupMemberInput, Empty>('groups/members/add'),
        remove: write<GroupMemberInput, Empty>('groups/members/remove'),
      },
    },
    taskRoots: {
      list: read<WorkspacePage, TaskRoot[]>('task_roots/list'),
      managed: { list: read<WorkspacePage, TaskRoot[]>('task_roots/managed/list') },
    },
  };
}
