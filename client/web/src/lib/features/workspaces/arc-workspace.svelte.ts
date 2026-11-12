import { getContext, setContext } from 'svelte';
import type { Workspace, TaskRoot } from '@arc/client';
const key = Symbol('arc-workspace');
export class ArcWorkspace {
  workspace = $state<Workspace | null>(null);
  root = $state<TaskRoot | null>(null);
}
export function provideArcWorkspace() { return setContext(key, new ArcWorkspace()); }
export function useArcWorkspace(): ArcWorkspace { return getContext(key); }
