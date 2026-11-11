export * from './transport.js';
export * from './identity.js';
export * from './auth.js';
export * from './task.generated.js';
export * from './notify.generated.js';
export type { TaskTask as Task, TaskTasks as TaskList, TaskList as TaskListRequest, TaskWork as WorkItem } from './task.generated.js';

import { createTransport, type ClientOptions } from './transport.js';
import { createAuthAPI } from './auth.js';
import { createIdentityAPI } from './identity.js';
import { createTaskAPI } from './task.generated.js';
import { createNotifyAPI } from './notify.generated.js';

export function createClient(options?: ClientOptions) {
  const transport = createTransport(options);
  return { auth: createAuthAPI(transport), identity: createIdentityAPI(transport), task: createTaskAPI(transport), notify: createNotifyAPI(transport) };
}
