export * from './transport.js';
export * from './identity.js';
export * from './auth.js';
export * from './task.generated.js';
export * from './notify.generated.js';
export * from './files.generated.js';
export * from './pages.generated.js';
export type { TaskWork as WorkItem } from './task.generated.js';

import { createTransport, type ClientOptions } from './transport.js';
import { createAuthAPI } from './auth.js';
import { createIdentityAPI } from './identity.js';
import { createTaskAPI } from './task.generated.js';
import { createNotifyAPI } from './notify.generated.js';
import { createFilesAPI } from './files.generated.js';
import { createPagesAPI } from './pages.generated.js';

export function createClient(options?: ClientOptions) {
  const transport = createTransport(options);
  return { auth: createAuthAPI(transport), identity: createIdentityAPI(transport), task: createTaskAPI(transport), notify: createNotifyAPI(transport), files: createFilesAPI(transport), pages: createPagesAPI(transport) };
}
