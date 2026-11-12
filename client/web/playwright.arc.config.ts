import { defineConfig } from '@playwright/test';

// Run after the production build; this suite exercises only connected Arc flows.
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'arc-foundation.test.ts',
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 2,
  reporter: 'list',
  use: { baseURL: 'http://127.0.0.1:4174', trace: 'off', launchOptions: { executablePath: process.env.ARC_CHROMIUM_EXECUTABLE } },
  webServer: {
    command: 'npm run preview -- --host 127.0.0.1 --port 4174',
    url: 'http://127.0.0.1:4174',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
