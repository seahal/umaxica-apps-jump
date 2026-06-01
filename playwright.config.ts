import { defineConfig, devices } from '@playwright/test';

const isCI = Boolean(process.env.CI);
const port = Number(process.env.E2E_PORT ?? 4173);
const baseURL = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: isCI,
  retries: isCI ? 2 : 0,
  ...(isCI ? { workers: 1 } : {}),
  reporter: isCI ? 'github' : 'list',
  use: {
    baseURL,
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: 'vp exec tsx e2e/server.ts',
    url: baseURL,
    reuseExistingServer: !isCI,
    timeout: 15_000,
    env: {
      E2E_PORT: String(port),
    },
  },
});
