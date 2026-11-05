import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests/browser', testMatch: '**/*.pw.ts', workers: 1, fullyParallel: false,
  forbidOnly: !!process.env.CI, retries: 0, timeout: 30000,
  outputDir: './test-results', reporter: 'list',
  use: { browserName: 'chromium', channel: process.env.PLAYWRIGHT_CHANNEL || (process.platform === 'win32' ? 'msedge' : undefined), viewport: { width: 1440, height: 1000 }, screenshot: 'only-on-failure', trace: 'off' },
});
