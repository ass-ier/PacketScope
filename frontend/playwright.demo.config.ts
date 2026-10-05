import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  testMatch: 'demo.spec.ts',
  outputDir: '../artifacts/demo-e2e-results',
  workers: 1,
  timeout: 60000,
  use: { baseURL: 'http://127.0.0.1:8767', viewport: { width: 1440, height: 1000 }, trace: 'retain-on-failure' },
  webServer: {
    command: 'cd ../backend && PACKETSCOPE_DATA=../artifacts/demo-e2e-data PORT=8767 ../.venv/bin/python demo.py',
    url: 'http://127.0.0.1:8767/api/health',
    reuseExistingServer: false,
    timeout: 120000,
  },
});
