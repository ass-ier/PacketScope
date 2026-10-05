import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  outputDir: '../artifacts/e2e-results',
  workers: 1,
  timeout: 90000,
  use: { baseURL: 'http://127.0.0.1:8766', viewport: { width: 1440, height: 1000 }, trace: 'retain-on-failure' },
  webServer: {
    command: 'cd .. && .venv/bin/python fixtures/generate.py --output artifacts/fixtures && cd backend && PACKETSCOPE_DATA=../artifacts/e2e-data ../.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8766',
    url: 'http://127.0.0.1:8766/api/health',
    reuseExistingServer: false,
    timeout: 30000,
  },
});
