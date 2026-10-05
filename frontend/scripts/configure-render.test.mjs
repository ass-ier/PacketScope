import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

test('Render rewrite configurator accepts only the intended HTTPS origin and preserves security headers', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'packetscope-deploy-config-'));
  try {
    fs.mkdirSync(path.join(directory, 'scripts'));
    fs.copyFileSync(new URL('./configure-render.mjs', import.meta.url), path.join(directory, 'scripts/configure-render.mjs'));
    const filename = path.join(directory, 'vercel.json');
    fs.copyFileSync(new URL('../vercel.json', import.meta.url), filename);
    const original = JSON.parse(fs.readFileSync(filename, 'utf8'));
    const run = value => spawnSync(process.execPath, [path.join(directory, 'scripts/configure-render.mjs'), value], { encoding: 'utf8' });
    for (const value of ['http://demo.onrender.com', 'https://localhost', 'https://demo.onrender.com/api',
      'https://demo.onrender.com?secret=x', 'https://user:password@demo.onrender.com', 'not a URL']) {
      assert.equal(run(value).status, 1);
      assert.deepEqual(JSON.parse(fs.readFileSync(filename, 'utf8')), original);
    }
    assert.equal(run('https://synthetic-demo.onrender.com').status, 0);
    const configured = JSON.parse(fs.readFileSync(filename, 'utf8'));
    assert.deepEqual(configured.rewrites, [{ source: '/api/:path*', destination: 'https://synthetic-demo.onrender.com/api/:path*' }]);
    assert.deepEqual(configured.headers, original.headers);
    assert.equal(configured.framework, 'vite');
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});
