import { test, expect, type Page } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import axe from 'axe-core';

declare global {
  interface Window { axe: typeof axe }
}

const root = path.resolve('..');
const navigation = (page: Page) => page.getByRole('navigation', { name: 'Main navigation' });
const tabs = (page: Page) => page.getByRole('navigation', { name: 'Capture investigation' });

async function importCapture(page: Page, filename: string) {
  await navigation(page).getByRole('link', { name: 'Captures', exact: true }).click();
  await page.locator('input[type=file]').setInputFiles(path.join(root, 'artifacts/fixtures', filename));
  await page.getByRole('button', { name: 'Analyze capture', exact: true }).click();
  await expect(page.getByText('completed', { exact: true })).toBeVisible();
  return page.url().split('/captures/')[1].split('/')[0];
}

test('analyst workflow: PCAPNG, PCAP, evidence, case, graph, extraction and reports', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Investigation overview' })).toBeVisible();
  await page.locator('input[type=file]').setInputFiles({ name: 'invalid.pcap', mimeType: 'application/octet-stream', buffer: Buffer.from('not a capture') });
  await expect(page.getByRole('alert')).toContainText('Not a PCAP');
  const mixed = await importCapture(page, 'mixed.pcapng');
  await tabs(page).getByRole('link', { name: 'DNS', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'fixture.test', exact: true })).toBeVisible();
  await page.getByRole('button', { name: /Inspect row/ }).first().click();
  await expect(page.getByRole('heading', { name: 'answers', exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: '198.51.100.20', exact: true })).toBeVisible();
  await page.goto(`/#/captures/${mixed}/tls`);
  await page.getByRole('button', { name: /Inspect row/ }).first().click();
  await expect(page.locator('main')).toContainText('unavailable');
  const periodic = await importCapture(page, 'periodic.pcap');
  await tabs(page).getByRole('link', { name: 'Findings', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'Possible periodic communication', exact: true })).toBeVisible();
  await page.getByRole('button', { name: /Inspect row/ }).first().click();
  await expect(page.locator('main')).toContainText('coefficient_of_variation');
  await page.getByRole('button', { name: /Inspect row/ }).first().click();
  await expect(page.getByRole('heading', { name: /^Frame / })).toBeVisible();
  await page.goto(`/#/captures/${periodic}/attack`);
  await expect(page.getByRole('heading', { name: 'T1071 · Application Layer Protocol' })).toBeVisible();
  await tabs(page).getByRole('link', { name: 'Graph', exact: true }).click();
  await page.locator('.react-flow__node').first().click();
  await expect(page.getByRole('link', { name: 'Inspect evidence', exact: true })).toBeVisible();
  await navigation(page).getByRole('link', { name: 'Cases', exact: true }).click();
  const title = `Synthetic investigation ${Date.now()}`;
  await page.getByRole('textbox', { name: 'New investigation title' }).fill(title);
  await page.getByRole('button', { name: 'Create case', exact: true }).click();
  await page.getByRole('combobox', { name: 'Completed capture', exact: true }).selectOption(periodic);
  await page.getByRole('button', { name: 'Attach capture', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'periodic.pcap', exact: true })).toBeVisible();
  await page.getByRole('combobox', { name: 'Verdict', exact: true }).selectOption('Suspicious');
  await page.getByRole('textbox', { name: 'Reasoning', exact: true }).fill('Review authorized schedules. Periodicity does not prove C2.');
  await page.getByRole('button', { name: 'Save assessment', exact: true }).click();
  await expect(page.getByText('Analyst assessment saved.', { exact: true })).toBeVisible();
  await page.getByRole('textbox', { name: 'Note', exact: true }).fill('Synthetic test evidence only.');
  await page.getByRole('button', { name: 'Add note', exact: true }).click();
  await expect(page.getByText('Synthetic test evidence only.', { exact: true })).toBeVisible();
  await page.goto(`/#/captures/${periodic}/files`);
  await page.getByRole('checkbox', { name: 'I understand extracted content is untrusted evidence.' }).check();
  await page.getByRole('button', { name: 'Extract safely', exact: true }).first().click();
  await expect(page.getByRole('link', { name: 'Download untrusted evidence' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'ReverseScope hash handoff' })).toBeVisible();
  await tabs(page).getByRole('link', { name: 'Report', exact: true }).click();
  await page.getByRole('combobox', { name: 'Analyst case (must link this capture)', exact: true }).selectOption({ label: title });
  for (const format of ['pdf', 'markdown', 'json', 'stix']) {
    await page.getByRole('combobox', { name: 'Report format', exact: true }).selectOption(format);
    await page.getByRole('button', { name: 'Generate report', exact: true }).click();
    const link = page.getByRole('link', { name: `Download ${format.toUpperCase()}`, exact: true });
    await expect(link).toBeVisible();
    const href = await link.getAttribute('href');
    const response = await page.request.get(href!);
    expect(response.ok()).toBeTruthy();
    expect((await response.body()).length).toBeGreaterThan(100);
  }
  await navigation(page).getByRole('link', { name: 'Compare', exact: true }).click();
  await page.getByRole('combobox', { name: 'Baseline capture', exact: true }).selectOption(mixed);
  await page.getByRole('combobox', { name: 'Comparison capture', exact: true }).selectOption(periodic);
  await page.getByRole('button', { name: 'Compare captures', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'findings', exact: true })).toBeVisible();
  await page.getByRole('textbox', { name: 'Search all evidence', exact: true }).fill('fixture.test');
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Results for “fixture.test”' })).toBeVisible();
});

test('responsive layout, keyboard skip link and WCAG automated checks', async ({ browser }) => {
  // Only this audit context bypasses CSP so the locally installed checker can run.
  const context = await browser.newContext({ bypassCSP: true, baseURL: 'http://127.0.0.1:8766' });
  const page = await context.newPage();
  const source = await readFile(path.resolve('node_modules/axe-core/axe.min.js'), 'utf8');
  try {
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 1000 });
      await page.goto('/');
      await expect(page.getByRole('heading', { name: 'Recent findings', exact: true })).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
      await page.evaluate(source);
      const violations = await page.evaluate(async () => {
        const engine = window.axe;
        return (await engine.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa'] } })).violations;
      });
      expect(violations.map(v => ({ id: v.id, targets: v.nodes.map(n => n.target) }))).toEqual([]);
    }
    await page.goto('/?keyboard-check');
    await page.keyboard.press('Tab');
    await expect(page.getByRole('link', { name: 'Skip to investigation' })).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.locator('main')).toBeFocused();
  } finally {
    await context.close();
  }
});
