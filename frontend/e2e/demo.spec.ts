import { test, expect } from '@playwright/test';

test('public preview exposes populated investigations without mutation actions', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  await expect(page.getByText('Read-only live demo · synthetic data', { exact: true })).toBeVisible();
  await expect(page.getByText('16 captures', { exact: true })).toBeVisible();
  await expect(page.locator('input[type=file]')).toHaveCount(0);
  const response = await page.request.get('/api/captures');
  const captures: { id: string; original_filename: string }[] = await response.json();
  const periodic = captures.find(c => c.original_filename === 'synthetic-periodic.pcapng')!;
  expect(periodic).toBeTruthy();
  await page.goto(`/#/captures/${periodic.id}/graph`);
  await page.locator('.react-flow__node').first().click();
  await expect(page.getByRole('link', { name: 'Inspect evidence', exact: true })).toBeVisible();
  const tabs = page.getByRole('navigation', { name: 'Capture investigation' });
  await tabs.getByRole('link', { name: 'Report', exact: true }).click();
  for (const format of ['PDF', 'MARKDOWN', 'JSON', 'STIX']) {
    const link = page.getByRole('link', { name: `Download ${format}`, exact: true });
    await expect(link).toBeVisible();
    expect((await page.request.get((await link.getAttribute('href'))!)).ok()).toBeTruthy();
  }
  await expect(page.getByRole('button', { name: 'Generate report', exact: true })).toHaveCount(0);
  await tabs.getByRole('link', { name: 'Files', exact: true }).click();
  await expect(page.getByRole('link', { name: 'Download untrusted evidence' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Extract safely', exact: true })).toHaveCount(0);
  const navigation = page.getByRole('navigation', { name: 'Main navigation' });
  await navigation.getByRole('link', { name: 'Cases', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'Synthetic: periodic communication review', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create case', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: /Inspect row/ }).first().click();
  await expect(page.getByRole('heading', { name: 'Example analyst assessment' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save assessment', exact: true })).toHaveCount(0);
  await navigation.getByRole('link', { name: 'Compare', exact: true }).click();
  await page.getByRole('combobox', { name: 'Baseline capture', exact: true }).selectOption(captures[0].id);
  await page.getByRole('combobox', { name: 'Comparison capture', exact: true }).selectOption(periodic.id);
  await page.getByRole('button', { name: 'Compare captures', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'findings', exact: true })).toBeVisible();
  const denied = await page.request.post('/api/cases', { data: { title: 'Public edit attempt' } });
  expect(denied.status()).toBe(403);
  await navigation.getByRole('link', { name: 'Settings', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Save rule', exact: true })).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  expect(errors).toEqual([]);
});
