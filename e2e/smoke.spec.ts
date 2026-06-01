import { expect, test, type APIResponse } from '@playwright/test';

test.describe('jump gateway smoke', () => {
  test('/ returns a 200 response after the about redirect', async ({ page }) => {
    const response = await page.goto('/');

    expect(response?.status()).toBe(200);
    await expect(page).toHaveURL('/about');
    await expect(page.locator('body')).toContainText('UMAXICA');
  });

  test('invalid rt parameter does not redirect to an external URL', async ({ page }) => {
    const response = await page.goto('/?rt=https%3A%2F%2Fevil.example');

    expect(response?.status()).toBe(400);
    await expect(page).toHaveURL('/?rt=https%3A%2F%2Fevil.example');
  });

  test('/about serves the about page', async ({ page }) => {
    const response = await page.goto('/about');

    expect(response?.status()).toBe(200);
    await expect(page.locator('body')).toContainText('UMAXICA');
  });

  test('/health serves the health HTML page by default', async ({ page }) => {
    const response = await page.goto('/health');

    expect(response?.status()).toBe(200);
    await expect(page.locator('body')).toContainText('service');
    await expect(page.locator('body')).toContainText('jump');
  });

  test('/health returns JSON when requested', async ({ request }) => {
    const response = await request.get('/health', {
      headers: {
        Accept: 'application/json',
      },
    });

    expect(response.status()).toBe(200);
    expect(response.headers()['content-type']).toContain('application/json');
    expect(await response.json()).toEqual(
      expect.objectContaining({
        status: 'OK',
        service: 'jump',
        edge: 'local',
      }),
    );
  });

  test('/health.json returns health JSON', async ({ request }) => {
    const response = await request.get('/health.json');

    expect(response.status()).toBe(200);
    expect(response.headers()['content-type']).toContain('application/json');
    expect(await response.json()).toEqual(
      expect.objectContaining({
        status: 'OK',
        service: 'jump',
        edge: 'local',
      }),
    );
  });

  test('/health.html serves the health HTML page', async ({ page }) => {
    const response = await page.goto('/health.html');

    expect(response?.status()).toBe(200);
    await expect(page.locator('body')).toContainText('service');
    await expect(page.locator('body')).toContainText('jump');
  });

  test('unknown routes return 404', async ({ request }) => {
    const response = await request.get('/not-found');

    expect(response.status()).toBe(404);
  });

  test('security headers are present', async ({ request }) => {
    const response = await request.get('/about');

    expectSecurityHeaders(response);
  });
});

function expectSecurityHeaders(response: APIResponse) {
  const headers = response.headers();

  expect(headers['content-security-policy']).toContain("default-src 'none'");
  expect(headers['x-content-type-options']).toBe('nosniff');
  expect(headers['x-frame-options']).toBe('DENY');
  expect(headers['cross-origin-embedder-policy']).toBe('require-corp');
  expect(headers['cross-origin-opener-policy']).toBe('same-origin');
  expect(headers['cross-origin-resource-policy']).toBe('same-origin');
  expect(headers['referrer-policy']).toBe('no-referrer');
  expect(headers['permissions-policy']).toBeTruthy();
  expect(headers['cache-control']).toBe('no-store');
  expect(headers['x-robots-tag']).toBe('noindex, nofollow, noarchive');
  expect(headers['strict-transport-security']).toContain('max-age=63072000');
  expect(headers['set-cookie']).toBeUndefined();
}
