import {
  decodeProtectedHeader,
  exportJWK,
  exportPKCS8,
  generateKeyPair,
  importJWK,
  importPKCS8,
  jwtVerify,
  SignJWT,
  type JWK,
} from 'jose';
import { describe, expect, test, vi } from 'vite-plus/test';
import { registry as umaxicaRegistry } from '../src/config/registry.umaxica';
import { createApp, detectRuntime, fetchExampleJwks, type AppOptions } from '../src';
import { fetchRegistryJwks } from '../src/core/fetch_jwks';
import cloudflareWorker from '../src/cloudflare';
import { handleJump } from '../src/core/handle_jump';
import { healthJson, renderHealthHtml, wantsJson } from '../src/core/health';
import { JwksCache } from '../src/core/jwks_cache';
import { normalizeOrigin, normalizeUrl } from '../src/core/normalize_url';
import { assertDestinationPolicy } from '../src/core/policy';
import { MemoryReplayCache, NoopReplayCache } from '../src/core/replay_cache';
import { JoseOutboundSigner, NoopOutboundSigner } from '../src/core/sign_outbound';
import {
  JumpError,
  PRODUCTION_SERVICE_ORIGIN,
  type InboundJumpClaim,
  type IssuerRegistry,
} from '../src/core/types';
import { assertBase64Url, verifyJumpJwt } from '../src/core/verify_jwt';

const NOW = 1_800_000_000;

type Fixture = {
  app: ReturnType<typeof createApp>;
  signToken: (
    claim?: Partial<InboundJumpClaim>,
    header?: Record<string, unknown>,
  ) => Promise<string>;
  signRaw: (payload: Record<string, unknown>, header?: Record<string, unknown>) => Promise<string>;
  fetchCount: () => number;
  jumpPublicKey: Parameters<SignJWT['sign']>[0];
  jumpPublicJwk: JWK;
};

async function fixture(): Promise<Fixture> {
  return fixtureWithOptions();
}

async function fixtureWithOptions(options: AppOptions = {}): Promise<Fixture> {
  const issuerKeys = await generateKeyPair('ES384');
  const jumpKeys = await generateKeyPair('ES384', { extractable: true });
  const issuerJwk = await exportJWK(issuerKeys.publicKey);
  const jumpJwk = await exportJWK(jumpKeys.publicKey);
  const publicJwk: JWK = { ...issuerJwk, kid: 'kid-1', alg: 'ES384', use: 'sig' };
  const jumpPublicJwk: JWK = { ...jumpJwk, kid: 'jump-test', alg: 'ES384', use: 'sig' };
  let fetches = 0;
  const registry: IssuerRegistry = {
    'https://app.example.com': {
      iss: 'https://app.example.com',
      jwks_uri: 'https://app.example.com/.well-known/jwks.json',
      allowed_dst_internal: ['https://app.example.com', 'https://docs.example.com'],
      allowed_dst_external: ['https://example.org'],
    },
  };
  const app = createApp({
    registry,
    jwksCache: new JwksCache(async () => {
      fetches += 1;
      return { keys: [publicJwk] };
    }),
    replayCache: new NoopReplayCache(),
    runtime: { edge: 'local', production: true },
    signer: new JoseOutboundSigner(jumpKeys.privateKey, 'jump-test'),
    now: () => NOW,
    ...options,
    jumpJwks: options.jumpJwks ?? { keys: [jumpPublicJwk] },
  });
  return {
    app,
    fetchCount: () => fetches,
    signToken: (claim, header) => signToken(issuerKeys.privateKey, claim, header),
    signRaw: (payload, header) => signPayload(issuerKeys.privateKey, payload, header),
    jumpPublicKey: jumpKeys.publicKey,
    jumpPublicJwk,
  };
}

async function signToken(
  privateKey: Parameters<SignJWT['sign']>[0],
  claim: Partial<InboundJumpClaim> = {},
  header: Record<string, unknown> = {},
) {
  return signPayload(privateKey, { ...baseClaim(), ...claim }, header);
}

function baseClaim(): InboundJumpClaim {
  return {
    schema: 1,
    iss: 'https://app.example.com',
    aud: PRODUCTION_SERVICE_ORIGIN,
    sub: 'jump-redirect',
    iat: NOW,
    nbf: NOW,
    exp: NOW + 3600,
    jti: crypto.randomUUID(),
    dst: 'internal',
    url: 'https://app.example.com/path',
  };
}

async function signPayload(
  privateKey: Parameters<SignJWT['sign']>[0],
  payload: Record<string, unknown>,
  header: Record<string, unknown> = {},
) {
  return new SignJWT(payload)
    .setProtectedHeader({ typ: 'JWT', alg: 'ES384', kid: 'kid-1', ...header })
    .sign(privateKey);
}

async function jump(app: Fixture['app'], rt: string) {
  return app.request(`https://jump.example.net/?rt=${rt}`);
}

async function jumpEn(app: Fixture['app'], rt: string) {
  return app.request(`https://jump.example.net/?rt=${rt}`, {
    headers: { 'Accept-Language': 'en' },
  });
}

async function fetchCloudflareWorker(
  path: string,
  env: Parameters<typeof cloudflareWorker.fetch>[1],
) {
  return cloudflareWorker.fetch(
    new Request(`https://jump.example.net${path}`),
    env,
    {} as ExecutionContext,
  );
}

async function cloudflareInternalRedirectFixture() {
  const previousFetch = globalThis.fetch;
  const issuerKeys = await generateKeyPair('ES384');
  const jumpKeys = await generateKeyPair('ES384', { extractable: true });
  const issuerJwk = await exportJWK(issuerKeys.publicKey);
  const jumpJwk = await exportJWK(jumpKeys.publicKey);
  const issuerPublicJwk: JWK = { ...issuerJwk, kid: 'rails-kid-1', alg: 'ES384', use: 'sig' };
  const jumpPublicJwk: JWK = {
    ...jumpJwk,
    kid: 'cloudflare-active-2026-05',
    alg: 'ES384',
    use: 'sig',
  };
  globalThis.fetch = vi.fn(async () => Response.json({ keys: [issuerPublicJwk] })) as typeof fetch;
  const now = Math.floor(Date.now() / 1000);
  const inboundToken = await signPayload(
    issuerKeys.privateKey,
    {
      ...baseClaim(),
      iss: 'https://www.umaxica.app',
      aud: 'https://jump.umaxica.net',
      iat: now,
      nbf: now,
      exp: now + 3600,
      jti: crypto.randomUUID(),
      dst: 'internal',
      url: 'https://www.umaxica.app/',
    },
    { kid: 'rails-kid-1' },
  );
  return {
    inboundToken,
    jumpPrivatePem: await exportPKCS8(jumpKeys.privateKey),
    jumpPublicJwk,
    jumpPublicKey: jumpKeys.publicKey,
    restore() {
      globalThis.fetch = previousFetch;
    },
  };
}

describe('jump gateway routes', () => {
  test('default app serves local health data', async () => {
    const app = createApp();
    const res = await app.request('https://jump.example.net/health.json');
    expect(await res.json()).toMatchObject({ edge: 'local' });
    expect((await fetchExampleJwks()).keys.length).toBeGreaterThan(0);
  });

  test('umaxica production registry limits issuers and internal destinations', () => {
    expect(Object.keys(umaxicaRegistry)).toEqual([
      'https://id.umaxica.app',
      'https://id.umaxica.com',
      'https://id.umaxica.org',
      'https://www.umaxica.app',
      'https://www.umaxica.com',
      'https://www.umaxica.org',
      'https://www.jp.umaxica.app',
      'https://www.jp.umaxica.com',
      'https://www.jp.umaxica.org',
    ]);
    expect(umaxicaRegistry['https://id.umaxica.app']).toMatchObject({
      jwks_uri: 'https://id.umaxica.app/.well-known/jwks.json',
      allowed_dst_internal: ['https://id.umaxica.app', 'https://www.umaxica.app'],
      allowed_dst_external: false,
    });
    for (const issuer of Object.values(umaxicaRegistry)) {
      expect(issuer.iss).toBeTruthy();
      expect(issuer.jwks_uri).toBe(`${issuer.iss}/.well-known/jwks.json`);
      expect(issuer.allowed_dst_external).toBe(false);
      expect(issuer.revoked_kids).toEqual([]);
      for (const origin of issuer.allowed_dst_internal) {
        expect(new URL(origin).origin).toBe(origin);
      }
    }
  });

  test('registry jwks fetcher uses issuer jwks uri', async () => {
    const previousFetch = globalThis.fetch;
    const fetchMock = vi.fn(async () => Response.json({ keys: [{ kid: 'kid-1' }] }));
    globalThis.fetch = fetchMock as typeof fetch;
    try {
      const issuer = umaxicaRegistry['https://id.umaxica.app'];
      expect(issuer).toBeDefined();
      if (!issuer) throw new Error('missing test issuer');
      await expect(fetchRegistryJwks(issuer)).resolves.toEqual({
        keys: [{ kid: 'kid-1' }],
      });
      expect(fetchMock).toHaveBeenCalledWith(
        'https://id.umaxica.app/.well-known/jwks.json',
        expect.objectContaining({
          headers: { Accept: 'application/json' },
          signal: expect.any(AbortSignal),
        }),
      );
    } finally {
      globalThis.fetch = previousFetch;
    }
  });

  test('runtime detection names fastly and cloudflare explicitly', () => {
    const globalEdge = globalThis as { FASTLY_SERVICE_VERSION?: string; WebSocketPair?: unknown };
    const previousFastly = globalEdge.FASTLY_SERVICE_VERSION;
    const previousCloudflare = globalEdge.WebSocketPair;
    try {
      globalEdge.FASTLY_SERVICE_VERSION = '1';
      expect(detectRuntime().edge).toBe('fastly');
      delete globalEdge.FASTLY_SERVICE_VERSION;
      globalEdge.WebSocketPair = function WebSocketPair() {};
      expect(detectRuntime().edge).toBe('cloudflare');
    } finally {
      if (previousFastly === undefined) delete globalEdge.FASTLY_SERVICE_VERSION;
      else globalEdge.FASTLY_SERVICE_VERSION = previousFastly;
      if (previousCloudflare === undefined) delete globalEdge.WebSocketPair;
      else globalEdge.WebSocketPair = previousCloudflare;
    }
  });

  test('GET / redirects to about when rt is absent', async () => {
    const { app } = await fixture();
    const res = await app.request('https://jump.example.net/');

    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toBe('/about');
  });

  test('GET / processes invalid rt query parameters through guardrails', async () => {
    const { app } = await fixture();
    const res = await app.request('https://jump.example.net/?rt=abc.def');

    expect(res.status).toBe(400);
    expect(res.headers.get('X-Jump-Error')).toBe('malformed');
  });

  test('health JSON and HTML include runtime data', async () => {
    const { app } = await fixture();
    const json = await app.request('https://jump.example.net/health', {
      headers: { Accept: 'application/json' },
    });
    expect(await json.json()).toMatchObject({
      ok: true,
      service: 'jump',
      version: '0.1.0',
      edge: 'local',
    });
    const html = await app.request('https://jump.example.net/health.html');
    const healthHtml = await html.text();
    expect(healthHtml).toContain('<meta name="robots" content="noindex,nofollow,noarchive"/>');
    expect(healthHtml).toContain('<title>UMAXICA Jump Gateway | Health status</title>');
    expect(healthHtml).toContain('<header><a href="/">UMAXICA</a></header>');
    expect(healthHtml).toContain('<dt>ok</dt><dd>true</dd>');
    expect(healthHtml).toContain('<dt>service</dt><dd>jump</dd>');
    expect(healthHtml).toContain('<dt>version</dt><dd>0.1.0</dd>');
    expect(healthHtml).toContain('<dt>edge</dt><dd>local</dd>');
    expect(healthHtml).toContain('<dt>time</dt><dd>');
    expect(healthHtml).toContain('<footer>© 2026 UMAXICA</footer>');
    expect(html.headers.get('Content-Language')).toBe('ja');
  });

  test('html routes default to ja and support en via Accept-Language', async () => {
    const { app } = await fixture();
    const ja = await app.request('https://jump.example.net/about');
    const en = await app.request('https://jump.example.net/about', {
      headers: { 'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8' },
    });
    const ignored = await app.request('https://jump.example.net/about', {
      headers: { 'Accept-Language': 'fr' },
    });

    expect(ja.headers.get('Content-Language')).toBe('ja');
    const jaHtml = await ja.text();
    expect(jaHtml).toContain('<title>UMAXICA Jump Gateway | About</title>');
    expect(jaHtml).toContain('<header><a href="/">UMAXICA</a></header>');
    expect(jaHtml).toContain('<footer>© 2026 UMAXICA</footer>');
    expect(en.headers.get('Content-Language')).toBe('en');
    expect(await en.text()).toContain('<html lang="en">');
    expect(ignored.headers.get('Content-Language')).toBe('ja');
  });

  test('health helpers cover accept parsing', () => {
    expect(wantsJson(null)).toBe(false);
    expect(wantsJson('text/html, application/json')).toBe(true);
    expect(healthJson({ edge: 'local', production: false }, new Date(0))).toMatchObject({
      time: '1970-01-01T00:00:00.000Z',
    });
  });

  test('robots.txt is restrictive', async () => {
    const { app } = await fixture();
    expect(await (await app.request('https://jump.example.net/robots.txt')).text()).toBe(
      'User-agent: *\nDisallow: /\nAllow: /about\nSitemap: https://jump.example.net/sitemap.xml\n',
    );
  });

  test('sitemap.xml lists public routes', async () => {
    const { app } = await fixture();
    const res = await app.request('https://jump.example.net/sitemap.xml');
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toBe('application/xml; charset=utf-8');
    expect(await res.text()).toBe(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://jump.example.net/about</loc>
  </url>
</urlset>
`);
  });

  test('favicon.ico is an explicit empty response', async () => {
    const { app } = await fixture();
    const res = await app.request('https://jump.example.net/favicon.ico');
    expect(res.status).toBe(204);
    expect(await res.text()).toBe('');
  });

  test('cloudflare worker serves robots without importing private key', async () => {
    const res = await fetchCloudflareWorker('/robots.txt', {
      UMAXICA_JUMP_PRIVATE_KEY_PEM: 'not a pkcs8 key',
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(
      'User-agent: *\nDisallow: /\nAllow: /about\nSitemap: https://jump.example.net/sitemap.xml\n',
    );
  });

  test('cloudflare worker serves sitemap without importing private key', async () => {
    const res = await fetchCloudflareWorker('/sitemap.xml', {
      UMAXICA_JUMP_PRIVATE_KEY_PEM: 'not a pkcs8 key',
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toBe('application/xml; charset=utf-8');
    expect(await res.text()).toContain('<loc>https://jump.example.net/about</loc>');
  });

  test('cloudflare worker serves favicon without importing private key', async () => {
    const res = await fetchCloudflareWorker('/favicon.ico', {
      UMAXICA_JUMP_PRIVATE_KEY_PEM: 'not a pkcs8 key',
    });
    expect(res.status).toBe(204);
    expect(await res.text()).toBe('');
  });

  test('cloudflare worker serves health without importing private key', async () => {
    const res = await fetchCloudflareWorker('/health.json', {
      UMAXICA_JUMP_PRIVATE_KEY_PEM: 'not a pkcs8 key',
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, edge: 'cloudflare', version: null });
  });

  test('cloudflare worker uses configured production origin for about output', async () => {
    const res = await fetchCloudflareWorker('/about', {});

    expect(res.status).toBe(200);
    expect(await res.text()).toContain('https://jump.umaxica.net');
  });

  test('cloudflare worker serves configured Jump public jwks binding', async () => {
    const { jumpPublicJwk } = await fixture();
    const res = await fetchCloudflareWorker('/.well-known/jwks.json', {
      UMAXICA_JUMP_PUBLIC_JWKS: JSON.stringify({ keys: [jumpPublicJwk] }),
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ keys: [jumpPublicJwk] });
  });

  test('cloudflare worker derives Jump public jwks from private key secret', async () => {
    const setup = await cloudflareInternalRedirectFixture();
    try {
      const res = await fetchCloudflareWorker('/.well-known/jwks.json', {
        UMAXICA_JUMP_PRIVATE_KEY_PEM: setup.jumpPrivatePem,
        UMAXICA_JUMP_PRIVATE_KEY_KID: 'cloudflare-active-2026-05',
      });

      expect(res.status).toBe(200);
      const jwks = (await res.json()) as { keys: JWK[] };
      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys[0]).toMatchObject({
        kid: 'cloudflare-active-2026-05',
        kty: 'EC',
        crv: 'P-384',
        alg: 'ES384',
        use: 'sig',
      });
      expect(jwks.keys[0]).not.toHaveProperty('d');

      const privateKey = await importPKCS8(setup.jumpPrivatePem, 'ES384');
      const token = await new SignJWT({ ok: true })
        .setProtectedHeader({ typ: 'JWT', alg: 'ES384', kid: 'cloudflare-active-2026-05' })
        .sign(privateKey);
      await expect(
        jwtVerify(token, await importJWK(jwks.keys[0] ?? {}, 'ES384'), {
          algorithms: ['ES384'],
          typ: 'JWT',
        }),
      ).resolves.toBeTruthy();
    } finally {
      setup.restore();
    }
  });

  test('cloudflare worker reports signer_unavailable when private key import fails', async () => {
    const setup = await cloudflareInternalRedirectFixture();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const res = await fetchCloudflareWorker(`/?rt=${setup.inboundToken}`, {
        UMAXICA_JUMP_PRIVATE_KEY_PEM: 'not a pkcs8 key',
        UMAXICA_JUMP_PRIVATE_KEY_KID: 'cloudflare-active-2026-05',
        UMAXICA_JUMP_PUBLIC_JWKS: JSON.stringify({ keys: [setup.jumpPublicJwk] }),
      });

      expect(res.status).toBe(503);
      expect(res.headers.get('X-Jump-Error')).toBe('signer_unavailable');
      expect(warn.mock.calls.map(([message]) => String(message)).join('\n')).toContain(
        'pkcs8_import_failed',
      );
      expect(warn.mock.calls.map(([message]) => String(message)).join('\n')).toContain(
        '"private_key_present":true',
      );
      expect(warn.mock.calls.map(([message]) => String(message)).join('\n')).not.toContain(
        'not a pkcs8 key',
      );
    } finally {
      setup.restore();
      warn.mockRestore();
    }
  });

  test('cloudflare worker reports signer_unavailable when private key is missing', async () => {
    const setup = await cloudflareInternalRedirectFixture();
    try {
      const res = await fetchCloudflareWorker(`/?rt=${setup.inboundToken}`, {
        UMAXICA_JUMP_PRIVATE_KEY_KID: 'cloudflare-active-2026-05',
        UMAXICA_JUMP_PUBLIC_JWKS: JSON.stringify({ keys: [setup.jumpPublicJwk] }),
      });

      expect(res.status).toBe(503);
      expect(res.headers.get('X-Jump-Error')).toBe('signer_unavailable');
    } finally {
      setup.restore();
    }
  });

  test('cloudflare worker signs internal redirect rt with configured kid', async () => {
    const setup = await cloudflareInternalRedirectFixture();
    const info = vi.spyOn(console, 'info').mockImplementation(() => {});
    try {
      const res = await fetchCloudflareWorker(`/?rt=${setup.inboundToken}`, {
        UMAXICA_JUMP_PRIVATE_KEY_PEM: `  ${setup.jumpPrivatePem.replaceAll('\n', '\\n')}  `,
        UMAXICA_JUMP_PRIVATE_KEY_KID: ' cloudflare-active-2026-05 ',
      });

      expect(res.status).toBe(302);
      const location = res.headers.get('Location');
      expect(location).toBeTruthy();
      const returnedRt = new URL(location ?? '').searchParams.get('rt');
      expect(returnedRt).toBeTruthy();
      expect(decodeProtectedHeader(returnedRt ?? '').kid).toBe('cloudflare-active-2026-05');
      const verified = await jwtVerify(returnedRt ?? '', setup.jumpPublicKey, {
        issuer: 'https://jump.umaxica.net',
        audience: 'https://www.umaxica.app',
        algorithms: ['ES384'],
        typ: 'JWT',
        currentDate: new Date(),
      });
      expect(verified.payload).toMatchObject({
        schema: 1,
        iss: 'https://jump.umaxica.net',
        aud: 'https://www.umaxica.app',
        sub: 'jump-redirect',
        src: 'https://www.umaxica.app',
        dst: 'internal',
        url: 'https://www.umaxica.app/',
      });
      const infoLines = info.mock.calls.map(([message]) => String(message)).join('\n');
      expect(infoLines).toContain('"signer_configured":true');
      expect(infoLines).toContain('"signer_kid":"cloudflare-active-2026-05"');
      expect(infoLines).toContain('"private_key_imported":true');
      expect(infoLines).toContain('"jwks_derived_from_private_key":true');
    } finally {
      setup.restore();
      info.mockRestore();
    }
  });

  test('cloudflare worker live rails acme app handshake contract stays stable', async () => {
    const setup = await cloudflareInternalRedirectFixture();
    try {
      const env = {
        UMAXICA_JUMP_PRIVATE_KEY_PEM: setup.jumpPrivatePem,
        UMAXICA_JUMP_PRIVATE_KEY_KID: 'cloudflare-active-2026-05',
      };
      const res = await fetchCloudflareWorker(`/?rt=${setup.inboundToken}`, env);

      expect(res.status).toBe(302);
      expect(res.headers.get('X-Jump-Error')).toBeNull();
      const location = res.headers.get('Location');
      expect(location).toBeTruthy();
      const locationUrl = new URL(location ?? '');
      expect(locationUrl.origin).toBe('https://www.umaxica.app');
      expect(locationUrl.pathname).toBe('/');
      expect(locationUrl.searchParams.getAll('rt')).toHaveLength(1);
      expect(locationUrl.searchParams.has('jump_rt')).toBe(false);
      expect(locationUrl.searchParams.has('jump_probe')).toBe(false);

      const returnedRt = locationUrl.searchParams.get('rt') ?? '';
      expect(decodeProtectedHeader(returnedRt)).toEqual({
        typ: 'JWT',
        alg: 'ES384',
        kid: 'cloudflare-active-2026-05',
      });

      const jwksRes = await fetchCloudflareWorker('/.well-known/jwks.json', env);
      expect(jwksRes.status).toBe(200);
      const jwks = (await jwksRes.json()) as { keys: JWK[] };
      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys[0]).toMatchObject({
        kid: 'cloudflare-active-2026-05',
        kty: 'EC',
        crv: 'P-384',
        alg: 'ES384',
        use: 'sig',
      });
      expect(jwks.keys[0]).not.toHaveProperty('d');

      const verified = await jwtVerify(returnedRt, await importJWK(jwks.keys[0] ?? {}, 'ES384'), {
        issuer: 'https://jump.umaxica.net',
        audience: 'https://www.umaxica.app',
        algorithms: ['ES384'],
        typ: 'JWT',
        currentDate: new Date(),
      });
      locationUrl.searchParams.delete('rt');
      expect(locationUrl.href).toBe('https://www.umaxica.app/');
      expect(verified.payload).toMatchObject({
        schema: 1,
        iss: 'https://jump.umaxica.net',
        aud: 'https://www.umaxica.app',
        sub: 'jump-redirect',
        src: 'https://www.umaxica.app',
        dst: 'internal',
        url: locationUrl.href,
      });
    } finally {
      setup.restore();
    }
  });

  test('cloudflare worker accepts quoted escaped PKCS8 private key secret', async () => {
    const setup = await cloudflareInternalRedirectFixture();
    try {
      const quotedEscapedPem = JSON.stringify(setup.jumpPrivatePem.replaceAll('\n', '\\n'));
      const res = await fetchCloudflareWorker(`/?rt=${setup.inboundToken}`, {
        UMAXICA_JUMP_PRIVATE_KEY_PEM: quotedEscapedPem,
        UMAXICA_JUMP_PRIVATE_KEY_KID: 'cloudflare-active-2026-05',
        UMAXICA_JUMP_PUBLIC_JWKS: JSON.stringify({ keys: [setup.jumpPublicJwk] }),
      });

      expect(res.status).toBe(302);
      const location = res.headers.get('Location');
      const returnedRt = new URL(location ?? '').searchParams.get('rt');
      expect(decodeProtectedHeader(returnedRt ?? '').kid).toBe('cloudflare-active-2026-05');
    } finally {
      setup.restore();
    }
  });

  test('cloudflare worker reports version metadata id as health version', async () => {
    const res = await fetchCloudflareWorker('/health.json', {
      'UMAXICA-APPS-EDGE-JUMP-VERSION': {
        id: 'cloudflare-revision-123',
        tag: 'deploy-tag',
        timestamp: '2026-05-27T00:00:00.000Z',
      },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({
      ok: true,
      edge: 'cloudflare',
      version: 'cloudflare-revision-123',
    });
  });

  test('renderHealthHtml escapes html metacharacters in runtime fields', () => {
    const html = renderHealthHtml({
      edge: '<edge>' as 'local',
      production: true,
      version: `"><script>alert(1)</script>`,
    });
    expect(html).toContain('<dd>&lt;edge&gt;</dd>');
    expect(html).toContain('<dd>&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;</dd>');
    expect(html).not.toContain('<script>alert(1)</script>');
  });

  test('renderHealthHtml renders null version as empty string', () => {
    const html = renderHealthHtml({ edge: 'cloudflare', production: true, version: null });
    expect(html).toContain('<dt>version</dt><dd></dd>');
  });

  test('security headers are applied to static and well-known responses', async () => {
    const { app } = await fixture();
    for (const path of [
      '/about',
      '/health',
      '/health.html',
      '/health.json',
      '/favicon.ico',
      '/robots.txt',
      '/sitemap.xml',
      '/.well-known/jwks.json',
    ]) {
      const res = await app.request(`https://jump.example.net${path}`, {
        headers: { Cookie: 'sid=1' },
      });
      expectSecurityHeaders(res);
    }
  });

  test('well-known jwks serves configured Jump public keyset', async () => {
    const { app, jumpPublicJwk } = await fixture();
    const res = await app.request('https://jump.example.net/.well-known/jwks.json');

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ keys: [jumpPublicJwk] });
  });

  test('production app refuses to publish example jwks without configured Jump public keyset', async () => {
    const app = createApp({
      runtime: { edge: 'cloudflare', production: true },
    });
    const res = await app.request('https://jump.umaxica.net/.well-known/jwks.json');

    expect(res.status).toBe(503);
  });

  test('configured Jump jwks rejects private key material', async () => {
    const { jumpPublicJwk } = await fixture();

    expect(() =>
      createApp({
        runtime: { edge: 'cloudflare', production: true },
        jumpJwks: { keys: [{ ...jumpPublicJwk, d: 'private' }] },
      }),
    ).toThrow(JumpError);
  });

  test('security headers are applied to invalid token and cushion responses', async () => {
    const { app, signToken } = await fixture();
    const invalid = await jump(app, 'abc.def');
    expectSecurityHeaders(invalid);
    const invalidHtml = await invalid.text();
    expect(invalidHtml).toContain('<header><a href="/">UMAXICA</a></header>');
    expect(invalidHtml).toContain('<footer>© 2026 UMAXICA</footer>');
    const cushion = await jump(
      app,
      await signToken({ dst: 'external', url: 'https://example.org/a?b=1' }),
    );
    expectSecurityHeaders(cushion);
    const cushionHtml = await cushion.text();
    expect(cushionHtml).toContain('<header><a href="/">UMAXICA</a></header>');
    expect(cushionHtml).toContain('<footer>© 2026 UMAXICA</footer>');
  });

  test('request logs redact rt tokens', async () => {
    const { app } = await fixture();
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    let lines: string[] = [];
    try {
      await app.request('https://jump.example.net/?rt=header.payload.signature&x=1');
      lines = log.mock.calls.map(([message]) => String(message));
    } finally {
      log.mockRestore();
    }
    expect(lines.some((line) => line.includes('header.payload.signature'))).toBe(false);
    expect(lines.some((line) => line.includes('rt=[redacted]'))).toBe(true);
  });

  test('signer unavailable maps to 503 for internal redirects', async () => {
    const issuerKeys = await generateKeyPair('ES384');
    const jwk = await exportJWK(issuerKeys.publicKey);
    const noSigner = createApp({
      registry: {
        'https://app.example.com': {
          iss: 'https://app.example.com',
          jwks_uri: 'https://app.example.com/.well-known/jwks.json',
          allowed_dst_internal: ['https://app.example.com'],
          allowed_dst_external: false,
        },
      },
      jwksCache: new JwksCache(async () => {
        return { keys: [{ ...jwk, kid: 'kid-1', alg: 'ES384', use: 'sig' }] };
      }),
      replayCache: new NoopReplayCache(),
      runtime: { edge: 'local', production: true },
      now: () => NOW,
    });
    const res = await noSigner.request(
      `https://jump.example.net/?rt=${await signPayload(issuerKeys.privateKey, {
        ...baseClaim(),
        dst: 'internal',
      })}`,
    );
    expect(res.status).toBe(503);
    expect(res.headers.get('X-Jump-Error')).toBe('signer_unavailable');
  });

  test('redirect responses avoid referrer, cache, and cookies', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({ dst: 'internal' }));
    expect(res.status).toBe(302);
    expect(res.headers.get('Referrer-Policy')).toBe('no-referrer');
    expect(res.headers.get('Cache-Control')).toBe('no-store');
    expect(res.headers.get('Set-Cookie')).toBeNull();
  });

  test('decision audit logs omit rt while keeping verification fields', async () => {
    const entries: unknown[] = [];
    const { app, signToken } = await fixtureWithOptions({
      auditLog: (entry) => entries.push(entry),
    });
    const token = await signToken({
      jti: 'audit-jti',
      url: 'https://app.example.com/a/path?secret=value#frag',
    });
    const res = await jump(app, token);

    expect(res.status).toBe(302);
    expect(entries).toEqual([
      {
        level: 'info',
        event: 'jump_accept',
        result: 'accepted',
        iss: 'https://app.example.com',
        kid: 'kid-1',
        jti: 'audit-jti',
        dst: 'internal',
        dst_origin: 'https://app.example.com',
        dst_path: '/a/path',
      },
    ]);
    expect(JSON.stringify(entries)).not.toContain(token);
    expect(JSON.stringify(entries)).not.toContain('secret=value');
  });
});

describe('jump token validation', () => {
  test('rt multiple reject', async () => {
    const { app, signToken } = await fixture();
    const token = await signToken();
    const res = await app.request(`https://jump.example.net/?rt=${token}&rt=${token}`);
    expect(res.status).toBe(400);
    expect(res.headers.get('X-Jump-Error')).toBe('malformed');
  });

  test('malformed reject', async () => {
    const { app } = await fixture();
    const res = await jump(app, 'abc.def');
    expect(res.status).toBe(400);
  });

  test('decision audit logs malformed rt parse failures without raw token', async () => {
    const entries: unknown[] = [];
    const { app } = await fixtureWithOptions({
      auditLog: (entry) => entries.push(entry),
    });
    const token = 'not-a-compact-jwt-with-secret-like-content';
    const res = await jump(app, token);

    expect(res.headers.get('X-Jump-Error')).toBe('malformed');
    expect(entries).toEqual([
      {
        level: 'warn',
        event: 'jump_reject',
        result: 'rejected',
        reason: 'malformed',
      },
    ]);
    expect(JSON.stringify(entries)).not.toContain(token);
  });

  test('oversized rt rejects before jwt parsing', async () => {
    const { app } = await fixture();
    const res = await jump(app, `${'a'.repeat(8193)}.b.c`);
    expect(res.status).toBe(400);
    expect(res.headers.get('X-Jump-Error')).toBe('malformed');
  });

  test('invalid base64url reject', async () => {
    const { app } = await fixture();
    const res = await jump(app, 'abc=.def.ghi');
    expect(res.headers.get('X-Jump-Error')).toBe('malformed');
  });

  test('typ mismatch reject', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({}, { typ: 'JOSE' }));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_header');
  });

  test('alg mismatch reject', async () => {
    const { app, signToken } = await fixture();
    const token = await signToken();
    const parts = token.split('.');
    const header = b64(JSON.stringify({ typ: 'JWT', alg: 'HS256', kid: 'kid-1' }));
    const res = await jump(app, [header, parts[1], parts[2]].join('.'));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_header');
  });

  test('none algorithm token rejects', async () => {
    const { app } = await fixture();
    const token = [
      b64(JSON.stringify({ typ: 'JWT', alg: 'none', kid: 'kid-1' })),
      b64(JSON.stringify(baseClaim())),
      'unsigned',
    ].join('.');

    const res = await jump(app, token);
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_header');
  });

  test('non-ES384 signed tokens reject before key lookup', async () => {
    const { app } = await fixture();
    const algorithms = [
      { alg: 'ES256', keyPair: await generateKeyPair('ES256') },
      { alg: 'RS256', keyPair: await generateKeyPair('RS256') },
    ];

    for (const { alg, keyPair } of algorithms) {
      const token = await new SignJWT(baseClaim())
        .setProtectedHeader({ typ: 'JWT', alg, kid: 'kid-1' })
        .sign(keyPair.privateKey);

      const res = await jump(app, token);
      expect(res.headers.get('X-Jump-Error')).toBe('invalid_header');
    }
  });

  test('legacy EdDSA token rejects before key lookup', async () => {
    const { app } = await fixture();
    const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const token = await new SignJWT(baseClaim())
      .setProtectedHeader({ typ: 'JWT', alg: 'EdDSA', kid: 'kid-1' })
      .sign(privateKey);

    const res = await jump(app, token);
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_header');
  });

  test('jku reject', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({}, { jku: 'https://evil.example/jwks.json' }));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_header');
  });

  test('crit, jwk, and x5u headers reject', async () => {
    const { app, signToken } = await fixture();
    const token = await signToken();
    expect(
      (
        await jump(
          app,
          replaceHeader(token, { typ: 'JWT', alg: 'ES384', kid: 'kid-1', crit: ['exp'] }),
        )
      ).headers.get('X-Jump-Error'),
    ).toBe('invalid_header');
    expect(
      (
        await jump(app, replaceHeader(token, { typ: 'JWT', alg: 'ES384', kid: 'kid-1', jwk: {} }))
      ).headers.get('X-Jump-Error'),
    ).toBe('invalid_header');
    expect(
      (
        await jump(
          app,
          replaceHeader(token, {
            typ: 'JWT',
            alg: 'ES384',
            kid: 'kid-1',
            x5u: 'https://evil.example/cert',
          }),
        )
      ).headers.get('X-Jump-Error'),
    ).toBe('invalid_header');
  });

  test('missing kid reject', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({}, { kid: '' }));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_header');
  });

  test('iss mismatch reject', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({ iss: 'https://evil.example' }));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_claim');
  });

  test('missing unsafe issuer rejects before JWKS fetch', async () => {
    const { app, signRaw } = await fixture();
    const payload = baseClaim() as Record<string, unknown>;
    delete payload.iss;
    const res = await jump(app, await signRaw(payload));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_claim');
  });

  test('invalid payload json rejects as malformed', async () => {
    const { app, signToken } = await fixture();
    const token = await signToken();
    const parts = token.split('.');
    const res = await jump(app, [parts[0], b64('{'), parts[2]].join('.'));
    expect(res.headers.get('X-Jump-Error')).toBe('malformed');
  });

  test('exp reject', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({ exp: NOW - 61 }));
    expect(res.status).toBe(410);
    expect(res.headers.get('X-Jump-Error')).toBe('expired');
  });

  test('schema, aud, sub, and required claim validation reject invalid tokens', async () => {
    const { app, signToken } = await fixture();
    expect((await jump(app, await signToken({ schema: 2 as 1 }))).headers.get('X-Jump-Error')).toBe(
      'invalid_claim',
    );
    expect(
      (await jump(app, await signToken({ aud: 'https://other.example' }))).headers.get(
        'X-Jump-Error',
      ),
    ).toBe('invalid_claim');
    expect(
      (await jump(app, await signToken({ sub: 'other' as 'jump-redirect' }))).headers.get(
        'X-Jump-Error',
      ),
    ).toBe('invalid_claim');
    expect((await jump(app, await signToken({ jti: '' }))).headers.get('X-Jump-Error')).toBe(
      'invalid_claim',
    );
  });

  test('unknown destination claim rejects after signature verification', async () => {
    const { app, signRaw } = await fixture();
    const res = await jump(app, await signRaw({ ...baseClaim(), dst: 'other' }));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_dst');
  });

  test('nbf future and empty url reject', async () => {
    const { app, signToken } = await fixture();
    expect((await jump(app, await signToken({ nbf: NOW + 61 }))).headers.get('X-Jump-Error')).toBe(
      'invalid_claim',
    );
    expect((await jump(app, await signToken({ url: '' }))).headers.get('X-Jump-Error')).toBe(
      'invalid_url',
    );
  });

  test('iat future reject', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({ iat: NOW + 120, nbf: NOW, exp: NOW + 3600 }));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_claim');
  });

  test('ttl over max reject', async () => {
    const { app, signToken } = await fixture();
    const tooLong = 31 * 24 * 3600;
    const res = await jump(app, await signToken({ exp: NOW + tooLong }));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_claim');
  });

  test('missing required time claims reject', async () => {
    const { app, signRaw } = await fixture();
    for (const claimName of ['exp', 'nbf', 'iat']) {
      const payload = baseClaim() as Record<string, unknown>;
      delete payload[claimName];
      const res = await jump(app, await signRaw(payload));
      expect(res.headers.get('X-Jump-Error')).toBe('invalid_claim');
    }
  });

  test('invalid signature rejects after retry', async () => {
    const { app, signToken } = await fixture();
    const token = await signToken();
    const parts = token.split('.');
    const payload = b64(JSON.stringify({ ...baseClaim(), jti: 'tampered' }));
    const res = await jump(app, [parts[0], payload, parts[2]].join('.'));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_signature');
  });

  test('wrong elliptic curve key rejects for ES384', async () => {
    const { privateKey } = await generateKeyPair('ES384');
    const wrongCurveKeys = await generateKeyPair('ES256');
    const wrongCurveJwk = await exportJWK(wrongCurveKeys.publicKey);
    const registry: IssuerRegistry = {
      'https://app.example.com': {
        iss: 'https://app.example.com',
        jwks_uri: 'https://app.example.com/.well-known/jwks.json',
        allowed_dst_internal: ['https://app.example.com'],
        allowed_dst_external: false,
      },
    };
    const token = await signPayload(privateKey, baseClaim());

    await expect(
      verifyJumpJwt(
        token,
        registry,
        new JwksCache(async () => ({
          keys: [{ ...wrongCurveJwk, kid: 'kid-1', alg: 'ES384', use: 'sig' }],
        })),
        new NoopReplayCache(),
        NOW,
      ),
    ).rejects.toMatchObject({ code: 'invalid_signature' });
  });

  test('signature verification retries against refreshed JWKS', async () => {
    const staleKeys = await generateKeyPair('ES384');
    const freshKeys = await generateKeyPair('ES384');
    const staleJwk = await exportJWK(staleKeys.publicKey);
    const freshJwk = await exportJWK(freshKeys.publicKey);
    let fetches = 0;
    const registry: IssuerRegistry = {
      'https://app.example.com': {
        iss: 'https://app.example.com',
        jwks_uri: 'https://app.example.com/.well-known/jwks.json',
        allowed_dst_internal: ['https://app.example.com'],
        allowed_dst_external: false,
      },
    };
    const claim = baseClaim();
    const token = await signPayload(freshKeys.privateKey, claim);
    const verified = await verifyJumpJwt(
      token,
      registry,
      new JwksCache(async () => {
        fetches += 1;
        return {
          keys: [
            {
              ...(fetches === 1 ? staleJwk : freshJwk),
              kid: 'kid-1',
              alg: 'ES384',
              use: 'sig',
            },
          ],
        };
      }),
      new NoopReplayCache(),
      NOW,
    );
    expect(verified.claim.jti).toBe(claim.jti);
    expect(fetches).toBe(2);
  });

  test('skew handling permits recently expired token', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({ iat: NOW - 3600, nbf: NOW - 60, exp: NOW - 30 }));
    expect(res.status).toBe(302);
  });

  test('dst policy rejects unlisted internal origin', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({ url: 'https://other.example/path' }));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_dst');
  });

  test('decision audit logs rejected token metadata without full jwt', async () => {
    const entries: unknown[] = [];
    const { app, signToken } = await fixtureWithOptions({
      auditLog: (entry) => entries.push(entry),
    });
    const token = await signToken({ jti: 'reject-jti', url: 'https://other.example/path?q=1' });
    const res = await jump(app, token);

    expect(res.headers.get('X-Jump-Error')).toBe('invalid_dst');
    expect(entries).toEqual([
      {
        level: 'warn',
        event: 'jump_reject',
        result: 'rejected',
        reason: 'invalid_dst',
        iss: 'https://app.example.com',
        kid: 'kid-1',
        jti: 'reject-jti',
        dst: 'internal',
        dst_origin: 'https://other.example',
        dst_path: '/path',
      },
    ]);
    expect(JSON.stringify(entries)).not.toContain(token);
    expect(JSON.stringify(entries)).not.toContain('q=1');
  });

  test('self-link reject', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({ url: `${PRODUCTION_SERVICE_ORIGIN}/about` }));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_url');
  });

  test('forbidden protocols reject', async () => {
    const { app, signToken } = await fixture();
    for (const url of [
      'javascript:alert(1)',
      'data:text/html,x',
      'file:///etc/passwd',
      'blob:https://app.example.com/abc',
    ]) {
      const res = await jump(app, await signToken({ url }));
      expect(res.headers.get('X-Jump-Error')).toBe('invalid_url');
    }
  });

  test('non-production http is normalized by the URL parser', () => {
    const normalized = normalizeUrl('http://EXAMPLE.com.:80/a', {
      edge: 'local',
      production: false,
    });
    expect(normalized).toMatchObject({
      href: 'http://example.com/a',
      origin: 'http://example.com',
      hostname: 'example.com',
      hasNonAsciiHostname: false,
    });
  });

  test('public IP and public IPv6 hosts are allowed through URL normalization', () => {
    expect(
      normalizeUrl('https://192.0.2.1/path', {
        edge: 'local',
        production: true,
      }).hostname,
    ).toBe('192.0.2.1');
    expect(
      normalizeUrl('https://[2001:db8::1]/path', {
        edge: 'local',
        production: true,
      }).hostname,
    ).toBe('[2001:db8::1]');
  });

  test('localhost and additional private IPv4 ranges reject', () => {
    for (const url of [
      'https://localhost/path',
      'https://foo.localhost/path',
      'https://10.0.0.1/path',
      'https://172.16.0.1/path',
      'https://0.0.0.0/path',
    ]) {
      expect(() => normalizeUrl(url, { edge: 'local', production: true })).toThrow(JumpError);
    }
  });

  test('normalizeOrigin requires origin-only allowlist entries', () => {
    expect(() =>
      normalizeOrigin('https://example.com/path', {
        edge: 'local',
        production: true,
      }),
    ).toThrow(JumpError);
  });

  test('userinfo reject', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({ url: 'https://user:pass@app.example.com/path' }));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_url');
  });

  test('production http reject', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({ url: 'http://app.example.com/path' }));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_url');
  });

  test('private IP reject', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({ url: 'https://192.168.0.10/path' }));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_url');
  });

  test('metadata IP reject', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({ url: 'https://169.254.169.254/latest' }));
    expect(res.headers.get('X-Jump-Error')).toBe('invalid_url');
  });

  test('IPv6 loopback, link-local, ULA, and mapped metadata reject', async () => {
    const { app, signToken } = await fixture();
    for (const url of [
      'https://[::1]/path',
      'https://[fe80::1]/path',
      'https://[fc00::1]/path',
      'https://[::ffff:127.0.0.1]/path',
      'https://[::ffff:169.254.169.254]/latest',
      'https://[::]/path',
    ]) {
      const res = await jump(app, await signToken({ url }));
      expect(res.headers.get('X-Jump-Error')).toBe('invalid_url');
    }
  });

  test('malformed IPv6 rejected when runtime parser accepts bracket form', () => {
    for (const url of ['https://[::1::2]/', 'https://[2001:db8::1::2]/']) {
      expect(() => normalizeUrl(url, { edge: 'local', production: true })).toThrow(JumpError);
    }
  });

  test('IPv6 IPv4-compatible and 6to4 with private embedded IPv4 reject', async () => {
    const { app, signToken } = await fixture();
    for (const url of [
      'https://[::10.0.0.1]/path',
      'https://[::192.168.1.1]/path',
      'https://[::169.254.169.254]/latest',
      'https://[2002:0a00:0001::]/path',
      'https://[2002:c0a8:0101::]/path',
      'https://[2002:a9fe:a9fe::]/latest',
    ]) {
      const res = await jump(app, await signToken({ url }));
      expect(res.headers.get('X-Jump-Error')).toBe('invalid_url');
    }
  });

  test('integer and shortened IPv4 forms reject after URL parser normalization', async () => {
    const { app, signToken } = await fixture();
    for (const url of [
      'https://2130706433/path',
      'https://127.1/path',
      'https://127.0.1/path',
      'https://0177.0.0.1/path',
    ]) {
      const parsed = new URL(url);
      expect(parsed.hostname).toBe('127.0.0.1');
      const res = await jump(app, await signToken({ url }));
      expect(res.headers.get('X-Jump-Error')).toBe('invalid_url');
    }
  });

  test('origin policy treats equivalent host spellings and default ports as the same origin', async () => {
    const { app, signToken } = await fixture();
    for (const url of [
      'https://APP.example.com/path',
      'https://app.example.com./path',
      'https://app.example.com:443/path',
    ]) {
      const res = await jump(app, await signToken({ url }));
      expect(res.status).toBe(302);
    }
  });

  test('non-default ports reject unless explicitly allowlisted', async () => {
    const { app, signToken } = await fixture();
    const rejected = await jump(app, await signToken({ url: 'https://app.example.com:444/path' }));
    expect(rejected.headers.get('X-Jump-Error')).toBe('invalid_dst');

    const issuerKeys = await generateKeyPair('ES384');
    const jumpKeys = await generateKeyPair('ES384');
    const jwk = await exportJWK(issuerKeys.publicKey);
    const registry: IssuerRegistry = {
      'https://app.example.com': {
        iss: 'https://app.example.com',
        jwks_uri: 'https://app.example.com/.well-known/jwks.json',
        allowed_dst_internal: ['https://app.example.com:444'],
        allowed_dst_external: false,
      },
    };
    const explicitApp = createApp({
      registry,
      jwksCache: new JwksCache(async () => ({
        keys: [{ ...jwk, kid: 'kid-1', alg: 'ES384', use: 'sig' }],
      })),
      replayCache: new NoopReplayCache(),
      runtime: { edge: 'local', production: true },
      signer: new JoseOutboundSigner(jumpKeys.privateKey, 'jump-test'),
      now: () => NOW,
    });
    const allowed = await jump(
      explicitApp,
      await signPayload(issuerKeys.privateKey, {
        ...baseClaim(),
        url: 'https://app.example.com:444/path',
      }),
    );
    expect(allowed.status).toBe(302);
  });

  test('external cushion renders continue URL and replaceState', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(
      app,
      await signToken({ dst: 'external', url: 'https://example.org/a?b=1' }),
    );
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(html).toContain('history.replaceState');
    expect(html).toContain('href="https://example.org/a?b=1"');
    expect(html).toContain('rel="noopener noreferrer"');
  });

  test('umaxica issuer renders external cushion only when external origin is allowlisted', async () => {
    const issuerKeys = await generateKeyPair('ES384');
    const jumpKeys = await generateKeyPair('ES384');
    const jwk = await exportJWK(issuerKeys.publicKey);
    const umaxicaIssuer = umaxicaRegistry['https://id.umaxica.app'];
    if (!umaxicaIssuer) throw new Error('missing Umaxica test issuer');
    const registry: IssuerRegistry = {
      ...umaxicaRegistry,
      'https://id.umaxica.app': {
        ...umaxicaIssuer,
        allowed_dst_external: ['https://example.com'],
      },
    };
    const app = createApp({
      registry,
      jwksCache: new JwksCache(async () => ({
        keys: [{ ...jwk, kid: 'kid-1', alg: 'ES384', use: 'sig' }],
      })),
      replayCache: new NoopReplayCache(),
      runtime: { edge: 'local', production: true },
      signer: new JoseOutboundSigner(jumpKeys.privateKey, 'jump-test'),
      now: () => NOW,
    });
    const token = await signPayload(issuerKeys.privateKey, {
      ...baseClaim(),
      iss: 'https://id.umaxica.app',
      dst: 'external',
      url: 'https://example.com/jump/end?ok=1',
    });

    const res = await jumpEn(app, token);
    const html = await res.text();

    expect(res.status).toBe(200);
    expect(html).toContain('Continue to external site');
    expect(html).toContain('href="https://example.com/jump/end?ok=1"');
    expect(html).toContain('<dt>host</dt><dd>example.com</dd>');
  });

  test('external cushion truncates long displayed URLs while preserving href', async () => {
    const registry: IssuerRegistry = {
      'https://app.example.com': {
        iss: 'https://app.example.com',
        jwks_uri: 'https://app.example.com/.well-known/jwks.json',
        allowed_dst_internal: ['https://app.example.com'],
        allowed_dst_external: true,
      },
    };
    const issuerKeys = await generateKeyPair('ES384');
    const jumpKeys = await generateKeyPair('ES384');
    const jwk = await exportJWK(issuerKeys.publicKey);
    const app = createApp({
      registry,
      jwksCache: new JwksCache(async () => ({
        keys: [{ ...jwk, kid: 'kid-1', alg: 'ES384', use: 'sig' }],
      })),
      replayCache: new NoopReplayCache(),
      runtime: { edge: 'local', production: true },
      signer: new JoseOutboundSigner(jumpKeys.privateKey, 'jump-test'),
      now: () => NOW,
    });
    const longUrl = `https://example.org/${'a'.repeat(220)}`;
    const token = await signPayload(issuerKeys.privateKey, {
      ...baseClaim(),
      dst: 'external',
      url: longUrl,
    });
    const html = await (await jump(app, token)).text();
    expect(html).toContain(`href="${longUrl}"`);
    expect(html).toContain('...');
  });

  test('cushion shows non-ASCII warning when hostname is punycode', async () => {
    const registry: IssuerRegistry = {
      'https://app.example.com': {
        iss: 'https://app.example.com',
        jwks_uri: 'https://app.example.com/.well-known/jwks.json',
        allowed_dst_internal: ['https://app.example.com'],
        allowed_dst_external: true,
      },
    };
    const issuerKeys = await generateKeyPair('ES384');
    const jumpKeys = await generateKeyPair('ES384');
    const jwk = await exportJWK(issuerKeys.publicKey);
    const app = createApp({
      registry,
      jwksCache: new JwksCache(async () => ({
        keys: [{ ...jwk, kid: 'kid-1', alg: 'ES384', use: 'sig' }],
      })),
      replayCache: new NoopReplayCache(),
      runtime: { edge: 'local', production: true },
      signer: new JoseOutboundSigner(jumpKeys.privateKey, 'jump-test'),
      now: () => NOW,
    });
    const token = await signToken(issuerKeys.privateKey, {
      dst: 'external',
      url: 'https://xn--r8jz45g.example/path',
    });
    const res = await jump(app, token);
    const html = await res.text();
    expect(html).toContain('非 ASCII');
  });

  test('internal redirect carries outbound rt signed by jump', async () => {
    const { app, signToken, jumpPublicKey } = await fixture();
    const res = await jump(app, await signToken({ dst: 'internal' }));
    expect(res.status).toBe(302);
    const location = res.headers.get('Location');
    expect(location).toBeTruthy();
    const url = new URL(location ?? '');
    const rt = url.searchParams.get('rt');
    expect(rt).toBeTruthy();
    const verified = await jwtVerify(rt ?? '', jumpPublicKey, {
      issuer: PRODUCTION_SERVICE_ORIGIN,
      audience: 'https://app.example.com',
      algorithms: ['ES384'],
      typ: 'JWT',
      currentDate: new Date(NOW * 1000),
    });
    expect(verified.payload).toMatchObject({
      schema: 1,
      iss: PRODUCTION_SERVICE_ORIGIN,
      aud: 'https://app.example.com',
      sub: 'jump-redirect',
      dst: 'internal',
      src: 'https://app.example.com',
      url: 'https://app.example.com/path',
    });
  });

  test('production service origin accepts umaxica audience without example origin', async () => {
    const { app, signToken } = await fixtureWithOptions({
      config: { serviceOrigin: 'https://jump.umaxica.net' },
    });
    const res = await app.request(
      `https://jump.umaxica.net/?rt=${await signToken({
        aud: 'https://jump.umaxica.net',
        dst: 'internal',
      })}`,
    );

    expect(res.status).toBe(302);
  });

  test('production internal redirect return rt verifies against Jump JWKS', async () => {
    const { app, signToken } = await fixtureWithOptions({
      config: { serviceOrigin: 'https://jump.umaxica.net' },
    });
    const inbound = await signToken({
      aud: 'https://jump.umaxica.net',
      dst: 'internal',
      url: 'https://app.example.com/return',
    });

    const res = await app.request(`https://jump.umaxica.net/?rt=${inbound}`);
    expect(res.status).toBe(302);
    const location = res.headers.get('Location');
    const returnedRt = new URL(location ?? '').searchParams.get('rt');
    expect(returnedRt).toBeTruthy();

    const jwksRes = await app.request('https://jump.umaxica.net/.well-known/jwks.json');
    const jwks = (await jwksRes.json()) as { keys: JWK[] };
    const jumpKey = jwks.keys.find((key) => key.kid === 'jump-test');
    expect(jumpKey).toBeTruthy();
    const verified = await jwtVerify(returnedRt ?? '', await importJWK(jumpKey ?? {}, 'ES384'), {
      issuer: 'https://jump.umaxica.net',
      audience: 'https://app.example.com',
      algorithms: ['ES384'],
      typ: 'JWT',
      currentDate: new Date(NOW * 1000),
    });
    expect(verified.protectedHeader.kid).toBe('jump-test');
    expect(verified.payload).toMatchObject({
      schema: 1,
      iss: 'https://jump.umaxica.net',
      aud: 'https://app.example.com',
      sub: 'jump-redirect',
      dst: 'internal',
      src: 'https://app.example.com',
      url: 'https://app.example.com/return',
    });
  });

  test('app passes random jti and outbound ttl options into internal redirects', async () => {
    const { app, signToken, jumpPublicKey } = await fixtureWithOptions({
      randomJti: () => 'fixed-outbound-jti',
      outboundTtl: 7,
    });
    const res = await jump(app, await signToken({ dst: 'internal' }));
    const location = res.headers.get('Location');
    const rt = new URL(location ?? '').searchParams.get('rt');
    const verified = await jwtVerify(rt ?? '', jumpPublicKey, {
      issuer: PRODUCTION_SERVICE_ORIGIN,
      audience: 'https://app.example.com',
      algorithms: ['ES384'],
      typ: 'JWT',
      currentDate: new Date(NOW * 1000),
    });
    expect(verified.payload).toMatchObject({
      jti: 'fixed-outbound-jti',
      exp: NOW + 7,
    });
  });

  test('JWKS cache avoids repeated fetch and negative cache rejects missing kid', async () => {
    const { app, signToken, fetchCount } = await fixture();
    expect((await jump(app, await signToken({ jti: 'a' }))).status).toBe(302);
    expect((await jump(app, await signToken({ jti: 'b' }))).status).toBe(302);
    expect(fetchCount()).toBe(1);
    const missing = await signToken({ jti: 'c' }, { kid: 'missing' });
    expect((await jump(app, missing)).headers.get('X-Jump-Error')).toBe('invalid_signature');
  });

  test('replay cache rejects repeated jti when enabled', async () => {
    const issuerKeys = await generateKeyPair('ES384');
    const jumpKeys = await generateKeyPair('ES384');
    const jwk = await exportJWK(issuerKeys.publicKey);
    const registry: IssuerRegistry = {
      'https://app.example.com': {
        iss: 'https://app.example.com',
        jwks_uri: 'https://app.example.com/.well-known/jwks.json',
        allowed_dst_internal: ['https://app.example.com'],
        allowed_dst_external: false,
      },
    };
    const app = createApp({
      registry,
      jwksCache: new JwksCache(async () => ({
        keys: [{ ...jwk, kid: 'kid-1', alg: 'ES384', use: 'sig' }],
      })),
      replayCache: new MemoryReplayCache(),
      signer: new JoseOutboundSigner(jumpKeys.privateKey, 'jump-test'),
      runtime: { edge: 'local', production: true },
      now: () => NOW,
    });
    const token = await signToken(issuerKeys.privateKey, { jti: 'same-jti' });
    expect((await jump(app, token)).status).toBe(302);
    const replay = await jump(app, token);
    expect(replay.headers.get('X-Jump-Error')).toBe('replay');
  });

  test('direct policy helpers reject disabled external and unknown destinations', () => {
    const target = normalizeUrl('https://app.example.com/path', {
      edge: 'local',
      production: true,
    });
    const issuer = {
      iss: 'https://app.example.com',
      jwks_uri: 'https://app.example.com/.well-known/jwks.json',
      allowed_dst_internal: ['https://app.example.com'],
      allowed_dst_external: false,
    };
    const externalClaim: InboundJumpClaim = { ...baseClaim(), dst: 'external' };
    const unknownClaim: InboundJumpClaim = { ...baseClaim(), dst: 'other' as 'internal' };
    expect(() => assertDestinationPolicy(externalClaim, issuer, target)).toThrow(JumpError);
    expect(() => assertDestinationPolicy(unknownClaim, issuer, target)).toThrow(JumpError);
  });

  test('handleJump uses current time and default outbound ttl when deps omit optional hooks', async () => {
    const issuerKeys = await generateKeyPair('ES384');
    const jumpKeys = await generateKeyPair('ES384');
    const jwk = await exportJWK(issuerKeys.publicKey);
    const now = Math.floor(Date.now() / 1000);
    const token = await signPayload(issuerKeys.privateKey, {
      ...baseClaim(),
      iat: now,
      nbf: now,
      exp: now + 3600,
    });
    const res = await handleJump(new Request(`https://jump.example.net/?rt=${token}`), {
      registry: {
        'https://app.example.com': {
          iss: 'https://app.example.com',
          jwks_uri: 'https://app.example.com/.well-known/jwks.json',
          allowed_dst_internal: ['https://app.example.com'],
          allowed_dst_external: false,
        },
      },
      jwksCache: new JwksCache(async () => ({
        keys: [{ ...jwk, kid: 'kid-1', alg: 'ES384', use: 'sig' }],
      })),
      replayCache: new NoopReplayCache(),
      runtime: { edge: 'local', production: true },
      signer: new JoseOutboundSigner(jumpKeys.privateKey, 'jump-test'),
    });
    expect(res.status).toBe(302);
  });

  test('app route can validate tokens without a test clock override', async () => {
    const issuerKeys = await generateKeyPair('ES384');
    const jumpKeys = await generateKeyPair('ES384');
    const jwk = await exportJWK(issuerKeys.publicKey);
    const now = Math.floor(Date.now() / 1000);
    const app = createApp({
      registry: {
        'https://app.example.com': {
          iss: 'https://app.example.com',
          jwks_uri: 'https://app.example.com/.well-known/jwks.json',
          allowed_dst_internal: ['https://app.example.com'],
          allowed_dst_external: false,
        },
      },
      jwksCache: new JwksCache(async () => ({
        keys: [{ ...jwk, kid: 'kid-1', alg: 'ES384', use: 'sig' }],
      })),
      replayCache: new NoopReplayCache(),
      runtime: { edge: 'local', production: true },
      signer: new JoseOutboundSigner(jumpKeys.privateKey, 'jump-test'),
    });
    const token = await signPayload(issuerKeys.privateKey, {
      ...baseClaim(),
      iat: now,
      nbf: now,
      exp: now + 3600,
    });
    expect((await jump(app, token)).status).toBe(302);
  });

  test('base64url assertion rejects empty and reserved characters', () => {
    for (const value of ['', 'abc=', 'abc+def', 'abc/def', 'abc.def']) {
      expect(() => assertBase64Url(value)).toThrow(JumpError);
    }
    expect(() => assertBase64Url('abc_def-123')).not.toThrow();
  });

  test('replay cache garbage collects expired entries', async () => {
    const cache = new MemoryReplayCache();
    await cache.checkAndStore('iss', 'jti', 10, 1, 0);
    await cache.checkAndStore('iss', 'jti', 20, 11, 0);
  });

  test('jwks cache rejects revoked and negative cached kids', async () => {
    const { signToken } = await fixture();
    const issuerKeys = await generateKeyPair('ES384');
    const jwk = await exportJWK(issuerKeys.publicKey);
    const issuer = {
      iss: 'https://app.example.com',
      jwks_uri: 'https://app.example.com/.well-known/jwks.json',
      allowed_dst_internal: ['https://app.example.com'],
      allowed_dst_external: false,
      revoked_kids: ['revoked'],
    };
    const cache = new JwksCache(async () => ({
      keys: [{ ...jwk, kid: 'kid-1', alg: 'ES384', use: 'sig' }],
    }));

    await expect(cache.getKey(issuer, 'revoked', 'ES384')).rejects.toThrow(JumpError);
    await expect(cache.getKey(issuer, 'missing', 'ES384')).rejects.toThrow(JumpError);
    await expect(cache.getKey(issuer, 'missing', 'ES384')).rejects.toThrow(JumpError);
    expect(await signToken()).toBeTruthy();
  });

  test('noop outbound signer fails closed', async () => {
    await expect(new NoopOutboundSigner().sign()).rejects.toThrow('outbound signer not configured');
  });

  test('PKCS8 PEM can create JoseOutboundSigner', async () => {
    const keys = await generateKeyPair('ES384', { extractable: true });
    const privateKey = await importPKCS8(await exportPKCS8(keys.privateKey), 'ES384');
    const signer = new JoseOutboundSigner(privateKey, 'cloudflare-active-2026-05');
    const token = await signer.sign({
      schema: 1,
      iss: 'https://jump.umaxica.net',
      aud: 'https://www.umaxica.app',
      sub: 'jump-redirect',
      iat: NOW,
      nbf: NOW,
      exp: NOW + 60,
      jti: 'pkcs8-signer-test',
      src: 'https://www.umaxica.app',
      dst: 'internal',
      url: 'https://www.umaxica.app/',
    });

    expect(decodeProtectedHeader(token)).toMatchObject({
      typ: 'JWT',
      alg: 'ES384',
      kid: 'cloudflare-active-2026-05',
    });
  });
});

function b64(value: string) {
  return btoa(value).replaceAll('=', '').replaceAll('+', '-').replaceAll('/', '_');
}

function replaceHeader(token: string, header: Record<string, unknown>) {
  const parts = token.split('.');
  return [b64(JSON.stringify(header)), parts[1], parts[2]].join('.');
}

function expectSecurityHeaders(res: Response) {
  expect(res.headers.get('Content-Security-Policy')).toContain("default-src 'none'");
  expect(res.headers.get('Content-Security-Policy')).toContain(
    "'sha256-8A+3er73YJf04rRHGhbZwZQACPiiipi9EPduIeAAIDk='",
  );
  expect(res.headers.get('Content-Security-Policy')).not.toContain("'unsafe-inline'");
  expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
  expect(res.headers.get('X-Frame-Options')).toBe('DENY');
  expect(res.headers.get('Cross-Origin-Embedder-Policy')).toBe('require-corp');
  expect(res.headers.get('Cross-Origin-Opener-Policy')).toBe('same-origin');
  expect(res.headers.get('Cross-Origin-Resource-Policy')).toBe('same-origin');
  expect(res.headers.get('Referrer-Policy')).toBe('no-referrer');
  expect(res.headers.get('Permissions-Policy')).toBeTruthy();
  expect(res.headers.get('Cache-Control')).toBe('no-store');
  expect(res.headers.get('X-Robots-Tag')).toBe('noindex, nofollow, noarchive');
  expect(res.headers.get('Strict-Transport-Security')).toContain('max-age=63072000');
  expect(res.headers.get('Set-Cookie')).toBeNull();
}
