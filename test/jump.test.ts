import { exportJWK, generateKeyPair, jwtVerify, SignJWT, type JWK } from 'jose';
import { describe, expect, test } from 'vite-plus/test';
import { createApp, detectRuntime, fetchExampleJwks } from '../src';
import cloudflareWorker from '../src/cloudflare';
import { handleJump, type JumpDeps } from '../src/core/handle_jump';
import { healthJson, wantsJson } from '../src/core/health';
import { JwksCache } from '../src/core/jwks_cache';
import { normalizeOrigin, normalizeUrl } from '../src/core/normalize_url';
import { assertDestinationPolicy } from '../src/core/policy';
import { MemoryReplayCache, NoopReplayCache } from '../src/core/replay_cache';
import { JoseOutboundSigner, NoopOutboundSigner } from '../src/core/sign_outbound';
import { JumpError, SERVICE, type InboundJumpClaim, type IssuerRegistry } from '../src/core/types';
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
};

async function fixture(): Promise<Fixture> {
  return fixtureWithOptions();
}

async function fixtureWithOptions(options: Partial<JumpDeps> = {}): Promise<Fixture> {
  const issuerKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const jumpKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const issuerJwk = await exportJWK(issuerKeys.publicKey);
  const publicJwk: JWK = { ...issuerJwk, kid: 'kid-1', alg: 'EdDSA', use: 'sig' };
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
  });
  return {
    app,
    fetchCount: () => fetches,
    signToken: (claim, header) => signToken(issuerKeys.privateKey, claim, header),
    signRaw: (payload, header) => signPayload(issuerKeys.privateKey, payload, header),
    jumpPublicKey: jumpKeys.publicKey,
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
    aud: SERVICE.origin,
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
    .setProtectedHeader({ typ: 'JWT', alg: 'EdDSA', kid: 'kid-1', ...header })
    .sign(privateKey);
}

async function jump(app: Fixture['app'], rt: string) {
  return app.request(`https://jump.example.net/?rt=${rt}`);
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

describe('jump gateway routes', () => {
  test('default app serves local health data', async () => {
    const app = createApp();
    const res = await app.request('https://jump.example.net/health.json');
    expect(await res.json()).toMatchObject({ edge: 'local' });
    expect((await fetchExampleJwks()).keys.length).toBeGreaterThan(0);
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

  test('GET / redirects to /about when rt is absent', async () => {
    const { app } = await fixture();
    const res = await app.request('https://jump.example.net/');
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toBe('/about');
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
    expect(await html.text()).toContain(
      '<meta name="robots" content="noindex,nofollow,noarchive">',
    );
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
      'User-agent: *\nDisallow: /\nAllow: /about\n',
    );
  });

  test('cloudflare worker serves robots without importing private key', async () => {
    const res = await fetchCloudflareWorker('/robots.txt', {
      UMAXICA_JUMP_PRIVATE_KEY_PEM: 'not a pkcs8 key',
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('User-agent: *\nDisallow: /\nAllow: /about\n');
  });

  test('cloudflare worker serves health without importing private key', async () => {
    const res = await fetchCloudflareWorker('/health.json', {
      UMAXICA_JUMP_PRIVATE_KEY_PEM: 'not a pkcs8 key',
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, edge: 'cloudflare' });
  });

  test('security headers are applied to static and well-known responses', async () => {
    const { app } = await fixture();
    for (const path of [
      '/about',
      '/health',
      '/health.html',
      '/health.json',
      '/robots.txt',
      '/.well-known/jwks.json',
    ]) {
      const res = await app.request(`https://jump.example.net${path}`, {
        headers: { Cookie: 'sid=1' },
      });
      expectSecurityHeaders(res);
    }
  });

  test('security headers are applied to invalid token and cushion responses', async () => {
    const { app, signToken } = await fixture();
    expectSecurityHeaders(await jump(app, 'abc.def'));
    const cushion = await jump(
      app,
      await signToken({ dst: 'external', url: 'https://example.org/a?b=1' }),
    );
    expectSecurityHeaders(cushion);
  });

  test('default signer failure maps to malformed error', async () => {
    const issuerKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
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
        return { keys: [{ ...jwk, kid: 'kid-1', alg: 'EdDSA', use: 'sig' }] };
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
    expect(res.status).toBe(400);
    expect(res.headers.get('X-Jump-Error')).toBe('malformed');
  });

  test('redirect responses avoid referrer, cache, and cookies', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({ dst: 'internal' }));
    expect(res.status).toBe(302);
    expect(res.headers.get('Referrer-Policy')).toBe('no-referrer');
    expect(res.headers.get('Cache-Control')).toBe('no-store');
    expect(res.headers.get('Set-Cookie')).toBeNull();
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
          replaceHeader(token, { typ: 'JWT', alg: 'EdDSA', kid: 'kid-1', crit: ['exp'] }),
        )
      ).headers.get('X-Jump-Error'),
    ).toBe('invalid_header');
    expect(
      (
        await jump(app, replaceHeader(token, { typ: 'JWT', alg: 'EdDSA', kid: 'kid-1', jwk: {} }))
      ).headers.get('X-Jump-Error'),
    ).toBe('invalid_header');
    expect(
      (
        await jump(
          app,
          replaceHeader(token, {
            typ: 'JWT',
            alg: 'EdDSA',
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

  test('signature verification retries against refreshed JWKS', async () => {
    const staleKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const freshKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
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
              alg: 'EdDSA',
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

  test('self-link reject', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({ url: 'https://jump.example.net/about' }));
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

    const issuerKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const jumpKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
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
        keys: [{ ...jwk, kid: 'kid-1', alg: 'EdDSA', use: 'sig' }],
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

  test('external cushion truncates long displayed URLs while preserving href', async () => {
    const registry: IssuerRegistry = {
      'https://app.example.com': {
        iss: 'https://app.example.com',
        jwks_uri: 'https://app.example.com/.well-known/jwks.json',
        allowed_dst_internal: ['https://app.example.com'],
        allowed_dst_external: true,
      },
    };
    const issuerKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const jumpKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const jwk = await exportJWK(issuerKeys.publicKey);
    const app = createApp({
      registry,
      jwksCache: new JwksCache(async () => ({
        keys: [{ ...jwk, kid: 'kid-1', alg: 'EdDSA', use: 'sig' }],
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
    const issuerKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const jumpKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const jwk = await exportJWK(issuerKeys.publicKey);
    const app = createApp({
      registry,
      jwksCache: new JwksCache(async () => ({
        keys: [{ ...jwk, kid: 'kid-1', alg: 'EdDSA', use: 'sig' }],
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
    expect(html).toContain('non-ASCII');
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
      issuer: SERVICE.origin,
      audience: 'https://app.example.com',
      algorithms: ['EdDSA'],
      typ: 'JWT',
      currentDate: new Date(NOW * 1000),
    });
    expect(verified.payload).toMatchObject({
      schema: 1,
      iss: SERVICE.origin,
      aud: 'https://app.example.com',
      sub: 'jump-redirect',
      dst: 'internal',
      src: 'https://app.example.com',
      url: 'https://app.example.com/path',
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
      issuer: SERVICE.origin,
      audience: 'https://app.example.com',
      algorithms: ['EdDSA'],
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
    const issuerKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const jumpKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
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
        keys: [{ ...jwk, kid: 'kid-1', alg: 'EdDSA', use: 'sig' }],
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
    const issuerKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const jumpKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
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
        keys: [{ ...jwk, kid: 'kid-1', alg: 'EdDSA', use: 'sig' }],
      })),
      replayCache: new NoopReplayCache(),
      runtime: { edge: 'local', production: true },
      signer: new JoseOutboundSigner(jumpKeys.privateKey, 'jump-test'),
    });
    expect(res.status).toBe(302);
  });

  test('app route can validate tokens without a test clock override', async () => {
    const issuerKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const jumpKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
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
        keys: [{ ...jwk, kid: 'kid-1', alg: 'EdDSA', use: 'sig' }],
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
    const issuerKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const jwk = await exportJWK(issuerKeys.publicKey);
    const issuer = {
      iss: 'https://app.example.com',
      jwks_uri: 'https://app.example.com/.well-known/jwks.json',
      allowed_dst_internal: ['https://app.example.com'],
      allowed_dst_external: false,
      revoked_kids: ['revoked'],
    };
    const cache = new JwksCache(async () => ({
      keys: [{ ...jwk, kid: 'kid-1', alg: 'EdDSA', use: 'sig' }],
    }));

    await expect(cache.getKey(issuer, 'revoked', 'EdDSA')).rejects.toThrow(JumpError);
    await expect(cache.getKey(issuer, 'missing', 'EdDSA')).rejects.toThrow(JumpError);
    await expect(cache.getKey(issuer, 'missing', 'EdDSA')).rejects.toThrow(JumpError);
    expect(await signToken()).toBeTruthy();
  });

  test('noop outbound signer fails closed', async () => {
    await expect(new NoopOutboundSigner().sign()).rejects.toThrow('outbound signer not configured');
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
  expect(res.headers.get('Referrer-Policy')).toBe('no-referrer');
  expect(res.headers.get('Permissions-Policy')).toBeTruthy();
  expect(res.headers.get('Cache-Control')).toBe('no-store');
  expect(res.headers.get('X-Robots-Tag')).toBe('noindex, nofollow, noarchive');
  expect(res.headers.get('Strict-Transport-Security')).toContain('max-age=63072000');
  expect(res.headers.get('Set-Cookie')).toBeNull();
}
