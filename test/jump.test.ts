import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import { describe, expect, test } from 'vite-plus/test';
import { createApp } from '../src';
import { JwksCache } from '../src/core/jwks_cache';
import { MemoryReplayCache, NoopReplayCache } from '../src/core/replay_cache';
import { SERVICE, type InboundJumpClaim, type IssuerRegistry } from '../src/core/types';

const NOW = 1_800_000_000;

type Fixture = {
  app: ReturnType<typeof createApp>;
  signToken: (
    claim?: Partial<InboundJumpClaim>,
    header?: Record<string, unknown>,
  ) => Promise<string>;
  signRaw: (payload: Record<string, unknown>, header?: Record<string, unknown>) => Promise<string>;
  fetchCount: () => number;
};

async function fixture(): Promise<Fixture> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const jwk = await exportJWK(publicKey);
  const publicJwk: JWK = { ...jwk, kid: 'kid-1', alg: 'EdDSA', use: 'sig' };
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
    runtime: { edge: 'local', region: 'test', production: true },
    now: () => NOW,
  });
  return {
    app,
    fetchCount: () => fetches,
    signToken: (claim, header) => signToken(privateKey, claim, header),
    signRaw: (payload, header) => signPayload(privateKey, payload, header),
  };
}

async function signToken(
  privateKey: Parameters<SignJWT['sign']>[0],
  claim: Partial<InboundJumpClaim> = {},
  header: Record<string, unknown> = {},
) {
  return signPayload(privateKey, { ...baseClaim(), ...claim }, header);
}

function baseClaim() {
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
  return app.request(`https://jump.example.net/?rt=${encodeURIComponent(rt)}`);
}

describe('jump gateway routes', () => {
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
      region: 'test',
    });
    const html = await app.request('https://jump.example.net/health.html');
    expect(await html.text()).toContain(
      '<meta name="robots" content="noindex,nofollow,noarchive">',
    );
  });

  test('robots.txt is restrictive', async () => {
    const { app } = await fixture();
    expect(await (await app.request('https://jump.example.net/robots.txt')).text()).toBe(
      'User-agent: *\nDisallow: /\nAllow: /about\n',
    );
  });

  test('security headers are applied and Set-Cookie is absent', async () => {
    const { app } = await fixture();
    const res = await app.request('https://jump.example.net/about', {
      headers: { Cookie: 'sid=1' },
    });
    expect(res.headers.get('Content-Security-Policy')).toContain("default-src 'none'");
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
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

  test('nbf future and empty url reject', async () => {
    const { app, signToken } = await fixture();
    expect((await jump(app, await signToken({ nbf: NOW + 61 }))).headers.get('X-Jump-Error')).toBe(
      'invalid_claim',
    );
    expect((await jump(app, await signToken({ url: '' }))).headers.get('X-Jump-Error')).toBe(
      'invalid_url',
    );
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

  test('skew handling permits recently expired token', async () => {
    const { app, signToken } = await fixture();
    const res = await jump(app, await signToken({ exp: NOW - 30 }));
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

  test('JWKS cache avoids repeated fetch and negative cache rejects missing kid', async () => {
    const { app, signToken, fetchCount } = await fixture();
    expect((await jump(app, await signToken({ jti: 'a' }))).status).toBe(302);
    expect((await jump(app, await signToken({ jti: 'b' }))).status).toBe(302);
    expect(fetchCount()).toBe(1);
    const missing = await signToken({ jti: 'c' }, { kid: 'missing' });
    expect((await jump(app, missing)).headers.get('X-Jump-Error')).toBe('invalid_signature');
  });

  test('replay cache rejects repeated jti when enabled', async () => {
    const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const jwk = await exportJWK(publicKey);
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
      runtime: { edge: 'local', region: 'test', production: true },
      now: () => NOW,
    });
    const token = await signToken(privateKey, { jti: 'same-jti' });
    expect((await jump(app, token)).status).toBe(302);
    const replay = await jump(app, token);
    expect(replay.headers.get('X-Jump-Error')).toBe('replay');
  });
});

function b64(value: string) {
  return btoa(value).replaceAll('=', '').replaceAll('+', '-').replaceAll('/', '_');
}

function replaceHeader(token: string, header: Record<string, unknown>) {
  const parts = token.split('.');
  return [b64(JSON.stringify(header)), parts[1], parts[2]].join('.');
}
