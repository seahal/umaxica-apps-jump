# TypeScript Usage

These examples are intentionally copy-paste oriented. Do not hide the JWT shape from issuer applications yet.

## Node.js Issuing Example

```ts
import { importPKCS8, SignJWT } from 'jose';

const privateKeyPem = process.env.JUMP_PRIVATE_KEY_PEM;
if (!privateKeyPem) throw new Error('JUMP_PRIVATE_KEY_PEM is required');

const privateKey = await importPKCS8(privateKeyPem, 'EdDSA');
const now = Math.floor(Date.now() / 1000);

const rt = await new SignJWT({
  schema: 1,
  iss: 'https://app.example.com',
  aud: 'https://jump.example.net',
  sub: 'jump-redirect',
  iat: now,
  nbf: now,
  exp: now + 14 * 24 * 60 * 60,
  jti: crypto.randomUUID(),
  dst: 'internal',
  url: 'https://docs.example.com/getting-started',
})
  .setProtectedHeader({ typ: 'JWT', alg: 'EdDSA', kid: 'app-2026-05' })
  .sign(privateKey);

console.log(`https://jump.example.net/?rt=${encodeURIComponent(rt)}`);
```

## Browser Redirect Helper

```ts
export function goToJump(rt: string) {
  const url = new URL('https://jump.example.net/');
  url.searchParams.set('rt', rt);
  location.assign(url.href);
}
```

Browsers should not hold private signing keys. Generate `rt` on a server and pass it to the browser.

## Hono Issuer Route

```ts
import { Hono } from 'hono';
import { importPKCS8, SignJWT } from 'jose';

const app = new Hono();

app.get('/go/docs', async (c) => {
  const pem = c.env.JUMP_PRIVATE_KEY_PEM;
  const key = await importPKCS8(pem, 'EdDSA');
  const now = Math.floor(Date.now() / 1000);
  const rt = await new SignJWT({
    schema: 1,
    iss: 'https://app.example.com',
    aud: 'https://jump.example.net',
    sub: 'jump-redirect',
    iat: now,
    nbf: now,
    exp: now + 14 * 24 * 60 * 60,
    jti: crypto.randomUUID(),
    dst: 'internal',
    url: 'https://docs.example.com/',
  })
    .setProtectedHeader({ typ: 'JWT', alg: 'EdDSA', kid: 'app-2026-05' })
    .sign(key);

  return c.redirect(`https://jump.example.net/?rt=${encodeURIComponent(rt)}`);
});
```

## Fetch Example

```ts
const response = await fetch('https://jump.example.net/health', {
  headers: { Accept: 'application/json' },
});

console.log(await response.json());
```

## JWKS Verification Example

```ts
import { createRemoteJWKSet, jwtVerify } from 'jose';

const jwks = createRemoteJWKSet(
  new URL('https://app.example.com/.well-known/jwks.json'),
);
const { payload } = await jwtVerify(rt, jwks, {
  issuer: 'https://app.example.com',
  audience: 'https://jump.example.net',
  algorithms: ['EdDSA'],
});

console.log(payload.jti);
```
