# ADR 0002: Security Review — Rails Issuer Integration

## Status

Accepted — H2/H3/M1 remediated in the same change set as this ADR. H1 was
reframed (see below) and the related Cache API discussion was withdrawn: Jump
does not perform replay detection by design; that responsibility belongs to
the receiving party. Documentation under `docs/` was updated accordingly.

## Context

Commits `6b5b47c`, `315abd3`, and `e653bc7` ("modified with rails check") added
the Rails application at `https://www.umaxica.app` as a first-class issuer in
the Jump registry and configured the Cloudflare runtime to sign outbound `rt`
tokens with the ES384 key `cloudflare-active-2026-05`. A pending change to
`test/jump.test.ts` pins the Rails ↔ Cloudflare handshake contract as a
regression test.

This ADR records the security posture observed at that point in time. It does
**not** change code or configuration. Scope: Rails handshake, Cloudflare
runtime, and supply chain. The Fastly runtime is out of scope for this review.

## Trust Model

```
Rails (www.umaxica.app)
  signs inbound JWT (ES384, issuer-owned kid)
  hosts https://www.umaxica.app/.well-known/jwks.json
        │
        ▼
Jump Worker (jump.umaxica.net)
  verifies inbound JWT against issuer JWKS
  enforces iss/aud/dst/url against registry
  re-signs outbound JWT (ES384, kid=cloudflare-active-2026-05)
        │
        ▼
Rails verifies outbound JWT against
  https://jump.umaxica.net/.well-known/jwks.json
```

Registry entry: `src/config/registry.umaxica.ts:25-31` —
`iss=https://www.umaxica.app`, `allowed_dst_internal=['https://www.umaxica.app']`,
`allowed_dst_external=false`, `revoked_kids=[]`.

The handshake contract pinned by `test/jump.test.ts`
(`cloudflare worker live rails acme app handshake contract stays stable`):

- Inbound: `iss=https://www.umaxica.app`, `aud=https://jump.umaxica.net`,
  `dst=internal`, `url=https://www.umaxica.app/`.
- Outbound: `iss=https://jump.umaxica.net`, `aud=https://www.umaxica.app`,
  `sub=jump-redirect`, `src=https://www.umaxica.app`.
- Public JWK: `kty=EC, crv=P-384, alg=ES384, kid=cloudflare-active-2026-05`.
- Response is `302`, `Location` carries exactly one `rt` query, and neither
  `jump_rt` nor `jump_probe` is appended.

## Findings

Severity ranking reflects exploitability under the current configuration
(`wrangler.jsonc` rate limit `10000 req / 10s`, `vars` rather than
`secrets_store_secrets` for `UMAXICA_JUMP_PRIVATE_KEY_KID`).

### High

#### H1. Replay cache wired but not part of Jump's responsibility (reframed)

**Original framing (since revised):** `MemoryReplayCache` in
`src/core/replay_cache.ts:7-23` was treated as a replay defense; because the
state lives in a per-isolate `Map`, it does not stop replay across Cloudflare
isolates. This was reported as a high-severity finding.

**Revised framing after maintainer review:** Jump is an OpenRedirect-prevention
intermediary, not an authentication or session layer. Replay defense — deciding
whether a given `jti` may be used once, N times, or unrestricted within `exp` —
belongs at the **receiving party's** boundary, where the local session and
downstream side effects determine the accept/reject outcome. Jump signs `jti`,
`iat`, `nbf`, `exp`, `src`, `dst`, and `url` into the token but does not record
which `jti` values have been seen. The pre-existing `MemoryReplayCache` default
was a misfit for this responsibility split: it would have wrongly rejected
legitimate reuse inside a hot isolate while letting the same token through on a
cold one.

**Changes kept:**

- `src/cloudflare.ts` wires `new NoopReplayCache()` explicitly, matching the
  intended responsibility split. `MemoryReplayCache` remains available for
  local development and single-process tests.
- `DEFAULT_OUTBOUND_TTL` in `src/core/handle_jump.ts` lowered from 60 to 30
  seconds. This shrinks the freshness window of an emitted return `rt`; it
  is unrelated to replay defense and was retained as conservative hygiene.

**Documentation updates:** `docs/security.md`, `docs/architecture.md`,
`docs/threat-model.md`, and `docs/decisions.md` now state explicitly that
Jump does not detect replay and that the receiving party owns the policy.

**Receiving-party guidance (informational):** for the current Rails consumer
of return `rt`, a single-use policy keyed on `jti` is the simplest fit;
typical user reloads strip `?rt=` via 303 to the same URL before any second
use occurs. Other consumers may choose N-uses or unrestricted within `exp`
depending on their semantics. Jump does not enforce any of these.

#### H2. JWKS response has no size or timeout limits

`src/core/fetch_jwks.ts:4-10` calls `fetch(issuer.jwks_uri)` and immediately
`await response.json()`. There is no `AbortController`, no `Content-Length`
check, no streaming read cap, and no `Content-Type` validation. A compromised,
misconfigured, or degraded Rails JWKS endpoint can:

- Return a multi-megabyte JSON document and exhaust the Worker isolate's
  memory budget.
- Hang indefinitely (subject only to platform defaults) and consume the
  isolate's CPU-time budget.

The blast radius scales with isolate cold-start frequency because
`JwksCache` (see M3) is also isolate-local.

**Remediated:** `src/core/fetch_jwks.ts` now wraps the fetch in an
`AbortController` with a 2 s timeout, validates that the response
`Content-Type` matches `application/(*+)?json`, checks the advertised
`Content-Length` against a 64 KiB cap, and streams the body chunk-by-chunk
aborting the read as soon as the cap is exceeded.

#### H3. Rate limit key is pathname-only

`src/cloudflare.ts:69-70` invokes `rateLimiter.limit({ key: pathname })`. The
configured limit in `wrangler.jsonc:14-17` is `10000 req / 10 s` — a single
bucket shared across every client of `/`. An attacker sending invalid `?rt=…`
queries from one IP can fill the bucket and cause `429` for every legitimate
Rails handshake against the apex path (noisy-neighbor DoS).

**Remediated:** `src/cloudflare.ts` now keys the rate limiter on
`${CF-Connecting-IP}|${pathname}`. A single source IP can still exhaust its
own bucket, but no longer drags other clients into the same 429 window.

### Medium

#### M1. `LazyCloudflareSigner.kid` may resolve to `'unloaded'`

`src/cloudflare.ts:87` reads the signing kid via `readStringBindingSync`
(`src/cloudflare.ts:168-170`), which returns the literal `'unloaded'` when the
binding is anything other than a plain string. The current `wrangler.jsonc:29`
exposes `UMAXICA_JUMP_PRIVATE_KEY_KID` as a plain `vars` entry, so this works
today. If the kid is later migrated into `secrets_store_secrets` (a reasonable
operational hardening), the synchronous read silently produces `'unloaded'`
while the asynchronous path inside `createJoseSigner` resolves the real kid.
The signer's externally observable `kid` field and the JWT protected header
would diverge.

**Remediated:** `readonly kid` was removed from the `OutboundSigner`
interface and from `LazyCloudflareSigner` / `NoopOutboundSigner`. `kid` now
lives only inside `JoseOutboundSigner` where it is supplied by the async
`createJoseSigner` path. `readStringBindingSync` was deleted. Migrating the
kid into `secrets_store_secrets` is now safe.

#### M2. Signing kid lives in plaintext `vars`

`wrangler.jsonc:27-31` — the kid itself is not secret, but tying its
lifecycle to the secret rotation (`UMAXICA_JUMP_PRIVATE_KEY_PEM` in
`secrets_store_secrets`) is awkward in two separate config layers.

Recommended remediation: define a written rotation runbook covering
`(secret, kid, public JWKS)` together. No code change.

#### M3. JwksCache is isolate-local

`src/core/jwks_cache.ts:11-19` — positive TTL 5 min, negative TTL 30 s, held
in process memory. Each new isolate fetches Rails JWKS again. This is a
capacity-planning concern rather than a vulnerability on its own, but it
amplifies H2 and ties the Worker's availability to Rails serving
`/.well-known/jwks.json` reliably under the cold-start rate.

Recommended remediation: confirm the Rails-side SLO for JWKS and add Workers
KV or Cache API as a shared layer if warranted.

### Low / Informational

#### L1. Audit log fields populated before verification

`src/core/handle_jump.ts` writes `iss`, `kid`, `jti` from the unverified
header into the audit record before JWT validation, then overwrites them with
verified values on success. Current behavior is safe; the risk is fragility
under future refactors — an accidental skip of the overwrite would persist
attacker-controlled values into logs.

Recommended remediation (optional): defer audit field population until after
`verifyJumpJwt` returns.

#### L2. Devcontainer carries `NOPASSWD` sudo and `allowDangerouslySkipPermissions`

`Dockerfile` enables passwordless sudo for the `jump` user, and
`.devcontainer/devcontainer.json` sets `claude.allowDangerouslySkipPermissions:
true`. Both are scoped to the development image and are not produced from the
Worker bundle, but a CI check that asserts these flags do not leak into the
deployed artifact would harden the supply chain.

#### L3. Findings rejected during review

Two patterns flagged by the initial sweep are not vulnerabilities:

- **JTI uses `crypto.randomUUID()`** — Web Crypto / Workers `randomUUID`
  produces UUIDv4 from a CSPRNG. The historical "MAC address bits" concern
  applies to UUIDv1, which is not in use.
- **`verify_jwt.ts` "double verification"** — the retry at lines 70-85 is
  the standard JWKS-rotation pattern: it calls `getKey(..., forceRefresh=true)`
  only when the first verification fails. This is correct behavior, not a
  redundancy bug.

## Strengths Observed

For completeness, the following defenses were validated end-to-end and should
be preserved through any remediation work above.

- **Inbound JWT verification** (`src/core/verify_jwt.ts:12-49, 132-156`):
  algorithm pinned to `ES384`, `alg=none` rejected, `jku`/`jwk`/`x5u`/`crit`
  headers rejected, `typ='JWT'` enforced, strict `iss`/`aud` match,
  `MAX_TOKEN_LENGTH=8192`, `MAX_TTL=30 days`, `SKEW=60s`.
- **Key pair self-check** (`src/cloudflare.ts:172-186`): on signer init the
  loaded private key signs a probe JWT that is verified against the public
  JWK before the signer is exposed.
- **Public JWKS scrubbing** (`src/cloudflare.ts:218-224`): strips
  `d, p, q, dp, dq, qi, oth, k` before publishing.
- **SSRF defenses** (`src/core/normalize_url.ts`): rejects loopback, RFC1918,
  link-local, cloud metadata, IPv4-mapped IPv6, and 6to4 ranges.
- **Issuer policy** (`src/config/registry.umaxica.ts:25-31`):
  `allowed_dst_internal` is self-only and `allowed_dst_external` is `false`
  for Rails.
- **Security headers** (`src/core/security_headers.ts`): HSTS with `preload`,
  strict CSP with SHA-256 inline script allowance, `X-Frame-Options: DENY`,
  `Cache-Control: no-store`, mandatory `Set-Cookie` stripping.
- **Supply chain**: `pnpm audit` reports `0` vulnerabilities across 456
  dependencies. `git ls-files | grep -Ei '\.(pem|key|env|secret|cert)$'`
  returns nothing. GitHub Actions hold `permissions: contents: read` only,
  use no `pull_request_target`, and run `gitleaks` in CI.

## Rails Handshake — Operational Items Not Covered By Tests

The pinned contract test guards the JWT shape but cannot observe operational
state. The following must be tracked in Rails-side documentation:

- TTL and cache headers served by `https://www.umaxica.app/.well-known/jwks.json`.
- Rotation procedure for the Rails issuer signing key.
- Runbook for revoking a compromised Rails `kid` by adding it to
  `revoked_kids` in `src/config/registry.umaxica.ts` and redeploying the
  Worker.

## Verification

This ADR is a record; no runtime verification is required. Reviewers can
reproduce the underlying observations with read-only commands:

```sh
# Dependency CVE recheck
vp run audit            # or: pnpm audit --audit-level=high

# Confirm no secret material is committed
git ls-files | grep -Ei '\.(pem|key|env|secret|cert)$'

# Inspect the verification core
rg -n 'ALLOWED_ALGS|forceRefresh|MemoryReplayCache|key: pathname' src/

# Run the pinned Rails handshake contract test
vp test run test/jump.test.ts -t 'rails acme app handshake'
```

## Out of Scope

- Fastly runtime (`src/fastly.ts`, `fastly.toml`).
- Rails application source (not in this repository).
- Cloudflare dashboard configuration (secrets store ACLs, route bindings).
- Cache API as a distributed replay backend (option A) — withdrawn. Replay
  defense is not Jump's responsibility (see revised H1), so an edge-side
  replay backend is not warranted.

## Open Decisions

None. The Cache API option discussed earlier in this review is withdrawn
following the H1 reframing: Jump does not perform replay detection, so an
edge-side replay backend is out of scope.

## Future Review

Revisit when any of the following occurs:

- A new issuer is added to `src/config/registry.umaxica.ts`.
- `UMAXICA_JUMP_PRIVATE_KEY_KID` is moved into `secrets_store_secrets`.
- A receiving party explicitly asks Jump to take on replay detection, which
  would invert the H1 decision and require a designed state backend.
