# Security

## Purpose

Jump reduces redirect risk by verifying signed redirect requests at a dedicated FQDN boundary. It is not a confidentiality layer.

## NON-GOALS

- This project is NOT an authentication provider.
- This project is NOT a session manager.
- This project is NOT a generic proxy.
- This project is NOT a URL shortener.
- This project is NOT a confidential transport.
- This project does NOT hide redirect destinations.
- This project does NOT replace OAuth/OIDC.
- This project is ONLY a redirect trust broker across FQDN boundaries.

## OpenRedirect Risk

OpenRedirect bugs let attackers create trusted-looking links that send users to attacker-controlled destinations. Jump mitigates this by requiring a valid issuer signature, fixed audience, claim validation, URL normalization, and issuer-scoped allowlists.

## Referer And URL Leakage

`rt` appears in the URL by design. It can leak through browser history, screenshots, bookmarks, chat previews, analytics, and infrastructure logs. Referrer policy is `no-referrer`, but that does not make URLs confidential.

## JWT Leakage

`rt` JWTs are NOT confidential. They should contain only routing claims, never secrets or personal data. Every token must include a random `jti` and an `exp`.

## Why jti Exists

`jti` makes every token unique even when the destination is the same. It exists so that the **receiving party** (the destination application that consumes the return `rt`) can implement its own replay policy — for example, single-use, N-uses, or unrestricted within `exp`. Jump itself does not track `jti` usage; see "Replay Detection" below.

## Why exp Exists

`exp` bounds token lifetime. Default TTL is 14 days. Maximum TTL is 30 days. Leeway is 60 seconds.

## Replay Detection

**Jump does not perform replay detection.** It does not record which `jti` values have been consumed, and it will accept the same valid `rt` repeatedly within its `exp` window. This is intentional architecture, not a limitation: Jump's responsibility ends at signature, claim, and policy validation.

Replay defense — including deciding whether a `jti` may be used once, N times, or unrestricted within `exp` — is the **receiving party's** responsibility. The receiving party verifies the return `rt` via JWKS, validates `url`/`aud`/`iss`/`src`/`dst`/`exp`, and then applies its own `jti` consumption policy backed by its own storage (DB, Redis, etc.). Expired tokens must be rejected.

The reason for placing replay defense at the receiving boundary is that the receiving party holds the local session, context, and downstream side effects needed to make the accept/reject decision. Edge replay state in Jump would be isolate-local, race-prone, and redundant with the receiving party's own check. The Cloudflare runtime therefore wires `NoopReplayCache` explicitly.

## JWT Schema Version

JWT schema is independent from service version. Service `0.1.0` starts with `schema: 1`. Patch or minor service releases must not change JWT compatibility. Increase schema only when token compatibility changes.

## Issuer-Scoped Allowlists

Each issuer has its own internal and external destination policy. This prevents a valid issuer from becoming a confused deputy for every destination.

## External Cushion Pages

External redirects require a cushion page. The page escapes the URL, displays the punycode hostname, warns about non-ASCII hostnames, removes `?rt` with `history.replaceState`, and uses `rel="noopener noreferrer"`.

## Security Headers

Responses use CSP, `nosniff`, frame denial, no-referrer, restrictive permissions policy, HSTS, no-store, and noindex headers. `Set-Cookie` is forbidden.

## Attack Surface

- Public `GET /?rt=<JWT>` entry point.
- Public `GET /.well-known/jwks.json` key discovery endpoint.
- Public health and informational HTML endpoints.
- Issuer registry configuration.
- Runtime secret stores holding private keys.
- Edge access logs and error logs.
- Cushion page rendering of external URLs.

Each surface is designed to expose public data only, except runtime private keys. Private keys must remain in runtime secrets and must never enter git, logs, screenshots, or example configs.

## Migration Strategy

Security-sensitive compatibility changes must use JWT schema migration rather than silent behavior changes. See [schema migration](operations/schema-migration.md).

## Operational Procedures

Key rotation, compromise response, and key state definitions live in [key rotation](operations/key-rotation.md). Logging requirements live in [logging](logging.md).

## Known Limitations

- Jump cannot prevent a user from copying a URL with `rt`.
- Jump cannot make URL-visible JWTs confidential.
- Jump does not detect replay; receiving parties must enforce their own `jti` policy.
- External cushion pages reduce phishing risk but cannot eliminate it.
- Issuer key compromise requires operational rotation and revocation.
