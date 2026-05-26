# FAQ

## Why Not Use Opaque Tokens?

Opaque tokens require a database or introspection service. Jump is intentionally stateless.

## Why Not Encrypt JWTs?

The token is not confidential. Encryption would hide data from operators without removing URL leakage risk.

## Why Are JWTs Visible?

The entry point is a URL designed to cross FQDNs without cookies or sessions. Visible tokens are acceptable only because they contain no secrets.

## Why Not Use Cookies?

Cookies add session behavior and cross-site complexity. Jump ignores cookies and emits no cookies.

## Why Not Redirect Directly?

External direct redirects increase phishing and OpenRedirect risk. Jump uses cushion pages for external destinations.

## Why Use JWKS?

JWKS lets Jump verify public keys while private keys stay in issuer or runtime secret stores.

## Why Active-Active?

Active-active Fastly and Cloudflare operation improves resilience and lets traffic move during provider incidents.

## Why Not OAuth?

Jump does not authenticate users or delegate authorization. OAuth/OIDC solves a different problem.

## Why Not Use A Database?

Database dependency would make redirects stateful and reduce edge portability.

## Why Not Use Server-Side Sessions?

Sessions would add state and cookies. Jump is only a redirect trust broker.
