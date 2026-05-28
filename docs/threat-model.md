# Threat Model

## Scope

Jump protects redirect decisions across FQDN boundaries. It does not authenticate users, manage sessions, or hide destinations.

## NON-GOALS

- This project is NOT an authentication provider.
- This project is NOT a session manager.
- This project is NOT a generic proxy.
- This project is NOT a URL shortener.
- This project is NOT a confidential transport.
- This project does NOT hide redirect destinations.
- This project does NOT replace OAuth/OIDC.
- This project is ONLY a redirect trust broker across FQDN boundaries.

## Threats

### Phishing

Impact: Attackers may use trusted domains to send users to malicious sites.

Mitigation: External destinations render a cushion page with escaped URL and punycode hostname.

Limitations: Users can still choose to continue.

### Token Replay

Impact: A copied `rt` may be reused until expiry.

Mitigation: `exp` bounds the usable window. The signed `jti` claim is provided so that the **receiving party** can enforce its own consumption policy (single-use, N-uses, or unrestricted) at its own boundary, backed by its own storage.

Limitations: Jump does not perform replay detection. If the receiving party does not enforce `jti` consumption, any copy of `rt` is usable until `exp`. See [security: Replay Detection](security.md#replay-detection).

### Referer Leakage

Impact: URL-visible JWTs may leak to third parties.

Mitigation: `Referrer-Policy: no-referrer`, external cushion page, and no secrets in JWTs.

Limitations: Browser history, screenshots, logs, bookmarks, and chat tools may still store URLs.

### JWKS Poisoning

Impact: Attackers may try to make Jump trust attacker keys.

Mitigation: Token `jku`, `jwk`, `x5u`, and `crit` are rejected. JWKS is fetched only from issuer registry.

Limitations: Registry compromise remains high impact.

### Confused Deputy

Impact: One issuer might redirect to destinations intended for another issuer.

Mitigation: Destination policy is issuer-scoped.

Limitations: Bad registry configuration can still allow too much.

### Homograph Attacks

Impact: Unicode hostnames may visually mimic trusted domains.

Mitigation: URLs are parsed with `new URL()`, hostnames are normalized, punycode hostname is displayed, and non-ASCII hostname warnings are shown.

Limitations: Visual similarity cannot be fully prevented.

### XSS On Cushion Page

Impact: Malicious URLs might inject HTML or script.

Mitigation: URL and hostname output are HTML-escaped. CSP is restrictive.

Limitations: Any future rich UI changes must preserve escaping.

### SSRF Via URL Parsing

Impact: Attackers may target local services or special protocols.

Mitigation: `javascript:`, `data:`, `file:`, `blob:`, userinfo, localhost, private IPs, loopback, metadata IPs, and self-links are rejected.

Limitations: IP classification must be kept current.

### Localhost And Private IP Attacks

Impact: Redirects could target local admin panels or internal networks.

Mitigation: `localhost`, `127.0.0.1`, `::1`, RFC1918 ranges, link-local ranges, and `0.0.0.0/8` are rejected.

Limitations: DNS rebinding is not fully addressed by hostname-only checks.

### Metadata Service Attacks

Impact: Cloud metadata endpoints could be exposed.

Mitigation: `169.254.169.254` and known metadata hostnames are rejected.

Limitations: Provider-specific metadata aliases should be reviewed per runtime.

### Key Compromise

Impact: Attackers can issue valid redirect JWTs for that issuer.

Mitigation: Add `kid` to revoked list, remove key from signing, rotate immediately, and skip grace.

Limitations: Tokens signed before detection may have been used.

### Edge Cache Inconsistency

Impact: Fastly and Cloudflare may briefly have different JWKS cache state during key rotation.

Mitigation: JWKS includes active and grace keys; isolate-local caches refresh on signature failure with `forceRefresh`. Jump holds no replay state, so cross-edge consistency only needs to cover JWKS.

Limitations: Propagation delay must be accounted for during rotation.
