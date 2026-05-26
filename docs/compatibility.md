# Compatibility

## WebCrypto

Core code targets Web Standard APIs. Runtime adapters may be needed where Fastly Compute and Cloudflare Workers differ.

## EdDSA And Ed25519

The intended algorithm is `EdDSA` with Ed25519 OKP JWKs. Runtime support must be verified in each target edge environment before production use.

## Fastly And Cloudflare Differences

Fastly and Cloudflare expose different runtime bindings, secret stores, region metadata, and cache behavior. Keep those differences outside `src/core`.

## Clock Skew

Jump assumes issuer and edge clocks are close enough for 60 seconds of leeway. Larger skew may reject valid tokens or accept recently expired ones.

## URL Parsing

Jump uses `new URL()` and validates the reconstructed URL. Do not replace this with string parsing.

## Punycode And Unicode

Hostnames are compared after URL parser normalization. Cushion pages display punycode hostnames and warn on non-ASCII hostnames. Unicode normalization can still be visually confusing; do not treat visual similarity as proof of trust.

## Localhost Handling

`localhost`, loopback, private IPv4 ranges, link-local ranges, and metadata IPs are rejected. Runtime DNS behavior may differ, so hostname allowlists should prefer explicit public origins.

## Known Caveats

- DNS rebinding is not fully solved by URL parsing.
- Provider-specific metadata names may need runtime-specific denylist additions.
- Browser URL rendering can differ from server-side URL parsing.
