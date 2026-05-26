# Decisions

## Why JWT In Query String?

The redirect entry point must work across FQDNs without cookies or sessions. A URL token is portable and explicit. It is not confidential, so claims must not contain secrets.

## Why No Cookies?

Cookies create session semantics and cross-site policy concerns. Jump is stateless and ignores cookies.

## Why Stateless?

Stateless validation works well across active-active edge runtimes and avoids database availability in the redirect path.

## Why Fastly + Cloudflare Active-Active?

Two edge providers reduce dependence on one runtime and allow traffic steering during incidents.

## Why Hono Only?

Hono provides small Web Standard routing primitives without requiring a frontend or build framework.

## Why No Vite?

Jump is an edge HTTP service, not a frontend app. The initial implementation should avoid deploy and bundler coupling.

## Why Ed25519?

Ed25519 keys are small, fast, and map cleanly to OKP JWKs with `alg: EdDSA`.

## Why Replay Cache Is Optional?

Shared replay state would add cross-edge consistency and availability concerns. `exp`, `jti`, signature validation, and policy validation are mandatory; replay cache is defense-in-depth.

## Why No Opaque Tokens?

Opaque tokens require shared server-side storage or introspection. That would conflict with the stateless edge design.

## Why No SDK Abstraction Initially?

Copy-paste examples keep the protocol visible. Official libraries can come later after the claim model and operational practices stabilize.

## Why Direct Redirects Are Forbidden?

External direct redirects make phishing and OpenRedirect failures harder to see. Cushion pages make the cross-site transition explicit.

## Why Jump Acts As A Trust Broker?

Jump centralizes redirect policy at an FQDN boundary so each issuer does not reimplement URL validation and external redirect behavior differently.
