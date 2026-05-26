# Ruby Usage

These examples use explicit claims and avoid framework lock-in.

## Example Config

```ruby
JUMP_ISSUER = "https://app.example.com"
JUMP_AUDIENCE = "https://jump.example.net"
JUMP_KID = "app-2026-05"
JUMP_PRIVATE_KEY_PEM = ENV.fetch("JUMP_PRIVATE_KEY_PEM")
```

## JWT Issuing Example

```ruby
require "jwt"
require "securerandom"
require "openssl"
require "uri"

private_key = OpenSSL::PKey.read(JUMP_PRIVATE_KEY_PEM)
now = Time.now.to_i

payload = {
  schema: 1,
  iss: JUMP_ISSUER,
  aud: JUMP_AUDIENCE,
  sub: "jump-redirect",
  iat: now,
  nbf: now,
  exp: now + 14 * 24 * 60 * 60,
  jti: SecureRandom.uuid,
  dst: "internal",
  url: "https://docs.example.com/getting-started"
}

rt = JWT.encode(payload, private_key, "EdDSA", typ: "JWT", kid: JUMP_KID)
jump_url = "https://jump.example.net/?rt=#{URI.encode_www_form_component(rt)}"
puts jump_url
```

## Redirect Helper

```ruby
def jump_redirect_url(rt)
  "https://jump.example.net/?rt=#{URI.encode_www_form_component(rt)}"
end
```

## Rails Controller Example

```ruby
class RedirectsController < ApplicationController
  def docs
    rt = issue_jump_token("https://docs.example.com/")
    redirect_to jump_redirect_url(rt), allow_other_host: true
  end
end
```

## JWKS Verification Example

```ruby
require "jwt"
require "net/http"
require "json"

jwks = JSON.parse(Net::HTTP.get(URI("https://app.example.com/.well-known/jwks.json")))
decoded = JWT.decode(
  rt,
  nil,
  true,
  algorithms: ["EdDSA"],
  iss: "https://app.example.com",
  verify_iss: true,
  aud: "https://jump.example.net",
  verify_aud: true,
  jwks: jwks
)

puts decoded.first.fetch("jti")
```

## Notes

Keep private keys in runtime secrets. Commit only public JWKs.
