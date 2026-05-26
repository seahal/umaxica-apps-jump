# Logging

## Policy

Logs should help operate Jump without storing redirect tokens or secrets.

## Must Not Log

- The `rt` query parameter must NOT be stored in access logs.
- Full JWTs must NOT appear in error logs.
- Malformed JWTs must be truncated or redacted.
- External destination path and query should be redacted.

## Allowed

- `jti` logging is allowed.
- `hash(rt)` logging is allowed.
- Issuer hostname logging is allowed.
- Destination hostname logging is allowed.
- Internal error category logging is allowed.

## Safe Logs

```text
level=warn event=jump_reject reason=expired iss_host=app.example.com jti=8b1... dst_host=docs.example.com
level=info event=jump_accept iss_host=app.example.com dst=external dst_host=example.org rt_sha256=4b227777...
```

## Unsafe Logs

```text
GET /?rt=eyJ0eXAiOiJKV1Qi...
error="invalid jwt eyJ0eXAiOiJKV1Qi..."
dst="https://example.org/account?email=user@example.com"
```

## Malformed Token Handling

When logging malformed input, record only length, a hash, and coarse category. Do not log the raw token.
