# Rust Usage

These examples prioritize explicit claims and simple integration.

## Cargo Dependencies

```toml
[dependencies]
jsonwebtoken = "9"
reqwest = { version = "0.12", features = ["json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
time = "0.3"
uuid = { version = "1", features = ["v4"] }
urlencoding = "2"
```

## JWT Claims

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct JumpClaims {
    schema: i32,
    iss: String,
    aud: String,
    sub: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
    dst: String,
    url: String,
}
```

## JWT Issuing Example

```rust
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use time::OffsetDateTime;
use uuid::Uuid;

fn issue_jump_token(private_key_pem: &[u8]) -> jsonwebtoken::errors::Result<String> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = JumpClaims {
        schema: 1,
        iss: "https://app.example.com".to_string(),
        aud: "https://jump.example.net".to_string(),
        sub: "jump-redirect".to_string(),
        iat: now,
        nbf: now,
        exp: now + 14 * 24 * 60 * 60,
        jti: Uuid::new_v4().to_string(),
        dst: "internal".to_string(),
        url: "https://docs.example.com/getting-started".to_string(),
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some("JWT".to_string());
    header.kid = Some("app-2026-05".to_string());

    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ed_pem(private_key_pem)?)
}
```

## Redirect URL

```rust
let rt = issue_jump_token(private_key_pem)?;
let jump_url = format!("https://jump.example.net/?rt={}", urlencoding::encode(&rt));
```

## Reqwest Health Example

```rust
let health: serde_json::Value = reqwest::Client::new()
    .get("https://jump.example.net/health")
    .header("accept", "application/json")
    .send()
    .await?
    .json()
    .await?;

println!("{health}");
```

## JWKS Fetch Example

```rust
let jwks: serde_json::Value = reqwest::get("https://app.example.com/.well-known/jwks.json")
    .await?
    .json()
    .await?;

println!("{}", jwks);
```

## Notes

Rust library support for EdDSA/JWKS verification differs by crate. Verify algorithm support in your selected JWT crate before production use.
