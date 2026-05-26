# Privacy

## Privacy Assumptions

`rt` JWTs are NOT confidential. Redirect URLs and JWT claims must be treated as data that can be copied, logged, screenshotted, bookmarked, or shared.

Redirect URLs may appear in:

- browser history
- screenshots
- bookmarks
- analytics systems
- chat tools
- edge infrastructure logs

## Forbidden Data

Do not put these values inside JWT claims or redirect URLs:

- email addresses
- passwords
- OAuth authorization codes
- access tokens
- session ids
- personal identifiers

## Limitations

Referrer policy and logging controls reduce leakage but cannot erase URL exposure. If a value must be confidential, it does not belong in `rt` or in the destination URL.
