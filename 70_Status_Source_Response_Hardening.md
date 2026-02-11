# 70 — Status Source Response Hardening

Stand: 2026-02-11

## Implemented
- HTTP credential-status fetch now sends `Accept: application/json`.
- Response payload shape is now validated:
  - must include at least one of: `revokedCredentialIds` or `revokedIndexes`
  - if present, each must be an array
- Malformed payloads are treated fail-closed (`credential_status_unavailable` path).

## Security benefit
Prevents silent acceptance when status providers return unexpected/invalid JSON structures.
