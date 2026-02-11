# 42 — Pilot-Critical Config

## Required for protected `/verify`
- `AUTH_TOKEN_REQUIRED=1`
- `AUTH_TOKEN=<strong-random-token>`

Optional for token rotation window:
- `AUTH_TOKEN_NEXT=<new-token-during-rollover>`

Clients must send:
- `Authorization: Bearer <token>`

## Runtime audience
- `RUNTIME_AUDIENCE=rp.example`

## Key resolver for non-local mode
- `LOCAL_TEST_KEYS=0`
- `PUBLIC_KEYS_JSON={"kid-1":"-----BEGIN PUBLIC KEY-----..."}`
- Optional revoked list:
  - `REVOKED_KEY_IDS=kid-2,kid-3`

## Safety defaults
- `NODE_ENV=production` to disable dashboard/test endpoints
- `ALLOW_METRICS=1` only if metrics endpoint is explicitly desired
- `MAX_BODY_BYTES=262144` (adjust if needed)
