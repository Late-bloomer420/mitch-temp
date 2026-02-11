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
- `KEY_SOURCE_MODE=env|file|http`

### env mode
- `PUBLIC_KEYS_JSON={"kid-1":"-----BEGIN PUBLIC KEY-----..."}`

### file mode
- `KEY_SOURCE_FILE=./data/public-keys.json`

### http mode
- `KEY_SOURCE_URL=http://key-provider.local/keys`
- `KEY_SOURCE_TIMEOUT_MS=1500`

Optional revoked list:
- `REVOKED_KEY_IDS=kid-2,kid-3`

Operational behavior notes:
- missing/revoked/status-unavailable keys are deny-biased for high-risk purposes.
- keep key source timeout low (e.g., `KEY_SOURCE_TIMEOUT_MS=1500`) to avoid hanging verifier paths.

## Safety defaults
- `NODE_ENV=production` to disable dashboard/test endpoints
- `ALLOW_METRICS=1` only if metrics endpoint is explicitly desired
- `MAX_BODY_BYTES=262144` (adjust if needed)
