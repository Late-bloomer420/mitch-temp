# 44 — Evidence Runbook (B1)

## Goal
Produce reproducible pilot evidence for core scenarios.

## Command
```powershell
cd C:\Users\Admin\Documents\miTch
npm run evidence
```

## Expected scenarios
- `allow_valid` -> `ALLOW_MINIMAL_PROOF_VALID`
- `deny_replay` -> `DENY_BINDING_NONCE_REPLAY`
- `deny_hash_mismatch` -> `DENY_BINDING_HASH_MISMATCH`
- `deny_revoked_key` -> `DENY_CRYPTO_KEY_STATUS_INVALID`

## Output
JSON summary printed to console (can be copied into weekly KPI report).

## Notes
This runbook validates deterministic control behavior, not business throughput.
