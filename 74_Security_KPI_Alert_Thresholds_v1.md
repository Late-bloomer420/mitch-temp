# 74 — Security KPI Alert Thresholds v1

Stand: 2026-02-11

## Purpose
Define simple, actionable alert thresholds for pilot operations.

## KPI signals and thresholds

### 1) Status source degradation
- Signal: `deny_status_source_unavailable_rate`
- Warning: `> 0.05` over last review window
- Critical: `> 0.20` over last review window
- Action:
  1. Check status provider health/timeouts/content-type/payload size
  2. Validate network path and resolver reachability
  3. Keep fail-closed mode active until root cause confirmed

### 2) Revoked-cache dependency spike
- Signals:
  - `revoked_cache_hit_total`
  - `revoked_cache_store_total`
- Warning pattern: cache hits increase rapidly while status-source-unavailable denials also increase
- Critical pattern: sustained high cache-hit growth with unresolved provider instability
- Action:
  1. Treat as potential status backend incident
  2. Investigate stale-risk exposure window (TTL settings)
  3. Reduce TTL if needed and restore provider reliability

### 3) Revocation pressure change
- Signal: `deny_credential_revoked_total`
- Warning: sudden step-up versus recent baseline
- Action:
  1. Validate issuer/key incident feed
  2. Confirm revocation source integrity
  3. Inform pilot stakeholders if impact is broad

### 4) WebAuthn evidence drift
- Signal: `deny_reauth_proof_invalid_total`
- Warning: sustained increase over baseline
- Action:
  1. Check RP-ID/origin/challenge/age config alignment
  2. Validate strict-mode metadata generation in clients
  3. Review recent re-auth policy/config changes

## Operational notes
- Evaluate thresholds per rolling window (e.g., 15-60 min) rather than raw lifetime totals.
- `kpi:check` behavior can be tuned with `KPI_FAIL_ON_WARNING` (default soft-fail on warnings).
- These thresholds are pilot defaults and should be tuned with real traffic.
