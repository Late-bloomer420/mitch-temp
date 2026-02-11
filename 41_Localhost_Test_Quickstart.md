# 41 — Localhost Test Quickstart

## Start server
```powershell
cd C:\Users\Admin\Documents\miTch
npm install
npm run compile
$env:RUNTIME_AUDIENCE="rp.example"
npm start
```

Server runs on `http://localhost:8080`.

## Health check
```powershell
Invoke-WebRequest -UseBasicParsing http://localhost:8080/health | Select-Object -ExpandProperty Content
```

## Verify test request (expected DENY for now, because demo key resolver is missing)
```powershell
$body = @{
  version = "v0"
  requestId = "req-local-1"
  rp = @{ id = "rp.example"; audience = "rp.example" }
  purpose = "age_gate_checkout"
  claims = @(@{ type = "predicate"; name = "age_gte"; value = 18 })
  proofBundle = @{ format = "sd-jwt-vc"; proof = "ZmFrZQ"; keyId = "kid-demo-1"; alg = "EdDSA" }
  binding = @{ nonce = "nonce-local-1"; requestHash = "dummy"; expiresAt = (Get-Date).AddMinutes(5).ToString("o") }
  policyRef = "policy-v0-age"
} | ConvertTo-Json -Depth 5

Invoke-WebRequest -UseBasicParsing http://localhost:8080/verify `
  -Method POST `
  -ContentType "application/json" `
  -Headers @{"x-correlation-id"="local-test-1"} `
  -Body $body | Select-Object -ExpandProperty Content
```

## Notes
- Current `/verify` path is wired and functional, but default key resolver returns `missing`.
- That is expected in current stage and useful for testing deny paths.
- Next step: wire real key resolver + signature-valid request generator for ALLOW over HTTP.
