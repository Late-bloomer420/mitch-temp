import assert from "assert";
import { createServer } from "http";
import { generateKeyPairSync, sign } from "crypto";
import { verifyRequest } from "../api/verifierRoutes";
import { computeRequestHash } from "../binding/requestHash";
import { VerificationRequestV0 } from "../types/api";
import { PolicyManifestV0 } from "../types/policy";
import { ResolveKey } from "../proof/keyResolver";
import { resetProofFatigue } from "../api/proofFatigue";
import { resetRateLimiter } from "../api/rateLimiter";

function b64u(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

const policy: PolicyManifestV0 = {
  version: "v0",
  id: "policy-v0-age",
  purposes: ["age_gate_checkout"],
  predicates: [{ name: "age_gte", allowed: true }],
  failClosed: true,
};

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
const keyId = "kid-demo-1";

const resolveKey: ResolveKey = async (kid?: string) => {
  if (kid !== keyId) return { status: "missing" };
  return { status: "active", publicKeyPem };
};

function buildRequest(): VerificationRequestV0 {
  const base: VerificationRequestV0 = {
    version: "v0",
    requestId: `req-${Date.now()}-${Math.random()}`,
    rp: { id: "rp.example", audience: "rp.example" },
    purpose: "age_gate_checkout",
    claims: [{ type: "predicate", name: "age_gte", value: 18 }],
    proofBundle: { format: "sd-jwt-vc", proof: "", keyId, alg: "EdDSA" },
    binding: {
      nonce: `nonce-${Date.now()}-${Math.random()}`,
      requestHash: "",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    },
    policyRef: "policy-v0-age",
  };

  const requestHash = computeRequestHash(base);
  const signature = sign(null, Buffer.from(requestHash, "utf8"), privateKey);
  base.binding.requestHash = requestHash;
  base.proofBundle.proof = b64u(signature);
  return base;
}

async function run(): Promise<void> {
  resetRateLimiter();
  resetProofFatigue();

  // 1) happy path
  const happy = await verifyRequest(buildRequest(), policy, "rp.example", resolveKey);
  assert.equal(happy.decisionCode, "ALLOW_MINIMAL_PROOF_VALID");

  // 2) replay
  const replayReq = buildRequest();
  const first = await verifyRequest(replayReq, policy, "rp.example", resolveKey);
  assert.equal(first.decision, "ALLOW");
  const second = await verifyRequest(replayReq, policy, "rp.example", resolveKey);
  assert.equal(second.decisionCode, "DENY_BINDING_NONCE_REPLAY");

  // 3) audience mismatch
  const aud = await verifyRequest(buildRequest(), policy, "other.example", resolveKey);
  assert.equal(aud.decisionCode, "DENY_BINDING_AUDIENCE_MISMATCH");

  // 4) expiry
  const expired = buildRequest();
  expired.binding.expiresAt = new Date(Date.now() - 3600_000).toISOString();
  expired.binding.requestHash = computeRequestHash(expired);
  expired.proofBundle.proof = b64u(sign(null, Buffer.from(expired.binding.requestHash, "utf8"), privateKey));
  const exp = await verifyRequest(expired, policy, "rp.example", resolveKey);
  assert.equal(exp.decisionCode, "DENY_BINDING_EXPIRED");

  // 5) crypto bad signature
  const bad = buildRequest();
  bad.proofBundle.proof = "ZmFrZQ";
  const badSig = await verifyRequest(bad, policy, "rp.example", resolveKey);
  assert.equal(badSig.decisionCode, "DENY_CRYPTO_VERIFY_FAILED");

  // 6) unsupported alg
  const wrongAlg = buildRequest();
  wrongAlg.proofBundle.alg = "RS256";
  const wrongAlgRes = await verifyRequest(wrongAlg, policy, "rp.example", resolveKey);
  assert.equal(wrongAlgRes.decisionCode, "DENY_CRYPTO_UNSUPPORTED_ALG");

  // 7) revoked key
  const revokedResolver: ResolveKey = async () => ({ status: "revoked" });
  const revoked = await verifyRequest(buildRequest(), policy, "rp.example", revokedResolver);
  assert.equal(revoked.decisionCode, "DENY_CRYPTO_KEY_STATUS_INVALID");

  // 7b) missing key
  const missingResolver: ResolveKey = async () => ({ status: "missing" });
  const missing = await verifyRequest(buildRequest(), policy, "rp.example", missingResolver);
  assert.equal(missing.decisionCode, "DENY_CRYPTO_KEY_STATUS_INVALID");

  // 7c) status unavailable (high-risk purpose fail-closed)
  const unavailableResolver: ResolveKey = async () => ({ status: "unavailable" });
  const unavailable = await verifyRequest(buildRequest(), policy, "rp.example", unavailableResolver);
  assert.equal(unavailable.decisionCode, "DENY_STATUS_SOURCE_UNAVAILABLE");

  // 7d) revoked credential id
  resetRateLimiter();
  process.env.REVOKED_CREDENTIAL_IDS = "cred-revoked-1";
  const revokedCredReq = buildRequest();
  revokedCredReq.proofBundle.credentialId = "cred-revoked-1";
  const revokedCred = await verifyRequest(revokedCredReq, policy, "rp.example", resolveKey);
  assert.equal(revokedCred.decisionCode, "DENY_CREDENTIAL_REVOKED");
  delete process.env.REVOKED_CREDENTIAL_IDS;

  // 7e) credential status provider unavailable (http mode)
  process.env.CREDENTIAL_STATUS_MODE = "http";
  process.env.CREDENTIAL_STATUS_URL = "http://127.0.0.1:9/revoked";
  process.env.CREDENTIAL_STATUS_TIMEOUT_MS = "10";
  const statusUnavailableReq = buildRequest();
  statusUnavailableReq.proofBundle.credentialId = "cred-check-1";
  const statusUnavailableRes = await verifyRequest(statusUnavailableReq, policy, "rp.example", resolveKey);
  assert.equal(statusUnavailableRes.decisionCode, "DENY_STATUS_SOURCE_UNAVAILABLE");
  delete process.env.CREDENTIAL_STATUS_MODE;
  delete process.env.CREDENTIAL_STATUS_URL;
  delete process.env.CREDENTIAL_STATUS_TIMEOUT_MS;

  // 7f) revoked-only cache behavior (http mode)
  process.env.CREDENTIAL_STATUS_MODE = "http";
  process.env.CREDENTIAL_STATUS_URL = "http://127.0.0.1:18084/revoked";
  process.env.CREDENTIAL_STATUS_TIMEOUT_MS = "200";
  process.env.CREDENTIAL_STATUS_REVOKED_CACHE_TTL_MS = "10000";
  const revokedCacheServer = createServer((_, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ revokedCredentialIds: ["cred-cache-1"] }));
  });
  await new Promise<void>((resolve) => revokedCacheServer.listen(18084, resolve));

  const cachePrimeReq = buildRequest();
  cachePrimeReq.proofBundle.credentialId = "cred-cache-1";
  const cachePrimeRes = await verifyRequest(cachePrimeReq, policy, "rp.example", resolveKey);
  assert.equal(cachePrimeRes.decisionCode, "DENY_CREDENTIAL_REVOKED");
  await new Promise<void>((resolve, reject) => revokedCacheServer.close((err) => (err ? reject(err) : resolve())));

  // provider down now; same revoked credential should still deny from local revoked-only cache
  process.env.CREDENTIAL_STATUS_URL = "http://127.0.0.1:9/revoked";
  const cacheHitReq = buildRequest();
  cacheHitReq.proofBundle.credentialId = "cred-cache-1";
  const cacheHitRes = await verifyRequest(cacheHitReq, policy, "rp.example", resolveKey);
  assert.equal(cacheHitRes.decisionCode, "DENY_CREDENTIAL_REVOKED");

  // different credential must NOT get allow from cache; should fail closed on unavailable source
  const cacheMissReq = buildRequest();
  cacheMissReq.proofBundle.credentialId = "cred-cache-2";
  const cacheMissRes = await verifyRequest(cacheMissReq, policy, "rp.example", resolveKey);
  assert.equal(cacheMissRes.decisionCode, "DENY_STATUS_SOURCE_UNAVAILABLE");

  delete process.env.CREDENTIAL_STATUS_MODE;
  delete process.env.CREDENTIAL_STATUS_URL;
  delete process.env.CREDENTIAL_STATUS_TIMEOUT_MS;
  delete process.env.CREDENTIAL_STATUS_REVOKED_CACHE_TTL_MS;

  // 7g) malformed credential status payload (http mode)
  const malformedStatusServer = createServer((_, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ unexpected: true }));
  });
  await new Promise<void>((resolve) => malformedStatusServer.listen(18081, resolve));

  process.env.CREDENTIAL_STATUS_MODE = "http";
  process.env.CREDENTIAL_STATUS_URL = "http://127.0.0.1:18081/revoked";
  process.env.CREDENTIAL_STATUS_TIMEOUT_MS = "200";
  const malformedProviderReq = buildRequest();
  malformedProviderReq.proofBundle.credentialId = "cred-check-2";
  const malformedProviderRes = await verifyRequest(malformedProviderReq, policy, "rp.example", resolveKey);
  assert.equal(malformedProviderRes.decisionCode, "DENY_STATUS_SOURCE_UNAVAILABLE");
  await new Promise<void>((resolve, reject) => malformedStatusServer.close((err) => (err ? reject(err) : resolve())));
  delete process.env.CREDENTIAL_STATUS_MODE;
  delete process.env.CREDENTIAL_STATUS_URL;
  delete process.env.CREDENTIAL_STATUS_TIMEOUT_MS;

  // 7g) status provider wrong content-type must fail closed
  const wrongCtServer = createServer((_, res) => {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(JSON.stringify({ revokedCredentialIds: [] }));
  });
  await new Promise<void>((resolve) => wrongCtServer.listen(18082, resolve));

  process.env.CREDENTIAL_STATUS_MODE = "http";
  process.env.CREDENTIAL_STATUS_URL = "http://127.0.0.1:18082/revoked";
  process.env.CREDENTIAL_STATUS_TIMEOUT_MS = "200";
  const wrongCtReq = buildRequest();
  wrongCtReq.proofBundle.credentialId = "cred-check-3";
  const wrongCtRes = await verifyRequest(wrongCtReq, policy, "rp.example", resolveKey);
  assert.equal(wrongCtRes.decisionCode, "DENY_STATUS_SOURCE_UNAVAILABLE");
  await new Promise<void>((resolve, reject) => wrongCtServer.close((err) => (err ? reject(err) : resolve())));

  delete process.env.CREDENTIAL_STATUS_MODE;
  delete process.env.CREDENTIAL_STATUS_URL;
  delete process.env.CREDENTIAL_STATUS_TIMEOUT_MS;

  // 7h) oversized status provider response must fail closed
  const oversizedServer = createServer((_, res) => {
    const payload = JSON.stringify({ revokedCredentialIds: ["x".repeat(5000)] });
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload),
    });
    res.end(payload);
  });
  await new Promise<void>((resolve) => oversizedServer.listen(18083, resolve));

  process.env.CREDENTIAL_STATUS_MODE = "http";
  process.env.CREDENTIAL_STATUS_URL = "http://127.0.0.1:18083/revoked";
  process.env.CREDENTIAL_STATUS_TIMEOUT_MS = "200";
  process.env.CREDENTIAL_STATUS_MAX_BYTES = "256";
  const oversizedReq = buildRequest();
  oversizedReq.proofBundle.credentialId = "cred-check-4";
  const oversizedRes = await verifyRequest(oversizedReq, policy, "rp.example", resolveKey);
  assert.equal(oversizedRes.decisionCode, "DENY_STATUS_SOURCE_UNAVAILABLE");
  await new Promise<void>((resolve, reject) => oversizedServer.close((err) => (err ? reject(err) : resolve())));

  delete process.env.CREDENTIAL_STATUS_MODE;
  delete process.env.CREDENTIAL_STATUS_URL;
  delete process.env.CREDENTIAL_STATUS_TIMEOUT_MS;
  delete process.env.CREDENTIAL_STATUS_MAX_BYTES;

  // 8) jurisdiction incompatibility
  process.env.REQUIRE_JURISDICTION_MATCH = "1";
  process.env.RUNTIME_JURISDICTION = "EU";
  const jurisdictionReq = buildRequest();
  jurisdictionReq.rp.jurisdiction = "US";
  const jurisdictionRes = await verifyRequest(jurisdictionReq, policy, "rp.example", resolveKey);
  assert.equal(jurisdictionRes.decisionCode, "DENY_JURISDICTION_INCOMPATIBLE");
  delete process.env.REQUIRE_JURISDICTION_MATCH;
  delete process.env.RUNTIME_JURISDICTION;

  // 9) malformed StatusList2021 shape in request schema
  const malformedStatusReq = buildRequest();
  malformedStatusReq.proofBundle.credentialStatus = {
    type: "StatusList2021Entry",
    statusListCredential: "https://status.example/list/1",
    // missing statusListIndex
  } as unknown as VerificationRequestV0["proofBundle"]["credentialStatus"];
  const malformedStatusRes = await verifyRequest(malformedStatusReq, policy, "rp.example", resolveKey);
  assert.equal(malformedStatusRes.decisionCode, "DENY_STATUS_SOURCE_UNAVAILABLE");

  // 10) StatusList2021 index revoke (env mode)
  process.env.CREDENTIAL_STATUS_MODE = "env";
  process.env.REVOKED_STATUS_LIST_INDEXES = "42,99";
  const revokedIndexReq = buildRequest();
  revokedIndexReq.proofBundle.credentialStatus = {
    type: "StatusList2021Entry",
    statusListCredential: "https://status.example/list/1",
    statusListIndex: "42",
  };
  const revokedIndexRes = await verifyRequest(revokedIndexReq, policy, "rp.example", resolveKey);
  assert.equal(revokedIndexRes.decisionCode, "DENY_CREDENTIAL_REVOKED");
  delete process.env.REVOKED_STATUS_LIST_INDEXES;
  delete process.env.CREDENTIAL_STATUS_MODE;

  // 11) unknown schema field
  const unknownFieldReq = {
    ...buildRequest(),
    sneaky: true,
  } as unknown;
  const unknownField = await verifyRequest(unknownFieldReq, policy, "rp.example", resolveKey);
  assert.equal(unknownField.decisionCode, "DENY_SCHEMA_UNKNOWN_FIELD");

  // 12) proof fatigue / re-auth required on repeated high-risk prompts
  process.env.PROOF_FATIGUE_WINDOW_SECONDS = "3600";
  process.env.PROOF_FATIGUE_MAX_HIGH_RISK_PROMPTS = "2";
  process.env.HIGH_RISK_PURPOSES = "age_gate_checkout";

  resetRateLimiter();
  resetProofFatigue();
  const hf1 = await verifyRequest(buildRequest(), policy, "rp.example", resolveKey);
  const hf2 = await verifyRequest(buildRequest(), policy, "rp.example", resolveKey);
  const hf3 = await verifyRequest(buildRequest(), policy, "rp.example", resolveKey);
  assert.equal(hf1.decision, "ALLOW");
  assert.equal(hf2.decision, "ALLOW");
  assert.equal(hf3.decisionCode, "DENY_REAUTH_REQUIRED");

  const reauthReq = buildRequest();
  reauthReq.meta = { reAuthRecent: true };
  const reauth = await verifyRequest(reauthReq, policy, "rp.example", resolveKey);
  assert.equal(reauth.decision, "ALLOW");

  // 13) strict re-auth evidence mode (webauthn scaffold)
  process.env.REQUIRE_STRONG_REAUTH = "1";
  process.env.WEBAUTHN_ASSERTION_ALLOWLIST = "assert-ok-1";
  resetProofFatigue();
  resetRateLimiter();

  await verifyRequest(buildRequest(), policy, "rp.example", resolveKey);
  await verifyRequest(buildRequest(), policy, "rp.example", resolveKey);

  const weakReauthReq = buildRequest();
  weakReauthReq.meta = { reAuthRecent: true };
  const weakReauthRes = await verifyRequest(weakReauthReq, policy, "rp.example", resolveKey);
  assert.equal(weakReauthRes.decisionCode, "DENY_REAUTH_PROOF_INVALID");

  const strongReauthReq = buildRequest();
  strongReauthReq.meta = { reAuthMethod: "webauthn", reAuthAssertion: "assert-ok-1" };
  const strongReauthRes = await verifyRequest(strongReauthReq, policy, "rp.example", resolveKey);
  assert.equal(strongReauthRes.decision, "ALLOW");

  delete process.env.REQUIRE_STRONG_REAUTH;
  delete process.env.WEBAUTHN_ASSERTION_ALLOWLIST;

  // 14) rate limit burst
  resetRateLimiter();
  let rateLimited = false;
  for (let i = 0; i < 20; i++) {
    const res = await verifyRequest(buildRequest(), policy, "rp.example", resolveKey);
    if (res.decisionCode === "DENY_RATE_LIMIT_EXCEEDED") {
      rateLimited = true;
      break;
    }
  }
  assert.equal(rateLimited, true);

  console.log("core tests passed");
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
