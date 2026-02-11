import assert from "assert";
import { generateKeyPairSync, sign } from "crypto";
import { verifyRequest } from "../api/verifierRoutes";
import { computeRequestHash } from "../binding/requestHash";
import { VerificationRequestV0 } from "../types/api";
import { PolicyManifestV0 } from "../types/policy";
import { ResolveKey } from "../proof/keyResolver";

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

  console.log("core tests passed");
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
