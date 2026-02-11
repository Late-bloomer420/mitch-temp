import { verifyRequest } from "./api/verifierRoutes";
import { computeRequestHash } from "./binding/requestHash";
import { VerificationRequestV0 } from "./types/api";
import { PolicyManifestV0 } from "./types/policy";

const policy: PolicyManifestV0 = {
  version: "v0",
  id: "policy-v0-age",
  purposes: ["age_gate_checkout"],
  predicates: [{ name: "age_gte", allowed: true }],
  failClosed: true,
};

const requestBase: Omit<VerificationRequestV0, "binding"> = {
  version: "v0",
  requestId: "req-1",
  rp: { id: "rp.example", audience: "rp.example" },
  purpose: "age_gate_checkout",
  claims: [{ type: "predicate", name: "age_gte", value: 18 }],
  proofBundle: { format: "sd-jwt-vc", proof: "opaque-proof", alg: "EdDSA" },
  policyRef: "policy-v0-age",
};

async function run(): Promise<void> {
  const provisional: VerificationRequestV0 = {
    ...requestBase,
    binding: {
      nonce: "nonce-1",
      requestHash: "",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    },
  };

  const request: VerificationRequestV0 = {
    ...provisional,
    binding: {
      ...provisional.binding,
      requestHash: computeRequestHash(provisional),
    },
  };

  const result = await verifyRequest(request, policy, "rp.example");
  console.log(result);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
