import { VerificationRequestV0, VerificationResponseV0 } from "../types/api";
import { PolicyManifestV0 } from "../types/policy";
import { InMemoryNonceStore } from "../binding/nonceStore";
import { validateBinding } from "../binding/validateBinding";
import { evaluatePolicy } from "../policy/evaluator";
import { verifyProofBundle } from "../proof/verifier";

const nonceStore = new InMemoryNonceStore();

function deny(requestId: string, decisionCode: string): VerificationResponseV0 {
  return {
    version: "v0",
    requestId,
    decision: "DENY",
    decisionCode,
    claimsSatisfied: [],
    receiptRef: "aqdr:pending",
    verifiedAt: new Date().toISOString(),
  };
}

/**
 * Minimal verifier orchestration for MVP scaffolding.
 * Gate order: schema -> binding -> policy -> (crypto placeholder) -> receipt
 */
export async function verifyRequest(
  request: VerificationRequestV0,
  policy: PolicyManifestV0,
  runtimeAudience: string
): Promise<VerificationResponseV0> {
  try {
    // binding gate
    const binding = await validateBinding(request, runtimeAudience, nonceStore, {
      clockSkewSeconds: 90,
      nonceTtlSeconds: 600,
    });

    if (!binding.ok) return deny(request.requestId, binding.code ?? "DENY_INTERNAL_SAFE_FAILURE");

    // policy gate
    const decision = evaluatePolicy(request, policy);
    if (decision.decision === "DENY") return deny(request.requestId, decision.decisionCode);

    // crypto verify gate (MVP stub wired in)
    const crypto = verifyProofBundle(request.proofBundle);
    if (!crypto.ok) {
      const code = crypto.reason === "unsupported_alg"
        ? "DENY_CRYPTO_UNSUPPORTED_ALG"
        : "DENY_CRYPTO_VERIFY_FAILED";
      return deny(request.requestId, code);
    }

    return {
      version: "v0",
      requestId: request.requestId,
      decision: "ALLOW",
      decisionCode: "ALLOW_MINIMAL_PROOF_VALID",
      claimsSatisfied: decision.claimsSatisfied,
      receiptRef: "aqdr:pending",
      verifiedAt: new Date().toISOString(),
    };
  } catch {
    return deny(request.requestId, "DENY_INTERNAL_SAFE_FAILURE");
  }
}
