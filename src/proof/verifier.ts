import { ProofBundleV0 } from "../types/api";

const ALLOWED_ALGS = new Set(["EdDSA"]);

export function verifyProofBundle(bundle: ProofBundleV0): { ok: boolean; reason?: string } {
  if (!bundle || typeof bundle !== "object") return { ok: false, reason: "missing_bundle" };
  if (!bundle.proof || bundle.proof.trim().length === 0) return { ok: false, reason: "empty_proof" };
  if (!bundle.alg || !ALLOWED_ALGS.has(bundle.alg)) return { ok: false, reason: "unsupported_alg" };

  // MVP stub: cryptographic signature/proof verification integration comes next.
  return { ok: true };
}
