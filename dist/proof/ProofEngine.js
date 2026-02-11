"use strict";
/**
 * ProofEngine (Layer 3)
 *
 * CONSTRAINTS:
 * - Receives ConsentDecision (is access allowed?)
 * - Calls Vault to get raw data (only if allowed)
 * - NEVER exposes raw data
 * - Generates minimal proof (yes/no + proof type)
 * - Converts data validation into abstract claim
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProofEngine = void 0;
class ProofEngine {
    constructor(vault) {
        this.vault = vault;
    }
    /**
     * Generate proof based on decision and data
     *
     * @param decision - Can we access the data?
     * @param userId - Who is asking?
     * @param category - What category of data?
     * @returns Minimal proof (only isValid and type, no raw data)
     *
     * SECURITY: Even if data is retrieved, proof is abstract.
     * Example: age 27 -> "age_over_18" proof, not the number itself.
     */
    generateProof(decision, userId, category) {
        const proof = {
            requestId: decision.requestId,
            isValid: false,
            proofType: `${category}_proof`,
            generatedAt: Date.now(),
            expiresAt: decision.constraints?.validUntil
        };
        // If decision denies access, proof is invalid (but doesn't say why)
        if (!decision.allowed) {
            return proof;
        }
        // Access allowed - retrieve data and validate
        const rawData = this.vault.retrieveDataByCategory(userId, category);
        if (rawData === null) {
            proof.isValid = false;
            return proof;
        }
        // Validate data based on category (convert to abstract proof)
        proof.isValid = this.validateAndAbstract(category, rawData, proof);
        return proof;
    }
    /**
     * Internal: Validate data and abstract it into proof type
     *
     * This is where raw data is touched, but NEVER exposed.
     * The proof returned is always abstract.
     */
    validateAndAbstract(category, rawData, proof) {
        switch (category) {
            case "age":
                // Check if age is a number and >= 0
                if (typeof rawData === "number" && rawData >= 0) {
                    // Convert to abstract proof claim
                    if (rawData >= 18) {
                        proof.proofType = "age_over_18";
                    }
                    else {
                        proof.proofType = "age_under_18";
                    }
                    return true;
                }
                return false;
            case "email":
                // Check if email is a string (never expose the actual email)
                if (typeof rawData === "string" && rawData.length > 0) {
                    proof.proofType = "email_verified";
                    return true;
                }
                return false;
            default:
                return false;
        }
    }
}
exports.ProofEngine = ProofEngine;
