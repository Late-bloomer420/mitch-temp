"use strict";
/**
 * ExternalInterface (Layer 4)
 *
 * CONSTRAINTS:
 * - ONLY receives and sends proofs
 * - Stateless - no data storage
 * - Orchestrates the layer chain: Request → Policy → Proof → Response
 * - Never touches raw data
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExternalInterface = void 0;
exports.createSystem = createSystem;
const PolicyEngine_1 = require("../policy/PolicyEngine");
const ProofEngine_1 = require("../proof/ProofEngine");
const PersonalDataVault_1 = require("../vault/PersonalDataVault");
class ExternalInterface {
    constructor(policyEngine, proofEngine) {
        this.policyEngine = policyEngine;
        this.proofEngine = proofEngine;
    }
    /**
     * Handle external access request (public API)
     *
     * Flow:
     * 1. External system sends AccessRequest
     * 2. Policy engine decides: allowed?
     * 3. Proof engine generates abstract proof (no data)
     * 4. Return proof to external system
     *
     * @param request - What is being asked for?
     * @returns Proof (abstract, no raw data exposed)
     */
    handleAccessRequest(request) {
        const proofs = [];
        // Step 1: Policy evaluation
        const decision = this.policyEngine.evaluateAccess(request);
        // Step 2: For each requested category, generate proof
        for (const category of request.dataCategories) {
            const proof = this.proofEngine.generateProof(decision, request.userId, category);
            proofs.push(proof);
        }
        return proofs;
    }
}
exports.ExternalInterface = ExternalInterface;
/**
 * Factory to instantiate the complete system (Phase 0)
 */
function createSystem() {
    const vault = new PersonalDataVault_1.PersonalDataVault();
    const policyEngine = new PolicyEngine_1.PolicyEngine();
    const proofEngine = new ProofEngine_1.ProofEngine(vault);
    const externalInterface = new ExternalInterface(policyEngine, proofEngine);
    return {
        interface: externalInterface,
        vault: vault
    };
}
