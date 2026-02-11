"use strict";
/**
 * PersonalDataVault (Layer 1)
 *
 * CONSTRAINTS:
 * - Only stores encrypted/raw user data locally
 * - NEVER receives AccessRequest (doesn't know WHO is asking)
 * - NEVER receives ConsentDecision (doesn't know IF access is allowed)
 * - Only responds to direct category queries from Proof Engine
 * - No knowledge of external systems or policies
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.PersonalDataVault = void 0;
class PersonalDataVault {
    /**
     * Initialize vault with dummy user (Phase 0 simulation only)
     */
    constructor() {
        this.vault = new Map();
        // Dummy data for testing - never real data
        this.vault.set("user_001", {
            userId: "user_001",
            age: 27,
            email: "user@example.local"
        });
    }
    /**
     * Internal: Retrieve raw data for a specific category
     *
     * @param userId - System user ID
     * @param category - What data? (e.g., "age")
     * @returns The raw value, or null if not found
     *
     * SECURITY: This method is ONLY called by ProofEngine.
     * It returns the raw value, but the Proof Engine MUST NOT expose it.
     */
    retrieveDataByCategory(userId, category) {
        const userData = this.vault.get(userId);
        if (!userData)
            return null;
        // Explicitly handle each category - no shortcuts
        switch (category) {
            case "age":
                return userData.age;
            case "email":
                return userData.email;
            default:
                return null;
        }
    }
    /**
     * User-facing audit: what data do I have?
     * This is for the USER to review, not for external systems.
     */
    getUserDataSummary(userId) {
        const userData = this.vault.get(userId);
        if (!userData)
            return [];
        return [
            { category: "age", present: userData.age !== undefined },
            { category: "email", present: userData.email !== undefined }
        ];
    }
}
exports.PersonalDataVault = PersonalDataVault;
