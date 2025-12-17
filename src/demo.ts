/**
 * Phase 0 Demonstration
 * 
 * Shows the layer chain in action with dummy requests.
 * No real data leaves the vault. No raw values reach external systems.
 */

import { createSystem } from "./interface/ExternalInterface";
import { AccessRequest } from "./types/AccessRequest";

function demo() {
  console.log("=== PHASE 0: Privacy-First System Demo ===\n");

  // Create the system
  const { interface: externalAPI, vault } = createSystem();

  // Show what the vault has (user perspective)
  console.log("USER'S DATA VAULT:");
  const userSummary = vault.getUserDataSummary("user_001");
  userSummary.forEach((item) => {
    console.log(`  ${item.category}: ${item.present ? "present" : "not present"}`);
  });
  console.log();

  // Test 1: Age verification request (should be allowed)
  console.log("TEST 1: Age Verification Request");
  const ageRequest: AccessRequest = {
    requestId: "req_001",
    userId: "user_001",
    dataCategories: ["age"],
    purpose: "age_gate",
    timestamp: Date.now()
  };
  console.log("Request:", ageRequest);
  const ageProofs = externalAPI.handleAccessRequest(ageRequest);
  console.log("Proofs received:");
  ageProofs.forEach((proof) => {
    console.log(
      `  Type: ${proof.proofType}, Valid: ${proof.isValid}, Expires: ${new Date(proof.expiresAt || 0).toISOString()}`
    );
  });
  console.log("  ⚠️  NOTE: External system only sees 'age_over_18', not the value 27\n");

  // Test 2: Email request (should be denied)
  console.log("TEST 2: Email Access Request (Denied)");
  const emailRequest: AccessRequest = {
    requestId: "req_002",
    userId: "user_001",
    dataCategories: ["email"],
    purpose: "marketing",
    timestamp: Date.now()
  };
  console.log("Request:", emailRequest);
  const emailProofs = externalAPI.handleAccessRequest(emailRequest);
  console.log("Proofs received:");
  emailProofs.forEach((proof) => {
    console.log(`  Type: ${proof.proofType}, Valid: ${proof.isValid}`);
  });
  console.log("  ⚠️  NOTE: Policy denied email access. Proof is invalid.\n");

  // Test 3: Unknown purpose (should be denied)
  console.log("TEST 3: Age request with unknown purpose (Denied)");
  const unknownRequest: AccessRequest = {
    requestId: "req_003",
    userId: "user_001",
    dataCategories: ["age"],
    purpose: "unknown_purpose",
    timestamp: Date.now()
  };
  console.log("Request:", unknownRequest);
  const unknownProofs = externalAPI.handleAccessRequest(unknownRequest);
  console.log("Proofs received:");
  unknownProofs.forEach((proof) => {
    console.log(`  Type: ${proof.proofType}, Valid: ${proof.isValid}`);
  });
  console.log();

  console.log("=== END DEMO ===");
  console.log("\nKEY OBSERVATIONS:");
  console.log("  ✓ Raw data never leaves the vault");
  console.log("  ✓ External systems only see abstract proofs (yes/no + type)");
  console.log("  ✓ Policy engine never sees raw data");
  console.log("  ✓ Layers are strictly separated");
  console.log("  ✓ Every decision is auditable");
}

// Run if this file is executed directly
if (require.main === module) {
  demo();
}

export { demo };
