# miTch — Context Pack (for AI + humans)

**Purpose:** This folder is a compact, high-signal context bundle for the *miTch* project (user-sovereign identity + authorization).
It is designed to be pasted into other AI systems (Gemini, Claude, AI Studio) or shared with collaborators without losing the core invariants.

**Build date:** 2026-02-11 (Europe/Vienna)

## How to use
- Start with: `01_Project_OnePager.md`
- If the other system tends to hallucinate or “optimize UX by breaking privacy”, also paste:
  - `02_Principles_and_NonNegotiables.md`
  - `04_Data_Flows_and_PII_Boundaries.md`
  - `05_Threat_Model.md`
  - `08_Prompts_for_Collaboration.md` (ready-made system prompts)

## Integrity notes
- These documents prioritize **privacy, minimization, user sovereignty, and fail-closed logic** over convenience.
- Anything implying centralized identity storage, profiling/analytics, blockchain dependency, asset custody, or “trust us” security is considered **out of scope** and must be rejected.

## Contents
- `01_Project_OnePager.md` — shareable overview
- `02_Principles_and_NonNegotiables.md` — invariants + constraints
- `03_Architecture_Core.md` — components + responsibilities
- `04_Data_Flows_and_PII_Boundaries.md` — how to keep PII inside state DBs
- `05_Threat_Model.md` — failure analysis, metadata leaks, mitigations
- `06_Policy_Engine_Spec.md` — policy artifacts + enforcement rules
- `07_Backlog_and_Roadmap.md` — active concept-phase backlog/roadmap
- `archive/07_Backlog_and_Implemented_Tasks_legacy_snapshot.md` — legacy snapshot (“implemented” framing)
- `08_Prompts_for_Collaboration.md` — system prompts for other AIs
- `09_Glossary.md`
- `10_Open_Questions.md`
- `11_MVP_Gap_Analysis.md` — technical gaps from concept to MVP
- `12_MVP_Execution_Plan_6_Weeks.md` — practical implementation plan
- `13_MVP_Readiness_Checklist.md` — go/no-go criteria for pilot
- `14_MVP_Risk_Register.md` — active risk tracking for MVP delivery
- `15_MVP_Work_Breakdown.md` — epics/tasks/owners/estimates for delivery
- `16_MVP_Architecture_Decision_Log.md` — ADR index for hard technical choices
- `17_API_Contract_v0.md` — requester/verifier contract draft for MVP
- `18_Test_Plan_Adversarial_and_E2E.md` — adversarial + E2E test strategy
- `19_Data_Retention_Matrix.md` — field-level retention and purge policy
- `20_Canonicalization_and_Binding_Spec_v0.md` — deterministic binding + anti-replay spec
- `21_Deny_Reason_Code_Catalog.md` — normative deny code source of truth
- `22_Pilot_Go_NoGo_Template.md` — formal pilot decision template
- `23_Implementation_Sequence_v0.md` — concrete build order to MVP
- `24_Repo_Setup_and_GitHub_Linking.md` — current git/remote status + linking steps
- `25_Sprint_1_Task_Board.md` — week-1 execution board with acceptance criteria
- `26_Repository_Hygiene_Plan.md` — cleanup plan for dependency/build artifacts
- `27_ADR_Closure_Record.md` — accepted MVP architecture decisions (binding)
- `28_Test_Vector_Pack_v0.md` — canonicalization/binding normative vectors
- `29_Implementation_Scaffold.md` — target module/file structure for coding phase
- `30_First_Code_Tasks.md` — immediate implementation backlog (top 10)
- `31_Interface_Definitions_v0.md` — internal contracts for parallel implementation
- `32_Config_Profile_v0.md` — safe runtime defaults and config shape
- `33_Business_Case_01_Age_Verification.md` — first business case definition (ICP/value/KPI)
- `34_Use_Case_Prioritization_Matrix.md` — weighted use-case selection matrix
- `35_Product_Architecture_Layers.md` — scope-safe layering (Core/Shield/Orchestrator)
- `36_Phase2_Shield_and_AI_Orchestration_Roadmap.md` — future expansion roadmap after Core MVP
- `37_Privacy_Policy_Language_for_Web_and_AI.md` — shared policy grammar concept for web+AI controls
- `38_KPI_Framework_Core_and_Business.md` — security + business KPI baseline and targets
- `39_Pilot_KPI_Dashboard_Template.md` — weekly KPI reporting template for pilot operations
- `40_KPI_Definitions_and_Data_Sources.md` — formulas, telemetry sources, and KPI ownership
- `41_Localhost_Test_Quickstart.md` — run/test instructions for local verifier service
- `42_Pilot_Critical_Config.md` — required env config for protected pilot operation
- `src/api/metrics.ts` — in-service counters for basic KPI telemetry (`GET /metrics`)
- `src/api/eventLog.ts` + `src/api/kpi.ts` — structured audit events and derived KPI snapshot (`GET /kpi`)
- `src/api/auditVerify.ts` — audit hash-chain integrity verification (`GET /audit/verify`)
- `LICENSE` — MIT open-source license
- `NOTICE` — ownership and positioning notice
- `CODEOWNERS` — default review ownership
- `CONTRIBUTING.md` — contribution workflow and required checks
- `WHAT_MITCH_IS_NOT.md` — guardrails / positioning
