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
- `WHAT_MITCH_IS_NOT.md` — guardrails / positioning
