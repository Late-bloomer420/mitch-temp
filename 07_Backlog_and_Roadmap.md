# Backlog & Roadmap (Concept Phase → Implementation)

Stand: 2026-02-11  
Status: **CONCEPT PHASE (T0)** — wir starten bewusst “bei Null”.  
Hinweis: Frühere Task-IDs (T-37..T-40) bleiben als **spätere Phase** referenzierbar, gelten aber **nicht** als “done” im Concept-Reset.

---

## T0 — Concept Phase (Definition of Done)
T0 ist abgeschlossen, wenn wir **schriftlich** und **prüfbar** haben:

- **System Model** (Actors, Trust boundaries, threat model, invariants)
- **PII Boundary** (was darf wo existieren; was ist verboten; Metadaten-Controls)
- **Policy Model** (Manifest-Schema, Semantik, Fail-closed Regeln, Gate precedence)
- **Proof Strategy** (welcher Nachweis-Typ für welche Predicate-Klasse)
- **Recovery Strategy** (ohne zentrale Backdoors, minimal linkable)
- **Audit Strategy** (WORM-Events, PII-minimal, verify-only)
- **Prototype Plan** (MVP scope + test strategy + success metrics)

---

## T0 Backlog (Concept Tasks)

### T0-01 Scope & Non-Goals (Guardrails)
**Objective:** Projektgrenzen so scharf, dass “Privacy Drift” unmöglich wird.  
**Deliverable:** “What miTch is / is not” + automatische Reject-Kriterien.  
**Notes:** Muss explizit *zentrale Speicherung*, *Profiling*, *Blockchain-Core*, *Custody*, *trust-us* ausschließen.

### T0-02 Actor Model & Trust Boundaries
**Objective:** Eindeutig: wer weiß was, wer darf was, wer kann was attacken.  
**Deliverable:** Diagramm + textuelle Spezifikation der Trust Boundaries.

### T0-03 Data Classification & PII Boundary Spec
**Objective:** Datenklassen (PII, quasi-identifier, metadata) + zulässige Lebensdauer.  
**Deliverable:** Dateninventar + “ephemeral by default” Regeln + Vernichtungsmechanik.

### T0-04 Metadata Threats & Controls
**Objective:** Linkability/Correlation als First-Class Risiko behandeln.  
**Deliverable:** Liste der Leak-Vektoren + Controls (pairwise IDs, routing, padding, TTL stores, logging discipline).  
**Fail-closed rule:** Wenn Metadata-Exposure nicht bewertet werden kann → deny oder degrade.

### T0-05 Policy Manifest Schema (v0)
**Objective:** maschinenlesbares Policy-Format, das deterministisch evaluiert werden kann.  
**Deliverable:** JSON Schema + Beispiele (Age gate, residency, eligibility).  
**Key properties:** versioning, predicate set, binding requirements, minimization constraints, deny-precedence.

### T0-06 Policy Semantics & Gate Precedence
**Objective:** Formal: wie wird evaluiert; was passiert bei Missing Path/Schema mismatch.  
**Deliverable:** Semantik-Dokument + “Fail-closed checklist”.

### T0-07 Proof Strategy Matrix
**Objective:** Zu jedem Predicate eine geeignete Proof-Art definieren.  
**Deliverable:** Matrix:
- boolean predicates (>=18)
- set membership
- range proofs
- attribute equality
- non-repudiation vs privacy trade-offs  
**Notes:** Keine Proof-Art wählen, die RP-übergreifende Linkability erzeugt.

### T0-08 Request/Response Binding (Concept)
**Objective:** Replay & token forwarding verhindern.  
**Deliverable:** Binding spec (request hash, audience, nonce, expiry, channel binding optional).  
**Notes:** Bindung muss RP-spezifisch sein; keine globalen Correlation IDs.

### T0-09 Key Management & Key Protection Levels (Concept)
**Objective:** Honest model: software-only vs hardware-backed; keine TEE-Mythen.  
**Deliverable:** Key lifecycle (generate, use, rotate, destroy) + ProtectionLevel taxonomy + honesty constraints.

### T0-10 Recovery (Social / Multi-device / Migration) — Concept
**Objective:** Recovery ohne zentrale Backdoor, minimal linkable.  
**Deliverable:** Recovery flow options + threat analysis (guardian collusion, coercion, phishing).  
**Fail-closed rule:** Recovery uncertainty → deny/reset with explicit user consent.

### T0-11 Audit & Accountability (WORM, PII-minimal)
**Objective:** Auditierbarkeit ohne PII-Offenlegung.  
**Deliverable:** Event taxonomy + retention rules + verification story.  
**Notes:** Logs dürfen keine Langzeitprofile erzeugen (TTL/aggregation/coarse timestamps).

### T0-12 Compliance Mapping (Non-binding)
**Objective:** EU-logische Einordnung (GDPR by construction, proportionality, eIDAS2 alignment).  
**Deliverable:** Mapping-Tabelle “principle → mechanism → evidence”.

### T0-13 Developer Surface (SDK/API) — Concept
**Objective:** RP-Integration minimal & safe.  
**Deliverable:** API surface spec: request format, policy retrieval, verification endpoint expectations, error semantics.

### T0-14 Test Strategy & Metrics (Concept)
**Objective:** Security/Privacy messbar machen.  
**Deliverable:** Invariant-driven test plan (TP/FP/TN/FN für policy evaluation; replay tests; metadata budget checks).

---

## Post-T0 Phases (nur Referenz, keine “Done”-Claims)

### T1 — Security Hygiene (Hardening)
- **T1-01** WORM Audit Trail (vormals T-37)
- **T1-02** AAD / Context Binding (vormals T-38)
- **T1-03** Rate Limiting (vormals T-39)
- **T1-04** Nonce Store Hardening (vormals T-40)

### T2 — Selective Disclosure / ZK Core
- Predicate proofs (SD-JWT / BBS+ / mdoc je nach Matrix)
- Verification library + deterministic policy gates
- Metadata minimization in transport & logging

### T3 — MVP Pilot (Regulated)
- One issuer + 2 predicates (z. B. >=18 + residency)
- 2 RPs (unterschiedliche risk profiles)
- Audit verification demo without PII

---

## Suggested Next Actions (wenn wir morgen weitermachen)
1. Finalisiere T0-02/03/04 als “System Model v0”.
2. Policy Manifest v0 (T0-05) + 2 Beispiel-Policies.
3. Proof Strategy Matrix (T0-07) mit klarer Auswahl pro Predicate.

## Added execution artifacts (2026-02-11)
- `11_MVP_Gap_Analysis.md`
- `12_MVP_Execution_Plan_6_Weeks.md`
- `13_MVP_Readiness_Checklist.md`

Empfohlene Nutzung:
- Gap-Analyse als Priorisierungsbasis
- 6-Wochen-Plan als Umsetzungsboard
- Readiness-Checklist als Pilot-Gate (Go/No-Go)
