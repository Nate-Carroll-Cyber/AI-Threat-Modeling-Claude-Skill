# Framework Crosswalk

Load this reference **only when the user requests** mapping to one of: STRIDE, MITRE ATLAS, OWASP LLM Top 10, OWASP Agentic AI Top 10, NIST AI RMF, or a cloud-provider AI security framework. MAESTRO is the primary spine; these are secondary lenses.

**Source**: MAESTRO v2.0, Section 12.

---

## When to include Section 11 (Framework Crosswalk) in the output

Include if the user:
- Explicitly names another framework ("map this to ATLAS", "give me OWASP Agentic Top 10 alignment", "map to the OWASP T1–T15 agentic threats / playbooks")
- Is in a compliance context where multiple frameworks are required (audit, vendor questionnaire)
- Has an existing security program built on STRIDE or another lens and is adding MAESTRO
- Requests the **full crosswalk** — any of "full framework crosswalk", "crosswalk to everything", "all frameworks", "every framework" (see "Full crosswalk mode" below)

Otherwise omit. Don't pad the output with crosswalks the user didn't ask for. The default — no Section 11 at all — is correct for the majority of assessments; crosswalks are a secondary lens that compete with the MAESTRO spine for the reader's attention, so they appear only on request.

### Scope of a single-framework request

When the user names one framework, emit only that subsection. Do not opportunistically add the others — naming ATLAS is not a request for NIST AI RMF. If two or three are named, emit those and only those.

### Full crosswalk mode (opt-in, off by default)

When — and only when — the user explicitly asks for all frameworks (the trigger phrases above), emit the complete Section 11 with all six subsections in this fixed order:

1. **11.1 STRIDE**
2. **11.2 MITRE ATLAS**
3. **11.3 OWASP LLM Top 10**
4. **11.4 OWASP Agentic AI Top 10 (ASI01–ASI10)**
5. **11.5 OWASP Agentic Threats & Mitigations (T1–T15)** — with the matching mitigation playbook cited per row
6. **11.6 NIST AI RMF** — lead with the Govern/Map/Measure/Manage function, pivot into the MAESTRO layer

Rules for full crosswalk mode, all of which preserve the skill's evidence discipline:
- **Map only the assessment's existing findings.** Each subsection re-expresses the Section 8 MAESTRO findings in the other framework's vocabulary. A crosswalk never introduces a new threat that Section 8 did not already establish on the evidence.
- **Omit empty cells; do not pad.** If the system has no evidenced threat for a given framework category, leave that row out rather than writing "N/A". State explicitly where a whole technique class is not mapped and why (e.g. "model-extraction techniques not mapped — no training/fine-tuning surface evidenced").
- **MAESTRO `L<n>-T<nn>` stays the canonical ID** in every row; the external framework ID is the secondary column.
- **Do not silently widen scope** beyond the standard external-attacker lenses. The TRAIT&R inverted-adversary lens is NOT part of the full crosswalk — it is a separate opt-in (`ai-control-trait-r.md`) with its own adversary direction and must not be folded into the ATLAS-keyed tables.
- **Preserve the per-framework "good at / bad at" framing.** Each subsection keeps its short paragraph stating what the framework can and cannot attest — this is where the NIST governance-lens caveat lives.

---

## MAESTRO + STRIDE

STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) is built for deterministic software. Use STRIDE for traditional components (APIs, databases) and MAESTRO for AI-specific components (models, agents, context windows).

Example mappings:

| STRIDE Category | MAESTRO Layer / Threat |
|---|---|
| Spoofing | L7 — Agent Identity Forgery (L7-T01) |
| Tampering | L3 — Data Poisoning (L3-T01, L3-T03) |
| Repudiation | L9 — Log Tampering (L9-T02), Audit Trail Gaps (L10-T05) |
| Information Disclosure | L2 — Model Inversion (L2-T06); L3 — Embedding Inversion (L3-T05) |
| Denial of Service | L1-T03; L4-T01 (infinite planning loop); L3-T07 (context overflow) |
| Elevation of Privilege | L4-T05 (delegation chain escalation); L7-T03, L7-T07 |

---

## MAESTRO + MITRE ATLAS

MITRE ATLAS is a knowledge base of adversarial tactics against ML systems organized by attack lifecycle stages. ATLAS provides the *attack techniques*; MAESTRO provides the *architectural context*.

Example mappings:

| ATLAS Tactic / Technique | MAESTRO Layer |
|---|---|
| ML Model Theft / ML Model Extraction | L2 (L2-T01) |
| Poison Training Data | L3 (L3-T01); L2 (L2-T02 for training-time) |
| Evade ML Model | L2 / L8 (L2-T03, L8-T01) |
| LLM Prompt Injection | L2 / L4 (L2-T03, L4-T02) |
| ML Supply Chain Compromise | L2 (L2-T04); L1 (L1-T01); L6 (L6-T04 for MCP server, L6-T05 for marketplace) |
| Discover ML Model Family | L6 (information disclosure via tool/API surface) |
| Exfiltration via ML Inference API | L6 (L6-T06); L2 (L2-T01 if extraction-style) |

**How to use in the assessment**: when an ATLAS technique applies, name the technique ID and the corresponding MAESTRO layer(s). Don't substitute MAESTRO for ATLAS — they're complementary.

**For technique-level granularity**, load `references/threat-technique-and-control-library.md`, which expands this high-level mapping into ~140 `AITech-*`/`AISubtech-*` techniques (each tagged OWASP + ATLAS + MAESTRO layer) and a FAIR-CAM control library. Use it when the user wants finer attack-technique detail than MAESTRO's per-layer sample threats, or a structured control source for Step 4.

---

## MAESTRO + OWASP LLM Top 10

OWASP LLM Top 10 focuses on LLM application security at the application layer. OWASP covers L4 and L6 primarily; MAESTRO provides full-stack coverage.

Example mappings:

| OWASP LLM Top 10 | MAESTRO Layer |
|---|---|
| LLM01 Prompt Injection | L2 + L4 (L2-T03, L4-T02) |
| LLM02 Insecure Output Handling | L4 / L6 |
| LLM03 Training Data Poisoning | L3 (L3-T01); L2 (L2-T02) |
| LLM04 Model Denial of Service | L1-T03; L3-T07; L4-T01 |
| LLM05 Supply Chain Vulnerabilities | L1 (L1-T01); L2 (L2-T04); L6 (L6-T04, L6-T05) |
| LLM06 Sensitive Information Disclosure | L3 (L3-T05); L2 (L2-T06); L6 (L6-T06) |
| LLM07 Insecure Plugin Design | L6 (L6-T04, L6-T08); agent skills/tool-registry surface |
| LLM08 Excessive Agency | L7 (L7-T03, L7-T04); L4 (L4-T04, L4-T07) |
| LLM09 Overreliance | L8 + L10 |
| LLM10 Model Theft | L2 (L2-T01) |

---

## MAESTRO + OWASP Agentic AI Top 10 (2026)

The OWASP Top 10 for Agentic Applications identifies the most critical risks specific to agentic AI systems. The Agent 3SRM (Annex) provides a canonical mapping of each OWASP risk to AICM controls, primary supply-chain roles, and MAESTRO architecture layers. Use this mapping directly when crosswalking — it is more precise than the high-level pattern in MAESTRO §12.5.

### Canonical OWASP Agentic Top 10 → AICM/MAESTRO mapping (3SRM Annex)

| OWASP Risk | Primary AICM Role(s) | Key AICM Controls | MAESTRO Layer(s) |
|---|---|---|---|
| **ASI01 Agent Goal Hijacking** | MP + AP / AIC | AIS-08 Input Validation, AIS-15 Prompt Differentiation, TVM-11 Guardrails, MDS-07 Hardening | L2, L8 |
| **ASI02 Tool Misuse** | OSP + AP / AIC | AIS-11 Agent Boundaries, AIS-13 Sandboxing, IAM-18 Output Mod Auth | L6, L8, L7 |
| **ASI03 Identity & Privilege Abuse** | AIC + CSP | IAM-01–19, IAM-18, GRC-15 Human Supervision | L7, L4 |
| **ASI04 Supply Chain Vulnerabilities** | AIC (due diligence) + all | STA-01–16, STA-16 BOM, MDS-09 Model Signing, AIS-12 Source Code | L6, L2, L5 |
| **ASI05 Unexpected Code Execution** | CSP + OSP + AP | AIS-13 Sandboxing, AIS-04–06 SDLC, I&S-01–09 | L5, L6, L8 |
| **ASI06 Memory Poisoning** | AIC + MP | DSP-21 Data Poisoning, DSP-23 Integrity, AIS-14 Cache Protection | L3, L8 |
| **ASI07 Insecure Inter-Agent Comms** | OSP + CSP | AIS-10 API Security, AIS-11 Agent Boundaries, CEK-03 Encryption | L4, L7 |
| **ASI08 Cascading Failures** | AIC + OSP | BCR-01–11, SEF-01–09, LOG-01–15, MDS-11 Model Failure | L4, L9 |
| **ASI09 Human-Agent Trust** | AIC | GRC-15 Human Supervision, GRC-13–14 Explainability, AIS-09 Output Validation | L10, L2 |
| **ASI10 Rogue Agents** | AIC + OSP | LOG-14–15 I/O Monitoring, MDS-10 Continuous Mon, TVM-11 Guardrails, GRC-15 Human Supervision | L9, L10 |

**Pattern**: OWASP Agentic tells the practitioner *what* to prioritize; MAESTRO tells them *where* in the stack to implement mitigations; 3SRM tells them *who* (which AICM role) owns the mitigation.

When citing OWASP Agentic risks in the assessment, include all three coordinates: risk ID, MAESTRO layer(s), and primary AICM role(s).

---

## MAESTRO + OWASP Agentic Threats & Mitigations (T1–T15)

**This is a distinct OWASP artifact from the ASI01–ASI10 Top 10 above.** The Top 10 (previous section) is a prioritized risk list; the T1–T15 taxonomy below is OWASP's *threat-and-mitigations* model, paired with a six-step **Agentic Threat Decision Path** and six **Mitigation Playbooks**. Both come from the OWASP Agentic Security Initiative; they overlap but are not identical and use different numbering. When a user references "the OWASP agentic threats" without specifying, clarify which they mean — or map against both. Do not conflate the `T<n>` IDs here with MAESTRO's `L<n>-T<nn>` IDs; they are independent numbering systems.

Use this taxonomy as a **secondary lens**. MAESTRO remains the spine: every T-threat below is expressed as one or more MAESTRO layer threats, and the assessment's Section 8 should continue to use MAESTRO `L<n>-T<nn>` IDs as primary, citing the OWASP `T<n>` ID parenthetically where the user wants OWASP alignment.

### T1–T15 → MAESTRO mapping

| OWASP Threat | MAESTRO Layer / Threat ID(s) |
|---|---|
| **T1 Memory Poisoning** | L3-T03 (Memory Pollution), L3-T04 (Context Poisoning); CE-T1 |
| **T2 Tool Misuse** | L6-T04 (MCP Server Compromise), L6-T08 (Tool Definition Poisoning); L4-T04 (Unauthorized Tool Invocation) |
| **T3 Privilege Compromise** | L7-T03 (Over-privileged Identities), L7-T07 (Permission Inheritance Abuse); L4-T05 (Delegation Chain Privilege Escalation) |
| **T4 Resource Overload** | L1-T03 (Resource Exhaustion); L4-T01 (Infinite Planning Loop); L5-T05 (Resource Starvation) |
| **T5 Cascading Hallucination Attacks** | L8-T03 (Cascading Safety Failures); L6-T02 (Cascade Failures) — multi-agent propagation |
| **T6 Intent Breaking & Goal Manipulation** | L4-T02 (Goal Hijacking); L2-T03 (Prompt Injection / Jailbreak) |
| **T7 Misaligned & Deceptive Behaviors** | L8-T01 (Guardrail Bypass); L2-T05 (Safety Alignment Degradation) |
| **T8 Repudiation & Untraceability** | L9-T02 (Log Tampering); L10-T05 (Audit Trail Gaps) |
| **T9 Identity Spoofing & Impersonation** | L7-T01 (Agent Identity Forgery), L7-T02 (Credential Theft & Replay) |
| **T10 Overwhelming Human-in-the-Loop (HITL)** | L4-T07 (Human-in-the-Loop Bypass); L9-T06 (Alert Fatigue Exploitation) |
| **T11 Unexpected RCE & Code Attacks** | L5-T01 (Container Escape), L5-T04 (Sandbox Breakout) |
| **T12 Agent Communication Poisoning** | L4 / L6 multi-agent — Chain Reaction Malicious Command Propagation |
| **T13 Rogue Agents in Multi-Agent Systems** | L10-T01 (Shadow AI / Rogue Agents); Sub-Agent Impersonation |
| **T14 Human Attacks on Multi-Agent Systems** | L4-T06 (Workflow State Tampering); L7-T06 (Improper Trust Escalation) |
| **T15 Human Manipulation** | L6-T07 (User Interface Manipulation); L8 (safety/behavioral) |

> **Footnote on T1 / CE-T1 / L3-T04.** *Context Poisoning* appears under both L3-T04 and CE-T1 by design. The distinction is ownership: L3-T04 is typically governed by data-engineering / vector-store administration (the persistence and retrieval surface), while CE-T1 is governed by prompt-engineering and model-core developers (the in-context surface). When mapping T1, cite both, and note which owner the evidenced finding actually sits with rather than collapsing them.

### Agentic Threat Decision Path (six steps)

OWASP organizes T1–T15 behind a six-question decision path. It is a useful *triage aid during Step 1 (System Decomposition)*: each "yes" answer activates a cluster of T-threats, which then map to MAESTRO layers via the table above.

1. **Does the agent independently determine the steps to achieve its goals?** → T6, T7, T8 (reasoning/planning autonomy → L4, L2, L8, L9).
2. **Does the agent rely on stored memory for decision-making?** → T1, T5 (memory/state → L3, CE-T1–T7).
3. **Does the agent execute actions via tools, system commands, or external integrations?** → T2, T3, T4, T11 (execution surface → L6, L7, L5, L1).
4. **Does the system rely on authentication to verify users, tools, or services?** → T9 (identity → L7).
5. **Does the system require human engagement to function?** → T10, T15 (HITL → L4-T07, L9-T06, L6-T07).
6. **Does the system rely on multiple interacting agents?** → T12, T13, T14 (multi-agent → L4/L6/L7; evaluate inter-agent comms, collusion, sub-agent impersonation, and coordination manipulation).

### The six mitigation playbooks

When the user wants OWASP-aligned remediation, draw recommended mitigations from the matching playbook and express them as concrete controls in the Section 8 "Recommended Mitigations" field. Each playbook tags its measures as **Proactive**, **Reactive**, or **Detective** — preserve that tagging, it maps cleanly onto MAESTRO's preventive/detective/corrective control taxonomy.

- **Playbook 1 — Preventing Agent Reasoning Manipulation.** Mitigates T6, T8. Attack-surface reduction + behavior profiling (proactive); goal-consistency validation, goal-modification-frequency tracking, anti-self-reinforcement constraints (reactive); cryptographic/immutable decision logging, real-time anomaly detection on decision workflows, logging of human overrides and high-risk decision reversals (detective). → MAESTRO L4, L8, L9.
- **Playbook 2 — Preventing Memory Poisoning & Knowledge Corruption.** Mitigates T1, T5. Trusted-source-only persistence with cryptographic validation, memory-access logging, session isolation, context-aware retrieval limits, source attribution (proactive); anomaly detection on memory logs, multi-agent/external validation before persistent commits, rollback to validated states, forensic snapshots, probabilistic truth-checking (reactive); cross-agent validation, knowledge-lineage tracking, version control on knowledge updates (detective). → MAESTRO L3, CE-T1–T7, L8.
- **Playbook 3 — Securing Tool Execution & Preventing Unauthorized Actions.** Mitigates T2, T3, T4, T11. Strict tool-access policy, function-level auth before tool use, execution sandboxes, real-time risk-scored tool gating, JIT access with immediate revocation (proactive); tool-interaction logging, command-chaining detection, human approval for sensitive operations, human verification before privileged code execution, side-effect monitoring (reactive); workload monitoring, auto-suspension on resource thresholds, execution-control policy flags, cumulative cross-agent resource tracking, concurrency limits to prevent DoS (detective). → MAESTRO L6, L7, L5, L1.
- **Playbook 4 — Strengthening Authentication, Identity & Privilege Controls.** Mitigates T3, T9. Cryptographic agent identity, granular RBAC/ABAC, MFA for high-privilege agents, continuous reauthentication, no cross-agent delegation without explicit authorization, short-lived credentials (proactive); auto-expiring elevated permissions, behavioral profiling of role/access patterns, two-agent or human validation for high-risk auth, time-bounded privilege elevation (reactive); behavioral identity-deviation monitoring, role-change/permission-abuse detection, historical-trend correlation, failed-auth brute-force flagging (detective). → MAESTRO L7, L4.
- **Playbook 5 — Protecting HITL & Human-Interaction Threats.** Mitigates T10, T15. Trust-scored review queues, automation of low-risk approvals, notification rate-limiting, dual-agent verification before self-goal modification, reviewer-assist summaries, adaptive workload distribution (proactive); goal-consistency validation, goal-modification-frequency tracking (reactive); cryptographic/immutable logging, anomaly detection, override and decision-reversal logging (detective). → MAESTRO L4-T07, L9-T06, L6-T07.
- **Playbook 6 — Securing Multi-Agent Communication & Trust.** Mitigates T12, T13, T14. Message authentication + encryption for inter-agent comms, agent trust scoring, multi-approval for workflow-critical decisions, task segmentation, distributed consensus for high-risk changes, role-scoped cross-communication limits (proactive); real-time rogue-agent detection, isolation/privilege revocation of suspicious agents, dynamic disable of unauthorized processes, re-join-under-new-identity detection (reactive); role-change and task-assignment monitoring, inter-agent comms logging with anomaly detection, approval-discrepancy tracking, decision-consistency monitoring across similar cases (detective). → MAESTRO L4, L6, L7.

**How to cite in an assessment**: when the user asks for OWASP T1–T15 alignment, add the OWASP `T<n>` ID alongside the MAESTRO ID in the per-threat block, and pull remediation from the matching playbook. MAESTRO stays primary; OWASP is the secondary lens.

---

## MAESTRO + NIST AI RMF

NIST AI RMF is a governance-level risk-management framework. NIST tells you "what to do"; MAESTRO tells you "how to do it."

Pattern:
- **NIST AI RMF** governs organizational governance → MAESTRO L10
- **MAESTRO L1–L9** provides the technical-control implementation

For audit / regulatory contexts, lead with the NIST RMF function (Govern / Map / Measure / Manage) and pivot into the MAESTRO layer for the technical control.

---

## MAESTRO + Cloud-Provider AI Frameworks

Cloud-provider AI security offerings simplify control adoption but are scoped to each provider's platform. They do not provide the cross-vendor, full-stack perspective MAESTRO requires.

Recommended pattern: **MAESTRO is the primary spine; CSP-specific frameworks map into MAESTRO layers.**

Example mappings (illustrative, not exhaustive):

| Provider Service | MAESTRO Layer |
|---|---|
| AWS Bedrock Guardrails | L8 |
| Azure AI Content Safety | L2 / L8 |
| GCP Vertex AI Model Monitoring | L9 |

This ensures CSP-native controls are positioned within the broader threat model and that cross-CSP gaps are identified.

---

## Recommended integrated framework stack

When asked for a holistic security-program recommendation, refer the user to this stack from MAESTRO §12.7:

- **Governance Layer**: NIST AI RMF (primary governance lens). Management-system standards (e.g. AI- and infosec-management standards) may be layered in by organizations that require them, but are out of scope for this skill.
- **Threat Modeling**: MAESTRO (primary), STRIDE (supplementary)
- **Attack Knowledge Base**: MITRE ATLAS
- **Application Security**: OWASP LLM Top 10, OWASP Agentic AI Top 10
- **Infrastructure Security**: CIS Benchmarks, NIST CSF
- **AI Supply Chain Responsibility**: CSA AICM, Agent SSRM
- **Compliance**: industry-specific (PCI DSS, HIPAA, SOC 2, EU AI Act)
