# Framework Crosswalk

Load this reference **only when the user requests** mapping to one of: STRIDE, PHANTOM-B (the STRIDE analog for LLMs), MITRE ATLAS, OWASP LLM Top 10, OWASP Agentic AI Top 10, OWASP Agentic Skills Top 10 (AST01–AST10), OWASP MCP Top 10 (MCP01–MCP10), NIST AI RMF, or a cloud-provider AI security framework. MAESTRO is the primary spine; these are secondary lenses.

**Source**: MAESTRO v2.0, Section 12.

---

## When to include Section 13 (Framework Crosswalk) in the output

Include if the user:
- Explicitly names another framework ("map this to ATLAS", "give me OWASP Agentic Top 10 alignment", "map to the OWASP T1–T15 agentic threats / playbooks", "run PHANTOM-B on the LLM parts")
- Is in a compliance context where multiple frameworks are required (audit, vendor questionnaire)
- Has an existing security program built on STRIDE or another lens and is adding MAESTRO
- Requests the **full crosswalk** — any of "full framework crosswalk", "crosswalk to everything", "all frameworks", "every framework" (see "Full crosswalk mode" below)

Otherwise omit. Don't pad the output with crosswalks the user didn't ask for. The default — no Section 13 at all — is correct for the majority of assessments; crosswalks are a secondary lens that compete with the MAESTRO spine for the reader's attention, so they appear only on request.

### Scope of a single-framework request

When the user names one framework, emit only that subsection. Do not opportunistically add the others — naming ATLAS is not a request for NIST AI RMF. If two or three are named, emit those and only those.

### Full crosswalk mode (opt-in, off by default)

When — and only when — the user explicitly asks for all frameworks (the trigger phrases above), emit the complete Section 13 with all nine subsections in this fixed order:

1. **13.1 STRIDE**
2. **13.2 PHANTOM-B (STRIDE analog for LLMs)** — populated when an L2 LLM component is evidenced (nearly always); re-expresses Section 9 findings under the eight letters, one line per letter with no evidenced instance. Carries the CC-BY attribution and the no-mitigations design note from `phantom-b.md`
3. **13.3 MITRE ATLAS**
4. **13.4 OWASP LLM Top 10**
5. **13.5 OWASP Agentic AI Top 10 (ASI01–ASI10)**
6. **13.6 OWASP Agentic Threats & Mitigations (T1–T15)** — with the matching mitigation playbook cited per row
7. **13.7 OWASP Agentic Skills Top 10 (AST01–AST10)** — only populated when a skill-installation surface is evidenced; otherwise the subsection states in one line that no third-party skill/plugin loading surface is evidenced and is not padded
8. **13.8 OWASP MCP Top 10 (MCP01–MCP10)** — only populated when MCP is explicitly evidenced (rule 5); otherwise a one-line no-MCP-surface statement, not padded. Carries the beta + BY-NC-SA license caveats from `mcp-top10.md` whenever populated
9. **13.9 NIST AI RMF** — lead with the Govern/Map/Measure/Manage function, pivot into the MAESTRO layer

Rules for full crosswalk mode, all of which preserve the skill's evidence discipline:
- **Map only the assessment's existing findings.** Each subsection re-expresses the Section 9 MAESTRO findings in the other framework's vocabulary. A crosswalk never introduces a new threat that Section 9 did not already establish on the evidence.
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

## MAESTRO + PHANTOM-B (STRIDE analog for LLMs)

PHANTOM-B (Shostack + Associates, White Paper #6, July 2026; v1.0 Q3 2026; CC-BY) is an eight-letter mnemonic that does for the LLM component what STRIDE does for deterministic software: Prompt injection, Hallucination, Anthropomorphization, Non-explainability, Training issues, Over-reliance, Missing security engineering, Biases. It applies to the LLM subset of the data-flow diagram (prompt assembly plus inference) and hands everything else back to STRIDE. Full detail — design caveats, per-letter evidence checks, mitigation routing — lives in `references/phantom-b.md`.

**Good at**: recall. Eight low-effort prompts that make the non-adversarial surfaces explicit — hallucination, anthropomorphization, explainability, over-reliance, bias — which MAESTRO's `L<n>-T<nn>` list reaches only through L8 components and L10 GRC controls. It is right-sized for the passive-chatbot case where MAESTRO is over-scoped. **Bad at**: placement and depth. It carries no layer model, no ownership model, and by design no mitigations, so it cannot say where in the stack a finding lives, who owns it, or what to do — that is what the MAESTRO spine, the 3SRM, and Step 4 supply. Its use here is a completeness check on L2, not a second spine.

**Applicability**: populated whenever an L2 LLM component is evidenced. PB-P and PB-T re-express findings the assessment already has (L2-T03; L2-T02/L2-T04) and do not generate a second finding; the net-new rows are PB-H, PB-A, PB-N, PB-O, PB-B. Rows with no evidenced instance are one line, not padded.

### PHANTOM-B → MAESTRO v2.0 mapping (summary)

| PB | Threat | Adversary? | MAESTRO Layer / Threat |
|---|---|---|---|
| **PB-P** Prompt injection (direct / indirect / multi-stage) | Yes | L2-T03; L3-T04 / CE-T1 and L6-T04/L6-T08 for the indirect surface; L4-T02; L8-T01 |
| **PB-H** Hallucination | No (inducible) | L2 reliability finding (no canonical ID); L8-T03 in agent chains; L6-T07 when it misleads a user into action |
| **PB-A** Anthropomorphization | No | L2 system-prompt/persona surface (no canonical ID); L10 GRC-09; L6-T07 |
| **PB-N** Non-explainability | No | L9-T04 (nearest); L10-T06; L9 logging substrate; GRC-13/14 |
| **PB-T** Training issues (intentional / incidental) | Both | L2-T02, L2-T04, L2-T05; L1-T01 — not L3-T01 |
| **PB-O** Over-reliance | No (amplifier) | L7-T03, L7-T04, L4-T07, L6-T06; LLM09; ASI09 |
| **PB-M** Missing security engineering | Condition | Outside the LLM subset — STRIDE on the rest of the DFD; L5-T02, L1-T01, L10-T02/T03; Section 14 validation |
| **PB-B** Biases | No | L2 behavioral finding (no canonical ID); L10-T06; GRC-11; L8 output validation |

**How to cite in an assessment**: MAESTRO `L<n>-T<nn>` stays the canonical ID; add `PB-<letter>` parenthetically (`PB-*` is skill-local shorthand — the paper uses bare letters). For the three letters without a canonical L2-T ID, anchor to the layer as `maestro-layers.md` does for OWASP T16. Non-adversarial findings use `Failure mode (no adversary required): …` in the Attack Vector field. Mitigations are never attributed to PHANTOM-B; the paper ships none by design.

---

## MAESTRO + MITRE ATLAS

MITRE ATLAS is a knowledge base of adversarial tactics against ML systems organized by attack lifecycle stages. ATLAS provides the *attack techniques*; MAESTRO provides the *architectural context*.

Example mappings:

| ATLAS Technique (ATLAS 5.6.0 IDs, from `atlas-techniques.md`) | MAESTRO Layer |
|---|---|
| AML.T0024 Exfiltration via AI Inference API — .002 Extract AI Model, .001 Invert AI Model, .000 Infer Training Data Membership | L2 (L2-T01 for .002; L2-T06 for .001/.000). Retrieval-corpus membership is an L3 finding with no ATLAS technique; do not cite .000 for it |
| AML.T0020 Poison Training Data; AML.T0018.000 Poison AI Model; AML.T0058 Publish Poisoned Models | L3 (L3-T01); L2 (L2-T02 training-time, L2-T04 for T0058) |
| AML.T0015 Evade AI Model; AML.T0054 LLM Jailbreak; AML.T0068 LLM Prompt Obfuscation | L2 / L8 (L2-T03, L8-T01) |
| AML.T0051 LLM Prompt Injection — .000 Direct, .001 Indirect, .002 Triggered | L2 / L4 (L2-T03, L4-T02); .001 and .002 also L3-T04 / CE-T1 (PB-P sub-types) |
| AML.T0010 AI Supply Chain Compromise — .003 Model, .004 Container Registry, .005 AI Agent Tool | L2 (L2-T04); L1 (L1-T01); L5 (L5-T02 for .004); L6 (L6-T04 for .005) |
| AML.T0014 Discover AI Model Family; AML.T0069 Discover LLM System Information; AML.T0084 Discover AI Agent Configuration (.001 Tool Definitions, .003 Call Chains) | L6 / L2 (information disclosure via tool/API surface); L5-T03 for T0084 |
| AML.T0040 AI Model Inference API Access | L2 (L2-T01 if extraction-style); L6 |

**Agentic techniques (added to ATLAS through 2026; all `realized` or `demonstrated`)**

| ATLAS Technique | MAESTRO Layer | Also cited under |
|---|---|---|
| AML.T0110 AI Agent Tool Poisoning; AML.T0011.002 Poisoned AI Agent Tool | L6-T08, L6-T04 | MCP03; AST01 |
| AML.T0104 Publish Poisoned AI Agent Tool; AML.T0109 AI Supply Chain Rug Pull; AML.T0111 AI Supply Chain Reputation Inflation | L6-T05, L1-T01 | MCP04; AST02, AST07 |
| AML.T0053 AI Agent Tool Invocation; AML.T0086 Exfiltration via AI Agent Tool Invocation; AML.T0101 Data Destruction via AI Agent Tool Invocation | L4-T04, L6-T06, L4-T07 | MCP05, MCP06; OWASP T2 |
| AML.T0080 AI Agent Context Poisoning — .000 Memory, .001 Thread | L3-T03, L3-T04 / CE-T1 | MCP10; OWASP T1 |
| AML.T0070 RAG Poisoning; AML.T0071 False RAG Entry Injection; AML.T0066 Retrieval Content Crafting; AML.T0064 Gather RAG-Indexed Targets | L3-T01 | OWASP T18 |
| AML.T0105 Escape to Host; AML.T0097 Virtualization/Sandbox Evasion; AML.T0112 Machine Compromise (.000 Local AI Agent) | L5-T01, L5-T04 | MCP05; OWASP T11 |
| AML.T0081 Modify AI Agent Configuration; AML.T0083 Credentials from AI Agent Configuration; AML.T0098 AI Agent Tool Credential Harvesting; AML.T0082 RAG Credential Harvesting; AML.T0055 Unsecured Credentials | L5-T03, L7-T02 | MCP01; library Part 3 |
| AML.T0103 Deploy AI Agent; AML.T0108 AI Agent (Command and Control) | L10-T01 | MCP09; OWASP T13 |
| AML.T0056 Extract LLM System Prompt; AML.T0057 LLM Data Leakage; AML.T0077 LLM Response Rendering; AML.T0067.000 Citations manipulation | L2 / L3 disclosure; L6-T07 | LLM07; PB-H for T0067 |
| AML.T0092 Manipulate User LLM Chat History; AML.T0094 Delay Execution of LLM Instructions | L9-T04, L8 | OWASP T7 |

**How to use in the assessment**: when an ATLAS technique applies, name the technique ID and the corresponding MAESTRO layer(s). Don't substitute MAESTRO for ATLAS — they're complementary.

**For technique-level granularity**, load `references/threat-technique-and-control-library.md`, which expands this high-level mapping into ~140 `AITech-*`/`AISubtech-*` techniques (each tagged OWASP + ATLAS + MAESTRO layer) and a FAIR-CAM control library. Technique names are taken from `references/atlas-techniques.md` (generated from the current ATLAS release); cite sub-technique IDs wherever ATLAS has them. Use it when the user wants finer attack-technique detail than MAESTRO's per-layer sample threats, or a structured control source for Step 4.

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

Use this taxonomy as a **secondary lens**. MAESTRO remains the spine: every T-threat below is expressed as one or more MAESTRO layer threats, and the assessment's Section 9 should continue to use MAESTRO `L<n>-T<nn>` IDs as primary, citing the OWASP `T<n>` ID parenthetically where the user wants OWASP alignment.

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

When the user wants OWASP-aligned remediation, draw recommended mitigations from the matching playbook and express them as concrete controls in the Section 9 "Recommended Mitigations" field. Each playbook tags its measures as **Proactive**, **Reactive**, or **Detective** — preserve that tagging, it maps cleanly onto MAESTRO's preventive/detective/corrective control taxonomy.

- **Playbook 1 — Preventing Agent Reasoning Manipulation.** Mitigates T6, T8. Attack-surface reduction + behavior profiling (proactive); goal-consistency validation, goal-modification-frequency tracking, anti-self-reinforcement constraints (reactive); cryptographic/immutable decision logging, real-time anomaly detection on decision workflows, logging of human overrides and high-risk decision reversals (detective). → MAESTRO L4, L8, L9.
- **Playbook 2 — Preventing Memory Poisoning & Knowledge Corruption.** Mitigates T1, T5. Trusted-source-only persistence with cryptographic validation, memory-access logging, session isolation, context-aware retrieval limits, source attribution (proactive); anomaly detection on memory logs, multi-agent/external validation before persistent commits, rollback to validated states, forensic snapshots, probabilistic truth-checking (reactive); cross-agent validation, knowledge-lineage tracking, version control on knowledge updates (detective). → MAESTRO L3, CE-T1–T7, L8.
- **Playbook 3 — Securing Tool Execution & Preventing Unauthorized Actions.** Mitigates T2, T3, T4, T11. Strict tool-access policy, function-level auth before tool use, execution sandboxes, real-time risk-scored tool gating, JIT access with immediate revocation (proactive); tool-interaction logging, command-chaining detection, human approval for sensitive operations, human verification before privileged code execution, side-effect monitoring (reactive); workload monitoring, auto-suspension on resource thresholds, execution-control policy flags, cumulative cross-agent resource tracking, concurrency limits to prevent DoS (detective). → MAESTRO L6, L7, L5, L1.
- **Playbook 4 — Strengthening Authentication, Identity & Privilege Controls.** Mitigates T3, T9. Cryptographic agent identity, granular RBAC/ABAC, MFA for high-privilege agents, continuous reauthentication, no cross-agent delegation without explicit authorization, short-lived credentials (proactive); auto-expiring elevated permissions, behavioral profiling of role/access patterns, two-agent or human validation for high-risk auth, time-bounded privilege elevation (reactive); behavioral identity-deviation monitoring, role-change/permission-abuse detection, historical-trend correlation, failed-auth brute-force flagging (detective). → MAESTRO L7, L4.
- **Playbook 5 — Protecting HITL & Human-Interaction Threats.** Mitigates T10, T15. Trust-scored review queues, automation of low-risk approvals, notification rate-limiting, dual-agent verification before self-goal modification, reviewer-assist summaries, adaptive workload distribution (proactive); goal-consistency validation, goal-modification-frequency tracking (reactive); cryptographic/immutable logging, anomaly detection, override and decision-reversal logging (detective). → MAESTRO L4-T07, L9-T06, L6-T07.
- **Playbook 6 — Securing Multi-Agent Communication & Trust.** Mitigates T12, T13, T14. Message authentication + encryption for inter-agent comms, agent trust scoring, multi-approval for workflow-critical decisions, task segmentation, distributed consensus for high-risk changes, role-scoped cross-communication limits (proactive); real-time rogue-agent detection, isolation/privilege revocation of suspicious agents, dynamic disable of unauthorized processes, re-join-under-new-identity detection (reactive); role-change and task-assignment monitoring, inter-agent comms logging with anomaly detection, approval-discrepancy tracking, decision-consistency monitoring across similar cases (detective). → MAESTRO L4, L6, L7.

**How to cite in an assessment**: when the user asks for OWASP T1–T15 alignment, add the OWASP `T<n>` ID alongside the MAESTRO ID in the per-threat block, and pull remediation from the matching playbook. MAESTRO stays primary; OWASP is the secondary lens.

---

## MAESTRO + OWASP Agentic Skills Top 10 (AST01–AST10)

**A third, distinct OWASP artifact** — not the ASI01–ASI10 Top 10 and not the T1–T15 taxonomy. AST10 (OWASP Agentic Skills Top 10, v1.0 2026) covers the **installable behavior layer**: third-party skills, plugins, and behavior packages (SKILL.md / skill.json / manifest.json formats) and the registries that distribute them. Mental model: *MCP = how the model talks to tools; AST10 = what those tools actually do.* Three independent OWASP numbering systems now appear in this file — `ASI<nn>`, `T<n>`, `AST<nn>` — never conflate them with each other or with MAESTRO `L<n>-T<nn>` IDs.

Full detail — per-risk evidence checks, lethal-trifecta trigger, incident evidence base, mitigation sourcing — lives in `references/agentic-skills-top10.md`. That file also carries the mandatory layer-mapping caveat: the OWASP project publishes its MAESTRO mapping against the original 7-layer model; the table below (and the fuller one in the dedicated file) is this skill's re-mapping into MAESTRO v2.0 ten-layer coordinates.

**Applicability gate**: this crosswalk subsection is populated only when the assessment evidenced a skill installation/loading surface. Bare MCP tool use does not activate it — that stays with L6-T04/L6-T08 and the ASI/T lenses.

### AST01–AST10 → MAESTRO v2.0 mapping (summary)

| AST Risk | Severity | MAESTRO Layer(s) |
|---|---|---|
| **AST01 Malicious Skills** | Critical | L6 (L6-T05), L3 (L3-T03), L8, L5 |
| **AST02 Supply Chain Compromise** | Critical | L1 (L1-T01), L5 (L5-T02), L6, L10 |
| **AST03 Over-Privileged Skills** | High | L7 (L7-T03), L6 (L6-T06), L5 |
| **AST04 Insecure Metadata** | High | L6 (L6-T08), L5 (L5-T03), L8 |
| **AST05 Untrusted External Instructions** | High | L3 (CE-T1/L3-T04), L2 (L2-T03), L6, L1 |
| **AST06 Weak Isolation** | High | L5 (L5-T01, L5-T04), L1, L6 |
| **AST07 Update Drift** | Medium | L5 (L5-T06), L6, L10 |
| **AST08 Poor Scanning** | Medium | L9, L8 (L8-T01), L5 |
| **AST09 No Governance** | Medium | L10 (L10-T01), L7, L9 |
| **AST10 Cross-Platform Reuse** | Medium | L6, L10, L5 |

**How to cite in an assessment**: MAESTRO `L<n>-T<nn>` stays the canonical ID; add the `AST<nn>` ID parenthetically. Likelihood justifications may draw on the confirmed 2026 incident base in the dedicated file (ClawHavoc, ToxicSkills, ClawJacked, SkillJacking) — cite the source, not just the figure.

---

## MAESTRO + OWASP MCP Top 10 (MCP01:2025–MCP10:2025)

**A fourth OWASP artifact and a fourth numbering system** (`MCP<nn>:2025`) — the protocol layer connecting agents to tools, distinct from ASI (agentic application risks), T1–T15 (threat taxonomy), and AST (installable skill packages). Detail, per-risk evidence checks, and the full mapping live in `references/mcp-top10.md`.

**Three caveats travel with every citation** (full text in the dedicated file): Phase 3 beta — IDs stable, rankings/descriptions may shift, next release Oct 2026; **CC BY-NC-SA 4.0 license** — own-words paraphrase only, flag the NonCommercial term before use in commercial deliverables; MCP03's title says tool poisoning while its body describes schema poisoning — treat as covering both, note the inconsistency.

**Applicability gate**: populated only when MCP is explicitly evidenced (skill rule 5). Bare tool use is not MCP evidence.

### MCP01–MCP10 → MAESTRO v2.0 mapping (summary)

| MCP Risk | MAESTRO Layer(s) |
|---|---|
| **MCP01 Token Mismanagement & Secret Exposure** | L7 (L7-T02), L3 (L3-T05), L1 (L1-T04), L9 |
| **MCP02 Privilege Escalation via Scope Creep** | L7 (L7-T03, L7-T07), L4 (L4-T05) |
| **MCP03 Tool / Schema Poisoning** | L6 (L6-T08, L6-T04), L2 |
| **MCP04 Supply Chain & Dependency Tampering** | L1 (L1-T01), L6 (L6-T04/T05), L5 (L5-T02) |
| **MCP05 Command Injection & Execution** | L5 (L5-T01, L5-T04), L6 (L6-T06), L2 (L2-T03) |
| **MCP06 Intent Flow Subversion** | L4 (L4-T02), L2 (L2-T03), L3 (CE-T1/L3-T04) |
| **MCP07 Insufficient AuthN & AuthZ** | L7 (L7-T01, L7-T03), L6, L4 |
| **MCP08 Lack of Audit & Telemetry** | L9 (L9-T02), L10 (L10-T05) |
| **MCP09 Shadow MCP Servers** | L10 (L10-T01), L6 (L6-T04), L9 |
| **MCP10 Context Injection & Over-Sharing** | L3 (L3-T04, CE-T1/CE-T7, L3-T05), L6 (L6-T06) |

**How to cite**: MAESTRO ID primary, `MCP<nn>:2025` parenthetical. The AST10 whitepaper's per-risk mappings cite these same MCP IDs — the two subsections resolve each other.

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
- **Threat Modeling**: MAESTRO (primary), STRIDE (supplementary for non-LLM components), PHANTOM-B (supplementary for the LLM component; CC-BY)
- **Attack Knowledge Base**: MITRE ATLAS
- **Application Security**: OWASP LLM Top 10, OWASP Agentic AI Top 10
- **Skill / Behavior-Layer Supply Chain**: OWASP Agentic Skills Top 10 (AST01–AST10)
- **Tool-Protocol Layer**: OWASP MCP Top 10 (MCP01–MCP10; beta, BY-NC-SA — see caveats)
- **Infrastructure Security**: CIS Benchmarks, NIST CSF
- **AI Supply Chain Responsibility**: CSA AICM, Agent SSRM
- **Compliance**: industry-specific (PCI DSS, HIPAA, SOC 2, EU AI Act)
