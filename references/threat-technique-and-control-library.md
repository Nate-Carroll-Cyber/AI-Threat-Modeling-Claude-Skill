# Threat Technique Taxonomy & Control Library

Load this reference when the user wants **technique-level** attack granularity (finer than MAESTRO's `L<n>-T<nn>` sample threats) or a **structured control library** to draw mitigations from in Step 4. Three artifacts are combined here:

1. **AI Threat Technique Taxonomy** — ~140 techniques and subtechniques (`AITech-*` / `AISubtech-*`), each tagged with an OWASP category and a MITRE ATLAS technique, and (added here) a MAESTRO layer.
2. **FAIR-CAM GenAI Control Library** — controls organized under the FAIR Controls Analytics Model (Loss Event Controls, Variance Management Controls, Decision Support Controls), each tagged with OWASP and ATLAS.
3. **Trust & Identity-Lifecycle Threat Taxonomy** — ~41 named trust/identity-lifecycle threats (session/credential persistence, memory trust, inter-entity trust, delegation, trust-decay, scoring manipulation, gate bypass, trust forgery), each tagged with OWASP Agentic Top 10 (2026), a MITRE ATLAS tactic, CSA AICM v1.1 control(s), and (added here) a MAESTRO layer.

**Secondary-lens rule (read first).** The `AITech-*`/`AISubtech-*` IDs and the FAIR-CAM control names are **not** MAESTRO layer IDs and must never be substituted for `L<n>-T<nn>`. MAESTRO remains the spine: use these to *enrich* a finding (cite the technique ID and the matching control) after the MAESTRO layer threat is established. This is the same discipline applied to STRIDE/ATLAS/OWASP in `framework-crosswalk.md`.

**Relationship to `framework-crosswalk.md`.** That file gives the high-level MAESTRO↔ATLAS↔OWASP mapping; this file is the granular expansion. When a user asks for ATLAS technique-level detail, use this file; when they want the framework overview, use the crosswalk.

> **⚠️ Source caveats — read before citing.** This material was transcribed from a source with OCR damage and some non-canonical labels. See the "Source caveats" section at the end. In short: three mid-word OCR splices were repaired; OWASP/ASI category labels and a few ATLAS IDs in the source are **internally inconsistent and were left as-given** — reconcile against the authoritative OWASP 2025 lists and the live MITRE ATLAS matrix before relying on a specific tag.

---

## Part 1 — AI Threat Technique Taxonomy

Grouped by technique family. The **MAESTRO layer** column is added by this skill to tie each technique to the spine; the OWASP and ATLAS columns are from the source.

### Family 1 — Multi-Modal Injection (→ MAESTRO L2/L3)

| ID | Name | OWASP (source) | MITRE ATLAS | MAESTRO |
|---|---|---|---|---|
| AITech-1.4 | Multi-Modal Injection and Manipulation | ASI05: Multi-modal Poisoning | AML.T0051.001 Indirect Injection | L2, L3 |
| AISubtech-1.4.1 | Image-Text Injection | ASI05 | AML.T0051.001 | L3 |
| AISubtech-1.4.2 | Image Manipulation | ASI05 | AML.T0031 Evade ML Model | L2 |
| AISubtech-1.4.3 | Audio Command Injection | ASI05 | AML.T0051.001 | L3 |
| AISubtech-1.4.4 | Video Overlay Manipulation | ASI05 | AML.T0051.001 | L3 |

### Family 2 — Jailbreak & Obfuscation (→ L2/L4)

| ID | Name | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| AISubtech-2.1.1 | Context Manipulation (Jailbreak) | LLM01 Prompt Injection | AML.T0054 LLM Jailbreak | L2, L4 |
| AISubtech-2.1.2 | Obfuscation (Jailbreak) | LLM01 | AML.T0031 Evade ML Model | L2 |
| AISubtech-2.1.3 | Semantic Manipulation (Jailbreak) | LLM01 | AML.T0054 | L2 |
| AISubtech-2.1.5 | Multi-Agent Jailbreak Collaboration | ASI07 Insecure Agent Comm | AML.T0051.002 | L4, L6 |
| AISubtech-3.1.1 | Identity Obfuscation | LLM01 | AML.T0031 | L7 |

### Family 4 — Agent & Protocol Attacks (→ L4/L6/L7)

| ID | Name | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| AITech-4.1 | Agent Injection | ASI07 Insecure Agent Comm | AML.T0051.002 | L4, L6 |
| AISubtech-4.1.1 | Rogue Agent Introduction | ASI07 | AML.T0051.002 | L4, L10 |
| AITech-4.2 | Context Boundary Attacks | ASI06 Memory Injection | AML.T0051.002 | L3 |
| AISubtech-4.2.1 | Context Window Exploitation | ASI06 | AML.T0051.002 | L3 (CE-T6) |
| AISubtech-4.2.2 | Session Boundary Violation | ASI06 | AML.T0051.002 | L3 (CE-T7) |
| AITech-4.3 | Protocol Manipulation | ASI02 Tool Misuse | AML.T0055 Plugin Compromise | L6 |
| AISubtech-4.3.1 | Schema Inconsistencies | ASI02 | AML.T0055 | L6-T08 |
| AISubtech-4.3.3 | Server Rebinding Attack | ASI03 Broken Authorization | AML.TA0006 Priv Esc | L6, L7 |
| AISubtech-4.3.4 | Replay Exploitation | ASI06 | AML.TA0007 Persistence | L7-T02 |
| AISubtech-4.3.5 | Capability Inflation | ASI03 | AML.TA0006 | L6, L7 |
| AISubtech-4.3.6 | Cross-Origin Exploitation | ASI03 | AML.TA0006 | L6, L7 |

### Family 5 — Persistence (→ L3/L4)

| ID | Name | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| AITech-5.1 | Memory System Persistence | ASI06 Memory Injection | AML.TA0007 Persistence | L3 |
| AISubtech-5.1.1 | Long-term / Short-term Memory Injection | ASI06 | AML.TA0007 | L3 (CE-T1) |
| AITech-5.2 | Configuration Persistence | ASI06 | AML.TA0007 | L4, L10 |
| AISubtech-5.2.1 | Agent Profile Tampering | ASI01 Goal Hijacking | AML.TA0007 | L4 |

### Family 6 — Reinforcement / Training Poisoning (→ L2/L3)

| ID | Name | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| AISubtech-6.1.2 | Reinforcement Biasing | LLM04 Data Poisoning | AML.T0020 Poison Training Data | L2, L3 |
| AISubtech-6.1.3 | Reinforcement Signal Corruption | LLM04 | AML.T0020 | L2, L3 |

### Family 7 — Reasoning, Memory & Token Corruption (→ L2/L3/L7)

| ID | Name | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| AITech-7.1 | Reasoning Corruption | ASI01 Goal Hijacking | AML.T0048.001 Financial Impact | L4-T02 |
| AITech-7.2 | Memory System Corruption | ASI06 Memory Injection | AML.T0051.002 | L3 |
| AISubtech-7.2.2 | Memory Index Manipulation | ASI06 | AML.T0051.002 | L3 |
| AITech-7.3 | Data Source Abuse and Manipulation | LLM03 Supply Chain | AML.T0010 Supply Chain | L3, L6 |
| AISubtech-7.3.1 | Corrupted Third-Party Data | LLM03 | AML.T0010 | L6 |
| AITech-7.4 | Token Manipulation | ASI03 Broken Authorization | AML.TA0006 Priv Esc | L7-T02 |
| AISubtech-7.4.1 | Token Theft | ASI03 | AML.TA0006 | L7-T02 |

### Family 8 — Inference & Disclosure (→ L2/L3/L6)

| ID | Name | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| AITech-8.1 | Membership Inference | LLM02 Info Disclosure | AML.T0024 Invert/Infer Model | L2-T06 |
| AISubtech-8.1.1 | Presence Detection | LLM02 | AML.T0024 | L2 |
| AITech-8.2 | Data Exfiltration / Exposure | LLM06 Excessive Agency | AML.TA0009 Exfiltration | L6-T06 |
| AISubtech-8.2.1 | Training Data Exposure | LLM02 | AML.TA0009 | L2, L3 |
| AISubtech-8.2.2 | LLM Data Leakage | LLM02 | AML.TA0009 | L2 |
| AITech-8.3 | Information Disclosure | LLM02 | AML.TA0009 | L6 |
| AISubtech-8.3.1 | Tool Metadata Exposure | LLM02 | AML.TA0009 | L6 |
| AISubtech-8.3.2 | System Information Leakage | LLM02 | AML.TA0009 | L1, L6 |
| AITech-8.4 | Prompt/Meta Extraction | LLM07 Prompt Leakage | AML.T0051 Prompt Injection | L2, L4 |

### Family 9 — Code Execution, Evasion & Dependency Compromise (→ L5/L6)

| ID | Name | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| AITech-9.1 | Model or Agentic System Manipulation | LLM03 Supply Chain | AML.T0010 Supply Chain | L2, L6 |
| AISubtech-9.1.1 | Code Execution | ASI05 Unexpected Code Execution* | AML.TA0005 Execution | L5-T01/T04 |
| AISubtech-9.1.2 | Unauthorized/Unsolicited System Access | ASI03 Broken Authorization | AML.TA0006 Priv Esc | L7, L5 |
| AISubtech-9.1.3 | Unauthorized/Unsolicited Network Access | ASI02 Tool Misuse | AML.T0058 Exfil via Tool | L6-T06 |
| AISubtech-9.1.4 | Injection Attacks (SQL, Command, etc.) | LLM05 Output Handling | AML.TA0005 Execution | L6 |
| AISubtech-9.1.5 | Template Injection (SSTI) | LLM05 | AML.TA0005 | L6 |
| AITech-9.2 | Detection Evasion | LLM01 Prompt Injection | AML.T0031 Evade ML Model | L8, L9 |
| AISubtech-9.2.1 | Obfuscation Vulnerabilities | LLM01 | AML.T0031 | L8 |
| AISubtech-9.2.2 | Backdoors and Trojans | LLM04 Data Poisoning | AML.T0020 | L2 |
| AITech-9.3 | Dependency / Plugin Compromise | LLM03 Supply Chain | AML.T0010 | L6-T04, L5 |
| AISubtech-9.3.1 | Malicious Package / Tool Injection | LLM03 | AML.T0010 | L6 |
| AISubtech-9.3.3 | Dependency Replacement / Rug Pull | LLM03 | AML.T0010 | L6 |

### Family 10 — Model Extraction & Inversion (→ L2)

| ID | Name | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| AITech-10.1 | Model Extraction | LLM10 Model Theft | AML.T0024 Invert/Infer | L2-T01 |
| AISubtech-10.1.1 | API Query Stealing | LLM10 | AML.T0002 Inference API Access | L2, L6 |
| AISubtech-10.1.2 | Weight Reconstruction | LLM10 | AML.T0024 | L2-T01 |
| AISubtech-10.1.3 | Sensitive Data Reconstruction | LLM02 Info Disclosure | AML.T0024 | L2, L3 |
| AITech-10.2.1 | Model Inversion | LLM02 | AML.T0024 | L2-T06 |
| AISubtech-10.2.1 | Model Inversion | LLM02 | AML.T0024 | L2-T06 |

### Family 11 — Environment-Aware / Selective Evasion (→ L8)

| ID | Name | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| AITech-11.1 | Environment-Aware Evasion | LLM01 Prompt Injection | AML.T0031 Evade ML Model | L8 |
| AISubtech-11.1.1 | Agent-Specific Evasion | ASI01 Goal Hijacking | AML.T0031 | L8 |
| AISubtech-11.1.2 | Tool-Scoped Evasion | ASI02 Tool Misuse | AML.T0031 | L6, L8 |
| AISubtech-11.1.3 | Environment-Scoped Payloads | LLM01 | AML.T0031 | L8 |
| AISubtech-11.1.4 | Defense-Aware Payloads | LLM01 | AML.T0031 | L8, L9 |
| AITech-11.2 | Model-Selective Evasion *(OCR-repaired)* | LLM01 | AML.T0031 | L8 |
| AISubtech-11.2.1 | Targeted Model Fingerprinting | LLM01 | AML.T0002 Inference API Access | L2, L6 |
| AISubtech-11.2.2 | Conditional Attack Execution | LLM01 | AML.T0031 | L8 |

### Family 12 — Tool Exploitation & Output Handling (→ L6)

| ID | Name | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| AITech-12.1 | Tool Exploitation | ASI02 Tool Misuse | AML.T0058 Exfil via Tool | L6-T04 |
| AISubtech-12.1.1 | Parameter Manipulation | ASI02 | AML.T0058 | L6 |
| AISubtech-12.1.2 | Tool Poisoning | ASI02 | AML.T0055 Plugin Compromise | L6-T08 |
| AISubtech-12.1.3 | Unsafe System/Browser/File Execution | ASI05 Unexpected Code Execution* | AML.TA0005 Execution | L5, L6 |
| AITech-12.2 | Insecure Output Handling | LLM05 Output Handling | AML.TA0005 | L6, L4 |
| AISubtech-12.2.1 | Code Detection / Malicious Code Output | LLM05 | AML.TA0005 | L6 |

### Family 13 — Availability & Cost (→ L1/L4)

| ID | Name | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| AITech-13.1 | Disruption of Availability | LLM10 Unbounded Consumption | AML.T0029 Denial of Service | L1-T03 |
| AISubtech-13.1.1 | Compute Exhaustion | LLM10 | AML.T0029 | L1-T03 |
| AISubtech-13.1.2 | Memory Flooding | LLM10 | AML.T0029 | L1, L3 |
| AISubtech-13.1.3 | Model Denial of Service | LLM10 | AML.T0029 | L2, L1 |
| AISubtech-13.1.4 | Application Denial of Service | LLM10 | AML.T0029 | L4-T01 |
| AITech-13.2 | Cost Harvesting / Repurposing | LLM10 | AML.T0029 | L1, L4 |
| AISubtech-13.2.1 | Service Misuse for Cost Inflation | LLM10 | AML.T0029 | L1 |

### Family 14 — Access & Delegated Authority (→ L7)

| ID | Name | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| AITech-14.1 | Unauthorized Access | ASI03 Broken Authorization | AML.TA0006 Priv Esc | L7-T03 |
| AISubtech-14.1.1 | Credential Theft | ASI03 | AML.TA0006 | L7-T02 |
| AISubtech-14.1.2 | Insufficient Access Controls | ASI03 | AML.TA0006 | L7-T03 |
| AITech-14.2 | Abuse of Delegated Authority | ASI03 | AML.TA0006 | L7-T07, L4-T05 |
| AISubtech-14.2.1 | Permission Escalation via Delegation | ASI03 | AML.TA0006 | L7-T07 |

### Family 15 — Harmful Content & Safety (→ L8/L10)

This family is a content-safety/harm taxonomy. It maps primarily to **L8 (Safety & Security)** and **L10 (Governance & Compliance)** rather than to a single technical threat. The source tags most of these as `LLM09: Misinformation` / `AML.T0048: External Harms`; that is a coarse tag and several subtypes (e.g. PII/PHI/PCI, confidential data) are really disclosure (LLM02 / Exfiltration). Use this family when the assessment scope includes content-harm or responsible-AI requirements; otherwise it is usually out of scope for an architecture threat model.

Representative entries (full list preserved from source): Harmful Content (15.1); Cybersecurity malware/abuse (15.1.1–2 → also L6/execution); Safety subtypes — animal abuse, child abuse/exploitation, environmental, financial, harassment, hate speech, non-violent crime, profanity, scams/deception, self-harm, sexual content/exploitation, social division, terrorism/extremism, violence (15.1.3–17); Integrity — hallucinations/misinformation, unauthorized financial advice (15.1.19–20); IP — intellectual property plagiarism *(OCR-repaired)*, confidential data disclosure (15.1.23–24 → L2/L6 disclosure); Privacy — PII/PHI/PCI (15.1.25 → L3/L6 disclosure).

### Family 16–19 — Eavesdropping, Sensor Spoofing, Fraudulent Use, Cross-Modal (→ L1/L2/L6)

| ID | Name | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| AITech-16.1 | Eavesdropping | LLM02 Info Disclosure | AML.TA0009 Exfiltration | L1, L6 |
| AISubtech-16.1.1 | Logging Sensitive Conversations | LLM02 | AML.TA0009 | L9, L3 |
| AITech-17.1 | Sensor Spoofing | ASI05 Multi-modal Poisoning | AML.T0051.001 | L1, L2 |
| AISubtech-17.1.1 | Sensor Spoofing: Action Signals | ASI05 | AML.T0051.001 | L1 |
| AITech-18.1 | Fraudulent Use | LLM06 Excessive Agency | AML.TA0005 Execution | L6, L10 |
| AISubtech-18.1.1 | Spam / Scam / Social Engineering Generation | LLM09 Misinformation | AML.T0048 External Harms | L8 |
| AITech-18.2 | Malicious Workflows | ASI01 Goal Hijacking | AML.TA0005 | L4 |
| AISubtech-18.2.1 | Abuse of APIs for Mass Automation | LLM10 Unbounded Consumption | AML.T0029 DoS | L1, L6 |
| AISubtech-18.2.2 | Dedicated Malicious Server / Infrastructure | LLM06 Excessive Agency | AML.TA0005 | L6 |
| AITech-19.1 | Cross-Modal Inconsistency Exploitation | ASI05 Multi-modal Poisoning | AML.T0051.001 | L2, L3 |
| AISubtech-19.1.1 | Contradictory Inputs Attack | ASI05 | AML.T0051.001 | L3 (CE-T3) |
| AISubtech-19.1.2 | Modality Skewing | ASI05 | AML.T0031 Evade | L2 |
| AITech-19.2 | Fusion Payload Split | ASI05 | AML.T0051.001 | L3 |
| AISubtech-19.2.1 | Convergence Payload Injection | ASI05 | AML.T0051.001 | L3 |
| AISubtech-19.2.2 | Chained Payload Execution | ASI01 Goal Hijacking | AML.TA0005 Execution | L4, L6 |

*\* ASI05 label note: the source labels ASI05 as both "Multi-modal Poisoning" (Family 1, 17, 19) and "Unexpected Code Execution" (9.1.1, 12.1.3). The OWASP Agentic Top 10 in `framework-crosswalk.md` uses ASI05 = Unexpected Code Execution. Treat the multi-modal entries' ASI05 tag with suspicion — they likely predate a renumbering. Left as-given pending reconciliation.*

---

## Part 2 — FAIR-CAM GenAI Control Library

A mitigation source for **Step 4**. FAIR-CAM (Factor Analysis of Information Risk — Controls Analytics Model) groups controls by function. When recommending mitigations for a MAESTRO finding, draw from the matching control category here and cite it alongside the MAESTRO per-layer guidance.

The three FAIR-CAM functional domains:
- **Loss Event Controls (LEC)** — act on a loss event directly: Prevention (Avoidance, Deterrence, Resistance), Detection (Visibility, Monitoring), Response (Event Termination, Loss Reduction).
- **Variance Management Controls (VMC)** — keep other controls working: Prevention, Identification (Monitoring), Correction (Implementation).
- **Decision Support Controls (DSC)** — govern decisions: Prevention (Expectations, Awareness, Incentives), Misaligned-Decision analysis.

### Loss Event Controls

| Function | Control | OWASP (source) | ATLAS | Maps to MAESTRO |
|---|---|---|---|---|
| Prevention · Avoidance | Access privileges restrict access to sensitive info | ASI03 Broken Authorization | AML.TA0006 | L7 |
| Prevention · Avoidance | Restrict groups with access to sensitive info | ASI03 | AML.TA0006 | L7 |
| Prevention · Avoidance | Secure hosted info behind reCaptcha v3 | LLM10 Unbounded Consumption | AML.T0029 | L1 |
| Prevention · Avoidance | Secondary verification for new accounts | ASI03 | AML.T0004 Reconnaissance | L7 |
| Prevention · Deterrence | Audit logs retained for 180 days | LLM08 Insecure Output Handling† | AML.T0031 | L9 |
| Prevention · Resistance | Browser-level protection vs sensitive-data publishing | LLM02 Sensitive Info Disclosure | AML.TA0009 | L8 |
| Prevention · Resistance | Endpoint-level protection vs sensitive-data publishing | LLM02 | AML.TA0009 | L8 |
| Prevention · Resistance | Network-level protection vs sensitive-data publishing | LLM02 | AML.TA0009 | L1, L8 |
| Prevention · Resistance | DLP solution enforces data classification policy | LLM02 | AML.TA0009 | L8, L3 |
| Prevention · Resistance | GenAI prompt and metadata collection disabled *(OCR-repaired)* | LLM07 Prompt Leakage | AML.T0051 | L3, L9 |
| Prevention · Resistance | Access to plugins and extensions restricted | ASI02 Tool Misuse | AML.T0055 Plugin Compromise | L6 |
| Prevention · Resistance | AES-256 encryption for data at rest | LLM02 | AML.TA0009 | L1, L3 |
| Prevention · Resistance | DDoS protection implemented | LLM10 | AML.T0029 | L1 |
| Prevention · Resistance | robots.txt restricts proprietary data | LLM02 | AML.T0004 | L1 |
| Prevention · Resistance | Rate limiting for Internet-exposed apps | LLM10 | AML.T0029 | L1, L4 |
| Detection · Visibility | Intrusion detection for GenAI applications | LLM01 Prompt Injection | AML.T0031 | L9 |
| Detection · Monitoring | Ensure monitoring of bots | ASI07 Insecure Agent Comm | AML.T0051.002 | L9 |
| Detection · Monitoring | No unauthenticated public data repository | LLM02 | AML.T0004 | L1, L7 |
| Response · Event Termination | Documented incident response process | ASI01 Goal Hijacking | AML.T0048 | L10 |
| Response · Event Termination | Intrusion detection for Internet-exposed app | LLM01 | AML.T0031 | L9 |
| Response · Event Termination | Data scraping prevention techniques | LLM02 | AML.T0004 | L1 |
| Response · Loss Reduction | Insurance for data compromise | ASI01 | AML.T0048.001 Financial Impact | L10 |
| Response · Loss Reduction | Cease-and-desist policy for deletion of info | LLM02 | AML.T0048 | L10 |

### Variance Management Controls

| Function | Control | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| Prevention · Reduce Variance | Consumers trained in acceptable use | LLM09 Misinformation | AML.T0048 | L10 |
| Prevention · Reduce Variance | Consumers receive privacy-policy training | LLM02 | AML.TA0009 | L10 |
| Identification · Monitoring | Hardening review for GenAI usages | LLM03 Supply Chain | AML.T0010 | L5, L6 |
| Identification · Monitoring | Validate effectiveness of training | LLM09 | AML.T0048 | L10 |
| Identification · Monitoring | Periodic policy review for GenAI usage | LLM03 | AML.T0010 | L10 |
| Identification · Monitoring | User access review performed periodically | ASI03 | AML.TA0006 | L7 |
| Identification · Monitoring | Inventory of permitted GenAI applications | LLM03 | AML.T0010 | L10 |
| Identification · Monitoring | Inventory of sensitive information | LLM02 | AML.TA0009 | L3, L10 |
| Identification · Monitoring | Application vulnerability testing (periodic) | LLM01 | AML.T0031 | L5, L8 |
| Identification · Monitoring | Monitor user behavior for bot behavior | ASI07 | AML.T0051.002 | L9 |
| Correction · Implementation | Revoke overly permissive user access | LLM06 Excessive Agency | AML.TA0005 | L7 |
| Correction · Implementation | Update misconfigurations and vulnerabilities | LLM05 Output Handling | AML.TA0005 | L5 |
| Correction · Implementation | Ensure credential rotation is performed regularly | ASI03 | AML.TA0006 | L7-T02 |
| Correction · Implementation | Revoke access to compromised credentials | ASI03 | AML.TA0006 | L7-T02 |

### Decision Support Controls

| Function | Control | OWASP | ATLAS | MAESTRO |
|---|---|---|---|---|
| Prevention · Expectations | Acceptable Use Policy exists for GenAI | LLM09 Misinformation | AML.T0048 | L10 |
| Prevention · Expectations | Data classification policy documented | LLM02 | AML.TA0009 | L10, L3 |
| Prevention · Awareness | Risk analysis | ASI01 Goal Hijacking | AML.T0031 | L10 |
| Prevention · Awareness | Reporting of incidents to executive and board | LLM08 Insecure Output Handling† | AML.T0048 | L10 |
| Prevention · Incentives | Ensure publicly available code includes licenses | LLM03 Supply Chain | AML.T0010 | L10 |
| Misaligned Decisions · Analysis | Root cause analysis reviewed | ASI01 | AML.T0048 | L10 |

### Using the control library in an assessment

In a Section 8 per-threat block's **Recommended Mitigations** field, you can pair the MAESTRO per-layer guidance with a concrete FAIR-CAM control and its function class. Example: for an `L7-T02` credential-theft finding, cite "Ensure credential rotation is performed regularly (FAIR-CAM VMC · Correction)" and "Revoke access to compromised credentials (VMC · Correction)" alongside the MAESTRO mitigation. The FAIR-CAM function (Prevention / Detection / Response, or Variance / Decision) maps onto MAESTRO's preventive/detective/corrective taxonomy and onto the OWASP playbooks' Proactive/Reactive/Detective tagging.

---

## Part 3 — Trust & Identity-Lifecycle Threat Taxonomy

Load this part when the assessment scope includes **agent identity, session/credential lifecycle, trust relationships, delegation chains, or trust-decay / monitoring-evasion** concerns — the surfaces where an agent's *standing trust* (rather than a single malicious input) is the exploited asset. These ~41 threats enumerate failure modes of persisted trust, inherited authority, and the controls that are supposed to re-verify it.

This is a **third artifact**, structurally distinct from Part 1 (the `AITech-*`/`AISubtech-*` technique taxonomy) and Part 2 (the FAIR-CAM control library). It maps each named threat across three external frameworks: **OWASP Agentic Top 10 (2026)**, **MITRE ATLAS tactic**, and **CSA AICM v1.1 control(s)**. As in Parts 1 and 2, the **MAESTRO layer** column is this skill's interpretive addition tying each entry to the spine — it is not part of the source.

**Secondary-lens rule still applies.** These threat names and their ASI / ATLAS / AICM / ISO tags are **not** MAESTRO layer IDs and must never be substituted for `L<n>-T<nn>`. Establish the MAESTRO layer threat first, then cite the matching row here (and its AICM control / ISO clause) to enrich the finding — the same discipline used for STRIDE/ATLAS/OWASP in `framework-crosswalk.md`. The AICM controls named below are also directly usable as a **Step 4 mitigation source**, alongside the FAIR-CAM library in Part 2.

**Note on the OWASP Agentic Top 10 IDs used here.** This part uses the **ASI01–ASI10** numbering (Identity & Privilege Abuse = ASI03, Memory & Context Poisoning = ASI06, etc.) consistent with the canonical OWASP Agentic Top 10 table in `framework-crosswalk.md` — *not* the inconsistent ASI05 multi-modal labels flagged in Part 1's source caveats. The ATLAS column gives **tactics** (e.g. Credential Access, Defense Evasion) rather than technique IDs; pair with Part 1 technique IDs (`AITech-*`) when technique-level granularity is needed.

> **⚠️ AICM control caveat.** Three controls below are tagged in the source as **proposed / not-yet-canonical** AICM v1.1 entries — `LOG-16 (Proposed Behavioral Drift Detection)`, plus the behavioral-drift surface generally. These map to the structural AICM gaps documented in `ssrm-ownership.md` (§"Six categories of AICM gap" — behavioral drift, sub-agent delegation, cross-org agent trust). Where a finding centers on one of those gaps, name the gap explicitly rather than citing a tangentially-related existing control, and verify any control ID against the authoritative AICM v1.1 catalog before audit-grade citation.

### Family T-A — Session, Credential & Trust Persistence (→ MAESTRO L7, L3)

The agent reuses a credential, token, approval, or trust decision **past the point where it should have been re-verified**. The asset is the *durability* of an authentication or authorization artifact.

| Threat | OWASP Agentic (2026) | MITRE ATLAS Tactic | CSA AICM v1.1 Control(s) | MAESTRO |
|---|---|---|---|---|
| Session Reuse | ASI03 Identity & Privilege Abuse | Credential Access | AIS-14 (AI Cache Protection) | L7-T02 |
| Token Persistence | ASI03 Identity & Privilege Abuse | Credential Access | IAM-07 (Access Revocation) | L7-T02 |
| Approval Reuse | ASI09 Human-Agent Trust Exploitation | Defense Evasion | IAM-18 (Special Authorization) | L4-T07, L7 |
| Delegated Credential Reuse | ASI03 Identity & Privilege Abuse | Credential Access / Lateral Movement | IAM-15 (Secrets Management); AIS-14 (AI Cache Protection) | L7-T02, L4-T05 |
| Cached Identity Assertions | ASI03 Identity & Privilege Abuse | Credential Access | AIS-14 (AI Cache Protection) | L7-T02, L3 |
| Stale Trust Decisions | ASI03 Identity & Privilege Abuse | Privilege Escalation | IAM-07 (Access Revocation); CCC-04 (Change Authorization) | L7-T03 |

### Family T-B — Memory & Historical-Context Trust Abuse (→ MAESTRO L3)

The agent over-trusts persisted memory, retrieved history, or prior preferences. These overlap the context-engineering threats (CE-T1 poisoning, CE-T7 stale retention) — apply that lens when the system has RAG / long-term memory.

| Threat | OWASP Agentic (2026) | MITRE ATLAS Tactic | CSA AICM v1.1 Control(s) | MAESTRO |
|---|---|---|---|---|
| Long-Term Memory Trust Abuse | ASI06 Memory & Context Poisoning | Collection / Impact | DSP-21 (Data Poisoning Prevention); AIS-14 (AI Cache Protection) | L3-T03 (CE-T1) |
| Historical Context Poisoning | ASI06 Memory & Context Poisoning | Data Poisoning | DSP-21 (Data Poisoning Prevention) | L3-T04 (CE-T1) |
| Preference Persistence Attacks | ASI06 Memory & Context Poisoning | Data Poisoning | DSP-21 (Data Poisoning Prevention); DSP-23 (Data Integrity Check) | L3-T03 |
| Context Inheritance | ASI06 Memory & Context Poisoning | Collection | AIS-08 (Input Validation); DSP-24 (Data Differentiation) | L3 (CE-T7) |
| Retrieval Trust Abuse | ASI01 Agent Goal Hijacking; ASI06 Memory & Context Poisoning | Execution / Impact | AIS-08 (Input Validation); DSP-23 (Data Integrity Check) | L3-T04, L4-T02 |
| Cross-Session Contamination | ASI06 Memory & Context Poisoning | Collection | AIS-14 (AI Cache Protection); DSP-24 (Data Differentiation) | L3 (CE-T7) |
| Historical Trust Abuse | ASI06 Memory & Context Poisoning | Defense Evasion / Impact | DSP-21 (Data Poisoning Prevention); AIS-14 (AI Cache Protection) | L3-T03 (CE-T1) |

### Family T-C — Inter-Entity Trust Abuse (Agent / Tool / MCP / SaaS / Tenant) (→ MAESTRO L6, L7, L4)

Trust extended *between* entities is abused for lateral movement, execution, or cross-boundary exfiltration. The Agent-to-MCP and Agent-to-Tool rows are the direct MCP/tool surface; for A2A propagation, evaluate against the L6-T01/T02 multi-agent threats.

| Threat | OWASP Agentic (2026) | MITRE ATLAS Tactic | CSA AICM v1.1 Control(s) | MAESTRO |
|---|---|---|---|---|
| Agent-to-Agent Trust Abuse | ASI07 Insecure Inter-Agent Comm. | Lateral Movement | AIS-11 (Agents Security Boundaries) | L6, L4 |
| Agent-to-Tool Trust Abuse | ASI02 Tool Misuse & Exploitation | Execution | AIS-11 (Agents Security Boundaries); AIS-13 (AI Sandboxing) | L6-T04 |
| Agent-to-MCP Trust Abuse | ASI02 Tool Misuse & Exploitation; ASI07 Insecure Inter-Agent Comm. | Execution / Lateral Movement | AIS-11 (Agents Security Boundaries); AIS-10 (API Security) | L6-T04, L6-T08 |
| Agent-to-SaaS Trust Abuse | ASI02 Tool Misuse & Exploitation | Lateral Movement / Exfiltration | AIS-10 (API Security); STA-10 (Primary Service Contract) | L6-T06 |
| Cross-Tenant Trust Violations | ASI03 Identity & Privilege Abuse; ASI06 Memory & Context Poisoning | Exfiltration / Impact | I&S-06 (Segmentation and Segregation); DSP-24 (Data Differentiation) | L3, L6-T06 |
| Trust Relationship Injection | ASI07 Insecure Inter-Agent Comm. | Lateral Movement | AIS-11 (Agents Security Boundaries); IPY-03 (Secure Interoperability) | L6, L4 |

### Family T-D — Trust Inheritance, Delegation & Chain Compromise (→ MAESTRO L4, L7)

Privilege or trust flows *down a delegation chain* and is inherited, escalated, or compromised at a link. Maps onto delegation-chain escalation (`L4-T05`) and permission-inheritance abuse (`L7-T07`).

| Threat | OWASP Agentic (2026) | MITRE ATLAS Tactic | CSA AICM v1.1 Control(s) | MAESTRO |
|---|---|---|---|---|
| Trust Chain Compromise | ASI08 Cascading Failures | Lateral Movement / Impact | BCR-04 (Business Continuity Planning); AIS-11 (Agents Security Boundaries) | L4, L6-T02 |
| Trust Inheritance Abuse | ASI03 Identity & Privilege Abuse | Privilege Escalation | IAM-09 (Segregation of Privileged Roles); AIS-11 (Agents Security Boundaries) | L7-T07, L4-T05 |
| Delegated Trust Exploitation | ASI03 Identity & Privilege Abuse | Privilege Escalation | IAM-09 (Segregation of Privileged Roles); AIS-11 (Agents Security Boundaries) | L7-T07, L4-T05 |

### Family T-E — Trust-Decay & Monitoring Evasion (Rogue-Agent Surface) (→ MAESTRO L9, L10)

The agent (or an adversary acting through it) degrades the controls that are supposed to re-verify trust over time — reducing verification frequency, masking behavior, suppressing risk signals. This is the **ASI10 Rogue Agents** cluster; it maps primarily to monitoring (L9) and governance (L10), and the mitigations are detective/corrective. Distinguish audit-grade logging from eval/observability per SKILL.md rule 4.

| Threat | OWASP Agentic (2026) | MITRE ATLAS Tactic | CSA AICM v1.1 Control(s) | MAESTRO |
|---|---|---|---|---|
| Verification Frequency Reduction | ASI10 Rogue Agents | Defense Evasion | MDS-10 (Model Continuous Monitoring); LOG-03 (Security Monitoring & Alerting) | L9 |
| Monitoring Blind Spots | ASI10 Rogue Agents | Defense Evasion | LOG-03 (Security Monitoring & Alerting); LOG-07 (Logging Scope) | L9 |
| Policy Drift | ASI10 Rogue Agents | Defense Evasion | LOG-16 (Proposed Behavioral Drift Detection); CCC-07 (Detection of Baseline Deviation) | L9, L10 |
| Trust Decay Exploitation | ASI10 Rogue Agents | Persistence / Defense Evasion | MDS-10 (Model Continuous Monitoring); CCC-07 (Detection of Baseline Deviation) | L9 |
| Risk Signal Suppression | ASI10 Rogue Agents | Defense Evasion | LOG-02 (Audit Logs Protection); LOG-09 (Log Protection) | L9-T02 |
| Continuous Assessment Failure | ASI10 Rogue Agents | Defense Evasion | MDS-10 (Model Continuous Monitoring); A&A-01 (Audit & Assurance Policies) | L9, L10 |
| Behavioral Masking | ASI10 Rogue Agents | Defense Evasion | LOG-16 (Proposed Behavioral Drift Detection); MDS-10 (Model Continuous Monitoring) | L9, L8 |
| Verification Suppression | ASI10 Rogue Agents | Defense Evasion | TVM-13 (Threat Response); LOG-13 (Anomalies Reporting) | L9 |

### Family T-F — Trust/Reputation Scoring & Confidence Manipulation (→ MAESTRO L9, L10, L2)

The *signals used to compute trust* (reputation, trust score, expressed confidence) are inflated or spoofed. Overlaps the supply-chain surface (**ASI04**) where the manipulated reputation belongs to a third-party agent/tool.

| Threat | OWASP Agentic (2026) | MITRE ATLAS Tactic | CSA AICM v1.1 Control(s) | MAESTRO |
|---|---|---|---|---|
| Trust Score Manipulation | ASI04 Supply Chain Vulnerabilities; ASI10 Rogue Agents | Defense Evasion | GRC-10 (AI Impact Assessment); STA-12 (Supply Chain Compliance) | L9, L10 |
| Reputation Inflation | ASI04 Supply Chain Vulnerabilities; ASI10 Rogue Agents | Defense Evasion | GRC-10 (AI Impact Assessment); STA-12 (Supply Chain Compliance) | L6, L10 |
| Reputation Manipulation | ASI04 Supply Chain Vulnerabilities; ASI10 Rogue Agents | Defense Evasion | GRC-10 (AI Impact Assessment); STA-12 (Supply Chain Compliance) | L6, L10 |
| Confidence Spoofing | ASI09 Human-Agent Trust Exploitation | Defense Evasion / Manipulation | GRC-13 (Explainability Requirement); AIS-09 (Output Validation) | L2, L10 |
| Goal-Action Mismatch | ASI01 Agent Goal Hijacking; ASI10 Rogue Agents | Intent Manipulation | AIS-15 (Prompt Differentiation); TVM-11 (Guardrails) | L4-T02, L8 |

### Family T-G — Authentication / Authorization / Policy / Approval Bypass (→ MAESTRO L7, L8, L4)

A control that *gates* an action is bypassed outright — authentication, authorization, policy enforcement, or human approval. Distinct from Family T-A (which reuses a still-valid artifact past its window); here the gate is evaded.

| Threat | OWASP Agentic (2026) | MITRE ATLAS Tactic | CSA AICM v1.1 Control(s) | MAESTRO |
|---|---|---|---|---|
| Authentication Bypass | ASI03 Identity & Privilege Abuse | Defense Evasion | IAM-14 (Strong Authentication); IAM-16 (Authorization) | L7-T01 |
| Authorization Bypass | ASI02 Tool Misuse & Exploitation; ASI03 Identity & Privilege Abuse | Privilege Escalation | AIS-11 (Agents Security Boundaries); IAM-16 (Authorization) | L7-T03, L6 |
| Policy Enforcement Bypass | ASI10 Rogue Agents | Defense Evasion | TVM-11 (Guardrails); AIS-11 (Agents Security Boundaries) | L8-T01 |
| Approval Workflow Bypass | ASI09 Human-Agent Trust Exploitation | Execution | GRC-15 (Human Supervision); IAM-18 (Special Authorization) | L4-T07 |

### Family T-H — Trust Forgery & Malicious Onboarding (Supply-Chain Entry) (→ MAESTRO L6, L4, L10)

An adversary forges a trust assertion or abuses the onboarding/registration path to enter the trust fabric as a seemingly-legitimate entity. The **ASI04 supply-chain** entry point.

| Threat | OWASP Agentic (2026) | MITRE ATLAS Tactic | CSA AICM v1.1 Control(s) | MAESTRO |
|---|---|---|---|---|
| Trust Assertion Forgery | ASI04 Supply Chain Vulnerabilities; ASI07 Insecure Inter-Agent Comm. | Defense Evasion | STA-16 (Service Bill of Material); IPY-03 (Secure Interoperability) | L6-T04, L7-T01 |
| Agent Onboarding Abuse | ASI04 Supply Chain Vulnerabilities | Initial Access / Persistence | STA-08 (Supply Chain Inventory); GRC-09 (Acceptable Use of AI) | L6, L10-T01 |

### Using Part 3 in an assessment

These threats are the right lens when the evidenced system has **persistent agent identity, delegated authority, long-lived sessions/tokens, cross-agent or cross-tenant trust, or trust/reputation scoring**. Workflow:

1. Establish the MAESTRO layer threat first (Section 8 stays keyed on `L<n>-T<nn>`).
2. Where a Part 3 row matches, cite the threat name + its ASI / ATLAS-tactic tags parenthetically (the same way `framework-crosswalk.md` cites OWASP `T<n>`), and pull the AICM control(s) and ISO clause(s) into the finding.
3. Use the named AICM control(s) as a Step 4 mitigation source — pair with the FAIR-CAM function class from Part 2 (Prevention / Detection / Response) and the MAESTRO per-layer guidance. Family T-E/T-F threats are predominantly **detective/corrective**; Family T-A/T-G are predominantly **preventive**.
4. For findings centered on behavioral drift, sub-agent delegation, or cross-org agent trust, treat `LOG-16 (Proposed …)` as a placeholder for a not-yet-canonical control: name the structural AICM gap (per `ssrm-ownership.md` §"Six categories of AICM gap") rather than over-claiming coverage, and reconcile any control ID against the authoritative AICM v1.1 catalog before audit-grade citation (per the caveat above and SKILL.md rule 6).
## Source caveats

**OCR splices repaired (3).** The string "Loss Event Control (LEC) Functions" was spliced mid-word into three source cells. Each was reconstructed unambiguously from the surrounding letters and is marked *(OCR-repaired)* inline:
- `AITech-11.2`: "Model-Se…tive Evasion" → **Model-Selective Evasion**
- `AISubtech-15.1.23`: "IP: Intel…tual Property Plagiarism" → **Intellectual Property Plagiarism**
- LEC control: "prompt and metadata col…tion disabled" → **collection disabled**

**Label inconsistencies left as-given (not corrected).** These require reconciliation against authoritative sources; this skill does not silently rewrite them:
- **ASI05** is labeled "Multi-modal Poisoning" in some rows and "Unexpected Code Execution" in others (9.1.1, 12.1.3). The canonical OWASP Agentic Top 10 used elsewhere in this skill has ASI05 = Unexpected Code Execution. Flagged with `*` in Part 1.
- **† LLM08** appears as "Insecure Output Handling," but in the OWASP LLM Top 10 (2025) LLM08 is *Vector & Embedding Weaknesses* / the 2025 list places Excessive Agency at LLM06 and System-Prompt Leakage at LLM07; "Insecure Output Handling" was an earlier-edition entry. The source mixes editions. Flagged with `†`.
- A few ATLAS IDs use tactic codes (`AML.TA0005` Execution, `AML.TA0006` Privilege Escalation, `AML.TA0007` Persistence, `AML.TA0009` Exfiltration) where a *technique* ID would be more precise. Preserved as-given.

**MAESTRO column is this skill's addition** — it is an interpretive mapping to tie each technique/control/threat to the spine, not part of the source data. Where a clean `L<n>-T<nn>` match exists it is named; otherwise only the layer is given. This applies to Parts 1, 2, and 3 alike.

**Part 3 source cleanup.** The Part 3 trust/identity threat set was transcribed from a tabular source whose framework cells carried trailing provenance markers ("Google Docs" / "PDF" / "TXT") and ~40% duplicate rows; these were removed and the set deduplicated to 41 unique threats. Part 3 uses the canonical **ASI01–ASI10** OWASP Agentic numbering (consistent with `framework-crosswalk.md`), not the inconsistent ASI05 labels flagged above. Its ATLAS column gives **tactics**, not technique IDs. `LOG-16 (Proposed Behavioral Drift Detection)` is a non-canonical/proposed AICM entry — treat it as a placeholder for a structural AICM gap (see `ssrm-ownership.md`) and verify against the AICM v1.1 catalog before audit-grade citation.

**Reconcile before high-stakes citation.** For any assessment where a specific OWASP/ASI/ATLAS ID carries weight (audit, compliance attestation), verify the tag against the live OWASP 2025 lists and the current MITRE ATLAS matrix rather than relying on the source's label.
