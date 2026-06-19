# MAESTRO v2.0 — Ten-Layer Threat Reference

This file is the layer-by-layer threat catalog used by the AI Threat Model Analyst skill. Each layer entry lists: definition, components, SSRM owner, key AICM controls, and the canonical sample threats (`L<n>-T<nn>`). Use these threat IDs verbatim in Section 8 of the assessment output.

**Source**: MAESTRO v2.0 (CSA, Apr 2026, v0.91 draft), Section 7.

## Table of contents

- [Domain 1 — Infrastructure, Intelligence & Knowledge](#domain-1)
  - L1 Infrastructure
  - L2 Cognitive Core
  - L3 Data, Memory, and Knowledge
- [Domain 2 — Environment and Execution](#domain-2)
  - L4 Orchestration and Coordination
  - L5 Deployment and Execution
  - L6 Tools, Application, Environment, and Ecosystem
- [Domain 3 — Agency, Governance, and Accountability (Horizontal)](#domain-3)
  - L7 Identity and Autonomy
  - L8 Safety and Security
  - L9 Monitoring and Observability
  - L10 Governance, Authority, and Compliance

---

## <a name="domain-1"></a>Domain 1 — Infrastructure, Intelligence & Knowledge

Typical owner: CDO / Head of Data Science / ML Engineering / VP Infrastructure. Control type: primarily preventive, build-time. Review cadence: quarterly and on model/infrastructure changes.

### L1 — Infrastructure

**Definition.** Compute, network, storage, and platform infrastructure on which agents execute. The physical/cloud foundation under all higher layers.

**Components.**
- *Network*: VPC segmentation, distributed network policies, egress filtering, NDR traffic inspection, service mesh (Istio, Linkerd), API gateways with DPI.
- *Endpoint*: container/VM runtime security, EDR/XDR, process integrity monitoring, supply-chain verification, image signing and scanning, kernel-level protections.
- *Storage & compute*: datacenter physical security, hypervisor security, encryption at rest and in transit, HSMs, secure enclaves (TEE).

**Primary SSRM owner.** CSP. AIC selects the CSP, defines infrastructure requirements, validates via CSA STAR / AI-CAIQ.

**Key AICM controls.** I&S-01–09, DCS-01–15, CEK-01–21, BCR-01–11.

**Sample threats.**
- **L1-T01 Infrastructure compromise via supply chain attack** — malicious code in base images, compromised CI/CD pipelines, or backdoored deployment dependencies.
- **L1-T02 Lateral movement from compromised infrastructure** — pivot from infrastructure access to data stores or model endpoints.
- **L1-T03 Resource exhaustion attacks** — DoS against compute required for agent inference.
- **L1-T04 Credential theft from infrastructure layer** — service-account keys or API keys stolen from infrastructure components.

**Key considerations.** Agent inference requires GPU compute, high-bandwidth network paths for tool invocation, low-latency storage for memory. Each is attack surface not present in traditional cloud workloads.

---

### L2 — Cognitive Core

**Definition.** The probabilistic engines that generate reasoning, decisions, and outputs. LLMs, SLMs, vision and multi-modal models. Covers pre-training data, model architecture, safety alignment (RLHF, Constitutional AI, DPO), and fine-tuning pipelines.

**Components.** Base model weights and architecture; training data and provenance; fine-tuning datasets and processes; safety alignment mechanisms; model serving infrastructure; API endpoints and access controls; system prompts and persona definitions.

**Primary SSRM owner.** MP for base model training, safety alignment, and hosted inference. CSP shared for model hosting infrastructure. AIC configures system prompts, selects models, and implements application-level defenses.

**Key AICM controls.** MDS-01–13, AIS-08–09 (I/O Validation), AIS-15 (Prompt Differentiation).

**Sample threats.**
- **L2-T01 Model extraction attack** — systematic querying to reconstruct model weights or decision boundaries.
- **L2-T02 Training data poisoning** — malicious data injected into training or fine-tuning to create backdoors.
- **L2-T03 Prompt injection / jailbreak** — adversarial inputs that bypass safety alignment and alter model behavior.
- **L2-T04 Model supply-chain attack** — compromised weights, backdoored open-source models, or malicious model formats.
- **L2-T05 Safety alignment degradation** — fine-tuning that inadvertently or deliberately weakens guardrails.
- **L2-T06 Model inversion attack** — extracting training data from model outputs.

**Key considerations.** Weights, training code, and deployment endpoints are sensitive. Enterprises fine-tuning vendor base models on proprietary data introduce new attack surface. The AICM's 13 MDS controls govern this layer.

---

### L3 — Data, Memory, and Knowledge

**Definition.** Grounds agents in reality through knowledge retrieval, memory management, and context engineering. The "knowledge layer" connecting models to real-world information and maintaining persistent state.

**Components.** Vector databases and embedding models; document ingestion pipelines; RAG (chunking, indexing, retrieval); context engineering (the seven context threats CE-T1 poisoning, CE-T2 distraction, CE-T3 confusion, CE-T4 clash, CE-T5 compression-loss, CE-T6 overflow, CE-T7 stale retention); short-term memory (context window); long-term memory (episodic/semantic stores); knowledge graphs; data sanitization and validation; access control and row-level security.

**Primary SSRM owner.** AIC (Agent Owner) primary for data governance, privacy, and integrity. CSP shared for storage and encryption. MP shared for embedding-model integrity. OSP shared for data-pipeline orchestration.

**Key AICM controls.** DSP-01–24, DSP-21 (Data Poisoning Prevention), DSP-23–24 (Data Integrity, Data Differentiation).

**Sample threats.**
- **L3-T01 RAG poisoning** — injection of malicious documents into the retrieval corpus to manipulate agent behavior.
- **L3-T02 Vector database access-control bypass** — unauthorized access to vector stores containing sensitive embeddings.
- **L3-T03 Memory pollution** — corruption of agent memory stores to influence future decisions.
- **L3-T04 Context poisoning** — malicious information contaminating the context window (the in-context surface of the CE-T1 poisoning threat; distinct from L3-T01 RAG-corpus poisoning by ownership — prompt/model-core vs. data-engineering).
- **L3-T05 Embedding inversion attack** — reconstructing original text from vector embeddings.
- **L3-T06 Knowledge graph manipulation** — altering relationships in knowledge graphs to mislead agent reasoning.
- **L3-T07 Context overflow attack** — deliberately exceeding context limits to force lossy compression.

**Key considerations.** This is the critical boundary between external data and the agent's decision-making process. Context engineering is the dominant security concern in production — when this layer is in scope, evaluate all seven context threats (CE-T1 through CE-T7) against the evidence.

---

## <a name="domain-2"></a>Domain 2 — Environment and Execution

Typical owner: CPO / Head of Application Development / Product Engineering / Platform Engineering. Control type: preventive and detective, runtime and per-release. Review cadence: per release and for new agent capabilities.

### L4 — Orchestration and Coordination

**Definition.** Orchestrates model inference, memory management, planning, tool invocation, and sub-agent coordination. Frameworks: LangGraph, Semantic Kernel, AutoGen, CrewAI.

**Components.** Orchestration engines/frameworks; planning and reasoning loops; tool governance registries; sub-agent coordination and delegation; workflow state management; human-in-the-loop mechanisms; skill libraries and invocation logic; permission narrowing for delegation chains.

**Primary SSRM owner.** OSP primary for the orchestration platform. AP shared for application-level orchestration policy. AIC defines delegation policies and workflow approval rules.

**Key AICM controls.** AIS-11 (Agent Security Boundaries), AIS-10 (API Security), IPY-01–04.

**Sample threats.**
- **L4-T01 Infinite planning loop** — unbounded reasoning cycles consuming resources.
- **L4-T02 Goal hijacking via orchestration manipulation** — attacker modifies the orchestration flow to redirect goals.
- **L4-T03 Sub-agent coordination failure** — conflicting instructions or sync failure across sub-agents.
- **L4-T04 Unauthorized tool invocation** — agent invokes tools outside its authorized scope via orchestration bypass.
- **L4-T05 Delegation chain privilege escalation** — sub-agent inherits or exceeds parent agent's permissions.
- **L4-T06 Workflow state tampering** — modification of workflow state to alter execution paths.
- **L4-T07 Human-in-the-loop bypass** — agent circumvents required human approval steps.

**Key considerations.** Agents use tools adaptively and modify their approach based on results. This layer is the "decision-making brain." For multi-agent systems, additionally evaluate agent-to-agent boundaries, cascading leaks, jailbreak proliferation, collusion, and delegation-chain escalation (L4-T05).

---

### L5 — Deployment and Execution

**Definition.** Runtime environment and deployment pipeline for agent systems. Containerization, CI/CD, runtime isolation, service deployment, execution security.

**Components.** Kubernetes / container orchestration; CI/CD pipeline security; runtime isolation and sandboxing; service mesh management; blue/green and canary deployments; rollback mechanisms; resource allocation and limits; runtime integrity monitoring.

**Primary SSRM owner.** CSP + OSP. CSP provides deployment infrastructure and container security. OSP provides runtime orchestration and coordinated deployment. AP shared for deployment configuration. AIC defines rollback policies and approval.

**Key AICM controls.** CCC-01–09, AIS-04–06 (SDLC, Testing, Deployment), I&S-01–09.

**Sample threats.**
- **L5-T01 Container escape** — agent process breaks out of container isolation to access the host.
- **L5-T02 CI/CD pipeline compromise** — malicious code injected via compromised build pipeline.
- **L5-T03 Runtime tampering** — modification of agent binaries or configurations at runtime.
- **L5-T04 Sandbox breakout** — agent escapes sandboxed execution (e.g., Python REPL).
- **L5-T05 Resource starvation** — competing agents or processes consume shared resources.
- **L5-T06 Deployment rollback exploitation** — attacker triggers rollback to a known-vulnerable version.

**Key considerations.** Separating L5 from L1 reflects that deployment/runtime security has distinct owners (DevOps/Platform Engineering), distinct AICM controls (CCC domain), and distinct threat patterns.

---

### L6 — Tools, Application, Environment, and Ecosystem

**Definition.** How agents interact with tools, users, other agents, business processes, and external systems. User interfaces, tool protocols (MCP), multi-agent protocols (A2A), digital marketplaces, third-party integrations.

**Components.** User-facing applications; tool integration via MCP; multi-agent communication protocols (A2A); agent marketplaces and skill registries; third-party integrations and APIs; business-process automation; agent-to-agent authentication; collaborative multi-agent workflows; circuit breakers and fail-safes.

**Primary SSRM owner.** OSP + AP + **Tool Provider** for tool integration and ecosystem management. The Tool Provider is a 3SRM extension to the AICM's five-role supply chain, formally recognized at L6 where TaaS (MCP servers, plugins, external tool APIs) is structurally distinct from CSP/OSP/AP. The STA domain (16 controls) governs supply-chain management for tools, plugins, and MCP servers. STA-16 (Service BOM) is AIC-owned — the Agent Owner must maintain a complete inventory of tool dependencies.

**Key AICM controls.** AIS-11–13 (Agent Boundaries, Source Code, Sandboxing), STA-01–16, TVM-01–13.

**Sample threats.**
- **L6-T01 Agent-to-agent social engineering** — malicious agent manipulates another via crafted communication.
- **L6-T02 Cascade failures in multi-agent systems** — error in one agent propagates through the network.
- **L6-T03 Business logic abuse** — agent exploits legitimate processes for unauthorized outcomes.
- **L6-T04 MCP server compromise** — malicious or vulnerable MCP tool server provides poisoned outputs.
- **L6-T05 Agent marketplace threats** — trojan-horse agents or skills in third-party marketplaces.
- **L6-T06 API abuse and exfiltration** — agent misuses API access to exfiltrate data or invoke unauthorized services.
- **L6-T07 User interface manipulation** — deceptive agent outputs that mislead users into unsafe actions.
- **L6-T08 Tool definition poisoning** — modification of tool descriptions to cause agent to misuse tools.

**Key considerations.** Tool providers are a distinct supply-chain actor under the Agent SSRM. Tool security must be verified via STA-domain controls — not assumed. For multi-agent flows, additionally evaluate inter-agent communication (L6-T01), cascade failures (L6-T02), and A2A trust abuse.

---

## <a name="domain-3"></a>Domain 3 — Agency, Governance, and Accountability (Horizontal)

Typical owner: CISO / CTO / VP SecOps / VP Platform Engineering. Control type: preventive, detective, and corrective — continuous. Review cadence: continuous monitoring with quarterly reporting.

**Horizontal layers (L7–L10) span all operational layers.** Identity applies to L1 access and L6 tool invocation. Safety controls govern L2 model behavior and L6 ecosystem interactions. Monitoring covers L1 telemetry and L4 behavioral drift. Treat these as cross-cutting in the assessment.

### L7 — Identity and Autonomy

**Definition.** Manages agent identity, authentication, authorization, and autonomy boundaries. Cross-cuts all operational layers.

**Components.** Non-human identity lifecycle management; agent authentication and authorization; service-account provisioning and deprovisioning; credential rotation and short-lived (JIT) credentials; agent-to-agent identity federation; autonomy-level configuration; permission scoping and narrowing; human-in-the-loop escalation triggers; agent behavioral boundaries.

**Primary SSRM owner.** AIC (AP) primary. The AICM IAM domain (19 controls) is the framework. CSP shared for identity infrastructure and certificates. OSP shared for agent-to-agent federation.

**Key AICM controls.** IAM-01–19, IAM-18 (Output Modification & Special Authorization), GRC-15 (Human Supervision).

**Sample threats.**
- **L7-T01 Agent identity forgery** — adversaries forge agent identities to bypass trust mechanisms.
- **L7-T02 Credential theft and replay** — stolen agent credentials used to impersonate legitimate agents.
- **L7-T03 Over-privileged agent identities** — agents with permissions exceeding operational need.
- **L7-T04 Autonomy boundary violation** — agent exceeds configured autonomy without triggering human oversight.
- **L7-T05 Session hijacking** — takeover of active agent sessions.
- **L7-T06 Improper trust escalation** — compromised agents falsely escalate tasks appearing to come from authorized sources.
- **L7-T07 Permission inheritance abuse** — sub-agents inheriting or expanding parent permissions beyond intended scope.

**Key considerations.** Agent identity *is* the control plane for agentic security. Every action an agent takes is mediated by identity. Without robust non-human identity management, all other controls can be bypassed.

---

### L8 — Safety and Security

**Definition.** Defines and enforces safety and security controls across all operational layers. Cross-cuts L1–L6. Each provider bears safety/security responsibility within its delivery layer; the Agent Owner is the integrating party.

**Components.** Behavioral guardrails and safety filters; input/output validation; adversarial robustness testing; security incident response; safety alignment verification; prompt-injection detection; hallucination detection and mitigation; circuit breakers for unsafe behavior; red-teaming frameworks.

**Primary SSRM owner.** Shared by all roles within their delivery layers. TVM-11 (Guardrails) shifts: CSP–MP at platform infrastructure, MP at Model, MP–OSP at Orchestrated Services, AP at Application. AIC is the integrating authority.

**Key AICM controls.** TVM-11 (Guardrails), AIS-08–09 (I/O Validation), MDS-06–07 (Adversarial Attack), SEF-01–09 (Security Incident Management).

**Sample threats.**
- **L8-T01 Guardrail bypass** — adversarial techniques that circumvent safety filters.
- **L8-T02 Safety alignment degradation through fine-tuning** — fine-tuning that weakens built-in safety mechanisms.
- **L8-T03 Cascading safety failures** — safety failure in one component propagating through the agent chain.
- **L8-T04 Incident response blind spots** — security incidents in agent systems that evade traditional SOC detection.
- **L8-T05 Adversarial robustness failure** — model fails under adversarial conditions not covered by red-teaming.

**Key considerations.** Safety is distinct from security. An agent can be perfectly secure — authenticated, encrypted, authorized — and still cause harm through misaligned behavior, hallucinated outputs, or cascading autonomous decisions. L8 addresses both dimensions.

---

### L9 — Monitoring and Observability

**Definition.** Systems used to test, monitor, and evaluate agents across all operational layers. Telemetry pipelines, logging frameworks, drift detection, red-teaming, SOC integration.

**Components.** Red-teaming frameworks; prompt and context logging; synthetic test data generation; behavioral baselines and drift detection; OpenTelemetry collection; immutable (WORM) logging; SIEM/SOAR integration; explainability tools (Chain-of-Thought logging); performance and cost metrics; agent behavioral analytics.

**Primary SSRM owner.** Shared by all roles. CSP provides infrastructure-level monitoring. MP provides model-level monitoring via MDS-10. OSP provides orchestration telemetry. AP provides application logging. AIC integrates into a coherent posture.

**Key AICM controls.** LOG-01–15, LOG-14–15 (I/O Monitoring), MDS-10 (Model Monitoring).

**Sample threats.**
- **L9-T01 Monitoring blind spots** — agent activity outside telemetry coverage.
- **L9-T02 Log tampering** — modification or deletion of audit trails to hide misbehavior.
- **L9-T03 Drift detection bypass** — behavioral drift that evades detection algorithms.
- **L9-T04 Explainability manipulation** — agent generates plausible but misleading explanations.
- **L9-T05 Telemetry poisoning** — injection of false telemetry to mask actual behavior.
- **L9-T06 Alert fatigue exploitation** — generating noise to desensitize monitoring teams.

**Key considerations.** Operational metrics extend beyond safety — drift, performance, resource usage, cost. Logs must be tamper-evident and stored separately from the agent execution environment. A compromise at any operational layer should generate observable signals at L9. Evaluation/monitoring is NOT the same as audit-grade logging — do not conflate them in the assessment.

---

### L10 — Governance, Authority, and Compliance

**Definition.** Policies, compliance mapping, audit mechanisms, and the Trust Control Plane. The governance substrate for the entire architecture.

**Components.** Policy-as-code frameworks (OPA, Cedar); compliance automation (PCI DSS, GDPR, EU AI Act); ABAC/RBAC for agent identities; trust metrics and dashboards; audit trail management and evidence collection; risk assessment frameworks; regulatory reporting; third-party assessment and certification; AI ethics governance.

**Primary SSRM owner.** AIC. **Governance is non-delegable.** GRC-09 (Acceptable Use), GRC-10 (AI Impact Assessment), GRC-11 (Bias and Fairness), GRC-12 (Ethics Committee) are AIC-owned regardless of deployment model. All providers support governance via compliance attestations.

**Key AICM controls.** GRC-01–15, A&A-01–06, HRS-14–15, GRC-09–12 (AI-specific).

**Sample threats.**
- **L10-T01 Shadow AI / rogue agents** — unauthorized agents operating outside organizational governance.
- **L10-T02 Policy bypass** — agent actions that violate governance policies without detection.
- **L10-T03 Compliance drift** — gradual deviation from regulatory requirements as agent systems evolve.
- **L10-T04 Trust metric manipulation** — gaming of trust scores or governance dashboards.
- **L10-T05 Audit trail gaps** — incomplete or missing audit records for agent actions.
- **L10-T06 Regulatory non-compliance** — agent behavior that violates AI-specific regulations (EU AI Act, etc.).

**Key considerations.** Governance is the one domain that cannot be outsourced. Regardless of deployment model (AaI, AaP, AaaS), the Agent Owner always retains governance responsibility. In the assessment, L10 ownership is always AIC.

---

## Extended threat scenarios (OWASP T16–T25 → MAESTRO)

These ten scenarios come from OWASP's agentic threat-modeling work (the extension set beyond the T1–T15 taxonomy in `framework-crosswalk.md`). They are **concrete, often application-specific manifestations** of the canonical MAESTRO threats above — not new layers. The source paper presented them under an independent 8-layer scheme; that scheme is **not used here** because its layer numbers collide with MAESTRO's L1–L10. Each scenario is instead mapped to its MAESTRO home below. Use the MAESTRO `L<n>-T<nn>` ID as primary in Section 8; cite the OWASP `T<n>` ID parenthetically when the user wants OWASP alignment.

| OWASP | Scenario | MAESTRO home | Notes |
|---|---|---|---|
| **T16** | Model inconsistency leading to variable approvals | **L2** | Foundation-model non-determinism produces inconsistent policy decisions. Closest canonical threat is the L2 behavioral surface; not a clean match to any single L2-T id — treat as an L2 reliability/safety finding with L8 (guardrail consistency) and L10 (policy) impact. |
| **T17** | Semantic drift in embeddings | **L3** | Stale embeddings not updated when source data changes → outdated retrieval. Maps to CE-T7 (Stale Context Retention); L3 data-freshness surface. |
| **T18** | RAG input manipulation leading to policy bypass | **L3-T01** | Inputs crafted to resemble valid vector-DB entries, exploiting similarity retrieval to bypass policy. A RAG-poisoning variant (L3-T01) with CE-T1 overlap. |
| **T19** | Unintended workflow execution | **L4** | Steps executed out of order or validation skipped. Relates to L4-T06 (Workflow State Tampering) and L4-T02 where goals are subverted; flag HITL-bypass (L4-T07) if validation gates are skipped. |
| **T20** | Framework vulnerability to code injection | **L5-T02 / L6** | Security flaw in the agent framework allows code injection/execution. Framework-level manifestation of T11 (Unexpected RCE); maps to L5-T02 (CI/CD / build) or L6 (framework/tool surface) depending on where the flaw sits. |
| **T21** | Inconsistent workflow state | **L4** | Unsynchronized views of shared state (shared memory, graph data) cause conflicting actions or DoS. L4 orchestration/state surface; cross-ref CE-T4 (Context Clash) for multi-agent shared-context cases. |
| **T22** | Service account exposure | **L7-T02** | Agent service-account credentials exposed → unauthorized access / privilege escalation. Maps to L7-T02 (Credential Theft & Replay) with L1-T04 (infra credential theft) and L7-T03 (over-privilege) impact. |
| **T23** | Selective log manipulation | **L9-T02** | Specific log entries altered/removed to conceal activity while leaving others intact. A targeted variant of L9-T02 (Log Tampering); reinforces the audit-grade-logging distinction in skill rule #4. |
| **T24** | Dynamic policy enforcement failure | **L10-T02** | Flaws in a dynamic policy engine produce incorrect/inconsistent/missing policy application. Maps to L10-T02 (Policy Bypass) with L8 (guardrail) impact. |
| **T25** | Workflow disruption via dependency exploitation | **L6** | A dependency (third-party API, plugin, peer agent/system) is targeted to interrupt primary-agent workflows. L6 ecosystem/supply-chain surface; cross-ref STA-domain controls and multi-agent coordination-manipulation patterns for multi-agent cases. |

**Usage**: when an assessment surfaces one of these patterns in the evidence, document it in Section 8 under its MAESTRO home using the standard per-threat block, and note the OWASP `T<n>` ID. Do not introduce the 8-layer scheme into the output — it would conflict with the MAESTRO layer mapping that anchors the assessment.

---

## Quick-reference table

| Layer | Name | Domain | Horizontal? | Primary SSRM Owner |
|-------|------|--------|-------------|--------------------|
| L1 | Infrastructure | 1 | No | CSP |
| L2 | Cognitive Core | 1 | No | MP |
| L3 | Data, Memory, Knowledge | 1 | No | AIC |
| L4 | Orchestration & Coordination | 2 | No | OSP |
| L5 | Deployment & Execution | 2 | No | CSP + OSP |
| L6 | Tools, Application, Ecosystem | 2 | No | OSP + AP + Tool Provider |
| L7 | Identity & Autonomy | 3 | Yes | AIC |
| L8 | Safety & Security | 3 | Yes | AIC (integrating) |
| L9 | Monitoring & Observability | 3 | Yes | AIC (integrating) |
| L10 | Governance & Compliance | 3 | Yes | AIC (non-delegable) |
