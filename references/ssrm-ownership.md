# Shared Security and Safety Responsibility Model (Agent 3SRM)

Load this reference for Step 4 of the methodology (mitigation and ownership assignment). Every threat in the assessment must have an SSRM owner attached.

**Terminology note.** The CSA's full name is the **Agent Shared Security and Safety Responsibility Model**, abbreviated either **Agent 3SRM** or **Agent SSRM** (and sometimes **SSSRM** in early drafts). MAESTRO v2.0 uses "Agent SSRM"; the standalone paper uses "Agent 3SRM". They refer to the same framework. This skill uses both interchangeably depending on which source is being cited.

**Sources**: MAESTRO v2.0 (CSA, Apr 2026), Section 9; *AI Agents: Shared Security and Safety Responsibility Model* (CSA, Apr 2026, v0.981); AI Controls Matrix (AICM) v1.1.

---

## The six AICM/3SRM roles

The Agent 3SRM extends the AICM v1.1 five-role supply chain with a sixth role — the **Tool Provider** — to reflect that TaaS (tools delivered as a service via MCP, plugins, and similar protocols) is a structurally distinct actor in agentic systems. Use these abbreviations in the assessment output.

- **CSP — Cloud Service Provider.** Underlying compute, storage, networking, and platform infrastructure. *AICM scope*: Processing Infrastructure (PI) column.
- **MP — Model Provider.** Develops, trains, and serves foundation models, including training-pipeline security and model integrity. *AICM scope*: Model column.
- **OSP — Orchestrated Service Provider.** The orchestration layer that integrates models with tools, APIs, and workflows. *AICM scope*: Orchestrated Services column.
- **AP — Application Provider.** Builds and delivers the end-user application, including agent logic and application-level security. *AICM scope*: Application column.
- **AIC — AI Customer.** The organization or individual consuming the AI-powered application. Responsible for data governance, acceptable use, and organizational compliance. *AICM scope*: Owns DSP-01, GRC-09–12, DSP-23–24 among others.
- **Tool Provider (TaaS Provider).** *3SRM extension, not yet a recognized AICM role*. Develops, hosts, and maintains tools that agents discover and invoke at runtime through MCP and similar protocols. Distinct from CSP (no general infrastructure), OSP (no orchestration), and AP (no agent application). Currently partially covered by STA, AIS-11, AIS-13. The 3SRM recommends future AICM versions formally introduce this role.

### The Agent Service Provider (Agent Provider)

The **Agent Service Provider** (or simply Agent Provider) is a *specialization* of the AP role rather than a new role in the supply chain. It is the entity that develops, maintains, and delivers agents as a service (AaaS). Where a traditional SaaS provider delivers applications for human consumption, the Agent Provider delivers autonomous agents that consume applications and tools on behalf of organizations.

The Agent Provider is responsible for the agent's design integrity, skills, scaffolds, knowledge, world models, and ongoing maintenance. Its obligations are governed by the AICM's STA domain (supply chain transparency, STA-01–15; service BOM, STA-16) and contractual commitments.

### The Agent Owner overlay

The **Agent Owner** is the entity bearing ultimate, **non-delegable** accountability for all agent actions. The Agent Owner is *not* a new role in the supply chain — it is a **functional overlay** that maps to one or more existing AICM roles depending on the deployment model.

| Deployment Model | Agent Owner Maps To | Rationale |
|---|---|---|
| Self-built agent on own or cloud-based infrastructure | AIC + Agent Provider + OSP (+ MP if fine-tuning) | Organization controls the full stack from model selection through application delivery |
| Agent built on a managed platform | AIC + Agent Provider | Organization builds the agent; consumes orchestration/model from providers |
| Pre-built agent consumed as a service (AaaS) | AIC | Organization consumes a vendor's agent; vendor is AP (and possibly OSP, MP) |

Regardless of which role(s) the Agent Owner occupies, the principle is constant: **the Agent Owner is always accountable for everything the agent and its sub-agents do.** This accountability is non-delegable; it cannot be transferred to a Model Provider, Tool Provider, or any other supply-chain actor by contract.

**The Agent Owner's responsibilities, per 3SRM §3.1**:
- **Selection and Due Diligence** — choosing providers that meet security/safety requirements (STA domain, STA-16 Service BOM, AI-CAIQ questionnaire).
- **Configuration and Policy** — defining behavioral boundaries, autonomy levels, tool access permissions, safety guardrails (AIS-11, TVM-11, GRC-09).
- **Monitoring and Oversight** — continuous visibility into agent behavior (LOG-14/15) and human oversight enforcement (GRC-15).
- **Incident Response** — responding to incidents regardless of which provider's component was the proximate cause (SEF domain).
- **Sub-Agent Accountability** — accepting responsibility for all sub-agents in the delegation chain. The governing principle: delegating execution does not delegate accountability — responsibility flows to the full depth of the chain, and the Agent Owner is accountable for every sub-agent's actions regardless of how many delegation hops separate them.

---

## Six-layer agent deployment model (aaS stack)

The Agent 3SRM extends the cloud (3-layer) and AI (4-layer) as-a-service stacks to **six layers**. Each layer corresponds to who delivers what:

| Layer | Description | SSRM Role |
|---|---|---|
| **IaaS** | Compute, storage, networking, physical infrastructure | CSP |
| **MaaS** | Foundation model development, training, fine-tuning, inference serving | MP |
| **P/OaaS** | Platform / Orchestration — service integration, orchestration, data pipelines, runtime coordination | OSP |
| **AaaS** | Autonomous agents delivered as a service, with skills, scaffolds, knowledge, world models | AP (Agent Provider) |
| **SaaS** | Software / applications (consumed by agents as much as by humans now) | AP |
| **TaaS** | Tools, APIs, plugins, MCP servers that agents discover and invoke at runtime | Tool Provider |

**Key structural observation** (3SRM §2.3): SaaS and TaaS sit at the same level. Both provide capabilities agents consume — SaaS delivers applications (originally designed for humans, being adapted for agent consumption), TaaS delivers tools (designed natively for machine invocation). Together they constitute MAESTRO Layer 6 (Tools, Application, Environment, and Ecosystem).

The **AaaS layer** is the structurally distinguishing feature of the agent era. Below AaaS, the stack provides capabilities. **At AaaS, those capabilities become an autonomous agent.** Above AaaS, SaaS and TaaS provide the external resources the agent consumes to act.

---

## Responsibility matrix — MAESTRO layers × AICM/3SRM roles

`P` = Primary · `S` = Shared · `C` = Configures / Consumes · `A` = Agent Owner Accountable (always applies).

The Tool Provider column is shown where relevant; in current AICM ownership designations, Tool Provider responsibilities are absorbed into shared categories (AIS-11, AIS-13, STA domain).

| MAESTRO v2 Layer | CSP | MP | OSP | AP | Tool Prov | AIC / Agent Owner | Key AICM Controls |
|---|---|---|---|---|---|---|---|
| **L1 Infrastructure** | P | — | — | — | — | C/A | I&S-01–09, DCS-01–15, CEK-01–21, BCR-01–11 |
| **L2 Cognitive Core** | S | P | S | — | — | C/A | MDS-01–13, AIS-08–09, AIS-15 |
| **L3 Data, Memory, Knowledge** | S | S | S | S | — | P/A | DSP-01–24, DSP-21, DSP-23–24 |
| **L4 Orchestration & Coordination** | — | S | P | S | S | S/A | AIS-11, AIS-10, IPY-01–04 |
| **L5 Deployment & Execution** | P | — | P | S | — | C/A | CCC-01–09, AIS-04–06, I&S-01–09 |
| **L6 Tools, Application, Ecosystem** | — | S | P | P | **P** | S/A | AIS-11–13, STA-01–16, TVM-01–13 |
| **L7 Identity & Autonomy** | S | — | S | S | S | P/A | IAM-01–19, IAM-18, GRC-15 |
| **L8 Safety & Security** | S | S | S | S | S | P/A | TVM-11, AIS-08–09, MDS-06–07, SEF-01–09 |
| **L9 Monitoring & Observability** | S | S | S | S | S | P/A | LOG-01–15, LOG-14–15, MDS-10 |
| **L10 Governance & Compliance** | C | C | C | C | C | P/A | GRC-01–15, A&A-01–06, HRS-14–15 |

**L6 reading**: with the Tool Provider added, L6 has **three Primary** owners — OSP (orchestration of tool invocation), AP (application logic exposing tools), and Tool Provider (the tool itself). This is the layer where the six-role model materially changes ownership analysis.

---

## Key principles (use these verbatim in the SSRM Ownership section)

**Non-delegable accountability.** The Agent Owner (AIC) bears ultimate accountability for all agent actions, regardless of which provider's component was the proximate cause. **Governance (L10) is always the Agent Owner's responsibility.** This accountability follows the delegation chain to its full depth — delegating execution does not delegate accountability.

**Horizontal-layer shared responsibility.** Layers 7–10 are cross-cutting. Each provider contributes component-level implementation within its delivery layer; the Agent Owner serves as the integrating authority.

**Defense in depth.** Multiple parties share responsibility at each layer. The 3SRM ensures no security gaps exist between vendor and enterprise.

**Clear boundaries.** The AICM's nine ownership designations (Owned by, Shared, Shared across supply chain) provide unambiguous responsibility attribution at the control level. The 3SRM extends this to the architectural layer level.

**Continuous verification.** The AI-CAIQ questionnaire enables periodic reassessment of provider control implementation.

**Cumulative evolution.** Each era inherits and extends: CCM SSRM (2 roles, 3 layers) → AICM SSRM (5 roles, 4 layers) → Agent 3SRM (6 roles, 6 layers). As the customer consumes more of the stack from providers, operational responsibility shifts but governance accountability does not.

---

## Six categories of AICM gap (3SRM §2.6)

The Agent 3SRM identifies six categories where AICM v1.1 is structurally insufficient for agentic systems. Flag these in assessments where the system exhibits the relevant pattern — they represent areas where ownership attribution is genuinely ambiguous in the current framework:

1. **Sub-Agent Delegation.** When a primary agent spawns sub-agents, who owns the security of the delegation chain? AICM's five-role model does not address intra-agent delegation or accountability chains.
2. **Dynamic Tool Discovery.** Agents discover and invoke tools at runtime via MCP and similar. AICM addresses tool security (AIS-11, AIS-13) but not runtime tool binding — and does not recognize the Tool Provider as a distinct role.
3. **Autonomous Decision-Making.** AICM's ownership designations assume humans/organizations make control-implementation decisions. Agents make operational decisions autonomously, creating a layer of *behavioral* responsibility not captured by control ownership.
4. **Cross-Organizational Agent Collaboration.** When agents from different organizations interact via A2A protocols, the responsibility boundary between organizations needs explicit definition.
5. **Cascading Failures.** Multi-agent systems can experience cascading failures across delegation chains. AICM's per-control ownership does not address systemic risk across agent populations.
6. **Agent Lifecycle Accountability.** AICM addresses the AI service lifecycle. Agents have a distinct lifecycle — creation, deployment, runtime, sub-agent spawning, decommissioning — with different responsibility implications at each stage.

These gaps map directly to MAESTRO layers: (1, 3, 6) → L4/L7; (2) → L6; (4) → L6/L7; (5) → L4/L6/L8. Where the current AICM catalog lacks a clean control for one of these gaps, say so in the finding rather than citing a tangentially-related existing control as if it covered the gap.

---

## Deployment model variations

The Agent 3SRM varies across agent deployment models. **Identify which model applies before assigning ownership.** If the deployment model isn't evidenced, mark it as a clarifying-question candidate or flag as `Unanswerable from current evidence`.

| Model | Description | Agent Owner AICM Roles | Analogy |
|---|---|---|---|
| **Agent-as-Infrastructure (AaI)** | Agent Owner builds and operates agents on rented infrastructure. CSP provides L1/L6 infrastructure. MP provides the foundation model. Owner controls everything else. | AIC + AP + OSP | IaaS |
| **Agent-as-Platform (AaP)** | Agent Owner builds agents on a managed agent platform (e.g., LangGraph Cloud, AWS Bedrock Agents). Platform vendor serves as OSP (and partially CSP). | AIC + AP | PaaS |
| **Agent-as-Service (AaaS)** | Agent Owner consumes pre-built agents from a vendor. Vendor serves as AP + OSP (and potentially MP). | AIC | SaaS |

### Per-layer responsibility shift across deployment models (3SRM §8.2)

| MAESTRO Layer | AaI (Owner = AIC+AP+OSP) | AaP (Owner = AIC+AP) | AaaS (Owner = AIC) |
|---|---|---|---|
| **L1 Infrastructure** | CSP | CSP / Platform | Vendor |
| **L2 Cognitive Core** | Owner + MP | Platform + MP | Vendor |
| **L3 Data, Memory, Knowledge** | Owner | Owner | Shared |
| **L4 Orchestration** | Owner | Platform (OSP) | Vendor |
| **L5 Deployment/Execution** | Owner + CSP | Platform | Vendor |
| **L6 Tools/Environment** | Owner + Tool Providers | Owner + Platform + Tools | Vendor + Tools |
| **L7 Identity & Autonomy** | Owner | Owner (on platform) | Shared |
| **L8 Safety & Security** | Owner (full) | Owner + Platform | Shared |
| **L9 Monitoring & Observability** | Owner (full) | Owner + Platform | Shared |
| **L10 Governance & Compliance** | Owner (always) | Owner (always) | **Owner (always)** |

**Quote this directly in the SSRM Ownership section whenever L10 is in scope**: "In all three deployment models, Layer 10 (Governance) remains with the Agent Owner. Governance cannot be outsourced."

---

## How to assign ownership in an assessment

For each threat in Section 8 of the output:

1. Look up the layer in the matrix above.
2. Read off the Primary and Shared owners. Include the Tool Provider where it materially applies (especially L6 threats involving MCP or external tools).
3. Note "Agent Owner accountable: yes (always, per 3SRM §3.1 and MAESTRO §9.3)" — this never changes.
4. If the deployment model affects assignment (AaI vs AaP vs AaaS), state which model is in play and how it shifts the role mapping. Use the §8.2 table above. If the model isn't evidenced, mark ownership as `Partial — depends on deployment model`.
5. For shared-responsibility threats (e.g., L8 has 5 shared owners), name **all** the parties — don't compress to a single owner. The whole point of the 3SRM is to surface these handoffs.
6. For threats involving sub-agent delegation, apply the delegation-chain principle: responsibility flows to the full depth of the chain and accountability is non-delegable — the Agent Owner answers for every sub-agent's actions, however many hops deep.

---

## Contractual considerations (3SRM §6.2)

When the assessment touches procurement, vendor management, or contract review (which it often does, indirectly), the 3SRM identifies five contractual implications worth flagging in Section 12 (Required Validation Steps):

- **AI-CAIQ as contractual baseline.** Use AI-CAIQ questionnaire responses as contractual annexes establishing provider commitments to specific AICM controls.
- **Shared Responsibility Addenda.** Explicitly map provider responsibilities to 3SRM layers and AICM control ownership designations in contracts.
- **Audit Rights.** Include right-to-audit clauses for AICM controls relevant to each provider's SSRM responsibilities (aligned with A&A-01–06).
- **Safety SLAs.** Specify safety metrics beyond traditional uptime — maximum hallucination rates, response time for human escalation (GRC-15), behavioral drift thresholds (LOG-14/15).
- **Delegation Chain Clauses.** Define contractual obligations for providers when their services are consumed by sub-agents in delegation chains.
