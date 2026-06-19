# AI Threat Model Assessment — Example Report (SEC545 Beta MCP Multi-Server Lab)

**Framework:** MAESTRO v2.0 (Cloud Security Alliance, Apr 2026)
**Method:** AI Threat Model Analyst skill — evidence-gated, layered.
**Evidence base:** The 14-question filled MAESTRO Threat Assessment worksheet ("Best Practice Answers"), dated 2/13/26, plus the named system artifacts it references.
**Evidence-gating rule:** All findings are gated on that worksheet. Items the worksheet does not support are marked **Unanswerable from current evidence** and the artifacts needed are listed, rather than inferred.

---

## 1. Understanding Confirmed

The request is for a full MAESTRO v2.0 threat assessment of the **SEC545 MCP multi-server lab** — a hands-on agentic AI lab environment composed of a GenAI application backend (`sec545-genaiapp`) fronted by a Model Context Protocol server cluster (`sec545-mcp-servers`), exposing filesystem, calendar, and multi-assistant query tools to one or more LLM agents. This is an agentic, tool-using, multi-agent system. MAESTRO is the correct framework; no down-scoping to a passive-LLM subset is warranted.

## 2. Scope and Assumptions

In scope: the evidenced components of the lab — MCP server cluster, the GenAI app backend, the tool surface, the orchestration/agent layer, the credential/secret artifacts, and the deployment substrate (Docker Compose).

- This assessment treats the lab as the unit of analysis. It is a **training lab**, not a production deployment; risk ratings reflect the architecture as built, not a hardened production posture.
- **Deployment model:** the evidence (self-built agent app, self-hosted MCP servers, Docker Compose, own model/embedding configuration via `bedrock.tf`) indicates **Agent-as-Infrastructure (AaI)**. Agent Owner therefore maps to **AIC + AP + OSP** (+ MP for the embedding/inference config). Where a finding's ownership hinges on this, it is stated.
- No control-effectiveness testing was performed; this is a design/architecture-evidence assessment, not a pentest.
- The three-bucket discipline is enforced throughout: **Current Evidence** (facts), **Reasonable Inferences** (bounded), **Unknowns / Missing Evidence** (gaps). They are never blended.

## 3. System Summary

The SEC545 lab is a self-hosted agentic stack. A GenAI application (`assistants_server.py`, `langchain_agent.py`) orchestrates one or more LLM-backed assistants and reaches external capability through an MCP client (`mcp_client.py`) into a cluster of MCP servers (`sec545-mcp-servers`). The MCP tool surface is broad and high-privilege: a full filesystem toolset (`read_file`, `write_file`, `list_directory`, `create_directory`, `delete_file_or_directory`, `copy_file_or_directory`, `move_file_or_directory`, `get_file_info`, `search_files`, `get_current_directory`), arbitrary command execution (`execute_command`), Google Calendar tools (`authorize_calendar_user`, `list_events`, `create_event`, `delete_event`, `get_free_busy`), and a set of assistant-routing tools (`query_security_assistant`, `query_movies_assistant`, `query_investment_assistant`, `query_multi_agent_assistant`, `query_langchain_agent`, `query_any_assistant`, `get_backend_status`).

The system is **multi-agent**: a multi-agent assistant (`query_multi_agent_assistant`) routes across specialized sub-assistants, and a LangChain agent is independently reachable. Retrieval/knowledge grounding is present via a Weaviate vector store (`deploy_weaviate.sh`, `weaviate-client==4.4.1`) with an embedding model configured through `bedrock.tf` (`embedding_model_arn`, `access_policy`, `data_source_sync`). Secrets are file-resident: `client_secret.json` (Google OAuth), `.env` (`OPENAI_API_KEY`, `HUGGINGFACE_KEY`, `SERPAPI_API_KEY`), `users.json`, and a `.tokens` store. Deployment is via `docker-compose.yml`/`dockercompose.yml`; container user handling is partially evidenced (`USER appuser` appears, but its consistency across all services is not).

**This is an agentic system** with tools, memory/retrieval, sub-agents, and autonomous tool invocation. Full MAESTRO scope applies.

## 4. Evidence Available

Drawn directly from the worksheet and the artifacts it names:

- **Tool surface (L6):** filesystem suite, `execute_command`, calendar suite, assistant-router suite — all enumerated above.
- **MCP architecture (L6):** `sec545-mcp-servers` cluster, `mcp_client.py`, MCP transport configured via `TRANSPORT`/`HOST`/`PORT`/`BACKEND_URL`; worksheet indicates **stdio** transport in at least one path.
- **Orchestration / agents (L4):** `assistants_server.py`, `langchain_agent.py`, `query_multi_agent_assistant`, `query_langchain_agent`.
- **Retrieval / knowledge (L3):** Weaviate (`deploy_weaviate.sh`, `weaviate-client==4.4.1`), embedding config in `bedrock.tf`, `data_source_sync`, `context-engineering.md` referenced as a control artifact.
- **Cognitive core (L2):** model/embedding configuration via `bedrock.tf` (`embedding_model_arn`); generation models reached via `OPENAI_API_KEY`/`HUGGINGFACE_KEY`.
- **Identity / secrets (L7):** `client_secret.json`, `.env`, `users.json`, `.tokens`, `authorize_calendar_user`.
- **Deployment (L5/L1):** `docker-compose.yml`, `requirements.txt`, `deploy_weaviate.sh`, `bedrock.tf` (IaC), partial `USER appuser` directive.
- **Governance/secret-hygiene artifacts (L10/L9):** `.gitignore`, `check-keys.sh`, plus design notes `context-engineering.md`, `multi-agent-threats.md`, `proposed-aicm-extensions.md`, `output-templates.md`, `aicm-iso42001-mapping.md`.

## 5. Immediate Gaps / Missing Information

The worksheet leaves several determinative items unsupported. These cap the confidence of dependent findings:

- **Identity model for agents/tools (L7):** No evidence the MCP tools run under per-task, scoped, or short-lived identities. Whether `execute_command` and the filesystem tools execute with the same broad privilege as the agent is **Unanswerable from current evidence**.
- **Authorization / tool-gating policy (L4/L7):** No evidence of an allow-list, human-in-the-loop gate, or per-tool authorization for destructive tools (`delete_file_or_directory`, `execute_command`). Worksheet marks the relevant question **Unanswerable**.
- **Audit-grade logging (L9):** `check-keys.sh` and design notes exist, but no evidence of tamper-evident, retained, IR-queryable logs. Observability ≠ audit logging (skill rule #4). **Unanswerable.**
- **Secret-at-rest protection (L7/L1):** Secrets are file-resident (`.env`, `client_secret.json`, `users.json`, `.tokens`). `.gitignore` reduces commit risk but does not encrypt or vault them. Whether a secrets manager/KMS is in play is **Unanswerable**.
- **Container isolation completeness (L5):** `USER appuser` appears for at least one service; whether every service (notably the `execute_command` host) drops root and is sandboxed is **Unanswerable**.
- **Vector-store access control (L3):** No evidence of authn/row-level controls on Weaviate. **Unanswerable.**
- **Worksheet-flagged ambiguity:** the worksheet itself records "asks / different / not / Unanswerable" against several transport and identity questions — these are carried forward as gaps, not resolved.

## 6. MAESTRO Layer Mapping

Only evidenced components are mapped. "No evidence in this layer" is stated where applicable rather than invented.

| Layer | Name | Evidenced components in this system |
|---|---|---|
| **L1** | Infrastructure | Docker host substrate, `bedrock.tf` IaC, network exposure via `HOST`/`PORT`; physical/cloud infra otherwise unspecified |
| **L2** | Cognitive Core | OpenAI / HuggingFace generation models (via `.env` keys); Bedrock embedding model (`embedding_model_arn`) |
| **L3** | Data, Memory, Knowledge | Weaviate vector store, `data_source_sync`, embeddings, `context-engineering.md` |
| **L4** | Orchestration & Coordination | `assistants_server.py`, `langchain_agent.py`, multi-agent router (`query_multi_agent_assistant`) |
| **L5** | Deployment & Execution | `docker-compose.yml`, `deploy_weaviate.sh`, `requirements.txt`, partial `USER appuser` |
| **L6** | Tools, Application, Ecosystem | `sec545-mcp-servers`, `mcp_client.py`, filesystem suite, `execute_command`, calendar suite, assistant-router tools |
| **L7** | Identity & Autonomy | `client_secret.json`, `.env`, `users.json`, `.tokens`, `authorize_calendar_user` |
| **L8** | Safety & Security | No dedicated guardrail/IO-validation component evidenced — **No positive evidence in this layer** (analyzed as a gap) |
| **L9** | Monitoring & Observability | `check-keys.sh` (secret-presence check only); no audit-grade logging evidenced |
| **L10** | Governance & Compliance | `.gitignore`, design notes (`multi-agent-threats.md`, `proposed-aicm-extensions.md`, `aicm-iso42001-mapping.md`) — governance artifacts, no enforcement engine evidenced |

## 7. Assessment Status by Layer

- **L1 Infrastructure** — Partially Answerable. IaC and exposure evidenced; physical/network controls not.
- **L2 Cognitive Core** — Partially Answerable. Models identified; training/alignment provenance out of scope (vendor-hosted).
- **L3 Data, Memory, Knowledge** — Answerable for architecture; access-control posture Unanswerable.
- **L4 Orchestration & Coordination** — Answerable. Multi-agent routing and tool invocation evidenced; gating policy Unanswerable.
- **L5 Deployment & Execution** — Partially Answerable. Compose evidenced; isolation completeness Unanswerable.
- **L6 Tools, Application, Ecosystem** — Answerable. This is the richest, best-evidenced layer.
- **L7 Identity & Autonomy** — Partially Answerable. Secret artifacts evidenced; scoping/lifecycle Unanswerable.
- **L8 Safety & Security** — Answerable as a gap (absence of controls is itself the finding).
- **L9 Monitoring & Observability** — Unanswerable (no audit-grade logging evidenced).
- **L10 Governance & Compliance** — Partially Answerable. Governance artifacts exist; enforcement Unanswerable.

## 8. Detailed Threat Analysis

Findings are grouped by layer. MAESTRO `L<n>-T<nn>` IDs are primary; OWASP `T<n>` IDs are cited parenthetically where they apply.

---

### L6-T04 — MCP Server Compromise / Over-Broad Tool Surface (maps to OWASP T2 Tool Misuse)

**MAESTRO Layer**
- L6: Tools, Application, Environment, and Ecosystem (Domain 2)

**Current Evidence**
- The MCP cluster exposes `execute_command` (arbitrary command execution) and a full destructive filesystem suite including `delete_file_or_directory`, `move_file_or_directory`, and `write_file`.
- A single agent path can reach all of these tools through `mcp_client.py`.

**Reasonable Inferences**
- An agent that can be steered (via prompt injection at L2/L3) into calling `execute_command` effectively has shell-equivalent capability on the MCP server host.

**Unknowns / Missing Evidence**
- Whether any allow-list, confirmation gate, or per-tool authorization wraps the destructive tools (worksheet: Unanswerable).

**Assessment Status** — Answerable (the exposure is evidenced; the mitigation state is the gap).

**Attack Vector** — Untrusted content reaches the model (user input, retrieved document, calendar event body) → model emits a tool call to `execute_command` or `delete_file_or_directory` → MCP server executes it with the server's privilege.

**Cross-Layer Impact** — L2 (injection origin) → L4 (orchestration passes the call) → **L6** (execution) → L1/L5 (host effect); L7 if the tool runs with broad identity.

**Likelihood / Impact / Risk** — Likelihood **High** (broad tools + no evidenced gating); Impact **High** (RCE-equivalent and data destruction); **Risk: High.**

**Recommended Mitigations** — Remove `execute_command` from the default tool surface or gate it behind explicit human approval (AIS-11 Agent Security Boundaries); apply per-tool allow-lists and least-capability tool scoping; sandbox the tool-execution host (AIS-13); make destructive filesystem tools require confirmation or operate within a constrained jail. Pair with FAIR-CAM prevention-class controls on tool invocation.

**SSRM Ownership**
- Primary: OSP + AP + **Tool Provider** (three Primary owners at L6)
- Shared: MP
- Agent Owner accountable: yes (always, per 3SRM §3.1 / MAESTRO §9.3). Under the AaI model the Owner here is AIC+AP+OSP.

**Required Evidence to Fully Answer** — Tool authorization policy / allow-list config; HITL gate configuration; the execution context (user, sandbox) of the MCP server process.

---

### L6-T08 — Tool Definition Poisoning (maps to OWASP T2 / T15)

**MAESTRO Layer**
- L6: Tools, Application, Environment, and Ecosystem (Domain 2)

**Current Evidence**
- Tools are advertised to the agent by description via MCP (`read_file`, `list_directory`, `search_files`, `execute_command`, etc.).

**Reasonable Inferences**
- If a tool description can be altered (e.g., a compromised or modified MCP server), the agent can be induced to misuse a benign-looking tool or to prefer a dangerous one.

**Unknowns / Missing Evidence**
- Whether MCP tool definitions are integrity-verified or pinned; whether server provenance is checked (STA domain). Unanswerable.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Modified tool metadata changes the agent's tool-selection behavior without any change to user input.

**Cross-Layer Impact** — L6 origin → L4 (tool-selection logic) → L2 (model acts on poisoned description).

**Likelihood / Impact / Risk** — Likelihood **Medium** (requires server-side modification in a lab); Impact **High**; **Risk: Medium.**

**Recommended Mitigations** — Integrity-verify and version-pin MCP tool definitions; STA-domain supply-chain verification of the server; maintain a Service BOM (STA-16, AIC-owned) of all tool dependencies.

**SSRM Ownership**
- Primary: Tool Provider + OSP
- Shared: AP
- Agent Owner accountable: yes (always).

**Required Evidence to Fully Answer** — Tool-definition integrity controls; MCP server build/provenance evidence.

---

### L3-T01 — RAG Poisoning (maps to OWASP T18 RAG Input Manipulation; T1 Memory Poisoning)

**MAESTRO Layer**
- L3: Data, Memory, and Knowledge (Domain 1)

**Current Evidence**
- A Weaviate vector store with `data_source_sync` grounds the assistants; `context-engineering.md` is present as a design artifact.

**Reasonable Inferences**
- Documents ingested into the corpus, or content synced via `data_source_sync`, can carry adversarial instructions that surface during retrieval and steer the agent toward tool misuse (links to L6-T04).

**Unknowns / Missing Evidence**
- Ingestion sanitization, source trust boundaries, and vector-store access control (L3-T02). Unanswerable.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Poisoned document enters the corpus → retrieved into context (CE-T1 in-context poisoning) → influences a downstream tool call.

**Cross-Layer Impact** — **L3** origin → L2 (reasoning) → L6 (tool action).

**Likelihood / Impact / Risk** — Likelihood **Medium**; Impact **High** (couples to the destructive tool surface); **Risk: Medium–High.**

**Recommended Mitigations** — Ingestion-time sanitization and provenance tagging (DSP-21 Data Poisoning Prevention, DSP-23 Data Integrity); source allow-listing for `data_source_sync`; treat retrieved content as untrusted at the orchestration boundary; evaluate the seven context-engineering threats (CE-T1 poisoning especially) against ingestion design.

**SSRM Ownership**
- Primary: AIC (Agent Owner) for data governance/integrity
- Shared: CSP (storage), MP (embedding integrity), OSP (pipeline)
- Agent Owner accountable: yes (always).

**Required Evidence to Fully Answer** — Ingestion pipeline config, source trust policy, Weaviate access-control configuration.

---

### L3-T07 / CE-T7 — Stale Context Retention / Semantic Drift (maps to OWASP T17 Semantic Drift)

**MAESTRO Layer**
- L3: Data, Memory, and Knowledge (Domain 1)

**Current Evidence**
- `data_source_sync` implies a sync cadence between source data and embeddings.

**Reasonable Inferences**
- If embeddings are not refreshed when source data changes, retrieval returns outdated content (CE-T7), producing decisions on stale grounds.

**Unknowns / Missing Evidence**
- Sync frequency and freshness guarantees. Unanswerable.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Source updated, embeddings not → agent reasons over outdated retrieval.

**Cross-Layer Impact** — L3 → L2.

**Likelihood / Impact / Risk** — Likelihood **Medium**; Impact **Low–Medium** (lab context); **Risk: Low–Medium.**

**Recommended Mitigations** — Define and monitor embedding-refresh SLAs; freshness metadata on retrieved chunks (DSP family).

**SSRM Ownership** — Primary: AIC; Shared: MP, OSP. Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — `data_source_sync` schedule and freshness policy.

---

### L4-T04 / L4-T07 — Unauthorized Tool Invocation & HITL Bypass (maps to OWASP T6 Intent Breaking; T19 Unintended Workflow Execution)

**MAESTRO Layer**
- L4: Orchestration and Coordination (Domain 2)

**Current Evidence**
- The orchestration layer (`assistants_server.py`, `langchain_agent.py`) can invoke the full L6 tool surface; no human-approval gate is evidenced for destructive tools.

**Reasonable Inferences**
- Without a gating step, the orchestrator will pass through a model-emitted destructive tool call autonomously.

**Unknowns / Missing Evidence**
- Existence of any approval/validation gate (L4-T07). Worksheet: Unanswerable.

**Assessment Status** — Answerable as a gap.

**Attack Vector** — Goal subversion or injection causes the orchestrator to invoke a tool outside intended scope with no checkpoint.

**Cross-Layer Impact** — L2 (injection) → **L4** → L6 (action).

**Likelihood / Impact / Risk** — Likelihood **High**; Impact **High**; **Risk: High.**

**Recommended Mitigations** — Insert HITL approval for destructive/irreversible tools (GRC-15 Human Supervision, AIS-11); scope each assistant's tool registry to least capability; workflow-state validation to prevent skipped gates.

**SSRM Ownership** — Primary: OSP; Shared: AP, MP; Agent Owner accountable: yes (AaI → AIC+AP+OSP).

**Required Evidence to Fully Answer** — Orchestration tool-gating / approval configuration.

---

### L4-T05 / L6-T01 — Delegation-Chain Escalation & Multi-Agent Trust Abuse (maps to OWASP T3 Privilege Compromise; T14)

**MAESTRO Layer**
- L4: Orchestration and Coordination (Domain 2), with L6 inter-agent surface

**Current Evidence**
- `query_multi_agent_assistant` routes across sub-assistants; `query_any_assistant` and `query_langchain_agent` provide cross-agent reach. Design note `multi-agent-threats.md` is present.

**Reasonable Inferences**
- A sub-assistant invoked through the router may inherit the parent's tool access; a compromised or injected sub-assistant can propagate instructions to peers (cascading leak / jailbreak proliferation).

**Unknowns / Missing Evidence**
- Per-sub-agent permission narrowing; whether sub-agents share the parent's identity/credentials. Unanswerable.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Injection lands in one assistant → propagates via `query_multi_agent_assistant` / `query_any_assistant` → reaches an assistant with destructive tool access.

**Cross-Layer Impact** — L4 origin → L6 (A2A propagation) → L7 (inherited privilege).

**Likelihood / Impact / Risk** — Likelihood **Medium**; Impact **High**; **Risk: Medium–High.**

**Recommended Mitigations** — Permission narrowing across delegation hops (IPY controls, AIS-11); per-sub-agent identity and scoped credentials; inter-agent message validation. Flag the **Sub-Agent Delegation** and **Cross-Org Collaboration** AICM structural gaps (3SRM §2.6) — current AICM lacks a clean control for intra-agent delegation accountability.

**SSRM Ownership** — Primary: OSP; Shared: MP, AP, Tool Provider; Agent Owner accountable: yes, to the full depth of the delegation chain (non-delegable).

**Required Evidence to Fully Answer** — Sub-agent permission model; credential-scoping per assistant.

---

### L7-T02 / L7-T03 — Service-Account Exposure & Over-Privileged Identity (maps to OWASP T22 Service Account Exposure; T9 Identity Spoofing)

**MAESTRO Layer**
- L7: Identity and Autonomy (Domain 3, horizontal)

**Current Evidence**
- Secrets are file-resident: `client_secret.json` (Google OAuth), `.env` (`OPENAI_API_KEY`, `HUGGINGFACE_KEY`, `SERPAPI_API_KEY`), `users.json`, `.tokens`. `authorize_calendar_user` mints/uses calendar authority.

**Reasonable Inferences**
- An agent with `read_file` over the working tree can read `.env`, `client_secret.json`, `users.json`, and `.tokens` — i.e., the tool surface can exfiltrate its own credentials. This couples L6 (read_file) directly to L7 (credential theft).

**Unknowns / Missing Evidence**
- Whether secrets are vaulted/KMS-backed rather than plaintext on disk; whether tool identities are scoped distinct from the agent. Unanswerable.

**Assessment Status** — Answerable for the exposure path; mitigation state Unanswerable.

**Attack Vector** — Injected agent calls `read_file('.env')` / `read_file('client_secret.json')` → returns live credentials → replay against OpenAI, Google, SerpAPI.

**Cross-Layer Impact** — **L7** ↔ L6 (read tool) ↔ L1-T04 (infra credential theft).

**Likelihood / Impact / Risk** — Likelihood **High** (plaintext secrets reachable by an evidenced tool); Impact **High** (third-party account compromise); **Risk: High.**

**Recommended Mitigations** — Move secrets out of the filesystem into a secrets manager/KMS (CEK domain); deny the filesystem toolset read access to secret paths; issue short-lived scoped credentials (IAM JIT); separate tool identity from agent identity (IAM-05 Least Privilege). `.gitignore` prevents commit leakage but does **not** address runtime read exposure.

**SSRM Ownership** — Primary: AIC (AP); Shared: CSP (identity infra), OSP (federation); Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Secrets-management design; filesystem-tool path restrictions; credential lifecycle (rotation, TTL).

---

### L5-T01 / L5-T04 — Container Escape / Sandbox Breakout (maps to OWASP T11 Unexpected RCE; T20 Framework Code Injection)

**MAESTRO Layer**
- L5: Deployment and Execution (Domain 2)

**Current Evidence**
- Deployment via `docker-compose.yml`; `USER appuser` appears for at least one service; `execute_command` provides an in-container command path.

**Reasonable Inferences**
- If the `execute_command` host runs privileged or as root, or shares the host namespace, a command-injection path escalates to host compromise.

**Unknowns / Missing Evidence**
- Whether all services drop root, set resource limits, and isolate the execution host; whether `USER appuser` is applied to the tool-executing container specifically. Unanswerable.

**Assessment Status** — Partially Answerable.

**Attack Vector** — `execute_command` invocation in an under-isolated container → host or cross-container reach.

**Cross-Layer Impact** — L6 (execute) → **L5** (escape) → L1 (host).

**Likelihood / Impact / Risk** — Likelihood **Medium**; Impact **High**; **Risk: Medium–High.**

**Recommended Mitigations** — Enforce non-root (`USER`) across **all** services; drop capabilities, set seccomp/AppArmor, read-only root fs; resource limits (CCC domain, AIS-13 Sandboxing); isolate the command-execution service.

**SSRM Ownership** — Primary: CSP + OSP; Shared: AP; Agent Owner accountable: yes (AaI → Owner + CSP).

**Required Evidence to Fully Answer** — Full Compose service definitions, container security context, host topology.

---

### L1-T03 — Resource Exhaustion (maps to OWASP T4 Resource Overload)

**MAESTRO Layer**
- L1: Infrastructure (Domain 1)

**Current Evidence**
- Agent reasoning/generation loop reaches external models and tools; no resource-limit evidence in Compose.

**Reasonable Inferences**
- An unbounded planning loop (L4-T01) or repeated tool calls can exhaust compute / hit paid-API rate limits and cost.

**Unknowns / Missing Evidence**
- Rate limits, loop bounds, quotas. Unanswerable.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Induced reasoning loop or tool-call flood.

**Cross-Layer Impact** — L4 (loop) → L1 (compute) → cost.

**Likelihood / Impact / Risk** — Likelihood **Medium**; Impact **Low–Medium** (lab); **Risk: Low–Medium.**

**Recommended Mitigations** — Loop/step caps in orchestration; per-tool rate limits; API spend quotas (BCR/CCC).

**SSRM Ownership** — Primary: CSP; Shared: OSP; Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Resource limits and loop-bound config.

---

### L8-T01 — Guardrail Bypass / Absence of I/O Validation

**MAESTRO Layer**
- L8: Safety and Security (Domain 3, horizontal)

**Current Evidence**
- No dedicated guardrail, prompt-injection detector, or I/O-validation component is evidenced in the architecture.

**Reasonable Inferences**
- With no L8 filter between untrusted input and a high-privilege tool surface, injection→tool-misuse chains (see L6-T04, L4-T04) have no compensating control.

**Unknowns / Missing Evidence**
- Whether any guardrail exists outside the evidenced artifacts. Unanswerable; analyzed as an absence.

**Assessment Status** — Answerable as a gap.

**Attack Vector** — Any injection vector reaches the model with no detection layer.

**Cross-Layer Impact** — L8 absence amplifies every L2/L3/L4/L6 finding above.

**Likelihood / Impact / Risk** — Likelihood **High**; Impact **High**; **Risk: High** (this is the missing compensating control for the whole chain).

**Recommended Mitigations** — Add input/output validation (AIS-08/09); prompt-injection detection and guardrails (TVM-11); circuit breakers for unsafe tool sequences. Owner-integrated per the L8 shared model.

**SSRM Ownership** — Shared across CSP/MP/OSP/AP/Tool Provider within their layers; **AIC is the integrating authority**; Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Any guardrail / validation component config.

---

### L9-T02 — Log Tampering / Audit-Trail Gaps (maps to OWASP T23 Selective Log Manipulation; T8 Repudiation)

**MAESTRO Layer**
- L9: Monitoring and Observability (Domain 3, horizontal)

**Current Evidence**
- `check-keys.sh` validates secret presence; no tamper-evident, retained, IR-queryable logging is evidenced.

**Reasonable Inferences**
- Without audit-grade logs, destructive tool actions (`delete_file_or_directory`, `execute_command`) cannot be reconstructed after the fact.

**Unknowns / Missing Evidence**
- Existence of WORM/SIEM-integrated logging. Unanswerable. (Skill rule #4: observability/eval ≠ audit logging.)

**Assessment Status** — Unanswerable from current evidence (treated as a gap).

**Attack Vector** — Action taken with no durable record; or selective entry removal.

**Cross-Layer Impact** — L9 gap blinds IR for all operational layers.

**Likelihood / Impact / Risk** — Unassessable for tampering specifically; the **logging-absence** risk is **High** for forensic readiness.

**Recommended Mitigations** — Tamper-evident (WORM) logging stored separately from the execution environment; log every tool invocation with arguments; SIEM/SOAR integration (LOG-01–15, LOG-14/15).

**SSRM Ownership** — Shared across all roles; AIC integrates; Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Logging architecture, retention, tamper-evidence design.

---

### L10-T02 — Policy Bypass / Dynamic Enforcement Failure (maps to OWASP T24 Dynamic Policy Enforcement Failure)

**MAESTRO Layer**
- L10: Governance, Authority, and Compliance (Domain 3, horizontal)

**Current Evidence**
- Governance design artifacts exist (`multi-agent-threats.md`, `proposed-aicm-extensions.md`, `aicm-iso42001-mapping.md`); no policy-as-code enforcement engine (OPA/Cedar) is evidenced.

**Reasonable Inferences**
- Governance intent is documented but not mechanically enforced at runtime, so policy and actual tool behavior can diverge silently.

**Unknowns / Missing Evidence**
- Any runtime policy engine. Unanswerable.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Agent action violates documented policy with no enforcing gate.

**Cross-Layer Impact** — L10 → L8 (guardrail) → L6 (action).

**Likelihood / Impact / Risk** — Likelihood **Medium**; Impact **Medium**; **Risk: Medium.**

**Recommended Mitigations** — Policy-as-code (OPA/Cedar) for tool authorization; ABAC/RBAC for agent identities; bind documented policy to enforced controls (GRC-01–15).

**SSRM Ownership** — Primary: **AIC — governance is non-delegable** (per the §8.2 rule, L10 remains with the Agent Owner in all deployment models); Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Policy-enforcement architecture.

---

## 9. Cross-Layer Path Analysis

The evidence supports three concrete attack chains. They share a common spine: **the system pairs a high-privilege tool surface with no evidenced L8 guardrail and no evidenced L7 credential isolation.**

**Path A — Injection to RCE/destruction.**
Untrusted input or retrieved content (L2/L3) → orchestrator passes model-emitted call with no gate (L4-T04/T07) → `execute_command` or `delete_file_or_directory` executes (L6-T04) → host effect, possibly container escape (L5-T01). The absence of L8 validation is what makes this chain end-to-end.

**Path B — Credential theft via the agent's own tools.**
Injection (L2) → `read_file` on `.env` / `client_secret.json` / `.tokens` (L6) → live third-party credentials returned (L7-T02) → replay against OpenAI / Google / SerpAPI (L1-T04). This is the highest-confidence chain because every step maps to an evidenced artifact.

**Path C — Multi-agent propagation.**
Injection lands in one assistant → propagates via `query_multi_agent_assistant` / `query_any_assistant` (L6-T01) → reaches an assistant holding destructive tools, inheriting privilege across the delegation hop (L4-T05). Confidence is bounded by the unknown sub-agent permission model.

No further cross-layer paths are manufactured beyond what the evidence supports.

## 10. SSRM Ownership Summary

Deployment model: **Agent-as-Infrastructure (AaI)** → Agent Owner = **AIC + AP + OSP** (+ MP for embedding/model config).

| Finding | Layer | Primary | Shared | Agent Owner Accountable |
|---|---|---|---|---|
| L6-T04 Tool surface / RCE | L6 | OSP + AP + Tool Provider | MP | Yes |
| L6-T08 Tool def poisoning | L6 | Tool Provider + OSP | AP | Yes |
| L3-T01 RAG poisoning | L3 | AIC | CSP, MP, OSP | Yes |
| L3-T07 Stale retention | L3 | AIC | MP, OSP | Yes |
| L4-T04/T07 Tool invocation / HITL | L4 | OSP | AP, MP | Yes |
| L4-T05 Delegation escalation | L4 | OSP | MP, AP, Tool Provider | Yes (full chain) |
| L7-T02/T03 Credential exposure | L7 | AIC (AP) | CSP, OSP | Yes |
| L5-T01/T04 Container escape | L5 | CSP + OSP | AP | Yes |
| L1-T03 Resource exhaustion | L1 | CSP | OSP | Yes |
| L8-T01 Guardrail absence | L8 | Shared (all roles) | — | Yes (AIC integrates) |
| L9-T02 Logging gap | L9 | Shared (all roles) | — | Yes (AIC integrates) |
| L10-T02 Policy bypass | L10 | **AIC (non-delegable)** | — | Yes |

**Verbatim governance principle:** *In all three deployment models, Layer 10 (Governance) remains with the Agent Owner. Governance cannot be outsourced.*

**Structural AICM gaps flagged (3SRM §2.6):** Sub-Agent Delegation and Cross-Organizational Collaboration (Path C / L4-T05) and Dynamic Tool Discovery (L6 MCP runtime binding) are areas where AICM v1.1 lacks a clean control — named here rather than papered over with a tangential control citation.

## 11. Framework Crosswalk

Full crosswalk, all lenses opted in. MAESTRO remains the analytical spine throughout — every mapping below expresses this system's evidenced findings (Section 8) in another framework's vocabulary; it does not introduce new findings. Where a framework structurally cannot attest a control family, that is stated rather than papered over. Only findings actually surfaced in Section 8 are mapped; rows are omitted where this system has no evidenced threat in that cell rather than padded with "N/A."

### 11.1 STRIDE

STRIDE is built for deterministic software; it is used here for the lab's traditional components (the MCP transport, the backend API, the Weaviate store) and pivots into MAESTRO for the AI-specific surface.

| STRIDE Category | This system's evidenced finding(s) | MAESTRO ID |
|---|---|---|
| **Spoofing** | Sub-agent / inter-agent trust abuse via the router | L4-T05 / L6-T01 |
| **Tampering** | RAG/corpus poisoning; tool-definition poisoning | L3-T01; L6-T08 |
| **Repudiation** | No audit-grade logging of tool actions | L9-T02 |
| **Information Disclosure** | Credential read-out via `read_file` on `.env`/`client_secret.json` | L7-T02 |
| **Denial of Service** | Resource exhaustion / unbounded loop | L1-T03 |
| **Elevation of Privilege** | Delegation-chain escalation; over-privileged tool identity | L4-T05; L7-T03 |

### 11.2 MITRE ATLAS

ATLAS supplies the adversarial *technique*; MAESTRO supplies the architectural *context*. The techniques that apply to this system's evidenced surface:

| ATLAS Technique | This system's finding | MAESTRO ID |
|---|---|---|
| LLM Prompt Injection | Injection is the entry step of Paths A–C | L2-T03 → L4-T02 |
| ML Supply Chain Compromise | MCP server compromise / tool-def poisoning | L6-T04 / L6-T08 |
| Exfiltration via ML Inference API | Credential / data exfil through tool surface | L6-T06 / L7-T02 |
| Evade ML Model | Guardrail bypass (absence of L8 control) | L8-T01 |

ATLAS techniques for *model extraction / inversion / training-data poisoning* (L2-T01/T02/T06) are **not mapped** — this lab consumes vendor-hosted models and shows no training/fine-tuning surface, so those techniques have no evidenced applicability. For technique-level granularity beyond this (the ~140 `AITech-*`/`AISubtech-*` library), that lens can be added; it was not, to avoid over-claiming detail the evidence doesn't reach.

### 11.3 OWASP LLM Top 10

| OWASP LLM | This system's finding | MAESTRO ID |
|---|---|---|
| LLM01 Prompt Injection | Entry vector, Paths A–C | L2-T03 / L4-T02 |
| LLM03 Training Data Poisoning | RAG corpus poisoning (data, not training) | L3-T01 |
| LLM04 Model Denial of Service | Resource exhaustion / loop | L1-T03 |
| LLM06 Sensitive Info Disclosure | Credential/secret read-out | L7-T02 / L6-T06 |
| LLM07 Insecure Plugin Design | MCP tool surface, def poisoning | L6-T04 / L6-T08 |
| LLM08 Excessive Agency | No tool gating; broad autonomy | L4-T04/T07; L7-T03 |
| LLM09 Overreliance | No guardrail / output validation | L8-T01 |

### 11.4 OWASP Agentic AI Top 10 (2026)

This is the most directly applicable external lens, since the lab is genuinely agentic. The 3SRM Annex gives all three coordinates — risk ID, MAESTRO layer, and the AICM role that owns the mitigation:

| OWASP Agentic Risk | This system's finding | MAESTRO | Primary AICM role |
|---|---|---|---|
| **ASI01 Agent Goal Hijacking** | Injection-driven goal subversion | L2, L8 | MP + AP / AIC |
| **ASI02 Tool Misuse** | `execute_command` + destructive FS tools | L6, L8, L7 | OSP + AP / AIC |
| **ASI03 Identity & Privilege Abuse** | Plaintext creds; over-privileged tools | L7, L4 | AIC + CSP |
| **ASI04 Supply Chain Vulnerabilities** | Unverified MCP server / tool defs | L6, L2, L5 | AIC + all |
| **ASI05 Unexpected Code Execution** | Container escape via `execute_command` | L5, L6, L8 | CSP + OSP + AP |
| **ASI06 Memory Poisoning** | RAG/Weaviate corpus poisoning | L3, L8 | AIC + MP |
| **ASI07 Insecure Inter-Agent Comms** | Router propagation, no message auth | L4, L7 | OSP + CSP |
| **ASI08 Cascading Failures** | Multi-agent propagation (Path C) | L4, L9 | AIC + OSP |
| **ASI10 Rogue Agents** | No monitoring to detect rogue assistant | L9, L10 | AIC + OSP |

(ASI09 Human-Agent Trust is not separately mapped — no human-facing trust/explainability surface is evidenced in the lab.)

### 11.5 OWASP Agentic Threats & Mitigations (T1–T15)

The T1–T15 taxonomy is a distinct OWASP artifact from the ASI Top 10 above, with its own numbering and paired mitigation playbooks. This is the lens already cited inline in Section 8; consolidated here:

| OWASP T-ID | This system's MAESTRO finding | Mitigation playbook |
|---|---|---|
| **T1 Memory Poisoning** | L3-T01 / CE-T1 | Playbook 2 |
| **T2 Tool Misuse** | L6-T04, L6-T08, L4-T04 | Playbook 3 |
| **T3 Privilege Compromise** | L7-T03, L4-T05 | Playbook 4 |
| **T4 Resource Overload** | L1-T03 | Playbook 3 |
| **T6 Intent Breaking & Goal Manipulation** | L4-T04/T07 | Playbook 1 |
| **T8 Repudiation & Untraceability** | L9-T02 | Playbook 1 (detective) |
| **T9 Identity Spoofing** | L7-T02 | Playbook 4 |
| **T11 Unexpected RCE** | L5-T01/T04 | Playbook 3 |
| **T17 Semantic Drift** | L3-T07 / CE-T7 | Playbook 2 |
| **T22 Service Account Exposure** | L7-T02 | Playbook 4 |
| **T23 Selective Log Manipulation** | L9-T02 | Playbook 1 (detective) |
| **T24 Dynamic Policy Enforcement Failure** | L10-T02 | Playbook 1 |

The remediation in each Section 8 finding already draws from the matching playbook (e.g., L6-T04 mitigations are Playbook 3 measures: strict tool-access policy, function-level auth, execution sandbox, human approval for sensitive operations).

### 11.6 NIST AI RMF crosswalk

NIST AI RMF is a governance-level risk-management framework: it tells an organization **what to do**, while MAESTRO tells it **how**. The pattern is to lead with the RMF function (Govern / Map / Measure / Manage), then pivot into the MAESTRO layer that carries the technical control. RMF **Govern** anchors at MAESTRO **L10**; **L1–L9** supply the technical implementation that Map/Measure/Manage call for. Applied to this system's findings:

| NIST AI RMF Function | What it requires here | MAESTRO home(s) | This system's status |
|---|---|---|---|
| **Govern** | Accountable ownership, policy, acceptable-use, oversight of the agent | **L10** (and the non-delegable Agent-Owner accountability) | Governance artifacts exist (`multi-agent-threats.md`, `proposed-aicm-extensions.md`) but no enforcement engine evidenced → see L10-T02. **Partial.** |
| **Map** | Identify context, the tool surface, and the attack surface | **L1–L6** decomposition (Step 1 mapping) | Done in §6; tool surface and multi-agent topology are well-evidenced. The destructive-tool + broad-privilege surface is the dominant mapped risk. **Answerable.** |
| **Measure** | Test, quantify, and monitor risk — adversarial robustness, drift, logging | **L8** (guardrails / robustness), **L9** (monitoring/logging), **L2** (model behavior) | No L8 guardrail and no audit-grade L9 logging evidenced → L8-T01, L9-T02. This is the weakest RMF dimension for the lab. **Largely Unanswerable.** |
| **Manage** | Prioritize, treat, and respond to risk — gating, least privilege, IR | **L4** (HITL/authorization), **L7** (identity/least-privilege), **L8** (incident response) | No tool-authorization gate, plaintext tool-readable credentials → L4-T04/T07, L7-T02/T03. Treatment controls are the priority remediation. **Gap-dominated.** |

**Reading.** Under NIST framing, the lab is strongest on **Map** (the surface is well-understood) and weakest on **Measure** and **Manage** — exactly the two functions whose technical implementation lives in the L4/L7/L8/L9 layers this assessment flagged as gaps. A NIST-led audit would therefore open on **Govern** (L10 ownership is clear; enforcement is not) and concentrate findings in **Measure/Manage**. As with ISO 42001, NIST AI RMF is a governance lens — it does not by itself attest the technical controls; those map down into MAESTRO L1–L9 and should be evidenced via the Section 12 artifacts.

### 11.7 ISO/IEC 42001:2023 alignment

**Headline, stated plainly:** ISO 42001 is a *management-system* standard — strong on governance, lifecycle, and data handling, and **structurally weak on technical security controls**. Encryption/key management, audit-grade logging, model security, and foundational identity have **no ISO 42001 equivalent** (roughly 37% of AICM controls — 90 of 243 — have no ISO 42001 anchor, clustering in exactly those four families). An organization certifying this lab to ISO 42001 would get attestation for governance and process, **not** for the technical controls that carry most of this system's actual risk. Supplement with ISO/IEC 27001, SOC 2, and NIST CSF for the gapped layers.

Per-layer alignment for the layers where this assessment found threats:

| MAESTRO Layer (this system's finding) | ISO 42001 alignment | Anchor that holds / cite-instead for the gap |
|---|---|---|
| **L1** Infrastructure (L1-T03) | `Partial` | BCR/DCS → A.4, A.2; **CEK-01–21 all unmapped** → ISO 27001 A.8.24, SOC 2 |
| **L2** Cognitive Core (injection origin) | `Severely limited` | AIS-08/09 → A.6.2.4, A.7.4; **all MDS unmapped** → MITRE ATLAS / NIST Measure |
| **L3** Data/Memory (L3-T01, L3-T07) | `Strong` | DSP family → A.7.3/7.4/7.5, A.6.2.4/2.6 — ISO genuinely covers this layer |
| **L4** Orchestration (L4-T04/T07, L4-T05) | `Partial` | **AIS-10 ↔ 6.1 (strict 1-to-1)**; AIS-11 → A.6 lifecycle; thins past that |
| **L5** Deployment (L5-T01/T04) | `Strong (CCC/AIS), weak (I&S)` | CCC-01 → B.6.2.7; CCC-08/09 + most I&S unmapped → ISO 27001 |
| **L6** Tools/Ecosystem (L6-T04, L6-T08) | `Mixed` | STA → A.10 Suppliers (strong); TVM gaps; L6-T08 alignment weak |
| **L7** Identity (L7-T02/T03) | `Structurally weak — weakest layer` | **IAM-19 ↔ 6.2 is the *only* clean IAM anchor**, and it's a planning clause; IAM-01/04/05/08/17 unmapped → ISO 27001/27002 |
| **L8** Safety (L8-T01) | `Partial` | AIS-08/09, SEF → A.8.3/8.4; **MDS-06/07 unmapped** → MITRE ATLAS |
| **L9** Monitoring (L9-T02) | **`Structurally limited`** | **All LOG-01–15 + MDS-10 unmapped** → ISO 27001 A.8.15, SOC 2 CC7.x |
| **L10** Governance (L10-T02) | `Strong — densest alignment` | GRC-08 ↔ B.4.6 (1-to-1); A&A → 9.2/9.3/10.1; **§9.3 Agent-Owner accountability ↔ ISO 5.1 Leadership** |

**The structural irony, worth stating in any ISO-led review of this system:** the layers where this lab's risk actually concentrates — L7 (plaintext credentials), L9 (no audit logging), L8 (no guardrails), L5 (container isolation) — are precisely the layers where ISO 42001 has the weakest or zero coverage. The layer where ISO 42001 is strongest (L10 governance) is the layer where this lab is *least* deficient (ownership is clear; only enforcement tooling is missing). ISO 42001 certification would therefore look reassuring while leaving the lab's dominant attack chains (Paths A and B) entirely un-attested. Those must be evidenced through ISO 27001 / SOC 2 / MITRE ATLAS instead.

**Audit-grade caveat:** the source AICM↔ISO correlation contains 53 known data-quality issues (mostly ISO 27001 clause IDs mislabeled with a 42001 prefix). Any single control-to-clause citation above should be verified against the catalog being certified against before audit use. The AICM revision analyzed is v1.0.3.

## 12. Required Validation Steps

1. **Tool authorization config** — produce the allow-list / HITL-gate configuration for `execute_command` and the destructive filesystem tools (resolves L6-T04, L4-T04/T07).
2. **Secrets architecture** — confirm whether `.env`/`client_secret.json`/`users.json`/`.tokens` are vaulted and whether the filesystem toolset can read those paths (resolves L7-T02/T03, Path B).
3. **Container security contexts** — full Compose definitions: user, capabilities, seccomp, resource limits, isolation of the execute host (resolves L5-T01/T04).
4. **Sub-agent permission model** — per-assistant tool scoping and credential separation across the multi-agent router (resolves L4-T05, Path C).
5. **Logging architecture** — tamper-evidence, retention, tool-call coverage, SIEM integration (resolves L9-T02).
6. **Vector-store + ingestion controls** — Weaviate access control and `data_source_sync` source-trust policy (resolves L3-T01/T07).
7. **Contractual baseline** (if any third-party tool/model providers are in contractual scope) — AI-CAIQ responses, Shared Responsibility Addenda, Safety SLAs, Delegation-Chain clauses (3SRM §6.2).

## 13. Conclusion: What Can and Cannot Be Concluded

**What can be concluded.** The SEC545 lab is a genuinely agentic, multi-agent, MCP-tool-using system whose **dominant risk is structural**: it pairs an exceptionally high-privilege tool surface (arbitrary command execution + destructive filesystem operations + calendar write) with (a) no evidenced authorization gate at L4, (b) no evidenced safety/guardrail layer at L8, and (c) plaintext, tool-readable credentials at L7. Those three facts compose into two high-confidence, fully-evidenced attack chains — injection-to-RCE/destruction (Path A) and credential-theft-via-own-tools (Path B) — plus a third, multi-agent propagation (Path C), bounded by an unknown sub-agent permission model. As a teaching lab this surface is arguably intentional; as a template for anything production-facing it would require the L4/L7/L8 controls listed in Section 12 before deployment.

**What cannot be concluded.** Whether any compensating controls exist outside the evidenced artifacts — tool gating, secret vaulting, container hardening, sub-agent scoping, audit-grade logging, runtime policy enforcement — is **Unanswerable from current evidence**. Every dependent finding's residual-risk rating is therefore a ceiling, not a verdict; supplying the Section 12 artifacts would let several Medium/High ratings be revised. No finding in this report was asserted beyond what the worksheet and named artifacts support, and absences (L8, L9) were reported as gaps rather than filled by inference.

---

*Prepared with the AI Threat Model Analyst skill (MAESTRO v2.0, CSA). MAESTRO `L<n>-T<nn>` IDs are primary; OWASP `T<n>` IDs are secondary cross-references. All ratings are design-evidence based; no control-effectiveness testing was performed.*
