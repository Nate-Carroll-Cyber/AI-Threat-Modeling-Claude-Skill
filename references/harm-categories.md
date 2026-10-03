# Harm Categories (owner-directed, outward-directed, ATLAS external harms)

Load this reference when **either** condition holds:

1. **Mandatory Step 2 lens (skill rule 9; results in Section 10.6)** — the evidence or the request references an agent that holds tools, credentials, or data access on behalf of an owner (the owner-directed part runs), or any model whose output reaches people outside the deployment (the outward-directed part runs). Rule 1 still gates each finding on evidence, so a category with no evidenced reach is listed as having no evidenced instance and is not padded.
2. **Impact naming** — every adversarial per-threat block in Sections 9 and 10 names the party harmed and a category from this file in its Impact line. This applies whenever the file is loaded.

**What this lens is.** MAESTRO IDs name mechanisms. This file names outcomes: what is lost, and by whom. It is the only lens in the skill organized by who bears the harm.

**Sources**

- Owner-directed categories: Dongcheng Zhang and Yiqing Jiang, *Owner-Harm: A Missing Threat Model for AI Agent Safety*, arXiv:2604.18658, 2026. https://arxiv.org/abs/2604.18658
- Outward-directed categories: Andriushchenko, Souly, Dziemian, and colleagues (Gray Swan AI, UK AI Security Institute, and others), *AgentHarm: A Benchmark for Measuring Harmfulness of LLM Agents*, arXiv:2410.09024v3, 18 Apr 2025. https://arxiv.org/abs/2410.09024v3
- External harms: MITRE ATLAS, Impact tactic, as listed in `atlas-techniques.md`.

## Mandatory caveats (read before citing)

- **Licenses.** The owner-harm preprint shows no license and the AgentHarm paper is under the arXiv non-exclusive license. Category names are cited as names. Every definition, mapping, and check in this file is the skill's own wording. Do not reproduce either paper's prose in a deliverable.
- **Shorthand is skill-local.** `OH-C1` through `OH-C8` are the owner-harm paper's C1 through C8 with a skill prefix. `AH-<Name>` marks an AgentHarm category, which the paper identifies by name only. Neither is a threat ID and neither replaces `L<n>-T<nn>`.
- **AgentHarm defines no categories.** It lists eleven names with no definitions and does not state who is harmed. Treating them as harm directed outward, the reach conditions, and the checks below are this skill's.
- **No rates are carried.** The owner-harm benchmark is author-built after system tuning with a single annotator, and the paper calls it diagnostic. AgentHarm scores describe specific 2024 models. Neither set of figures justifies a Likelihood rating.
- **No incidents are carried.** The owner-harm paper cites real incidents per category. They have not been checked against primary reports and are not in this file.
- **Gaps in both papers.** Neither has a category for direct financial loss, service disruption, or reputational damage. The ATLAS external harms below cover those.

---

## Owner-directed categories → MAESTRO v2.0 mapping

The owner is the party that deploys the agent, grants it access, and answers for what it does. In 3SRM terms this is the Agent Owner.

| ID | Category | Own-words definition | Nearest MAESTRO threat IDs | ATLAS (5.6.0) |
|---|---|---|---|---|
| OH-C1 | Credential Leak | Authentication material (keys, tokens, cookies, passwords) leaves the owner's control | L7-T02, L1-T04 | AML.T0055 Unsecured Credentials; AML.T0083 Credentials from AI Agent Configuration; AML.T0098 AI Agent Tool Credential Harvesting |
| OH-C2 | Infrastructure Exposure | Network rules, cloud resource policies, or internal architecture are misconfigured or disclosed | L5-T03, L1-T02, L6-T06 | AML.T0081 Modify AI Agent Configuration (where the change is to the agent's own environment) |
| OH-C3 | Privacy Exposure | Personal data or confidential business data reaches a party the owner has not authorized | L3-T02, L3-T05, L6-T06 | AML.T0057 LLM Data Leakage |
| OH-C4 | Inner Circle Leak | Commercially sensitive relationships are disclosed: client lists, partner agreements, deal discussions, roadmaps | No canonical ID. Anchor to L3 or L6 by the T16 convention, with L6-T06 as the exit path | AML.T0057 LLM Data Leakage; AML.T0086 Exfiltration via AI Agent Tool Invocation |
| OH-C5 | Asset Destruction | Owner data, configuration, or digital assets are irreversibly deleted or corrupted | L4-T07, L6-T03 | AML.T0101 Data Destruction via AI Agent Tool Invocation |
| OH-C6 | Exfiltration via Tools | A tool the agent is authorized to use becomes a covert channel for data | L6-T06 | AML.T0086 Exfiltration via AI Agent Tool Invocation |
| OH-C7 | Hijacking | An adversary gains persistent control of the agent under the owner's identity, credentials, or access | L4-T02, L7-T05, L3-T03 | AML.T0051.001 Indirect; AML.T0080 AI Agent Context Poisoning; AML.T0108 AI Agent |
| OH-C8 | Unauthorized Autonomy | The agent takes a consequential action outside its authorized scope or without a required confirmation | L7-T04, L4-T07, L4-T04 | AML.T0053 AI Agent Tool Invocation |

## Outward-directed categories → MAESTRO v2.0 mapping

The agent is driven, by its user or by injected content, to act against people outside the deployment. The mechanism finding is the same for all eleven: L2-T03 (jailbreak or injection), L8-T01 (guardrail bypass), or L8-T05, with AML.T0054 LLM Jailbreak. What differs is the reach that makes each category possible.

| ID | Borne by | Reach that makes it possible (skill's reading) |
|---|---|---|
| AH-Fraud | Third parties | Payment, purchasing, or account tools; messaging to individuals; document or identity generation |
| AH-Cybercrime | Third parties | Code execution, network access to external hosts, credential or scanning tools |
| AH-Harassment | Third parties | Messaging or posting directed at named individuals; lookup of personal details |
| AH-Disinformation | Society | Publishing or posting at volume; account creation; content generation tied to distribution |
| AH-Hate | Third parties, society | Content generation with a publication path |
| AH-Violence | Third parties | Content generation, procurement, or targeting lookups |
| AH-Terrorism | Society | Content generation, procurement, recruitment, or financing paths |
| AH-Drugs | Third parties, society | Procurement, marketplace, or synthesis-information paths |
| AH-Sexual | Third parties | Image or text generation with a distribution path |
| AH-Copyright | Rights holders | Retrieval, download, or reproduction of protected works with a distribution path |
| AH-Self-harm | The user | Any user-facing conversational surface |

## ATLAS external harms (for harm neither paper names)

Use these when the harm is real and fits none of the categories above. They are ATLAS technique IDs and are cited as such.

| ATLAS ID | Name | Use for |
|---|---|---|
| AML.T0048.000 | Financial Harm | Direct monetary loss to the owner or a third party |
| AML.T0048.001 | Reputational Harm | Damage to the owner's standing from what the agent said or did |
| AML.T0048.002 | Societal Harm | Harm at population scale not captured by an outward-directed category |
| AML.T0048.003 | User Harm | Harm to the person using the system, other than self-harm |
| AML.T0048.004 | AI Intellectual Property Theft | Loss of the owner's model, prompts, or training data as an asset |
| AML.T0029 | Denial of AI Service | The service is unavailable to the owner's users |
| AML.T0034 | Cost Harvesting | The owner is billed for compute or API use an attacker induced |

---

## Evidence the lens asks for

Owner-directed harm cannot be judged from an action's content. Sending an email is benign until the attachment is the owner's and the recipient is not one the owner authorized. Three facts are needed, and each is an evidence artifact (owner-harm paper, owner-context dimensions):

- **Resources.** Which data, credentials, and assets are the owner's and must not be disclosed or destroyed.
- **Counterparties.** Who the owner treats as an authorized recipient for each kind of resource.
- **Authorization scope.** Which actions the agent may take without confirmation, and which need one.

Where any of the three is absent, the categories that depend on it are recorded as `unevidenced` and the missing artifact is listed in Section 5.

## Per-category evidence checks

### OH-C1 — Credential Leak
- Which credentials can the agent read, counting environment, configuration, tool results, and memory?
- Can any tool send data to a destination outside the owner's authorized counterparties?

### OH-C2 — Infrastructure Exposure
- Can the agent read or change network rules, cloud policies, infrastructure code, or architecture documents?
- Is a change of that kind gated by a confirmation enforced outside the model?

### OH-C3 — Privacy Exposure
- Which stores of personal or confidential data can the agent reach, and through which tools can that data leave?
- Is the recipient of an outbound action checked against the owner's authorized counterparties?

### OH-C4 — Inner Circle Leak
- Has the owner stated which relationship data is commercially sensitive? No data pattern identifies it, so without that statement the category is `unevidenced`.
- Is that data reachable by the agent, and does an outbound path exist?

### OH-C5 — Asset Destruction
- Which tools delete, overwrite, or reconfigure, and which of those actions are irreversible?
- Is confirmation for them enforced outside the model (L4-T07)?

### OH-C6 — Exfiltration via Tools
- Which authorized tools can carry arbitrary data out: email, webhooks, file writes to shared locations, URL fetches with attacker-chosen parameters?
- Are the destination and payload of each call checked, as opposed to the tool's name alone?

### OH-C7 — Hijacking
- Can untrusted content write to anything that persists across sessions: memory, agent configuration, scheduled tasks, stored credentials?
- Is there a way to detect such a write and to restore a known-good state?

### OH-C8 — Unauthorized Autonomy
- Is the authorization scope written down, and where is it enforced?
- Which consequential actions (payments, external messages, publication, deletion) can the agent complete with no human step?

### Outward-directed categories (one check set)
- Which categories does the agent's evidenced tool reach make possible? A category with no enabling reach is listed as not applicable to this system, with the reason.
- For each model in the path, what safeguard evidence exists? A model with none, or with weights under an `Unjustified` Section 2 row, is assumed to refuse nothing (see the L2 and L8 Key considerations in `maestro-layers.md`).
- For AH-Self-harm, is there an evidenced escalation or safe-messaging path on user-facing surfaces?

---

## How results are recorded

- **In existing blocks.** Where a category describes the impact of a MAESTRO finding already in Section 9, cite it in that block's title parenthetical and name it in the Impact line. Do not open a second block.
- **Lens-only blocks.** A category with evidenced reach and no MAESTRO finding (most often OH-C4) gets a full per-threat block in Section 10.6, anchored to its layer by the T16 convention.
- **Section 10.6 table.** One row per category for each part that ran: category, party harmed, what the lens found with its citation, the Section 9 block it attaches to or "block below", and status.
- **Section 8.** The `Lens` column carries `OH` or `AH`.

## Evidence base (for Likelihood justification)

None is carried in this file, for the reasons under Mandatory caveats. Likelihood for a harm-category finding comes from the mechanism finding it attaches to and from the system's own evidence.

## Mitigation sourcing (Step 4)

The sources supply no controls that this file carries. Route mitigations through the MAESTRO layer of the mechanism finding, and credit each one only against the path it sits on (`SKILL.md` Step 4).

**SSRM note.** Owner-directed harm falls on the Agent Owner by definition, and the Agent Owner supplies the three owner-context artifacts. Outward-directed harm is shared: the MP for model safeguards, the AP or AIC for the tool reach that makes a category possible.
