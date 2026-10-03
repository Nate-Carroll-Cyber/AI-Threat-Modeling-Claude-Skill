# AI Threat Models

A Claude skill that produces **evidence-based, layered threat-model assessments** for agentic AI systems — LLM, RAG, MCP, tool-using, and multi-agent architectures. The analytical backbone is **MAESTRO v2.0** (Cloud Security Alliance): a ten-layer, three-domain framework purpose-built for agentic AI.

The skill's defining trait is **evidence discipline**. Every finding is gated on what the user actually supplied. Claims that the evidence doesn't support are marked `Unanswerable from current evidence` with a list of the artifacts needed to close the gap, rather than being filled in with plausible-sounding speculation. A short, honest gap assessment is treated as more valuable than a long hedged one.

The skill carries **two adversary directions**, kept explicitly separate. The default lens treats the AI system as the *asset under attack* (external/upstream adversaries — prompt injection, RAG poisoning, malicious MCP servers, model theft). A second, opt-in lens treats the AI system *itself* as the adversary (insider-threat / misalignment / untrusted internal deployment), via the TRAIT&R taxonomy. A control's value can flip between the two, so they are never conflated in an assessment.

---

## What it does

Given a system description — a filled worksheet, a partial worksheet, or just a casual paragraph — the skill produces a structured assessment that:

- Maps every evidenced component to one of the ten MAESTRO layers.
- Enumerates applicable threats per layer, each separated into evidenced facts, bounded inferences, and unknowns.
- Traces cross-layer attack paths (kill-chain / attack-tree style) that the evidence makes plausible.
- Assigns **Agent 3SRM** ownership (CSP / MP / OSP / AP / Tool Provider / AIC) to each finding, with the Agent Owner's non-delegable accountability made explicit.
- Runs the eight **PHANTOM-B** prompts (Shostack's STRIDE analog for LLMs) against every evidenced LLM component as a completeness check on L2, surfacing the non-adversarial surfaces — hallucination, anthropomorphization, non-explainability, over-reliance, bias — that MAESTRO's threat list reaches only through L8/L10 controls.
- Optionally crosswalks to other frameworks (STRIDE, PHANTOM-B, MITRE ATLAS, OWASP LLM Top 10, OWASP Agentic ASI01–ASI10 and T1–T15, OWASP Agentic Skills Top 10 AST01–AST10, OWASP MCP Top 10 MCP01–MCP10, NIST AI RMF) on request — one named framework at a time, or all of them at once via full-crosswalk mode (see **Output**).
- Optionally applies the **inverted-adversary lens** (TRAIT&R) when insider-threat / misalignment is in scope.

It is a **defensive** modeling tool. It declines requests for exploit code or weaponizable detail and continues with the defensive analysis.

## When it fires

The skill is for a structured security analysis of an AI system — not generic security advice, a CVE lookup, or a code review. It triggers when the user:

- Names a system (built or proposed) and asks for risks, threats, or a security review.
- Mentions agentic / MCP / RAG / multi-agent / tool-using / LLM architecture and wants the attack surface mapped.
- Explicitly asks for MAESTRO, STRIDE-for-AI, PHANTOM-B, MITRE ATLAS, or OWASP LLM/Agentic alignment.
- Asks what can go wrong with the LLM parts of a system, including a passive chatbot with no agentic surface.
- Asks for an insider-threat / misalignment / AI-control assessment (the inverted-adversary lens).
- Pastes a filled or partial worksheet / architecture description.

If the request is for *advice on building secure AI* (architecture guidance, control selection without a threat model), this skill is the wrong tool — answer directly instead.

## The ten MAESTRO layers

- **Domain 1 — Infrastructure, Intelligence & Knowledge:** L1 Infrastructure · L2 Cognitive Core · L3 Data, Memory, Knowledge
- **Domain 2 — Environment & Execution:** L4 Orchestration & Coordination · L5 Deployment & Execution · L6 Tools, Application, Ecosystem
- **Domain 3 — Agency, Governance, Accountability (horizontal):** L7 Identity & Autonomy · L8 Safety & Security · L9 Monitoring & Observability · L10 Governance & Compliance

## The non-negotiable rules

These are the reason to use a structured skill rather than free-form analysis; each prevents a specific failure mode.

1. No speculation, no assumed facts — unsupported claims are marked unanswerable.
2. Always separate evidenced facts, bounded inferences, and unknowns.
3. A MAESTRO layer is unanswered unless that layer is evidenced (e.g. no L7 findings without an identity model).
4. Evaluation/measurement/monitoring is distinct from audit-grade logging.
5. MCP-specific findings require explicit MCP evidence.
6. Cite real sources for external factual claims; never fabricate URLs.
7. Prefer a gap assessment over a weak answer.
8. At most one clarifying question, at the end.
9. Every lens whose technology or scope is referenced in the evidence or the request runs in full from its reference file (MCP → `mcp-top10.md`, skills/plugins → `agentic-skills-top10.md`, any LLM component → `phantom-b.md`, insider/misalignment → `ai-control-trait-r.md`, a tool-holding agent or outward-reaching model → `harm-categories.md`, persistent identity/delegation → library Part 3). Reference triggers the run; evidence still gates the findings. Skipping a triggered lens or running it from memory invalidates the assessment; Section 10 records the disposition of every lens.
10. Every `path:line` citation is verified mechanically (`scripts/verify_citations.py`) before the report is final; unresolvable citations are marked `[unverified]` and the finding drops to Partial.

## Methodology (five steps)

1. **System Decomposition** — map evidenced components to layers with their AI asset type and origin (produced or consumed); record each consumed component's assumed upstream attacker capability and its justification in Section 2; map agent-to-agent boundaries if multi-agent.
2. **Layer-Specific Threat Analysis** — assess applicable threats per evidenced layer by capability test (a threat stays only if the evidence grants the minimum capability it needs over each asset); additionally evaluate multi-agent categories, the seven context-engineering threats (CE-T1…CE-T7), the OWASP Agentic Skills Top 10 lens (AST01–AST10) when the system installs/loads third-party skills or plugins, the OWASP MCP Top 10 lens (MCP01–MCP10) when MCP is explicitly evidenced, the PHANTOM-B eight-prompt lens for every evidenced LLM component, the harm-category lens for any tool-holding agent or outward-reaching model (which also supplies the category named in every Impact line), and — if insider-threat/misalignment is in scope — the TRAIT&R inverted-adversary lens.
3. **Cross-Layer Path Analysis** — trace how compromise propagates as a chain of stated capabilities, each link naming the rule that carries it (component, dependency, relationship, conversion); don't manufacture paths.
4. **Mitigation & SSRM Ownership** — recommend concrete controls; assign 3SRM roles.
5. **Framework Crosswalk** — optional, on request (see **Output** for how to control it).

## Output

A 16-section assessment in a fixed order: understanding, scope, system summary, evidence, gaps, layer mapping, per-layer status, a **Summary of Findings** table (every finding ordered by risk with Likelihood / Impact / Risk, status, and implementing party), the detailed MAESTRO per-threat blocks, a **Lens Results** section (one subsection per lens, present whether or not it fired, holding the per-item results table, any lens-only findings that have no MAESTRO ID, the non-instances, and the lens's net contribution), cross-layer paths, the SSRM ownership table, an optional crosswalk, required validation steps, the conclusion, and a single clarifying question (omitted if nothing critical is missing). The exact section list, the Section 8 and Section 10 specs, and the per-threat block template live inline in `SKILL.md`.

### Framework crosswalk (Section 13) — how to control it

**By default the assessment uses MAESTRO as its single spine and includes no external-framework crosswalk.** This keeps the report focused: crosswalks are a secondary lens that competes with the MAESTRO spine for the reader's attention, so Section 13 appears only when asked for. To get one, say what you want:

- **One (or a few) named frameworks** — *"map this to MITRE ATLAS"*, *"add NIST AI RMF alignment"*, *"include the OWASP Agentic Top 10 crosswalk"* — produces just that subsection (or those subsections). Naming one framework does not pull in the others.
- **All of them at once** — *"include the full framework crosswalk"*, *"crosswalk to everything"*, or *"all frameworks"* — triggers **full-crosswalk mode**: the complete Section 13 with all nine subsections in fixed order — **13.1 STRIDE · 13.2 PHANTOM-B (STRIDE analog for LLMs; CC-BY attribution) · 13.3 MITRE ATLAS · 13.4 OWASP LLM Top 10 · 13.5 OWASP Agentic Top 10 (ASI01–ASI10) · 13.6 OWASP Agentic T1–T15 (with mitigation playbooks) · 13.7 OWASP Agentic Skills Top 10 (AST01–AST10, populated only when a skill-installation surface is evidenced) · 13.8 OWASP MCP Top 10 (MCP01–MCP10, populated only when MCP is evidenced; beta + BY-NC-SA caveats apply) · 13.9 NIST AI RMF**.

Two things hold in either case, by design:

- **Crosswalks re-express existing findings; they never add new ones.** Each subsection restates the assessment's Section 9 MAESTRO findings in another framework's vocabulary. The MAESTRO `L<n>-T<nn>` ID stays canonical; the external framework ID is the secondary column. Cells with no evidenced threat are omitted, not padded with "N/A", and a whole technique class that doesn't apply is called out with the reason (e.g. "model-extraction techniques not mapped — no training/fine-tuning surface evidenced").
- **Full-crosswalk mode does *not* include the inverted-adversary lens.** TRAIT&R (insider-threat / misalignment) is a separate opt-in with its own adversary direction — ask for it explicitly if you want it; "all frameworks" does not pull it in.

---

## Repository structure

```
SKILL.md                                Orchestration: triggers, rules, methodology, output format,
                                        the per-threat block template, and edge cases
README.md                               This file
references/
  maestro-layers.md                     The L1–L10 layer catalog: components, AI assets (the eight
                                        asset types of arXiv:2505.06315 placed per layer), sample threats
                                        (L<n>-T<nn>), SSRM owners, the CE-T1…CE-T7 context threats
                                        and multi-agent categories handled inline within the relevant
                                        layers, plus the OWASP T16–T25 extended scenarios mapped to layers
  ssrm-ownership.md                     Agent 3SRM six-role model, responsibility matrix, six-layer
                                        aaS stack, deployment-model variations, the delegation-chain
                                        accountability principle, the six categories of structural
                                        AICM gap, and the justification kinds for consumed assets
  framework-crosswalk.md                STRIDE / PHANTOM-B / ATLAS / OWASP LLM / OWASP Agentic
                                        (ASI01–ASI10 + T1–T15 with decision path and six mitigation
                                        playbooks) / AST01–AST10 / MCP01–MCP10 / NIST AI RMF /
                                        cloud-provider mappings; defines full-crosswalk mode
                                        (the opt-in all-frameworks path, 13.1–13.9)
  agentic-skills-top10.md               OWASP Agentic Skills Top 10 (AST01–AST10): installable
                                        behavior-layer lens — severity tiers, MAESTRO v2.0 re-mapping,
                                        lethal-trifecta trigger, per-risk evidence checks, incident
                                        evidence base, B1–B4 trust-boundary screen
  mcp-top10.md                          OWASP MCP Top 10 (MCP01:2025–MCP10:2025): protocol-layer
                                        lens — MAESTRO v2.0 re-mapping, per-risk evidence checks,
                                        evidence base, mitigation sourcing; beta + BY-NC-SA caveats
  phantom-b.md                          PHANTOM-B (Shostack + Associates WP #6, v1.0 Q3 2026, CC-BY):
                                        the eight-letter STRIDE analog for the LLM component —
                                        design caveats, PB-P…PB-B → MAESTRO v2.0 mapping with
                                        adversary column, per-letter evidence checks, mitigation
                                        routing (the paper ships no controls by design)
  harm-categories.md                    The outcome lens: eight owner-directed harm categories
                                        (arXiv:2604.18658, OH-C1…OH-C8), eleven outward-directed
                                        (AgentHarm, arXiv:2410.09024v3, AH-<Name>), ATLAS external
                                        harms; MAESTRO v2.0 mapping, owner-context evidence
                                        artifacts, per-category checks; names the Impact line
  atlas-techniques.md                   GENERATED by scripts/refresh_atlas.py — current MITRE ATLAS
                                        tactics and techniques (ID, name, tactic, maturity, ATT&CK
                                        ref, modified date), dated and versioned; do not hand-edit
scripts/
  plan_subsystems.py                    Step 1 aid: key-file inventory per directory, signal flags,
                                        proposed subsystems with likely MAESTRO layers (no LLM)
  verify_citations.py                   Rule 10: checks every path:line citation in a report
                                        against the source tree; exit 1 on any unresolvable
  section8_to_sarif.py                  Exports Section 8 to SARIF 2.1.0 with locations taken from
                                        the matching Section 9/10 block
  refresh_atlas.py                      Downloads ATLAS.yaml, regenerates atlas-techniques.md,
                                        audits cited ATLAS IDs for absence, name drift, and
                                        uncited current techniques; --strict is the packaging gate
  package.sh                            Clean-copy zip build, refused if the strict audit fails
  threat-technique-and-control-library.md   Three parts: (1) ~140 AITech-*/AISubtech-* technique
                                        taxonomy (OWASP + ATLAS + MAESTRO); (2) the FAIR-CAM GenAI
                                        control library; (3) the ~41-threat Trust & Identity-Lifecycle
                                        taxonomy (OWASP Agentic + ATLAS tactic + AICM v1.1
                                        + MAESTRO layer)
  ai-control-trait-r.md                 The inverted-adversary lens: TRAIT&R objectives and tactics,
                                        the distributed kill chain, and the two capability-gated
                                        mitigation ladders (D1–D4 detection, R1–R3 prevention/response)
```

### Reference-file loading

`maestro-layers.md` and `ssrm-ownership.md` load for every assessment. The lens references load under rule 9, which makes each one mandatory the moment its technology or scope is referenced in the evidence or the request; the conditions below say what triggers each lens, not whether it is optional:

- `maestro-layers.md` — always, when producing an assessment. (Context-engineering and multi-agent threat categories are inline here and in the methodology, not separate files.)
- `ssrm-ownership.md` — for Step 4 ownership assignment, and when a finding maps to one of the six structural AICM gaps.
- `framework-crosswalk.md` — only when the user requests a non-MAESTRO framework (one named framework, several, or all of them via full-crosswalk mode).
- `threat-technique-and-control-library.md` — when technique-level attack granularity, a structured control source, or the trust/identity-lifecycle lens is needed.
- `ai-control-trait-r.md` — when insider-threat, misalignment, or untrusted-internal-deployment concerns are in scope.
- `agentic-skills-top10.md` — when the system installs or loads third-party skills/plugins, or the user names AST10.
- `mcp-top10.md` — when MCP is explicitly evidenced, or the user names the MCP Top 10.
- `phantom-b.md` — for every assessment with an evidenced LLM component (it is the primary L2 prompt set when the system is not agentic), and when the user names PHANTOM-B.
- `harm-categories.md` — when an agent holds tools, credentials, or data access for an owner, or a model's output reaches people outside the deployment; also whenever an Impact line is written.

---

## Maintainer notes

### Crosswalk default — opt-in, not automatic

Section 13 is **off by default and produced only on request** — one subsection per named framework, or all nine via full-crosswalk mode. This is deliberate, not an omission: the skill's first principle is that MAESTRO is the single analytical spine and the other frameworks are secondary lenses that map *into* it. Emitting crosswalks unprompted reintroduces the failure mode the design prevents — the report drifts from a threat model toward a framework-mapping exercise, and reflexively generated mappings tend to overstate coverage. If you are considering changing the default to always-on, weigh that against the majority of uses that are not compliance-driven; the recommended posture is to keep it opt-in and make opting-in cheap (the full-crosswalk trigger phrases), which is the current design. The trigger list and the full-crosswalk spec both live in `framework-crosswalk.md` under "When to include Section 13".

### Numbering systems — keep them separate

The skill deliberately uses several independent ID schemes. Conflating them is the most common way to corrupt an assessment:

- **`L<n>-T<nn>`** — MAESTRO layer threats (the primary spine; always used as the canonical ID in output).
- **`CE-T1 … CE-T7`** — context-engineering threats, anchored to L3.
- **OWASP `T1–T15`** and the extended **`T16–T25`** — a *secondary lens* in `framework-crosswalk.md` and `maestro-layers.md`. These are NOT MAESTRO IDs and must never be substituted for `L<n>-T<nn>`.
- **`ASI01–ASI10`** — the OWASP Agentic Top 10, distinct again from the T1–T15 taxonomy.
- **`AST01–AST10`** and **`MCP01:2025–MCP10:2025`** — the OWASP Agentic Skills Top 10 and OWASP MCP Top 10; two more independent OWASP numberings (behavior layer and protocol layer). The MCP set is CC BY-NC-SA — own-words only, flag NC for commercial deliverables.
- **`PB-P … PB-B`** — skill-local shorthand for the eight PHANTOM-B letters (the paper uses bare mnemonic letters, not IDs). Three letters (H, A, B) have no canonical `L2-T<nn>` home and are anchored to the layer, the same way `maestro-layers.md` handles OWASP T16 — never mint an `L2-T07` for them. Non-adversarial PB findings use `Failure mode (no adversary required)` in the Attack Vector field.
- **Capability names** (`Inspect`, `Contribute`, `Influence`, and the other six defined in `SKILL.md` Step 2) — a vocabulary from arXiv:2505.06315, not an ID scheme. Written as `Asset type (component): Capability` in the Attack Vector field, Section 2, and Section 11; never placed in an ID column and never substituted for `L<n>-T<nn>`.
- **`OH-C1 … OH-C8`** and **`AH-<Name>`** — skill-local shorthand for the harm categories in `harm-categories.md`. The owner-harm paper's own IDs are C1–C8; AgentHarm identifies its categories by name only. They name outcomes, not mechanisms, and are cited parenthetically and in the Impact line, never in place of `L<n>-T<nn>`.
- **`AITech-* / AISubtech-*`** — the technique taxonomy in `threat-technique-and-control-library.md` Part 1; a secondary lens, never substituted for MAESTRO IDs.
- **`AML.T####[.###]`** — MITRE ATLAS technique IDs, cited with sub-technique precision wherever ATLAS has one; names come from the generated `atlas-techniques.md`, and a bare `T0###` in a table cell is shorthand for the AML-prefixed ID.
- **TRAIT&R `D1–D4` / `R1–R3`** — capability tiers in `ai-control-trait-r.md`; these gate *mitigations by model capability*, a different axis from MAESTRO's layer decomposition. Do not conflate with `L<n>-T<nn>`.
- **`LOG-16 (Proposed …)`** and similar — proposed / not-yet-canonical AICM entries; always cited as `Proposed [ID]` and reconciled against the authoritative AICM catalog before audit-grade use. Where no clean control exists, name the structural AICM gap (see `ssrm-ownership.md`) rather than over-claiming coverage.

When extending the skill, the MAESTRO `L<n>-T<nn>` ID stays primary in all output; everything else is cited parenthetically as a secondary lens.

### Two adversary directions — keep them separate

The default lenses (MAESTRO, ATLAS, OWASP, AICM) model threats *against* the AI system. TRAIT&R (`ai-control-trait-r.md`) models threats *by* a misaligned internal agent — the inverse. A control's sign can flip between them (chain-of-thought access is a disclosure risk under the external lens but the key defensive affordance under the internal one). Keep findings tagged with their adversary direction; do not fold TRAIT&R tactics into the ATLAS-keyed crosswalk. Note in particular that full-crosswalk mode covers only the external-attacker frameworks and deliberately excludes TRAIT&R.

### Adding a new threat

Add it to the relevant layer in `maestro-layers.md` with a canonical `L<n>-T<nn>` ID, sample attack vector, and SSRM owner. If it has cross-framework equivalents, add the mapping rows to `framework-crosswalk.md`. Technique-level or trust/identity threats go in the appropriately-labeled part of `threat-technique-and-control-library.md`. Keep the canonical per-layer lists clean — imported taxonomies (OWASP T-numbers, AITech-*) go in their own clearly-labeled sections, not interleaved into the MAESTRO lists.

### Adding a framework crosswalk

Add a `## MAESTRO + <Framework>` section to `framework-crosswalk.md`, following the existing pattern: a short framing paragraph stating what the framework is good and bad at, then a mapping table into MAESTRO layers. Update the "When to include Section 13" trigger list and the reference-file description in `SKILL.md`. **If the new framework should be part of full-crosswalk mode, also add it to the fixed subsection order in the "Full crosswalk mode" block** (and renumber the 11.x sequence) so the all-frameworks path stays complete and reproducible. Renumbering touches four places: the order block in `framework-crosswalk.md`, Step 5 and the Section 13 line in `SKILL.md`, this README's Output section, and the `(Section 13.x)` pointer at the top of each lens reference (`agentic-skills-top10.md`, `mcp-top10.md`, `phantom-b.md`).

### Adding a lens

A lens is a reference file that runs a second taxonomy over the evidence under rule 9. Adding one means: the file with its trigger line ("Mandatory Step 2 lens (skill rule 9; results in Section 10.x)"), a Step 2 item in `SKILL.md` naming the trigger, a rule 9 entry mapping the technology to the file, a fixed slot in the Section 10 order (currently 10.1 PHANTOM-B, 10.2 MCP Top 10, 10.3 AST10, 10.4 Trust & Identity-Lifecycle, 10.5 TRAIT&R, 10.6 Harm Categories), a license line for the Section 8 preamble, and, if it should also crosswalk, a 13.x subsection per the previous note.

### Report-format history

Revision 4 of the skill (Sep 2026) moved from 14 to 16 sections: Section 8 Summary of Findings and Section 10 Lens Results were added after a worked assessment of `cloudflare/mcp-server-cloudflare` showed lens output scattered across the MAESTRO blocks with no single place to audit which lenses ran. `example-report.md` follows the 16-section layout.

The October 2026 revision worked the asset-centric method of Sanchez Vicarte et al. (arXiv:2505.06315v2) into the existing steps with no new file and no change to the section count: `AI asset type` and `Origin` columns in Section 6, a consumed-asset table in Section 2, a capability test for applicability in Step 2 with a capability-required line in the Attack Vector field, and capability chains with named propagation rules in Section 11. `example-report.md` predates this change and shows none of them.

### Source licensing carried in-file

Three lens references have license terms that shape how their content may appear in a deliverable: `mcp-top10.md` is CC BY-NC-SA (own-words only; flag NonCommercial before commercial use), `phantom-b.md` is CC-BY (attribution required, no NC term), and the OWASP AST and Agentic material is CC BY-SA. `harm-categories.md` cites category names from two arXiv papers (one with no license shown, one under the arXiv non-exclusive license) and writes every definition and check in the skill's own words. The asset types and capability names worked into `maestro-layers.md` and `SKILL.md` are from arXiv:2505.06315, CC BY 4.0, so a report that uses the capability names carries that attribution in Section 2. Keep the license line at the top of each file current when the upstream source changes.

### Source versioning (known inconsistencies, not yet reconciled)

Reference files cite their MAESTRO / AICM / 3SRM source sections, and some version strings disagree. These are left as-is pending verification against the published sources rather than silently aligned:

- **MAESTRO**: cited as "v2.0" in most files, but `maestro-layers.md` cites a "v0.91 draft" (Section 7). Align when the canonical version is confirmed.
- **AICM**: cited as "v1.1" across most of the skill. Verify control IDs against the catalog you are working from before audit-grade use.
- **3SRM**: tracks CSA's *AI Agents: Shared Security and Safety Responsibility Model* (v0.981); naming varies between "Agent 3SRM" and "Agent SSRM" (see the terminology note in `ssrm-ownership.md`).
- **ATLAS**: snapshot in `references/atlas-techniques.md` is ATLAS 5.6.0 (generated 2026-09-29). Technique names in every mapping table are reconciled against it; re-run `scripts/refresh_atlas.py` on each release.
- **Asset-centric method**: arXiv:2505.06315v2 (2 Jul 2025), a preprint with no venue or evaluation. Its attack knowledge base and analysis engine are unpublished and not claimed; its Figure 3 implication matrix is not reproduced, only the relations its text states. The layer placement of asset types is this skill's.
- **RAG formal definitions**: arXiv:2509.20324 (Arzanipour et al., 2025), used for three notes in `maestro-layers.md` (corpus membership inference and the verbatim-leakage test at L3, retrieval logging at L9). Formal definitions with no experiments; version and license not confirmed, so own-words only. Its cited mitigations are not carried because they were not checked against their primary papers.
- **Multi-agent extension**: arXiv:2508.09815v1 (Krawiecka and Schroeder de Witt, 13 Aug 2025), used for two multi-agent categories (verifier subversion at L4, cross-model task splitting at L8), the Verifier and Refiner distinction in Step 1, and the context-loss note on rewriting controls in Step 4. Its other fifteen classes are already covered or out of scope; its cited frameworks and metrics (NetSafe, TrustAgent, agreement scores) are not carried because they were not checked against their primary papers.
- **Harm categories**: arXiv:2604.18658 (Zhang and Jiang, preprint) and arXiv:2410.09024v3 (AgentHarm, 18 Apr 2025). `harm-categories.md` carries their category names only; benchmark rates and cited incidents are not carried, and the outward-directed framing and all per-category checks are the skill's. ATLAS external harms fill the financial, reputational, and availability gap both papers leave.
- **Method comparison (GenAI threat modeling in practice)**: arXiv:2607.28431 (Díaz Ferreyra et al., 2026), a one-case comparison of three published methods against the OWASP LLM Top 10. It prompted the system prompt leakage check at L2 and the AML.T0056 mapping on library row AITech-8.4, since all three methods missed that category. Cited as a preprint; the page carries two different venue strings.
- **Multi-agent prompt injection**: arXiv:2609.22949v1 (Paul and Nandy, 2026), used for four evidence checks (aggregation and out-of-model termination at L4, tool-output schema validation and format mimicry at L6) and the Step 4 rule that an injection mitigation is credited only against the path it sits on. Its figures are not carried: rates are the maximum across three models, the judging method is unstated, no code or data is released, and its headline residual (4.2%) does not reconcile with its own combined-defense row. The ICML footer on the page is unconfirmed, so it is cited as a preprint.
- **GenAI privacy (LINDDUN)**: arXiv:2603.06051 (Liao et al.), published at SOUPS 2026, used for four checks: per-store erasure and rectification at L3, fabricated statements about real people under PB-H, residual-leakage assets (KV-cache, gradients) at L1 and L2, and the `Data sent to producer` column in Section 2. The LINDDUN GenAI knowledge base (supplementary DOI 10.5281/zenodo.20645261) is not carried, so this is not a privacy lens. arXiv non-exclusive license, own-words only.
- **TRAIT&R**: sourced from the *GDM AI Control Roadmap* v0.1 (Phuong et al., Google DeepMind, June 2026). Theory-based, not observed in the wild — findings are marked as conservative hypotheticals. Confirm the citation against the live GDM publication before any audit-facing use.

### Scripts

Four scripts ship under `scripts/`, all LLM-free, all runnable from the skill root with Python 3.10+ (`refresh_atlas.py` needs PyYAML and network, or `--atlas PATH` offline):

- `plan_subsystems.py <repo>` — run before Step 1 on any non-trivial repository.
- `verify_citations.py REPORT.md --root <repo>` — run before a report is final (rule 10). `--show` prints the cited lines. In the first worked run it caught 6 out-of-range line numbers and 3 ambiguous basenames out of 143 citations.
- `section8_to_sarif.py REPORT.md --out findings.sarif --root <repo>` — on request, after verification.
- `refresh_atlas.py` — on each ATLAS release. Its audit output is the reconciliation to-do list; it never rewrites the hand-curated mappings. `--strict` also fails on unmarked name mismatches.
- `package.sh <tag>` — builds `ai-threat-models-<tag>.zip` from a clean copy after a passing strict audit (`ATLAS_YAML=path` for offline).

### ATLAS reconciliation (2026-09-29, ATLAS 5.6.0)

`refresh_atlas.py --check-only --strict` now passes: 0 cited IDs absent, 0 unmarked name mismatches (six `abbrev?` shorthand hits remain by design). What changed: six source IDs whose written names did not match the release were re-IDed by row intent (T0055 "Plugin Compromise" → T0110 / T0011.002 / T0053; T0058 "Exfil via Tool" → T0086 / T0053; T0002 "Inference API Access" → T0040; T0024 sharpened to .000 / .001 / .002; T0004 "Reconnaissance" → T0003 / T0064 / T0012; T0048.001 → T0048.000 and T0080); the upstream rename of T0031 to Erode AI Model Integrity was applied, with the 17 evasion rows moved to T0015 or the specific T0068 / T0097 / T0094 / T0053. The 2026 agentic techniques (T0053, T0080, T0086, T0101, T0104, T0105, T0109–T0112, T0070/T0071, T0081–T0084, T0098, T0103/T0108, T0056/T0057/T0077/T0067, T0092/T0094) are in the crosswalk's ATLAS table and in a labeled Part 1 addendum of the library; the MCP, AST, and PHANTOM-B mapping tables each carry an ATLAS column. Distinct ATLAS IDs cited: 69 (was 15). Still uncited: 55 top-level techniques, mostly classic ML (image/audio attacks) and ATT&CK-mirror entries; run the audit to list them.

`scripts/package.sh <tag>` is the packaging path and refuses to build the zip if the strict audit fails.

### Data-quality caveats carried in-file

One reference file carries source-fidelity warnings that should be preserved on edit:

- `threat-technique-and-control-library.md` — Part 1 has OCR-repaired strings and internally inconsistent OWASP/ASI/ATLAS labels (notably the ASI05 dual-labeling); reconcile against authoritative lists before high-stakes citation. Part 3's source carried trailing provenance markers and duplicate rows, since cleaned and deduplicated to 41 unique threats.

### Known edge cases worth tightening

Surfaced during a full worked assessment:

- **Mis-slotted worksheet answers.** If a filled-worksheet answer doesn't actually address its question, treat the question as unanswered — don't harvest the mismatched text as evidence for something else.
- **Aspirational vs. implemented controls.** "Best practice" worksheet answers often blend evidenced facts with recommended-but-unverified controls. Treat a recommended control as "None evidenced" for control state unless its implementation is shown.
- **Deployment model is rarely stated.** AaI/AaP/AaaS is needed for SSRM ownership but seldom provided; it's a strong default for the single clarifying question.
- **Impact ceiling vs. likelihood.** Don't let a high impact ceiling (e.g. the mere presence of `execute_command`) inflate a risk rating when likelihood is genuinely unassessed — mark likelihood unassessable and keep the rating provisional.

---

## Scope and limitations

- Built for **agentic** systems. For a purely passive LLM chatbot (no tools, memory, or autonomy) the skill produces an abbreviated assessment (L2, L3, L8, L9, L10), notes MAESTRO is partially over-scoped, and uses PHANTOM-B as the primary L2 prompt set for that case.
- Defensive only — no exploit code or weaponizable detail.
- The TRAIT&R lens is a *second line of defence* model: it limits the harm of a misaligned agent, it does not prevent the cause, and its threats are conservative hypotheticals rather than observed behaviour.
- Not a substitute for hands-on testing; its output identifies what to validate and which artifacts would close each gap.
