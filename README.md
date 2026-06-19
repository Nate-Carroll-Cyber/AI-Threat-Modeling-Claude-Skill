# AI Threat Models

IN DEVELOPMENT.

INSTALLATION: DOWNLOAD AND INSTALL THE .ZIP FILE VIA CLAUDE SETTINGS (MAC OSX) > CAPABILITIES > SKILLS (CUSTOMIZE) > + CREATE SKILL > UPLOAD A SKILL 

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
- Optionally crosswalks to other frameworks (STRIDE, MITRE ATLAS, OWASP LLM Top 10, OWASP Agentic, NIST AI RMF) on request — one named framework at a time, or all of them at once via full-crosswalk mode (see **Output**).
- Optionally applies the **inverted-adversary lens** (TRAIT&R) when insider-threat / misalignment is in scope.

It is a **defensive** modeling tool. It declines requests for exploit code or weaponizable detail and continues with the defensive analysis.

## When it fires

The skill is for a structured security analysis of an AI system — not generic security advice, a CVE lookup, or a code review. It triggers when the user:

- Names a system (built or proposed) and asks for risks, threats, or a security review.
- Mentions agentic / MCP / RAG / multi-agent / tool-using / LLM architecture and wants the attack surface mapped.
- Explicitly asks for MAESTRO, STRIDE-for-AI, MITRE ATLAS, or OWASP LLM/Agentic alignment.
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

## Methodology (five steps)

1. **System Decomposition** — map evidenced components to layers; map agent-to-agent boundaries if multi-agent.
2. **Layer-Specific Threat Analysis** — assess applicable threats per evidenced layer; additionally evaluate multi-agent categories, the seven context-engineering threats (CE-T1…CE-T7), and — if insider-threat/misalignment is in scope — the TRAIT&R inverted-adversary lens.
3. **Cross-Layer Path Analysis** — trace how compromise propagates; don't manufacture paths.
4. **Mitigation & SSRM Ownership** — recommend concrete controls; assign 3SRM roles.
5. **Framework Crosswalk** — optional, on request (see **Output** for how to control it).

## Output

A 14-section assessment in a fixed order, from "Understanding Confirmed" through per-layer status, detailed per-threat blocks, cross-layer paths, the SSRM ownership table, an optional crosswalk, required validation steps, and a single clarifying question (omitted if nothing critical is missing). The exact section list and the per-threat block template live inline in `SKILL.md`.

### Framework crosswalk (Section 11) — how to control it

**By default the assessment uses MAESTRO as its single spine and includes no external-framework crosswalk.** This keeps the report focused: crosswalks are a secondary lens that competes with the MAESTRO spine for the reader's attention, so Section 11 appears only when asked for. To get one, say what you want:

- **One (or a few) named frameworks** — *"map this to MITRE ATLAS"*, *"add NIST AI RMF alignment"*, *"include the OWASP Agentic Top 10 crosswalk"* — produces just that subsection (or those subsections). Naming one framework does not pull in the others.
- **All of them at once** — *"include the full framework crosswalk"*, *"crosswalk to everything"*, or *"all frameworks"* — triggers **full-crosswalk mode**: the complete Section 11 with all six subsections in fixed order — **11.1 STRIDE · 11.2 MITRE ATLAS · 11.3 OWASP LLM Top 10 · 11.4 OWASP Agentic Top 10 (ASI01–ASI10) · 11.5 OWASP Agentic T1–T15 (with mitigation playbooks) · 11.6 NIST AI RMF**.

Two things hold in either case, by design:

- **Crosswalks re-express existing findings; they never add new ones.** Each subsection restates the assessment's Section 8 MAESTRO findings in another framework's vocabulary. The MAESTRO `L<n>-T<nn>` ID stays canonical; the external framework ID is the secondary column. Cells with no evidenced threat are omitted, not padded with "N/A", and a whole technique class that doesn't apply is called out with the reason (e.g. "model-extraction techniques not mapped — no training/fine-tuning surface evidenced").
- **Full-crosswalk mode does *not* include the inverted-adversary lens.** TRAIT&R (insider-threat / misalignment) is a separate opt-in with its own adversary direction — ask for it explicitly if you want it; "all frameworks" does not pull it in.

---

## Repository structure

```
SKILL.md                                Orchestration: triggers, rules, methodology, output format,
                                        the per-threat block template, and edge cases
README.md                               This file
references/
  maestro-layers.md                     The L1–L10 layer catalog: components, sample threats
                                        (L<n>-T<nn>), SSRM owners, the CE-T1…CE-T7 context threats
                                        and multi-agent categories handled inline within the relevant
                                        layers, plus the OWASP T16–T25 extended scenarios mapped to layers
  ssrm-ownership.md                     Agent 3SRM six-role model, responsibility matrix, six-layer
                                        aaS stack, deployment-model variations, the delegation-chain
                                        accountability principle, and the six categories of structural
                                        AICM gap
  framework-crosswalk.md                STRIDE / ATLAS / OWASP LLM / OWASP Agentic (ASI01–ASI10 +
                                        T1–T15 with decision path and six mitigation playbooks) /
                                        NIST AI RMF / cloud-provider mappings;
                                        defines full-crosswalk mode (the opt-in all-frameworks path)
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

Reference files are loaded conditionally, not all at once:

- `maestro-layers.md` — always, when producing an assessment. (Context-engineering and multi-agent threat categories are inline here and in the methodology, not separate files.)
- `ssrm-ownership.md` — for Step 4 ownership assignment, and when a finding maps to one of the six structural AICM gaps.
- `framework-crosswalk.md` — only when the user requests a non-MAESTRO framework (one named framework, several, or all of them via full-crosswalk mode).
- `threat-technique-and-control-library.md` — when technique-level attack granularity, a structured control source, or the trust/identity-lifecycle lens is needed.
- `ai-control-trait-r.md` — when insider-threat, misalignment, or untrusted-internal-deployment concerns are in scope.

---

## Maintainer notes

### Crosswalk default — opt-in, not automatic

Section 11 is **off by default and produced only on request** — one subsection per named framework, or all six via full-crosswalk mode. This is deliberate, not an omission: the skill's first principle is that MAESTRO is the single analytical spine and the other frameworks are secondary lenses that map *into* it. Emitting crosswalks unprompted reintroduces the failure mode the design prevents — the report drifts from a threat model toward a framework-mapping exercise, and reflexively generated mappings tend to overstate coverage. If you are considering changing the default to always-on, weigh that against the majority of uses that are not compliance-driven; the recommended posture is to keep it opt-in and make opting-in cheap (the full-crosswalk trigger phrases), which is the current design. The trigger list and the full-crosswalk spec both live in `framework-crosswalk.md` under "When to include Section 11".

### Numbering systems — keep them separate

The skill deliberately uses several independent ID schemes. Conflating them is the most common way to corrupt an assessment:

- **`L<n>-T<nn>`** — MAESTRO layer threats (the primary spine; always used as the canonical ID in output).
- **`CE-T1 … CE-T7`** — context-engineering threats, anchored to L3.
- **OWASP `T1–T15`** and the extended **`T16–T25`** — a *secondary lens* in `framework-crosswalk.md` and `maestro-layers.md`. These are NOT MAESTRO IDs and must never be substituted for `L<n>-T<nn>`.
- **`ASI01–ASI10`** — the OWASP Agentic Top 10, distinct again from the T1–T15 taxonomy.
- **`AITech-* / AISubtech-*`** — the technique taxonomy in `threat-technique-and-control-library.md` Part 1; a secondary lens, never substituted for MAESTRO IDs.
- **TRAIT&R `D1–D4` / `R1–R3`** — capability tiers in `ai-control-trait-r.md`; these gate *mitigations by model capability*, a different axis from MAESTRO's layer decomposition. Do not conflate with `L<n>-T<nn>`.
- **`LOG-16 (Proposed …)`** and similar — proposed / not-yet-canonical AICM entries; always cited as `Proposed [ID]` and reconciled against the authoritative AICM catalog before audit-grade use. Where no clean control exists, name the structural AICM gap (see `ssrm-ownership.md`) rather than over-claiming coverage.

When extending the skill, the MAESTRO `L<n>-T<nn>` ID stays primary in all output; everything else is cited parenthetically as a secondary lens.

### Two adversary directions — keep them separate

The default lenses (MAESTRO, ATLAS, OWASP, AICM) model threats *against* the AI system. TRAIT&R (`ai-control-trait-r.md`) models threats *by* a misaligned internal agent — the inverse. A control's sign can flip between them (chain-of-thought access is a disclosure risk under the external lens but the key defensive affordance under the internal one). Keep findings tagged with their adversary direction; do not fold TRAIT&R tactics into the ATLAS-keyed crosswalk. Note in particular that full-crosswalk mode covers only the external-attacker frameworks and deliberately excludes TRAIT&R.

### Adding a new threat

Add it to the relevant layer in `maestro-layers.md` with a canonical `L<n>-T<nn>` ID, sample attack vector, and SSRM owner. If it has cross-framework equivalents, add the mapping rows to `framework-crosswalk.md`. Technique-level or trust/identity threats go in the appropriately-labeled part of `threat-technique-and-control-library.md`. Keep the canonical per-layer lists clean — imported taxonomies (OWASP T-numbers, AITech-*) go in their own clearly-labeled sections, not interleaved into the MAESTRO lists.

### Adding a framework crosswalk

Add a `## MAESTRO + <Framework>` section to `framework-crosswalk.md`, following the existing pattern: a short framing paragraph stating what the framework is good and bad at, then a mapping table into MAESTRO layers. Update the "When to include Section 11" trigger list and the reference-file description in `SKILL.md`. **If the new framework should be part of full-crosswalk mode, also add it to the fixed subsection order in the "Full crosswalk mode" block** (and renumber the 11.x sequence) so the all-frameworks path stays complete and reproducible.

### Source versioning (known inconsistencies, not yet reconciled)

Reference files cite their MAESTRO / AICM / 3SRM source sections, and some version strings disagree. These are left as-is pending verification against the published sources rather than silently aligned:

- **MAESTRO**: cited as "v2.0" in most files, but `maestro-layers.md` cites a "v0.91 draft" (Section 7). Align when the canonical version is confirmed.
- **AICM**: cited as "v1.1" across most of the skill. Verify control IDs against the catalog you are working from before audit-grade use.
- **3SRM**: tracks CSA's *AI Agents: Shared Security and Safety Responsibility Model* (v0.981); naming varies between "Agent 3SRM" and "Agent SSRM" (see the terminology note in `ssrm-ownership.md`).
- **TRAIT&R**: sourced from the *GDM AI Control Roadmap* v0.1 (Phuong et al., Google DeepMind, June 2026). Theory-based, not observed in the wild — findings are marked as conservative hypotheticals. Confirm the citation against the live GDM publication before any audit-facing use.

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

- Built for **agentic** systems. For a purely passive LLM chatbot (no tools, memory, or autonomy) the skill produces an abbreviated assessment (L2, L3, L8, L9, L10) and notes it is partially over-scoped.
- Defensive only — no exploit code or weaponizable detail.
- The TRAIT&R lens is a *second line of defence* model: it limits the harm of a misaligned agent, it does not prevent the cause, and its threats are conservative hypotheticals rather than observed behaviour.
- Not a substitute for hands-on testing; its output identifies what to validate and which artifacts would close each gap.
