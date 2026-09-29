# PHANTOM-B (STRIDE analog for LLMs)

Load this reference when **either** condition holds:

1. **Mandatory Step 2 lens (skill rule 9; results in Section 10.1)** — the evidence or the request references at least one LLM call component (an L2 Cognitive Core entry in the Step 1 mapping). This is nearly every assessment, so the lens is cheap by design: eight prompts run once per evidenced LLM component. It is also the **primary L2 prompt set for the not-actually-agentic edge case** (a passive chatbot with no tools, memory, or autonomy), where MAESTRO's agentic threat list is partially over-scoped and PHANTOM-B is right-sized.
2. **Named crosswalk** — the user asks for "PHANTOM-B", "STRIDE for LLMs / STRIDE analog", or "what can go wrong with the LLM parts" alignment (Section 13.2).

**Source**: Adam Shostack, *PHANTOM-B: A STRIDE Analog for LLMs*, Shostack + Associates White Paper #6, July 2026 — version **PHANTOM-B 1.0, Q3 2026**. https://shostack.org/files/papers/PHANTOM-B_Whitepaper_Shostack.pdf. Companion blog posts at https://shostack.org/blog/why-phantom-b/ and https://shostack.org/blog/phantom-b-talk-summary/ (Black Hat USA 2026 talk).

**License**: CC-BY. Attribution is required in any deliverable that uses the mnemonic; there is no NonCommercial term (contrast `mcp-top10.md`). This file is still own-words paraphrase — do not lift the paper's prose into a deliverable.

---

## Design characteristics that change how the lens behaves

Each of these is a stated design choice in the paper and determines how the skill applies the lens. Do not silently override them.

- **Scoped to LLM callers, not LLM trainers.** The paper draws the PHANTOM-B boundary around the LLM subset of the data-flow diagram (the front end that assembles prompts plus the inference component, whether self-hosted weights or a provider API). Everything outside that boundary stays with STRIDE — and, in this skill, with the MAESTRO layers other than L2. Training-pipeline threats are covered only as they land on the caller (model selection).
- **Prompts, not categories.** The eight letters are questions to run against each LLM component, designed to move from a general threat class to specific instances. A specific finding may not fit one letter cleanly; file it under its MAESTRO home and cite the nearest letter. Never pad a letter with a manufactured finding — a letter with no evidenced instance is one line ("no instance evidenced") and is dropped from Section 9.
- **No mitigations, by design.** The paper deliberately ships no defenses, controls, or mitigations (the same choice Google SAIF makes), on the grounds that controls change faster than the threats. Step 4 mitigations for PHANTOM-B findings are therefore sourced from MAESTRO per-layer guidance, the FAIR-CAM library, and the OWASP playbooks — never attributed to PHANTOM-B.
- **Five of the eight are not attacks.** Hallucination, Anthropomorphization, Non-explainability, Over-reliance, and Biases are failure modes or conditions that need no adversary (each can also be induced or exploited, and the adversarial variant is noted below). In the Section 9 per-threat block, the **Attack Vector** field for a non-adversarial finding reads `Failure mode (no adversary required): …`, and **Likelihood** is justified from evidenced evaluation results (bias tests, hallucination-rate measurements, HITL coverage), not from an attacker model.
- **Breadth over depth.** The paper's own comparison table rates PHANTOM-B low effort to learn, low effort to use, high threat uniqueness, low detail; it rates MAESTRO very high to learn, high to use, and leaves its uniqueness and detail unevaluated, with a footnote that MAESTRO does not align to the Four Question Framework. In this skill PHANTOM-B is a **completeness check on L2**, not a replacement for L2-T01–L2-T06: it surfaces the non-adversarial surfaces (H, A, N, O, B) that MAESTRO's threat list covers only through L8 components and L10 GRC controls.
- **Four Question Framework alignment.** The paper positions PHANTOM-B as an answer to Q2 ("what can go wrong?") for the LLM component. This skill's steps sit on the same four questions: Step 1 ↔ Q1 (what are we working on), Steps 2–3 ↔ Q2, Step 4 ↔ Q3 (what are we going to do about it), Sections 14–15 ↔ Q4 (did we do a good job). Use this mapping when the user's program runs on the Four Question Framework and is adding MAESTRO.

---

## The eight prompts → MAESTRO v2.0 mapping

MAESTRO `L<n>-T<nn>` IDs stay primary in Section 9; cite the letter parenthetically as `PB-<letter>` (skill-local shorthand — the paper uses the bare mnemonic letters, not IDs). Three letters have **no canonical L2-T ID**; anchor them to the layer and treat as an L2 reliability/safety finding, the same convention `maestro-layers.md` applies to OWASP T16.

| PB | Threat (own-words gist) | Adversary? | MAESTRO v2.0 layer homes | Nearest MAESTRO threat IDs | ATLAS (5.6.0) |
|---|---|---|---|---|---|
| PB-P | Prompt injection — input confused with instructions because the model compresses user, system, and retrieved text into the same token stream. Three forms: **direct** (adversarial chat input), **indirect** (instructions planted in web pages, images, or documents and left to be retrieved), **multi-stage** (spread across several messages to evade single-message filters). The paper's framing: prompt injection is a demonstration that code/data separation is missing, and asking the model to reason about its own input safety is not that control. | Yes | L2, L4, L3, L6, L8 | L2-T03 (direct); L3-T04 / CE-T1 and L6-T04/L6-T08 (indirect via retrieved or tool-returned content); L4-T02 (goal hijacking outcome); L8-T01 (guardrail bypass) | AML.T0051.000 Direct; T0051.001 Indirect; T0051.002 Triggered; T0054 Jailbreak; T0080 Context Poisoning |
| PB-H | Hallucination — outputs at odds with fact, arithmetic, or common sense (fabricated citations are the recognizable case). The paper's framing: every output is the same statistical process; "hallucination" is the name for the cases we notice. | No (inducible) | L2, L8, L6 | No canonical L2-T ID — L2 reliability finding; L8 (hallucination detection component; L8-T03 when it cascades through an agent chain, cf. OWASP T5); L6-T07 when output misleads a user into action | AML.T0067.000 Citations manipulation (adversarial variant); no ATLAS technique for unforced hallucination |
| PB-A | Anthropomorphization — attributing intent, thinking, or remorse to the model. Design consequences: assuming a negative instruction ("do not X") works as it would on a person when it may add weight to X; "reasoning"/"agentic" vocabulary misleading the deploying team about what the component does; chatbots presenting as "I". | No | L2, L10, L6 | No canonical L2-T ID — L2 system-prompt/persona surface; L10 (GRC-09 acceptable use, risk communication to the organization); L6-T07 (persona presentation that misleads users); ASI09 | none (design condition, not an adversary technique) |
| PB-N | Non-explainability — when the LLM decides or commands (screening, diagnosis), the deployer must be able to say why; the model's own account of its prior output is a plausible reconstruction, not an analysis; non-determinism makes reproduction and debugging harder. | No (L9-T04 is the adversarial variant) | L9, L10 | L9-T04 (explainability manipulation — nearest ID); L10-T06 (regulatory explainability obligations); L9 prompt/context logging as the reconstruction substrate; GRC-13/14 | AML.T0092 Manipulate User LLM Chat History (adversarial variant) |
| PB-T | Training issues — **intentional** poisoning (trigger-phrase backdoors, capacity degradation) and **accidental/incidental** poisoning (scraped-corpus junk, in-jokes). The caller cannot change the training set but can fold what is known about it into model selection. | Both | L2, L1 | L2-T02 (training/fine-tune poisoning), L2-T04 (model supply chain), L2-T05 (alignment degradation via fine-tuning); L1-T01 for the weight-distribution path. **Not** L3-T01 — RAG poisoning is retrieval-time, a different surface | AML.T0020 Poison Training Data; T0018.000 Poison AI Model; T0058 Publish Poisoned Models; T0010.003 Model |
| PB-O | Over-reliance — accepting model output without oversight because it is cheaper, faster, or shifts responsibility; unwanted **actions** are worse than wrong answers; model-written code shipped without review; a model running as root, with network reach, or with a user's SSO credentials can do whatever those can. Distinct from PB-A: A treats the LLM as a person, O accepts its output unchecked. | No (amplifies every other letter) | L7, L4, L8, L10, L6 | L7-T03 (over-privileged identity), L7-T04 (autonomy boundary violation), L4-T07 (HITL bypass by design), L6-T06 (API reach); OWASP LLM09; ASI09 | AML.T0053 AI Agent Tool Invocation; T0101 Data Destruction via AI Agent Tool Invocation; T0086 (outcomes of unchecked output) |
| PB-M | Missing security engineering — the catch-all: an LLM magnifies whatever conventional engineering failures already exist, and rush-to-ship or vibe-coded software nobody understands magnifies them further. | Condition | Outside the LLM subset | STRIDE on the rest of the DFD; MAESTRO L5-T02, L1-T01, L10-T02/L10-T03; the assessment's Section 5 gaps and Section 14 validation steps | none (condition); ATT&CK Enterprise applies to the rest of the DFD |
| PB-B | Biases — inherited at every stage (data collection, filtering, training, tuning) and also **introduced** by de-biasing, system prompts, and inference about the user; the caller inherits them but can test for them (representation tests). Three business exposures: bad answers, being seen as giving bad answers, breaking the law — protected-characteristic bias combined with over-reliance in hiring or similar decisions is the legal case. Bias differs from poison: narrower, baseline-relative and statistical, naturally introduced, subject to interpretation. | No | L2, L10, L8 | No canonical L2-T ID — L2 behavioral finding; L10-T06 (regulatory non-compliance); GRC-11 Bias and Fairness (AIC-owned per `maestro-layers.md` L10); L8 output validation | none (statistical property, not a technique) |

**Overlap discipline.** PB-P duplicates L2-T03 and PB-T duplicates L2-T02/L2-T04, which every assessment already evaluates. Do not emit a second finding; attach the PB letter to the existing block and use the sub-typing (direct/indirect/multi-stage; intentional/incidental) as evidence-check detail. The lens's net-new contribution is PB-H, PB-A, PB-N, PB-O, and PB-B.

---

## Per-prompt evidence checks

Same discipline as the AST and MCP lenses: each item is an evidence question; "no" is a finding, "unevidenced" is a gap. The first question under each letter is the paper's own prompt, reworded; the rest are what this skill needs to move it from general to specific.

### PB-P — Prompt injection
- Which inputs reach the model: user chat only, or also retrieved documents, tool/MCP output, images, web content (indirect surface)?
- Is retrieved and tool-returned content tagged as data and structurally separated from instructions (AIS-15 prompt differentiation), or does the design rely on the model judging its own inputs?
- Are conversation-level (multi-turn) detections in place, or only per-message filters?
- What can the model *do* on a successful injection (the blast radius question — answered by PB-O and L7 evidence)?

### PB-H — Hallucination
- What does the deployment assume about output correctness, and what happens when that assumption fails (cost of a wrong answer vs. a wrong action)?
- Is there a grounding, verification, or citation-check step before output is used or shown?
- Is a hallucination rate measured against a defined baseline (safety SLA per `ssrm-ownership.md`), and is the measurement pipeline distinct from security logging (skill rule 4)?
- In agent chains: does one component's output feed another's context without validation (PB-H → L8-T03 path)?

### PB-A — Anthropomorphization
- Does the system prompt or product copy present the model as a person, colleague, or reasoning agent, and to whom (end users, the deploying team)?
- Are behavioral constraints written as negative instructions with no enforcement outside the model?
- Does internal documentation describe what the component actually does (token prediction under a system prompt) or use "thinks / reasons / decides" language that shapes control decisions?

### PB-N — Non-explainability
- When does the output need justification, to whom (user, regulator, auditor, court), and under what obligation (L10-T06)?
- Is the justification produced from logged inputs, retrieved context, and decision rules, or from asking the model to explain itself after the fact?
- Are prompts, context, model version, and sampling parameters logged so a decision can be reconstructed (L9)?

### PB-T — Training issues
- Is the model's training-data provenance known at all (provider documentation, model card, dataset disclosure)?
- Did model selection weigh poisoning exposure and data quality, or only capability and price?
- Is any fine-tuning performed, and on what data with what integrity controls (L2-T02/L2-T05)?
- Are weights fetched from a verified source with integrity checks (L2-T04, L1-T01)?

### PB-O — Over-reliance
- What decisions does the model make, what does it control, and does that inadvertently widen the attack surface?
- Which outputs are acted on without human review (code merged, transactions approved, tickets closed)?
- What identity and reach does the runtime carry (root, network, SSO/SAML credentials) — the paper's three examples?
- Is oversight sized to the consequence of the action, or removed for throughput (L4-T07 by design rather than by bypass)?

### PB-M — Missing security engineering
- Was threat modeling and the rest of the SDL applied to the non-LLM parts of the system as appropriate?
- Was any of the surrounding code generated without review by people who understand it?
- Is the data the model can access, and where its output can be disclosed, controlled (the paper lists this under this prompt; map the finding to L3/L6 disclosure IDs)?

### PB-B — Biases
- Which biases matter for this use case (representation, protected characteristics, cultural), and are they acceptable for it?
- Has the caller tested for them, with what baseline and what result?
- Do the system prompt, de-biasing layer, or user-inference features introduce bias of their own?
- Is any decision in scope one where protected-characteristic bias plus over-reliance creates legal exposure (hiring, lending, medical triage)?

---

## Evidence base (for Likelihood justification)

The paper supplies one quantitative source; the rest of PHANTOM-B's Likelihood justification comes from the deployment's own evaluation evidence, which is the point of the evidence checks above.

- Souly et al., *Poisoning Attacks on LLMs Require a Near-constant Number of Poison Samples*, 8 Oct 2025, https://arxiv.org/abs/2510.07192 — on the order of 250 poisoned documents suffice to implant a backdoor across a wide range of model and dataset sizes. → PB-T (intentional). Use for Likelihood of L2-T02 when the training or fine-tuning corpus is open or partly untrusted.
- For PB-H, PB-B: an evidenced hallucination-rate or bias-test result is the Likelihood justification. Absent one, Likelihood is `Unassessable from current evidence` — a high impact ceiling does not substitute (see the README "Impact ceiling vs. likelihood" edge case).
- For PB-P: the incident bases in `agentic-skills-top10.md` and `mcp-top10.md` apply when the indirect surface runs through skills or MCP.

---

## Mitigation sourcing (Step 4)

PHANTOM-B ships none. Route each letter to the control sources already in the skill; own words, FAIR-CAM function class where used with `threat-technique-and-control-library.md`:

- **PB-P**: L2/L4 guidance — AIS-08 input validation, AIS-15 prompt differentiation, TVM-11 guardrails, untrusted-by-default tagging of retrieved and tool content, multi-turn detection (Prevention); injection-attempt logging (Detection). Playbook 1 for the reasoning-manipulation outcome.
- **PB-H**: grounding and citation verification, AIS-09 output validation, consequence-scaled human review before action (Prevention); hallucination-rate measurement against a safety SLA, cross-component validation before persistent commit — Playbook 2 (Detection).
- **PB-A**: system-prompt and product-copy review removing person-framing and unenforced negative instructions; behavioral constraints enforced outside the model (policy decision point, tool gating) rather than by instruction; internal documentation that names the component's actual function (Prevention). GRC-09 acceptable use.
- **PB-N**: decision logging of inputs, context, model version, and parameters sufficient to reconstruct an output (L9, LOG-*); explanation obligations traced to the regulatory driver (GRC-13/14); explanations generated from logged decision rules, never from post-hoc model self-report (Prevention/Detection).
- **PB-T**: provenance-weighted model selection, signed and integrity-checked weights (MDS-09), fine-tuning data integrity (DSP-21/23), documented training-data disclosure requirements in the MP contract (Prevention).
- **PB-O**: least-privilege runtime identity (no root, scoped network, no ambient SSO credentials — L7 guidance, Playbook 3/4), consequence-scaled HITL (GRC-15, Playbook 5), code review and testing gates on model-written code before production (Prevention); side-effect monitoring (Detection).
- **PB-M**: this letter's mitigation is the SDL itself — STRIDE on the rest of the DFD and the MAESTRO L1/L5/L10 findings. Record it as a Section 14 validation step, not a per-threat control.
- **PB-B**: representation and protected-characteristic testing with a stated baseline (GRC-11, GRC-10 impact assessment), output validation for the specific bias classes in scope (AIS-09), and — where over-reliance stacks on it — the PB-O controls, since the legal exposure needs both (Prevention/Detection).

**SSRM note.** Root cause for PB-P, PB-H, PB-T, and PB-B sits with the **MP** (model behavior and training), but the deployable mitigations are **AIC**-owned (model selection, prompt differentiation, output validation, testing). PB-A, PB-N, and PB-O are AIC-owned end to end — system prompt, explanation obligations, and oversight design are the Agent Owner's, and L10 accountability for the legal exposure under PB-B and PB-N is non-delegable per `ssrm-ownership.md`. Where the model is a provider API, PB-T evidence is limited to what the MP discloses; mark the rest `Unanswerable from current evidence` and name the model card or data-disclosure artifact as what would close it.
