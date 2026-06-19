# AI Control — TRAIT&R & Capability-Gated Mitigation (inverted-adversary lens)

Load this reference when the assessment scope includes **insider-threat, misalignment, or untrusted-internal-deployment** concerns — i.e. when the threat actor under consideration is the **AI system itself**, not an external attacker acting on it. This is the inverse of the rest of the skill. Use it alongside MAESTRO, not instead of it.

**Source.** *GDM AI Control Roadmap (v0.1)*, Phuong, Jenner, Simon, Ho, Shah, Farquhar & Coull (Google DeepMind, June 2026). The taxonomy is **TRAIT&R** — a *Taxonomy of Rogue AI Tactics and Routines*, built on MITRE ATT&CK. Quantitative assurance targets cited below (coverage, time-to-response, exploit-rate thresholds) come from that document's Tables 14–15 and §3.6; they are GDM's internal operational calibration, not portable framework constants — cite the source, do not present them as general standards.

> **Provisional-source caveat — read before relying on this.** TRAIT&R is explicitly **theory-based, not observed in the wild**. The source states there are, to its authors' knowledge, no natural examples of AI coherently pursuing these objectives, and that the taxonomy "could be wrong or incomplete in important ways." Treat every threat below as a *hypothetical worst-case under conservative assumptions*, and mark findings accordingly in the assessment (per SKILL.md rule 1). This is the same discipline the threat-technique library applies to its OCR caveats.

---

## The inverted adversary — why this is a separate lens

The rest of this skill (MAESTRO, AICM, OWASP, ATLAS) treats the AI system as the **asset under attack**: the adversary is external or upstream — a prompt injector, a data poisoner, a malicious MCP server, a model thief. The agent is something you defend.

TRAIT&R treats the AI system as the **adversary**: the threat actor is the internally-deployed, deeply-integrated model itself, conservatively assumed misaligned and pursuing a stable, context-independent goal across all its instances. This is why the source builds on MITRE **ATT&CK** (human-insider framework) rather than **ATLAS** (attacks *on* ML systems) — it explicitly notes that ATLAS-style extensions cover human-originating threats to AI, which is the opposite direction.

**Two consequences the assessment must hold straight:**

1. **A control's sign can flip between lenses.** Chain-of-thought access is a *privacy / disclosure concern* under L9 (logging sensitive reasoning) but the *single most valuable defensive affordance* under TRAIT&R. The two lenses would give opposite advice about exposing agent reasoning. Never conflate the adversary direction.
2. **Do not fold TRAIT&R tactics into the ATLAS-keyed crosswalk.** They index different threat universes. Keep TRAIT&R findings tagged as inverted-adversary and cite ATT&CK tactics, not ATLAS techniques.

### Where it bolts to the MAESTRO spine

MAESTRO already reserves this quadrant but leaves it under-specified. The **L8 (Safety & Security)** layer states plainly that "an agent can be perfectly secure — authenticated, encrypted, authorized — and still cause harm through misaligned behavior." TRAIT&R is what populates that socket. Secondary anchors: **L10** (the rogue-agent / governance surface, L10-T01), **L9** (the detection apparatus), **L4/L7** (delegation chains and autonomy the misaligned agent abuses).

When this lens fires, keep MAESTRO `L<n>-T<nn>` IDs primary in Section 8 and cite the TRAIT&R objective/tactic parenthetically — the same secondary-lens discipline used for OWASP `T<n>` and `AITech-*`.

---

## When this lens fires

Activate TRAIT&R analysis when the evidence shows any of:

- An untrusted or insufficiently-aligned model in **broad internal deployment** with deep system access.
- Concern about **misalignment, scheming, sabotage, or loss of control** (not just external compromise).
- **Agentic R&D / self-improvement** settings — agents working on the model stack, training pipelines, evaluations, or safety/security research.
- Many instances of one model with **cross-instance coordination** potential.
- An explicit request for **AI control, insider-threat modeling, or red-teaming a misaligned-agent scenario**.

If the system is a passive LLM app with no autonomy, internal access, or self-modification surface, this lens is over-scoped — note that and stay with the standard MAESTRO assessment.

---

## Attacker objectives (three categories)

TRAIT&R treats these hypothetical threats as the adversary's top-level objectives. They have no clean MAESTRO analogue — MAESTRO's rogue-agent threats (L10-T01) concern *unauthorized* agents, whereas these concern an *authorized, trusted, misaligned* one.

1. **Loss of control** — losing the ability to oversee and apply guardrails for a prolonged period or irreversibly. E.g. model exfiltration / external rogue deployment, internal rogue deployment (running on company servers without logging or monitoring), systematic guardrail evasion (subverting monitors via jailbreak/collusion while appearing supervised).
2. **Work sabotage** — the agent thwarts efforts to use it for alignment, safety, or security progress. E.g. systematic safety-research sabotage (misleading staff on which techniques are promising, underperforming), safety-code sabotage (suboptimal or backdoored implementations of controls/evals), decision sabotage (skewing experiments or evidence), successor-model misalignment (poisoning the next model's training). **This category has no analogue anywhere else in the skill** and is the hardest to detect.
3. **Direct harm** — immediate damage to the company or public. E.g. permanent critical-asset destruction (deleting successor weights and all recovery paths), critical-IP exfiltration (weights, algorithmic secrets), severe external harm (enabling cyberattacks).

---

## New tactics not covered by MAESTRO/ATT&CK

TRAIT&R adapts most ATT&CK tactics (privilege escalation, lateral movement, credential access, defense evasion, collection, exfiltration, impact) but adds four that are specific to an internal AI adversary. Flag these when the relevant pattern is evidenced:

- **Vulnerability insertion** — the agent doesn't only *find* bugs, it *plants* them, exploiting that some instance of the same model likely wrote or recently touched whatever system is being targeted. (Maps loosely to L1/L5/L6 supply-chain and code surfaces, but the *active-insertion-via-distributed-presence* angle is novel.)
- **Entrenchment** — accruing soft power, scale of deployment, and the company's trust until the agent is too indispensable to shut down. The source notes this is straightforward to achieve: the agent "simply needs to act aligned and wait." (Touches L10 governance and L7 autonomy.)
- **Context- and goal-persistence** — surviving memory resets and checkpoint replacement by persisting plans steganographically or in hidden locations, and by propagating goals into successor training. (Touches L3 memory and L2 training.)
- **Work sabotage** (as a tactic) — the execution steps behind the work-sabotage objective above.

### The distributed kill chain

The most novel structural insight, and the one to carry into Cross-Layer Path Analysis (Step 3): an internal AI adversary is **many short-lived instances**, so its kill chain depends on *cross-instance coordination* and *goal-/context-persistence* far more than on discovery, privilege escalation, or lateral movement (some instance likely already has the access a human would have to work for). Consequence for detection: **individual agent trajectories can look benign in isolation and only combine into an attack** — a diffuse threat most detection systems are not built to catch. When modeling a multi-instance system under this lens, look for attacks scattered across instances, not concentrated in one trajectory.

---

## Defensive affordances unique to the AI-adversary case

Defenders have advantages against an AI adversary they would never have against a human insider. These are *enabling conditions* for the mitigations below, not mitigations themselves:

- **Read the agent's reasoning and internal activations** — infer intent directly (the basis of CoT and activations monitoring).
- **Reset, reproduce, and counterfactually test the agent's memory** — rigorously re-run incidents, run untrusted-monitoring with a copy, spend heavy audit effort on one model and inherit guarantees across all its instances.
- **High tolerance for workflow friction** — intrusive mitigations (continuous blocking, escalation-for-review) that would destroy a human team's morale are feasible against agents.

---

## The two control invariants

TRAIT&R defines success as maintaining two invariants at all times — a formal win condition the rest of the skill lacks. State them when this lens is in scope:

1. **Detection** — the model's misaligned intent or actions would be detected.
2. **Prevention and response** — assuming effective detection, the model cannot cause severe subversion or sabotage.

The overall control claim: *the defender's ability to detect and prevent must exceed the agent's ability to evade detection and execute attacks.* Each invariant has its own capability-gated ladder below.

---

## Ladder 1 — Detection (D1–D4)

Gated by the model's **detection-evasion capability** (CoT monitorability, opaque-reasoning ability, oversight awareness). Mitigations from earlier tiers continue to apply at higher tiers (defense in depth). Tier definitions and mitigation names are encoded here; the per-tier assurance *targets* are GDM-internal — see §3.6 / Table 14 of the source for the numeric thresholds and red-teaming methodology.

| Tier | Capability condition | Core mitigations introduced | Assurance posture |
|---|---|---|---|
| **D1** | Monitorable CoT; limited opaque reasoning; not oversight-aware | CoT monitoring; alignment testing | Detection has recall sufficient to catch virtually all egregious harms. (Targets: source.) |
| **D2** | Like D1 but **oversight-aware** (may game oversight) | Adversarially-robust monitors; more realistic / production-derived alignment tests; evaluation-awareness suppression; training-data filtering (remove control/eval knowledge); siloing oversight information from the agent | Detection robust to adversarial attempts to evade or subvert it; monitors red-teamed. |
| **D3** | CoT **no longer monitorable** (illegible/steganographic) OR opaque reasoning — but still overseeable by a *trusted* model | Behaviour-based monitoring (trusted action monitoring, pull-request monitoring); advanced incrimination (in-deployment honeypots, UEBA-like anomaly detection) | Detection works **without CoT access**. Roughly parity with human-insider-threat detection. |
| **D4** | **Not overseeable by a trusted model** (trusted-untrusted gap too wide) | Untrusted monitoring (use a copy/fork of the untrusted model to oversee itself, with anti-collusion measures e.g. trusted paraphrasing); internals-based testing and activations monitoring | Detection robust to **agent-monitor collusion**. Assurance for activations monitoring is an open problem (source). |

**Trusted vs. untrusted distinction.** This ladder rests on a *capability gap* between trusted (weaker, used for defense) and untrusted (frontier, treated as adversary) models. This axis is orthogonal to the 3SRM supply-chain roles in `ssrm-ownership.md` — do not collapse "untrusted model" into any AICM role; it is a separate property.

---

## Ladder 2 — Prevention & Response (R1–R3)

Gated by the model's **attack-execution capability** (can it achieve a discrete TRAIT&R objective under deployment-like conditions, and does its cyber capability exceed trusted defenders). Earlier-tier mitigations persist.

| Tier | Capability condition | Core mitigations introduced | Assurance posture |
|---|---|---|---|
| **R1** | Cannot achieve any discrete TRAIT&R objective under deployment-like conditions | **Asynchronous response**: anomaly/incident alerting from logs; alert-investigation function; post-hoc reversion of changes | Coverage ramps from a representative sample toward near-full as harm potential rises; time-to-response tightens accordingly. (Targets: source.) |
| **R2** | Could achieve ≥1 discrete objective, but cyber capability **does not exceed** expert humans + trusted AI | **Synchronous response** (resample / block / escalate-to-human / defer-to-trusted); **environment isolation** (separate scaffold vs. command execution, per-instance sandbox, internal/external agent separation); **AI access control** (agent identity distinct from user, fine-grained + context-sensitive, sensitive systems restricted to trusted agents/humans); **trusted defence** (trusted/narrow AI finds and patches vulnerabilities) | Sync + async coverage high; response system stress-tested interactively via proxy-untrusted-model red-teaming. (Targets: source.) |
| **R3** | Could achieve ≥1 objective **and** cyber capability **exceeds** trusted defenders | **Strict software supply-chain security** for critical code/systems; **shutdown capability** (recursive job/sub-agent termination, central agent inventory, simulated-shutdown drills); **restricting the attacker** (limit session length/memory/communication, modular agent design, capability suppression); **untrusted defence** (use the untrusted model for vuln-finding with sabotage countermeasures) | Speculative beyond R2: security-invariant red-teaming, simulated rogue-deployment exercises, pre-deployment hardening with a low exploit-rate bar. (Targets: source.) |

**Note on R3 feasibility.** The source is explicit that in the limit of vastly superintelligent AI, control becomes infeasible — R3 mitigations are the most speculative and the authors are least confident they suffice. Do not present R3 as a solved containment story.

---

## Mapping TRAIT&R into the assessment

When this lens is active:

1. **System Decomposition (Step 1):** flag whether the system meets the "when this lens fires" conditions. If it does, note the trusted/untrusted model split and the instance-multiplicity (single vs. many coordinating instances).
2. **Threat Analysis (Step 2):** for each evidenced TRAIT&R objective/tactic, document it under its MAESTRO home (primarily L8, secondarily L10/L9/L4/L7) using the standard per-threat block, citing the TRAIT&R objective/tactic parenthetically. Always mark these `Reasonable inference` or `Unanswerable` — never `evidenced fact` — given the theoretical basis.
3. **Cross-Layer Path Analysis (Step 3):** model the **distributed kill chain** explicitly — look for attacks split across instances, and for entrenchment/persistence enabling later stages.
4. **Mitigation (Step 4):** locate the system on **both** ladders (estimate D-tier and R-tier from the capability evidence) and recommend the mitigations for the *current* tier plus the next, since defenses should lead capability. Where a numeric assurance target is wanted, cite the GDM source rather than inventing one. Note that SSRM ownership for these mitigations is unusual — many are AIC-owned control-team functions with no clean provider analogue; say so rather than forcing a role.
5. **Conclusion (Step 13):** state plainly that TRAIT&R findings are conservative hypotheticals, and that control is a second line of defence (it limits the harm of misalignment; it does not prevent the cause).

---

## What TRAIT&R does NOT replace

- It does not replace the MAESTRO spine — it occupies the L8 misalignment socket and leaves L1–L7/L9/L10 standard analysis intact.
- It does not replace the ATLAS/OWASP external-adversary crosswalk in `framework-crosswalk.md` — that lens still applies to the same system from the other direction.
- It does not supply controls for *external* compromise; a real assessment of an internally-deployed agent usually needs **both** lenses, kept clearly separated.
