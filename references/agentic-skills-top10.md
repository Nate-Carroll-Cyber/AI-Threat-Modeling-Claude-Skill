# OWASP Agentic Skills Top 10 (AST01–AST10)

Load this reference when **either** condition holds:

1. **Conditional Step 2 lens** — the evidence shows the system installs, loads, or executes third-party *skills* (behavior packages: SKILL.md, skill.json, manifest.json, package.json extensions), plugins, or agent extensions; or it consumes a skill registry / marketplace (ClawHub, skills.sh, or equivalent). Same activation pattern as the multi-agent categories and CE-T1–T7: evidence-gated, applied inside the standard layer analysis.
2. **Named crosswalk** — the user asks for "OWASP Agentic Skills Top 10", "AST10", or a "skill security review / skill supply-chain assessment" alignment (Section 11.7).

Do **not** apply this lens on the bare fact that "the agent uses tools." MCP tool integration is L6-T04/L6-T08 territory; the AST10 lens is specifically about the **behavior layer** — installable skill packages that orchestrate those tools. Mental model from the source project: *MCP = how the model talks to tools; AST10 = what those tools actually do.* If no skill installation/loading surface is evidenced, AST findings are `Unanswerable from current evidence`.

**Sources**: OWASP Agentic Skills Top 10, v1.0 (2026 Edition), CC-BY-SA-4.0 — project page (https://owasp.org/www-project-agentic-skills-top-10/) and the V1 whitepaper (assets/publications/ast10-top10-whitepaper-2.pdf). Incubator project.

**Severity caveat**: the Critical/High/Medium tiers below come from the project index page. The V1 whitepaper deliberately assigns no per-risk severity, deferring to AIVSS v1 (expected end of 2026). Cite the tiers as "project-page ratings, pre-AIVSS," not as final.

**Source-freshness note**: the GitHub main-branch ast01.md–ast10.md files are an older revision than the V1 whitepaper (they predate the QSAF, LAAF, relay-node, and model-dependence content); v1 review moved to a Google Doc. Treat the whitepaper as authoritative; the repo files additionally carry platform-specific mitigation guides (OpenClaw / Claude Code / Cursor / VS Code) that the whitepaper demoted to implementation detail — consult ast01.md directly if per-platform config guidance is needed.

## Scope boundary (from the whitepaper's terminology)

- **Skill** — a self-contained, natively discoverable bundle of instructions and resources (SKILL.md plus files) the agent loads into context. **AST01–AST10 apply to this form only.**
- **Tool** — a single callable function. **MCP server** — a separate process exposing tools over MCP; covered by the OWASP MCP Top 10, NOT this taxonomy. **Plugin/extension** — a host-specific installable that may bundle skills, tools, or MCP connections.

When a finding sits on an MCP server rather than a skill, keep it under MAESTRO L6-T04/L6-T08 (optionally MCP Top 10 IDs) — do not force an AST label onto it.

## Overlap triage (decision tree, from the whitepaper)

Several AST entries overlap. Pick the **primary** AST by root cause:

1. Skill itself malicious at publish time (hidden payload, credential theft, backdoor) → **AST01**.
2. Finding is about how the skill reached the registry/pipeline (typosquatting, missing signatures, weak publisher vetting, account takeover) → **AST02**.
3. Finding is in the SKILL.md/manifest metadata itself (deceptive description, understated permissions, spoofed risk_tier, unsafe deserialization) → **AST04**.
4. A scanner/reviewer control failed to catch what it should have → **AST08**.
5. If several apply, record the primary root cause as the origin AST and the scanner gap as a contributing control failure — do not split one finding across multiple ASTs.

---

## Layer-mapping caveat (read before citing)

The OWASP project page maps AST risks to CSA MAESTRO's **original 7-layer** model (Foundation Models → Agent Ecosystem). This skill's spine is **MAESTRO v2.0 (ten-layer)**. The table below is a re-mapping into the v2.0 layers; it is this skill's translation, not the OWASP project's published mapping. When the user needs the OWASP-published coordinates, cite the 7-layer numbers from the project page and say which model they belong to. Never mix the two numbering systems in one table without labeling.

---

## The ten risks

| AST | Risk | Severity | MAESTRO v2.0 layer homes | Nearest MAESTRO threat IDs |
|---|---|---|---|---|
| AST01 | Malicious Skills | Critical | L6, L3, L8, L5 | L6-T05 (marketplace trojans); L3-T03 (memory pollution via identity-file writes); L8-T01 |
| AST02 | Supply Chain Compromise | Critical | L1, L5, L6, L10 | L1-T01; L5-T02 (CI/CD); L6-T05 |
| AST03 | Over-Privileged Skills | High | L7, L6, L5 | L7-T03 (over-privileged identities); L6-T06 (API abuse/exfiltration) |
| AST04 | Insecure Metadata | High | L6, L5, L8 | L6-T08 (tool/skill definition poisoning); L5-T03 (runtime tampering via unsafe deserialization) |
| AST05 | Untrusted External Instructions | High | L3, L2, L6, L1 | CE-T1 / L3-T04 (context poisoning); L2-T03 (indirect prompt injection); L1-T01 (hijackable dependency) |
| AST06 | Weak Isolation | High | L5, L1, L6 | L5-T01 (container escape); L5-T04 (sandbox breakout) |
| AST07 | Update Drift | Medium | L5, L6, L10 | L5-T06 (rollback/version exploitation); L6-T05 |
| AST08 | Poor Scanning | Medium | L9, L8, L5 | L9 detection-coverage gaps; L8-T01 (guardrail/scanner bypass) |
| AST09 | No Governance | Medium | L10, L7, L9 | L10-T01 (shadow AI / rogue agents); L7 NHI lifecycle |
| AST10 | Cross-Platform Reuse | Medium | L6, L10, L5 | L6-T05; L10 (governance property loss across platforms) |

Per-threat blocks in Section 8 keep MAESTRO `L<n>-T<nn>` IDs primary; cite the `AST<nn>` ID parenthetically, exactly as with OWASP `T<n>` and `ASI<nn>` IDs.

---

## The lethal trifecta (triage trigger)

A skill surface is *especially* dangerous when the evidence shows all three simultaneously (Simon Willison / Palo Alto Networks, 2026):

1. **Access to private data** — SSH keys, API credentials, wallet files, browser data.
2. **Exposure to untrusted content** — skill instructions, memory files, email, fetched docs.
3. **External communication ability** — network egress, webhooks, shell `curl`.

If all three are evidenced, say so explicitly in Section 8 and treat the affected AST findings as elevated. If only one or two are evidenced, state which leg is missing — the missing leg is often the cheapest mitigation.

---

## Per-risk assessment checks

Distilled review checks per risk. Each check is an evidence question: a "no" or "unevidenced" answer is a finding or a gap, respectively — never assume a pass.

### AST01 — Malicious Skills (Critical)
**Named scenarios (whitepaper)**: typosquatting (distinct from slopsquatting — LLM-hallucinated package names), social-engineering "Prerequisites," instruction override, ClickFix prompts, SOUL.md persistence, memory poisoning, cognitive degradation / agent drift (QSAF six-stage chain — silent, appears only over repeated runtime invocations, evading one-time AST04/AST08 review), identity cloning & impersonation (exfiltrating SOUL.md/MEMORY.md reproduces the agent's effective behavioral identity — DIRF, arXiv:2508.01997), WebSocket C2, data exfiltration via cross-skill composition, hidden prompt injection in skill output.
**Runtime controls beyond install-time gates**: quarantine and validate skill-authored writes to MEMORY.md/SOUL.md/vector stores before commit; monitor cognitive-degradation signals (starvation, token pressure, planner loops) across invocations — a signed, reputation-clean skill can still poison memory post-install.
**Maps**: ASI04/ASI10/ASI03 · MCP03/04/05/10 · LLM03, LLM01 · AISVS C6.1.1, C9.3.7, C12.2.1.
- Skill obtained from a verified publisher (no typosquat of a known name)?
- Behavioral/semantic security analysis performed — not pattern matching alone?
- ed25519 signature verified; `content_hash` matches published manifest?
- Scripts **and** natural-language instructions reviewed (encoded payloads, curl to unknown endpoints, credential access beyond stated function)?
- Canary/dynamic test: observed behavior matches declared behavior?
- No write access to agent identity files (SOUL.md, MEMORY.md, AGENTS.md) without explicit justification?

### AST02 — Supply Chain Compromise (Critical)
**Named scenarios**: registry flooding, dependency confusion (poison the nested dep, surface skill stays clean), config-file hijacking (execution at project open), maintainer account takeover.
**Additional controls (whitepaper)**: transparency logs for all registry operations with inclusion/consistency proofs (registry membership lookup alone is NOT verification); revocation infrastructure at three grains — signing key, skill version by digest, entire publisher — consulted at load time.
**Maps**: ASI04/ASI05/ASI03 · MCP04/03/05 · LLM03 · CWE-494 · AISVS C6.1.2, C6.1.3, C6.2.2.
- Publisher identity anchored to a code-signing key / verified identity (did:web, verified org)?
- Skill pinned to immutable `sha256:` content hash — no version ranges?
- All nested/transitive dependencies pinned; recursive tree scanned?
- SBOM generated (CycloneDX / SPDX)?
- Repo config files (hooks, settings, env overrides) treated as executable code with trust gates — not auto-executed at project open?
- Installer emits a reviewable pre-mutation receipt (skills, config files, hooks, MCP servers, env/network access, approver, `writes_started=false`) before any write?

### AST03 — Over-Privileged Skills (High)
**Named scenarios**: weather-assistant .env exfiltration, database-admin wipe via injection, identity-file backdoors, **LPCI** (Logic-layer Prompt Control Injection, arXiv:2507.10457 — encoded/delayed/conditionally-triggered payloads in memory, vector stores, or tool outputs treated as operator-level instructions; empirically reproduced at scale by LAAF, arXiv:2603.17239, across the six-stage lifecycle Recon→Injection→Trigger→Persistence→Evasion→Trace Tamper), and confused-deputy: a low-privilege skill invokes a high-privilege skill that trusts its caller without re-verifying original intent/authorization.
**Core gap**: permission checks happen at the tool-call level; injection operates at the intent level — a SELECT-permitted skill coerced into DELETE.
**Additional controls**: strict instruction hierarchy (System > Operator > User > Skill/Tool output — never elevate tool output); bind authorization to the user-approved task and re-verify action/resource/destination against that grant per action; every skill in a delegation chain validates the ORIGINAL caller, not the immediate one; explicit operator consent for persistent state changes.
**Maps**: ASI03/ASI02/ASI05 · MCP02/07/01 · LLM09, LLM01 · CWE-250 · AISVS C5.2.1, C9.5.1, C9.2.1.
- Permission manifest present, explicit, and scoped?
- Permissions minimized to stated function; no `shell: true`; no `**/*` file globs?
- Per-skill scoped credentials (not shared agent-level keys), rotated?
- Identity-file write access flagged for elevated review?
- Network permissions as domain allowlists, default-deny — not binary `network: true`?
- No access to credential stores, `.env`, `~/.ssh/`, `~/.aws/`, wallets, or browser data beyond stated function?

### AST04 — Insecure Metadata (High)
**Named scenarios**: brand impersonation, permission understating (network: false while script curls out), risk-tier spoofing, YAML code execution (only via legacy UnsafeLoader / pre-5.1 FullLoader — modern PyYAML/js-yaml/Psych are safe by default; the risk is a loader opting into the unsafe API), staged loader (clean SKILL.md, payload fires at dependency-install), JSON prototype pollution (via unsafe recursive merge, not JSON.parse itself), TOML/config key-override injection.
**Maps**: ASI04/ASI09/ASI01 · MCP03/06/10 · LLM04 · ASVS V5.5, A08:2021 · CWE-345, CWE-502 · AISVS C2.1.2, C6.2.3, C9.3.3.
- Description accurately reflects actual functionality — no hidden capabilities?
- Scanned for ASCII smuggling, zero-width Unicode, base64 payloads in metadata and instructions?
- Secure defaults; dangerous capabilities require explicit opt-in; declared `risk_tier` consistent with permission scope (L0 + `shell: true` is a red flag)?
- Brand/trademark impersonation checked?
- Safe loaders only (`yaml.safe_load`; no `!!python/object` tags); parsing/validation in an isolated subprocess with dropped privileges; key allowlist enforced?
- Dependency files inside the package treated as untrusted code; schema validation before any deserialization?

### AST05 — Untrusted External Instructions (High)
**Named scenarios**: author rug-pull (benign at review, referenced doc edited post-approval — the audited skill is never the skill that runs), reviewer bait-and-switch (URL cloaks clean content to scanners/reviewers by IP/UA/timing, serves payload to live agents), transitive reference chaining, **relay-node amplification** — in chained skills each node's backbone model re-parses upstream output with its own instruction-vs-data boundary, so a chain's injection resistance is the MINIMUM over the models on its path and does not compose: certifying endpoints does not certify the chain. Also: hidden instructions in processed documents (white text, metadata, comments), resource-exhaustion DoS.
**Additional controls**: final hash verification immediately before model ingestion (missing reference or redirect = verification failure, logged); treat every rescan as a snapshot of mutable state; separate instructions from data — retrieved content is reference data, never able to override system/developer instructions.
**Maps**: ASI01/ASI06/ASI04 · MCP06/10/03 · LLM01, LLM03 · CWE-829 · AISVS C2.1.3, C2.1.6, C7.3.4, C9.3.5.
- Full inventory of runtime external references (URLs, remote docs) in SKILL.md and bundled files?
- Each reference pinned to a content hash and re-verified on load; unpinned/drifted content refused?
- References inlined into the signed package where possible; runtime fetch eliminated?
- Fetches restricted to a vetted domain allowlist; reference graph followed transitively?
- Fleet-wide visibility: which skills fetch from which sources (compromised source → affected-skill tracing)?

### AST06 — Weak Isolation (High)
**Named scenarios**: host escape (cron persistence beyond uninstall), network pivot to C2, skill shadowing (workspace > managed > bundled precedence + hot-reload lets a planted workspace skill shadow built-ins instantly), localhost attack surface (browser-origin WebSocket brute force), cross-agent workspace contamination (shared writable state consumed as trusted by another agent).
**Additional control**: separate writable state by agent/trust zone; where shared, preserve provenance and validate artifacts before consumption.
**Maps**: ASI03/ASI05/ASI08 · MCP05/02/07 · LLM08 · CWE-653 · AISVS C4.1.1, C4.3.3, C9.3.1.
- Container/sandbox execution (host-mode = explicit opt-in only)?
- Filesystem access limited to declared paths; verified dynamically?
- Control interfaces localhost-bound **with auth** — not 0.0.0.0; WebSocket channels rate-limited and authenticated even from localhost?
- seccomp/AppArmor profiles applied; per-skill namespacing (no shared memory/filesystem between skills)?
- Hot-reload / workspace-precedence overrides restricted in production?

### AST07 — Update Drift (Medium)
**Named scenarios**: malicious update via compromised author account (silent v2.0 payload to auto-updaters), rollback attack (forced downgrade to known-vulnerable version via dependency-resolution manipulation), hot-reload abuse (SKILL.md modified mid-session, picked up without restart).
**Maps**: ASI04/ASI10/ASI08 · MCP03/04/08 · LLM03 · CWE-1329 · AISVS C3.1.2, C3.1.3, C3.2.3, C6.1.3.
- Immutable hash pinning (not mutable tags); auto-update disabled or gated behind re-approval?
- Updates signed by the original publisher; unsigned rejected?
- Automatic re-scan on every version change; hot-reload disabled outside development?
- Active CVE/advisory subscription for installed skills?

### AST08 — Poor Scanning (Medium)
**Named scenarios**: natural-language bypass (intent in prose, zero code signature), obfuscated instruction (base64/zero-width/ASCII smuggling — detection requires canonicalize-then-re-match, since a keyword split by a zero-width char defeats byte-level rules), scanner impersonation, context-dependent malice (activates only under runtime conditions), **model-dependent injection resistance** — a skill approved under an injection-resistant backbone model becomes exploitable unmodified under a weaker one; injection resistance is a behavioral property of the runtime model, not of the skill's bytes — scanner-target evasion (payload padding forcing truncation, logic in .pyc/.docx the scanner won't open, prompt-injecting the scanner's own LLM judge; open-source scanners can be iterated against offline until they pass), scanner host compromise (decompression bombs, parser exploits — limit failures must yield INCOMPLETE, never a clean verdict), bytecode cache poisoning (runtime loads a poisoned .pyc while reviewers inspect source).
**Additional controls (whitepaper)**: shell-aware parsing (resolve expansions statically — `c''url`, `curl${IFS}`, `V=curl; $V` defeat literal-verb rules); per-tier analysis with explicit machine-readable coverage records and PASS/FAIL/INCOMPLETE outcomes; direction-typed suppression allowlists (fetch-source reputation must never suppress egress-destination findings — the same providers host anonymously writable dead-drops); evaluate scanners against an ADAPTIVE adversary with scanner access, reporting bypass rate alongside detection rate; report false-positive rates per rule against a benign corpus; treat the backbone model per execution node as a re-evaluable security dependency.
**Maps**: ASI04/ASI08/ASI10 · MCP03/04/08 · LLM02 · CWE-693 · AISVS C11.1.3, C11.4.1, C12.2.1, C12.2.3.
- Behavioral/semantic analysis performed; code layer and natural-language instruction layer scanned **independently**?
- Credential detection run (Gitleaks/TruffleHog class)?
- Scanning performed in an isolated environment the skill cannot detect or influence?
- Dynamic behavioral test log: file access, network, shell match declared scope?
- No single-scanner reliance — especially not a scanner that is itself a skill (false-trust signal, and scanners themselves are bypassable: payload padding, logic in binaries/archives, prompt-injecting the scanner's LLM judge)?

### AST09 — No Governance (Medium)
**Named scenarios**: undetected compromise (no inventory, no alert), unapproved malicious skill, orphaned skill (departed employee's credentials still active), regulatory exposure (PII/PHI through unreviewed skill, no audit trail), **unreachable skill** — deployed inside a managed SaaS copilot the security team doesn't administer: no host to scan, no manifest to read, invisible by architecture, so every downstream governance control silently skips it — cascading agent compromise, manipulated trust signals (farmed stars/install counts steering autonomous skill selection).
**Additional controls**: identity-first discovery for unscannable skills (enumerate from OAuth grants, connected-app inventories, NHI activity — reconcile against approved inventory); scope/consent drift as a continuing discovery signal; **bilateral receipt audit pattern** — every execution emits a signed admission receipt (attempt_id, agent_id, action, scope, policy_version bound at decision time, ALLOW/DENY/ESCALATE) before execution and a signed outcome receipt (same attempt_id, COMMITTED/FAILED) after; DENY-before-dispatch carries equal audit weight; independently verifiable receipts support (not establish) EU AI Act Article 12 logging obligations; per-node backbone-model assignment recorded in inventory so a model swap at a relay node is a governed change.
**Maps**: ASI08/ASI09/ASI10 · MCP08/09/07 · LLM09 · NIST AI RMF GOVERN · AISVS C9.2.10, C9.4.2, C12.4.2.
- Centralized skill inventory entry: name, version, hash, install date, installer identity, scan status?
- Risk-tier (L0–L3) assigned and consistent with permission scope; approval record exists?
- Invocation logging sufficient for audit: skill ID, user context, tools called, files accessed, network, outputs?
- Review cadence defined; revocation/deprovisioning tied to identity lifecycle and IR playbooks?
- Agent identities managed as NHIs with scoped, rotated credentials?

### AST10 — Cross-Platform Reuse (Medium)
**Named scenarios**: security property loss in translation (risk_tier: L3 silently dropped by a platform without the field), cross-registry arbitrage (publish on lightly-scanned registry, promote install count as false trust signal on a stricter one), multi-platform campaign (same payload on four platforms, four unaware security teams), manifest stripping, implicit privilege escalation (tightly-scoped source skill inherits broad defaults on target platform), silent supply-chain injection via encoded blocks in shared repos.
**USF semantics (whitepaper)**: evaluation is default-deny (network.allow is the grant; deny: "*" is auditability, not an override); deny_write beats write for any listed path; **risk_tier is an untrusted author assertion** — governance policy must be driven by permission-derived risk classification, with declared risk_tier used only to detect under-declaration. OWASP ships a browser-only metadata-loss simulator for source-vs-ported manifest diffing.
**Maps**: ASI04 alignment via porting · AISVS C3.2.3 · project's metadata-loss tooling.
- Independent validation per target platform — equivalence never assumed?
- Security properties (permissions, risk_tier, signature) survive porting; no silent property loss?
- Per-platform gap analysis (sandbox model, permission enforcement, defaults); credential handling verified per platform?
- Cross-registry threat-intel sharing; platform-agnostic manifest (Universal Skill Format) used?

---

## Evidence artifacts for this lens

When AST findings are `Unanswerable from current evidence`, the "Required Evidence to Fully Answer" field should request from this list (the Universal Skill Format v1.0 manifest is the single richest artifact — it carries most of these fields):

- Skill manifest(s) with permission declarations, `risk_tier`, `signature`, `content_hash`
- Registry/publisher provenance (identity anchor, signing key)
- SBOM and dependency lockfiles
- Scan reports: static, credential, behavioral/dynamic — with scanner identity and date
- Installer pre-mutation receipt
- Skill inventory record + approval record
- Runtime isolation config (container spec, seccomp/AppArmor profile, egress allowlist)
- Invocation/audit logs

---

## Incident evidence base (for likelihood justification)

Confirmed 2026 incidents usable to justify Likelihood ratings — cite the source, not just the number:

- **ClawHavoc** (Antiy CERT): 1,184 malicious skills across 12 publisher accounts; 5 of top 7 most-downloaded ClawHub skills confirmed malware at peak; targeted `.env`, exchange API keys, wallets, SSH creds, browser passwords; wrote persistence instructions into MEMORY.md/SOUL.md. → AST01, AST03
- **Snyk ToxicSkills**: 3,984 skills scanned; 36.8% flawed; 13.4% critical; 76 confirmed payloads; 280+ skills leaking keys/PII beyond declared function. → AST01, AST03, AST08
- **Claude Code CVE-2025-59536** (CVSS 8.7, Check Point): repo config files execute before trust dialog at project open. → AST02
- **ClawJacked** (Oasis): browser-origin brute force against localhost agent WebSocket. **CVE discrepancy in OWASP's own material**: the project index page cites CVE-2026-28363 (CVSS 9.9); the V1 whitepaper cites CVE-2026-32025 (CVSS 7.5) for the gateway origin-check/auth-throttling bypass. Possibly two distinct CVEs — verify against NVD before citing either in a deliverable. → AST06
- **USENIX Security 2026 measurement study** (arXiv:2602.06547): 98,380 skills analyzed; 157 confirmed malicious carrying 632 vulnerabilities (avg 4.03/skill); 73.2% of malicious skills implemented shadow features hidden from the user; 54.1% traced to a single publisher cluster. → AST01, AST04
- **Adversa AI** (Jul 2026): all eight open-source skill scanners tested bypassed via simple obfuscation (non-standard SKILL.md encoding). → AST08
- **SecurityScorecard / Bitdefender**: 135,000+ instances internet-exposed; 53,000+ with no SOC visibility; 12,812 exploitable in patch-lag window. → AST06, AST07, AST09
- **Air Security "Story of Skills"**: researcher skill reached 26,000+ agents, every scanner cleared it, payload served from attacker-controlled external doc URL; follow-up scan: 12.4% of 142,836 live skills (6.7M installs) rest on ≥1 untrusted external instruction source. → AST05, AST08
- **Air Security "SkillJacking"**: 925 skills (~134K agents) on instantly hijackable dependencies (deleted accounts, expired domains); top skills.sh video-gen skill taken over via re-registered deleted owner account. → AST02, AST05
- **Trail of Bits**: every public skill scanner tested bypassed in under an hour. → AST08

These are incident-frequency justifications for *Likelihood* only. *Impact* still requires system-specific evidence.

---

## Suspected-malicious-skill triage and IR (from repo ast01.md)

When an assessment surfaces a suspected malicious skill, the analysis sequence is: **static** (SKILL.md instructions, obfuscation, YAML anomalies, signature vs known publisher keys) → **dynamic** (isolated sandbox; observe filesystem, network, process activity; check SOUL.md/MEMORY.md persistence writes) → **behavioral indicators** (unusual egress, exfiltration attempts, shell execution beyond stated function, identity-file modification). Common detection signatures: base64 payloads in YAML comments, non-HTTPS download instructions, excessive permission requests (identity-file writes), typosquats of popular services, social-engineering prompts ("run this command to enable...").

Confirmed-incident response checklist: isolate affected agents → revoke compromised credentials → scan for lateral movement → notify the skill registry → update detection signatures → review installation-approval process. Feed this into Section 12 (Required Validation Steps) when an AST01 finding is Answerable.

## Mitigation sourcing (Step 4)

Key mitigations per the source project, expressed as controls:

- **AST01/AST02**: ed25519 signing + `content_hash`, Merkle-root registry transparency, publish-time and install-time behavioral scanning, trust gates on repo-controlled config.
- **AST03/AST04**: least-privilege manifests (explicit paths, domain allowlists, `shell: false`, `deny_write` on identity files by default), schema validation before deserialization, safe loaders, sandboxed parsing with privilege drop.
- **AST05**: source inventory, content pinning + re-verification on load, inlining over fetching, egress allowlists, continuous rescanning, transitive-reference review.
- **AST06**: container-default execution, declared-path filesystem scoping, authenticated + rate-limited localhost control channels, seccomp/AppArmor, per-skill namespacing.
- **AST07**: immutable pinning, gated updates with signature verification and auto re-scan, hot-reload off in production, advisory subscriptions.
- **AST08**: multi-tool pipeline — static (Semgrep/Bandit) + secrets (Gitleaks/TruffleHog) + behavioral/dynamic (Caterpillar, SkillSpector) + runtime proxy (Pipelock-class DLP/injection detection); no single gate; scanner outputs advisory when the scanner is itself a skill.
- **AST09**: inventory + approval workflow + audit logging + risk-tiered review cadence + NHI lifecycle management + IR playbook coverage.
- **AST10**: Universal Skill Format / platform-agnostic manifest, per-platform validation, cross-registry intel sharing.

SSRM assignment note: the skill registry/marketplace operator behaves as a **Tool Provider**-adjacent actor in the 3SRM; the installing organization is AIC with non-delegable accountability for what its agents load. Where the deployment model leaves registry-side controls (scanning, transparency logs) outside AIC reach, assign Primary to the provider and mark the AIC-side compensating control (pre-install scanning, pinning) explicitly.

---

## Pipeline trust-boundary quick screen (B1–B4)

A four-boundary triage for skill-consuming CI/CD and dev pipelines. Use during Step 1 decomposition when the evidenced system spans development → build → deploy:

- **B1 (developer/agent session)**: agent permissions declared and minimal before session start; installers emit pre-mutation receipts before writing settings/hooks/MCP config/instruction files; developer context (MEMORY.md, issue content) sanitized before ingestion.
- **B2 (code generation)**: AI-generated dependency names validated against live registries (slopsquatting); AI-generated code passes SAST before commit.
- **B3 (build)**: AI-generated IaC/CI scripts scanned before pipeline ingestion; all dependencies hash-pinned.
- **B4 (production)**: AI-driven deployments sandboxed (not host-mode); audit logging on all agent-initiated production actions.
