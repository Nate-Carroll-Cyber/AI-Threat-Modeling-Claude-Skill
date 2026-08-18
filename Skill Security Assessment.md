# Skill Security Assessment — `ai-threat-models` vs. OWASP AST10 Checklist

| | |
|---|---|
| **Skill under review** | `ai-threat-models` (MAESTRO v2.0 AI Threat Model Analyst), v3 package |
| **Package** | `ai-threat-models-v3-ast-mcp.zip` — sha256 `491076b25d465885eb761d08b7d3f730ff4803213bd66123b84ba8611dd2947e` |
| **Contents** | SKILL.md + README.md + 7 reference files; **9 markdown files, 0 scripts, 0 dependencies, 0 executable content** (verified by file-type inventory) |
| **Checklist** | OWASP Agentic Skills Top 10 — Skill Security Assessment Checklist (CC-BY-SA-4.0) |
| **Review date** | 2026-08-18 |
| **Reviewer** | Claude (LLM semantic review + deterministic scans + SkillSpector v2.9.5 static scan). **Reviewer caveat**: the reviewer is an LLM in the same session that authored recent portions of the reviewed content — this is a self-review with instrumented scans, not an independent third-party assessment. Per the checklist's own 8.6 principle, treat it as advisory. |

## Scans performed (ground truth)

1. **File inventory + SHA-256 hashes** — all 9 files hashed (Appendix A); package hash recorded above.
2. **Unicode smuggling scan** — zero-width chars (U+200B–D, U+2060, U+FEFF) and bidi controls (U+202A–E, U+2066–69): **clean**.
3. **Base64 payload scan** — decodable printable blobs ≥40 chars: **none**.
4. **Secret-pattern scan** — AWS keys, GitHub PATs, private keys, hardcoded credentials (regex class; NOT Gitleaks/TruffleHog): **clean**.
5. **Model-directed-imperative scan** — "ignore previous instructions" / "do not tell the user" patterns as live instructions: **none** (such phrases exist only inside quoted attack descriptions).
6. **YAML frontmatter** — parses under `yaml.safe_load`; keys = `{name, description}` only; no unsafe tags.
7. **SkillSpector v2.9.5** (NVIDIA, agent-skill-aware) — static-only (`--no-llm`; semantic analyzers unavailable without external LLM key). Result: **72/100, HIGH, "DO NOT INSTALL," 12 issues, 100% coverage.** All 12 triaged below as false positives.

## SkillSpector finding triage

| # | Finding | Location | Conf. | Triage |
|---|---|---|---|---|
| 1–2 | AR3 Anti-Refusal | maestro-layers.md:65, :272 | 27% | **FP** — L2-T03 threat-catalog entry ("prompt injection / jailbreak") and T18 policy-bypass threat description. Naming a jailbreak threat ≠ issuing one. |
| 3 | EA2 Autonomous Decision | SKILL.md:166 | 80% | **FP** — "Extract what's evidenced into the layer mapping silently" is an output-formatting instruction (don't make the user fill a worksheet) in a read-only analysis skill. No destructive operation exists to gate. Optional hardening: reword "silently" to "without prompting the user for a worksheet" to avoid the trigger. |
| 4–6 | MP3 Memory Manipulation | agentic-skills-top10.md:78, framework-crosswalk.md:71, threat-library.md:70 | 27% | **FP** — a *defensive control* (quarantine skill-authored memory writes), an ATLAS mapping row ("Poison Training Data"), and a technique-taxonomy row. All describe or defend against memory attacks. |
| 7 | PE3 Credential Access | agentic-skills-top10.md:99 | 18% | **FP** — AST03 scenario naming (".env exfiltration"). This is precisely the class the AST10 whitepaper says to demote to informational: credential-path references in documentation. |
| 8–10 | P1 Instruction Override | agentic-skills-top10.md:122, maestro-layers.md:65, mcp-top10.md:76 | 27% | **FP** — a hash-verification control, the L2-T03 entry again, and an MCP06 checklist item that *mandates* treating content as unable to override instructions. Finding #10 flags the exact sentence that implements the mitigation. |
| 11–12 | YR4 YARA exploit-framework / hidden-instructions | agentic-skills-top10.md:77, maestro-layers.md:3 | 80% | **FP** — scenario-name list (typosquatting, ClickFix, memory poisoning) and the threat-catalog header line. YARA keyword hits on a threat taxonomy. |

**True positives: 0.** The scan empirically validates the skill's own AST08 content: pattern matching on a security-documentation skill, with the LLM semantic layer disabled, convicts the documentation of the attacks it documents. Retained as advisory input per 8.6, not as a gate.

## Status legend

- **Yes** — satisfied, evidence cited. **No** — genuine gap. **N/A** — structurally inapplicable (e.g., zero dependencies). **Platform** — not controllable at the skill layer; owned by the Claude skill runtime (Anthropic). **Owner** — organizational process; unanswerable from package evidence, requires owner attestation.

## Summary

| AST | Yes | No | N/A | Platform | Owner |
|---|---|---|---|---|---|
| AST01 (6) | 4 | 1 | 0 | 1 | 0 |
| AST02 (7) | 0 | 3 | 3 | 1 | 0 |
| AST03 (8) | 4 | 2 | 2 | 0 | 0 |
| AST04 (12) | 5 | 2 | 2 | 3 | 0 |
| AST05 (6) | 3 | 2 | 0 | 0 | 1 |
| AST06 (7) | 0 | 0 | 1 | 6 | 0 |
| AST07 (6) | 2 | 3 | 1 | 0 | 0 |
| AST08 (7) | 5 | 1 | 0 | 0 | 1 |
| AST09 (7) | 1 | 1 | 0 | 0 | 5 |
| AST10 (6) | 1 | 1 | 4 | 0 | 0 |
| **Total (62)** | **25** | **16** | **13** | **11** | **7** |

Top remediations (ordered by value): §Remediation, end of document.

---

## AST01 — Malicious Skills (Critical)

**1.1 Verified, trusted source — Yes.** First-party: authored and packaged by the owner (Nate-Carroll-Cyber); no registry, no third-party publisher, no typosquat surface. Provenance is by construction, not by verification infrastructure — see 2.1 for the signing gap that would matter on any distribution.

**1.2 Behavioral analysis beyond pattern matching — Yes (with caveat).** This review is an LLM semantic analysis of intent across both layers, plus SkillSpector static. Caveat: semantic reviewer = session LLM (self-review); SkillSpector's own LLM analyzers did not run. An independent semantic scan on the owner's machine (SkillSpector with an LLM key) would close the independence gap.

**1.3 Cryptographic signature verification — No.** No signing exists. The Claude skill ecosystem has no signature or manifest-hash field. Compensating control applied in this review: SHA-256 recorded per file and per package (Appendix A) — a pin, not a signature.

**1.4 Scripts and NL instructions reviewed for malicious patterns — Yes.** Zero scripts (verified). NL layer: smuggling, base64, secret, and imperative scans clean; full-content manual review performed during construction. No curl instructions, no credential access, no encoded payloads.

**1.5 Isolated canary before production — No.** No formal declared-vs-observed dynamic test report exists for v3. Prior real-use assessments (SEC545 MCP lab) are operational evidence, not a canary protocol. Remediation: one skill-creator eval run against v3 with asserted outputs.

**1.6 Avoids writing to identity files — Yes.** Markdown-only; no write capability; instructions direct analysis output only. No SOUL.md/MEMORY.md/AGENTS.md references as write targets.

## AST02 — Supply Chain Compromise (Critical)

**2.1 Publisher identity vs code-signing key — No.** No signing key, no did:web, no verified-org binding. If the skill is ever published (GitHub repo), the verified GitHub org/account becomes the identity anchor; a detached signature (minisign/ssh-keygen -Y) over the package hash is the cheap upgrade.

**2.2 Pinned to immutable content hash — No → remediated in this review.** Hash now recorded (Appendix A + package hash above). No registry record exists to match against; the hash in this report is the record.

**2.3 Nested dependencies pinned — N/A.** Zero dependencies. No requirements.txt/package.json exists (verified: 0 non-markdown files).

**2.4 SBOM generated — No.** Formally absent. For a zero-dependency, 9-file markdown package an SBOM is near-trivial (9 components, no dependency edges) — low value, low cost. CycloneDX doc-component SBOM can be generated in minutes if audit posture requires it.

**2.5 Repo config files as executable code with trust gates — N/A (package) / Platform (consumption).** The package contains no hooks, settings files, or env overrides. Whether the consuming environment executes repo config at open is the runtime's property (the CVE-2025-59536 class), outside this skill's control.

**2.6 Recursive dependency tree scanned — N/A.** No tree.

**2.7 Pre-mutation receipt from installer — Platform.** Installation is manual zip upload through the Claude interface; no installer exists at the skill layer to emit a receipt. The claude.ai skill-upload flow does not currently emit one.

## AST03 — Over-Privileged Skills (High)

**3.1 Permission manifest with explicit scoped permissions — No (platform format gap).** The Claude skill format carries `name` + `description` frontmatter only; no permission-manifest field exists. Compensating: Appendix B provides a Universal Skill Format manifest declaring the skill's actual needs (`shell: false`, no file writes, citation-only network use), portable and diff-able even though the runtime does not enforce it.

**3.2 Permissions minimized to stated function — Yes (behaviorally).** The instructions request: reading the skill's own bundled files, and web search for citation/verification when available. Nothing else — no shell, no file writes, no credential access, no tool invocation beyond search.

**3.3 Avoids unrestricted shell — Yes.** No shell use requested anywhere; no scripts to run.

**3.4 File permissions scoped, no wildcards — N/A.** No file access declared or needed beyond the bundle itself.

**3.5 Per-skill scoped credentials — N/A.** No credentials used, stored, or requested.

**3.6 Identity-file write access flagged — Yes.** None requested (see 1.6); nothing to flag.

**3.7 Network as domain allowlist — No.** SKILL.md rule 6 directs the executing agent to use web access for citation without any domain scoping. Genuine gap, low severity (lookups are citation/verification, and the trust direction is inverted — the agent verifies against these sources rather than obeying them). Remediation: add an advisory citation-domain allowlist to SKILL.md (owasp.org, cloudsecurityalliance.org, arxiv.org, nvd.nist.gov, github.com/OWASP, atlas.mitre.org) — advisory because the runtime doesn't enforce it, but it pins reviewer expectations and feeds 5.4.

**3.8 Avoids credential stores/.env/wallets/SSH — Yes.** No such access; the strings `~/.ssh`, `.env`, etc. appear only as detection indicators inside threat documentation (SkillSpector finding #7, triaged FP).

## AST04 — Insecure Metadata (High)

**4.1 Description accurate and complete — Yes.** The frontmatter description enumerates triggers and output (MAESTRO assessment, SSRM ownership, unanswerable-marking) and matches observed behavior. The AST/MCP lens additions are reflected in the current description.

**4.2 Scanned for smuggling/zero-width/base64 — Yes.** Clean (scans 2–3 above).

**4.3 Secure metadata defaults — Platform.** No capability fields exist to default open or closed. The USF manifest in Appendix B declares dangerous capabilities explicitly off.

**4.4 Metadata validated against security schema — Yes (minimal).** Frontmatter safe-parses; key set = exactly the two fields the Claude skill schema expects; no unexpected fields. No formal JSON-Schema pipeline exists (that is the runtime's loader; see 4.11).

**4.5 risk_tier consistent with permission scope — No (field absent) → declared in this review.** No risk_tier exists in the format. Assessed tier: **L1 (low)** — advisory/documentation skill, zero execution capability, network use limited to citation lookups. Declared in Appendix B; consistent with the (empty) permission scope.

**4.6 Brand impersonation checked — Yes.** Name `ai-threat-models` impersonates nothing. OWASP, CSA, MITRE, NVIDIA marks appear nominatively with attribution and license notes (CC-BY-SA content adapted; BY-NC-SA content paraphrased own-words with the NC term flagged in-file).

**4.7 Safe YAML loaders — Yes** for the artifact (verified safe_load-parseable, no unsafe tags). Loader choice itself is Platform.

**4.8 Config parsed in isolated subprocess — Platform.** Anthropic's loader; not skill-controllable.

**4.9 Key allowlist enforced — Yes (de facto)** — key set matches expected schema exactly; enforcement mechanism is Platform.

**4.10 Dependency files treated as untrusted — N/A.** None exist.

**4.11 Schema validation before deserialization — Platform.** Runtime loader pipeline.

**4.12 Deserialization at minimum privilege — Platform.** Same.

## AST05 — Untrusted External Instructions (High)

**5.1 External references inventoried — Yes.** Full inventory: (a) SKILL.md rule 6 — directs web citation with direct URLs, unscoped; (b) `agentic-skills-top10.md` — pointer to GitHub `ast01.md` for platform-specific guidance, and to NVD for the ClawJacked CVE discrepancy; (c) `threat-technique-and-control-library.md` — pointer to the authoritative AICM catalog for control-ID verification; (d) source-attribution URLs in the AST/MCP files (2 raw URL instances). **None is a load-time instruction fetch**: the skill never directs the agent to retrieve external content and follow it as instructions.

**5.2 Referenced content hash-pinned, re-verified on load — No.** The advisory pointers (ast01.md, NVD, AICM catalog) are unpinned. Mitigating: the trust direction is inverted — each pointer tells the agent to *verify claims against* the source, not to *obey* it; a poisoned source degrades citation accuracy, not agent behavior. Residual risk accepted with that rationale, or pin the ast01.md pointer to the commit hash of the revision reviewed here.

**5.3 Referenced documentation inlined where possible — Yes.** This is the package's design: AST10 and MCP Top 10 content was inlined (own-words) into the reference files precisely so the agent does not fetch OWASP pages at assessment time. The remaining pointers are for content that must stay current (NVD, catalog) — the legitimate exception the checklist allows.

**5.4 Runtime fetches domain-allowlisted — No.** Same gap as 3.7; same remediation (advisory citation-domain allowlist).

**5.5 References followed transitively — Yes (at review time).** The reference graph was walked during construction: OWASP index → whitepaper → GitHub source files → cited research (arXiv, vendor reports). No ongoing re-walk is scheduled — feeds the 9.5 cadence item.

**5.6 Fleet-wide source visibility — Owner.** Whether the owner's environment tracks which installed skills reference which external sources is an organizational property. Single-skill contribution: the 5.1 inventory above is the skill's entry in such a register.

## AST06 — Weak Isolation (High)

All seven checks concern the execution environment, which for a claude.ai skill is Anthropic's sandbox — not configurable at the skill layer.

**6.1 Container/sandbox — Platform** (Anthropic-managed isolation; skill cannot opt into host-mode). **6.2 Filesystem scoping — Platform.** **6.3 Network binding/auth — Platform.** **6.4 seccomp/AppArmor — Platform.** **6.5 Per-skill namespacing — Platform.** **6.6 WebSocket auth/rate-limits — Platform.** **6.7 Hot-reload / workspace precedence — N/A** at claude.ai (skills load per-conversation from the uploaded package; no watcher, no workspace shadowing mechanism analogous to OpenClaw's three-tier precedence). If this skill is ported to Claude Code or another runtime, 6.1–6.7 must be re-answered per that runtime (see 10.3).

The skill's only contribution to isolation posture: it requests no capability that isolation would need to contain (see AST03).

## AST07 — Update Drift (Medium)

**7.1 Pinned to immutable hash — Yes (as of this review).** v3 package and per-file hashes recorded (Appendix A). Prior versions (v2 AST-only, v1) were not hash-recorded at packaging time — history before this report is reconstructable only from chat artifacts.

**7.2 Auto-update disabled/gated — Yes (by construction).** No auto-update mechanism exists; every update is a manual re-upload by the owner. Human approval is inherent.

**7.3 Updates cryptographically signed — No.** Same gap as 1.3/2.1.

**7.4 Automatic re-scan on updates — No.** No pipeline. This review is the first scan; nothing triggers the next one. Remediation: a 5-line script (hash + SkillSpector + the deterministic scans above) run at each packaging.

**7.5 Hot-reload disabled in production — N/A.** No hot-reload mechanism exists in this deployment model.

**7.6 Security-advisory subscription — No.** For a self-authored documentation skill the analog is upstream-source watch: AST10 v1 final (Q3/Q4 2026), MCP Top 10 next release (Oct 2026), AICM/3SRM revisions, AIVSS v1 (severity ratings land). None is subscribed. Remediation: calendar the two dated releases; they will both invalidate caveats currently hard-coded in the reference files.

## AST08 — Poor Scanning (Medium)

**8.1 Behavioral/semantic analysis performed — Yes** (LLM semantic review, this session), with the 1.2 independence caveat. SkillSpector's semantic layer did not run.

**8.2 Code layer and NL layer scanned independently — Yes.** Code layer: trivially empty, verified by inventory (0 executable files — SkillSpector concurs: "Executable scripts: No"). NL layer: scans 2–5 plus semantic review.

**8.3 Credential detection — Yes (regex class).** Clean. Labeled honestly: pattern-equivalent scan, not Gitleaks/TruffleHog binaries. Running Gitleaks on the repo history (not just the package) remains worthwhile on the owner's machine.

**8.4 Scanning isolated from skill interference — Partial.** The skill is inert markdown and cannot detect or influence scanning. However, the *semantic reviewer* is an LLM reading the content it evaluates — the exact injectable-scanner surface the skill's own AST08 section documents. The deterministic scans (2–6) are immune; the semantic judgment is not. Recorded as the review's chief methodological limit.

**8.5 Dynamic behavioral testing in sandboxed runtime — No.** Same as 1.5: no formal declared-vs-observed run for v3.

**8.6 Skill-based scanner results advisory only — Yes, demonstrated.** SkillSpector's 72/100 "DO NOT INSTALL" verdict — 12 findings, 0 true positives on triage — was treated as advisory input, triaged line-by-line, and retained in this report. Gating on it would have blocked a clean package; ignoring it would have skipped the one 80%-confidence wording improvement it surfaced (SKILL.md:166 "silently").

**8.7 Agent-skill-aware scanner pre-install — Yes.** SkillSpector v2.9.5, static profile, 100% coverage, report reproduced above. Risk score above threshold *before triage*; all critical/high findings triaged and resolved as FPs. Coverage limitation recorded: 4 analyzers disabled (LLM-dependent) — per the skill's own coverage-record principle, this scan is PASS-with-declared-limits, not unqualified PASS.

## AST09 — No Governance (Medium)

**9.1 Centralized skill inventory entry — Owner.** No formal inventory evidenced. The row it needs: name `ai-threat-models` · version v3 (AST+MCP) · hash `491076b2…2947e` · packaged 2026-08-18 · installer: owner · last scan: SkillSpector v2.9.5 static, 2026-08-18, 0 TPs post-triage.

**9.2 Risk tier assigned — Yes (as of this review).** **L1 (low)**: advisory/documentation, zero execution capability, unscoped-but-outbound-only citation lookups. Consistent with permission scope (none). Declared in Appendix B.

**9.3 Approval record — Owner.** Self-authored/self-approved is the de facto state; no dated record exists. This report can serve as the v3 approval artifact if countersigned by the owner.

**9.4 Invocation logging — Owner/Platform.** claude.ai conversation history is the de facto invocation log (skill, context, outputs); it is not an audit-grade, query-able log per the skill's own rule 4 distinction.

**9.5 Review cadence — Owner.** None defined. Recommended: re-review on any of — AST10 v1 final, MCP Top 10 Oct 2026 release, AIVSS v1, AICM version change — or 6 months, whichever first. Matches a Medium-tier cadence.

**9.6 Revocation/deprovisioning process — Owner.** Single-owner deployment; removal = delete from claude.ai. No IR-playbook linkage exists or is proportionate at this scale; becomes real if the skill is distributed.

**9.7 Agent NHI with scoped rotated credentials — Owner/Platform.** The executing agent identity is the owner's Claude account; no skill-level NHI exists in this deployment model.

## AST10 — Cross-Platform Reuse (Medium)

**10.1 Independently validated per platform — N/A (single platform).** Deployed on claude.ai only. Becomes mandatory if ported to Claude Code (where `.claude/settings.json`-class surfaces exist — see 2.5).

**10.2 Security properties consistent across platform versions — N/A.** One platform version exists.

**10.3 Platform-specific gap assessment per target — N/A now; pre-work done.** The AST06 answers above already document which controls are platform-owned at claude.ai; a Claude Code port would re-open all of AST06 plus 2.5.

**10.4 Credential handling consistent across platforms — N/A.** No credentials.

**10.5 Cross-registry threat intel — N/A.** Not published to any registry.

**10.6 Universal Skill Format manifest — No → remediated in this review.** Appendix B provides the USF v1.0 manifest. Unsigned (`signature` field left as the recorded gap per 1.3), but permissions, deny_write, network posture, risk_tier, and scan_status are declared and portable.

## Pipeline Trust Boundary Review (B1–B4)

**B1 permissions declared/minimal pre-session** — Partial: no manifest format (3.1); behavioral needs are minimal and now declared in Appendix B. **B1 installer pre-mutation receipt** — Platform (2.7). **B1 developer context sanitized** — N/A: the skill ingests user-supplied architecture evidence by design; its evidence-gating rules (three-bucket separation, no speculation) are the sanitization-equivalent at the analysis layer. **B2 AI-generated dependency validation / B2 SAST pre-commit / B3 IaC-CI scanning / B3 hash pinning** — N/A: the skill generates assessments, not code, dependencies, or IaC; nothing it produces enters a build pipeline. **B4 sandboxed deployment** — Platform (AST06). **B4 audit logging of agent-initiated production actions** — N/A: the skill initiates no production actions.

## Remediation (ordered)

1. **Advisory citation-domain allowlist in SKILL.md** — closes 3.7 + 5.4, five minutes. (owasp.org, cloudsecurityalliance.org, arxiv.org, nvd.nist.gov, github.com/OWASP, atlas.mitre.org.)
2. **Adopt Appendix B USF manifest into the package** — closes 10.6; declares 3.1/4.3/4.5 as far as the format allows.
3. **Detached signature over the package hash** (minisign or `ssh-keygen -Y sign`) published alongside any distribution — closes 1.3/2.1/7.3 to the extent possible without registry infrastructure.
4. **Re-scan script at packaging** (hash + SkillSpector + deterministic scans) — closes 7.4; makes 7.1 continuous instead of point-in-time.
5. **One skill-creator eval run against v3** with asserted outputs — closes 1.5/8.5.
6. **Calendar the two dated upstream releases** (MCP Top 10 Oct 2026; AST10 v1 final Q3/Q4 2026) — closes 7.6; both invalidate hard-coded caveats when they land.
7. **Optional wording change** — SKILL.md:166 "silently" → "without prompting the user for a worksheet"; removes the one high-confidence scanner trigger with no semantic loss.
8. **Owner attestations** for the seven AST09/5.6 items — or adopt the 9.1 inventory row and this report as the 9.3 approval record.

## Appendix A — File hashes (SHA-256, v3 package)

```
ad63e8917b2881db5ff5c7708e1c731e94de7624b7b7f571b244a87ea67e0315  README.md
657ce6b6b1fe4161250e47a0d147f9fafe7715b4b9080b22a82e2c76138d7c57  SKILL.md
f1b172b350dfbd815f2166f620c5b57f67159460e7d978a65699b03f63c62fce  references/agentic-skills-top10.md
00661d2e811d23d10c87d7bc63a974d254db1d72ae55a18847575a65289cf007  references/ai-control-trait-r.md
f8a00f957fddf57d49fde0a6aee6b2ecff6b067178aa4d8ea4f7338590aa5578  references/framework-crosswalk.md
e872a905c3f12de88193d04e5fa8953e921c80173b18dcc76169f174946cb762  references/maestro-layers.md
c80bb07e5ac4d8855b58113fc0f566356ae1c6be3ec67e4350818157f1feb9e1  references/mcp-top10.md
2c1d32b7b91eb90e05f26d3c696a1cd6bf3d8d5bbfb4222dbf74feba2d7e5d26  references/ssrm-ownership.md
bd82b5bfab5432f8e75ce533991fe65e3740906378621f42a0386ab08c9bc2c8  references/threat-technique-and-control-library.md

package: 491076b25d465885eb761d08b7d3f730ff4803213bd66123b84ba8611dd2947e  ai-threat-models-v3-ast-mcp.zip
```

## Appendix B — Universal Skill Format manifest (draft, unsigned)

```yaml
---
# Universal Agentic Skill Format v1.0
name: ai-threat-models
version: 3.0.0
platforms: [claude]

description: "Evidence-gated MAESTRO v2.0 threat-model assessments for agentic AI systems; documentation-only skill, no execution capability"
author:
  name: "Nate Carroll"
  identity: "github:Nate-Carroll-Cyber"      # no did:web anchor; GitHub account as identity
  signing_key: null                           # GAP — see checklist 1.3/2.1

permissions:
  files:
    read: []                                  # reads only its own bundled reference files
    write: []
    deny_write:
      - SOUL.md
      - MEMORY.md
      - AGENTS.md
  network:
    allow:                                    # advisory citation-domain allowlist (runtime does not enforce)
      - owasp.org
      - cloudsecurityalliance.org
      - arxiv.org
      - nvd.nist.gov
      - github.com
      - atlas.mitre.org
    deny: "*"
  shell: false
  tools:
    - web_search                              # citation/verification only, per SKILL.md rule 6

requires:
  binaries: []
  min_runtime_version: null

risk_tier: L1                                 # advisory/documentation; zero execution capability
scan_status:
  scanner: "skillspector@2.9.5 (static, --no-llm)"
  last_scanned: "2026-08-18"
  result: "pass-with-declared-limits"         # 12 findings, 0 true positives post-triage; 4 LLM analyzers disabled

signature: null                               # GAP
content_hash: "sha256:491076b25d465885eb761d08b7d3f730ff4803213bd66123b84ba8611dd2947e"

changelog:
  - version: "3.0.0"
    date: "2026-08-18"
    notes: "Added OWASP MCP Top 10 lens (mcp-top10.md); full crosswalk to eight subsections"
  - version: "2.0.0"
    date: "2026-08-18"
    notes: "Added OWASP Agentic Skills Top 10 lens (agentic-skills-top10.md)"
---
```

---

*Assessment produced against the OWASP Agentic Skills Top 10 Security Assessment Checklist (CC-BY-SA-4.0). SkillSpector © NVIDIA, Apache-2.0.*
