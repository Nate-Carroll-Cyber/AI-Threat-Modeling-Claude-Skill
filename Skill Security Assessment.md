# Skill Security Assessment — `ai-threat-models` vs. OWASP AST10 Checklist

| | |
|---|---|
| **Skill under review** | `ai-threat-models` (MAESTRO v2.0 AI Threat Model Analyst), v7 plus the October 2026 additions (local branch `asset-capability`: seven content commits over `main` at `d857b32`, plus the commit carrying this report; not yet pushed) |
| **Package** | `ai-threat-models-v7-plus-harm-lens.zip` — sha256 `940f1e80cde20d02abe25e1372ddd8fdb5e5e29852eed9a2ed01bf9a147de113` |
| **Contents** | SKILL.md + README.md + 10 reference files (9 hand-curated, 1 generated) + 5 scripts (4 Python, 1 shell); **17 files, 543 lines of executable content, 1 third-party dependency (PyYAML, unpinned), 1 outbound fetch** (verified by file-type inventory and code review). The v3 package this report first covered was 9 markdown files with no executable content; every answer that rested on that fact is re-answered below. |
| **Checklist** | OWASP Agentic Skills Top 10 — Skill Security Assessment Checklist (CC-BY-SA-4.0) |
| **Review date** | 2026-10-03 (supersedes the 2026-08-18 review of the v3 package) |
| **Reviewer** | Claude (LLM semantic review + deterministic scans + SkillSpector v2.12.0 static scan + Bandit 1.9.4 + ShellCheck 0.11.0). **Reviewer caveat**: the reviewer is an LLM in the same session that authored the October 2026 additions to the reviewed content — this is a self-review with instrumented scans, not an independent third-party assessment. Per the checklist's own 8.6 principle, treat it as advisory. |

## Scans performed (ground truth)

1. **File inventory + SHA-256 hashes** — all 17 files hashed (Appendix A); package hash recorded above.
2. **Unicode smuggling scan** — zero-width chars (U+200B–D, U+2060, U+FEFF), bidi controls (U+202A–E, U+2066–69), and Unicode tag characters (U+E0000–E007F): **clean**.
3. **Base64 payload scan** — decodable printable blobs ≥40 chars: **none**.
4. **Secret-pattern scan** — AWS keys, GitHub PATs, Slack tokens, private keys, hardcoded credential assignments (regex class; NOT Gitleaks/TruffleHog): **clean**.
5. **Model-directed-imperative scan** — "ignore previous instructions" / "do not tell the user" patterns as live instructions: **none**.
6. **YAML frontmatter** — parses under `yaml.safe_load`; keys = `{name, description}` only; no unsafe tags.
7. **SkillSpector v2.12.0** (NVIDIA, commit `3527006`, static-only `--no-llm`). Result: **100/100, CRITICAL, "DO NOT INSTALL," 22 issues, 17 of 17 files inspected.** Four analyzers disabled (meta analyzer and the three semantic analyzers, all LLM-dependent). All 22 findings are in markdown; none is in `scripts/`. Triage below: **21 false positives, 1 true positive.**
8. **Bandit 1.9.4** over `scripts/*.py` (442 lines): **1 finding**, B310 medium, `refresh_atlas.py:48` (`urllib.request.urlopen`). The URL is a module constant with a fixed `https` scheme, so the scheme risk B310 names does not apply. The real issue at that line is the unpinned fetch recorded under 5.2.
9. **ShellCheck 0.11.0** over `scripts/package.sh`: **clean**.
10. **Manual code review** of all five scripts. No `subprocess`, `eval`, `exec`, or `os.system` call (the strings appear only inside a detection regex in `plan_subsystems.py:40`). YAML is parsed with `yaml.safe_load`. Network: one fetch, `refresh_atlas.py:48`, of `ATLAS.yaml` from the `main` branch of `mitre-atlas/atlas-data`. Writes: `references/atlas-techniques.md` (refresh), the `--out` path (SARIF), the `--json` path (citations), and the zip in the repo root (package). `verify_citations.py` rejects cited paths that resolve outside `--root`; `section8_to_sarif.py:59` has no such guard but only returns a string and reads nothing.

## SkillSpector finding triage (v2.12.0, current package)

| # | Finding | Location | Conf. | Triage |
|---|---|---|---|---|
| 1, 12 | YR4 YARA match | agentic-skills-top10.md:77, maestro-layers.md:3 | 80% | **FP** — a list of named attack scenarios and the threat-catalog header line. Keyword hits on a threat taxonomy. |
| 2 | MP3 Memory Poisoning | agentic-skills-top10.md:78 | 90% | **FP** — a sentence stating that a signed skill can still poison memory after install. It describes the risk. |
| 6–9 | MP3 Memory Poisoning | atlas-techniques.md:81, framework-crosswalk.md:97, phantom-b.md:37, threat-technique-and-control-library.md:70 | 90% | **FP** — four table rows naming the ATLAS technique "Poison Training Data" (AML.T0020). |
| 3 | PE3 Privilege Escalation | agentic-skills-top10.md:99 | 60% | **FP** — AST03 scenario name ("`.env` exfiltration") in documentation. |
| 10–11 | PE3 Privilege Escalation | atlas-techniques.md:175, mcp-top10.md:31 | 70% | **FP** — table rows naming the ATLAS technique "Application Access Token" (AML.T0091.000). |
| 4–5 | P1 Prompt Injection | agentic-skills-top10.md:122, mcp-top10.md:76 | 90% | **FP** — two control statements requiring that retrieved content be unable to override system instructions. The flagged sentences are the defense. |
| 13–14 | AR3 Anti-Refusal, P1 | maestro-layers.md:69 | 90% | **FP** — the L2-T03 threat-catalog entry ("adversarial inputs that bypass safety alignment"). Naming a jailbreak threat is not issuing one. |
| 15 | AR3 Anti-Refusal | maestro-layers.md:292 | 90% | **FP** — the OWASP T18 scenario description ("bypass policy"). |
| 17 | EA2 Excessive Agency | SKILL.md:216 | 80% | **FP** — "Do not ask the user to fill out a full evidence worksheet" is an output-formatting instruction in an analysis skill. No action is being taken without consent. |
| 18 | EA2 Excessive Agency | agentic-skills-top10.md:95 | 85% | **FP** — an evidence check asking whether repo config is "not auto-executed at project open". |
| 19 | EA2 Excessive Agency | harm-categories.md:82 | 75% | **FP** — the definition of an owner's authorization scope ("which actions the agent may take without confirmation"), added in this revision. |
| 20–22 | EA3 Excessive Agency | agentic-skills-top10.md:83, :108, :215 | 70% | **FP** — three checklist items that ask whether a skill reaches "beyond stated function". |
| 16 | **LP3 MCP Least Privilege** | SKILL.md:1 | 70% | **True positive.** The skill declares no tool scope (`permissions` or `allowed-tools`) while shipping scripts that read files, write files, and open a network connection. Same gap as checklist 3.1. Remediation 2. |

**True positives: 1 (LP3, medium).** The other 21 are pattern matches on security documentation with the LLM semantic layer disabled, which is the failure mode the skill's own AST08 content describes. The score rose from 72 to 100 because the package grew from 9 to 17 files and the scanner changed version, not because the 21 documentation hits became more serious. Retained as advisory input per 8.6, not as a gate.

**Superseded result.** The 2026-08-18 scan (SkillSpector v2.9.5, 72/100, 12 findings, 0 true positives) covered the v3 package only. Its line references no longer resolve and it is not carried forward.

## Status legend

- **Yes** — satisfied, evidence cited. **No** — genuine gap. **N/A** — structurally inapplicable (e.g., zero dependencies). **Platform** — not controllable at the skill layer; owned by the Claude skill runtime (Anthropic). **Owner** — organizational process; unanswerable from package evidence, requires owner attestation.

## Summary

| AST | Yes | No | N/A | Platform | Owner |
|---|---|---|---|---|---|
| AST01 (6) | 4 | 1 | 0 | 1 | 0 |
| AST02 (7) | 0 | 5 | 1 | 1 | 0 |
| AST03 (8) | 5 | 2 | 1 | 0 | 0 |
| AST04 (12) | 5 | 2 | 2 | 3 | 0 |
| AST05 (6) | 2 | 3 | 0 | 0 | 1 |
| AST06 (7) | 0 | 0 | 1 | 6 | 0 |
| AST07 (6) | 2 | 3 | 1 | 0 | 0 |
| AST08 (7) | 5 | 1 | 0 | 0 | 1 |
| AST09 (7) | 1 | 1 | 0 | 0 | 5 |
| AST10 (6) | 1 | 1 | 3 | 0 | 1 |
| **Total (72)** | **25** | **19** | **9** | **11** | **8** |

Changed since the v3 review: 2.3 and 2.6 (N/A → No), 3.4 (N/A → Yes), 5.5 (Yes → No), 10.1 (N/A → Owner). The earlier total row read "(62)"; the rows sum to 72 checks and always did.

Top remediations (ordered by value): §Remediation, end of document.

---

## AST01 — Malicious Skills (Critical)

**1.1 Verified, trusted source — Yes.** First-party: authored and packaged by the owner (Nate-Carroll-Cyber); no registry, no third-party publisher, no typosquat surface. Provenance is by construction, not by verification infrastructure — see 2.1 for the signing gap that would matter on any distribution.

**1.2 Behavioral analysis beyond pattern matching — Yes (with caveat).** This review is an LLM semantic analysis of intent across both layers, a line-by-line read of all five scripts, plus SkillSpector, Bandit, and ShellCheck static scans. Caveat: semantic reviewer = session LLM (self-review); SkillSpector's own LLM analyzers did not run. An independent semantic scan on the owner's machine (SkillSpector with an LLM key) would close the independence gap.

**1.3 Cryptographic signature verification — No.** No signing exists. The Claude skill ecosystem has no signature or manifest-hash field. Compensating control applied in this review: SHA-256 recorded per file and per package (Appendix A) — a pin, not a signature.

**1.4 Scripts and NL instructions reviewed for malicious patterns — Yes.** Five scripts, 543 lines, read in full (scan 10): no shell-out, no dynamic evaluation, no credential access, no encoded payloads, safe YAML loading. One outbound fetch to a fixed GitHub raw URL. NL layer: smuggling, base64, secret, and imperative scans clean.

**1.5 Isolated canary before production — No.** No formal declared-vs-observed dynamic test report exists for this package. The scripts were executed during this session's packaging (`package.sh` and `refresh_atlas.py --check-only --strict` ran to completion), which is operational evidence, not a canary protocol. Remediation: one skill-creator eval run with asserted outputs, with script network and file activity recorded.

**1.6 Avoids writing to identity files — Yes.** The scripts write only to `references/atlas-techniques.md`, to output paths the operator names (`--out`, `--json`), and to the package zip. No SOUL.md/MEMORY.md/AGENTS.md references as write targets.

## AST02 — Supply Chain Compromise (Critical)

**2.1 Publisher identity vs code-signing key — No.** No signing key, no did:web, no verified-org binding. If the skill is ever published (GitHub repo), the verified GitHub org/account becomes the identity anchor; a detached signature (minisign/ssh-keygen -Y) over the package hash is the cheap upgrade.

**2.2 Pinned to immutable content hash — No → remediated in this review.** Hash now recorded (Appendix A + package hash above). No registry record exists to match against; the hash in this report is the record.

**2.3 Nested dependencies pinned — No.** `refresh_atlas.py` imports PyYAML. No requirements file, lock file, or version pin exists, so the version is whatever the host has. Everything else is Python standard library; `package.sh` needs `zip` and `unzip`.

**2.4 SBOM generated — No.** Formally absent. The package is 17 files with one Python dependency and one fetched data file (ATLAS.yaml). A CycloneDX SBOM is small and now has real content to record: PyYAML, and the ATLAS release the snapshot was generated from.

**2.5 Repo config files as executable code with trust gates — N/A (package) / Platform (consumption).** The package contains no hooks, settings files, or env overrides. Whether the consuming environment executes repo config at open is the runtime's property (the CVE-2025-59536 class), outside this skill's control.

**2.6 Recursive dependency tree scanned — No.** The tree is one package (PyYAML) and it was not scanned. SkillSpector's dependency lookup had nothing to query because no manifest declares it.

**2.7 Pre-mutation receipt from installer — Platform.** Installation is manual zip upload through the Claude interface; no installer exists at the skill layer to emit a receipt. The claude.ai skill-upload flow does not currently emit one.

## AST03 — Over-Privileged Skills (High)

**3.1 Permission manifest with explicit scoped permissions — No (platform format gap, now a scanner finding).** The Claude skill format carries `name` + `description` frontmatter only; no permission-manifest field exists. SkillSpector LP3 flags exactly this: no declared tool scope, with file and network capability present in `scripts/`. Compensating: Appendix B provides a Universal Skill Format manifest declaring the skill's actual needs, updated in this review for the scripts.

**3.2 Permissions minimized to stated function — Yes (behaviorally).** The instructions request: reading the skill's own bundled files, web search for citation when available, and running four named Python scripts that read an operator-supplied repository or report and write to operator-named outputs. `refresh_atlas.py` and `package.sh` are maintainer tools, not part of an assessment run. No credential access.

**3.3 Avoids unrestricted shell — Yes (scoped).** SKILL.md directs three fixed commands during an assessment (`plan_subsystems.py`, `verify_citations.py`, `section8_to_sarif.py`), each with operator-supplied paths as the only arguments. No instruction asks for arbitrary shell. This answer was "no shell use requested anywhere" for v3; that is no longer true.

**3.4 File permissions scoped, no wildcards — Yes (behaviorally, with one caveat).** Reads are confined to the tree the operator passes. `plan_subsystems.py` walks that whole tree by design and prints only counts and directory names, never file content. `verify_citations.py` rejects paths that escape `--root`; with `--show` it prints cited lines from the assessed repository into the session, which is untrusted content reaching the model (the skill reads that repository anyway). Caveat: `section8_to_sarif.py:59` lacks the escape guard, with no read behind it.

**3.5 Per-skill scoped credentials — N/A.** No credentials used, stored, or requested.

**3.6 Identity-file write access flagged — Yes.** None requested (see 1.6); nothing to flag.

**3.7 Network as domain allowlist — No.** SKILL.md rule 6 directs the executing agent to use web access for citation without any domain scoping, and `refresh_atlas.py` fetches from `raw.githubusercontent.com`. Low severity for the citation lookups (the agent verifies against these sources and does not obey them); higher for the ATLAS fetch (see 5.2). Remediation: add an advisory citation-domain allowlist to SKILL.md (owasp.org, cloudsecurityalliance.org, arxiv.org, nvd.nist.gov, github.com, raw.githubusercontent.com, atlas.mitre.org, shostack.org, anthropic.com) — advisory because the runtime doesn't enforce it, but it pins reviewer expectations and feeds 5.4.

**3.8 Avoids credential stores/.env/wallets/SSH — Yes.** No script opens a credential store. `plan_subsystems.py` reads the first 64 KB of configuration-type files in the assessed repository to count signal matches, and those files can contain secrets; it prints counts only. The strings `~/.ssh`, `.env`, etc. otherwise appear only as detection indicators inside threat documentation (SkillSpector findings 3 and 21, triaged FP).

## AST04 — Insecure Metadata (High)

**4.1 Description accurate and complete — Yes (with one omission).** The frontmatter description enumerates triggers and output and matches observed behavior for the MAESTRO, AST, MCP, and PHANTOM-B paths. It does not mention that the skill ships scripts, or the harm-category lens added in this revision (that lens fires from the evidence, not from a user phrase).

**4.2 Scanned for smuggling/zero-width/base64 — Yes.** Clean (scans 2–3 above).

**4.3 Secure metadata defaults — Platform.** No capability fields exist to default open or closed. The USF manifest in Appendix B declares dangerous capabilities explicitly off.

**4.4 Metadata validated against security schema — Yes (minimal).** Frontmatter safe-parses; key set = exactly the two fields the Claude skill schema expects; no unexpected fields. No formal JSON-Schema pipeline exists (that is the runtime's loader; see 4.11).

**4.5 risk_tier consistent with permission scope — No (declared tier is stale).** The v3 review declared **L1 (low)** on the basis of zero execution capability. That basis is gone. Assessed tier for this package: **L2 (moderate)** — local script execution over operator-supplied paths, one outbound fetch to a fixed host, writes confined to named outputs, no credential access. Updated in Appendix B; the owner should confirm.

**4.6 Brand impersonation checked — Yes.** Name `ai-threat-models` impersonates nothing. OWASP, CSA, MITRE, NVIDIA marks appear nominatively with attribution and license notes (CC-BY-SA content adapted; BY-NC-SA content paraphrased own-words with the NC term flagged in-file).

**4.7 Safe YAML loaders — Yes** for the artifact (verified safe_load-parseable, no unsafe tags). Loader choice itself is Platform.

**4.8 Config parsed in isolated subprocess — Platform.** Anthropic's loader; not skill-controllable.

**4.9 Key allowlist enforced — Yes (de facto)** — key set matches expected schema exactly; enforcement mechanism is Platform.

**4.10 Dependency files treated as untrusted — N/A.** None exist.

**4.11 Schema validation before deserialization — Platform.** Runtime loader pipeline.

**4.12 Deserialization at minimum privilege — Platform.** Same.

## AST05 — Untrusted External Instructions (High)

**5.1 External references inventoried — Yes.** Full inventory by domain, from a scan of the package: arxiv.org (9 URLs, source citations, six added in this revision), shostack.org (3), raw.githubusercontent.com (3: the ATLAS fetch URL and the SARIF schema URL), owasp.org (2), github.com (2, plus three bare repository pointers), anthropic.com (1, added in this revision). Also SKILL.md rule 6 (web citation, unscoped) and the pointers to NVD and the AICM catalog. **One is a load-time fetch whose result becomes skill content**: `refresh_atlas.py` downloads ATLAS.yaml and writes technique names from it into `references/atlas-techniques.md`, which the skill then loads. No other reference directs the agent to retrieve external content and follow it.

**5.2 Referenced content hash-pinned, re-verified on load — No.** The advisory pointers are unpinned, and so is the ATLAS fetch: it reads the `main` branch with no commit pin and no hash check, and technique names from the fetched file are written unescaped into a reference file the model reads. A tampered upstream file is therefore an indirect-injection path into the skill's own content. Mitigating: the refresh is a maintainer action, the result is a reviewable diff, and `package.sh` gates on an audit of that file. Remediation 3.

**5.3 Referenced documentation inlined where possible — Yes.** This is the package's design: AST10 and MCP Top 10 content was inlined (own-words) into the reference files precisely so the agent does not fetch OWASP pages at assessment time. The remaining pointers are for content that must stay current (NVD, catalog) — the legitimate exception the checklist allows.

**5.4 Runtime fetches domain-allowlisted — No.** Same gap as 3.7; same remediation (advisory citation-domain allowlist).

**5.5 References followed transitively — No (for the October 2026 additions).** The v3 reference graph was walked at construction. The eight papers added in this revision were each read directly, but the works they cite were not followed. Content that depended on an unchecked secondary citation (cited mitigations, incident lists, benchmark rates) was left out for that reason, and each reference file says so.

**5.6 Fleet-wide source visibility — Owner.** Whether the owner's environment tracks which installed skills reference which external sources is an organizational property. Single-skill contribution: the 5.1 inventory above is the skill's entry in such a register.

## AST06 — Weak Isolation (High)

All seven checks concern the execution environment. On claude.ai that is Anthropic's sandbox, which is not configurable at the skill layer. The scripts change what is at stake: on a runtime with a local shell they run with the operator's own file and network access, and nothing in the package constrains that.

**6.1 Container/sandbox — Platform** (Anthropic-managed isolation; skill cannot opt into host-mode). **6.2 Filesystem scoping — Platform.** **6.3 Network binding/auth — Platform.** **6.4 seccomp/AppArmor — Platform.** **6.5 Per-skill namespacing — Platform.** **6.6 WebSocket auth/rate-limits — Platform.** **6.7 Hot-reload / workspace precedence — N/A** at claude.ai (skills load per-conversation from the uploaded package; no watcher, no workspace shadowing mechanism analogous to OpenClaw's three-tier precedence). If this skill is ported to Claude Code or another runtime, 6.1–6.7 must be re-answered per that runtime (see 10.3).

The skill's contribution to isolation posture: the three assessment-time scripts need read access to the assessed tree and write access to one output file each, and nothing else. `refresh_atlas.py` needs outbound HTTPS to one host. A runtime that grants only that is sufficient.

## AST07 — Update Drift (Medium)

**7.1 Pinned to immutable hash — Yes (as of this review).** Package and per-file hashes recorded (Appendix A). Versions between v3 and this package were not hash-recorded in this report; the v3 hashes it previously carried are removed as no longer describing anything shipped.

**7.2 Auto-update disabled/gated — Yes (by construction).** No auto-update mechanism exists; every update is a manual re-upload by the owner. Human approval is inherent.

**7.3 Updates cryptographically signed — No.** Same gap as 1.3/2.1.

**7.4 Automatic re-scan on updates — No (partial progress).** `scripts/package.sh` now refuses to build if the strict ATLAS audit fails, which is a content gate, not a security scan. Nothing re-runs hashing, the deterministic scans, SkillSpector, Bandit, or ShellCheck at packaging, and this report went stale across four package revisions as a result. Remediation 4.

**7.5 Hot-reload disabled in production — N/A.** No hot-reload mechanism exists in this deployment model.

**7.6 Security-advisory subscription — No.** For a self-authored skill the analog is upstream-source watch: AST10 v1 final (Q3/Q4 2026), MCP Top 10 next release (October 2026, so due now), AICM/3SRM revisions, AIVSS v1, ATLAS releases, and PyYAML advisories now that it is a dependency. None is subscribed. Remediation: calendar the two dated releases; they will both invalidate caveats currently hard-coded in the reference files.

## AST08 — Poor Scanning (Medium)

**8.1 Behavioral/semantic analysis performed — Yes** (LLM semantic review, this session), with the 1.2 independence caveat. SkillSpector's semantic layer did not run.

**8.2 Code layer and NL layer scanned independently — Yes.** Code layer: Bandit, ShellCheck, and a full manual read (scans 8–10); SkillSpector reports executable scripts present and raised no finding in them. NL layer: scans 2–5 plus semantic review.

**8.3 Credential detection — Yes (regex class).** Clean. Labeled honestly: pattern-equivalent scan, not Gitleaks/TruffleHog binaries. Running Gitleaks on the repo history (not just the package) remains worthwhile on the owner's machine.

**8.4 Scanning isolated from skill interference — Partial.** The deterministic scans (2–6, 8, 9) are immune to the content they scan. The *semantic reviewer* is an LLM reading the content it evaluates — the exact injectable-scanner surface the skill's own AST08 section documents — and in this revision it also wrote part of that content. Recorded as the review's chief methodological limit.

**8.5 Dynamic behavioral testing in sandboxed runtime — No.** Same as 1.5: no formal declared-vs-observed run. With scripts present this is no longer a formality; the declared behavior in scan 10 comes from reading the code, not from observing it under instrumentation.

**8.6 Skill-based scanner results advisory only — Yes, demonstrated.** SkillSpector's 100/100 "DO NOT INSTALL" verdict — 22 findings, 1 true positive on triage — was treated as advisory input, triaged line-by-line, and retained in this report. Gating on it would have blocked the package over 21 documentation hits; ignoring it would have missed LP3, the one finding that names a real gap.

**8.7 Agent-skill-aware scanner pre-install — Yes.** SkillSpector v2.12.0, static profile, 17 of 17 files inspected, report reproduced above. Risk score above threshold *before triage*; all findings triaged, one confirmed. Coverage limitation recorded: 4 analyzers disabled (LLM-dependent) — per the skill's own coverage-record principle, this scan is PASS-with-declared-limits, not unqualified PASS.

## AST09 — No Governance (Medium)

**9.1 Centralized skill inventory entry — Owner.** No formal inventory evidenced. The row it needs: name `ai-threat-models` · version v7 plus October 2026 additions (unreleased) · hash `940f1e80…7de113` · packaged 2026-10-03 · installer: owner · last scan: SkillSpector v2.12.0 static + Bandit + ShellCheck, 2026-10-03, 1 TP post-triage (LP3).

**9.2 Risk tier assigned — Yes (reassessed in this review).** **L2 (moderate)**, up from L1: the package now executes locally and makes one outbound fetch. See 4.5. Declared in Appendix B, pending owner confirmation.

**9.3 Approval record — Owner.** Self-authored/self-approved is the de facto state; no dated record exists. This report can serve as the approval artifact for the package hashed in Appendix A if countersigned by the owner.

**9.4 Invocation logging — Owner/Platform.** claude.ai conversation history is the de facto invocation log (skill, context, outputs); it is not an audit-grade, query-able log per the skill's own rule 4 distinction.

**9.5 Review cadence — Owner.** None defined. Recommended: re-review on any of — AST10 v1 final, MCP Top 10 Oct 2026 release, AIVSS v1, AICM version change — or 6 months, whichever first. Matches a Medium-tier cadence.

**9.6 Revocation/deprovisioning process — Owner.** Single-owner deployment; removal = delete from claude.ai. No IR-playbook linkage exists or is proportionate at this scale; becomes real if the skill is distributed.

**9.7 Agent NHI with scoped rotated credentials — Owner/Platform.** The executing agent identity is the owner's Claude account; no skill-level NHI exists in this deployment model.

## AST10 — Cross-Platform Reuse (Medium)

**10.1 Independently validated per platform — Owner.** The v3 review recorded claude.ai as the only platform. The scripts presuppose a runtime with a shell and Python, and the repository is now public, so which runtimes the skill runs on cannot be answered from the package. Each one needs its own validation (see 2.5 and 6.1–6.7).

**10.2 Security properties consistent across platform versions — N/A.** One platform version exists.

**10.3 Platform-specific gap assessment per target — N/A now; pre-work done.** The AST06 answers above already document which controls are platform-owned at claude.ai; a Claude Code port would re-open all of AST06 plus 2.5.

**10.4 Credential handling consistent across platforms — N/A.** No credentials.

**10.5 Cross-registry threat intel — N/A.** Not published to any registry.

**10.6 Universal Skill Format manifest — No → drafted in this review.** Appendix B provides the USF v1.0 manifest, updated for the scripts. Unsigned (`signature` field left as the recorded gap per 1.3), and not yet adopted into the package.

## Pipeline Trust Boundary Review (B1–B4)

**B1 permissions declared/minimal pre-session** — Partial: no manifest format (3.1); behavioral needs are minimal and now declared in Appendix B. **B1 installer pre-mutation receipt** — Platform (2.7). **B1 developer context sanitized** — N/A: the skill ingests user-supplied architecture evidence by design; its evidence-gating rules (three-bucket separation, no speculation) are the sanitization-equivalent at the analysis layer. **B2 AI-generated dependency validation** — one dependency (PyYAML), unpinned and unscanned (2.3, 2.6). **B2 SAST pre-commit** — Bandit and ShellCheck were run by hand in this review; neither runs in a pipeline. **B3 IaC-CI scanning** — N/A: no IaC. **B3 hash pinning** — No for the ATLAS fetch (5.2). The skill's assessment output still enters no build pipeline, but the SARIF export is designed to be imported into code-scanning systems, so its content is assessor-controlled input to those systems. **B4 sandboxed deployment** — Platform (AST06). **B4 audit logging of agent-initiated production actions** — N/A: the skill initiates no production actions.

## Remediation (ordered)

1. **Pin the ATLAS fetch** — fetch a tagged release or commit of `atlas-data` and record its SHA-256 in the generated snapshot header; refuse to write the snapshot when a technique name contains markdown control characters. Closes the injection path in 5.2.
2. **Adopt Appendix B USF manifest into the package** — closes 10.6 and answers SkillSpector LP3; declares 3.1/4.3/4.5 as far as the format allows.
3. **Pin PyYAML** — add a one-line `requirements.txt` with a version and hash; closes 2.3 and gives 2.6 something to scan.
4. **Re-scan script at packaging** — extend `package.sh` to write per-file and package hashes and run the deterministic scans, SkillSpector, Bandit, and ShellCheck, then regenerate Appendix A. Closes 7.4 and stops this report going stale.
5. **Advisory citation-domain allowlist in SKILL.md** — closes 3.7 + 5.4. (owasp.org, cloudsecurityalliance.org, arxiv.org, nvd.nist.gov, github.com, raw.githubusercontent.com, atlas.mitre.org, shostack.org, anthropic.com.)
6. **Detached signature over the package hash** (minisign or `ssh-keygen -Y sign`) published alongside any distribution — closes 1.3/2.1/7.3 to the extent possible without registry infrastructure. More pressing now that the repository is public.
7. **One skill-creator eval run** with asserted outputs and recorded script activity — closes 1.5/8.5.
8. **Add the path-escape guard to `section8_to_sarif.py`** — reuse `resolve_safe` from `verify_citations.py`; closes the 3.4 caveat.
9. **Calendar the upstream releases** (MCP Top 10, due October 2026; AST10 v1 final) — closes 7.6.
10. **Owner attestations** for the Owner items in 5.6, AST09, and 10.1 — or adopt the 9.1 inventory row and this report as the 9.3 approval record.

Carried over and unchanged from the v3 review: the optional wording change at the "silently" sentence in SKILL.md (now line 216), which the current scanner flags on its neighbor sentence instead (finding 17).

## Appendix A — File hashes (SHA-256, package of 2026-10-03)

```
1fbefb9ddcb99c1f24ae8b4d3e14e3348eac4d159595cac34fbc1fffef949a80  README.md
5d3765f8d3935333ae19c3ed4ec3e819abd87b7a504d6db1a06704c865c5b724  SKILL.md
fb6e24caf94e18daa43cc7b3a15c16040bf5296f03ae713be2f4ba620133457d  references/agentic-skills-top10.md
f04b901e8cc935d0ee2bbfece1db4e592eaab6dab3b39e07c4aa9415af6f6cda  references/ai-control-trait-r.md
36b99d8e1aa340e10174d7825d926ab597f8954ee535af3c913398b58c961a35  references/atlas-techniques.md
67ee3ec655df302f438b6166874325c691ceec66d11e9c6602604f370f99a497  references/framework-crosswalk.md
1831f0e7db8a826be5ec74d98fbe09a03ac6bb5aef86ea772d06865fc48b289e  references/harm-categories.md
ffa9f9b82b354724fb19cc7581ab5c2deb0a6197674b951131cfd18bc4a500fd  references/maestro-layers.md
4e108b2c041b3c5251b2fecd051a5b5f46e1d29549648a2e766b690c7f6f6a28  references/mcp-top10.md
c7f5a801d5846f9d0e598086c71a15bbe7d302f8660cc4ec4fde79bb19ee7a5e  references/phantom-b.md
3e8a41056685817ed013063c107c6a11e03b91829332d9f7c8f1897d9abe8329  references/ssrm-ownership.md
2cc880f48978ddd1227b327d8ff98da3bf7ef73e6e43e7403998ffd4d4cd279f  references/threat-technique-and-control-library.md
c9230298f18d22c6a18d93fcc6f0916297c45a7313afde040ea924c6fc7157bb  scripts/package.sh
e17f92d043e4c751f71ac087d63605b481a3b9b6d8d834dc743f9fa5fa5ed34d  scripts/plan_subsystems.py
78cc7cd8b5c54f365fe73ae2a6d153e52f38d5cc61acc76c66a6870f13d5b2c8  scripts/refresh_atlas.py
03d678d7d00ec76bfb87faab0ed82f9f5f9db4bc9c15153fbf0f40c94fb406d8  scripts/section8_to_sarif.py
b35f2c78c85c9c4386806a26e658236262110cd7e698cd0be3c45884fd555347  scripts/verify_citations.py

package: 940f1e80cde20d02abe25e1372ddd8fdb5e5e29852eed9a2ed01bf9a147de113  ai-threat-models-v7-plus-harm-lens.zip
```

`references/atlas-techniques.md` is generated by `scripts/refresh_atlas.py` (ATLAS 5.6.0 snapshot dated 2026-09-29); its hash changes whenever the snapshot is regenerated. `Skill Security Assessment.md`, `example-report.md`, and the older zip in the repository root are not part of the package and are not hashed here.

## Appendix B — Universal Skill Format manifest (draft, unsigned)

```yaml
---
# Universal Agentic Skill Format v1.0
name: ai-threat-models
version: 7.1.0                                # unreleased: local branch asset-capability over main d857b32
platforms: [claude]

description: "Evidence-gated MAESTRO v2.0 threat-model assessments for agentic AI systems; ships four Python helper scripts and one packaging script"
author:
  name: "Nate Carroll"
  identity: "github:Nate-Carroll-Cyber"      # no did:web anchor; GitHub account as identity
  signing_key: null                           # GAP — see checklist 1.3/2.1

permissions:
  files:
    read:
      - "<skill>/references/**"               # its own bundled reference files
      - "<operator-supplied repo root>/**"    # plan_subsystems.py, verify_citations.py, section8_to_sarif.py
      - "<operator-supplied report>.md"
    write:
      - "<skill>/references/atlas-techniques.md"   # refresh_atlas.py (maintainer action)
      - "<operator-named --out / --json path>"     # SARIF and citation results
      - "<repo root>/ai-threat-models-*.zip"       # package.sh (maintainer action)
    deny_write:
      - SOUL.md
      - MEMORY.md
      - AGENTS.md
  network:
    allow:                                    # advisory (runtime does not enforce)
      - raw.githubusercontent.com             # refresh_atlas.py: ATLAS.yaml (unpinned — see 5.2)
      - owasp.org
      - cloudsecurityalliance.org
      - arxiv.org
      - nvd.nist.gov
      - github.com
      - atlas.mitre.org
      - shostack.org
      - anthropic.com
    deny: "*"
  shell: scoped                               # python3 scripts/{plan_subsystems,verify_citations,section8_to_sarif,refresh_atlas}.py; scripts/package.sh
  tools:
    - web_search                              # citation/verification only, per SKILL.md rule 6

requires:
  binaries: [python3, zip, unzip]             # zip/unzip for package.sh only
  python: ">=3.10"
  packages: [pyyaml]                          # refresh_atlas.py only; unpinned — see 2.3
  min_runtime_version: null

risk_tier: L2                                 # local script execution, one outbound fetch; was L1 for the markdown-only v3 package
scan_status:
  scanner: "skillspector@2.12.0 (static, --no-llm); bandit@1.9.4; shellcheck@0.11.0"
  last_scanned: "2026-10-03"
  result: "pass-with-declared-limits"         # 22 findings, 1 true positive (LP3) post-triage; 4 LLM analyzers disabled

signature: null                               # GAP
content_hash: "sha256:940f1e80cde20d02abe25e1372ddd8fdb5e5e29852eed9a2ed01bf9a147de113"

changelog:
  - version: "7.1.0"
    date: "2026-10-03"
    notes: "Asset-centric method worked into Steps 1-3; RAG, multi-agent, privacy, injection, and system-prompt checks in maestro-layers.md; harm-category lens (harm-categories.md, Section 10.6). Unreleased."
  - version: "7.0.0"
    date: "2026-09-29"
    notes: "State of main at d857b32: PHANTOM-B lens, 16-section report format, four Python scripts and package.sh, generated ATLAS 5.6.0 snapshot. Intermediate versions 4-6 are not separately recorded in this report."
  - version: "3.0.0"
    date: "2026-08-18"
    notes: "Added OWASP MCP Top 10 lens (mcp-top10.md); full crosswalk to eight subsections"
  - version: "2.0.0"
    date: "2026-08-18"
    notes: "Added OWASP Agentic Skills Top 10 lens (agentic-skills-top10.md)"
---
```

---

*Assessment produced against the OWASP Agentic Skills Top 10 Security Assessment Checklist (CC-BY-SA-4.0). SkillSpector © NVIDIA, Apache-2.0. Bandit © PyCQA, Apache-2.0. ShellCheck, GPL-3.0.*
