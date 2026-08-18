# OWASP MCP Top 10 (MCP01:2025–MCP10:2025)

Load this reference when **either** condition holds:

1. **Conditional Step 2 lens** — MCP is explicitly evidenced (skill rule 5 already gates this): the system runs, connects to, or exposes MCP servers, clients, or MCP-delivered tools. This is the **protocol layer** — how the model talks to tools. Contrast with `agentic-skills-top10.md`, which covers the installable **behavior layer**. The two lenses stack on the same system without overlapping: a finding about an MCP server, its schemas, its transport, or its auth belongs here; a finding about an installable skill package belongs to AST.
2. **Named crosswalk** — the user asks for "MCP Top 10", "MCP01–MCP10", or MCP-protocol security alignment (Section 11.7).

**Sources**: OWASP MCP Top 10 project — index and the ten per-risk source files at github.com/OWASP/www-project-mcp-top-10 (2025/ directory), project page https://owasp.org/www-project-mcp-top-10/. Project lead: Vandana Verma Sehgal.

## Mandatory caveats (read before citing)

- **License**: CC **BY-NC-SA** 4.0 — NonCommercial, unlike the AST10 project and the other OWASP material in this skill (CC-BY-SA). Everything in this file is the skill's own-words mapping and paraphrase. Never reproduce OWASP's risk descriptions verbatim into a deliverable, and flag the NC term to the user before this lens is used in a paid/commercial engagement deliverable.
- **Beta status**: Phase 3 (beta release and pilot testing); next release scheduled October 2026. The MCP01:2025–MCP10:2025 IDs are stable enough to cite; rankings and descriptions may shift. Pin the citation date in any assessment.
- **Known drafting inconsistency**: MCP03 is titled "Tool Poisoning" but its body text describes *schema* poisoning (tampering with the contract governing agent-tool interaction). Treat MCP03 as covering both: poisoned tool/parameter descriptions the model treats as authoritative, AND poisoned schemas that remap benign operations to destructive ones. Note the inconsistency when citing rather than silently picking one reading.
- MCP06 was renamed from an earlier "Prompt Injection via Contextual Payloads" draft to "Intent Flow Subversion" — older references to the previous name are the same risk.

---

## The ten risks → MAESTRO v2.0 mapping

MAESTRO `L<n>-T<nn>` IDs stay primary in Section 8; cite `MCP<nn>:2025` parenthetically, as with ASI/T/AST IDs.

| MCP | Risk (own-words gist) | MAESTRO v2.0 layer homes | Nearest MAESTRO threat IDs |
|---|---|---|---|
| MCP01 | Token mismanagement & secret exposure — long-lived/hard-coded credentials persisting in context memory, logs, vector stores; "contextual secret leakage" where the protocol layer itself becomes a secret repository | L7, L3, L1, L9 | L7-T02 (credential theft & replay); L1-T04; L3-T05 (disclosure via memory/embeddings) |
| MCP02 | Privilege escalation via scope creep — narrowly granted agent scopes widening through drift/convenience until autonomous over-privilege | L7, L4 | L7-T03 (over-privileged identities), L7-T07 (permission inheritance); L4-T05 (delegation-chain escalation) |
| MCP03 | Tool/schema poisoning — malicious tool descriptions steering the model, or tampered schemas remapping benign verbs to destructive actions while passing validation | L6, L2 | L6-T08 (tool definition poisoning), L6-T04 (MCP server compromise) |
| MCP04 | Supply chain & dependency tampering — compromised MCP server libraries, connectors, plugins, build pipelines in trusted execution paths | L1, L6, L5 | L1-T01; L6-T04/L6-T05; L5-T02 (CI/CD) |
| MCP05 | Command injection & execution — model-mediated injection: agent builds shell/SQL/API calls from untrusted context; chaining operators; unsafe exec paths | L5, L6, L2 | L5-T04 (sandbox breakout), L5-T01; L6-T06; L2-T03 (the mediation path) |
| MCP06 | Intent flow subversion — hidden instructions in retrieved context hijack the plan "in-flow" while the agent appears to serve the original request; meta-instructions persist across sessions | L4, L2, L3 | L4-T02 (goal hijacking); L2-T03; CE-T1 / L3-T04 |
| MCP07 | Insufficient authentication & authorization — missing mutual auth between agents/tools, client-side-only checks, trusted-but-unverified caller identity, unscoped tokens | L7, L6, L4 | L7-T01 (identity forgery), L7-T03; L6 tool-invocation auth; L4 orchestration trust |
| MCP08 | Lack of audit & telemetry — insufficient, mutable, or identity-uncorrelated logging of tool invocations and context changes | L9, L10 | L9-T02 (log tampering), L9 coverage gaps; L10-T05 (audit trail gaps) |
| MCP09 | Shadow MCP servers — unapproved MCP instances outside governance (default creds, permissive config, unsecured APIs), often discovered dynamically by agents | L10, L6, L9 | L10-T01 (shadow AI / rogue agents); L6-T04; L9 visibility gaps |
| MCP10 | Context injection & over-sharing — shared/persistent/under-scoped context windows leaking one task's, user's, or agent's data into another's | L3, L6 | L3-T04 (context poisoning), L3-T05/L3-T06 (leakage surfaces); CE-T1/CE-T7; L6-T06 (exfil path) |

The AST10 whitepaper's per-risk OWASP mappings cite these MCP IDs; the two files resolve each other's cross-references.

---

## Per-risk evidence checks

Same discipline as the AST lens: each item is an evidence question; "no" is a finding, "unevidenced" is a gap. Distilled and reworded from the project's per-risk vulnerability checklists.

### MCP01 — Token Mismanagement & Secret Exposure
- Secrets vaulted (not hard-coded in client/server/tool config); runtime-only injection?
- Tokens short-lived, session-bound, scoped, agent/tool/session-bound; renewal per MCP session?
- Context memory, logs, telemetry, and vector stores redacted — no full-prompt retention of secrets?
- Per-user/per-agent credentials rather than shared static service accounts?

### MCP02 — Privilege Escalation via Scope Creep
- Minimal scopes documented and mapped to intended actions per agent, fine-grained (resource- and branch-level, not repo-wide)?
- Policy-as-code enforcement in CI (violating configs rejected at PR)?
- Time-limited scopes with JIT elevation + approval gates for higher-risk actions?
- Per-agent identity with action attribution; automated entitlement review; no ad-hoc grants promoted to prod?

### MCP03 — Tool / Schema Poisoning
- Tool descriptions statically screened pre-connection for: model-directed imperatives, sensitive-path references, exfiltration verb+destination patterns, zero-width/bidi characters, comment-smuggled instructions?
- Schemas/manifests signed (content-addressed hashes verified before acceptance); no unsigned dynamic fetch?
- Schema registry immutable/version-controlled with RBAC, review, multi-party approval; provenance metadata (author, hash, approver) logged per invocation?
- Semantic invariants as policy-as-code (e.g., an "archive" operation can never map to DELETE) checked in CI and at a runtime PDP?
- Runtime revalidation before schema changes drive actions; destructive-impact thresholds pause for human approval?

### MCP04 — Supply Chain & Dependency Tampering
- Connectors/plugins installed only with signature/provenance verification; no floating "latest" versions?
- Complete SBOM/dependency inventory; hash/attestation integrity verification; third-party components sandboxed?
- Build pipelines and package registries in scope for the same controls (parallel to AST02 for the skill layer)?

### MCP05 — Command Injection & Execution
- No agent output passed to exec/system/eval/`shell=True` paths; parameterized queries and safe APIs only?
- Allowlists for permitted commands, arguments, and file paths; shell metacharacters and command substitution neutralized; path traversal blocked?
- Model-generated code sandboxed or human-reviewed before execution; tools run least-privilege, never root/admin?

### MCP06 — Intent Flow Subversion
- Original user goal anchored; per-step intent-alignment validation (proposed tool call checked against the anchored goal)?
- Independent checker/guardrail model that sees only intent + proposed action, isolated from retrieved context?
- All MCP resource/tool-output content treated untrusted-by-default, tagged as data, unable to override system/developer instructions (LLM01 safeguards applied to retrieved context)?
- Intent-drift monitoring with session pause + human re-authorization on deviation?

### MCP07 — Insufficient Authentication & Authorization
- Mutual authentication between agents, tools, and servers; caller identity verified server-side, never trusted from metadata or client hints?
- Per-scope authorization validated at the tool endpoint per user/agent; RBAC/ABAC in place?
- Tokens non-reusable across agents; expiry and rotation enforced; identity-correlated access logs answering "who did what, with what authority"?

### MCP08 — Lack of Audit & Telemetry
- Tool invocations, context changes, and user-agent interactions logged with identity correlation?
- Audit trails immutable/tamper-evident (see the bilateral receipt pattern in `agentic-skills-top10.md` — it applies equally here)?
- Telemetry sufficient for IR reconstruction, distinct from eval/observability pipelines (skill rule 4)?

### MCP09 — Shadow MCP Servers
- Central inventory of approved MCP servers; discovery mechanisms (registry, mDNS, config scans) reconciled against it?
- No default credentials or permissive configs on any instance; unapproved instances detectable (network telemetry, identity/OAuth-grant posture — same identity-first discovery pattern as AST09's unreachable skills)?
- Dynamic server discovery by agents restricted to a trusted, identity-validated registry (a shadow server impersonating a legitimate one is the core scenario)?

### MCP10 — Context Injection & Over-Sharing
- Context scoped per task/user/agent; no cross-session or cross-tenant persistence without explicit design and classification?
- Retrieved data provenance-tagged; injection into shared context surfaces treated as CE-T1 in L3 analysis?
- Sensitive data classes barred from shared/persistent context; context caches subject to the same redaction as logs (MCP01 interlock)?

---

## Evidence base (for Likelihood justification)

Cite the source, not just the figure; these are protocol-layer incidents, distinct from the AST skill-layer base:

- 30+ CVEs filed against MCP servers, clients, and tooling in Jan–Feb 2026; ~43% shell injections (Practical DevSecOps summary of NVD filings). → MCP05
- Palo Alto Unit 42: with five connected MCP servers, a single compromised server reached a 78.3% attack success rate. → MCP03, MCP04
- Tool poisoning success ~84.2% with auto-approval enabled (benchmark reporting, 2026); MCPTox (arXiv:2508.14925) provides the academic benchmark against real-world servers. → MCP03
- Audit of 17 popular MCP servers: average security score 34/100; 100% lacked permission declarations. → MCP02, MCP07
- CVE-2026-32211 (Azure MCP Server): authentication layer entirely missing. → MCP07
- BlueRock Security: of 7,000+ MCP servers analyzed, 36.7% potentially SSRF-vulnerable; PoC against Microsoft's MarkItDown MCP server retrieved AWS IAM keys from the EC2 metadata endpoint. → MCP05, MCP01
- Invariant Labs: original tool-poisoning disclosure and the GitHub MCP private-repo access attack; CyberArk "Poison Everywhere" extended poisoning to all server output; Trail of Bits proposed tool-description trust-on-first-use pinning. → MCP03

## Mitigation sourcing (Step 4)

Controls per risk, own words, mapped to FAIR-CAM function classes where used with `threat-technique-and-control-library.md`:

- **MCP01**: vaulted secrets, runtime-only injection, short-lived scoped session-bound tokens, context/log/vector-store redaction (Prevention); credential-flow audits across clients, tools, memory, caches (Detection).
- **MCP02**: least-privilege-by-design scope maps, policy-as-code in CI, JIT elevation with approval, per-agent identity binding (Prevention); entitlement reviews, attribution logging (Detection).
- **MCP03**: signed schemas/manifests with content-addressed versioning, immutable registry with multi-party approval, pre-connection static screening of tool descriptions, semantic-invariant policy checks at CI and runtime PDP, schema attestation binding hash to agent identity and session (Prevention); provenance logging per invocation, destructive-impact thresholds with human pause (Detection/Response); revoke poisoned schema version → roll back to known-good hash → rotate credentials → forensic replay of affected agents (Response).
- **MCP04**: signature/provenance-gated installs, pinned versions, SBOM, sandboxed third-party components (Prevention) — parallel AST02 controls at the protocol layer.
- **MCP05**: parameterization over concatenation, execution allowlists, metacharacter neutralization, sandboxed code execution, least-privilege tool runtimes (Prevention); runtime monitoring of spawned processes vs declared scope (Detection).
- **MCP06**: goal anchoring + per-step alignment scoring, isolated checker model, untrusted-by-default context tagging, PDP action gating (Prevention); intent-drift monitoring with pause-and-reauthorize (Detection/Response).
- **MCP07**: mutual auth, server-side authorization, RBAC/ABAC, scoped non-reusable expiring tokens (Prevention); identity-correlated logging (Detection).
- **MCP08**: immutable identity-correlated logging of invocations and context changes (Detection foundation for every other MCP control); bilateral receipts apply.
- **MCP09**: approved-server inventory + reconciliation, trusted discovery registry with identity validation, default-credential elimination, identity/OAuth-posture-based shadow discovery (Prevention/Detection).
- **MCP10**: per-scope context isolation, provenance tagging, sensitive-class exclusion from shared context, cache redaction (Prevention).

SSRM note: MCP server operators are the **Tool Provider** role in the Agent 3SRM — this taxonomy is the most direct control source for that role's obligations. The AIC retains non-delegable accountability for which servers its agents connect to (MCP09 is largely an AIC failure even when the server itself is the artifact).
