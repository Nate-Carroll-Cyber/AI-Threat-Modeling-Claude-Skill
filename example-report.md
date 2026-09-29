# MAESTRO v2.0 Threat Model Assessment: cloudflare/mcp-server-cloudflare

Assessed artifact: https://github.com/cloudflare/mcp-server-cloudflare at commit `1d7a16b` (2026-09-25). Assessment date 2026-09-29. Produced with the ai-threat-models skill, package v7 (16-section format; rules 9 and 10 applied: every referenced lens run from its file, every citation verified with `scripts/verify_citations.py`). ATLAS IDs are ATLAS 5.6.0 from `references/atlas-techniques.md`. File references below are `path:line` at that commit; prefix with `https://github.com/cloudflare/mcp-server-cloudflare/blob/1d7a16b/` for a direct link.

## 1. Understanding Confirmed

The request is a MAESTRO v2.0 assessment of Cloudflare's public MCP server monorepo, which ships 18 remote MCP servers (14 OAuth-authenticated, 4 public) that expose Cloudflare product APIs, a browser-rendering fetcher, and a per-user code-execution container to any MCP client. MCP is the system, so the OWASP MCP Top 10 lens is active (skill rule 5). Every server assembles instructions and tool descriptions for a client-side LLM and several return LLM-generated text, so the PHANTOM-B lens runs on that L2 surface. No third-party skill installation surface exists, so the AST10 lens is inactive. No crosswalk (Section 13) was requested and none is emitted. TRAIT&R was not requested.

## 2. Scope and Assumptions

- Scope is the repository contents at `1d7a16b`. Runtime behavior of the Cloudflare-hosted endpoints, the `@cloudflare/workers-oauth-provider` library internals (KV props encryption, DCR policy), the `agents` MCP handler defaults, Cloudflare Containers isolation, and GitHub branch protection are not in the repo and are marked unanswerable where they matter.
- The assessed deployment is the Cloudflare-hosted configuration described by `server.json` and the `production` env in each `wrangler.jsonc` (deployment account `6702657b...`, e.g. `apps/sandbox-container/wrangler.jsonc:130`). A self-hosted fork changes SSRM ownership (Section 12) but not the code findings.
- The 3SRM deployment model (AaI / AaP / AaaS) is a property of the AIC's agent, which is outside the repo. The system under assessment is TaaS (tools delivered over MCP), so Tool Provider assignments are evidenced and AIC-side assignments are marked `Partial — depends on deployment model` per `ssrm-ownership.md`.
- The LLM is the connecting client's model, outside the repo. PHANTOM-B findings therefore address the prompt-assembly surface the servers control (instructions, tool descriptions, returned content) and the two server-side LLM calls that are in scope (`ai_search`, `get_url_json`).
- Cloudflare's upstream API enforces token authorization independently of this code. Findings about account scoping in this repo are defense-in-depth findings unless stated otherwise.

## 3. System Summary

The monorepo builds one Cloudflare Worker per app on shared code in `packages/mcp-common`. Each request constructs a fresh `McpServer` (`packages/mcp-common/src/server.ts:73`) over streamable HTTP at `/mcp` and `/sse` (`oauth-router.ts:28`); legacy SSE returns 410 (`transport-migration.ts:5-6`) and no stdio mode exists. Authentication wraps every non-public app in `@cloudflare/workers-oauth-provider` 0.10.3 (`oauth-router.ts:99-102`) with dynamic client registration at `/register` (`:100`), a 1-hour access token (`:101`) and a 30-day refresh token (`:102`); the upstream Cloudflare OAuth access and refresh tokens are stored in the grant props (`cloudflare-oauth-handler.ts:670-676`) and read by every tool (`props.accessToken`). A direct Cloudflare API token is accepted as a Bearer alternative and its verified identity is cached in `OAUTH_KV` for 30 days (`api-token-mode.ts:75, :100`).

The tool surface spans read-only analytics and configuration tools, six write-scoped apps (workers-bindings with `workers:write` and `d1:write`, browser-rendering, dex-analysis, logpush, radar URL scanner, autorag), a raw SQL tool (`d1_database_query`, `apps/workers-bindings/src/tools/d1.tools.ts:194`), a raw GraphQL tool (`graphql_query`, `apps/graphql/src/tools/graphql.tools.ts:991`), arbitrary-URL fetchers (13 browser-rendering tools), remote packet-capture commands issued to real end-user devices (`dex_create_remote_pcap`, `apps/dex-analysis/src/tools/dex-analysis.tools.ts:200`), and a per-user Alpine container with an unfiltered shell (`exec(execParams.args)`, `apps/sandbox-container/container/sandbox.container.app.ts:140`) and internet egress (`enableInternet: true`, `server/containerHelpers.ts:25-27`).

The system is agentic in the MAESTRO sense only on the tool side: it holds non-human credentials, executes actions on behalf of a model, and runs code. It has no orchestration, memory, or sub-agents of its own. L4 findings are limited to the human-in-the-loop surface; L3 findings are limited to the context the servers inject into the client.

## 4. Evidence Available

- Full source tree at `1d7a16b`, including `packages/mcp-common` (auth, transport, account scoping, metrics, Sentry), all 18 apps, `packages/eval-tools`, CI workflows, `server.json`, per-app READMEs, `implementation-guides/*`.
- 143 vitest cases across the auth, transport, and account-scoping specs; 13 app spec files with zero cases; 5 eval files.
- Step 1 inventory by `scripts/plan_subsystems.py`: 326 key files; `packages/mcp-common` (55 files, auth/telemetry/MCP signals), `apps/sandbox-container` (30, container/runtime), `apps/autorag` (11, RAG) isolated as distinct subsystems; the fourteen product apps share one auth-lead profile and were gathered as a group.
- Every `path:line` citation below was checked with `scripts/verify_citations.py` against the clone (rule 10): 170 citations, 170 resolvable.
- Deployment configuration in `wrangler.jsonc` per app (bindings, KV IDs, Sentry DSNs, container image tags, observability settings).
- Not available: installed `node_modules`, runtime traffic, KV contents, GitHub repository settings, the Cloudflare Containers platform isolation model, the OAuth provider library's storage implementation.

## 5. Immediate Gaps / Missing Information

1. **Prompt-assembly and content-handling claims cannot be tested end to end.** No client is in scope, so whether any client honors `readOnlyHint`/`destructiveHint` or gates unannotated destructive tools is unknown.
2. **Container isolation is platform-owned.** The repo controls the image, the shell, and egress; escape resistance (L5-T01) belongs to Cloudflare Containers and is unanswerable here.
3. **Token-at-rest protection is library-owned.** Whether `OAuthProvider` encrypts grant props containing upstream Cloudflare tokens in `OAUTH_KV` is not verifiable from this repo.
4. **Documentation contradicts code in four places** (flagged, not resolved): the sandbox README promises "~10m" lifetime (`apps/sandbox-container/README.md:13`) while code reaps at 15 minutes (`containerManager.ts:40-41`); the model-facing instructions describe "an Ubuntu 20.04 base image" (`server/prompts.ts:6`) while the Dockerfile is `alpine:3.19` (`Dockerfile:2`); the README says containers "don't save any state" while the container DO is keyed per user (`container-tools.ts:17`); and three read scopes carry "See and change" consent descriptions (`workers-builds.app.ts:24-27`, `workers-observability.app.ts:15-16`).
5. **Retention of the only per-invocation record** (Analytics Engine `ToolCall` datapoints) is not stated anywhere in the repo.

## 6. MAESTRO Layer Mapping

| Layer | Evidenced components | Status |
|---|---|---|
| L1 Infrastructure | Cloudflare Workers per app; KV (`OAUTH_KV`, `USER_BLOCKLIST`); Durable Objects (`UserContainer`, `ContainerManager`, `WarpDiagReader`); Analytics Engine; Sentry via `toucan-js`; container registry `registry.cloudchamber.cfdata.org`; GitHub Actions | Evidenced |
| L2 Cognitive Core | Client LLM (external); server-side LLM calls in `ai_search` (`autorag.tools.ts:133`) and `get_url_json` (`browser.tools.ts:323`); eval models and LLM judge in `packages/eval-tools/src/test-models.ts:42-48`; server `instructions` and tool descriptions as the prompt-assembly surface | Evidenced (prompt surface); model internals unanswerable |
| L3 Data, Memory, Knowledge | Grant props in `OAUTH_KV`; API-token identity cache (30 d); AI Search / AutoRAG indexes; per-request context injected by 30+ content-returning tools; no agent memory | Evidenced |
| L4 Orchestration | None owned by the system. HITL surface only (annotations, confirmation text) | Partially evidenced |
| L5 Deployment & Execution | Per-user container (Alpine, shell, internet); CI deploy on push to `main` (`main.yml`, `release.yml`); container image built and pushed manually (`apps/sandbox-container/package.json:10`) | Evidenced |
| L6 Tools & Ecosystem | 150+ tools across 18 servers; upstream Cloudflare REST/GraphQL APIs; Browser Rendering; URL Scanner; DEX device commands; third-party sites via fetchers | Evidenced |
| L7 Identity & Autonomy | OAuth provider with DCR; upstream Cloudflare OAuth (PKCE S256); API-token mode; `AccountManager` scoping; per-app scope lists | Evidenced |
| L8 Safety & Security | Zod input validation; Host/Origin allowlist; 4 MiB body cap; partial tool annotations; no output guardrails | Evidenced (thin) |
| L9 Monitoring | Analytics Engine `ToolCall`/`McpRequest`/`AuthUser` events; Sentry; Workers observability at 10% trace sampling; no invocation audit log | Evidenced |
| L10 Governance | Apache-2.0; changesets; `server.json` registry manifest; deprecation notices in four apps; no SECURITY.md, no CODEOWNERS | Evidenced (gaps) |

## 7. Assessment Status by Layer

- **L1** Partially answerable. Supply-chain hygiene evidenced; infrastructure credential handling partially evidenced.
- **L2** Partially answerable. Prompt-assembly surface fully evidenced; model behavior and training unanswerable.
- **L3** Answerable for context injection; token-at-rest protection unanswerable. CE-T1 through CE-T7 evaluated: CE-T1 (L3-T04) and CE-T5/CE-T6 (L3-T07) evidenced; CE-T3 confusion appears as the PB-H finding (generated text indistinguishable from retrieved); CE-T2, CE-T4, CE-T7 have no evidenced instance (no agent memory, no persistent context across requests per `server.ts:73`).
- **L4** Partially answerable (HITL surface only).
- **L5** Partially answerable. Container configuration evidenced; platform isolation unanswerable; CI evidenced.
- **L6** Answerable.
- **L7** Answerable for the code; library storage unanswerable.
- **L8** Answerable (absence is the finding).
- **L9** Answerable (absence is the finding).
- **L10** Partially answerable; repository settings unanswerable.

## 8. Summary of Findings

Ordered by risk. Lens tags: MCP = OWASP MCP Top 10 (Phase 3 beta; CC BY-NC-SA 4.0, so all MCP material here is own-words paraphrase and the NonCommercial term applies to reuse of OWASP's text), PB = PHANTOM-B (CC-BY, attribution in Section 10), Part 3 = the Trust & Identity-Lifecycle taxonomy in `threat-technique-and-control-library.md`. ATLAS technique IDs in block titles are ATLAS 5.6.0 (Apache-2.0). Ratings are as justified in each Section 9 block; "prov." marks a rating provisional on evidence named in Section 14.

| # | Finding | Layer | Lens | Likelihood | Impact | Risk | Status | Implementing party |
|---|---|---|---|---|---|---|---|---|
| 1 | Third-party and user-controlled content returned into context unframed across 30+ tools | L3-T04 | PB-P, MCP06, MCP10 | High | High | **High** | Answerable | Tool Provider |
| 2 | No server-enforced approval on deletes, raw SQL, device captures, exec; `d1_database_query` annotated non-destructive; 14 of 18 apps unannotated | L4-T07 | PB-O, MCP02 | Medium | High | **High** (prov.) | Answerable | Tool Provider, AP |
| 3 | Raw SQL, raw GraphQL, public-by-default URL scans, Hyperdrive origin edits, employee-device captures, unredacted actor emails | L6-T06 | PB-O | Medium | High | Medium-High | Answerable | Tool Provider |
| 4 | Upstream Cloudflare tokens custodied 30 days in KV; identity cache 30 days; truthy `DEV_DISABLE_OAUTH` check | L7-T02 | MCP01, MCP07 | Low | High | Medium | Partial | Tool Provider |
| 5 | Scopes granted at app granularity only; client request overwritten; three read scopes described as "See and change" | L7-T03 | PB-A, MCP02 | High | Medium | Medium | Answerable | Tool Provider |
| 6 | Per-user container: unfiltered shell, internet egress, no `USER`, blocklist only at initialize, no timeout | L5-T04 | PB-O, MCP05 | Medium (escape unassessable) | Medium | Medium (prov.) | Partial | Tool Provider as OSP; CSP |
| 7 | No invocation-level audit record; tool name, user ID, error code only; 10% trace sampling | L9-T01 | MCP08 | High | Medium | Medium | Answerable | Tool Provider, AP |
| 8 | No outbound size caps on tool results; GraphQL size guard returns unflagged error text | L3-T07 | CE-T5/T6 | Medium | Medium | Medium | Answerable | Tool Provider |
| 9 | Tag-pinned actions, deploy on push to `main` with no environment gate, image by tag not digest, no SBOM/provenance, no Dependabot | L5-T02 / L1-T01 | MCP04 | Low | High | Medium | Partial | Tool Provider as OSP; CSP |
| 10 | `ai_search` returns generated text in the same format as retrieved documents; eval judge baseline unmeasured, evals not in CI | L2 (PB-H) | PB-H | Unassessable | Medium | Medium (prov.) | Partial | MP; Tool Provider |
| 11 | No SECURITY.md/CODEOWNERS; `server.json` and README disagree; four doc-vs-code mismatches; no data-handling statement | L10-T02 / T05 | — | High | Low-Medium | Low-Medium | Partial | AIC (governance); Tool Provider (repo) |
| 12 | One-year approved-clients cookie skips consent on re-authorization, including after scope changes | L4-T07 / L7-T02 | Part 3 (Approval Reuse) | Medium | Low | Low-Medium | Partial | Tool Provider |
| 13 | Model-directed imperatives in descriptions; sandbox prompt describes a nonexistent resource and wrong base image | L2 (PB-A/P) | PB-A, PB-P, MCP03 | Medium | Low | Low | Answerable | Tool Provider |

Controlling risk: #1 paired with #2 in any client session that connects a fetcher and a write-scoped server together (Section 11, Path 1). Findings #3, #6, and #8 are amplifiers of that pair; #4, #7, #9, and #12 govern how far a compromise travels, how long a grant stays live, and whether misuse is detected.

## 9. Detailed Threat Analysis

### L3-T04 Context poisoning via tool-returned third-party content (PB-P indirect; MCP06:2025; MCP10:2025; ATLAS AML.T0051.001 Indirect, AML.T0080 AI Agent Context Poisoning)

**MAESTRO Layer**
- L3: Data, Memory, Knowledge (Domain 1); surface owned by prompt/model-core per the L3-T04 ownership note

**Current Evidence**
- 13 browser-rendering tools return rendered third-party page text, markdown, links, DOM snapshots, and AI-extracted JSON as `JSON.stringify({result})` with no framing (`apps/browser-rendering/src/tools/browser.tools.ts:43-51, 87-95, 242-256, 300-306, 353-359, 402-408, 510-516`).
- Search tools wrap chunks in `<result>` tags but interpolate chunk text unescaped, including third-party docs indexed by stack-mcp from vite.dev, vitest.dev, docs.astro.build, opennext.js.org, replicate.com, hono.dev and community.cloudflare.com (`apps/stack-mcp/src/types/stack.types.ts:22-87`; `stack.tools.ts:138-148`).
- AutoRAG `search` returns user-indexed documents as `<file name="${item.filename}">${data}</file>` with filename and content unescaped (`apps/autorag/src/tools/autorag.tools.ts:85-95`).
- AI Gateway `get_log_request_body` / `get_log_response_body` return previously logged prompts and model responses raw (`ai-gateway.tools.ts:152-164, 193-205`); `workers_get_worker_code` returns raw script source (`worker.tools.ts:174-181`); build logs, DEX diag files, container stdout, D1 rows, and URL Scanner HAR files are returned raw.
- The `workers-prompt-full` prompt fetches `developers.cloudflare.com/workers/prompt.txt` and returns it as a `role: 'user'` message (`docs-ai-search.prompts.ts:14-25`).
- A grep for `sanitiz`, `redact`, `escape`, `untrusted`, `treat .* as data` finds only the OAuth consent page sanitizer (`workers-oauth-utils.ts:213-227`); no tool output is framed as untrusted.
- No size limit exists on browser page content, crawl results, HAR, worker source, warp-diag file content, container output, AI Gateway bodies, or D1 results; `getBuildLogs` follows every cursor (`workers-builds.api.ts:64-86`).

**Reasonable Inferences**
- Any page a user asks the model to fetch, any indexed third-party doc, any prior prompt stored in AI Gateway, and any worker source in the account can carry instructions the client model will read as context. The PHANTOM-B indirect-injection pattern (instructions planted and left to be retrieved) applies to at least 30 tools.
- `structuredContent` is returned by only 7 tools, so most clients receive free text with no schema boundary between data and instructions.

**Unknowns / Missing Evidence**
- Whether any connecting client applies its own untrusted-content framing.
- Whether Cloudflare's hosted Browser Rendering service strips scripts or active content before returning text (out of repo).

**Assessment Status**
- Answerable for the server side.

**Attack Vector**
- Indirect prompt injection. A page, document, log entry, or worker script contains model-directed text; the user invokes a fetch/search/read tool; the text enters context unframed; the model acts on it with the write tools available in the same session (Section 9, L4-T07, L6-T06).

**Cross-Layer Impact**
- L2 (model follows injected instruction), L4 (no HITL gate), L6 (write tools, container egress), L7 (acts with the user's token), L9 (arguments not logged).

**Likelihood / Impact / Risk**
- Likelihood: High. The surface is broad, the content is fetched on demand from arbitrary URLs, and OWASP MCP06 evidence (Invariant Labs GitHub MCP attack, CyberArk "Poison Everywhere", cited in `mcp-top10.md`) shows this exact path exploited against comparable servers.
- Impact: High when a write-scoped server is connected in the same client session as a fetcher; Medium for read-only sessions (disclosure only).
- Risk: High.

**Recommended Mitigations**
- Wrap every content-returning result in an explicit data envelope (a fixed preamble stating the content is untrusted and must not be followed as instructions, plus delimiters), and escape `<`/`>` in interpolated chunk text so `<result>`/`<file>` framing cannot be closed by content (DSP-24 Data Differentiation and AIS-15 Prompt Differentiation, implemented at the Tool Provider; DSP-21 for the AutoRAG corpus side).
- Return `structuredContent` with an `outputSchema` for the browser, AutoRAG, AI Gateway log, and worker-code tools so clients have a machine-readable data boundary.
- Cap returned bytes per tool (browser HTML/markdown, HAR, worker source, container stdout) and paginate; the 4 MiB inbound cap has no outbound counterpart.
- Deliver `workers-prompt-full` as a `resource` or `assistant`-framed content, not a `user` message.

**SSRM Ownership**
- Primary (L3 matrix): AIC — `Partial — depends on deployment model`
- Shared: CSP, MP, OSP, AP
- Implementing party: Tool Provider (Cloudflare). The L3 row of the 3SRM matrix has no Tool Provider entry, yet the unframed content is produced inside the Tool Provider's code. Structural AICM gap 2 (dynamic tool discovery; Tool Provider not a recognized AICM role, partially covered by STA, AIS-11, AIS-13).
- Agent Owner accountable: yes (always, per 3SRM §3.1 and MAESTRO MAESTRO §9.3)

**Required Evidence to Fully Answer**
- Client-side handling policy for tool results; Browser Rendering service content-sanitization documentation.

---

### L3-T07 Context overflow through unbounded tool results (CE-T6 overflow, CE-T5 compression-loss; ATLAS AML.T0046 Spamming AI System with Chaff Data)

**MAESTRO Layer**
- L3: Data, Memory, Knowledge (Domain 1)

**Current Evidence**
- No outbound size limit exists on browser page HTML/markdown, crawl results, URL Scanner HAR, worker source, warp-diag file content, container `exec` output, container file reads, AI Gateway log bodies, or D1 query results; `getBuildLogs` follows every cursor with no cap (`workers-builds.api.ts:64-86`).
- The one guard is GraphQL: a result over 800,000 characters is replaced by an error message that is not flagged `isError` (`graphql.tools.ts:1036-1051`).
- The inbound cap is 4 MiB (`server.ts:112, :214-261`); there is no outbound counterpart.
- Descriptions push toward large results: "Set a high limit (1000+)" (`workers-observability.tools.ts:199`); `start_crawl` takes depth and limit with no ceiling stated in the schema (`browser.tools.ts:430-436`).

**Reasonable Inferences**
- A single fetch of a large page, a HAR, or a crawl result can fill the client context; the model's client then compresses or truncates earlier context, which is the CE-T5 path through which system-prompt constraints and prior user instructions are lost (the compression-induced safety-loss chain in skill Step 3).
- The GraphQL guard's unflagged error text is itself returned as data, so the model may read the size-limit message as a query result.

**Unknowns / Missing Evidence**
- Client context-window handling; whether Browser Rendering caps output server-side.

**Assessment Status**
- Answerable for the server side.

**Attack Vector**
- Adversarial: a page or document sized to overflow, served to a fetcher, evicts safety context before an injected instruction (L3-T04) is acted on. Failure mode: an ordinary large result degrades the session without any adversary.

**Cross-Layer Impact**
- L3 to L8 (safety constraints lost under compression) to L6 (unauthorized action), the second cross-layer path in the skill's Step 3 list.

**Likelihood / Impact / Risk**
- Likelihood: Medium (no adversary needed; large results are routine for HAR and source tools).
- Impact: Medium (enabler for L3-T04, not a direct loss).
- Risk: Medium.

**Recommended Mitigations**
- Per-tool outbound byte caps with truncation markers and pagination cursors (browser content, HAR, source, logs, container output); return `isError: true` on the GraphQL size guard; add `structuredContent` so clients can summarize rather than inline (DSP-23 Data Integrity for the truncation marker; the L3 context-engineering component list).

**SSRM Ownership**
- Primary (L3 matrix): AIC — `Partial — depends on deployment model`
- Shared: CSP, MP, OSP, AP
- Implementing party: Tool Provider. Structural AICM gap 2.
- Agent Owner accountable: yes (always)

**Required Evidence to Fully Answer**
- Client context policy; Browser Rendering output limits.

---

### L4-T07 Human-in-the-loop absent by design for destructive and high-impact tools (PB-O; MCP02:2025; ATLAS AML.T0101 Data Destruction via AI Agent Tool Invocation, AML.T0053)

**MAESTRO Layer**
- L4: Orchestration & Coordination (Domain 2), HITL surface

**Current Evidence**
- No code-enforced confirmation, `elicitInput`, or dry-run exists on any mutating tool; deletes execute immediately (`d1.tools.ts:128`, `r2_bucket.tools.ts:165`, `hyperdrive.tools.ts:112`, `browser.tools.ts:544, :622`, `sandbox.container.app.ts:120` with `recursive: true`).
- The only confirmation language is advisory description text on the two DEX remote-capture tools ("Always ask for confirmation from the user", `dex-analysis.tools.ts:202-203, :260-261`), which issue `pcap` and `warp-diag` commands to real end-user devices (`:231-253, :277-299`).
- `d1_database_query` accepts arbitrary SQL (`d1.types.ts:13`) and is annotated `readOnlyHint: false, destructiveHint: false` (`d1.tools.ts:202-205`), so a client that honors annotations will treat `DROP TABLE` as non-destructive.
- Tool annotations are absent on every tool in sandbox-container (`container_exec`, `container_file_delete`), browser-rendering (`kill_browser_session`, `cancel_crawl`, `start_crawl`), dex-analysis (both remote-capture tools), radar (`create_url_scan`), graphql, ai-gateway, autorag, auditlogs, logpush, cloudflare-one-casb, dns-analytics, workers-observability, and demo-day. `openWorldHint` and `idempotentHint` are set nowhere.
- The implementation guide instructs contributors to "Mark read-only or destructive behavior accurately with tool annotations" (`implementation-guides/tools.md:118`); 14 of 18 apps do not.

**Reasonable Inferences**
- Approval is delegated entirely to the client. Where the client auto-approves (the configuration under which OWASP reports ~84% tool-poisoning success, cited in `mcp-top10.md`), every destructive action in this surface runs unattended.
- Missing `destructiveHint` on `d1_database_query` is worse than no annotation, since it affirmatively signals safety.

**Unknowns / Missing Evidence**
- Which clients are in use and whether they gate on annotations at all.

**Assessment Status**
- Answerable.

**Attack Vector**
- Failure mode (no adversary required): a hallucinated or misread instruction produces a delete, a `DROP`, a remote packet capture on an employee device, or `rm -rf` in the container with no checkpoint. Adversarial variant: the L3-T04 injection path drives the same calls.

**Cross-Layer Impact**
- L6 (the tools), L7 (user's write scopes), L3 (data loss), L9 (no argument log to reconstruct what ran), L10 (DEX captures on employee devices carry privacy obligations).

**Likelihood / Impact / Risk**
- Likelihood: Medium (depends on client configuration; unassessed for any specific client).
- Impact: High (irreversible deletes of KV/R2/D1/Hyperdrive; device-level captures).
- Risk: High, provisional on client evidence.

**Recommended Mitigations**
- Set `destructiveHint: true` on `d1_database_query`, `container_exec`, `container_file_delete`, `dex_create_remote_pcap`, `dex_create_remote_warp_diag`, `kill_browser_session`, `cancel_crawl`, `start_crawl`, and `create_url_scan`; set `openWorldHint: true` on every fetcher and on `container_exec`.
- Add MCP elicitation (`elicitInput`) before device captures and before any delete, or a `confirm: true` parameter that the tool refuses without (IAM-18 Output Modification & Special Authorization and GRC-15 Human Supervision at the Tool Provider; AIS-11 Agent Security Boundaries; OWASP Playbook 3 "human approval for sensitive operations").
- Parse `d1_database_query` SQL and reject DDL and multi-statement input unless an explicit `allow_destructive` flag is passed.

**SSRM Ownership**
- Primary (L4 matrix): OSP. No OSP exists in this system; the orchestration decision (approve or not) sits in the client. `Partial — depends on deployment model`.
- Shared: MP, AP (client-side gating), Tool Provider (annotations, elicitation), AIC (which write-scoped servers are authorized)
- Structural AICM gaps 2 (runtime tool binding: the client cannot learn destructiveness except from annotations the Tool Provider sets) and 3 (autonomous decision-making: AICM control ownership assumes a human decides; here the model decides whether to call `d1_database_query` and no AICM control assigns that behavioral responsibility). Name the gap rather than cite GRC-15 as full coverage.
- Agent Owner accountable: yes (always)

**Required Evidence to Fully Answer**
- Client configuration (auto-approve policy, annotation handling).

---

### L5-T04 Sandbox breakout surface and egress in the per-user container (MCP05:2025; PB-O; ATLAS AML.T0050 Command and Scripting Interpreter, AML.T0105 Escape to Host, AML.T0086)

**MAESTRO Layer**
- L5: Deployment & Execution (Domain 2)

**Current Evidence**
- `container_exec` passes a raw string to `child_process.exec` with no options (`sandbox.container.app.ts:140`); the declared `timeout` field (`shared/schema.ts:6`) is never applied.
- The container starts with `enableInternet: true` (`server/containerHelpers.ts:25-27`); the model is told it "has access to the internet" and "may install additional packages" (`server/prompts.ts:4, :16`).
- The Dockerfile has no `USER` directive (`apps/sandbox-container/Dockerfile`, ends at `EXPOSE 8080` line 61), so the Hono server and every exec run as the image default user.
- File write uses `fs.writeFile(reqPath, ...)` without joining to the working directory (`sandbox.container.app.ts:104`); read and delete join to `cwd` but apply no containment check (`:75, :120`); `get_file_name_from_path` only strips a prefix and trailing slash (`container/fileUtils.ts:9-14`).
- `USER_BLOCKLIST` is checked only in `container_initialize` (`container-tools.ts:42-45`), not in `container_exec`, the file tools, or `container_ping` (`:52-151`).
- One Durable Object per Cloudflare user ID (`container-tools.ts:17`); lifetime 15 minutes (`containerManager.ts:40-41`); `MAX_CONTAINERS = 50` with reaping from 25 (`containerHelpers.ts:1`, `userContainer.ts:43-50`); production `max_instances: 50` (`apps/sandbox-container/wrangler.jsonc:138-140`).
- `killContainer` tests `this.ctx.id.toString() in active` against a `string[]` (`userContainer.ts:28`), which checks array indices, not values; `containerManager.ts:42` carries a TODO about an invalid DO id.
- Sandbox tests cover path stripping, MIME type, and one DO state boundary (`fileUtils.spec.ts`, `utils.spec.ts`, `sandbox.server.spec.ts`); no test covers blocklist, isolation, reaping, limits, traversal, or exec constraints.
- The sandbox requests only `account:read` plus `user:read`/`offline_access` (`sandbox.server.app.ts:13-16`), so the container process does not receive Cloudflare write scopes through this server.

**Reasonable Inferences**
- Path traversal is not a privilege boundary here: the same user already holds an unfiltered shell. It matters only as evidence that the file tools were not written defensively.
- Internet egress plus shell plus 15-minute lifetime makes the container a usable exfiltration and command channel for any injected instruction (L3-T04), and a usable abuse platform (scanning, spam) attributable to Cloudflare's egress IPs.
- The blocklist gap means a blocked user with an already-running container keeps exec and file access until reaping.

**Unknowns / Missing Evidence**
- Container-to-host isolation (Cloudflare Containers runtime), egress filtering at the platform, resource quotas (CPU, memory, disk), and whether the default image user is root. All platform-owned.

**Assessment Status**
- Partially answerable.

**Attack Vector**
- Adversarial: injected instruction (L3-T04) or malicious user runs code that exfiltrates any content the model has placed in the container (including tool results from other servers in the same client session) to an external host; fork bombs or long-running processes with no timeout consume the per-user allocation.
- Failure mode: model-authored code with side effects on the internet (posting, emailing, purchasing) executes without review (PB-O).

**Cross-Layer Impact**
- L6 (egress), L1 (platform), L9 (only an active-count metric is emitted, `containerManager.ts:58`), L10 (abuse attribution).

**Likelihood / Impact / Risk**
- Likelihood: Medium for egress abuse (requires injected or malicious instruction; no upstream write scopes are exposed). Unassessable for escape.
- Impact: Medium (bounded to the user's own container and what the model puts in it; no Cloudflare write credentials are present).
- Risk: Medium, provisional.

**Recommended Mitigations**
- Default `enableInternet: false` with an allowlisted egress proxy (package registries), or a per-session opt-in flag surfaced to the user (AIS-13 Sandboxing; CCC-01–09 for the container change-control path; L1 egress filtering per the MAESTRO L1 network component list; OWASP Playbook 3 execution sandboxes).
- Apply `timeout` and `maxBuffer` to `exec`; add a non-root `USER` to the Dockerfile; normalize and contain file paths under `workdir`.
- Check `USER_BLOCKLIST` on every container tool and reap the DO on block.
- Fix the `in active` check to `active.includes(...)`; test reaping and limits.
- Correct the model-facing image description (`prompts.ts:6`) and the README lifetime claim so the model's plans match the runtime.

**SSRM Ownership**
- Primary (L5 matrix): CSP (Cloudflare Containers isolation) and OSP (container configuration and image, here Cloudflare as Tool Provider operating the Worker)
- Shared: AP; AIC configures (whether to connect the sandbox server at all)
- Structural AICM gap 6 (agent lifecycle): the per-user container has its own create / run / reap lifecycle (`containerManager.ts:40-41`, `userContainer.ts:24-32`) with a blocklist that applies only at creation; AICM's service-lifecycle controls do not assign responsibility for mid-life revocation.
- Agent Owner accountable: yes (always)

**Required Evidence to Fully Answer**
- Cloudflare Containers isolation and egress documentation; image user resolution; quota configuration.

---

### L7-T02 Credential theft and replay: upstream Cloudflare tokens held and cached by the server (MCP01:2025; MCP07:2025; Part 3 Token Persistence, Cached Identity Assertions; ATLAS AML.T0055 Unsecured Credentials, AML.T0091.000 Application Access Token)

**MAESTRO Layer**
- L7: Identity & Autonomy (Domain 3)

**Current Evidence**
- Upstream Cloudflare access and refresh tokens are placed in grant `props` (`cloudflare-oauth-handler.ts:670-676`; schema `auth-props.ts:20-32`) and persisted by `OAuthProvider` in `OAUTH_KV`; how the library protects them at rest is not verifiable here.
- Refresh token TTL 30 days (`oauth-router.ts:102`); access token TTL 1 hour (`:101`), then follows upstream `expires_in` on refresh (`cloudflare-oauth-handler.ts:399-405`).
- Direct API-token identity is cached under `api-token-identity:v1:<sha256(token)>` for 30 days (`api-token-mode.ts:75, :100`); tool calls use the token itself (`:71-73`), and account tokens are rejected on refresh (`cloudflare-oauth-handler.ts:346-352`).
- The `__Host-MCP_APPROVED_CLIENTS` cookie is HMAC-SHA256 signed with a one-year lifetime (`workers-oauth-utils.ts:5-6, :601`) and lets the consent screen be skipped (`cloudflare-oauth-handler.ts:496-511`). `MCP_COOKIE_ENCRYPTION_KEY` is referenced (`:69`) but declared in no wrangler or example file.
- Dynamic client registration is enabled (`oauth-router.ts:100`); redirect-URI validation is tested (`cloudflare-oauth-handler.spec.ts:602, :629`); RFC 8707 resource matching is exact (`oauth-router.spec.ts:46`; `auth-integration.spec.ts:156`).
- Dev bypass: `devApiTokenModeEnabled` requires `DEV_DISABLE_OAUTH === 'true'` (`api-token-mode.ts:150`), but `getCloudflareClient` and `fetchCloudflareApi` use a truthy check `if (env.DEV_DISABLE_OAUTH)` (`cloudflare-api.ts:10, :44`) and substitute `DEV_CLOUDFLARE_API_TOKEN` for the caller's token. No `wrangler.jsonc` sets `DEV_DISABLE_OAUTH`; `.gitignore:4` excludes `.dev.vars`.
- Sentry excludes `Authorization` and keeps only the `scope` query parameter (`sentry.ts:69-80`); no `console.*` call logs tokens or props; the mcp-common README states "Do not log raw tokens or authentication props" (`packages/mcp-common/README.md:73`).
- Sentry DSNs with embedded keys are committed in three apps (`workers-builds/wrangler.jsonc:70, :94`; `workers-observability/wrangler.jsonc:77, :119`; `docs-ai-search/wrangler.jsonc:58, :81`), and the transport sends `CF-Access-Client-ID`/`Secret` from env (`sentry.ts:96-101`).

**Reasonable Inferences**
- The server is a long-lived custodian of upstream credentials for every connected user: 30-day refresh tokens for OAuth users and 30-day identity cache entries keyed by token hash. A KV read primitive (compromised Worker, misconfigured binding, insider) yields account access at the scope of every connected user.
- The truthy check is latent: any non-empty value for `DEV_DISABLE_OAUTH` in a production env (e.g. `"false"`) would route every user's API calls through one shared token, a cross-tenant confused-deputy. Not evidenced as configured; evidenced as a one-line misconfiguration away.
- Sentry DSNs are write-only ingest keys; their exposure enables event spam, not read access.

**Unknowns / Missing Evidence**
- `OAuthProvider` props encryption and KV key management; DCR client-authentication policy; upstream token scope revocation on grant deletion.

**Assessment Status**
- Partially answerable.

**Attack Vector**
- Theft of `OAUTH_KV` contents or of a Worker with the binding; replay of a stolen 30-day refresh token; misconfiguration of `DEV_DISABLE_OAUTH` in a deployed env.

**Cross-Layer Impact**
- L1 (KV, Worker), L6 (every write tool executes under the stolen token), L9 (userId-only metrics cannot distinguish replay from the legitimate user), L10.

**Likelihood / Impact / Risk**
- Likelihood: Low for theft (requires infrastructure compromise); Low for misconfiguration (not present, one-line away).
- Impact: High (account-wide, all connected users).
- Risk: Medium.

**Recommended Mitigations**
- Replace the truthy checks in `cloudflare-api.ts:10, :44` with `devApiTokenModeEnabled(env)` and add a production guard that throws if `DEV_*` vars are present when `ENVIRONMENT === 'production'`.
- Document and verify grant-props encryption (or encrypt `accessToken`/`refreshToken` in props with a Worker secret before `completeAuthorization`); shorten the identity cache and refresh TTLs, or bind refresh to client re-authentication after a shorter window (IAM-01–19 credential lifecycle and short-lived/JIT credential components of L7; CEK-01–21 for encryption at rest at L1; MCP01 controls: vaulted secrets, session-bound short-lived tokens).
- Declare `MCP_COOKIE_ENCRYPTION_KEY` in the deployment contract (`.dev.vars.example`, CONTRIBUTING) or remove the dead reference.
- Move Sentry DSNs to secrets to keep ingest keys out of the public tree.

**SSRM Ownership**
- Primary (L7 matrix): AIC (AP) — `Partial — depends on deployment model`
- Shared: CSP (KV, Workers isolation, certificates), OSP, AP, Tool Provider
- Implementing party: Tool Provider (Cloudflare holds and refreshes the upstream tokens). The AIC cannot change custody; it can shorten exposure by revoking grants and by choosing API-token mode with short-lived tokens.
- Agent Owner accountable: yes (always)

**Required Evidence to Fully Answer**
- `@cloudflare/workers-oauth-provider` 0.10.3 storage documentation; production env var inventory.

---

### L7-T03 Over-privileged and mis-described scopes; consent-screen accuracy (MCP02:2025; PB-A; Part 3 Stale Trust Decisions, Authorization Bypass; ATLAS AML.T0053 AI Agent Tool Invocation)

**MAESTRO Layer**
- L7: Identity & Autonomy (Domain 3)

**Current Evidence**
- The authorize handler overwrites whatever scopes the client requested with the app's full list (`oauthReqInfo.scope = Object.keys(scopes)`, `cloudflare-oauth-handler.ts:493`), so a client cannot request a narrower grant than the app defines.
- Write scopes per app: `workers:write` + `d1:write` (workers-bindings, `bindings.app.ts:16-19`), `browser:write`, `dex:write`, `logpush:write`, `url_scanner:write`, `rag:write` (`packages/mcp-common/src/scopes.ts:2-5` plus each `*.app.ts`).
- Three read scopes carry "See and change" consent descriptions: `workers:read` and `workers_builds:read` in workers-builds (`workers-builds.app.ts:24-27`) and `workers:read` in workers-observability (`workers-observability.app.ts:15-16`).
- Tools registered with plain `registerTool` receive no `AccountManager` resolution or ownership check: `graphql_api_explorer` (`graphql.tools.ts:1077`), `dns_report`/`show_zone_dns_settings` (`dex-analytics.tools.ts:19-28, :102-117`), all radar tools, all container tools; `zone_details` ignores the resolved account (`zone.tools.ts:93`). Account-scoped tools validate header/argument account IDs against the token's account list (`account-manager.ts:74-117`; tested at `account-manager.spec.ts:82, :91`, `account-tool.spec.ts:87`).
- Multi-account tokens receive a list of every accessible account in the server instructions (`account-manager.ts:110-116`; `server.ts:72-78`).
- The account list used for the ownership check is the `/accounts` snapshot captured when the grant was issued and carried in props (`cloudflare-oauth-handler.ts:180-182, :663-677`; consumed at `account-manager.ts:88-96`), not re-fetched per call, so an account removed upstream stays selectable until the grant is refreshed (Part 3 Stale Trust Decisions; IAM-07, CCC-04). The upstream API still rejects the call.

**Reasonable Inferences**
- Least privilege is available only at app granularity. A user who wants `kv_namespaces_list` must grant `workers:write` and `d1:write`.
- The "See and change" descriptions on read scopes misinform the consent decision in the safe direction (over-warning), but they are still inaccurate consent text; the mismatch suggests descriptions are copied rather than reviewed.
- Tools without account resolution rely wholly on the upstream Cloudflare API to enforce token scope; that is Cloudflare's own API, so the practical exposure is the loss of the server-side ownership check as defense in depth, not a bypass.

**Unknowns / Missing Evidence**
- Whether Cloudflare's OAuth server supports finer scopes the app could split into read-only and write variants.

**Assessment Status**
- Answerable.

**Attack Vector**
- Failure mode: standing write grants enlarge the blast radius of every other finding (L3-T04, L4-T07) without the user having chosen them. Adversarial: any compromised client or stolen token inherits the widest scope the app offers.

**Cross-Layer Impact**
- L4, L6, L10 (consent accuracy).

**Likelihood / Impact / Risk**
- Likelihood: High that grants exceed need for read-only use cases (structural).
- Impact: Medium.
- Risk: Medium.

**Recommended Mitigations**
- Split workers-bindings into read and write server variants, or honor a client-requested scope subset at `:493` intersected with the app's list (MCP02 least-privilege-by-design scope maps).
- Correct the three scope descriptions; add a unit test that asserts every `*:read` scope description contains no "change".
- Route the zone, radar, and graphql tools through `accountTool()` or an equivalent ownership check.

**SSRM Ownership**
- Primary (L7 matrix): AIC (AP) — grant review and acceptable-use configuration (GRC-09); `Partial — depends on deployment model`
- Shared: CSP, OSP, AP (scope request behavior), Tool Provider (scope definitions and consent text, implementing party)
- Agent Owner accountable: yes (always)

**Required Evidence to Fully Answer**
- Cloudflare OAuth scope catalog.

---

### L4-T07 / L7-T02 Approval reuse: one-year approved-clients cookie skips consent (Part 3 Approval Reuse; IAM-18; ATLAS AML.T0012 Valid Accounts)

**MAESTRO Layer**
- L4: Orchestration & Coordination (HITL surface) and L7: Identity & Autonomy (Domain 2 / Domain 3)

**Current Evidence**
- A signed `__Host-MCP_APPROVED_CLIENTS` cookie records client IDs the user has approved once; when present for the requesting `clientId`, the authorize handler skips the consent screen and redirects straight to the upstream Cloudflare OAuth flow (`cloudflare-oauth-handler.ts:496-511`).
- The cookie lifetime is one year (`workers-oauth-utils.ts:5-6, :601`, `HttpOnly; Secure; SameSite=Lax`), HMAC-SHA256 signed with `MCP_COOKIE_ENCRYPTION_KEY` (`:41-87`), and that key is declared in no wrangler, example, or contributing file.
- Redirect-URI validation on the authorize request is tested (`cloudflare-oauth-handler.spec.ts:602, :629`), and dynamic client registration is open at `/register` (`oauth-router.ts:100`).

**Reasonable Inferences**
- Consent is a one-time event per client for a year. A user who approved a client in January sees no scope screen when the same client re-authorizes in November, including after the app's scope list has changed (the server overwrites requested scopes with its current list at `:493`).
- The cookie does not grant tokens by itself; the upstream Cloudflare login still runs. The exposure is the silent re-grant, not credential theft.

**Unknowns / Missing Evidence**
- Behavior when `MCP_COOKIE_ENCRYPTION_KEY` is unset in a deployment (signature verification path); whether a scope-list change invalidates prior approvals.

**Assessment Status**
- Partially answerable.

**Attack Vector**
- Failure mode (no adversary required): scope expansion in a later release is never re-consented for existing users. Adversarial: a client that keeps its registration can re-enter the grant flow for a year without a consent checkpoint the user would notice.

**Cross-Layer Impact**
- L7-T03 (scope changes propagate without consent), L10 (consent accuracy).

**Likelihood / Impact / Risk**
- Likelihood: Medium (structural; fires on any scope change).
- Impact: Low.
- Risk: Low-Medium.

**Recommended Mitigations**
- Bind the approval cookie to a hash of the scope list so any scope change forces re-consent; shorten the approval window to 30–90 days (IAM-18 Special Authorization; IAM-07 Access Revocation; FAIR-CAM VMC Correction).
- Declare `MCP_COOKIE_ENCRYPTION_KEY` in the deployment contract and fail closed when absent.

**SSRM Ownership**
- Primary (L4/L7 matrix): OSP for L4, AIC/AP for L7 — `Partial — depends on deployment model`
- Shared: CSP, MP, AP, Tool Provider
- Implementing party: Tool Provider (Cloudflare). Structural AICM gap 3 (the approval decision is automated by the server rather than made by a person).
- Agent Owner accountable: yes (always)

**Required Evidence to Fully Answer**
- Key-handling path when the encryption key is absent; scope-change re-consent policy.

---

### L6-T06 API abuse and data exposure through high-reach tools (Part 3 Agent-to-SaaS Trust Abuse; ATLAS AML.T0086 Exfiltration via AI Agent Tool Invocation, AML.T0057 LLM Data Leakage)

**MAESTRO Layer**
- L6: Tools, Application, Ecosystem (Domain 2)

**Current Evidence**
- `create_url_scan` defaults visibility to `Public` (`apps/radar/src/types/url-scanner.ts:29-31`; applied at `url-scanner.tools.ts:88, :114`); the parameter description does state that public scans appear in search results (`url-scanner.ts:34`); scans are indexed and returned with page data, verdicts, and full HAR (`:169-180, :278-283`).
- `graphql_query` POSTs raw client-supplied GraphQL and variables unmodified (`graphql.tools.ts:1015-1016, :274-288`) with no client-side mutation block; mutation refusal is delegated to the upstream API and merely logged (`:255-257`).
- `d1_database_query` forwards raw SQL and params to `client.d1.database.query` (`d1.tools.ts:212-216`).
- `dex_create_remote_pcap` and `dex_create_remote_warp_diag` issue capture commands to employee devices (`dex-analysis.tools.ts:231-253, :277-299`); diag archives are downloaded into a Durable Object keyed by token hash + device + command (`warp_diag_reader.ts:117, :132-134`) and files are returned raw by path (`:44-47`).
- Browser-rendering tools accept any `url` (`browser.tools.ts:27`), raw CSS selectors (`:277-284`), and a free-text extraction `prompt` with `json_schema: z.unknown()` (`:329-336`); `start_crawl` launches multi-page crawls (`:430-436`).
- `hyperdrive_config_edit` accepts host, port, user, and database (`hyperdrive.tools.ts:186-198`).
- Audit-log results keep `actor_email` and `actor_token_name` (`auditlogs.tools.ts:225-234`); no output redaction exists anywhere.

**Reasonable Inferences**
- A URL containing a session token, signed link, or internal hostname submitted to `create_url_scan` becomes a public record by default; the visibility text is on the optional parameter, so a model that omits the parameter gets the public default without having weighed it.
- Hyperdrive edits can repoint a production database connection to an attacker host; combined with L4-T07 this runs with no confirmation.
- Browser fetches originate from Cloudflare's rendering service, so classic SSRF to the deployer's private network is not evidenced; abuse is bounded to third-party targets and to content injection (L3-T04).

**Unknowns / Missing Evidence**
- Whether the Browser Rendering service blocks private ranges; whether D1 query is transactional per call.

**Assessment Status**
- Answerable.

**Attack Vector**
- Adversarial via L3-T04 or a compromised client; failure mode via PB-O (model submits secrets to a public scan, edits a Hyperdrive origin, or runs unintended SQL).

**Cross-Layer Impact**
- L3 (disclosure), L7 (device-level actions under `dex:write`), L10 (employee-device capture obligations).

**Likelihood / Impact / Risk**
- Likelihood: Medium.
- Impact: High for Hyperdrive/D1/DEX; Medium for public scans.
- Risk: Medium-High.

**Recommended Mitigations**
- Default `create_url_scan` visibility to `Unlisted` and move the visibility statement into the tool description; redact query strings from scanned URLs in returned results.
- Add a client-side GraphQL mutation block (parse the document and reject `mutation` operations) and a D1 DDL/multi-statement guard behind an explicit flag.
- Require elicitation for Hyperdrive edits and DEX captures (see L4-T07); add a circuit breaker on `start_crawl` depth and page limits (L6 circuit-breaker component; TVM-01–13).
- Redact `actor_email` unless the caller passes an explicit `include_actor_identity` flag.

**SSRM Ownership**
- Primary (L6 matrix, three primaries): OSP, AP, Tool Provider. Here the Tool Provider (Cloudflare) is the evidenced primary; the AP (client) is primary for how the tools are exposed to the user; no OSP exists.
- Shared: MP (URL Scanner and Browser Rendering models where used), AIC (STA-16 Service BOM: the AIC must inventory which of the 18 servers its users connect)
- Structural AICM gap 2 applies (runtime tool binding across 18 discoverable servers).
- Agent Owner accountable: yes (always)

**Required Evidence to Fully Answer**
- Browser Rendering egress policy.

---

### L9-T01 Monitoring blind spots: no invocation-level audit record (MCP08:2025; Part 3 Monitoring Blind Spots)

**MAESTRO Layer**
- L9: Monitoring & Observability (Domain 3)

**Current Evidence**
- The only per-invocation record is the Analytics Engine `ToolCall` datapoint with `userId`, `toolName`, `errorCode` (`packages/mcp-observability/src/metrics.ts`; emitted at `registration-context.ts:163-173`). Tool arguments and results are not logged anywhere.
- `McpRequest` records client name/version, protocol era, client ID, and capability flags (`packages/mcp-observability/src/metrics.ts:34-66`); `AuthUser` records userId or error (`packages/mcp-observability/src/metrics.ts:69-86`).
- Workers observability is enabled with `head_sampling_rate: 0.1` in all 17 `wrangler.jsonc` files; no `tail_consumers` or logpush configuration exists.
- Account-token callers are recorded with `userId: undefined` (`request-context.ts:26-28`).
- No retention, immutability, or IR-query capability for the Analytics Engine datasets is stated in the repo.
- `apps/auditlogs` reads Cloudflare's product audit logs; it is not an audit log of this service.

**Reasonable Inferences**
- Skill rule 4 applies directly: this is product telemetry, not security audit logging. After an incident, the operator can say which tool a user called and whether it errored, but not with what arguments, against which resource, or what came back. Replay of a stolen token (L7-T02) is indistinguishable from the user.
- Upstream Cloudflare audit logs capture the resulting API mutations under the user's token, so reconstruction is possible from the product side, without linkage to the MCP session or the tool call that caused it.

**Unknowns / Missing Evidence**
- Analytics Engine retention; whether Cloudflare's internal logging of the hosted Workers captures request bodies.

**Assessment Status**
- Answerable for the repo.

**Attack Vector**
- Not adversarial in itself; it removes detection and forensics for every other finding.

**Cross-Layer Impact**
- L7, L6, L10-T05.

**Likelihood / Impact / Risk**
- Likelihood: High (structural).
- Impact: Medium.
- Risk: Medium.

**Recommended Mitigations**
- Emit an append-only, identity-correlated invocation record for write and exec tools (tool, account, resource IDs, argument hash or redacted arguments, result status, client ID, cf-ray) to a retained store, stored separately from the Worker execution environment and tamper-evident (WORM) per the L9 component list (LOG-01–15, LOG-14–15 I/O Monitoring); add a session or request correlation ID that the upstream Cloudflare API can carry (e.g. a custom header) so product audit logs link back to MCP calls (MCP08; bilateral receipt pattern in `agentic-skills-top10.md`). This also closes L8-T04 (incident-response blind spots): no SOC-consumable signal exists for a misused grant.
- Record account-token callers by token-name hash rather than `undefined`.

**SSRM Ownership**
- Primary (L9 matrix): AIC integrates — `Partial — depends on deployment model`
- Shared: CSP (infrastructure monitoring), MP (MDS-10 model monitoring for AutoRAG), OSP, AP (client-side logging of tool calls and arguments, which is the AIC's only available invocation record today), Tool Provider (implementing party for server-side telemetry)
- Agent Owner accountable: yes (always)

**Required Evidence to Fully Answer**
- Retention and access policy for `mcp-metrics-production`.

---

### L5-T02 / L1-T01 CI/CD and supply-chain posture (MCP04:2025; ATLAS AML.T0010.004 Container Registry, AML.T0010.001 AI Software)

**MAESTRO Layer**
- L5: Deployment & Execution (Domain 2); L1: Infrastructure (Domain 1)

**Current Evidence**
- Every dependency is exact-pinned: syncpack `range: ''` (`.syncpackrc.cjs:80-83`) enforced by `pnpm check:deps` in CI (`branches.yml:21`, `main.yml:25`); five MCP packages are catalog-pinned (`pnpm-workspace.yaml:5-12`); lockfile v9 with 971 sha512 integrity entries; `--frozen-lockfile` install (`.github/actions/setup/action.yml:25`); install scripts restricted to esbuild, sharp, workerd (`package.json:43-47`).
- No Dependabot or Renovate configuration; updates are manual via `syncpack update` (`package.json:25`). No SBOM, provenance, signing, or attestation tooling (grep for sbom, provenance, cosign, sigstore, slsa, attest, cyclonedx, spdx: nothing).
- All GitHub Actions are tag-pinned, none SHA-pinned (`actions/checkout@v4`/`@v5`, `actions/cache@v5`, `changesets/action@v1`, `pnpm/action-setup@v4`, `actions/setup-node@v4`).
- Staging deploys on every push to `main` (`main.yml:34`) and production deploys when changesets reports `published == 'true'` (`release.yml:63-66`), both with `CLOUDFLARE_API_TOKEN`; no GitHub `environment:` gate or manual approval exists. `release.yml:35` interpolates the published-packages output into a shell `echo`.
- Semgrep `--config=auto` runs on PRs, pushes, and monthly (`semgrep.yml:3-8, :30`).
- The container base image is tag-pinned (`FROM alpine:3.19`, `Dockerfile:2`); `apk add`, `npm install -g pnpm`, and `pnpm install turbo --global` are unpinned (`:7-20, :27, :45`); the deployed image is referenced by short-SHA tag, not digest (`registry.cloudchamber.cfdata.org/sandbox-container:d802004`, `apps/sandbox-container/wrangler.jsonc:87, :136`), and is built and pushed by a manual script outside CI (`apps/sandbox-container/package.json:10`).
- KV namespace IDs for `OAUTH_KV` are shared across dns-analytics, dex-analysis, workers-builds, and workers-observability (`a6ad2420...`, `753f27a1...`).

**Reasonable Inferences**
- Dependency pinning is strong; update discipline is manual and unaudited, so a vulnerable pinned version persists until someone runs syncpack.
- A compromised tag on any listed action executes with `CLOUDFLARE_API_TOKEN` on push to `main` and deploys to every hosted server; the token's scope is unknown.
- The sandbox image supply chain has no reproducibility or attestation: the running image cannot be tied to a reviewed Dockerfile revision by digest.
- Shared `OAUTH_KV` across four apps means one app's grant store is readable by the other three Workers' bindings.

**Unknowns / Missing Evidence**
- Branch protection, required reviews, `CLOUDFLARE_API_TOKEN` scope, registry access controls.

**Assessment Status**
- Partially answerable.

**Attack Vector**
- Tag-mutation or maintainer-account compromise of a third-party action; manual image push from a compromised developer machine.

**Cross-Layer Impact**
- L6-T04 (every hosted server), L7-T02 (all user tokens transit a compromised Worker), L1-T04.

**Likelihood / Impact / Risk**
- Likelihood: Low.
- Impact: High.
- Risk: Medium.

**Recommended Mitigations**
- SHA-pin actions; add `environment: production` with required reviewers to `release.yml`; scope `CLOUDFLARE_API_TOKEN` per app or per environment; avoid shell interpolation of workflow outputs.
- Build and push the sandbox image in CI, reference it by digest, pin `apk`/`npm` versions, and publish an SBOM and provenance attestation for the image (STA-16 BOM, MDS-09 signing).
- Enable Dependabot or Renovate with the pin policy preserved.
- Separate `OAUTH_KV` namespaces per app.

**SSRM Ownership**
- Primary (L5 and L1 matrices): CSP (GitHub, registry, Workers platform) and OSP (Cloudflare as operator of the Worker code and image)
- Shared: AP; AIC configures (STA-01–16 supplier due diligence, STA-16 Service BOM; AI-CAIQ as the verification instrument)
- Agent Owner accountable: yes (always)

**Required Evidence to Fully Answer**
- GitHub repository settings; token scope.

---

### L10-T02 / L10-T05 Governance and consent gaps (Part 3 Agent Onboarding Abuse)

**MAESTRO Layer**
- L10: Governance & Compliance (Domain 3)

**Current Evidence**
- No `SECURITY.md`, no `CODEOWNERS`, no security issue template; the only template is a bug report (`.github/ISSUE_TEMPLATE/bug_report.md`).
- `server.json` (schema `2025-07-09`) lists 12 remotes; the README lists autorag, radar, and demo-day (`README.md:22, :26, :28`), which are absent from `server.json`; four apps carry deprecation notices in their instructions (auditlogs, autorag, graphql, radar).
- Documentation claims not matched by code: "run arbitrary code ... in a secure, sandboxed environment" (`apps/sandbox-container/README.md:5`) against a root-default, internet-enabled shell; "~10m" against 15-minute reaping; "don't save any state" against a per-user DO; "Ubuntu 20.04" against Alpine (Section 5).
- Consent-screen scope descriptions are wrong for three read scopes (L7-T03).
- No data-handling, retention, or privacy statement exists in `README.md` or `implementation-guides/*`; DEX capture tools act on employee devices with advisory-only confirmation text.
- Apache-2.0 license (`LICENSE:1-2`); all packages `private: true`; no npm provenance.

**Reasonable Inferences**
- A user connecting to a deprecated server (autorag, radar, graphql, auditlogs) that is still listed in the README but absent from `server.json` has no governance signal about support status beyond the runtime instruction string; this is the L10-T01 shadow pattern in mild form.
- The documentation mismatches indicate no doc-against-code review step; the safe-direction errors (over-warning scopes, shorter-than-actual lifetime) reduce but do not remove the concern.

**Unknowns / Missing Evidence**
- Cloudflare's external vulnerability disclosure route (may exist outside the repo); repository settings.

**Assessment Status**
- Partially answerable.

**Attack Vector**
- Not adversarial; governance absence compounds every other finding's time-to-detect and time-to-fix.

**Cross-Layer Impact**
- L7 (consent), L5, L9.

**Likelihood / Impact / Risk**
- Likelihood: High (structural).
- Impact: Low-Medium.
- Risk: Low-Medium.

**Recommended Mitigations**
- Add `SECURITY.md` pointing to Cloudflare's disclosure program and `CODEOWNERS` for `packages/mcp-common` and `apps/sandbox-container`; reconcile `server.json` with the README and mark deprecated servers as such in the manifest.
- Add a doc-claims test or review checklist for the sandbox README, prompts, and scope descriptions.
- Publish a short data-handling statement (what is stored, for how long, where: grant props, identity cache, warp-diag archives, Analytics Engine).

**SSRM Ownership**
- Primary: AIC. "In all three deployment models, Layer 10 (Governance) remains with the Agent Owner. Governance cannot be outsourced." (3SRM §8.2, quoted per `ssrm-ownership.md`)
- All providers consume/configure: Cloudflare supports the AIC's governance through attestations (A&A-01–06) and the repository governance artifacts named above; their absence is a Tool Provider deficiency the AIC must compensate for in its own GRC-09 acceptable-use policy and STA-16 inventory
- Agent Owner accountable: yes (non-delegable)

**Required Evidence to Fully Answer**
- Cloudflare disclosure program reference; repo settings.

---

## 10. Lens Results

Rule 9 disposition. Five lenses in fixed order; each states its trigger or its absence.

### 10.1 PHANTOM-B

**Trigger**: every server assembles instructions and tool descriptions for a client LLM, and two tools call a model server-side (`ai_search`, `get_url_json`). **Source**: Shostack + Associates White Paper #6, PHANTOM-B v1.0 Q3 2026, CC-BY, from `references/phantom-b.md`.

PHANTOM-B was run once against the servers' prompt-assembly surface (instructions, tool descriptions, returned content) and once against the two server-side LLM calls (`ai_search`, `get_url_json`). Letters that attach to an existing MAESTRO finding are recorded inside that Section 9 block and summarized here; letters that MAESTRO has no threat ID for are recorded in full below, anchored to L2 per the T16 convention. PHANTOM-B ships no mitigations by design; every control cited comes from MAESTRO, AICM, or the OWASP playbooks.

| Letter | Adversary? | What the lens found | Recorded in | Status |
|---|---|---|---|---|
| **P** Prompt injection | Yes | Indirect sub-type dominates: 30+ tools fetch or retrieve content on demand with no data framing; the `workers-prompt-full` prompt arrives as a `user`-role message; multi-turn detection absent | Section 9, L3-T04; descriptions block below | Answerable |
| **H** Hallucination | No (inducible) | `ai_search` output is generated text in the same result format as retrieved documents; eval judge (`gpt-5.4-nano`) baseline unmeasured; evals not in CI | Block below | Partial |
| **A** Anthropomorphization | No | Sandbox prompt tells the model about an unregistered `container_files` resource and an Ubuntu image that is Alpine; vendor-steering imperatives ("prefer this over web search"); consent text says "See and change" on read scopes | Block below; Section 9, L7-T03 | Answerable |
| **N** Non-explainability | No | No decision-making or regulated-explanation surface; reconstruction capability is the L9-T01 finding | No instance | Not applicable |
| **T** Training issues | Both | Models are the client's and Cloudflare's; no training or fine-tuning surface in the repo; artifact needed: AutoRAG generation model card | No instance | Unanswerable |
| **O** Over-reliance | No (amplifier) | Destructive tools run with no confirmation; `d1_database_query` marked non-destructive; DEX device captures with advisory-only confirmation text; container runtime reach (no `USER`, internet egress, no write scopes); public URL-scan default reached by omitting an optional parameter | Section 9, L4-T07, L5-T04, L6-T06; Section 11, Path 4 | Answerable |
| **M** Missing security engineering | Condition | Non-LLM paths are tested (143 cases), Semgrep in CI, exact pinning; gaps routed to L5-T02, L9-T01, L10 | Section 9, those blocks | Answerable |
| **B** Biases | No | No bias-sensitive decision surface | No instance | Not applicable |

Net contribution: two findings with no MAESTRO threat ID (H, A), the no-adversary reading of L4-T07 and Path 4 (O), and the expansion of L3-T04 from a category into a per-tool inventory (P).

### L2 Server-side LLM output returned unlabeled (PB-H; no canonical L2-T ID; ATLAS AML.T0067.000 Citations for the adversarial variant)

**MAESTRO Layer**
- L2: Cognitive Core (Domain 1), anchored to the layer per the T16 convention

**Current Evidence**
- `ai_search` returns the raw generated response of the AutoRAG model as tool text (`autorag.tools.ts:133, :142-148`), indistinguishable in format from `search`, which returns retrieved documents (`:85-95`).
- `get_url_json` performs AI extraction driven by a free-text `prompt` and returns the result as data (`browser.tools.ts:323-359`).
- The eval harness scores tool-use factuality with an LLM judge (`gpt-5.4-nano`, `test-models.ts:42-48`) using an autoevals rubric (`scorers.ts:12-68`); evals are not run in CI (`eval:ci` defined at `package.json:23` and `turbo.json:24`, referenced by no workflow).
- No hallucination-rate measurement, grounding check, or citation verification exists for either server-side LLM call.

**Reasonable Inferences**
- A client model receiving `ai_search` output cannot distinguish generated text from retrieved fact and will treat it with the authority of a tool result (a model-to-model relay of the PHANTOM-B hallucination pattern).
- The eval judge's own hallucination rate is unmeasured; a failing eval can pass on a lenient judge.

**Unknowns / Missing Evidence**
- Which model AutoRAG uses for generation; any grounding configuration in the AutoRAG instance.

**Assessment Status**
- Partially answerable.

**Attack Vector**
- Failure mode (no adversary required): generated text with fabricated facts or invented URLs is returned as a tool result and acted on. Inducible: indexed content (L3-T04) steers the generation.

**Cross-Layer Impact**
- L3 (retrieval corpus), L8 (no output validation), L10 (no eval gate on release).

**Likelihood / Impact / Risk**
- Likelihood: Unassessable from current evidence (no measured rate).
- Impact: Medium.
- Risk: Provisional Medium.

**Recommended Mitigations**
- Label `ai_search` output as model-generated in the result text and return the retrieved sources alongside it in `structuredContent` (AIS-09 output validation).
- Run evals in CI with a measured judge baseline; add a grounding assertion (every URL in output appears in retrieved chunks).

**SSRM Ownership**
- Primary (L2 matrix): MP (AutoRAG generation model) for root cause
- Shared: CSP, OSP; Tool Provider (Cloudflare) is the implementing party for labeling
- AIC configures (model selection for AutoRAG instances; safety SLA for hallucination rate per 3SRM §6.2)
- Agent Owner accountable: yes (always)

**Required Evidence to Fully Answer**
- AutoRAG model and grounding configuration; eval results.

---

### L2 Instructions and descriptions that direct the client model (PB-A, PB-P; MCP03:2025 hygiene; ATLAS AML.T0084.001 Tool Definitions as the discovery surface)

**MAESTRO Layer**
- L2: Cognitive Core (Domain 1), system-prompt/persona surface

**Current Evidence**
- Tool descriptions carry model-directed imperatives: "Prefer this over web search... Use even when you think you know the answer" (`stack.tools.ts:92`), "ALWAYS read this guide before migrating" (`docs-ai-search.tools.ts:84`), "Set a high limit (1000+)" (`workers-observability.tools.ts:199`), "This should be the first place you start" (`dex-analysis.tools.ts:552`), "call ... repeatedly in parallel" (`:519-521`).
- The sandbox instructions address the model in the second person, tell it it "may install additional packages" (`prompts.ts:16`), describe a `container_files` resource that is not registered (`:24-25`), and misstate the base image (`:6`).
- The `demo-day` tool appends "Use it to answer the user's questions" after an HTML resource (`demo-day.app.ts:22-36`).
- Descriptions are static in the repository; no dynamic description fetching exists.

**Reasonable Inferences**
- For the hosted endpoints, these are Cloudflare-authored steering instructions, not poisoning; MCP03 applies only to a forked or mirrored deployment where the tree could be altered. The hygiene concern is that clients cannot distinguish vendor steering ("prefer this over web search") from user intent.
- The `container_files` phantom resource and the wrong base image are PB-A in practice: the model is told a capability and environment it does not have, and will plan against them.

**Unknowns / Missing Evidence**
- None material for the hosted case.

**Assessment Status**
- Answerable.

**Attack Vector**
- Failure mode (no adversary required): model follows vendor steering over user instruction or plans against a described capability that does not exist.

**Cross-Layer Impact**
- L6, L4.

**Likelihood / Impact / Risk**
- Likelihood: Medium (structural).
- Impact: Low.
- Risk: Low.

**Recommended Mitigations**
- Remove behavioral imperatives from descriptions and keep them in `instructions`, where clients can display them; correct the sandbox prompt to the actual image and remove the unregistered resource; add a static screen in CI for model-directed imperatives in descriptions (MCP03 pre-connection screening, applied to the vendor's own tree).

**SSRM Ownership**
- Primary (L2 matrix): MP; the system-prompt/persona component is AIC-configured per `maestro-layers.md`, but here the instructions are authored by the Tool Provider, which the matrix does not place at L2 (gap 2 again)
- Shared: CSP, OSP; implementing party Tool Provider
- Agent Owner accountable: yes (always)

**Required Evidence to Fully Answer**
- None.

---

### PHANTOM-B letters with no evidenced instance

- **PB-N Non-explainability**: no decision-making or regulated-explanation surface is evidenced; the servers execute explicit tool calls. Unanswerable and not applicable at this layer; reconstruction capability is covered by L9-T01.
- **PB-T Training issues**: the models are the client's and Cloudflare's (AutoRAG, Workers AI eval models); no training or fine-tuning surface is in the repo. `Unanswerable from current evidence`; artifact needed: model cards for the AutoRAG generation model.
- **PB-B Biases**: no bias-sensitive decision surface evidenced. Not applicable.
- **PB-M Missing security engineering**: the non-LLM components have tested auth, transport, and scoping paths (143 cases), Semgrep in CI, and exact pinning. The gaps are recorded under L5-T02, L9-T01, and L10 rather than as a separate finding.

Attribution: PHANTOM-B by Adam Shostack, Shostack + Associates White Paper #6 (v1.0, Q3 2026), CC-BY, https://shostack.org/files/papers/PHANTOM-B_Whitepaper_Shostack.pdf.

### 10.2 OWASP MCP Top 10 (MCP01:2025–MCP10:2025)

**Trigger**: the system is a set of MCP servers (`packages/mcp-common/src/server.ts:73`, `oauth-router.ts:28`). **Source**: OWASP MCP Top 10, Phase 3 beta, CC BY-NC-SA 4.0, from `references/mcp-top10.md`; own-words throughout, NonCommercial term applies to reuse of OWASP text.

| MCP | Applies? | What the lens found | Recorded in | Status |
|---|---|---|---|---|
| MCP01 Token mismanagement | Yes | Upstream access and refresh tokens in grant props (`cloudflare-oauth-handler.ts:670-676`), 30-day refresh (`oauth-router.ts:102`), 30-day identity cache keyed by token hash (`api-token-mode.ts:75, :100`); no token logging (checked); Sentry DSNs committed | L7-T02 | Partial (props encryption unverifiable) |
| MCP02 Scope creep | Yes | Client-requested scopes overwritten with the app's full list (`cloudflare-oauth-handler.ts:493`); write scopes at app granularity; no JIT elevation | L7-T03; L4-T07 | Answerable |
| MCP03 Tool/schema poisoning | Hosted: hygiene only | Descriptions static in the tree; model-directed imperatives in 11 descriptions; phantom `container_files` resource. Poisoning proper applies only to a forked tree | 10.1 PB-A block | Answerable |
| MCP04 Supply chain | Yes | Exact pins and frozen lockfile; tag-pinned actions; image by SHA tag not digest; no SBOM/provenance; manual image push | L5-T02 / L1-T01 | Partial (branch protection, token scope) |
| MCP05 Command injection & execution | Yes | `child_process.exec` on a raw string with no timeout (`sandbox.container.app.ts:140`); raw SQL and raw GraphQL forwarded unmodified; container has internet | L5-T04; L6-T06 | Partial (platform isolation) |
| MCP06 Intent flow subversion | Yes | 30+ tools return third-party content with no data framing; `workers-prompt-full` as a `user`-role message; no goal anchoring or checker model | L3-T04 | Answerable |
| MCP07 AuthN/AuthZ | Partly | Server-side account ownership check on `accountTool()` tools only; zone, radar, graphql-explorer, container tools skip it; upstream API enforces; RFC 8707 resource matching tested | L7-T03 | Answerable |
| MCP08 Audit & telemetry | Yes | Only tool name, user ID, error code per call (`registration-context.ts:163-173`); no argument or result log; 10% trace sampling; no retention stated | L9-T01 | Answerable |
| MCP09 Shadow servers | Partly | `server.json` lists 12 of the hosted servers; README lists three more; four carry deprecation notices; no inventory of which servers an AIC's users connect | L10-T02 / T05 | Partial |
| MCP10 Context over-sharing | Yes | Stateless per request (`server.ts:73`), so no cross-session leak by the server; over-sharing happens outbound through unbounded tool results and AI Gateway logged prompts returned into context | L3-T04; L3-T07 | Answerable |

Net contribution: MCP08 and MCP01 supplied the custodial and telemetry framing that MAESTRO's L7/L9 sample threats state generically; MCP10 established that the over-sharing is outbound (tool results), not server-side state.

### 10.3 OWASP Agentic Skills Top 10 (AST01–AST10)

Not triggered: no third-party skill, plugin, or behavior-package installation surface and no skill registry is evidenced or referenced. MCP tool use alone does not activate this lens.

### 10.4 Trust & Identity-Lifecycle taxonomy (library Part 3)

**Trigger**: long-lived credentials (30-day refresh tokens, 30-day identity cache, one-year approval cookie) and per-user Durable Object identity. **Source**: `references/threat-technique-and-control-library.md` Part 3 (41 threats; ASI / ATLAS-tactic / AICM v1.1 tags).

| Part 3 threat | Family | What the lens found | Recorded in | Status |
|---|---|---|---|---|
| Token Persistence (IAM-07) | T-A | 30-day refresh TTL (`oauth-router.ts:102`); refresh follows upstream `expires_in` (`cloudflare-oauth-handler.ts:399-405`) | L7-T02 | Answerable |
| Cached Identity Assertions (AIS-14) | T-A | API-token identity cached 30 days under a token-hash key (`api-token-mode.ts:75, :100`); tool calls use the live token | L7-T02 | Answerable |
| Approval Reuse (IAM-18) | T-A | One-year approved-clients cookie skips the consent screen (`cloudflare-oauth-handler.ts:496-511`; `workers-oauth-utils.ts:601`) | Section 9, L4-T07 / L7-T02 approval-reuse block | Partial |
| Stale Trust Decisions (IAM-07, CCC-04) | T-A | Account list for ownership checks is the issuance-time `/accounts` snapshot in props (`cloudflare-oauth-handler.ts:663-677`; `account-manager.ts:88-96`) | L7-T03 | Answerable |
| Session Reuse (AIS-14) | T-A | No MCP session state; fresh `McpServer` per request (`server.ts:73`); parallel-request prop isolation tested (`server.spec.ts:407`) | No instance | Not applicable |
| Cross-Session Contamination; Context Inheritance | T-B | Stateless server; no agent memory | No instance | Not applicable |
| Agent-to-SaaS Trust Abuse (AIS-10, STA-10) | T-C | Every tool calls the Cloudflare API under the user's token; reach bounded by app scope | L6-T06 | Answerable |
| Cross-Tenant Trust Violations (I&S-06, DSP-24) | T-C | Shared `OAUTH_KV` namespace IDs across four apps; latent `DEV_DISABLE_OAUTH` truthy check would route every user through one token (`cloudflare-api.ts:10, :44`) | L7-T02; L5-T02 | Partial |
| Agent-to-MCP Trust Abuse | T-C | Direction inverted: this system is the MCP server the client trusts; its trustworthiness is the subject of Sections 9 and 10.2 | — | Not applicable as a finding |
| Trust Inheritance / Delegated Trust | T-D | No delegation chain or sub-agents | No instance | Not applicable |
| Monitoring Blind Spots (LOG-03, LOG-07) | T-E | No invocation-level record; account-token callers logged as `userId: undefined` (`request-context.ts:26-28`) | L9-T01 | Answerable |
| Authorization Bypass (AIS-11, IAM-16) | T-G | Tools registered outside `accountTool()` skip the server-side ownership check | L7-T03 | Answerable |
| Approval Workflow Bypass (GRC-15, IAM-18) | T-G | No approval workflow exists to bypass; advisory description text only | L4-T07 | Answerable |
| Agent Onboarding Abuse (STA-08, GRC-09) | T-H | Open dynamic client registration at `/register` (`oauth-router.ts:100`); consent still required on first use; no client allowlist evidenced | L10-T02 / T05 | Partial |
| Trust Assertion Forgery (STA-16, IPY-03) | T-H | Approval cookie is HMAC-signed; key declared nowhere in the deployment contract | Section 9, approval-reuse block | Partial |
| Family T-F (scoring, confidence, reputation) | T-F | No trust scoring or reputation surface | No instance | Not applicable |

Net contribution: one new finding (Approval Reuse) and two evidence additions to existing blocks (stale account snapshot in L7-T03; cross-tenant framing of the shared KV and dev bypass in L7-T02). The credential-lifecycle rows sharpened the L7-T02 mitigation from "shorten TTLs" to the specific IAM-07 / AIS-14 controls.

### 10.5 TRAIT&R (inverted-adversary lens)

Not triggered: no insider-threat, misalignment, or untrusted-internal-deployment scope was referenced. The servers execute explicit tool calls and hold no goals of their own; the client model is outside the assessed system.

## 11. Cross-Layer Path Analysis

**Path 1: Indirect injection to unattended destructive action.** A page fetched by `get_url_markdown` or a document returned by `search_dev_stack` carries model-directed text (L3-T04, unframed at `browser.tools.ts:87-95`); the client model, in a session that also has workers-bindings connected, calls `d1_database_query` with a `DROP` (annotated non-destructive, `d1.tools.ts:202-205`) or `kv_namespace_delete`, with no elicitation (L4-T07); the action runs under the user's `workers:write`/`d1:write` grant (L7-T03); the invocation record holds only tool name and user ID (L9-T01). Origin L3, pivot L4/L7, impact L6/L3. Every link is evidenced; the only assumption is a client session with both servers connected, which the README's multi-server listing invites. L3-T07 strengthens the first link: an oversized result can evict the client's safety context before the injected text is read.

**Path 2: Injection to exfiltration through the sandbox.** The same injection instructs the model to write tool results from another server (worker source from `workers_get_worker_code`, AI Gateway request bodies, audit-log actor emails) into the container via `container_file_write` and `curl` them out through `enableInternet: true` (L5-T04, L6-T06). Origin L3, pivot L6, impact L3 disclosure. Evidenced end to end within the repo; bounded by what the model places in the container.

**Path 3: CI compromise to fleet-wide credential exposure.** A mutated third-party action tag (L5-T02) runs with `CLOUDFLARE_API_TOKEN` on push to `main` and deploys altered Workers to every hosted server (L6-T04); each altered Worker reads `props.accessToken` for every request (L7-T02) with no invocation logging of what it does with them (L9-T01). Origin L5, pivot L1/L6, impact L7. Plausible on the evidence; likelihood low.

**Path 4: Public scan default to disclosure.** A user asks the model to check a link that contains a signed token; the model calls `create_url_scan` with the default `Public` visibility (`types/url-scanner.ts:31`) and no HITL (L4-T07); the URL, page, and HAR become a public record (L6-T06 to L3 disclosure). Origin L4 (PB-O), impact L3. Short, fully evidenced, no adversary required.

No multi-agent, memory-persistence, or delegation-chain paths are supported by the evidence; the system has no such components.

## 12. SSRM Ownership Summary

Hosted deployment (assessed). Cloudflare occupies CSP (Workers, KV, DOs, Containers), OSP (the Worker code), Tool Provider (the MCP servers), and MP (AutoRAG, Workers AI). The AIC is the organization whose users connect a client; the AP is the client vendor. A self-hosted fork moves OSP and Tool Provider to the AIC and leaves CSP and MP with Cloudflare.

Ownership below follows the MAESTRO-layer × 3SRM-role matrix in `ssrm-ownership.md`. Because the AIC's agent deployment model is not evidenced, every AIC-side Primary is `Partial — depends on deployment model`; the Tool Provider column is evidenced (Cloudflare hosts the servers). The recurring pattern is that the matrix's Primary owner and the party whose code must change are different roles, which is the 3SRM's own point about the Tool Provider not yet being a recognized AICM role.

| Finding | Matrix Primary | Shared | Implementing party | Structural AICM gap |
|---|---|---|---|---|
| L3-T04 unframed content | AIC (partial) | CSP, MP, OSP, AP | Tool Provider | 2 — Tool Provider absent from the L3 row |
| L3-T07 unbounded tool results | AIC (partial) | CSP, MP, OSP, AP | Tool Provider | 2 |
| L4-T07 no HITL, annotations | OSP (none exists) | MP, AP, Tool Provider, AIC | Tool Provider (annotations), AP (gating) | 2, 3 |
| L5-T04 sandbox egress/shell | CSP, OSP | AP; AIC configures | Tool Provider as OSP; CSP for isolation | 6 |
| L7-T02 token custody | AIC/AP (partial) | CSP, OSP, AP, Tool Provider | Tool Provider | none |
| L7-T03 scope granularity, consent text | AIC/AP (partial) | CSP, OSP, AP, Tool Provider | Tool Provider | none |
| L4-T07 / L7-T02 approval reuse (cookie) | OSP (L4), AIC/AP (L7), partial | CSP, MP, AP, Tool Provider | Tool Provider | 3 |
| L6-T06 high-reach tools | OSP, AP, Tool Provider | MP, AIC (STA-16) | Tool Provider | 2 |
| L2 PB-H unlabeled generation | MP | CSP, OSP; AIC configures | Tool Provider (labeling) | none |
| L2 PB-A/PB-P descriptions | MP (matrix); AIC for system prompts | CSP, OSP | Tool Provider | 2 |
| L9-T01 no invocation audit | AIC integrates (partial) | CSP, MP, OSP, AP, Tool Provider | Tool Provider (server side), AP (client side) | none; LOG-14/15 |
| L5-T02 / L1-T01 CI, image | CSP, OSP | AP; AIC configures | Tool Provider as OSP | none; STA-01–16 |
| L10 governance | AIC (always) | all providers consume | AIC | none |

"In all three deployment models, Layer 10 (Governance) remains with the Agent Owner. Governance cannot be outsourced." Agent Owner (AIC) accountability is non-delegable for L10 and for every action its users' clients take through these servers, regardless of who operates them (3SRM §3.1).

## 13. Framework Crosswalk

Not requested; omitted. Available on request: any single framework, or full crosswalk mode (13.1 STRIDE through 13.9 NIST AI RMF, nine subsections; AST10 at 13.7 would state no skill-installation surface is evidenced).

## 14. Required Validation Steps

1. Confirm `OAuthProvider` 0.10.3 grant-props storage and encryption against the library source or Cloudflare documentation (closes L7-T02 unknown).
2. Grep the production Worker environment inventory for `DEV_DISABLE_OAUTH` and `DEV_CLOUDFLARE_API_TOKEN`; confirm absent (closes the latent bypass).
3. Test at least one client (Claude, OpenAI Responses, Cursor) for annotation handling and auto-approve defaults against `d1_database_query` and `container_exec` (closes L4-T07 likelihood).
4. Resolve the sandbox image's default user (`docker inspect` on `sandbox-container:d802004`) and obtain Cloudflare Containers isolation and egress documentation (closes L5-T04 platform unknowns).
5. Obtain Analytics Engine retention and access policy for `mcp-metrics-production` (closes L9-T01 retention gap).
6. Verify `CLOUDFLARE_API_TOKEN` scope and GitHub branch protection (closes L5-T02 unknowns).
7. Run the repo's own eval suite and record the LLM judge baseline (closes PB-H likelihood).
8. Reconcile the four documentation-versus-code mismatches in Section 5 and the three scope descriptions.
9. Contractual (3SRM §6.2), for an AIC consuming the hosted endpoints: request Cloudflare's AI-CAIQ responses for the MCP servers as a baseline; a shared-responsibility addendum that names token custody (L7-T02), invocation telemetry retention (L9-T01), and container egress (L5-T04) as Tool Provider obligations; audit rights aligned to A&A-01–06; and a safety SLA for `ai_search` hallucination rate and for human-escalation response on DEX device captures.
10. Add the 18 servers to the AIC's STA-16 Service BOM with their write scopes, since the AIC, not Cloudflare, owns that inventory.
11. Re-run `scripts/verify_citations.py` and `scripts/section8_to_sarif.py` after any edit to this report; the SARIF export (`example-report.sarif`) carries all 13 findings with source locations.

## 15. Conclusion: What Can and Cannot Be Concluded

The repository's authentication, transport, and account-scoping code is tested, exact-pinned, and written with evident care for token handling in logs and error paths. What can be concluded from the code is that the servers hand the client model a large, unframed stream of third-party and user-controlled content and, in the same surface, expose immediate destructive actions, raw SQL, employee-device captures, public URL scans, and an internet-connected shell with no server-enforced approval step and incomplete or affirmatively wrong destructiveness annotations. The controlling risk is therefore the pairing of L3-T04 with L4-T07 across a multi-server client session, and it is entirely within the Tool Provider's power to close at the protocol layer. The second-order risk is custodial: 30-day upstream tokens and identity caches held in KV whose at-rest protection cannot be verified here, behind a one-line dev-bypass misconfiguration, with no invocation-level audit trail to detect misuse.

What cannot be concluded from the repo: platform isolation of the sandbox container, at-rest protection of grant props, client-side approval behavior, telemetry retention, and CI token scope. None of these is inferred; each has a named artifact in Section 14.

## 16. Single Clarifying Question

Is the deployment under assessment the Cloudflare-hosted endpoints in `server.json`, or a self-hosted fork of this repo? The answer moves OSP and Tool Provider ownership for every finding in Section 12 and determines whether the CI and image-supply-chain findings (L5-T02) are Cloudflare's or yours to remediate.
