#!/usr/bin/env python3
"""Step 1 aid for large codebases: inventory security-relevant files and propose subsystems.

Usage:
    python3 scripts/plan_subsystems.py /path/to/repo [--depth 2] [--top 40]

No LLM. Walks the tree (skipping .git, node_modules, vendor, dist, build), counts files that
match the key-file patterns below per directory to --depth, flags directories that contain
auth / crypto / CI / container / IaC / LLM-SDK / MCP / tool-definition signals, and prints a
proposed subsystem list with the MAESTRO layers each one most plausibly evidences. The output is
a starting point for the Section 6 component-to-layer table and for splitting evidence gathering
across subsystems; the assessor still reads the code. Signals are filename and import-string
matches only, so they say where to look, not what is there.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

SKIP = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__", ".turbo", ".next"}
KEY = re.compile(r"\.(py|js|ts|tsx|go|java|rs|rb|cs|kt|swift|tf|yaml|yml|toml|json|jsonc|sh|sql|proto|graphql|Dockerfile)$|^(Dockerfile|docker-compose.*|Makefile|go\.mod|package\.json|requirements\.txt|Cargo\.toml|pom\.xml|pyproject\.toml|wrangler\.(toml|json|jsonc))$")

# signal -> (regex over filename or first 64 KB of content, MAESTRO layers it usually evidences)
SIGNALS: dict[str, tuple[re.Pattern, str]] = {
    "auth/identity": (re.compile(r"oauth|jwt|passport|session|auth[nz]?|iam|rbac|abac|token|credential", re.I), "L7"),
    "secrets/crypto": (re.compile(r"secret|vault|kms|hmac|encrypt|decrypt|\.env|api[_-]?key", re.I), "L1/L7"),
    "ci/cd": (re.compile(r"\.github/workflows|gitlab-ci|jenkinsfile|buildkite|circleci|azure-pipelines", re.I), "L5"),
    "container/runtime": (re.compile(r"dockerfile|docker-compose|containerd|k8s|kubernetes|helm|sandbox|firecracker|gvisor", re.I), "L5"),
    "iac": (re.compile(r"\.tf$|terraform|pulumi|cloudformation|cdk", re.I), "L1"),
    "llm sdk": (re.compile(r"openai|anthropic|@google/generative-ai|mistralai|litellm|langchain|langgraph|crewai|autogen|pydantic[_-]ai|llama[_-]index|bedrock|vertexai|workers-ai", re.I), "L2/L4"),
    "mcp": (re.compile(r"modelcontextprotocol|mcp[_-]?server|mcp[_-]?client|McpServer|registerTool|@modelcontextprotocol", re.I), "L6"),
    "tools/functions": (re.compile(r"function[_-]?call|tool[_-]?(def|registry|schema)|tools\.ts|\.tools\.", re.I), "L6/L4"),
    "rag/vector/memory": (re.compile(r"embedding|vector|pinecone|weaviate|chroma|faiss|qdrant|pgvector|retriev|rag\b|memory[_-]?store", re.I), "L3"),
    "agents/orchestration": (re.compile(r"agent|orchestrat|planner|workflow|subagent|delegat", re.I), "L4"),
    "logging/telemetry": (re.compile(r"sentry|otel|opentelemetry|datadog|analytics|metrics|logger|audit", re.I), "L9"),
    "policy/governance": (re.compile(r"opa\b|cedar|policy|compliance|governance|SECURITY\.md|CODEOWNERS", re.I), "L10"),
    "exec/shell": (re.compile(r"child_process|subprocess|os\.system|exec\(|spawn\(|eval\(|shell=True", re.I), "L5/L6"),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--top", type=int, default=40)
    args = ap.parse_args()
    root = Path(args.root).resolve()

    counts: Counter[str] = Counter()
    sigs: dict[str, Counter[str]] = defaultdict(Counter)
    total = 0
    for p in root.rglob("*"):
        if any(part in SKIP for part in p.parts):
            continue
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        if not KEY.search(p.name) and not KEY.search(str(rel)):
            continue
        total += 1
        group = "/".join(rel.parts[: args.depth]) if len(rel.parts) > 1 else "(root)"
        counts[group] += 1
        hay = str(rel)
        try:
            hay += "\n" + p.read_text(encoding="utf-8", errors="ignore")[:65536]
        except OSError:
            pass
        for name, (rx, _) in SIGNALS.items():
            if rx.search(hay):
                sigs[group][name] += 1

    print(f"{total} key files under {root}\n")
    print(f"{'directory (depth ' + str(args.depth) + ')':<48} {'files':>5}  signals (file hits) -> likely MAESTRO layers")
    for g, n in counts.most_common(args.top):
        s = sigs[g]
        top = [f"{k}:{v}" for k, v in s.most_common(5)]
        layers = sorted({SIGNALS[k][1] for k, _ in s.most_common(5)})
        print(f"{g:<48} {n:>5}  {', '.join(top):<60} -> {' '.join(layers)}")

    print("\nProposed subsystems (merge or split by hand; 3–7 is the working range):")
    proposals = []
    for g, n in counts.most_common(args.top):
        s = sigs[g]
        if not s:
            continue
        lead = s.most_common(1)[0][0]
        proposals.append((g, lead, n))
    seen = set()
    for g, lead, n in proposals:
        key = (lead,)
        tag = "" if key not in seen else " (same lead signal as an earlier group; candidate to merge)"
        seen.add(key)
        print(f"  - {g}  [{lead}, {n} files]{tag}")
    print("\nGlobal signals with zero hits (state as 'No evidence in this layer' unless found by reading):")
    hit = {k for c in sigs.values() for k in c}
    for k in SIGNALS:
        if k not in hit:
            print(f"  - {k} -> {SIGNALS[k][1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
