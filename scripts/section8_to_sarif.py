#!/usr/bin/env python3
"""Export Section 8 (Summary of Findings) of an assessment to SARIF 2.1.0.

Usage:
    python3 scripts/section8_to_sarif.py REPORT.md --out findings.sarif [--root /path/to/repo] [--tool-version X]

Each Section 8 row becomes one SARIF rule and one result. The result's location is the
first `path:line` citation found in the matching Section 9 or Section 10 block (matched by
the row's Layer ID or lens letter); if none is found, the result carries no location and
`properties.locationNote` says so. Risk maps to SARIF level: High -> error, Medium/Medium-High
-> warning, Low/Low-Medium/provisional-Unassessable -> note. Ratings, layer, lens, status,
and implementing party are preserved under `properties` so nothing from the table is lost.

The SARIF imports into GitHub / GitLab / Azure DevOps code scanning and most IDEs. No LLM.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROW_RE = re.compile(r"^\|\s*(\d+)\s*\|(.+)\|\s*$")
CITE_RE = re.compile(r"`([A-Za-z0-9_./@+\-]+\.[A-Za-z0-9]+)(:\d+(?:[-–]\d+)?)")
ID_RE = re.compile(r"(L\d+-T\d+|L\d+ \(PB-[A-Z](?:/[A-Z])?\)|L\d+)")

LEVEL = {"high": "error", "medium-high": "warning", "medium": "warning", "low-medium": "note", "low": "note"}


def level_for(risk: str) -> str:
    r = risk.lower().replace("**", "").replace("(prov.)", "").strip()
    for k, v in LEVEL.items():
        if r.startswith(k):
            return v
    return "note"


def section(text: str, num: int) -> str:
    m = re.search(rf"^## {num}\. .*?$", text, re.M)
    if not m:
        return ""
    n = re.search(rf"^## {num + 1}\. ", text[m.end():], re.M)
    return text[m.end(): m.end() + n.start()] if n else text[m.end():]


def block_for(text9: str, text10: str, layer_cell: str) -> str:
    """Find the detailed block whose heading carries this row's ID(s)."""
    ids = [x for x in re.findall(r"L\d+-T\d+|PB-[A-Z]", layer_cell)]
    order = (text10, text9) if "PB-" in layer_cell and "-T" not in layer_cell else (text9, text10)
    for body in order:
        for h in re.finditer(r"^### (.+)$", body, re.M):
            if any(i in h.group(1) for i in ids):
                end = re.search(r"^### ", body[h.end():], re.M)
                return body[h.end(): h.end() + end.start()] if end else body[h.end():]
    return ""


def resolve_uri(root: Path, rel: str) -> str:
    """Return a root-relative URI; shortened basenames are resolved to their unique suffix match."""
    if (root / rel).is_file():
        return rel
    parts = Path(rel).parts
    hits = [q for q in root.rglob(parts[-1]) if q.is_file() and q.parts[-len(parts):] == parts
            and ".git" not in q.parts and "node_modules" not in q.parts]
    return str(hits[0].relative_to(root)) if len(hits) == 1 else rel


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--out", required=True)
    ap.add_argument("--root", default=".")
    ap.add_argument("--tool-version", default="4.0")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    text = Path(args.report).read_text(encoding="utf-8")
    s8, s9, s10 = section(text, 8), section(text, 9), section(text, 10)
    if not s8:
        print("No Section 8 found", file=sys.stderr)
        return 1
    header = None
    rules, results = [], []
    for line in s8.splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        cells = [c.strip() for c in m.group(2).split("|")]
        if header is None:
            # first data row follows the header + separator; infer columns from the header line above
            hdr = re.search(r"^\|\s*#\s*\|(.+)\|\s*$", s8, re.M)
            header = [c.strip().lower() for c in hdr.group(1).split("|")] if hdr else []
        row = dict(zip(header, cells))
        num = m.group(1)
        finding = row.get("finding", "").replace("`", "")
        layer = row.get("layer", "")
        risk = row.get("risk", "")
        rule_id = f"MAESTRO-{re.sub(r'[^A-Za-z0-9]+', '-', layer).strip('-')}-{num}"
        props = {k: v.replace("**", "") for k, v in row.items() if k not in ("#",)}
        rules.append({
            "id": rule_id,
            "name": layer or f"finding-{num}",
            "shortDescription": {"text": finding[:200]},
            "fullDescription": {"text": finding},
            "defaultConfiguration": {"level": level_for(risk)},
            "properties": {"layer": layer, "lens": row.get("lens", ""), "tags": ["MAESTRO", "threat-model"]},
        })
        blk = block_for(s9, s10, layer)
        cite = CITE_RE.search(blk) if blk else None
        result = {
            "ruleId": rule_id,
            "level": level_for(risk),
            "message": {"text": f"[{layer}] {finding} (Risk {risk.replace('**','')}; L {row.get('likelihood','')}, I {row.get('impact','')}; {row.get('status','')})"},
            "properties": props,
        }
        if cite:
            start = int(re.search(r"\d+", cite.group(2)).group(0))
            end_m = re.search(r"[-–](\d+)", cite.group(2))
            region = {"startLine": start, "endLine": int(end_m.group(1)) if end_m else start}
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": resolve_uri(root, cite.group(1)), "uriBaseId": "SRCROOT"}, "region": region}}]
        else:
            result["properties"]["locationNote"] = "no path:line citation found in the matching Section 9/10 block"
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ai-threat-models (MAESTRO v2.0)", "version": args.tool_version,
                                 "informationUri": "https://github.com/Nate-Carroll-Cyber/AI-Threat-Modeling-Claude-Skill",
                                 "rules": rules}},
            "originalUriBaseIds": {"SRCROOT": {"uri": "file:///" + str(root).lstrip("/") + "/"}},
            "results": results,
        }],
    }
    Path(args.out).write_text(json.dumps(sarif, indent=1), encoding="utf-8")
    located = sum(1 for r in results if "locations" in r)
    print(f"{len(results)} results ({located} with locations) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
