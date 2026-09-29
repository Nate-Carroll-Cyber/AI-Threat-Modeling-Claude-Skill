#!/usr/bin/env python3
"""Verify every `path:line` citation in an assessment against the source tree.

Usage:
    python3 scripts/verify_citations.py REPORT.md --root /path/to/repo [--show] [--json OUT]

What it checks, without an LLM:
  - the cited file exists under --root (symlink escapes refused)
  - every cited line number is within the file's length
  - with --show, prints the cited lines so the assessor can confirm content

Citation forms recognised (inside backticks, the form the skill's output uses):
    `path/to/file.ts:12`          `path/to/file.ts:12-18`        `path/to/file.ts:12, :40-44`
    `path/to/file.ts:12,:40`      `file.ts:12` (root-relative)   `:88` continuation after a path

Exit status is 1 when any citation is unresolvable, so it can gate a report.
Unverifiable citations must be marked `[unverified]` in the report and listed in Section 5.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CITE_RE = re.compile(r"`([A-Za-z0-9_./@+\-]+\.[A-Za-z0-9]+)(:\d+(?:[-–]\d+)?(?:,\s*:?\d+(?:[-–]\d+)?)*)`")
RANGE_RE = re.compile(r":?(\d+)(?:[-–](\d+))?")


def resolve_safe(root: Path, rel: str) -> tuple[Path | None, str]:
    """Resolve a cited path. Exact root-relative first; then a unique basename/suffix match
    anywhere under root (the skill's reports shorten paths after the first full mention).
    Returns (path, note) where note is '', 'resolved-by-suffix', 'ambiguous', or 'path-escape'."""
    cand = (root / rel).resolve()
    try:
        cand.relative_to(root.resolve())
    except ValueError:
        return None, "path-escape"
    if cand.is_file():
        return cand, ""
    parts = Path(rel).parts
    hits = [q for q in root.rglob(parts[-1]) if q.is_file() and q.parts[-len(parts):] == parts
            and ".git" not in q.parts and "node_modules" not in q.parts]
    if len(hits) == 1:
        return hits[0], "resolved-by-suffix"
    if len(hits) > 1:
        return None, "ambiguous"
    return None, ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--root", required=True)
    ap.add_argument("--show", action="store_true", help="print cited lines")
    ap.add_argument("--json", help="write results to this JSON file")
    ap.add_argument("--max-show", type=int, default=6)
    args = ap.parse_args()

    root = Path(args.root).resolve()
    text = Path(args.report).read_text(encoding="utf-8")
    results = []
    line_cache: dict[Path, list[str] | None] = {}

    for m in CITE_RE.finditer(text):
        rel, ranges = m.group(1), m.group(2)
        report_line = text.count("\n", 0, m.start()) + 1
        p, note = resolve_safe(root, rel)
        entry = {"report_line": report_line, "path": rel, "ranges": [], "status": "ok"}
        if note == "path-escape":
            entry["status"] = "path-escape"
        elif note == "ambiguous":
            entry["status"] = "ambiguous-basename"
        elif p is None:
            entry["status"] = "missing-file"
        else:
            if p not in line_cache:
                try:
                    line_cache[p] = p.read_text(encoding="utf-8", errors="replace").split("\n")
                except OSError:
                    line_cache[p] = None
            lines = line_cache[p]
            if lines is None:
                entry["status"] = "unreadable"
            else:
                if note:
                    entry["resolved"] = str(p.relative_to(root.resolve()))
                for rm in RANGE_RE.finditer(ranges):
                    a = int(rm.group(1)); b = int(rm.group(2) or a)
                    r = {"start": a, "end": b, "in_range": b <= len(lines) and a >= 1 and a <= b}
                    if args.show and r["in_range"]:
                        r["lines"] = [l.rstrip()[:160] for l in lines[a - 1 : min(b, a - 1 + args.max_show)]]
                    if not r["in_range"]:
                        entry["status"] = "line-out-of-range"
                    entry["ranges"].append(r)
        results.append(entry)

    bad = [r for r in results if r["status"] != "ok"]
    for r in results:
        flag = "OK " if r["status"] == "ok" else "!! "
        spans = ", ".join(f"{x['start']}" + (f"-{x['end']}" if x["end"] != x["start"] else "") for x in r["ranges"])
        extra = r["status"] if r["status"] != "ok" else (f"-> {r['resolved']}" if r.get("resolved") else "")
        print(f"{flag}{r['path']}:{spans}  (report line {r['report_line']}) {extra}")
        if args.show:
            for x in r["ranges"]:
                for i, l in enumerate(x.get("lines", []), start=x["start"]):
                    print(f"      {i:>5}  {l}")
    print(f"\n{len(results)} citations, {len(results)-len(bad)} resolvable, {len(bad)} unresolvable")
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1), encoding="utf-8")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
