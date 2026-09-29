#!/usr/bin/env bash
# Build the distributable skill package from a clean copy, gated on the ATLAS audit.
#
# Usage: scripts/package.sh [VERSION-TAG]        e.g. scripts/package.sh v7-atlas
# Produces ai-threat-models-<tag>.zip in the repo root, containing ai-threat-models/{SKILL.md,README.md,references/,scripts/}.
# Fails (no zip) if scripts/refresh_atlas.py --check-only --strict reports an absent ATLAS ID or an unmarked name mismatch.
# Set ATLAS_YAML=/path/to/ATLAS.yaml to audit offline; otherwise the audit downloads the current release.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${1:-$(date +%Y%m%d)}"
OUT="$ROOT/ai-threat-models-$TAG.zip"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "== ATLAS audit (strict) =="
if [ -n "${ATLAS_YAML:-}" ]; then
  python3 "$ROOT/scripts/refresh_atlas.py" --check-only --strict --atlas "$ATLAS_YAML"
else
  python3 "$ROOT/scripts/refresh_atlas.py" --check-only --strict
fi

echo "== staging =="
mkdir -p "$STAGE/ai-threat-models/references" "$STAGE/ai-threat-models/scripts"
cp "$ROOT/SKILL.md" "$ROOT/README.md" "$STAGE/ai-threat-models/"
cp "$ROOT"/references/*.md "$STAGE/ai-threat-models/references/"
cp "$ROOT"/scripts/*.py "$ROOT"/scripts/*.sh "$STAGE/ai-threat-models/scripts/"
rm -f "$OUT"
(cd "$STAGE" && zip -qr "$OUT" ai-threat-models)
echo "wrote $OUT"
unzip -l "$OUT" | tail -1
