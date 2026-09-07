#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ ! -x "$ROOT/dist/ddg" ] || [ ! -x "$ROOT/dist/ddg-agent" ]; then
  echo "[DDG] build artifacts missing; running build first..." >&2
  "$ROOT/scripts/build.sh"
fi

"$ROOT/dist/ddg" --agent "$ROOT/dist/ddg-agent" "$@"
