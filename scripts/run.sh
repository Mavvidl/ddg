#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"$ROOT/dist/ddg" --agent "$ROOT/dist/ddg-agent" "$@"
