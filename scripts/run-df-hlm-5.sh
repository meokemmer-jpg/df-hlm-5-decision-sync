#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK_DIR="${DF_HLM_5_LOCK_DIR:-/tmp/df-hlm-5.lock}"
STOP_FLAG="${ROOT_DIR}/STOP.flag"

if [[ -f "${STOP_FLAG}" ]]; then
  echo "DF-HLM-5 stopped by ${STOP_FLAG}" >&2
  exit 2
fi

if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
  echo "K16 mutex active: ${LOCK_DIR}" >&2
  exit 75
fi
trap 'rmdir "${LOCK_DIR}" 2>/dev/null || true' EXIT INT TERM

if pgrep -f "src/decision_sync.py" >/dev/null 2>&1; then
  echo "K16 engine_pgrep_check active: decision_sync.py already running" >&2
  exit 75
fi

cd "${ROOT_DIR}"
exec python3 src/decision_sync.py --config config.yaml
