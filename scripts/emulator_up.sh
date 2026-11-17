#!/usr/bin/env bash
# Boot or stop the headless Android emulator used by Maya's dynamic path.
#
# This script only brings the AVD up or down. The install, frida-server, and
# enumerate-script smoke is:
#
#   maya --emulator --package dvba_v1.1.0.apk
#
# Usage:
#   scripts/emulator_up.sh up [--api 34] [--abi x86_64] [--device pixel_6] [--name maya]
#   scripts/emulator_up.sh down [--port 5554]
#   scripts/emulator_up.sh status [--port 5554]
#
# A missing Android SDK prints an error and exits 2. It does not crash.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="${ROOT}${PYTHONPATH:+:${PYTHONPATH}}"

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "python3 is required to run the emulator helper." >&2
  exit 2
fi

exec "$PYTHON" -m maya.tools.emulator "$@"
