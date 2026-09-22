#!/usr/bin/env bash
# run-tests.sh — run daemon (pytest) and extension (vitest) test suites.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SCRIPT_DIR}/.."
DAEMON_DIR="${ROOT}/daemon"
EXT_DIR="${ROOT}/extension"
VENV="${DAEMON_DIR}/.venv"

echo "══════════════════════════════════════════"
echo "  CIDAS Test Suite"
echo "══════════════════════════════════════════"

# ── Daemon (pytest) ────────────────────────────────────────────────────────
echo ""
echo "▶ Daemon tests (pytest + coverage)…"

if [[ ! -d "${VENV}" ]]; then
  echo "[CIDAS] Creating venv and installing daemon dependencies…"
  python3 -m venv "${VENV}"
  "${VENV}/bin/pip" install --quiet --upgrade pip
  "${VENV}/bin/pip" install --quiet -e "${DAEMON_DIR}[dev]"
fi

cd "${ROOT}"
"${VENV}/bin/pytest" daemon/tests/ \
  --cov=daemon \
  --cov-report=term-missing \
  -v
PYTEST_EXIT=$?

# ── Extension (vitest) ─────────────────────────────────────────────────────
echo ""
echo "▶ Extension tests (vitest)…"

cd "${EXT_DIR}"
if [[ ! -d "node_modules" ]]; then
  echo "[CIDAS] Installing extension node_modules…"
  npm install
fi
npx vitest run
VITEST_EXIT=$?

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
if [[ ${PYTEST_EXIT} -eq 0 && ${VITEST_EXIT} -eq 0 ]]; then
  echo "  ALL TESTS PASSED ✓"
  exit 0
else
  echo "  FAILURES: pytest=${PYTEST_EXIT}  vitest=${VITEST_EXIT}"
  exit 1
fi
