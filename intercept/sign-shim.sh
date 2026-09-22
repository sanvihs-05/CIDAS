#!/usr/bin/env bash
# sign-shim.sh — compute and record the SHA-256 hash of npm-shim.js.
#
# Run once at install time (called automatically by install-shim.sh).
# The shim reads this hash at startup to detect tampering.
#
# Usage: bash sign-shim.sh [path/to/npm-shim.js]
#   The first argument overrides the default shim path (useful in CI).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIM_SRC="${1:-${SCRIPT_DIR}/npm-shim.js}"
CIDAS_DIR="${HOME}/.cidas"
HASH_FILE="${CIDAS_HASH_FILE:-${CIDAS_DIR}/shim.sha256}"

if [[ ! -f "${SHIM_SRC}" ]]; then
  echo "[CIDAS] Error: shim not found at ${SHIM_SRC}" >&2
  exit 1
fi

mkdir -p "$(dirname "${HASH_FILE}")"

# sha256sum is standard on Linux; shasum ships with macOS.
# We strip carriage returns first so this script produces the same hash as
# the shim's own self-check (which normalises CRLF→LF in JS). On a normal
# LF-only file this is a no-op.
if command -v sha256sum &>/dev/null; then
  HASH="$(tr -d '\r' < "${SHIM_SRC}" | sha256sum | awk '{print $1}')"
else
  HASH="$(tr -d '\r' < "${SHIM_SRC}" | shasum -a 256 | awk '{print $1}')"
fi

printf '%s  %s\n' "${HASH}" "${SHIM_SRC}" > "${HASH_FILE}"
chmod 600 "${HASH_FILE}"

echo "[CIDAS] Shim signed: ${HASH_FILE}"
echo "[CIDAS] SHA-256: ${HASH}"
