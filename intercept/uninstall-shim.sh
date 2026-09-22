#!/usr/bin/env bash
# uninstall-shim.sh — removes the CIDAS npm shim.

set -euo pipefail

CIDAS_DIR="${HOME}/.cidas"
WRAPPER="${CIDAS_DIR}/npm"
SHIM_DEST="${CIDAS_DIR}/npm-shim.js"

echo "[CIDAS] Uninstalling npm shim…"

for f in "${WRAPPER}" "${SHIM_DEST}"; do
  if [[ -f "${f}" ]]; then
    rm -f "${f}"
    echo "[CIDAS] Removed: ${f}"
  fi
done

for RC in "${HOME}/.zshrc" "${HOME}/.bashrc" "${HOME}/.profile"; do
  if [[ -f "${RC}" ]] && grep -qF "CIDAS npm shim" "${RC}"; then
    grep -vF "CIDAS npm shim" "${RC}" > "${RC}.cidas_bak" && mv "${RC}.cidas_bak" "${RC}"
    echo "[CIDAS] Removed PATH entry from ${RC}"
  fi
done

echo "[CIDAS] Uninstall complete. Open a new terminal or re-source your shell RC."
