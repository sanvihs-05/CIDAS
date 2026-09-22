#!/usr/bin/env bash
# install-shim.sh — installs the CIDAS npm shim on the current system.
#
# Creates ~/.local/bin/npm (or ~/bin/npm on macOS) that delegates to
# npm-shim.js, stores the real npm path, and prepends to PATH.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIM_SRC="${SCRIPT_DIR}/npm-shim.js"
CIDAS_DIR="${HOME}/.cidas"
SHIM_DEST="${CIDAS_DIR}/npm-shim.js"
WRAPPER="${CIDAS_DIR}/npm"
REAL_NPM_FILE="${CIDAS_DIR}/real-npm"

echo "[CIDAS] Installing npm shim…"

# Find the real npm (must exist)
REAL_NPM="$(command -v npm 2>/dev/null || true)"
if [[ -z "${REAL_NPM}" ]]; then
  echo "[CIDAS] Error: npm not found on PATH. Install Node.js first." >&2
  exit 1
fi

# Guard: refuse to wrap our own wrapper
if [[ "${REAL_NPM}" == "${WRAPPER}" ]]; then
  echo "[CIDAS] Shim is already active. Run uninstall-shim.sh first." >&2
  exit 1
fi

mkdir -p "${CIDAS_DIR}"
echo "${REAL_NPM}" > "${REAL_NPM_FILE}"
cp "${SHIM_SRC}" "${SHIM_DEST}"
chmod +x "${SHIM_DEST}"

# Write a tiny shell wrapper that calls `node <shim>`
cat > "${WRAPPER}" <<'WRAPPER'
#!/usr/bin/env sh
exec node "${HOME}/.cidas/npm-shim.js" "$@"
WRAPPER
chmod +x "${WRAPPER}"

echo "[CIDAS] Shim installed: ${WRAPPER}"
echo "[CIDAS] Real npm saved: ${REAL_NPM}"

# Prepend ~/.cidas to PATH in the user's shell RC
SHELL_RC=""
case "${SHELL:-}" in
  */zsh)  SHELL_RC="${HOME}/.zshrc"  ;;
  */bash) SHELL_RC="${HOME}/.bashrc" ;;
  *)      SHELL_RC="${HOME}/.profile" ;;
esac

PATH_LINE='export PATH="${HOME}/.cidas:${PATH}"  # CIDAS npm shim'
if ! grep -qF "CIDAS npm shim" "${SHELL_RC}" 2>/dev/null; then
  printf '\n%s\n' "${PATH_LINE}" >> "${SHELL_RC}"
  echo "[CIDAS] Added PATH entry to ${SHELL_RC}"
fi

echo "[CIDAS] Done. Open a new terminal (or: source ${SHELL_RC}) for changes to take effect."

# Sign the installed shim so the self-integrity check has a reference hash.
bash "${SCRIPT_DIR}/sign-shim.sh" "${SHIM_DEST}"
