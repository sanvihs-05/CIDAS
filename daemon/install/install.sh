#!/usr/bin/env bash
# install.sh — install the CIDAS daemon watchdog as a login service.
#
# Detects the current platform and installs:
#   - macOS  → ~/Library/LaunchAgents/com.cidas.watchdog.plist (launchd agent)
#   - Linux  → ~/.config/systemd/user/cidas-watchdog.service   (systemd user unit)
#
# Usage:  bash daemon/install/install.sh
#         bash daemon/install/install.sh --uninstall

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WATCHDOG="${DAEMON_DIR}/watchdog.sh"

PLIST_SRC="${SCRIPT_DIR}/com.cidas.watchdog.plist"
PLIST_DEST="${HOME}/Library/LaunchAgents/com.cidas.watchdog.plist"

UNIT_SRC="${SCRIPT_DIR}/cidas-watchdog.service"
UNIT_DEST="${HOME}/.config/systemd/user/cidas-watchdog.service"

ACTION="install"
if [[ "${1:-}" == "--uninstall" ]]; then
    ACTION="uninstall"
fi

# ── Sanity checks ─────────────────────────────────────────────────────────────
if [[ ! -f "${WATCHDOG}" ]]; then
    echo "[CIDAS] watchdog.sh not found at ${WATCHDOG}" >&2
    exit 1
fi
chmod +x "${WATCHDOG}" 2>/dev/null || true

if ! command -v curl >/dev/null 2>&1; then
    echo "[CIDAS] curl is required for the watchdog health probe but was not found on PATH." >&2
    exit 1
fi

mkdir -p "${HOME}/.cidas"

# ── macOS / launchd ───────────────────────────────────────────────────────────
_install_macos() {
    mkdir -p "${HOME}/Library/LaunchAgents"
    sed -e "s|__WATCHDOG_PATH__|${WATCHDOG}|g" \
        -e "s|__HOME__|${HOME}|g" \
        "${PLIST_SRC}" > "${PLIST_DEST}"
    launchctl unload "${PLIST_DEST}" 2>/dev/null || true
    launchctl load   "${PLIST_DEST}"
    echo "[CIDAS] launchd agent installed: ${PLIST_DEST}"
    echo "[CIDAS] Watchdog is now running. Logs: ${HOME}/.cidas/daemon.log"
}

_uninstall_macos() {
    if [[ -f "${PLIST_DEST}" ]]; then
        launchctl unload "${PLIST_DEST}" 2>/dev/null || true
        rm -f "${PLIST_DEST}"
        echo "[CIDAS] launchd agent removed."
    else
        echo "[CIDAS] launchd agent not installed; nothing to remove."
    fi
}

# ── Linux / systemd user ──────────────────────────────────────────────────────
_install_linux() {
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "[CIDAS] systemctl not found. The watchdog can be run manually with:" >&2
        echo "        nohup bash ${WATCHDOG} >/dev/null 2>&1 &" >&2
        exit 1
    fi
    mkdir -p "$(dirname "${UNIT_DEST}")"
    sed -e "s|__WATCHDOG_PATH__|${WATCHDOG}|g" "${UNIT_SRC}" > "${UNIT_DEST}"
    systemctl --user daemon-reload
    systemctl --user enable cidas-watchdog.service
    systemctl --user restart cidas-watchdog.service
    echo "[CIDAS] systemd user unit installed: ${UNIT_DEST}"
    echo "[CIDAS] Status: systemctl --user status cidas-watchdog.service"
    echo "[CIDAS] Logs:   ${HOME}/.cidas/daemon.log"
    echo "[CIDAS] To keep the watchdog running after logout, run:"
    echo "          sudo loginctl enable-linger \"\$USER\""
}

_uninstall_linux() {
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "[CIDAS] systemctl not available; nothing to do."
        return 0
    fi
    systemctl --user stop cidas-watchdog.service 2>/dev/null || true
    systemctl --user disable cidas-watchdog.service 2>/dev/null || true
    rm -f "${UNIT_DEST}"
    systemctl --user daemon-reload || true
    echo "[CIDAS] systemd user unit removed."
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
case "$(uname -s)" in
    Darwin)
        if [[ "${ACTION}" == "install" ]]; then _install_macos; else _uninstall_macos; fi
        ;;
    Linux)
        if [[ "${ACTION}" == "install" ]]; then _install_linux; else _uninstall_linux; fi
        ;;
    *)
        echo "[CIDAS] Unsupported platform: $(uname -s). Run watchdog.sh manually." >&2
        exit 1
        ;;
esac
