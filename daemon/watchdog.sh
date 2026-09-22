#!/usr/bin/env bash
# daemon/watchdog.sh — keeps the CIDAS daemon alive.
#
# Polls GET /api/v1/health every 10 seconds. After 3 consecutive failures
# (≈30s window) it invokes scripts/start-daemon.sh to restart the daemon.
# Every state transition is appended to ~/.cidas/daemon.log as one JSON
# object per line so that operators can audit restarts after the fact.
#
# This script is intended to run as a long-lived background process,
# managed by launchd on macOS or systemd --user on Linux. See
# daemon/install/install.sh for the platform installers.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
START_SCRIPT="${PROJECT_ROOT}/scripts/start-daemon.sh"

CIDAS_DIR="${HOME}/.cidas"
LOG_FILE="${CIDAS_DIR}/daemon.log"

PORT="${DAEMON_PORT:-7355}"
HOST="${DAEMON_HOST:-127.0.0.1}"
HEALTH_URL="http://${HOST}:${PORT}/api/v1/health"

POLL_INTERVAL="${CIDAS_WATCHDOG_INTERVAL:-10}"
FAILURE_THRESHOLD="${CIDAS_WATCHDOG_THRESHOLD:-3}"
RESTART_GRACE_SECONDS="${CIDAS_WATCHDOG_GRACE:-5}"

mkdir -p "${CIDAS_DIR}"

# ── Logging ───────────────────────────────────────────────────────────────────
_log() {
    local level="$1"; shift
    local msg="$*"
    # Escape embedded double quotes so the line stays valid JSON.
    msg="${msg//\"/\\\"}"
    local ts
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    printf '{"ts":"%s","level":"%s","event":"%s"}\n' \
        "${ts}" "${level}" "${msg}" >> "${LOG_FILE}"
}

# ── Health probe ──────────────────────────────────────────────────────────────
_probe() {
    # --max-time keeps us under the 10 s polling cadence on hung connections.
    curl --silent --show-error --fail --max-time 5 "${HEALTH_URL}" \
        >/dev/null 2>&1
}

# ── Restart ───────────────────────────────────────────────────────────────────
_restart() {
    _log "WARN" "daemon unhealthy after ${FAILURE_THRESHOLD} probes — restarting"
    if ! command -v bash >/dev/null 2>&1; then
        _log "ERROR" "bash not on PATH; cannot restart"
        return 1
    fi
    if [[ ! -x "${START_SCRIPT}" && ! -f "${START_SCRIPT}" ]]; then
        _log "ERROR" "start-daemon.sh not found at ${START_SCRIPT}"
        return 1
    fi
    bash "${START_SCRIPT}" >> "${LOG_FILE}" 2>&1
    local rc=$?
    if (( rc == 0 )); then
        _log "INFO" "restart command completed (rc=0)"
    else
        _log "ERROR" "restart command failed (rc=${rc})"
    fi
    sleep "${RESTART_GRACE_SECONDS}"
    return ${rc}
}

# ── Main loop ─────────────────────────────────────────────────────────────────
trap '_log "INFO" "watchdog stopping (signal)"; exit 0' SIGINT SIGTERM

_log "INFO" "watchdog starting (interval=${POLL_INTERVAL}s threshold=${FAILURE_THRESHOLD})"

failures=0
while true; do
    if _probe; then
        if (( failures > 0 )); then
            _log "INFO" "daemon recovered after ${failures} failed probes"
        fi
        failures=0
    else
        failures=$(( failures + 1 ))
        _log "WARN" "health probe failed (${failures}/${FAILURE_THRESHOLD})"
        if (( failures >= FAILURE_THRESHOLD )); then
            _restart
            failures=0
        fi
    fi
    sleep "${POLL_INTERVAL}"
done
