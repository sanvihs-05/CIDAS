#!/usr/bin/env bash
# start-daemon.sh — creates venv if needed, then starts the CIDAS daemon.
#
# Checks if the daemon is already running on port 7355; if so, prints
# a message and exits cleanly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/.."
DAEMON_DIR="${PROJECT_ROOT}/daemon"
VENV="${DAEMON_DIR}/.venv"
PID_FILE="${PROJECT_ROOT}/.cidas.pid"
PORT="${DAEMON_PORT:-7355}"
HOST="${DAEMON_HOST:-127.0.0.1}"

# Load .env if present
ENV_FILE="${PROJECT_ROOT}/.env"
if [[ -f "${ENV_FILE}" ]]; then
  set -a; source "${ENV_FILE}"; set +a
  echo "[CIDAS] Loaded ${ENV_FILE}"
fi

# Check if already running
if lsof -iTCP:"${PORT}" -sTCP:LISTEN -t &>/dev/null; then
  echo "[CIDAS] Daemon already running on port ${PORT}."
  exit 0
fi

# Create venv if absent
if [[ ! -d "${VENV}" ]]; then
  echo "[CIDAS] Creating Python virtual environment in ${VENV}…"
  python3 -m venv "${VENV}"
  "${VENV}/bin/pip" install --quiet --upgrade pip
  "${VENV}/bin/pip" install --quiet -e "${DAEMON_DIR}[dev]"
fi

echo "[CIDAS] Starting daemon on ${HOST}:${PORT} …"
"${VENV}/bin/uvicorn" daemon.main:app \
  --host "${HOST}" \
  --port "${PORT}" \
  --log-level "${LOG_LEVEL:-info}" \
  --app-dir "${PROJECT_ROOT}" &

DAEMON_PID=$!
echo "${DAEMON_PID}" > "${PID_FILE}"
echo "[CIDAS] Daemon PID ${DAEMON_PID} written to ${PID_FILE}"

# Wait until the health endpoint responds (up to 30 s)
echo "[CIDAS] Waiting for daemon to be ready…"
for i in $(seq 1 30); do
  if curl -sf "http://${HOST}:${PORT}/api/v1/health" >/dev/null 2>&1; then
    echo "[CIDAS] Daemon is ready."
    break
  fi
  if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
    echo "[CIDAS] Daemon process exited unexpectedly." >&2
    exit 1
  fi
  sleep 1
done

echo "[CIDAS] Swagger UI → http://${HOST}:${PORT}/docs"
