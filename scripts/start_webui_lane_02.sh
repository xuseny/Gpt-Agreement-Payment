#!/usr/bin/env bash
set -euo pipefail

LANE_ID="${LANE_ID:-lane-02}"
ROOT="${ROOT:-/opt/Gpt-Agreement-Payment-lane-02}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8766}"
PYTHON_BIN="${PYTHON_BIN:-$ROOT/.venv/bin/python}"

cd "$ROOT"
mkdir -p "$ROOT/output"

export PYTHONUNBUFFERED=1
export WEBUI_DATA_DIR="${WEBUI_DATA_DIR:-$ROOT/output}"
export WEBUI_INTERNAL_BASE_URL="${WEBUI_INTERNAL_BASE_URL:-http://127.0.0.1:$PORT}"

echo "[$LANE_ID] root=$ROOT"
echo "[$LANE_ID] data=$WEBUI_DATA_DIR"
echo "[$LANE_ID] internal=$WEBUI_INTERNAL_BASE_URL"
echo "[$LANE_ID] listen=http://$HOST:$PORT"

exec "$PYTHON_BIN" -m uvicorn webui.server:create_app --factory --host "$HOST" --port "$PORT"
