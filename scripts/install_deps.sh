#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Accept venv name as first arg, default to 'scanmal-venv'
VENV_NAME="${1:-scanmal-venv}"
PY="$ROOT/$VENV_NAME/bin/python"

if [ ! -x "$PY" ]; then
  # fallback to old 'venv' name if present
  if [ -x "$ROOT/venv/bin/python" ]; then
    PY="$ROOT/venv/bin/python"
    VENV_NAME="venv"
    echo "Using fallback virtualenv 'venv'"
  else
    echo "Virtualenv not found. Create it with: python3 -m venv ${VENV_NAME}"
    exit 2
  fi
fi

echo "Using virtualenv: $VENV_NAME"
echo "Upgrading pip and installing from requirements.txt"
"$PY" -m pip install --upgrade pip setuptools wheel
"$PY" -m pip install -r "$ROOT/requirements.txt"
