#!/usr/bin/env bash
# ==============================================================
#  Safeguard Pro+ - AI Security Toolkit
#  Launcher for Linux / Kali Linux / macOS
#  Made by Er-Suzen Kumar Mohanty - IBM Cyber Security Project
# ==============================================================
#
#  Usage:
#      chmod +x run.sh
#      ./run.sh
#
#  Creates a virtual environment on first run, installs the
#  dependencies, trains the models if missing, then starts the
#  Flask web app at http://127.0.0.1:5000
# --------------------------------------------------------------

set -e

# Always work from the folder this script lives in.
cd "$(dirname "$0")"

# --- pick a python command ------------------------------------
if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "[error] Python 3 is not installed. Run:  sudo apt install -y python3 python3-pip python3-venv"
    exit 1
fi

echo "==> Using $($PY --version)"

# --- create / activate the virtual environment ----------------
if [ ! -d "venv" ]; then
    echo "==> Creating virtual environment (first run)..."
    $PY -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate

# --- install dependencies -------------------------------------
REQ=""
if [ -f "requirements.txt" ]; then
    REQ="requirements.txt"
elif [ -f "PHISHINGGUARD Requirements File.txt" ]; then
    REQ="PHISHINGGUARD Requirements File.txt"
fi

if [ -n "$REQ" ]; then
    echo "==> Installing dependencies from \"$REQ\" ..."
    pip install --quiet --upgrade pip
    pip install --quiet -r "$REQ"
else
    echo "[warn] No requirements file found — skipping dependency install."
fi

# --- train models if missing ----------------------------------
if [ ! -f "models/url_model.joblib" ] || [ ! -f "models/email_model.joblib" ]; then
    echo "==> Training models (first run)..."
    $PY train_model.py
fi

# --- launch the main app --------------------------------------
MAIN=""
if [ -f "app.py" ]; then
    MAIN="app.py"
elif [ -f "SUZENKUMARMOHANTYPHISHINGGUARD.py" ]; then
    MAIN="SUZENKUMARMOHANTYPHISHINGGUARD.py"
fi

if [ -z "$MAIN" ]; then
    echo "[error] Main application file not found (app.py)."
    exit 1
fi

echo "==> Starting Safeguard Pro+ - open http://127.0.0.1:5000"
echo "    Press Ctrl + C to stop."
echo
exec $PY "$MAIN"
