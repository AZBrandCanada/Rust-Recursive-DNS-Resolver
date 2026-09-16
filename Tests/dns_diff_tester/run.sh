#!/usr/bin/env bash
# dns_diff_tester/run.sh
set -e

cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "[SETUP] Creating virtual environment..."
    python3 -m venv venv
fi

echo "[SETUP] Activating environment and verifying dependencies..."
source venv/bin/activate
pip install -q -r requirements.txt

echo "[START] Running differential DNS tester..."
python3 test_doh.py "$@"
