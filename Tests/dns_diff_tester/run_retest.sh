#!/usr/bin/env bash
# dns_diff_tester/run_retest.sh
set -e

cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "[SETUP] Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -q -r requirements.txt
else
    source venv/bin/activate
fi

echo "[START] Retesting failed and discrepant domains..."
python3 retest_failed.py "$@"
