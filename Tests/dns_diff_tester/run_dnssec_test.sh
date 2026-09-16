#!/usr/bin/env bash
# dns_diff_tester/run_dnssec_test.sh
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

python3 test_13_dnssec.py "$@"
